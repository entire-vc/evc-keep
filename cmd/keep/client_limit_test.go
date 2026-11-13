package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// TestClientResponseLimit: the shared client reads at most limit+1 bytes of a
// response. A body of exactly the limit decodes; one byte more is refused for
// both success and error statuses, before decoding, with a static error that
// carries no response bytes — not on stdout, not on stderr, not under --debug.
func TestClientResponseLimit(t *testing.T) {
	c := canary.New()
	mark := c.Value(0)

	// padded is valid JSON of exactly n bytes: prefix, spaces, suffix.
	padded := func(prefix, suffix string, n int) []byte {
		return []byte(prefix + strings.Repeat(" ", n-len(prefix)-len(suffix)) + suffix)
	}
	okBody := func(n int) []byte { return padded("[", "]", n) }
	errBody := func(n int) []byte {
		return padded(`{"error_class":"internal","message":"`+mark+`","request_id":"r1"}`, "", n)
	}

	cases := []struct {
		name    string
		status  int
		body    []byte
		chunked bool
		wantErr bool
	}{
		{"success small", 200, []byte("[]"), false, false},
		{"success exactly limit", 200, okBody(maxResponseBytes), false, false},
		{"success limit+1", 200, okBody(maxResponseBytes + 1), false, true},
		{"success far over", 200, okBody(maxResponseBytes * 3), false, true},
		{"success limit+1 chunked", 200, okBody(maxResponseBytes + 1), true, true},
		{"success exactly limit chunked", 200, okBody(maxResponseBytes), true, false},
		{"error limit+1", 500, errBody(maxResponseBytes + 1), false, true},
		{"error limit+1 chunked", 500, errBody(maxResponseBytes + 1), true, true},
		{"error exactly limit", 500, errBody(maxResponseBytes), false, true}, // decodes to *apiError
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if !tc.chunked {
					// Content-Length is set by net/http for a single Write of a small
					// body only; force it so an honest-looking header is exercised.
					w.Header().Set("Content-Length", strconv.Itoa(len(tc.body)))
				}
				w.WriteHeader(tc.status)
				// Write in pieces with a flush so chunked bodies stay chunked.
				for b := tc.body; len(b) > 0; {
					n := min(len(b), 32<<10)
					if _, err := w.Write(b[:n]); err != nil {
						return
					}
					if tc.chunked {
						w.(http.Flusher).Flush()
					}
					b = b[n:]
				}
			}))
			defer srv.Close()

			var stderr bytes.Buffer
			cl := newClient(srv.URL, "org-1", c.Value(1), true, &stderr)
			body, err := cl.do("GET", "/secrets", nil, nil)

			var all string
			if err != nil {
				all = err.Error()
			}
			all += stderr.String()
			if c.In(all) || strings.Contains(all, mark) {
				t.Fatalf("response bytes leaked into error/debug output (length %d)", len(all))
			}

			oversized := len(tc.body) > maxResponseBytes
			if oversized {
				if err == nil || body != nil {
					t.Fatalf("oversized body accepted")
				}
				if _, isAPI := err.(*apiError); isAPI {
					t.Fatalf("oversized body was decoded as an API error")
				}
				if err.Error() != "read response: too large" {
					t.Fatalf("want the static too-large error, got %q", err.Error())
				}
				return
			}
			if tc.wantErr {
				if _, isAPI := err.(*apiError); !isAPI {
					t.Fatalf("want *apiError for in-limit error body, got %v", err)
				}
				return
			}
			if err != nil || len(body) != len(tc.body) {
				t.Fatalf("in-limit body refused: err=%v len=%d", err, len(body))
			}
		})
	}
}

// TestClientResponseLimitEndlessStream: a server that never ends the body must
// be cut off after limit+1 bytes and abandoned, not drained on Close. Reading to EOF and checking the length
// afterwards would hang until the client timeout (read response: failed), so
// this fails if the bounded reader is replaced by an unbounded one.
func TestClientResponseLimitEndlessStream(t *testing.T) {
	handlerDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// The body never ends, but the server sends at most endlessSentCap
		// bytes and then stalls until the client goes away. An unbounded
		// reader therefore holds a few MiB (not gigabytes, whatever the
		// loopback speed or runner RAM) and runs into the client timeout.
		const endlessSentCap = 4 << 20
		chunk := bytes.Repeat([]byte(" "), 32<<10)
		for sent := 0; sent < endlessSentCap; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	cl := newClient(srv.URL, "org-1", "test-token", false, &bytes.Buffer{})
	cl.http.Timeout = 5 * time.Second
	start := time.Now()
	_, err := cl.do("GET", "/secrets", nil, nil)
	if err == nil || err.Error() != "read response: too large" {
		t.Fatalf("want the static too-large error for an endless body, got %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("endless body was read for %s; the read is not bounded", d)
	}
	// Closing the body must tear the connection down, not drain the rest of
	// it: the server's writer has to see the client go away.
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("server is still writing after the client returned; the body was not abandoned")
	}
}

// TestClientResponseLimitCLIPath drives the real command entry point: an
// oversized success or error answer ends in exit 1 with an empty stdout, and
// the canary carried inside the body appears on neither stdout nor stderr,
// --debug included. A body of exactly the limit (exit 0) is the positive control.
func TestClientResponseLimitCLIPath(t *testing.T) {
	c := canary.New()
	mark := c.Value(0)

	// pad grows prefix with trailing spaces to exactly n bytes.
	pad := func(prefix string, n int) string { return prefix + strings.Repeat(" ", n-len(prefix)) }
	cases := []struct {
		name   string
		status int
		body   string
		wantRC int
	}{
		{"success exactly limit", 200, pad(`[]`, maxResponseBytes), 0},
		{"success limit+1", 200, pad(`[{"id":"a","name":"`+mark+`"}]`, maxResponseBytes+1), 1},
		{"error limit+1", 500, pad(`{"error_class":"internal","message":"`+mark+`","request_id":"r1"}`, maxResponseBytes+1), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			getenv := func(k string) string {
				return map[string]string{"KEEP_SERVER": srv.URL, "KEEP_ORG": "org-1", "KEEP_TOKEN": "test-fixture-token"}[k]
			}
			var stdout, stderr bytes.Buffer
			rc := run([]string{"list", "--scope-level", "user", "--scope-id", "u1", "--json", "--debug"}, strings.NewReader(""), &stdout, &stderr, getenv)
			if tc.wantRC == 1 && stdout.Len() != 0 {
				t.Fatalf("refused answer produced stdout (%d bytes)", stdout.Len())
			}
			// An accepted answer is printed by design; the marker rides only in the
			// refused bodies, which must reach neither stream.
			if c.In(stdout.String()+stderr.String()) || strings.Contains(stdout.String()+stderr.String(), mark) {
				t.Fatalf("response marker reached stdout or stderr (stdout=%d stderr=%d bytes)", stdout.Len(), stderr.Len())
			}
			if rc != tc.wantRC {
				t.Fatalf("exit %d, want %d (stderr %q)", rc, tc.wantRC, stderr.String())
			}
		})
	}
}
