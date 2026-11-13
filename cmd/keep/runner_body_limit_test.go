package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// padJSON returns valid JSON of exactly n bytes: doc followed by spaces. The
// decoder accepts it at any size, so only a byte cap can refuse it.
func padJSON(doc string, n int) string {
	return doc + strings.Repeat(" ", n-len(doc))
}

// TestRunnerResponseBodyLimit: every runner command path reads at most
// maxRunnerResponseBytes of the server's answer. limit+1 (plain, chunked
// and streamed) fails closed with a static line; exactly limit passes.
func TestRunnerResponseBodyLimit(t *testing.T) {
	const runnerID = "11111111-2222-4333-8444-555555555555"
	const enrollDoc = `{"token":"keep_renr_fixture","token_id":"t1","expires_at":"2030-01-01T00:00:00Z"}`
	const revokeDoc = `{"ok":true,"request_id":"req1"}`
	const errDoc = `{"error_class":"not_found","message":"m","request_id":"req1"}`
	limit := maxRunnerResponseBytes

	type send func(w http.ResponseWriter, doc string, n int)
	plain := func(w http.ResponseWriter, doc string, n int) { _, _ = w.Write([]byte(padJSON(doc, n))) }
	chunked := func(w http.ResponseWriter, doc string, n int) {
		body := padJSON(doc, n)
		fl := w.(http.Flusher)
		for len(body) > 0 {
			k := min(len(body), 32<<10)
			_, _ = w.Write([]byte(body[:k]))
			fl.Flush()
			body = body[k:]
		}
	}
	// endless: valid JSON then whitespace until the client hangs up.
	var sent atomic.Int64
	endless := func(w http.ResponseWriter, doc string, _ int) {
		fl := w.(http.Flusher)
		_, _ = w.Write([]byte(doc))
		chunk := []byte(strings.Repeat(" ", 32<<10))
		for range 2048 { // 64 MiB ceiling so an unbounded reader still terminates
			if _, err := w.Write(chunk); err != nil {
				return
			}
			sent.Add(int64(len(chunk)))
			fl.Flush()
		}
	}

	paths := []struct {
		name    string
		cmd     string
		status  int
		doc     string
		okLine  string // stdout/stderr marker when within the limit
		badLine string // static stderr line when over the limit
	}{
		{"enroll-token-ok-status", "enroll", http.StatusCreated, enrollDoc, "", "decoding response"},
		{"revoke-ok-status", "revoke", http.StatusOK, revokeDoc, "", "decoding response"},
		{"enroll-token-error-body", "enroll", http.StatusForbidden, errDoc, "not_found", "server rejected the request"},
		{"revoke-error-body", "revoke", http.StatusForbidden, errDoc, "not_found", "server rejected the request"},
	}
	modes := []struct {
		name string
		n    int
		fn   send
		pass bool
	}{
		{"exact-limit", limit, plain, true},
		{"limit-plus-one", limit + 1, plain, false},
		{"chunked-limit-plus-one", limit + 1, chunked, false},
		{"endless", 0, endless, false},
	}
	for _, p := range paths {
		for _, m := range modes {
			t.Run(p.name+"/"+m.name, func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(p.status)
					m.fn(w, p.doc, m.n)
				}))
				sent.Store(0)
				defer srv.Close()
				t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
				caPath := writePEMCert(t, srv.Certificate())
				rc, stdout, stderr := captureOutput(t, func() int {
					if p.cmd == "enroll" {
						return runRunnerEnrollToken([]string{"-host", "h1", "-policy", policyFileFixture(t), "-server", srv.URL, "-server-ca", caPath})
					}
					return runRunnerRevoke([]string{"-server", srv.URL, "-server-ca", caPath, runnerID})
				})
				if m.pass {
					if p.okLine == "" && rc != 0 {
						t.Fatalf("exactly-limit answer refused: rc=%d stderr=%q", rc, stderr)
					}
					if p.okLine != "" && !strings.Contains(stderr, p.okLine) {
						t.Fatalf("exactly-limit error body not parsed: stderr=%q", stderr)
					}
					return
				}
				if m.name == "endless" {
					srv.Close() // waits for the handler, which stops once the client hangs up
					if got := sent.Load(); got > 16<<20 {
						t.Errorf("client kept reading an endless body: server sent %d bytes", got)
					}
				}
				if rc == 0 {
					t.Fatalf("oversized answer accepted: rc=0 stdout-len=%d", len(stdout))
				}
				if stdout != "" {
					t.Errorf("stdout not empty on oversized answer (len=%d)", len(stdout))
				}
				if !strings.Contains(stderr, p.badLine) {
					t.Errorf("stderr lost its static diagnostic: %q", stderr)
				}
				if p.okLine != "" && strings.Contains(stderr, p.okLine) {
					t.Errorf("oversized error body was parsed: %q", stderr)
				}
			})
		}
	}
}
