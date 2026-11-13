package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// TestRedactedHeaderDump: every header value is replaced by the closed
// template, whatever the header is called or how it is cased; only names from
// the closed static set stay, in canonical case.
func TestRedactedHeaderDump(t *testing.T) {
	c := canary.New()
	h := http.Header{}
	h.Add("Authorization", "Bearer "+c.Value(0))
	h.Add("Cookie", "sid="+c.Value(1))
	h.Add("Set-Cookie", "sid="+c.Value(2)+"; HttpOnly")
	h.Add("Set-Cookie", "again="+c.Value(3))
	h.Add("Proxy-Authorization", "Basic "+c.Value(4))
	h["x-lower-case"] = []string{c.Value(5)}
	h.Add("X-Unknown-Thing", c.Value(6))

	out := redactedHeaderDump(h)
	if c.In(out) {
		t.Fatalf("header dump leaks a canary value (dump length %d)", len(out))
	}
	for _, name := range []string{"Authorization", "Cookie", "Set-Cookie", "Proxy-Authorization", unlistedHeaderName} {
		if !strings.Contains(out, name+": "+redactedValue) {
			t.Fatalf("header dump lost %q or its closed template", name)
		}
	}
	if got := strings.Count(out, "Set-Cookie: "+redactedValue); got != 2 {
		t.Fatalf("repeated Set-Cookie values: want 2 redacted lines, got %d", got)
	}
}

// TestDebugHeadersLoopback: a real loopback server answers with Set-Cookie
// and unknown headers; --debug must trace method, status and header names
// without any value, and the JSON result must be unchanged.
func TestDebugHeadersLoopback(t *testing.T) {
	c := canary.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sid="+c.Value(0)+"; HttpOnly")
		w.Header().Add("Set-Cookie", "again="+c.Value(1))
		w.Header()["x-odd-case"] = []string{c.Value(2)}
		w.Header().Set("X-Unknown-Thing", c.Value(3))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	var stderr bytes.Buffer
	cl := newClient(srv.URL, "org-1", c.Value(4), true, &stderr)
	body, err := cl.do("GET", "/secrets", nil, nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if string(body) != "[]" {
		t.Fatalf("response body changed: got %d bytes", len(body))
	}
	out := stderr.String()
	if c.In(out) {
		t.Fatalf("--debug trace leaks a canary value (trace length %d)", len(out))
	}
	for _, want := range []string{"GET http://127.0.0.1", "-> 200", "Set-Cookie: " + redactedValue, unlistedHeaderName + ": " + redactedValue, "Authorization: " + redactedValue} {
		if !strings.Contains(out, want) {
			t.Fatalf("--debug trace lacks %q", want)
		}
	}
}

// TestDebugHeadersListCommand: the whole `keep list --json --debug` command
// against a loopback server that answers with Set-Cookie. Exit code, stdout
// JSON and the header names stay; no value reaches stdout or stderr.
func TestDebugHeadersListCommand(t *testing.T) {
	c := canary.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sid="+c.Value(0)+"; HttpOnly")
		w.Header().Set("X-Unknown-Thing", c.Value(1))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	env := map[string]string{"KEEP_SERVER": srv.URL, "KEEP_ORG": "org-1", "KEEP_TOKEN": c.Value(2)}
	var stdout, stderr bytes.Buffer
	code := runListSubcommand([]string{"--json", "--debug", "--scope-level", "org", "--scope-id", "org-1"}, &stdout, &stderr, func(k string) string { return env[k] })
	if code != 0 {
		t.Fatalf("keep list exit code %d", code)
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not valid JSON (length %d)", stdout.Len())
	}
	if c.In(stdout.String()) || c.In(stderr.String()) {
		t.Fatalf("a header or token canary reached stdout (%d bytes) or stderr (%d bytes)", stdout.Len(), stderr.Len())
	}
	for _, want := range []string{"GET http://127.0.0.1", "Set-Cookie: " + redactedValue, unlistedHeaderName + ": " + redactedValue, "-> 200"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("--debug trace lacks %q", want)
		}
	}
}

// TestDebugHeaderNamesNoLeak: a header NAME is as untrusted as its value. A
// real loopback server answers with a canary as a header name; the built
// request path carries one too. With --debug the canary must not appear in
// the trace in any encoding; without --debug nothing is traced; the result,
// method and status are unchanged and known names keep their canonical case.
func TestDebugHeaderNamesNoLeak(t *testing.T) {
	c := canary.New()
	name := "X-" + c.Value(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()[name] = []string{c.Value(1), c.Value(2)}
		w.Header()["x-mixed-"+strings.ToLower(c.Value(3))] = []string{"v"}
		w.Header()["content-type"] = []string{"application/json"}
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	run := func(debug bool) (int, string, string) {
		env := map[string]string{"KEEP_SERVER": srv.URL, "KEEP_ORG": "org-1", "KEEP_TOKEN": c.Value(4)}
		args := []string{"--json", "--scope-level", "org", "--scope-id", "org-1"}
		if debug {
			args = append(args, "--debug")
		}
		var stdout, stderr bytes.Buffer
		code := runListSubcommand(args, &stdout, &stderr, func(k string) string { return env[k] })
		return code, stdout.String(), stderr.String()
	}

	// Positive control: the detector must see a canary that is really there.
	if !c.In("noise " + name) {
		t.Fatal("canary detector does not recognise a plain canary")
	}
	for _, debug := range []bool{false, true} {
		code, stdout, stderr := run(debug)
		if code != 0 || strings.TrimSpace(stdout) != "[]" {
			t.Fatalf("debug=%v: exit %d, stdout length %d", debug, code, len(stdout))
		}
		if c.In(stdout) || c.In(stderr) {
			t.Fatalf("debug=%v: a canary reached stdout or stderr (%d/%d bytes)", debug, len(stdout), len(stderr))
		}
		if debug {
			for _, want := range []string{"GET http://127.0.0.1", "-> 200", "Content-Type: " + redactedValue, unlistedHeaderName + ": " + redactedValue} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("--debug trace lacks %q", want)
				}
			}
			if got := strings.Count(stderr, unlistedHeaderName); got != 3 {
				t.Fatalf("want 3 hidden-name lines (2 values + 1 mixed-case), got %d", got)
			}
		} else if stderr != "" {
			t.Fatalf("no --debug but stderr has %d bytes", len(stderr))
		}
	}
}
