package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRequireSecureURL(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"https any host", "https://keep.example.com", true},
		{"http loopback ip", "http://127.0.0.1:8080", true},
		{"http localhost", "http://localhost:8080", true},
		{"http ipv6 loopback", "http://[::1]:8080", true},
		{"http real host", "http://keep.example.com", false},
		{"http public ip", "http://93.184.216.34", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.raw, err)
			}
			err = requireSecureURL(u)
			if tc.ok && err != nil {
				t.Fatalf("requireSecureURL(%q) = %v, want nil", tc.raw, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("requireSecureURL(%q) = nil, want a refusal", tc.raw)
			}
		})
	}
}

// TestGlobalOptsNewClientRefusesInsecureServer: --server (or KEEP_SERVER)
// pointing at a real host over plain http must be refused before a client
// is even built — a bearer token going out over that link in plaintext is
// exactly the leak requireSecureURL exists to prevent (see client.go).
func TestGlobalOptsNewClientRefusesInsecureServer(t *testing.T) {
	o := &globalOpts{server: "http://keep.example.com", org: "org-1"}
	// KEEP_TOKEN set so resolveToken succeeds: the only way newClient can
	// still fail is the requireSecureURL check itself, which is the one
	// property under test — a test that also tolerated the generic
	// "no token" error wouldn't actually prove the security check ran.
	getenv := func(k string) string {
		if k == "KEEP_TOKEN" {
			return "tok"
		}
		return ""
	}
	var stderr bytes.Buffer
	if _, err := o.newClient(getenv, &stderr); err == nil {
		t.Fatal("newClient with a non-loopback http --server must refuse, got nil error")
	} else if !strings.Contains(err.Error(), "https") {
		t.Fatalf("newClient error = %q, want it to mention the https requirement", err)
	}
}

// TestGlobalOptsNewClientServerParseErrorDoesNotLeakUserinfo: a malformed
// --server value can still carry a userinfo component (e.g. a stray space
// forces url.Parse to fail on the whole string) — the resulting error must
// not repeat the raw --server value back, since url.Error's own Error()
// text does exactly that.
func TestGlobalOptsNewClientServerParseErrorDoesNotLeakUserinfo(t *testing.T) {
	o := &globalOpts{server: "https://user:s3cr3t@keep example.com", org: "org-1"} //nolint:gosec // G101: a fake fixture credential this test asserts never leaks, not a real one
	getenv := func(k string) string {
		if k == "KEEP_TOKEN" {
			return "tok"
		}
		return ""
	}
	var stderr bytes.Buffer
	_, err := o.newClient(getenv, &stderr)
	if err == nil {
		t.Fatal("newClient with an unparseable --server must fail, got nil error")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("parse error leaks the --server userinfo password: %v", err)
	}
}

// TestClientDebugTraceRedactsServerUserinfo: --server (or KEEP_SERVER) can
// carry a userinfo component; a --debug trace must never print it, even
// though it isn't the bearer token itself — it's still a credential, and a
// debug trace is exactly as public as a log line once it lands in a
// terminal someone screenshots or pastes.
func TestClientDebugTraceRedactsServerUserinfo(t *testing.T) {
	var stderr bytes.Buffer
	// Port 1 refuses the connection immediately (nothing listens there);
	// the request line is debug-printed before the dial is attempted, which
	// is all this test needs.
	c := newClient("http://user:s3cr3t@127.0.0.1:1", "org-1", "tok", true, &stderr)
	_, _ = c.do("GET", "/secrets", nil, nil)

	out := stderr.String()
	if out == "" {
		t.Fatal("--debug produced no output at all")
	}
	if strings.Contains(out, "s3cr3t") {
		t.Fatalf("debug trace leaks the server URL's userinfo password:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Fatalf("debug trace doesn't mention the request at all:\n%s", out)
	}
}

// TestClientCheckRedirectCapsRedirectCount: setting CheckRedirect at all
// replaces net/http's default policy wholesale, including its own
// 10-redirect cap — without re-adding an equivalent cap, a server that
// redirects to itself is followed until the client's 30s Timeout instead of
// a bounded number of hops (reproduced pre-fix: ~41,000 requests in 2s). The
// token stays on the same, already-authorized host each time so this isn't
// a leak, just excessive load — but the cap must still hold.
func TestClientCheckRedirectCapsRedirectCount(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		http.Redirect(w, r, r.URL.Path, http.StatusFound) //nolint:gosec // G710: this test's own httptest.Server redirecting to its own path to simulate a self-redirect loop, not an externally reachable route
	}))
	defer srv.Close()

	var stderr bytes.Buffer
	c := newClient(srv.URL, "org-1", "tok", false, &stderr)
	_, err := c.do("GET", "/secrets", nil, nil)
	if err == nil {
		t.Fatal("do against a self-redirecting server returned nil error, want a stopped-after-N-redirects error")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("do error = %q, want it to mention redirects", err)
	}
	got := atomic.LoadInt32(&requests)
	// The exact count is net/http's own accounting (one initial request plus
	// up to 10 redirects); the assertion only needs to rule out "unbounded",
	// not pin the precise number.
	if got > 20 {
		t.Fatalf("self-redirect loop sent %d requests, want a bounded count (~11)", got)
	}
	if got < 2 {
		t.Fatalf("self-redirect loop sent only %d request(s) — the redirect was never followed at all", got)
	}
}

// TestClientRefusesRedirectToInsecureHost: CheckRedirect must refuse to
// follow a redirect that would send the bearer token to a plain-http,
// non-loopback host — otherwise a compromised or misconfigured server can
// downgrade the connection mid-request and walk off with the Authorization
// header (see the CheckRedirect comment in client.go).
func TestClientRefusesRedirectToInsecureHost(t *testing.T) {
	var requests int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "http://keep.example.com/redirected", http.StatusFound)
	}))
	defer origin.Close()

	c := newClient(origin.URL, "org-1", "tok", false, io.Discard)
	_, err := c.do("GET", "/secrets", nil, nil)
	if err == nil {
		t.Fatal("client followed a redirect toward a non-loopback http host, want a refusal")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("error = %q, want it to mention the https requirement", err)
	}
	if requests != 1 {
		t.Fatalf("origin got %d requests, want exactly 1 (no second hop after the blocked redirect)", requests)
	}
}

func TestClientRefusesRedirectToDifferentHost(t *testing.T) {
	var gotAuth string
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("[]"))
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/secrets", http.StatusFound)
	}))
	defer origin.Close()

	c := newClient(origin.URL, "org-1", "tok", false, io.Discard)
	if _, err := c.do("GET", "/secrets", nil, nil); err == nil {
		t.Fatal("client followed a redirect to another host:port, want a refusal")
	}
	if hits != 0 || gotAuth != "" {
		t.Fatalf("redirect target received %d request(s), Authorization present=%v; the token must not leave the named host", hits, gotAuth != "")
	}
}
