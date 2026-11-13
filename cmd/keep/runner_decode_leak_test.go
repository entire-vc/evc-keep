package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// TestRunnerResponseDecodeNoLeak: a 2xx answer the CLI cannot decode must
// fail closed with a static message. The decoder's own error carries body
// text (time.ParseError quotes the bad date, SyntaxError names a byte,
// UnmarshalTypeError names the value), so none of it may reach the terminal
// and stdout must stay empty (threat model §4.3).
func TestRunnerResponseDecodeNoLeak(t *testing.T) {
	const runnerID = "11111111-2222-4333-8444-555555555555"
	cases := []struct {
		name   string
		cmd    string
		status int
		body   func(c string) string
	}{
		{"enroll-bad-date", "enroll", http.StatusCreated, func(c string) string {
			return `{"token":"keep_renr_fixture","token_id":"t1","expires_at":"` + c + `"}`
		}},
		{"enroll-syntax", "enroll", http.StatusCreated, func(c string) string { return c + `{` }},
		{"enroll-type-error", "enroll", http.StatusCreated, func(c string) string {
			return `{"token":{"` + c + `":1},"token_id":"t1"}`
		}},
		{"enroll-type-error-field", "enroll", http.StatusCreated, func(c string) string {
			return `{"token_id":` + `"` + c + `","last4":["` + c + `"]}`
		}},
		{"revoke-syntax", "revoke", http.StatusOK, func(c string) string { return c }},
		{"revoke-type-error", "revoke", http.StatusOK, func(c string) string {
			return `{"ok":"` + c + `"}`
		}},
		{"revoke-bad-request-id-type", "revoke", http.StatusOK, func(c string) string {
			return `{"request_id":{"` + c + `":1}}`
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			can := canary.New()
			val := can.Value(0)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body(val)))
			}))
			defer srv.Close()
			t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
			caPath := writePEMCert(t, srv.Certificate())

			rc, stdout, stderr := captureOutput(t, func() int {
				if tc.cmd == "enroll" {
					return runRunnerEnrollToken([]string{"-host", "h1", "-policy", policyFileFixture(t), "-server", srv.URL, "-server-ca", caPath})
				}
				return runRunnerRevoke([]string{"-server", srv.URL, "-server-ca", caPath, runnerID})
			})
			if rc == 0 {
				t.Fatalf("undecodable response accepted: rc=0")
			}
			if stdout != "" {
				t.Errorf("stdout not empty on invalid response (len=%d)", len(stdout))
			}
			if can.In(stderr) || can.In(stdout) {
				t.Errorf("canary from response body reached output (stderr len=%d)", len(stderr))
			}
			// Body-derived decoder text: any Go decoder error shape.
			for _, marker := range []string{"parsing time", "invalid character", "cannot unmarshal", "unexpected end of JSON", "json:", "Go struct"} {
				if strings.Contains(stderr, marker) {
					t.Errorf("stderr carries decoder error text %q", marker)
				}
			}
			if !strings.Contains(stderr, "decoding response") {
				t.Errorf("stderr lost its static diagnostic: len=%d", len(stderr))
			}
		})
	}
}

// TestRunnerResponseDecodePositiveControls: valid answers still succeed and
// the enrollment token stays on stdout alone, so the no-leak test above is
// not satisfied by a command that always fails.
func TestRunnerResponseDecodePositiveControls(t *testing.T) {
	const runnerID = "11111111-2222-4333-8444-555555555555"
	c := canary.New()
	tok := "keep_renr_" + c.Value(1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/revoke") {
			_, _ = w.Write([]byte(`{"ok":true,"request_id":"req1"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"` + tok + `","token_id":"t1","last4":"abcd","host":"h1","expires_at":"2030-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()
	t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
	caPath := writePEMCert(t, srv.Certificate())

	rc, stdout, stderr := captureOutput(t, func() int {
		return runRunnerEnrollToken([]string{"-host", "h1", "-policy", policyFileFixture(t), "-server", srv.URL, "-server-ca", caPath})
	})
	if rc != 0 || strings.TrimSpace(stdout) != tok {
		t.Fatalf("valid enroll: rc=%d stdout-len=%d", rc, len(stdout))
	}
	if strings.Contains(stderr, tok) {
		t.Errorf("enrollment token reached stderr")
	}
	rc, stdout, stderr = captureOutput(t, func() int {
		return runRunnerRevoke([]string{"-server", srv.URL, "-server-ca", caPath, runnerID})
	})
	if rc != 0 || !strings.Contains(stdout, "ok=true") {
		t.Fatalf("valid revoke: rc=%d stderr-len=%d", rc, len(stderr))
	}
}
