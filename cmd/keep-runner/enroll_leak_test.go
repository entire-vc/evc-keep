package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// A server answer must never reach the terminal as text: neither the
// decoder's error (a time.ParseError quotes the offending field) nor the
// error message of a rejected request (threat model section 4.3).
func TestEnrollServerTextNeverReachesTerminal(t *testing.T) {
	c := canary.New()
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"decoder-error-quotes-field", http.StatusOK, `{"runner_id":"r","not_after":"` + c.Value(1) + `"}`},
		{"error-message", http.StatusForbidden, `{"error_class":"forbidden","message":"` + c.Value(2) + `","request_id":"q1"}`},
		{"error-class", http.StatusForbidden, `{"error_class":"` + c.Value(3) + `","message":"m","request_id":"q1"}`},
		{"error-request-id", http.StatusForbidden, `{"error_class":"forbidden","message":"m","request_id":"` + c.Value(4) + ` !"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			caPath := writePEMCert(t, srv.Certificate())
			rc, stdout, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
				return runEnroll([]string{"-host", "h1", "-policy", enrollPolicyFixture(t), "-server", srv.URL, "-cred-dir", t.TempDir(), "-server-ca", caPath})
			})
			if rc == 0 {
				t.Fatalf("enroll succeeded on a rejected/invalid answer")
			}
			if c.In(stdout) || c.In(stderr) {
				t.Errorf("server text reached the terminal (stderr %d bytes)", len(stderr))
			}
		})
	}
}

// A successful enroll prints the result, not the -cred-dir flag value.
func TestEnrollSuccessDoesNotEchoCredDir(t *testing.T) {
	c := canary.New()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(validEnrollResponse(t, enrollFixtureRunnerID))
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), c.Value(1))
	rc, stdout, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
		return runEnroll([]string{"-host", "h1", "-policy", enrollPolicyFixture(t),
			"-server", srv.URL, "-cred-dir", dir, "-server-ca", writePEMCert(t, srv.Certificate())})
	})
	if rc != 0 || stdout != "enrolled: runner_id=11111111-1111-1111-1111-111111111111\n" {
		t.Fatalf("enroll did not succeed as expected: rc=%d", rc)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("credential directory was not written")
	}
	if !c.In("x "+dir) || c.In(stdout) || c.In(stderr) {
		t.Errorf("-cred-dir value reached the terminal or detector is blind (stdout %d bytes)", len(stdout))
	}
}

// A failed credential write does not echo the -cred-dir path either.
func TestEnrollSaveFailureDoesNotEchoCredDir(t *testing.T) {
	c := canary.New()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(validEnrollResponse(t, enrollFixtureRunnerID))
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), c.Value(1))
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(file, "sub") // under a regular file: Save must fail
	rc, stdout, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
		return runEnroll([]string{"-host", "h1", "-policy", enrollPolicyFixture(t),
			"-server", srv.URL, "-cred-dir", dir, "-server-ca", writePEMCert(t, srv.Certificate())})
	})
	if rc == 0 || stderr == "" {
		t.Fatalf("expected a failed save with a message: rc=%d", rc)
	}
	if !c.In("x "+dir) || c.In(stdout) || c.In(stderr) {
		t.Errorf("-cred-dir value reached the terminal or detector is blind (stderr %d bytes)", len(stderr))
	}
}
