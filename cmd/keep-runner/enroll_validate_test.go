package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// runEnrollAgainst serves resp from a TLS server and runs enroll against it,
// returning the exit code, both output streams and the credential directory.
func runEnrollAgainst(t *testing.T, resp runnerEnrollResponse) (rc int, stdout, stderr, dir string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	dir = filepath.Join(t.TempDir(), "cred")
	rc, stdout, stderr = captureEnrollOutput(t, testTokenFixture+"\n", func() int {
		return runEnroll([]string{"-host", "h1", "-policy", enrollPolicyFixture(t),
			"-server", srv.URL, "-cred-dir", dir, "-server-ca", writePEMCert(t, srv.Certificate())})
	})
	return rc, stdout, stderr, dir
}

func assertNothingSaved(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) > 0 {
		t.Errorf("credential files were written for a rejected answer: %d entries", len(entries))
	}
}

// not_after is server text: even a strictly valid RFC3339 value carries
// about 40 bits of arbitrary digits (nanoseconds, zone), so it is never printed.
func TestEnrollDoesNotPrintServerNotAfter(t *testing.T) {
	resp := validEnrollResponse(t, enrollFixtureRunnerID)
	resp.NotAfter = time.Date(2999, 12, 31, 23, 59, 59, 987654321, time.FixedZone("x", 23*3600+59*60))
	rc, stdout, stderr, _ := runEnrollAgainst(t, resp)
	if rc != 0 {
		t.Fatalf("enroll failed: rc=%d stderr=%q", rc, stderr)
	}
	if strings.Contains(stdout, "987654321") || strings.Contains(stdout, "2999") || strings.Contains(stdout, "not_after") {
		t.Errorf("server-supplied not_after reached stdout: %q", stdout)
	}
}

func TestEnrollRejectsMalformedSignKeyID(t *testing.T) {
	c := canary.New()
	cases := map[string]string{
		"empty":        "",
		"old-fixture":  "fixture",
		"upper-hex":    "orgsign_0123456789ABCDEF",
		"short":        "orgsign_0123456789abcde",
		"long":         "orgsign_0123456789abcdef0",
		"wrong-prefix": "orgkey_0123456789abcdef",
		"newline":      "orgsign_0123456789abcdef\n",
		"path":         "orgsign_../../../etc/pas",
		"canary":       c.Value(1),
		"huge":         "orgsign_" + strings.Repeat("a", 100000),
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			resp := validEnrollResponse(t, enrollFixtureRunnerID)
			resp.SignKeyID = id
			rc, stdout, stderr, dir := runEnrollAgainst(t, resp)
			if rc == 0 {
				t.Fatal("enroll accepted a malformed sign_key_id")
			}
			assertNothingSaved(t, dir)
			if c.In(stdout) || c.In(stderr) || strings.Contains(stdout+stderr, "orgsign_") {
				t.Errorf("rejected sign_key_id was reflected: %q %q", stdout, stderr)
			}
		})
	}
}

func TestEnrollRejectsRunnerIdentityMismatch(t *testing.T) {
	c := canary.New()
	other := "22222222-2222-2222-2222-222222222222"
	badCert := validEnrollResponse(t, enrollFixtureRunnerID)
	badCert.Certificate = []byte("not a certificate " + c.Value(2))
	cnDiffers := validEnrollResponse(t, other)
	cnDiffers.RunnerID = enrollFixtureRunnerID
	cases := map[string]runnerEnrollResponse{
		"cn-differs":        cnDiffers,
		"unparsable-cert":   badCert,
		"id-not-uuid":       validEnrollResponse(t, c.Value(3)),
		"id-uppercase-uuid": validEnrollResponse(t, "ABCDEF01-2222-3333-4444-555555555555"),
		"id-empty":          validEnrollResponse(t, ""),
		// Shape of runner_id (canonicalUUID): the cert CN carries the same padded id, so
		// only the shape check can refuse these.
		"id-trailing-newline": validEnrollResponse(t, enrollFixtureRunnerID+"\n"),
		"id-leading-text":     validEnrollResponse(t, "x"+enrollFixtureRunnerID),
		"id-trailing-digit":   validEnrollResponse(t, enrollFixtureRunnerID+"0"),
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			rc, stdout, stderr, dir := runEnrollAgainst(t, resp)
			if rc == 0 {
				t.Fatal("enroll accepted a runner_id that does not match its certificate")
			}
			assertNothingSaved(t, dir)
			out := stdout + stderr
			if c.In(out) || strings.Contains(out, other) || strings.Contains(out, enrollFixtureRunnerID) {
				t.Errorf("rejected identity was reflected: %q", out)
			}
		})
	}
}
