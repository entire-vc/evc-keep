package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// testAdminTokenFixture is a fixture value, never a real credential — no
// live server issued it and nothing in Keep treats it as a secret to redact.
const testAdminTokenFixture = "test-fixture-admin-token"

// captureOutput redirects os.Stdout/os.Stderr for the duration of fn, the
// only way to observe these commands' output: every runRunner* function
// prints straight to the package-level os.Stdout/os.Stderr, not to an
// injectable writer.
func captureOutput(t *testing.T, fn func() int) (rc int, stdout, stderr string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr = outW, errW
	t.Cleanup(func() { os.Stdout, os.Stderr = origOut, origErr })

	rc = fn()
	_ = outW.Close()
	_ = errW.Close()
	outBytes, _ := io.ReadAll(outR)
	errBytes, _ := io.ReadAll(errR)
	os.Stdout, os.Stderr = origOut, origErr
	return rc, string(outBytes), string(errBytes)
}

func policyFileFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"argv_templates":[]}`), 0o600); err != nil {
		t.Fatalf("write policy fixture: %v", err)
	}
	return path
}

// TestRunnerEnrollTokenRejectsNonHTTPSServer is this fix's own red run: an
// http:// -server must be refused before any request is attempted — the
// enrollment token this command would go on to receive, and the admin
// bearer token it always sends, must never be offered to a plaintext
// listener (leak-review finding: neither was checked before).
func TestRunnerEnrollTokenRejectsNonHTTPSServer(t *testing.T) {
	t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
	policyPath := policyFileFixture(t)

	rc, _, stderr := captureOutput(t, func() int {
		return runRunnerEnrollToken([]string{"-host", "h1", "-policy", policyPath, "-server", "http://127.0.0.1:1"})
	})
	if rc == 0 {
		t.Fatal("runRunnerEnrollToken accepted an http:// -server")
	}
	if !contains(stderr, "https://") {
		t.Errorf("stderr does not explain the https requirement: %q", stderr)
	}
}

func TestRunnerEnrollTokenSendsExplicitHostAssertions(t *testing.T) {
	var attrs struct {
		UIDShared *bool             `json:"uid_shared"`
		Labels    map[string]string `json:"labels"`
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			HostAttrs json.RawMessage `json:"host_attrs"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || json.Unmarshal(body.HostAttrs, &attrs) != nil {
			t.Error("host attributes missing from issue request")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(enrollTokenResponse{Token: testAdminTokenFixture, Host: "h1", ExpiresAt: time.Now().Add(time.Minute)})
	}))
	defer srv.Close()
	t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
	rc, _, _ := captureOutput(t, func() int {
		return runRunnerEnrollToken([]string{"-host", "h1", "-policy", policyFileFixture(t),
			"-server", srv.URL, "-uid-shared=false", "-environment", "staging", "-platform", "darwin", "-insecure-skip-verify"})
	})
	if rc != 0 || attrs.UIDShared == nil || *attrs.UIDShared || attrs.Labels["environment"] != "staging" || attrs.Labels["platform"] != "darwin" {
		t.Fatal("admin host assertions were not transmitted")
	}
}

func TestRunnerRevokeRejectsNonHTTPSServer(t *testing.T) {
	t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)

	rc, _, stderr := captureOutput(t, func() int {
		return runRunnerRevoke([]string{"-server", "http://127.0.0.1:1", "018f4d1e-0000-7000-8000-000000000000"})
	})
	if rc == 0 {
		t.Fatal("runRunnerRevoke accepted an http:// -server")
	}
	if !contains(stderr, "https://") {
		t.Errorf("stderr does not explain the https requirement: %q", stderr)
	}
}

// TestRunnerEnrollTokenDoesNotFollowRedirectToPlainHTTP reproduces
// keep-leak-reviewer's [high] finding directly: a TLS listener answering
// -server responds with a redirect to a second, plain-http listener. Before
// the fix, net/http's default client followed it and resent the same
// request — including the Authorization header and, on the real Keep
// Server enroll-token route, the freshly issued token in the response body
// this command reads next — to that second origin. The fix (CheckRedirect
// returning http.ErrUseLastResponse) must mean the second listener is never
// contacted at all.
func TestRunnerEnrollTokenDoesNotFollowRedirectToPlainHTTP(t *testing.T) {
	plainHitCount := 0
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHitCount++
		w.WriteHeader(http.StatusCreated)
	}))
	defer plain.Close()

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/runners/enroll-tokens", http.StatusTemporaryRedirect)
	}))
	defer tlsSrv.Close()

	t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
	tokenCanary := canary.Of(testAdminTokenFixture)
	policyPath := policyFileFixture(t)

	rc, stdout, stderr := captureOutput(t, func() int {
		return runRunnerEnrollToken([]string{
			"-host", "h1", "-policy", policyPath, "-server", tlsSrv.URL, "-insecure-skip-verify",
		})
	})
	if rc == 0 {
		t.Fatal("runRunnerEnrollToken succeeded against a server that only ever redirects")
	}
	if plainHitCount != 0 {
		t.Fatalf("the plain-http redirect target was contacted %d time(s) — the admin bearer token was resent to it", plainHitCount)
	}
	if tokenCanary.In(stdout) || tokenCanary.In(stderr) {
		t.Error("admin token leaked into this command's own output")
	}
}

func writePEMCert(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write CA pem fixture: %v", err)
	}
	return path
}

// unrelatedSelfSignedCert generates a throwaway self-signed certificate that
// signed nothing real — used as a deliberately wrong -server-ca pin. A
// second httptest.NewTLSServer would present net/http/httptest's own fixed
// shared certificate, the same one every httptest TLS server in this
// process uses, so it could never prove a mismatch is rejected.
func unrelatedSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create unrelated cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse unrelated cert: %v", err)
	}
	return cert
}

// TestRunnerEnrollTokenTrustsPinnedServerCA is the leak-review's own
// CA-pinning finding, turned into a positive red-run test: -server-ca (and
// KEEP_SERVER_CA) give an operator a pinning option instead of the OS trust
// store or the all-or-nothing -insecure-skip-verify. This server's
// self-signed certificate is not from any CA the OS trust store
// recognizes, so without -server-ca the request would fail.
func TestRunnerEnrollTokenTrustsPinnedServerCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"keep_renr_fixture","token_id":"t1","last4":"abcd","host":"h1","expires_at":"2030-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
	caPath := writePEMCert(t, srv.Certificate())
	policyPath := policyFileFixture(t)

	rc, _, stderr := captureOutput(t, func() int {
		return runRunnerEnrollToken([]string{
			"-host", "h1", "-policy", policyPath, "-server", srv.URL, "-server-ca", caPath,
		})
	})
	if rc != 0 {
		t.Fatalf("runRunnerEnrollToken with a correctly pinned -server-ca failed: rc=%d stderr=%q", rc, stderr)
	}
}

// TestRunnerEnrollTokenRejectsMismatchedPinnedServerCA is this finding's own
// red run: -server-ca pointed at a CA that did not sign the server's actual
// certificate must refuse the connection, and the server's handler must
// never even run.
func TestRunnerEnrollTokenRejectsMismatchedPinnedServerCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server must not be contacted when -server-ca does not match its actual certificate")
	}))
	defer srv.Close()

	t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
	wrongCAPath := writePEMCert(t, unrelatedSelfSignedCert(t))
	policyPath := policyFileFixture(t)

	rc, _, stderr := captureOutput(t, func() int {
		return runRunnerEnrollToken([]string{
			"-host", "h1", "-policy", policyPath, "-server", srv.URL, "-server-ca", wrongCAPath,
		})
	})
	if rc == 0 {
		t.Fatal("runRunnerEnrollToken succeeded against a server whose certificate does not match the pinned -server-ca")
	}
	if !contains(stderr, "certificate") && !contains(stderr, "x509") {
		t.Errorf("stderr does not look like a TLS verification failure: %q", stderr)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (substr == "" || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
