package main

import (
	"crypto/ecdh"
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
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// testTokenFixture is a fixture value, never a real credential — no live
// server issued it and nothing in Keep treats it as a secret to redact.
const testTokenFixture = "keep_renr_testfixturetestfixturetestfixture" //nolint:gosec // G101: a fixture value, never a real credential — no live server issued it

func captureEnrollOutput(t *testing.T, stdin string, fn func() int) (rc int, stdout, stderr string) {
	t.Helper()
	origOut, origErr, origIn := os.Stdout, os.Stderr, os.Stdin
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr, os.Stdin = outW, errW, inR
	t.Cleanup(func() { os.Stdout, os.Stderr, os.Stdin = origOut, origErr, origIn })

	go func() {
		_, _ = io.WriteString(inW, stdin)
		_ = inW.Close()
	}()

	rc = fn()
	_ = outW.Close()
	_ = errW.Close()
	outBytes, _ := io.ReadAll(outR)
	errBytes, _ := io.ReadAll(errR)
	os.Stdout, os.Stderr, os.Stdin = origOut, origErr, origIn
	return rc, string(outBytes), string(errBytes)
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
// signed nothing real — used as a deliberately wrong -server-ca pin.
// httptest.NewTLSServer's own certificate is a single fixed value shared by
// every httptest server in the process (net/http/httptest's own
// LocalhostCert), so a second httptest.NewTLSServer would present the exact
// same certificate and could never prove a mismatch is rejected.
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

func enrollPolicyFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"argv_templates":[]}`), 0o600); err != nil {
		t.Fatalf("write policy fixture: %v", err)
	}
	return path
}

// TestEnrollRejectsNonHTTPSServer is this fix's own red run: an http://
// -server must be refused before the enrollment token (read from stdin,
// never touched otherwise) or the CSR ever go on the wire in the clear
// (card's leak-review finding: neither was checked before).
func TestEnrollRejectsNonHTTPSServer(t *testing.T) {
	rc, _, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
		return runEnroll([]string{
			"-host", "h1", "-policy", enrollPolicyFixture(t), "-server", "http://127.0.0.1:1",
			"-cred-dir", t.TempDir(),
		})
	})
	if rc == 0 {
		t.Fatal("runEnroll accepted an http:// -server")
	}
	if !strings.Contains(stderr, "https://") {
		t.Errorf("stderr does not explain the https requirement: %q", stderr)
	}
}

// TestEnrollDoesNotFollowRedirectToPlainHTTP reproduces keep-leak-reviewer's
// [high] finding directly: a TLS listener answering -server redirects to a
// second, plain-http listener. Before the fix, net/http's default client
// followed it and resent the same POST — including the enrollment token and
// the CSR in the body — to that second origin. The fix (CheckRedirect
// returning http.ErrUseLastResponse) must mean the second listener is never
// contacted at all.
func TestEnrollDoesNotFollowRedirectToPlainHTTP(t *testing.T) {
	plainHitCount := 0
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHitCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/runners/enroll", http.StatusTemporaryRedirect)
	}))
	defer tlsSrv.Close()

	tokenCanary := canary.Of(testTokenFixture)

	rc, stdout, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
		return runEnroll([]string{
			"-host", "h1", "-policy", enrollPolicyFixture(t), "-server", tlsSrv.URL,
			"-cred-dir", t.TempDir(), "-insecure-skip-verify",
		})
	})
	if rc == 0 {
		t.Fatal("runEnroll succeeded against a server that only ever redirects")
	}
	if plainHitCount != 0 {
		t.Fatalf("the plain-http redirect target was contacted %d time(s) — the enrollment token/CSR were resent to it", plainHitCount)
	}
	if tokenCanary.In(stdout) || tokenCanary.In(stderr) {
		t.Error("enrollment token leaked into this command's own output")
	}
}

// TestEnrollTrustsPinnedServerCA is the leak-review's own finding, turned
// into a positive red-run test: -server-ca (and KEEP_SERVER_CA) exist so an
// operator has a pinning option for the one request that has no
// organization CA yet to trust anything against — enrollment itself.
// Without -server-ca, this server's self-signed certificate (not from any
// CA the OS trust store recognizes) would be refused unless
// -insecure-skip-verify were set, which trusts everything.
func TestEnrollTrustsPinnedServerCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(runnerEnrollResponse{
			RunnerID:      "11111111-1111-1111-1111-111111111111",
			Certificate:   []byte("leaf-der-fixture"),
			CACertificate: []byte("ca-der-fixture"),
			SignKeyID:     "test-sign-key",
			SignPubKey:    []byte("pub-fixture"),
			NotAfter:      time.Now().Add(time.Hour),
		})
	}))
	defer srv.Close()

	caPath := writePEMCert(t, srv.Certificate())

	rc, _, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
		return runEnroll([]string{
			"-host", "h1", "-policy", enrollPolicyFixture(t), "-server", srv.URL,
			"-cred-dir", t.TempDir(), "-server-ca", caPath,
		})
	})
	if rc != 0 {
		t.Fatalf("runEnroll with a correctly pinned -server-ca failed: rc=%d stderr=%q", rc, stderr)
	}
}

func TestEnrollRegistersLocalDeliveryPublicKey(t *testing.T) {
	var deliveredPublic []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			HPKEPublicKey []byte `json:"hpke_public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error("decode enrollment request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		deliveredPublic = body.HPKEPublicKey
		_ = json.NewEncoder(w).Encode(runnerEnrollResponse{
			RunnerID: "11111111-1111-1111-1111-111111111111", Certificate: []byte("fixture"),
			CACertificate: []byte("fixture"), SignKeyID: "fixture", SignPubKey: make([]byte, 32),
			NotAfter: time.Now().Add(time.Hour),
		})
	}))
	defer srv.Close()
	dir := t.TempDir()
	rc, stdout, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
		return runEnroll([]string{"-host", "h1", "-policy", enrollPolicyFixture(t),
			"-server", srv.URL, "-cred-dir", dir, "-insecure-skip-verify"})
	})
	if rc != 0 {
		t.Fatal("enrollment failed")
	}
	privateBytes, err := os.ReadFile(filepath.Join(dir, "runner_delivery.key")) //nolint:gosec // G304: the path is this test's temporary credential directory and fixed filename
	if err != nil {
		t.Fatal("delivery key was not saved")
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil || string(private.PublicKey().Bytes()) != string(deliveredPublic) {
		t.Fatal("registered public key does not match local private key")
	}
	if canary.Of(string(privateBytes)).In(stdout) || canary.Of(string(privateBytes)).In(stderr) {
		t.Fatal("delivery private key escaped into runner output")
	}
}

// TestEnrollRejectsMismatchedPinnedServerCA is this finding's own red run:
// -server-ca pointed at a CA that did not sign the server's actual
// certificate must refuse the connection — never fall back to trusting it
// anyway — and the target server's handler must never even run.
func TestEnrollRejectsMismatchedPinnedServerCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server must not be contacted when -server-ca does not match its actual certificate")
	}))
	defer srv.Close()

	wrongCAPath := writePEMCert(t, unrelatedSelfSignedCert(t))

	rc, _, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
		return runEnroll([]string{
			"-host", "h1", "-policy", enrollPolicyFixture(t), "-server", srv.URL,
			"-cred-dir", t.TempDir(), "-server-ca", wrongCAPath,
		})
	})
	if rc == 0 {
		t.Fatal("runEnroll succeeded against a server whose certificate does not match the pinned -server-ca")
	}
	if !strings.Contains(stderr, "certificate") && !strings.Contains(stderr, "x509") {
		t.Errorf("stderr does not look like a TLS verification failure: %q", stderr)
	}
}
