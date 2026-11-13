package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/runner"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

const goodRunnerID = "11111111-1111-1111-1111-111111111111"

func runnerIDServer(t *testing.T, runnerID string) *httptest.Server {
	t.Helper()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CSR []byte `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(body.CSR)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: runnerID},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, csr.PublicKey, caPriv)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(runnerEnrollResponse{
			RunnerID: runnerID, Certificate: der,
			CACertificate: caDER, SignKeyID: "orgsign_0123456789abcdef", SignPubKey: make([]byte, 32),
			NotAfter: time.Now().Add(time.Hour),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A server must not be able to turn the success line into a reflection
// channel: runner_id is accepted only as a canonical UUID, refused with a
// static line before anything is saved or printed.
func TestEnrollSuccessMetadataRejectsNonUUIDRunnerID(t *testing.T) {
	c := canary.New()
	if !c.In("x "+c.Value(1)) || !c.In(strings.Repeat("a", 3)+c.Value(2)) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	// The one in-memory token: sent on stdin AND reflected back as runner_id.
	token := c.Value(5)
	cases := map[string]string{
		"reflected-token":  token,
		"canary":           c.Value(1),
		"long":             c.Value(2) + strings.Repeat("a", 5000),
		"control-chars":    c.Value(3) + "\x1b[31m\r\n\x00",
		"empty":            "",
		"uuid-plus-suffix": goodRunnerID + c.Value(4),
		"uuid-braced":      "{" + goodRunnerID + "}",
		"uuid-urn":         "urn:uuid:" + goodRunnerID,
		"uuid-uppercase":   strings.ToUpper("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		"uuid-no-dashes":   strings.ReplaceAll(goodRunnerID, "-", ""),
		"uuid-padded":      " " + goodRunnerID,
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			srv := runnerIDServer(t, id)
			dir := filepath.Join(t.TempDir(), "cred")
			rc, stdout, stderr := captureEnrollOutput(t, token+"\n", func() int {
				return runEnroll([]string{"-host", "h1", "-policy", enrollPolicyFixture(t),
					"-server", srv.URL, "-cred-dir", dir, "-server-ca", writePEMCert(t, srv.Certificate())})
			})
			if rc == 0 {
				t.Fatalf("enroll succeeded with an invalid runner_id")
			}
			if strings.Contains(stdout, "enrolled:") || strings.Contains(stdout, "runner_id=") {
				t.Errorf("success line printed (stdout %d bytes)", len(stdout))
			}
			if _, err := os.Stat(dir); err == nil {
				t.Errorf("credential directory was created")
			}
			for _, out := range []string{stdout, stderr} {
				if c.In(out) || strings.Contains(out, token) || strings.Contains(out, "\x1b") || strings.Contains(out, goodRunnerID) {
					t.Errorf("response value reached the terminal (%d bytes)", len(out))
				}
			}
			if !strings.Contains(stderr, "runner_id is not a valid UUID") {
				t.Errorf("stderr lacks the static diagnostic (%d bytes)", len(stderr))
			}
		})
	}
}

// Positive control: the real built CLI enrolls against a canonical UUID,
// prints it, and runner.Load reads the saved credential.
func TestEnrollSuccessMetadataUUIDBuiltCLI(t *testing.T) {
	bin := buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep-runner", "keep-runner")
	srv := runnerIDServer(t, goodRunnerID)
	dir := filepath.Join(t.TempDir(), "cred")
	cmd := exec.Command(bin, "enroll", "-host", "h1", "-policy", enrollPolicyFixture(t), //nolint:gosec // G204: binary built by this test
		"-server", srv.URL, "-cred-dir", dir, "-server-ca", writePEMCert(t, srv.Certificate()))
	cmd.Stdin = strings.NewReader(testTokenFixture + "\n")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("built CLI enroll failed: %v (stderr %d bytes)", err, errb.Len())
	}
	if !strings.Contains(out.String(), "enrolled: runner_id="+goodRunnerID+"\n") {
		t.Fatalf("success line missing (stdout %d bytes)", out.Len())
	}
	if _, err := runner.Load(dir); err != nil {
		t.Fatalf("runner.Load rejected the saved credential: %v", err)
	}
}
