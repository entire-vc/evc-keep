//go:build unix

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/entire-vc/evc-keep/internal/runner"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// prefixHost is a credential, a real target directory and a symlink to it.
type prefixHost struct {
	base, credDir, realDir, link string
}

func newPrefixHost(t *testing.T) prefixHost {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := prefixHost{base: base, credDir: filepath.Join(base, "cred"), realDir: filepath.Join(base, "real"), link: filepath.Join(base, "link")}
	if err := os.Mkdir(h.realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.realDir, h.link); err != nil {
		t.Fatal(err)
	}
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	ca, _ := x509.ParseCertificate(caDER)
	rpub, rpriv, _ := ed25519.GenerateKey(rand.Reader)
	certTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{Organization: []string{uuid.NewString()}, CommonName: uuid.NewString()},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, ca, rpub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := runner.Save(h.credDir, runner.Credential{Key: rpriv, DeliveryKey: delivery, CertDER: certDER, CACertDER: caDER,
		SignKeyID: "org1", SignPubKey: spub, Host: "h1"}); err != nil {
		t.Fatal(err)
	}
	return h
}

// policy writes a host policy with one file rule under prefix.
func (h prefixHost) policy(t *testing.T, name, prefix string) string {
	t.Helper()
	b, err := json.Marshal(runnerproto.HostPolicy{Version: 1, AgentUIDs: []int64{1}, MaxDeploysPerHour: 1,
		Targets: []runnerproto.TargetRule{{Kind: runnerproto.TargetFile, PathPrefixes: []string{prefix}}}})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(h.base, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The built keep-runner check refuses a prefix through a symlink and names
// the component; the same prefix by its real path passes.
func TestCheckRefusesSymlinkPrefixEndToEnd(t *testing.T) {
	bin := buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep-runner", "keep-runner")
	h := newPrefixHost(t)
	check := func(policy string) (int, string) {
		var out bytes.Buffer
		cmd := exec.Command(bin, "check", "-cred-dir", h.credDir, "-policy", policy) //nolint:gosec // G204: this test's own build output and fixture paths
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		if err == nil {
			return 0, out.String()
		}
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		return ee.ExitCode(), out.String()
	}

	code, out := check(h.policy(t, "real.json", filepath.Join(h.realDir, "ext")))
	if code != 0 || !strings.Contains(out, "credential and local policy verified") {
		t.Fatalf("real path: code=%d out=%q", code, out)
	}
	code, out = check(h.policy(t, "link.json", filepath.Join(h.link, "ext")))
	if code == 0 {
		t.Fatalf("symlink prefix: exit 0, out=%q", out)
	}
	if !strings.Contains(out, `component "`+h.link+`" is a symlink`) {
		t.Fatalf("symlink prefix: stderr does not name the component: %q", out)
	}
}

// keep-runner run only warns about such a prefix: the other rules still
// work, so the start goes on to the poll.
func TestRunWarnsOnSymlinkPrefix(t *testing.T) {
	h := newPrefixHost(t)
	pol := h.policy(t, "link.json", filepath.Join(h.link, "ext"))
	code, out := capture(t, func() int {
		return run([]string{"run", "-once", "-cred-dir", h.credDir, "-policy", pol, "-server", "https://127.0.0.1:1", "-state-dir", filepath.Join(h.base, "state")})
	})
	if code != 1 || !strings.Contains(out, "poll or result send failed") {
		t.Fatalf("run stopped before the poll: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "policy_prefix_not_plain") {
		t.Fatalf("no warning: %q", out)
	}
	if strings.Contains(out, h.link) {
		t.Fatalf("log carries the path outside the closed key set: %q", out)
	}
	// Positive control: the real path starts without the warning.
	pol = h.policy(t, "real.json", filepath.Join(h.realDir, "ext"))
	code, out = capture(t, func() int {
		return run([]string{"run", "-once", "-cred-dir", h.credDir, "-policy", pol, "-server", "https://127.0.0.1:1", "-state-dir", filepath.Join(h.base, "state2")})
	})
	if code != 1 || strings.Contains(out, "policy_prefix_not_plain") {
		t.Fatalf("real path: code=%d out=%q", code, out)
	}
}
