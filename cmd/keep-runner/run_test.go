//go:build unix

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/runner"
	"github.com/entire-vc/evc-keep/internal/runner/execrun"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/execpolicy"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// capture runs fn with stderr and stdout redirected and returns what was printed.
func capture(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	code := fn()
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = w.Close()
	return code, <-done
}

// No refusal of the run command or of the dispatcher echoes an argument.
func TestRunCommandNeverReflectsArguments(t *testing.T) {
	c := canary.New().Value(1)
	for name, args := range map[string][]string{
		"unknown-command": {c},
		"unknown-flag":    {"run", "-" + c},
		"flag-value":      {"run", "-policy", "/nonexistent/" + c, "-server", "https://" + c + ".invalid", "-cred-dir", "/nonexistent/" + c},
		"positional":      {"run", c},
		"bad-server":      {"run", "-policy", "/" + c, "-server", "http://" + c},
		"bad-ca":          {"run", "-policy", "/" + c, "-server", "https://x.invalid", "-server-ca", "/" + c},
	} {
		code, out := capture(t, func() int { return run(args) })
		if code == 0 {
			t.Fatalf("%s: exit 0", name)
		}
		if strings.Contains(out, c) || strings.Contains(out, "nonexistent") {
			t.Fatalf("%s: output reflects an argument: %q", name, out)
		}
	}
	// Positive control: the detector sees the canary when it is printed.
	if _, out := capture(t, func() int { _, _ = os.Stderr.WriteString(c); return 0 }); !strings.Contains(out, c) {
		t.Fatal("capture does not see stderr")
	}
}

func TestRunRefusesWideCredentialAndPolicy(t *testing.T) {
	dir := t.TempDir()
	code, out := capture(t, func() int {
		return run([]string{"run", "-cred-dir", dir, "-policy", filepath.Join(dir, "p"), "-server", "https://x.invalid"})
	})
	if code != 1 || !strings.Contains(out, "credential is missing or insecure") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

// One job end to end through the binary's own entry point: mTLS, signature,
// policy, HPKE value, target write, closed result, empty outbox.
func TestRunOnceEndToEnd(t *testing.T) {
	runOnceEndToEnd(t, canary.New().Value(1), true)
}

// A valid builtin value is 0 bytes to 1 MiB; both ends must reach the target
// through the real CLI, mTLS listener and HPKE envelope.
func TestRunOnceValueSizes(t *testing.T) {
	for name, size := range map[string]int{"empty": 0, "64k": 64 << 10, "max": 1 << 20} {
		t.Run(name, func(t *testing.T) { runOnceEndToEnd(t, strings.Repeat("x", size), false) })
	}
}

func runOnceEndToEnd(t *testing.T, value string, probeCanary bool) {
	t.Helper()
	runOnce(t, value, probeCanary, nil)
}

// An exec_with_secret job through the same entry point: the flags, the
// policy's templates and the host's side of the isolation reach the loop, and
// the child sees the value in its environment and nowhere else.
func TestRunOnceExecEndToEnd(t *testing.T) {
	runOnce(t, canary.New().Value(1), true, &execOpts{})
}

// execOpts makes the job an exec job. flags builds the exec flags from the
// home directory (default: a valid set); refuse, when set, expects the runner
// to stop at start with that message instead of running the job.
type execOpts struct {
	flags  func(home string) []string
	refuse string
}

// A policy that allows exec cannot start the runner without the account and
// the home the children run in.
func TestRunRefusesExecPolicyWithoutChildAccount(t *testing.T) {
	for name, c := range map[string]struct {
		flags  func(home string) []string
		refuse string
	}{
		"no-flags": {func(string) []string { return nil }, "-exec-uid and -exec-gid are required"},
		"no-home":  {func(string) []string { return []string{"-exec-uid", "1234", "-exec-gid", "1234"} }, "-exec-home is required"},
		"uid-0": {func(h string) []string { return []string{"-exec-uid", "0", "-exec-gid", "1234", "-exec-home", h} },
			"-exec-uid and -exec-gid are required"},
		"gid-0": {func(h string) []string { return []string{"-exec-uid", "1234", "-exec-gid", "0", "-exec-home", h} },
			"-exec-uid and -exec-gid are required"},
		"missing-home": {func(h string) []string {
			return []string{"-exec-uid", "1234", "-exec-gid", "1234", "-exec-home", h + "-nope"}
		}, "exec home is unusable"},
	} {
		t.Run(name, func(t *testing.T) { runOnce(t, "v", false, &execOpts{flags: c.flags, refuse: c.refuse}) })
	}
}

// runOnce serves one signed job to `keep-runner run -once`; execJob makes it
// an exec_with_secret job instead of a deploy.
// passIso stands in for the kernel: it enforces every mode and wraps nothing.
type passIso struct{}

func (passIso) Enforces(execpolicy.NetMode) bool { return true }
func (passIso) Prepare(execpolicy.NetMode, []execrun.Pin) ([]string, func(), error) {
	return []string{"/usr/bin/env"}, func() {}, nil
}

func runOnce(t *testing.T, value string, probeCanary bool, ex *execOpts) {
	if ex != nil {
		old := newIsolator
		newIsolator = func(uint32, uint32) execrun.Isolator { return passIso{} }
		t.Cleanup(func() { newIsolator = old })
		execCorePiped = func() bool { return false }
		execChown = func(string, int, int) error { return nil }
		t.Cleanup(func() { execCorePiped, execChown = nil, nil })
	}
	t.Helper()
	execJob := ex != nil
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	credDir := filepath.Join(base, "cred")
	targetDir := filepath.Join(base, "target")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	orgID, runnerID := uuid.NewString(), uuid.NewString()
	rpub, rpriv, _ := ed25519.GenerateKey(rand.Reader)
	certTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{Organization: []string{orgID}, CommonName: runnerID},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, ca, rpub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spub, spriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := runner.Save(credDir, runner.Credential{Key: rpriv, DeliveryKey: delivery, CertDER: certDER, CACertDER: caDER,
		SignKeyID: "org1", SignPubKey: spub, Host: "h1"}); err != nil {
		t.Fatal(err)
	}

	policy := runnerproto.HostPolicy{Version: 1, AgentUIDs: []int64{1}, AgentGIDs: []int64{1}, MaxDeploysPerHour: 5,
		Targets: []runnerproto.TargetRule{{Kind: runnerproto.TargetEnvFile, PathPrefixes: []string{targetDir}, Fields: []string{"STRIPE_KEY"}}}}
	marker := filepath.Join(base, "marker")
	var execArgs []string
	var tpl execpolicy.Template
	if execJob {
		bin := filepath.Join(base, "bin")
		home := filepath.Join(base, "home")
		for _, d := range []string{bin, home} {
			if err := os.Mkdir(d, 0o755); err != nil { //nolint:gosec // G301: the child may have to enter them
				t.Fatal(err)
			}
		}
		tool := filepath.Join(bin, "tool")
		body := "#!/bin/sh\nprintf '%s:%s' \"$2\" \"${#TOOL_KEY}\" > " + marker + "\n"
		if err := os.WriteFile(tool, []byte(body), 0o755); err != nil { //nolint:gosec // G306: a test executable
			t.Fatal(err)
		}
		if err := os.Chmod(tool, 0o755); err != nil { //nolint:gosec // G302: a test executable
			t.Fatal(err)
		}
		if err := os.WriteFile(marker, nil, 0o666); err != nil { //nolint:gosec // G306: the child may run as another account
			t.Fatal(err)
		}
		if err := os.Chmod(marker, 0o666); err != nil { //nolint:gosec // G302: as above
			t.Fatal(err)
		}
		policy.AllowExec, policy.ExecNetUnenforced = true, true
		policy.ExecBinDirs = []string{bin}
		policy.ExecTemplates = []runnerproto.ExecTemplate{{
			ID: "tool-run", Argv: []string{tool, "--name", "{name}"},
			Params:    map[string]runnerproto.ExecParam{"name": {Pattern: `^[a-z0-9]{1,32}$`}},
			SecretEnv: []string{"TOOL_KEY"}, Network: runnerproto.ExecNetwork{Mode: "none"},
		}}
		var err error
		if tpl, err = policy.ExecTemplates[0].Template(); err != nil {
			t.Fatal(err)
		}
		// An account of its own: never the runner's.
		uid := 65534
		if os.Geteuid() == uid {
			uid = 65533
		}
		execArgs = []string{"-exec-uid", strconv.Itoa(uid), "-exec-gid", strconv.Itoa(uid), "-exec-home", home}
		if ex.flags != nil {
			execArgs = ex.flags(home)
		}
	}
	pb, _ := json.Marshal(policy)
	policyPath := filepath.Join(base, "policy.json")
	if err := os.WriteFile(policyPath, pb, 0o600); err != nil {
		t.Fatal(err)
	}

	key, _ := fingerprint.GenerateKey("store1")
	fp, _ := fingerprint.Compute(key, secret.New([]byte(value)))
	jobID, _ := uuid.NewV7()
	now := time.Now().Truncate(time.Second)
	job := runnerproto.Job{JobID: jobID.String(), OrgID: orgID, RunnerID: runnerID,
		Secret:          runnerproto.SecretRef{StoreID: "store-1", Provider: runnerproto.ProviderBuiltin, Name: "stripe/api-key", Scope: "prod"},
		ExpectedVersion: "7", ExpectedFingerprint: fp, Action: runnerproto.ActionDeploy,
		Target:   runnerproto.Target{Kind: runnerproto.TargetEnvFile, Path: filepath.Join(targetDir, "app.env"), Field: "STRIPE_KEY", Mode: 0o600, UID: int64(os.Geteuid()), GID: int64(os.Getegid())},
		IssuedAt: now, NotAfter: now.Add(5 * time.Minute), Nonce: bytes.Repeat([]byte{9}, runnerproto.NonceSize)}
	if execJob {
		job.Action, job.Target = runnerproto.ActionExec, runnerproto.Target{}
		job.Exec = &runnerproto.Exec{TemplateID: "tool-run", Digest: execpolicy.Digest(tpl), Params: map[string]string{"name": "alpha"}}
	}
	sj, err := runnerproto.Signer{KeyID: "org1", Key: spriv}.Sign(job)
	if err != nil {
		t.Fatal(err)
	}
	env, err := builtin.SealRunnerMaterial(job, delivery.PublicKey().Bytes(), secret.New([]byte(value)), key)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var gotResult []byte
	served := false
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/runners/jobs/next":
			if served {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			served = true
			_ = json.NewEncoder(w).Encode(sj)
		case r.URL.Path == "/runners/jobs/value":
			_ = json.NewEncoder(w).Encode(env)
		case strings.HasSuffix(r.URL.Path, "/result"):
			gotResult, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	caFile := filepath.Join(base, "server-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out := capture(t, func() int {
		return run(append([]string{"run", "-once", "-cred-dir", credDir, "-policy", policyPath, "-server", srv.URL, "-server-ca", caFile, "-state-dir", filepath.Join(base, "state")}, execArgs...))
	})
	if execJob && ex.refuse != "" {
		if code != 1 || !strings.Contains(out, ex.refuse) {
			t.Fatalf("want exit 1 with %q, got %d: %s", ex.refuse, code, out)
		}
		return
	}
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	mu.Lock()
	defer mu.Unlock()
	var res runnerproto.Result
	if err := json.Unmarshal(gotResult, &res); err != nil || !res.OK || res.Fingerprint != fp {
		t.Fatalf("result %q: %v", gotResult, err)
	}
	if execJob {
		if got, _ := os.ReadFile(marker); string(got) != "alpha:"+strconv.Itoa(len(value)) {
			t.Fatalf("the child did not run with the typed parameter and the value: %q", got)
		}
	} else if got, _ := os.ReadFile(job.Target.Path); !strings.Contains(string(got), "STRIPE_KEY="+value) {
		t.Fatal("target not written")
	}
	if probeCanary {
		probe := canary.Of(value)
		if probe.In(out) || probe.In(string(gotResult)) {
			t.Fatal("value reached stderr or the result")
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(base, "state", "outbox")); len(ents) != 0 {
		t.Fatalf("outbox not empty: %d", len(ents))
	}
}
