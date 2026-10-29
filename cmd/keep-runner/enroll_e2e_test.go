package main

// This file drives the real, separately-compiled binaries this card ships
// against each other over the network: `keep runner enroll-token` issues a
// token, `keep-runner enroll` redeems it against a real running
// keep-server, and the resulting credential is used to make one real mTLS
// request back — the card's own acceptance criterion (a live run of
// enroll-token, then keep-runner enroll, then an mTLS request), not a
// simulation through httptest or a hand-built mux. It lives in cmd/keep-runner's own
// package (not a separate test/e2e package) because verifying the saved
// credential means calling internal/runner.Load, which the zone-internals
// depguard rule only lets cmd/keep-server and cmd/keep-runner import.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/runner"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// e2eRequiredLogSettings is this file's own literal copy of
// store.RequiredLogSettings plus log_statement and log_min_messages — a
// real keep-server process refuses to serve without them (store.CheckLogSettings)
// — literal, not the package value, so a change to what's required still
// has to be reflected here to pass.
var e2eRequiredLogSettings = map[string]string{
	"log_error_verbosity":         "terse",
	"log_min_error_statement":     "panic",
	"log_statement":               "'none'",
	"log_min_duration_statement":  "-1",
	"log_min_duration_sample":     "-1",
	"log_transaction_sample_rate": "0",
	"log_min_messages":            "fatal",
}

type e2eSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *e2eSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *e2eSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func e2eFreeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func buildBinary(t *testing.T, importPath, name string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, importPath) //nolint:gosec // G204: fixed module import path, not external input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", importPath, err, out)
	}
	return bin
}

func e2eWaitForListening(t *testing.T, out *e2eSyncBuffer, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "listening") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("keep-server did not report listening within %s: %q", timeout, out.String())
}

func e2eCSR(t *testing.T, host string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}, PublicKey: pub}, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}

// TestRunnerEnrollmentLiveRoundTrip is the card's acceptance criterion:
// enroll-token → keep-runner enroll → a real mTLS request, run against the
// actual compiled binaries and a real Postgres, not a simulation.
func TestRunnerEnrollmentLiveRoundTrip(t *testing.T) {
	serverBin := buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep-server", "keep-server")
	keepBin := buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep", "keep")
	runnerBin := buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep-runner", "keep-runner")

	dsn := pgscratch.New(t, e2eRequiredLogSettings)
	migrateCmd := exec.Command(serverBin, "migrate", "up") //nolint:gosec // G204: serverBin is this test's own build output
	migrateCmd.Env = append(os.Environ(), "KEEP_DATABASE_URL="+dsn)
	if out, err := migrateCmd.CombinedOutput(); err != nil {
		t.Fatalf("migrate up: %v\n%s", err, out)
	}
	// pgscratch.New's admin connection is a superuser in CI (see pgscratch's
	// doc) — keep-server refuses to serve as one (store.CheckNotSuperuser),
	// so the actual server process runs as the non-superuser role instead;
	// only migrate and this test's own seeding keep using the admin dsn.
	roleDSN := pgscratch.NewRole(t, dsn, "keep_app")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer pool.Close()

	org, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, "org-"+org.String()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	admin, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)`, admin, org, "admin@example.test"); err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	membership, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1, $2, $3, $4, $5)`,
		membership, org, admin, tenancy.Org(org).String(), string(identity.RoleAdmin)); err != nil {
		t.Fatalf("seed admin membership: %v", err)
	}

	idr := identity.NewRepo(pool)
	adminIssued, err := idr.Issue(ctx, identity.IssueParams{OrgID: org, Kind: identity.KindUser, PrincipalID: admin, Scope: tenancy.Org(org).String()})
	if err != nil {
		t.Fatalf("issue admin token: %v", err)
	}
	// Consume the same one-time wire response as a client; token internals
	// remain readable only inside internal/identity.
	adminWire, err := adminIssued.Response().WireJSON()
	if err != nil {
		t.Fatal("encode test administrator issuance")
	}
	var adminCredential struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(adminWire, &adminCredential); err != nil {
		t.Fatal("decode test administrator issuance")
	}
	adminToken := adminCredential.Token

	host := "e2e-runner.example.test"
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"version":1,"targets":[],"max_deploys_per_hour":1}`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	credDir := filepath.Join(dir, "cred")

	httpAddr := e2eFreeAddr(t)
	runnerAddr := e2eFreeAddr(t)
	procCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverCmd := exec.CommandContext(procCtx, serverBin) //nolint:gosec // G204: serverBin is this test's own build output
	rootKey := make([]byte, 32)
	if _, err := rand.Read(rootKey); err != nil {
		t.Fatal("generate synthetic root")
	}
	rootFile := filepath.Join(t.TempDir(), "root-key")
	encodedRoot := make([]byte, base64.StdEncoding.EncodedLen(len(rootKey)))
	base64.StdEncoding.Encode(encodedRoot, rootKey)
	clear(rootKey)
	if err := os.WriteFile(rootFile, encodedRoot, 0600); err != nil {
		t.Fatal("write synthetic root")
	}
	clear(encodedRoot)
	serverCmd.Env = append(os.Environ(),
		"KEEP_ROOT_KEY_FILE="+rootFile,
		"KEEP_DATABASE_URL="+roleDSN,
		"KEEP_HTTP_ADDR="+httpAddr,
		"KEEP_RUNNER_ADDR="+runnerAddr,
		"KEEP_DEV_EPHEMERAL_TLS=1",
	)
	var serverOut e2eSyncBuffer
	serverCmd.Stdout = &serverOut
	serverCmd.Stderr = &serverOut
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start keep-server: %v", err)
	}
	defer func() {
		cancel()
		_ = serverCmd.Wait()
	}()
	e2eWaitForListening(t, &serverOut, 60*time.Second)

	serverURL := "https://" + runnerAddr

	// Step 1: admin issues a one-time enrollment token via the real `keep`
	// binary.
	issueCmd := exec.Command(keepBin, "runner", "enroll-token", //nolint:gosec // G204: keepBin is this test's own build output
		"-host", host, "-policy", policyPath, "-server", serverURL, "-ttl", "1m", "-insecure-skip-verify")
	issueCmd.Env = append(os.Environ(), "KEEP_ADMIN_TOKEN="+adminToken)
	var issueStdout, issueStderr bytes.Buffer
	issueCmd.Stdout = &issueStdout
	issueCmd.Stderr = &issueStderr
	if err := issueCmd.Run(); err != nil {
		t.Fatalf("keep runner enroll-token: %v\nstderr: %s", err, issueStderr.String())
	}
	token := strings.TrimSpace(issueStdout.String())
	if token == "" {
		t.Fatalf("keep runner enroll-token printed no token; stderr: %s", issueStderr.String())
	}
	tokenCanary := canary.Of(token)
	// A leak of just the random suffix, without the constant "keep_renr_"
	// prefix, would not contain the whole-token canary's base string —
	// probe the suffix on its own too.
	suffixCanary := canary.Of(strings.TrimPrefix(token, "keep_renr_"))

	// Step 2: the runner redeems the token via the real `keep-runner`
	// binary, key pair generated on this host, only the CSR leaving it.
	enrollCmd := exec.Command(runnerBin, "enroll", //nolint:gosec // G204: runnerBin is this test's own build output
		"-host", host, "-server", serverURL, "-policy", policyPath, "-cred-dir", credDir, "-insecure-skip-verify")
	enrollCmd.Stdin = strings.NewReader(token + "\n")
	var enrollStdout, enrollStderr bytes.Buffer
	enrollCmd.Stdout = &enrollStdout
	enrollCmd.Stderr = &enrollStderr
	if err := enrollCmd.Run(); err != nil {
		t.Fatalf("keep-runner enroll: %v\nstderr: %s", err, enrollStderr.String())
	}

	// The token must never appear anywhere except keep's own sanctioned
	// stdout disclosure to the admin and the exact bytes this test itself
	// piped into keep-runner's stdin — not in keep-runner's own output, and
	// not in keep-server's process output either.
	if tokenCanary.In(enrollStdout.String()) || suffixCanary.In(enrollStdout.String()) ||
		tokenCanary.In(enrollStderr.String()) || suffixCanary.In(enrollStderr.String()) {
		t.Error("enrollment token leaked into keep-runner's own output")
	}
	if tokenCanary.In(serverOut.String()) || suffixCanary.In(serverOut.String()) {
		t.Error("enrollment token leaked into keep-server's own process output")
	}

	// keep-runner's own rejection path, run against the real binary: the
	// token is now redeemed, so a second enroll with the same token must
	// fail, and its failure output (exactly where an unsanitized wrapped
	// error is most likely to slip a raw value) must not leak it either.
	reuseCredDir := filepath.Join(t.TempDir(), "runner-cred-reuse")
	reuseCmd := exec.Command(runnerBin, "enroll", //nolint:gosec // G204: runnerBin is this test's own build output
		"-host", host, "-server", serverURL, "-policy", policyPath, "-cred-dir", reuseCredDir, "-insecure-skip-verify")
	reuseCmd.Stdin = strings.NewReader(token + "\n")
	var reuseStdout, reuseStderr bytes.Buffer
	reuseCmd.Stdout = &reuseStdout
	reuseCmd.Stderr = &reuseStderr
	if err := reuseCmd.Run(); err == nil {
		t.Fatal("keep-runner enroll succeeded on a reused enrollment token")
	}
	if tokenCanary.In(reuseStdout.String()) || suffixCanary.In(reuseStdout.String()) ||
		tokenCanary.In(reuseStderr.String()) || suffixCanary.In(reuseStderr.String()) {
		t.Error("enrollment token leaked into keep-runner's token-reuse rejection output")
	}

	cred, err := runner.Load(credDir)
	if err != nil {
		t.Fatalf("load enrolled credential: %v", err)
	}
	if cred.Host != host {
		t.Fatalf("credential host = %q, want %q", cred.Host, host)
	}
	if len(cred.CertDER) == 0 || len(cred.CACertDER) == 0 || len(cred.SignPubKey) == 0 {
		t.Fatal("credential is missing certificate or key material")
	}
	for _, name := range []string{"runner_key.pem", "runner_cert.der", "org_ca.der"} {
		fi, err := os.Stat(filepath.Join(credDir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %o, want 0600", name, fi.Mode().Perm())
		}
	}

	// The real runner process checks secure local state before operation.
	check := func() error {
		cmd := exec.Command(runnerBin, "check", "-cred-dir", credDir, "-policy", policyPath) //nolint:gosec // Test-built binary and fixture paths.
		return cmd.Run()
	}
	if err := check(); err != nil {
		t.Fatal("runner rejected its freshly enrolled credential")
	}
	keyPath := filepath.Join(credDir, "runner_key.pem")
	if err := os.Chmod(keyPath, 0o644); err != nil { //nolint:gosec // Deliberately insecure fixture for rejection test.
		t.Fatal("widen key fixture permissions")
	}
	if err := check(); err == nil {
		t.Fatal("runner process accepted a mode 0644 private key")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal("restore key permissions")
	}
	if err := check(); err != nil {
		t.Fatal("runner still rejected credential after restoring mode 0600")
	}

	// Step 3: a real mTLS request using the credential keep-runner just
	// saved — the live round trip's final leg. renew presents the
	// enrolled client certificate; the server must accept it and resolve
	// org/runner/host from the certificate alone.
	clientCert := tls.Certificate{Certificate: [][]byte{cred.CertDER}, PrivateKey: cred.Key}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{clientCert},
				InsecureSkipVerify: true, //nolint:gosec // G402: this test's own client trusts the ephemeral dev listener cert, same as keep-runner enroll's -insecure-skip-verify above
			},
		},
	}
	renewCSR := e2eCSR(t, host)
	renewBody, err := json.Marshal(map[string]any{"csr": renewCSR})
	if err != nil {
		t.Fatalf("marshal renew body: %v", err)
	}
	resp, err := client.Post(serverURL+"/runners/renew", "application/json", bytes.NewReader(renewBody))
	if err != nil {
		t.Fatalf("mTLS renew request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("renew: status = %d: %s", resp.StatusCode, respBody)
	}
	var renewRes struct {
		RunnerID string `json:"runner_id"`
	}
	if err := json.Unmarshal(respBody, &renewRes); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	if renewRes.RunnerID == "" {
		t.Fatal("renew response carries no runner_id")
	}

	cancel()
	_ = serverCmd.Wait()
	if tokenCanary.In(serverOut.String()) || suffixCanary.In(serverOut.String()) {
		t.Error("enrollment token leaked into keep-server's own process output after the full flow")
	}
}
