package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// syncBuffer is an io.Writer safe for concurrent use by a running process's
// stdout/stderr pipes and this test's own polling reads of the same buffer.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freeAddr reserves an ephemeral TCP port and returns its address, then
// releases it immediately — the small TOCTOU window is the same tradeoff
// every "start a real server on a free port" test in Go accepts.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func processTestCSR(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate runner key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "process-test-runner"}, PublicKey: pub}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}

func waitForListening(t *testing.T, out *syncBuffer, timeout time.Duration) {
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

// TestRunnerEnrollmentTokenNeverLeaksInProcessOutput is the card's red-run
// test #4, process-level half (see the doc on
// internal/builtin/orgpki.TestCAPrivateKeyNeverLeaksThroughReturnValuesOrErrors,
// which points here): the real compiled keep-server binary's own stdout and
// stderr — not just the internal/api handler functions in isolation, which
// TestRunnerRoutesNeverLeakTokenOrCAKey in internal/api already covers —
// must never contain an enrollment token's plaintext, across both a real
// successful enrollment and a real token-reuse rejection.
//
// The CA private key's process-level probe lives inside the plaintext zone
// in orgpki.TestCAPrivateKeyNeverLeaksInServerProcess.
func TestRunnerEnrollmentTokenNeverLeaksInProcessOutput(t *testing.T) {
	bin := buildKeepServer(t)
	// requiredLogSettingsLiteral (main_test.go): a real keep-server process
	// refuses to serve without every setting in it (store.CheckLogSettings).
	dsn := pgscratch.New(t, requiredLogSettingsLiteral)
	migrate(t, bin, dsn)
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

	host := "process-test-runner.example.test"
	policy := hex.EncodeToString(make([]byte, 32))
	tokens := enrolltoken.NewRepo(pool)
	issued, err := tokens.Issue(ctx, enrolltoken.IssueParams{OrgID: org, Host: host, PolicySHA256: policy, CreatedBy: admin})
	if err != nil {
		t.Fatalf("issue enrollment token: %v", err)
	}
	plaintext := issued.Token.Reveal()
	tokenCanary := canary.Of(plaintext)
	// A leak of just the random suffix, without the constant "keep_renr_"
	// prefix, would not contain the whole-token canary's base string —
	// probe the suffix on its own too (canary.Of's own doc: "a value with a
	// recognizable prefix is leaked just as fully by its remainder alone").
	suffixCanary := canary.Of(strings.TrimPrefix(plaintext, "keep_renr_"))

	httpAddr := freeAddr(t)
	runnerAddr := freeAddr(t)

	procCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// bin is buildKeepServer's own output; every address here is either
	// this test's own freeAddr or the scratch DSN, never external input.
	cmd := exec.CommandContext(procCtx, bin) //nolint:gosec // G204
	cmd.Env = append(os.Environ(),
		"KEEP_DATABASE_URL="+roleDSN,
		"KEEP_HTTP_ADDR="+httpAddr,
		"KEEP_RUNNER_ADDR="+runnerAddr,
		"KEEP_ROOT_KEY_FILE="+serverRootKeyFile(t),
		"KEEP_DEV_EPHEMERAL_TLS=1",
	)
	var out syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start keep-server: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	waitForListening(t, &out, 60*time.Second)

	client := &http.Client{
		Timeout: 5 * time.Second,
		// InsecureSkipVerify: this test's own client against the server's
		// ephemeral self-signed listener certificate (serverTLSCert's own
		// doc) — the property under test is the runner CA path, not this
		// unrelated listener certificate's trust chain.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // G402
	}
	url := "https://" + runnerAddr + "/runners/enroll"

	enrollBody, err := json.Marshal(map[string]any{
		"token": plaintext, "host": host, "policy_sha256": policy, "csr": processTestCSR(t),
	})
	if err != nil {
		t.Fatalf("marshal enroll body: %v", err)
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatalf("enroll request: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll: status = %d: %s", resp.StatusCode, respBody)
	}

	// Reuse the same token — the failure path this test also wants
	// exercised, since an error path is exactly where an unsanitized
	// wrapped error is most likely to slip a raw value into a log line.
	resp2, err := client.Post(url, "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatalf("reused-token request: %v", err)
	}
	respBody2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("expected token reuse to be rejected")
	}

	cancel()
	_ = cmd.Wait()

	captured := out.String()
	if tokenCanary.In(captured) || suffixCanary.In(captured) {
		t.Error("enrollment token leaked into server process output")
	}
	if tokenCanary.In(string(respBody)) || suffixCanary.In(string(respBody)) {
		t.Error("enrollment token leaked into enrollment response")
	}
	if tokenCanary.In(string(respBody2)) || suffixCanary.In(string(respBody2)) {
		t.Error("enrollment token leaked into reused-token response")
	}
}
