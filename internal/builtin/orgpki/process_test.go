package orgpki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type processOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (o *processOutput) Write(b []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Write(b)
}
func (o *processOutput) text() string { o.mu.Lock(); defer o.mu.Unlock(); return o.b.String() }

// The test can unseal its own synthetic CA inside the plaintext zone while
// the separate server binary only receives a root-key file and sealed rows.
func TestCAPrivateKeyNeverLeaksInServerProcess(t *testing.T) {
	ctx := context.Background()
	settings := make(map[string]string)
	for k, v := range store.RequiredLogSettings {
		settings[k] = v
	}
	settings["log_statement"] = "'none'"
	settings["log_min_messages"] = "fatal"
	dsn := pgscratch.New(t, settings)
	bin := filepath.Join(t.TempDir(), "keep-server")
	build := exec.Command("go", "build", "-o", bin, "github.com/entire-vc/evc-keep/cmd/keep-server") //nolint:gosec // Fixed module and private test output path.
	if err := build.Run(); err != nil {
		t.Fatal("build server")
	}
	migrate := exec.Command(bin, "migrate", "up") //nolint:gosec // Test-built binary and scratch database.
	migrate.Env = append(os.Environ(), "KEEP_DATABASE_URL="+dsn)
	if err := migrate.Run(); err != nil {
		t.Fatal("migrate scratch database")
	}
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect scratch database")
	}
	defer db.Close()
	org := seedOrg(t, db)
	root := make([]byte, 32)
	// This is synthetic test material, stored only in this test's private directory.
	for i := range root {
		root[i] = byte(i + 1)
	}
	rootFile := filepath.Join(t.TempDir(), "root-key")
	if err := os.WriteFile(rootFile, []byte(base64.StdEncoding.EncodeToString(root)), 0600); err != nil {
		t.Fatal("write root fixture")
	}
	repo, err := NewRepoFromKey(db, "process-test-root", bytes.Clone(root))
	clear(root)
	if err != nil {
		t.Fatal("construct org repository")
	}
	if _, err := repo.Ensure(ctx, org); err != nil {
		t.Fatal("initialize CA")
	}
	key, err := repo.unsealCAKey(ctx, org)
	if err != nil {
		t.Fatal("unseal test CA")
	}
	defer wipe(key)
	probe := canary.Of(string(key))
	encodedProbe := canary.Of(base64.StdEncoding.EncodeToString(key))
	if !probe.In(string(key)) {
		t.Fatal("CA canary control failed")
	}
	admin := uuid.New()
	if _, err := db.Exec(ctx, `INSERT INTO users (id,org_id,email) VALUES ($1,$2,$3)`, admin, org, "process-admin@example.test"); err != nil {
		t.Fatal("seed administrator")
	}
	issued, err := enrolltoken.NewRepo(db).Issue(ctx, enrolltoken.IssueParams{OrgID: org, CreatedBy: admin, Host: "process.example.test", PolicySHA256: "0000000000000000000000000000000000000000000000000000000000000000"})
	if err != nil {
		t.Fatal("issue enrollment token")
	}
	address := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("reserve address")
		}
		addr := l.Addr().String()
		_ = l.Close()
		return addr
	}
	httpAddr, runnerAddr := address(), address()
	procCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(procCtx, bin) //nolint:gosec // Test-built server binary.
	cmd.Env = append(os.Environ(), "KEEP_DATABASE_URL="+pgscratch.NewRole(t, dsn, "keep_app"), "KEEP_HTTP_ADDR="+httpAddr, "KEEP_RUNNER_ADDR="+runnerAddr, "KEEP_ROOT_KEY_FILE="+rootFile, "KEEP_ROOT_KEY_ID=process-test-root", "KEEP_DEV_EPHEMERAL_TLS=1")
	var output processOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal("start server")
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // Loopback test server.
	csr, _ := runnerCSR(t, pkix.Name{})
	body, err := json.Marshal(map[string]any{"token": issued.Token.Reveal(), "host": "process.example.test", "policy_sha256": "0000000000000000000000000000000000000000000000000000000000000000", "csr": csr})
	if err != nil {
		t.Fatal("encode request")
	}
	deadline := time.Now().Add(10 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = client.Post("https://"+runnerAddr+"/runners/enroll", "application/json", bytes.NewReader(body))
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("server did not accept enrollment")
	}
	response, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal("read response")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enrollment status %d", resp.StatusCode)
	}
	if probe.In(string(response)) || encodedProbe.In(string(response)) {
		t.Fatal("CA key leaked into response")
	}
	// Reuse drives an error through the real process as well.
	resp, err = client.Post("https://"+runnerAddr+"/runners/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal("send reuse request")
	}
	errorResponse, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal("read token-reuse error response")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("token reuse was accepted")
	}
	if probe.In(string(errorResponse)) || encodedProbe.In(string(errorResponse)) {
		t.Fatal("CA key leaked into error response")
	}
	cancel()
	_ = cmd.Wait()
	if probe.In(output.text()) || encodedProbe.In(output.text()) {
		t.Fatal("CA key leaked into server stdout/stderr")
	}
}
