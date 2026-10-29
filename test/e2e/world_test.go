//go:build e2e

package e2e

// The W2 acceptance world: real keep-server, keep-runner and keep binaries
// over the network and a real PostgreSQL. The test plays three roles that
// never share a channel: the agent (keep CLI with an agent token), the human
// (headless browser on the input link) and the host operator (root of the
// stand, reading files directly).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// logSettings is this file's literal copy of what a real keep-server demands
// of its database (store.CheckLogSettings), kept literal on purpose.
var logSettings = map[string]string{
	"log_error_verbosity":         "terse",
	"log_min_error_statement":     "panic",
	"log_statement":               "'none'",
	"log_min_duration_statement":  "-1",
	"log_min_duration_sample":     "-1",
	"log_transaction_sample_rate": "0",
	"log_min_messages":            "fatal",
}

const secretName = "DEMO_API_KEY" //nolint:gosec // G101: a variable name, not a credential

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

type world struct {
	t          *testing.T
	pool       *pgxpool.Pool
	org        uuid.UUID
	secretID   uuid.UUID
	runnerID   string
	keepBin    string
	agentBin   string // the keep CLI the agent runs: a copy the agent account can execute
	httpAddr   string
	publicURL  string
	agentToken string
	hostDir    string // the directory the runner's host policy admits
	serverOut  *syncBuffer
	runnerOut  *syncBuffer
	enrollOut  *syncBuffer
}

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

func build(t *testing.T, importPath, name string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	out, err := exec.Command("go", "build", "-o", bin, importPath).CombinedOutput() //nolint:gosec // G204: fixed module import path
	if err != nil {
		t.Fatalf("build %s: %v\n%s", importPath, err, out)
	}
	return bin
}

func selfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate listener key")
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "keep-e2e-w2"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create listener certificate")
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal("marshal listener key")
	}
	certPath, keyPath = filepath.Join(dir, "listener.pem"), filepath.Join(dir, "listener-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal("write listener certificate")
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal("write listener key")
	}
	return certPath, keyPath
}

func waitListening(t *testing.T, out *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "listening") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("keep-server did not report listening: %q", out.String())
}

func mustID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal("new id")
	}
	return id
}

// newWorld starts the stand. hostPolicy builds the runner's host policy for
// the admitted directory; the secret DEMO_API_KEY exists with no value yet.
func newWorld(t *testing.T, hostPolicy func(dir string) map[string]any) *world {
	t.Helper()
	serverBin := build(t, "github.com/entire-vc/evc-keep/cmd/keep-server", "keep-server")
	runnerBin := build(t, "github.com/entire-vc/evc-keep/cmd/keep-runner", "keep-runner")
	w := &world{t: t, keepBin: build(t, "github.com/entire-vc/evc-keep/cmd/keep", "keep"),
		serverOut: &syncBuffer{}, runnerOut: &syncBuffer{}, enrollOut: &syncBuffer{}}

	w.agentBin = w.keepBin
	if _, _, ok := agentAccount(); ok {
		// t.TempDir is 0700; the agent account must be able to execute its CLI.
		dir, err := os.MkdirTemp("", "keep-agent-bin-")
		if err != nil || os.Chmod(dir, 0o755) != nil { //nolint:gosec // G302: the agent runs this directory's binary
			t.Fatal("agent bin dir")
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		src, err := os.ReadFile(w.keepBin) //nolint:gosec // G304: this test's own build output
		if err != nil {
			t.Fatal("read keep binary")
		}
		w.agentBin = filepath.Join(dir, "keep")
		if err := os.WriteFile(w.agentBin, src, 0o755); err != nil { //nolint:gosec // G306: executable by the agent
			t.Fatal("copy keep binary")
		}
	}

	dsn := pgscratch.New(t, logSettings)
	migrate := exec.Command(serverBin, "migrate", "up") //nolint:gosec // G204: this test's own build output
	migrate.Env = append(os.Environ(), "KEEP_DATABASE_URL="+dsn)
	if out, err := migrate.CombinedOutput(); err != nil {
		t.Fatalf("migrate up: %v\n%s", err, out)
	}
	roleDSN := pgscratch.NewRole(t, dsn, "keep_app")
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open pool")
	}
	t.Cleanup(pool.Close)
	w.pool = pool

	// Organization, a human admin, an agent sponsored by the admin, a
	// built-in store and a value-less secret reference.
	tr := tenancy.New(pool)
	org, err := tr.CreateOrganization(ctx, "w2-"+uuid.NewString()[:8], "")
	if err != nil {
		t.Fatal("organization")
	}
	w.org = org.ID
	admin := mustID(t)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)`, []any{admin, w.org, "admin@example.test"}},
		{`INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1, $2, $3, $4, $5)`, []any{mustID(t), w.org, admin, tenancy.Org(w.org).String(), string(identity.RoleAdmin)}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("seed organization")
		}
	}
	agent, err := tr.CreateAgent(ctx, w.org, admin, "agent-w2")
	if err != nil {
		t.Fatal("create agent")
	}
	// An agent asks for input links only with the explicit rotate grant.
	if _, err := pool.Exec(ctx, `INSERT INTO agent_grants(id,org_id,agent_id,permission) VALUES($1,$2,$3,'rotate')`, mustID(t), w.org, agent.ID); err != nil {
		t.Fatal("grant rotate to the agent")
	}
	token := func(kind identity.Kind, id uuid.UUID) string {
		issued, err := identity.NewRepo(pool).Issue(ctx, identity.IssueParams{OrgID: w.org, Kind: kind, PrincipalID: id, Scope: tenancy.Org(w.org).String()})
		if err != nil {
			t.Fatal("issue token")
		}
		wire, err := issued.Response().WireJSON()
		if err != nil {
			t.Fatal("encode issuance")
		}
		var cred struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(wire, &cred); err != nil {
			t.Fatal("decode issuance")
		}
		return cred.Token
	}
	w.agentToken = token(identity.KindAgent, agent.ID)
	adminToken := token(identity.KindUser, admin)

	cat := catalog.New(pool)
	st, err := cat.CreateStore(ctx, w.org, "builtin", "w2-store", tenancy.Org(w.org))
	if err != nil {
		t.Fatal("store")
	}
	if _, err = cat.CreateStoreBinding(ctx, w.org, tenancy.Org(w.org), st.ID); err != nil {
		t.Fatal("binding")
	}
	ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: w.org, Scope: tenancy.Org(w.org), Name: secretName, Class: "dev", Type: "generic", ProviderRef: "builtin://w2-store/" + secretName})
	if err != nil {
		t.Fatal("reference")
	}
	w.secretID = ref.ID

	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal("generate synthetic root")
	}
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root-key")
	if err := os.WriteFile(rootFile, []byte(base64.StdEncoding.EncodeToString(root)), 0o600); err != nil {
		t.Fatal("write synthetic root")
	}
	clear(root)

	certPath, keyPath := selfSigned(t, dir)
	runnerAddr := freeAddr(t)
	w.httpAddr = freeAddr(t)
	w.publicURL = "http://" + w.httpAddr
	procCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	t.Cleanup(cancel)
	server := exec.CommandContext(procCtx, serverBin) //nolint:gosec // G204: this test's own build output
	server.Env = append(os.Environ(),
		"KEEP_ROOT_KEY_FILE="+rootFile, "KEEP_DATABASE_URL="+roleDSN,
		"KEEP_HTTP_ADDR="+w.httpAddr, "KEEP_RUNNER_ADDR="+runnerAddr, "KEEP_PUBLIC_URL="+w.publicURL,
		"KEEP_SERVER_TLS_CERT_FILE="+certPath, "KEEP_SERVER_TLS_KEY_FILE="+keyPath)
	server.Stdout, server.Stderr = w.serverOut, w.serverOut
	if err := server.Start(); err != nil {
		t.Fatal("start keep-server")
	}
	t.Cleanup(func() { cancel(); _ = server.Wait() })
	waitListening(t, w.serverOut)

	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("resolve host directory")
	}
	w.hostDir = filepath.Join(base, "demo")
	if err := os.Mkdir(w.hostDir, 0o700); err != nil {
		t.Fatal("create host directory")
	}
	policyPath := filepath.Join(dir, "policy.json")
	policy, err := json.Marshal(hostPolicy(w.hostDir))
	if err != nil {
		t.Fatal("encode host policy")
	}
	if err := os.WriteFile(policyPath, policy, 0o600); err != nil {
		t.Fatal("write host policy")
	}

	serverURL := "https://" + runnerAddr
	host := "w2-stand.example.test"
	credDir := filepath.Join(dir, "cred")
	issue := exec.Command(w.keepBin, "runner", "enroll-token", "-host", host, "-policy", policyPath, "-server", serverURL, "-ttl", "1m", "-uid-shared=false", "-environment", "staging", "-platform", "darwin", "-insecure-skip-verify") //nolint:gosec // G204: this test's own build output
	issue.Env = append(os.Environ(), "KEEP_ADMIN_TOKEN="+adminToken)
	var enrollToken bytes.Buffer
	issue.Stdout = &enrollToken
	if err := issue.Run(); err != nil {
		t.Fatal("keep runner enroll-token failed")
	}
	enroll := exec.Command(runnerBin, "enroll", "-host", host, "-server", serverURL, "-policy", policyPath, "-cred-dir", credDir, "-insecure-skip-verify") //nolint:gosec // G204: this test's own build output
	enroll.Stdin = strings.NewReader(strings.TrimSpace(enrollToken.String()) + "\n")
	enroll.Stdout, enroll.Stderr = w.enrollOut, w.enrollOut
	if err := enroll.Run(); err != nil {
		t.Fatalf("keep-runner enroll failed: %s", w.enrollOut.String())
	}
	if err := pool.QueryRow(ctx, `SELECT id::text FROM runners WHERE org_id=$1`, w.org).Scan(&w.runnerID); err != nil {
		t.Fatal("read enrolled runner id")
	}
	run := exec.CommandContext(procCtx, runnerBin, "run", "-cred-dir", credDir, "-policy", policyPath, "-server", serverURL, "-server-ca", certPath) //nolint:gosec // G204: this test's own build output
	run.Stdout, run.Stderr = w.runnerOut, w.runnerOut
	if err := run.Start(); err != nil {
		t.Fatal("start keep-runner")
	}
	t.Cleanup(func() { cancel(); _ = run.Wait() })

	// The server-side deployment policy: the agent may place DEMO_API_KEY
	// as an env-file under the host directory, on this runner.
	// A second, deliberately loose rule admits the parent directory, so
	// requests the runner's own host policy must refuse still reach it.
	rules, _ := json.Marshal(map[string]any{"rules": []map[string]any{
		{"secret_id": w.secretID.String(), "runner_id": w.runnerID, "kind": "env-file", "path_prefix": w.hostDir},
		{"secret_id": w.secretID.String(), "runner_id": w.runnerID, "kind": "env-file", "path_prefix": filepath.Dir(w.hostDir)}}})
	if _, err := pool.Exec(ctx, `INSERT INTO deployment_policies(org_id,rules,max_deploys_per_hour) VALUES($1,$2,100)`, w.org, rules); err != nil {
		t.Fatal("store deployment policy")
	}
	return w
}

// agentKeep runs the real CLI with the agent's token and returns exit code,
// stdout and stderr: everything the agent can ever see.
func (w *world) agentKeep(args ...string) (int, string, string) {
	w.t.Helper()
	cmd := exec.Command(w.agentBin, args...) //nolint:gosec // G204: this test's own build output
	if uid, gid, ok := agentAccount(); ok {
		// On the Linux stand the agent really is another account.
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}} //nolint:gosec // G115: ids from user.Lookup
	}
	// The agent's environment holds its own variables only: no database URL, no host paths.
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.TempDir()}, "KEEP_SERVER=http://"+w.httpAddr, "KEEP_ORG="+w.org.String(), "KEEP_TOKEN="+w.agentToken)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Start(); err != nil {
		w.t.Fatal("start keep")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		w.t.Fatal("keep timed out")
	}
	return cmd.ProcessState.ExitCode(), so.String(), se.String()
}

func base64Of(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// statusAnswer is what the API tells the agent about a deployment request.
func (w *world) statusAnswer(requestID string) string {
	w.t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+w.httpAddr+"/v1/deployments/"+requestID, nil)
	if err != nil {
		w.t.Fatal("build status request")
	}
	req.Header.Set("Authorization", "Bearer "+w.agentToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal("status request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return string(b)
}

// auditText is every journal row as text, for the leak search.
func (w *world) auditText() string {
	w.t.Helper()
	rows, err := w.pool.Query(context.Background(), `SELECT to_jsonb(a)::text FROM audit_records a WHERE org_id=$1 ORDER BY org_seq`, w.org.String())
	if err != nil {
		w.t.Fatal("read journal")
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			w.t.Fatal("scan journal")
		}
		sb.WriteString(s + "\n")
	}
	return sb.String()
}
