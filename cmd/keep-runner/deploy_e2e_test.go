package main

// End-to-end acceptance of `keep deploy` with the real, separately compiled
// binaries: keep-server, keep and keep-runner talk to each other over the
// network and a real PostgreSQL. A secret is sealed into the built-in store,
// `keep deploy` is run on a test host, the runner writes the file, and the
// answer carries only ok, fingerprint, version and request_id. The same test
// then looks for a canary value, in all six encodings, in every surface that
// could carry it: CLI output, the status answer, server and runner process
// output and the audit trail.

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
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Field names the host policy admits for the json-path and launchd carriers.
const (
	e2eJSONField  = "mcpServers.srv.env.API_KEY"
	e2ePlistField = "LAUNCH_KEY"
)

type deployWorld struct {
	t          *testing.T
	pool       *pgxpool.Pool
	local      *builtin.Local
	org        uuid.UUID
	store      uuid.UUID
	runnerID   string
	keepBin    string
	httpAddr   string
	token      string
	targetDir  string
	serverOut  *e2eSyncBuffer
	runnerOut  *e2eSyncBuffer
	enrollOut  *e2eSyncBuffer
	policyPath string
}

func e2eSelfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate listener key")
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "keep-e2e"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true, BasicConstraintsValid: true,
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

// newDeployWorld starts a real keep-server and an enrolled, running
// keep-runner whose host policy admits one directory and one field name.
func newDeployWorld(t *testing.T) *deployWorld {
	t.Helper()
	serverBin := buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep-server", "keep-server")
	runnerBin := buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep-runner", "keep-runner")
	w := &deployWorld{t: t, keepBin: buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep", "keep"),
		serverOut: &e2eSyncBuffer{}, runnerOut: &e2eSyncBuffer{}, enrollOut: &e2eSyncBuffer{}}

	dsn := pgscratch.New(t, e2eRequiredLogSettings)
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

	newID := func() uuid.UUID {
		id, err := uuid.NewV7()
		if err != nil {
			t.Fatal("new id")
		}
		return id
	}
	w.org, w.store = newID(), newID()
	admin, membership := newID(), newID()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (id, name) VALUES ($1, $2)`, []any{w.org, "org-" + w.org.String()}},
		{`INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)`, []any{admin, w.org, "admin@example.test"}},
		{`INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1, $2, $3, $4, $5)`, []any{membership, w.org, admin, tenancy.Org(w.org).String(), string(identity.RoleAdmin)}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','e2e','org',$2)`, []any{w.store, w.org}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("seed organization")
		}
	}
	issued, err := identity.NewRepo(pool).Issue(ctx, identity.IssueParams{OrgID: w.org, Kind: identity.KindUser, PrincipalID: admin, Scope: tenancy.Org(w.org).String()})
	if err != nil {
		t.Fatal("issue admin token")
	}
	wire, err := issued.Response().WireJSON()
	if err != nil {
		t.Fatal("encode admin issuance")
	}
	var cred struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(wire, &cred); err != nil {
		t.Fatal("decode admin issuance")
	}
	w.token = cred.Token

	// The same synthetic root encrypts what the test seeds and what the
	// server opens, so the built-in store really delivers the value.
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
	if w.local, err = builtin.OpenLocalFile(pool, rootFile, "local-v1", nil, nopAudit); err != nil {
		t.Fatal("open synthetic root")
	}

	certPath, keyPath := e2eSelfSigned(t, dir)
	runnerAddr := e2eFreeAddr(t)
	w.httpAddr = e2eFreeAddr(t)
	procCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	t.Cleanup(cancel)
	server := exec.CommandContext(procCtx, serverBin) //nolint:gosec // G204: this test's own build output
	server.Env = append(os.Environ(),
		"KEEP_ROOT_KEY_FILE="+rootFile, "KEEP_DATABASE_URL="+roleDSN,
		"KEEP_HTTP_ADDR="+w.httpAddr, "KEEP_RUNNER_ADDR="+runnerAddr,
		"KEEP_SERVER_TLS_CERT_FILE="+certPath, "KEEP_SERVER_TLS_KEY_FILE="+keyPath,
		// These flows poll and submit far more often than one principal
		// may by default; the limit has its own tests in internal/api.
		"KEEP_CATALOG_RATE_PER_MINUTE=60000", "KEEP_CATALOG_BURST=10000")
	server.Stdout, server.Stderr = w.serverOut, w.serverOut
	if err := server.Start(); err != nil {
		t.Fatal("start keep-server")
	}
	t.Cleanup(func() { cancel(); _ = server.Wait() })
	e2eWaitForListening(t, w.serverOut, 15*time.Second)

	// Host policy: one directory, one credential-shaped field, and a runner
	// uid that is no agent's. EvalSymlinks keeps the prefix honest on macOS.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("resolve target directory")
	}
	w.targetDir = filepath.Join(base, "app")
	if err := os.Mkdir(w.targetDir, 0o700); err != nil {
		t.Fatal("create target directory")
	}
	w.policyPath = filepath.Join(dir, "policy.json")
	policy, err := json.Marshal(map[string]any{"version": 1, "agent_uids": []int64{}, "agent_gids": []int64{}, "max_deploys_per_hour": 100,
		"targets": []map[string]any{
			{"kind": "env-file", "path_prefixes": []string{w.targetDir}, "fields": []string{"STRIPE_API_KEY"}},
			{"kind": "mcp-config", "path_prefixes": []string{w.targetDir}, "fields": []string{e2eJSONField}},
			{"kind": "launchd-env", "path_prefixes": []string{w.targetDir}, "fields": []string{e2ePlistField}},
		}})
	if err != nil {
		t.Fatal("encode host policy")
	}
	if err := os.WriteFile(w.policyPath, policy, 0o600); err != nil {
		t.Fatal("write host policy")
	}

	serverURL := "https://" + runnerAddr
	host := "e2e-deploy.example.test"
	credDir := filepath.Join(dir, "cred")
	issue := exec.Command(w.keepBin, "runner", "enroll-token", "-host", host, "-policy", w.policyPath, "-server", serverURL, "-ttl", "1m", "-uid-shared=false", "-environment", "staging", "-platform", "darwin", "-insecure-skip-verify") //nolint:gosec // G204: this test's own build output
	issue.Env = append(os.Environ(), "KEEP_ADMIN_TOKEN="+w.token)
	var issued2 bytes.Buffer
	issue.Stdout = &issued2
	if err := issue.Run(); err != nil {
		t.Fatal("keep runner enroll-token failed")
	}
	enroll := exec.Command(runnerBin, "enroll", "-host", host, "-server", serverURL, "-policy", w.policyPath, "-cred-dir", credDir, "-insecure-skip-verify") //nolint:gosec // G204: this test's own build output
	enroll.Stdin = strings.NewReader(strings.TrimSpace(issued2.String()) + "\n")
	enroll.Stdout, enroll.Stderr = w.enrollOut, w.enrollOut
	if err := enroll.Run(); err != nil {
		t.Fatalf("keep-runner enroll failed: %s", w.enrollOut.String())
	}
	if err := pool.QueryRow(ctx, `SELECT id::text FROM runners WHERE org_id=$1`, w.org).Scan(&w.runnerID); err != nil {
		t.Fatal("read enrolled runner id")
	}

	run := exec.CommandContext(procCtx, runnerBin, "run", "-cred-dir", credDir, "-policy", w.policyPath, "-server", serverURL, "-server-ca", certPath) //nolint:gosec // G204: this test's own build output
	run.Stdout, run.Stderr = w.runnerOut, w.runnerOut
	if err := run.Start(); err != nil {
		t.Fatal("start keep-runner")
	}
	t.Cleanup(func() { cancel(); _ = run.Wait() })
	return w
}

// seed seals value into the built-in store and catalogs it, returning the
// catalog fingerprint and version. The value goes straight from the caller's
// string into the zone and is never printed.
func (w *deployWorld) seed(name, class, value string, allowPrefix string) (fp, version string) {
	w.t.Helper()
	return w.seedKind(name, class, value, allowPrefix, "env-file")
}

// seedKind is seed for a server policy rule of the given target kind.
func (w *deployWorld) seedKind(name, class, value, allowPrefix, kind string) (fp, version string) {
	w.t.Helper()
	ctx := context.Background()
	sec, ver := uuid.New(), uuid.New()
	ref := "builtin://e2e-" + sec.String()
	p := w.local.Provider(w.org.String(), "", "", "")
	v := secret.New([]byte(value))
	defer v.Wipe()
	meta, err := p.Write(ctx, provider.Ref{Path: ref}, v)
	if err != nil {
		w.t.Fatal("seal synthetic value")
	}
	k, err := p.FingerprintKey(ctx)
	if err != nil {
		w.t.Fatal("fingerprint key")
	}
	defer k.Wipe()
	if fp, err = fingerprint.Compute(k, v); err != nil {
		w.t.Fatal("compute fingerprint")
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,$3,$4,'generic',$5,$6)`, []any{sec, w.org, name, class, w.store, ref}},
		{`INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,$4,$5,$6)`, []any{ver, w.org, sec, meta.Version, fp, v.Len()}},
	} {
		if _, err := w.pool.Exec(ctx, q.sql, q.args...); err != nil {
			w.t.Fatal("catalog synthetic secret")
		}
	}
	rule := map[string]any{"secret_id": sec.String(), "runner_id": w.runnerID, "kind": kind, "path_prefix": allowPrefix}
	var rules struct {
		Rules []map[string]any `json:"rules"`
	}
	var cur []byte
	if err := w.pool.QueryRow(ctx, `SELECT rules FROM deployment_policies WHERE org_id=$1`, w.org).Scan(&cur); err == nil {
		_ = json.Unmarshal(cur, &rules)
	}
	rules.Rules = append(rules.Rules, rule)
	enc, err := json.Marshal(rules)
	if err != nil {
		w.t.Fatal("encode deployment policy")
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO deployment_policies(org_id,rules,max_deploys_per_hour) VALUES($1,$2,100)
		ON CONFLICT (org_id) DO UPDATE SET rules=EXCLUDED.rules`, w.org, enc); err != nil {
		w.t.Fatal("store deployment policy")
	}
	return fp, meta.Version
}

// keep runs the real CLI and returns exit code, stdout and stderr.
func (w *deployWorld) keep(args ...string) (int, string, string) {
	w.t.Helper()
	cmd := exec.Command(w.keepBin, args...) //nolint:gosec // G204: this test's own build output
	cmd.Env = append(os.Environ(), "KEEP_SERVER=http://"+w.httpAddr, "KEEP_ORG="+w.org.String(), "KEEP_TOKEN="+w.token)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		w.t.Fatal("start keep")
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		w.t.Fatal("keep timed out")
	}
	return cmd.ProcessState.ExitCode(), so.String(), se.String()
}

func (w *deployWorld) status(requestID string) string {
	w.t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+w.httpAddr+"/v1/deployments/"+requestID, nil)
	if err != nil {
		w.t.Fatal("build status request")
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal("status request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return string(b)
}

// auditText is every audit row as text, for canary and equality checks.
func (w *deployWorld) auditText() string {
	w.t.Helper()
	rows, err := w.pool.Query(context.Background(), `SELECT to_jsonb(a)::text FROM audit_records a WHERE org_id=$1 ORDER BY org_seq`, w.org.String())
	if err != nil {
		w.t.Fatal("read audit")
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			w.t.Fatal("scan audit")
		}
		sb.WriteString(s + "\n")
	}
	return sb.String()
}

// auditProjection is the stable part of one request's audit rows.
func (w *deployWorld) auditProjection(requestID string) string {
	w.t.Helper()
	rows, err := w.pool.Query(context.Background(), `SELECT action||'|'||secret_name||'|'||target_kind||'|'||target_path||'|'||policy_decision||'|'||result_status||'|'||result_error_class
		FROM audit_records WHERE org_id=$1 AND request_id=$2 ORDER BY org_seq`, w.org.String(), requestID)
	if err != nil {
		w.t.Fatal("read audit projection")
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			w.t.Fatal("scan audit projection")
		}
		sb.WriteString(s + "\n")
	}
	return sb.String()
}

func e2eNormalize(s, requestID string) string {
	return strings.ReplaceAll(s, requestID, "REQ")
}

func (w *deployWorld) deploy(name, file, field, requestID string, extra ...string) (int, string, string) {
	return w.deployKind("env-file", name, file, field, requestID, extra...)
}

func (w *deployWorld) deployKind(kind, name, file, field, requestID string, extra ...string) (int, string, string) {
	args := []string{"deploy", name, "--runner", w.runnerID, "--kind", kind, "--target", file, "--field", field,
		"--uid", itoa(os.Getuid()), "--gid", itoa(os.Getgid()), "--request-id", requestID, "--wait", "60s", "--json"}
	return w.keep(append(args, extra...)...)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestKeepDeployEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds three binaries and starts a server")
	}
	w := newDeployWorld(t)
	c := canary.New()
	value := c.Value(1)
	fp, version := w.seed("stripe-key", "dev", value, w.targetDir)
	file := filepath.Join(w.targetDir, "app.env")

	// Happy path: the real CLI deploys and the runner writes the file.
	req := "e2e-ok-" + uuid.NewString()[:8]
	code, stdout, stderr := w.deploy("stripe-key", file, "STRIPE_API_KEY", req)
	if code != 0 {
		t.Fatalf("keep deploy exit %d\nstdout: %s\nstderr: %s\nrunner: %s", code, stdout, stderr, w.runnerOut.String())
	}
	var got struct {
		OK          bool   `json:"ok"`
		RequestID   string `json:"request_id"`
		Fingerprint string `json:"fingerprint"`
		Version     string `json:"version"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal("deploy output is not JSON")
	}
	if !got.OK || got.RequestID != req {
		t.Fatalf("deploy result: %+v", got)
	}
	if got.Fingerprint != fp || got.Version != version {
		t.Fatalf("answer fingerprint/version differ from the catalog: %+v want %s %s", got, fp, version)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal("runner did not create the target file")
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("target mode %o, want 0600", info.Mode().Perm())
	}
	written, err := os.ReadFile(file) //nolint:gosec // G304: test-owned path
	if err != nil || !strings.Contains(string(written), "STRIPE_API_KEY=") || !c.In(string(written)) {
		t.Fatal("target file does not carry the value (positive control for the canary)")
	}

	// No surface carries the value, in any of the six encodings.
	surfaces := map[string]string{
		"cli stdout": stdout, "cli stderr": stderr, "status answer": w.status(req),
		"server output": w.serverOut.String(), "runner output": w.runnerOut.String(),
		"enroll output": w.enrollOut.String(), "audit": w.auditText(),
	}
	for name, s := range surfaces {
		if c.In(s) {
			t.Errorf("value canary found in %s", name)
		}
	}
	// Positive control: the detector sees the value when it is present.
	if !c.In(string(written)) || !c.In("x"+value+"y") {
		t.Fatal("canary detector is blind")
	}

	// Replay of the same request id answers the same, without a second write.
	code, again, _ := w.deploy("stripe-key", file, "STRIPE_API_KEY", req)
	if code != 0 || again != stdout {
		t.Fatalf("repeat of a request id changed the answer (exit %d)", code)
	}

	// A target outside the server policy never becomes a job.
	outside := filepath.Join(filepath.Dir(w.targetDir), "elsewhere.env")
	code, deniedOut, deniedErr := w.deploy("stripe-key", outside, "STRIPE_API_KEY", "e2e-deny-"+uuid.NewString()[:8])
	if code == 0 || strings.Contains(deniedOut+deniedErr, filepath.Dir(outside)) {
		t.Fatalf("target outside the server policy: exit %d", code)
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("file written outside the server policy")
	}

	// Broken server: the policy admits the parent directory, the runner's own
	// host policy does not. The runner must refuse and write nothing.
	w.seed("loose-key", "dev", c.Value(2), filepath.Dir(w.targetDir))
	{
		code, brokenOut, _ := w.deploy("loose-key", outside, "STRIPE_API_KEY", "e2e-broken-"+uuid.NewString()[:8])
		if code != 1 || !strings.Contains(brokenOut, `"error_class": "policy_denied"`) && !strings.Contains(brokenOut, `"error_class":"policy_denied"`) {
			t.Fatalf("runner did not refuse a target outside its host policy: exit %d out %s", code, brokenOut)
		}
		if _, err := os.Stat(outside); err == nil {
			t.Fatal("runner wrote outside its host policy")
		}
	}

	// A network target is refused before any job exists.
	code, netOut, netErr := w.deploy("stripe-key", "https://example.invalid/hook", "STRIPE_API_KEY", "e2e-net-"+uuid.NewString()[:8])
	if code != 1 || !strings.Contains(netOut+netErr, "invalid_argument") || strings.Contains(netOut+netErr, "example.invalid") {
		t.Fatalf("network target: exit %d out %s err %s", code, netOut, netErr)
	}

	// Format refusals: a value the env-file format cannot carry. API answer,
	// CLI output and audit rows are the same for every kind of refusal,
	// apart from the request id.
	type refusal struct{ cli, status, audit string }
	var refusals []refusal
	for i, bad := range []string{"line\none", "line\rone", "nul\x00one"} {
		name := "bad-format-" + itoa(i)
		w.seed(name, "dev", bad+c.Value(3), w.targetDir)
		r := "e2e-fmt" + itoa(i) + "-" + uuid.NewString()[:8]
		code, out, errOut := w.deploy(name, filepath.Join(w.targetDir, name+".env"), "STRIPE_API_KEY", r)
		if code != 1 {
			t.Fatalf("format refusal %d: exit %d out %s", i, code, out)
		}
		if _, err := os.Stat(filepath.Join(w.targetDir, name+".env")); err == nil {
			t.Fatal("a refused value was written")
		}
		refusals = append(refusals, refusal{cli: e2eNormalize(out+errOut, r), status: e2eNormalize(w.status(r), r), audit: e2eNormalize(w.auditProjection(r), r)})
		_ = name
	}
	// The three differ only in the name they carry: normalize it too, then compare.
	for i := range refusals {
		n := "bad-format-" + itoa(i)
		refusals[i].cli = strings.ReplaceAll(refusals[i].cli, n, "NAME")
		refusals[i].status = strings.ReplaceAll(refusals[i].status, n, "NAME")
		refusals[i].audit = strings.ReplaceAll(refusals[i].audit, n, "NAME")
		refusals[i].cli = strings.ReplaceAll(refusals[i].cli, n+".env", "FILE")
		refusals[i].audit = strings.ReplaceAll(refusals[i].audit, n+".env", "FILE")
	}
	for i := 1; i < len(refusals); i++ {
		if refusals[i] != refusals[0] {
			t.Fatalf("refusal %d differs from refusal 0:\n%+v\n%+v", i, refusals[i], refusals[0])
		}
	}
	if !strings.Contains(refusals[0].status, "target_write_failed") && !strings.Contains(refusals[0].status, "policy_denied") {
		t.Fatalf("refusal carries no closed error class: %s", refusals[0].status)
	}
	// Raw-error red control: the runner's own diagnostic text stays local and
	// is not in any server-side surface.
	for name, s := range map[string]string{"server output": w.serverOut.String(), "audit": w.auditText()} {
		if strings.Contains(s, "cannot appear in an env-file line") {
			t.Errorf("runner diagnostic text reached %s", name)
		}
		if c.In(s) {
			t.Errorf("value canary found in %s after refusals", name)
		}
	}

	// A production-class secret waits for approval, and no job is created.
	w.seed("prod-key", "prod", c.Value(4), w.targetDir)
	code, apprOut, apprErr := w.deploy("prod-key", filepath.Join(w.targetDir, "prod.env"), "STRIPE_API_KEY", "e2e-appr-"+uuid.NewString()[:8])
	if code != 3 || !strings.Contains(apprOut, `"approval"`) {
		t.Fatalf("prod secret: exit %d out %s err %s", code, apprOut, apprErr)
	}
	if _, err := os.Stat(filepath.Join(w.targetDir, "prod.env")); err == nil {
		t.Fatal("prod secret written without approval")
	}
	var queued int
	if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM deployment_jobs j JOIN deployment_requests r ON r.id=j.deployment_request_id WHERE r.org_id=$1 AND r.decision='approval_required'`, w.org).Scan(&queued); err != nil || queued != 0 {
		t.Fatal("approval_required request has a job")
	}
	if c.In(w.auditText()) || c.In(w.serverOut.String()) || c.In(w.runnerOut.String()) {
		t.Error("value canary found after the full flow")
	}
}
