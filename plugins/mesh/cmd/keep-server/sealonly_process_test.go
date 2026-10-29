package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// logSettings are store.RequiredLogSettings as server-side literals: the
// server refuses a database that would log rejected rows in full.
var logSettings = map[string]string{
	"log_error_verbosity":         "terse",
	"log_min_error_statement":     "panic",
	"log_statement":               "'none'",
	"log_min_duration_statement":  "-1",
	"log_min_duration_sample":     "-1",
	"log_transaction_sample_rate": "0",
	"log_min_messages":            "fatal",
}

func goBuild(t *testing.T, pkg string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "keep-server")
	out, err := exec.Command("go", "build", "-o", bin, pkg).CombinedOutput() //nolint:gosec // G204: a fixed package and a test-owned path
	if err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
	return bin
}

func rootKeyFile(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("root fixture generation failed")
	}
	defer clear(key)
	path := filepath.Join(t.TempDir(), "root-key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal("root fixture write failed")
	}
	return path
}

// syncBuf is the process output, written by exec and read while it runs.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// serve runs bin for d and reports its combined output, whether it was still
// running at the end and its exit code otherwise. during, if not nil, is
// called once the server has logged that it listens.
func serve(t *testing.T, bin string, d time.Duration, during func(), env ...string) (out string, running bool, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin) //nolint:gosec // G204: bin is goBuild's own output
	cmd.Env = append(os.Environ(), env...)
	var buf syncBuf
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }() // outcome read from ctx and ProcessState below
	if during != nil {
		for !strings.Contains(buf.String(), "keep-server listening") {
			select {
			case <-done:
				t.Fatalf("server exited before listening: %q", buf.String())
			case <-time.After(50 * time.Millisecond):
			}
		}
		during()
	}
	<-done
	if ctx.Err() == context.DeadlineExceeded {
		return buf.String(), true, -1
	}
	return buf.String(), false, cmd.ProcessState.ExitCode()
}

// freeAddr returns a loopback address with a port nothing listens on, so the
// test knows where the server it starts will answer.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// orgWithBearers creates an organisation with an admin and a plain member
// and returns their API tokens.
func orgWithBearers(t *testing.T, dsn string) (org uuid.UUID, admin, member string) {
	t.Helper()
	ctx := pgscratch.Context(t)
	pool, err := pgxpool.New(ctx, pgscratch.DSN(t, dsn))
	if err != nil {
		t.Fatal("fixture: connect failed")
	}
	defer pool.Close()
	tr := tenancy.New(pool)
	o, err := tr.CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	bearer := func(name string, isAdmin bool) string {
		u, err := tr.CreateUser(ctx, o.ID, name+"@example.test")
		if err != nil {
			t.Fatalf("user: %v", err)
		}
		if isAdmin {
			if _, err := tr.CreateMembership(ctx, o.ID, u.ID, tenancy.Org(o.ID), string(identity.RoleAdmin)); err != nil {
				t.Fatalf("admin role: %v", err)
			}
		}
		res, err := identity.NewRepo(pool).Issue(ctx, identity.IssueParams{OrgID: o.ID, Kind: identity.KindUser, PrincipalID: u.ID, Scope: "org:" + o.ID.String()})
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		wire, err := res.Response().WireJSON()
		if err != nil {
			t.Fatal("token wire failed")
		}
		var tok struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(wire, &tok); err != nil || tok.Token == "" {
			t.Fatal("token wire shape")
		}
		return tok.Token
	}
	return o.ID, bearer("admin", true), bearer("member", false)
}

// apiProbe asks the running server what an operator or a client could ask it
// after the token was sealed and returns every response, status line,
// headers and body, as received. It also returns the request id of a refused
// token issue, which the server must have journaled.
func apiProbe(t *testing.T, base string, org uuid.UUID, admin, member string) (dump, deniedRequestID string) {
	t.Helper()
	cl := &http.Client{Timeout: 5 * time.Second}
	var b strings.Builder
	do := func(method, path, bearer, body string, want int) []byte {
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("request %s %s: %v", method, path, err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := httputil.DumpResponse(resp, true)
		if err != nil {
			t.Fatalf("%s %s: dump: %v", method, path, err)
		}
		b.Write(raw)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: status %d, want %d", method, path, resp.StatusCode, want)
		}
		_, payload, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
		return payload
	}
	orgPath := "/orgs/" + org.String()
	do("GET", "/healthz", "", "", http.StatusOK)
	do("GET", "/readyz", "", "", http.StatusOK)
	do("GET", orgPath+"/secrets", "", "", http.StatusUnauthorized)
	list := do("GET", orgPath+"/secrets?scope_level=org&scope_id="+org.String(), admin, "", http.StatusOK)
	var secrets []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(list, &secrets); err != nil {
		t.Fatalf("secret list is not JSON: %v", err)
	}
	for _, s := range secrets {
		do("GET", orgPath+"/secrets/"+s.ID, admin, "", http.StatusOK)
		do("GET", orgPath+"/secrets/"+s.ID+"/versions", admin, "", http.StatusOK)
	}
	do("GET", orgPath+"/secrets/"+uuid.NewString(), admin, "", http.StatusNotFound)
	do("GET", orgPath+"/audit/verify", admin, "", http.StatusOK)
	denied := do("POST", orgPath+"/tokens", member, fmt.Sprintf(`{"kind":"s","principal_id":%q,"scope":"org:%s"}`, uuid.NewString(), org), http.StatusNotFound)
	var e struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(denied, &e); err != nil || e.RequestID == "" {
		t.Fatalf("refused token issue carries no request id: %q", denied)
	}
	return b.String(), e.RequestID
}

// The plugin binary started with KEEP_MESH_SVC_BOOTSTRAP_FILE and without
// KEEP_MESH_SELF_ROTATE seals the token, keeps running and reaches no Mesh
// (the URL points nowhere and is never named); the token is in neither its
// output, nor its API responses, nor the audit journal. A second start seals
// nothing new. The core binary with the same environment refuses to start.
func TestE2ESealOnlyProcess(t *testing.T) {
	plugin := goBuild(t, ".")
	core := goBuild(t, "github.com/entire-vc/evc-keep/cmd/keep-server")
	dsn := pgscratch.New(t, logSettings)
	migrate := exec.Command(plugin, "migrate", "up") //nolint:gosec // G204: goBuild's own output
	migrate.Env = append(os.Environ(), "KEEP_DATABASE_URL="+dsn)
	if out, err := migrate.CombinedOutput(); err != nil {
		t.Fatalf("migrate up: %v\n%s", err, out)
	}
	roleDSN := pgscratch.NewRole(t, dsn, "keep_app")
	org, admin, member := orgWithBearers(t, dsn)

	c := canary.New()
	tokenFile := filepath.Join(t.TempDir(), "svc.token")
	if err := os.WriteFile(tokenFile, []byte("ext_"+c.Value(0)+"\n"), 0o600); err != nil {
		t.Fatal("token fixture write failed")
	}
	addr := freeAddr(t)
	env := []string{
		"KEEP_DATABASE_URL=" + roleDSN, "KEEP_HTTP_ADDR=" + addr, "KEEP_RUNNER_ADDR=127.0.0.1:0",
		"KEEP_ROOT_KEY_FILE=" + rootKeyFile(t), "KEEP_ROOT_KEY_ID=local-v1", "KEEP_DEV_EPHEMERAL_TLS=1",
		"KEEP_MESH_EXTENSION=1", "KEEP_MESH_SELF_ROTATE=",
		"KEEP_MESH_SELF_ROTATE_ORG_ID=" + org.String(),
		"KEEP_MESH_SVC_BOOTSTRAP_FILE=" + tokenFile,
		// Rotation would call this address; seal-only must not.
		"KEEP_MESH_SELF_ROTATE_URL=https://mesh.invalid",
		"KEEP_MESH_SELF_ROTATE_ACCOUNT_ID=" + uuid.NewString(),
	}

	var api string
	var denied []string
	probe := func() {
		d, id := apiProbe(t, "http://"+addr, org, admin, member)
		api += d
		denied = append(denied, id)
	}

	out, running, code := serve(t, plugin, 8*time.Second, probe, env...)
	if !running {
		t.Fatalf("plugin binary did not stay up in seal-only (exit %d): %q", code, out)
	}
	for _, want := range []string{"sealed from bootstrap file", "name=mesh-service-token", "fingerprint=kfp1:", "seal-only"} {
		if !strings.Contains(out, want) {
			t.Fatalf("first start lacks %q: %q", want, out)
		}
	}
	all := out

	out, running, code = serve(t, plugin, 6*time.Second, probe, env...)
	if !running {
		t.Fatalf("second seal-only start failed (exit %d): %q", code, out)
	}
	if strings.Contains(out, "sealed from bootstrap file") {
		t.Fatalf("second start sealed a new version: %q", out)
	}
	all += out

	out, running, code = serve(t, core, 15*time.Second, nil, env...)
	if running || code != 1 || !strings.Contains(out, "no Mesh plugin") {
		t.Fatalf("core binary in seal-only: running=%v code=%d, want refusal: %q", running, code, out)
	}
	all += out

	// Positive control of the API capture: both starts answered, bodies and
	// headers included.
	for _, want := range []string{"HTTP/1.1 200 OK", "HTTP/1.1 401 Unauthorized", "Content-Type: application/json", `"error_class"`, `"request_id"`} {
		if strings.Count(api, want) < 2 {
			t.Fatalf("API capture lacks %q from both starts: %q", want, api)
		}
	}
	// Positive control of the journal read: each refused token issue is
	// there, read through the same query as the leak check.
	journal, n := auditText(t, dsn)
	if n < len(denied) || !strings.Contains(journal, "identity.token_issue") {
		t.Fatalf("audit read returned %d records, want the %d refused token issues: %q", n, len(denied), journal)
	}
	for _, id := range denied {
		if !strings.Contains(journal, id) {
			t.Fatalf("audit read lacks the refused token issue %s: %q", id, journal)
		}
	}

	if c.In(all) {
		t.Fatal("the token reached the process output")
	}
	if c.In(api) {
		t.Fatal("the token reached an API response")
	}
	if c.In(journal) {
		t.Fatal("the token reached the audit journal")
	}
}

// auditText returns every audit record as JSON text and how many there are.
func auditText(t *testing.T, dsn string) (string, int) {
	t.Helper()
	ctx := pgscratch.Context(t)
	conn, err := pgx.Connect(ctx, pgscratch.DSN(t, dsn))
	if err != nil {
		t.Fatal("audit read: connect failed")
	}
	defer func() { _ = conn.Close(ctx) }()
	rows, err := conn.Query(ctx, "SELECT row_to_json(a)::text FROM audit_records a")
	if err != nil {
		t.Fatal("audit read: query failed")
	}
	var b strings.Builder
	n := 0
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal("audit read: scan failed")
		}
		b.WriteString(s)
		n++
	}
	if rows.Err() != nil {
		t.Fatal("audit read: rows failed")
	}
	return b.String(), n
}
