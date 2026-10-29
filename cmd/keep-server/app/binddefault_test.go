package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// createSecretAt posts the request from the defect report: a reference at
// the org scope, provider_ref builtin://default/<name>.
func createSecretAt(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, token, name string) (int, string) {
	t.Helper()
	var logb bytes.Buffer
	router := api.NewRouter(obs.New(&logb), pool, api.Deps{Catalog: api.CatalogLimit{PerMinute: 100000, Burst: 100000}})
	body, _ := json.Marshal(map[string]string{
		"scope_level": "org", "scope_id": org.String(), "name": name,
		"class": "dev", "type": "generic", "provider_ref": "builtin://default/" + name,
	})
	req := httptest.NewRequest(http.MethodPost, "/orgs/"+org.String()+"/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	out, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(out)
}

func bootstrapAcme(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.token")
	res := runBootstrap(t, pool, "--ttl", "24h", "--name", "acme", "--admin-email", "a@acme.test", "--token-file", path)
	if res.code != 0 {
		t.Fatalf("bootstrap exit %d: %s", res.code, res.stderr)
	}
	var org uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM organizations WHERE name = 'acme'`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	return org, readToken(t, path)
}

func storeRowCounts(t *testing.T, pool *pgxpool.Pool, org uuid.UUID) (stores, bindings int) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT (SELECT count(*) FROM stores WHERE org_id = $1), (SELECT count(*) FROM store_bindings WHERE org_id = $1)`,
		org).Scan(&stores, &bindings); err != nil {
		t.Fatal(err)
	}
	return stores, bindings
}

// A secret can be created in an organization right after bootstrap-org;
// with the binding removed the same request is refused with no_store_bound
// (the red control: the request itself is fine, the binding is what makes
// it pass).
func TestBootstrapOrg_FirstSecretCreatable(t *testing.T) {
	pool := testPool(t)
	org, token := bootstrapAcme(t, pool)

	if st, b := storeRowCounts(t, pool, org); st != 1 || b != 1 {
		t.Fatalf("after bootstrap-org: stores=%d bindings=%d, want 1 and 1", st, b)
	}
	var provider, name, level string
	var owner uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`SELECT s.provider, s.name, b.scope_level, s.owner_scope_id FROM store_bindings b JOIN stores s ON s.id = b.store_id
		 WHERE b.org_id = $1 AND b.scope_id = $1`, org).Scan(&provider, &name, &level, &owner); err != nil {
		t.Fatalf("org-scope binding: %v", err)
	}
	if provider != "builtin" || name != "default" || level != "org" || owner != org {
		t.Errorf("binding to %s/%s at %s owned by %v, want builtin/default at the org scope", provider, name, level, owner)
	}
	if code, body := createSecretAt(t, pool, org, token, "x"); code != http.StatusCreated {
		t.Fatalf("POST secret after bootstrap-org: %d %s, want 201", code, body)
	}

	if _, err := pool.Exec(context.Background(), `DELETE FROM store_bindings WHERE org_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	code, body := createSecretAt(t, pool, org, token, "y")
	if code != http.StatusConflict || !strings.Contains(body, `"error_class":"no_store_bound"`) {
		t.Fatalf("POST secret without a binding: %d %s, want 409 no_store_bound", code, body)
	}
}

type bindRun struct {
	code           int
	stdout, stderr string
	log            string
}

func runBind(t *testing.T, pool *pgxpool.Pool, args ...string) bindRun {
	t.Helper()
	var out, errb, logb bytes.Buffer
	code := bindDefaultStore(context.Background(), pool, obs.New(&logb), args, &out, &errb)
	return bindRun{code: code, stdout: out.String(), stderr: errb.String(), log: logb.String()}
}

var bindStdout = regexp.MustCompile(`^org_id=([0-9a-f-]{36}) store_id=([0-9a-f-]{36}) binding=(created|exists)\n$`)

// An organization created without a store (before bootstrap-org made one)
// gets it from bind-default-store; a second run reports binding=exists and
// adds no rows. stdout is ids only, and each run is journaled.
func TestBindDefaultStore_ExistingOrgThenRepeat(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	org, token := bootstrapAcme(t, pool)
	// The state of an org bootstrapped before this change: no store at all.
	if _, err := pool.Exec(ctx, `DELETE FROM store_bindings WHERE org_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM stores WHERE org_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	if code, body := createSecretAt(t, pool, org, token, "before"); code != http.StatusConflict || !strings.Contains(body, "no_store_bound") {
		t.Fatalf("POST secret on a storeless org: %d %s, want 409 no_store_bound", code, body)
	}

	first := runBind(t, pool, "--org-id", org.String())
	m := bindStdout.FindStringSubmatch(first.stdout)
	if first.code != 0 || m == nil || m[1] != org.String() || m[3] != "created" {
		t.Fatalf("first run: exit %d stdout %q stderr %q, want binding=created for %v", first.code, first.stdout, first.stderr, org)
	}
	storeID := m[2]
	if code, body := createSecretAt(t, pool, org, token, "after"); code != http.StatusCreated {
		t.Fatalf("POST secret after bind-default-store: %d %s, want 201", code, body)
	}

	second := runBind(t, pool, "--org-id", org.String())
	if want := "org_id=" + org.String() + " store_id=" + storeID + " binding=exists\n"; second.code != 0 || second.stdout != want {
		t.Fatalf("second run: exit %d stdout %q, want exactly %q", second.code, second.stdout, want)
	}
	if st, b := storeRowCounts(t, pool, org); st != 1 || b != 1 {
		t.Errorf("stores=%d bindings=%d after two runs, want 1 and 1", st, b)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id = $1 AND scope = $2 AND action = 'store.bind_default'
		AND result_status = 'ok' AND actor_type = 'system' AND actor_via = 'cli'`,
		org.String(), tenancy.Org(org).String()).Scan(&n); err != nil || n != 2 {
		t.Errorf("store.bind_default journal records = %d (err %v), want 2", n, err)
	}
	for name, text := range map[string]string{"stdout": first.stdout + second.stdout, "stderr": first.stderr + second.stderr, "log": first.log + second.log} {
		if tokenIn(token, text) {
			t.Errorf("admin token in %s", name)
		}
	}
	if first.stderr != "" || second.stderr != "" {
		t.Errorf("stderr %q / %q, want empty on success", first.stderr, second.stderr)
	}
}

func TestBindDefaultStore_UnknownOrgAndBadArgs(t *testing.T) {
	pool := testPool(t)
	res := runBind(t, pool, "--org-id", uuid.NewString())
	if res.code == 0 || res.stdout != "" || !strings.Contains(res.stderr, "error_class=not_found") {
		t.Errorf("unknown org: exit %d stdout %q stderr %q, want a not_found refusal", res.code, res.stdout, res.stderr)
	}
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM stores) + (SELECT count(*) FROM audit_records)`).Scan(&n); err != nil || n != 0 {
		t.Errorf("rows after a refusal = %d (err %v), want 0", n, err)
	}
	for _, args := range [][]string{nil, {"--org-id", "not-a-uuid"}, {"--org-id", uuid.NewString(), "extra"}} {
		if res := runBind(t, pool, args...); res.code == 0 || res.stdout != "" {
			t.Errorf("args %q: exit %d stdout %q, want a refusal", args, res.code, res.stdout)
		}
	}
}
