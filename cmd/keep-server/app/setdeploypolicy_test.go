package app

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// policyWorld is an organization with one secret holding a canary value in
// the builtin store "default", one enrolled runner, and an admin user to
// request deployments as.
type policyWorld struct {
	pool                         *pgxpool.Pool
	org, user, secret, version   uuid.UUID
	runner                       uuid.UUID
	value                        string
	c                            canary.Canary
	foreignSecret, foreignRunner uuid.UUID
}

func newPolicyWorld(t *testing.T) *policyWorld {
	t.Helper()
	ctx := context.Background()
	pool := testPool(t)
	org, _ := bootstrapAcme(t, pool)
	w := &policyWorld{pool: pool, org: org, c: canary.New()}
	w.value = w.c.Value(1)
	must(t, pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1`, org).Scan(&w.user))

	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	local, err := builtin.NewLocal(pool, "policy-test-root", raw, obs.New(&bytes.Buffer{}), nopAudit)
	must(t, err)
	var storeID uuid.UUID
	must(t, pool.QueryRow(ctx, `SELECT store_id FROM store_bindings WHERE org_id=$1 AND scope_id=$1`, org).Scan(&storeID))
	const ref = "builtin://default/partner-signing"
	cat := catalog.New(pool)
	sec, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: org, Scope: tenancy.Org(org), Name: "partner-signing", Class: "dev", Type: "generic", ProviderRef: ref, StoreID: storeID})
	must(t, err)
	w.secret = sec.ID
	prov := local.Provider(org.String(), "", "", "")
	val := secret.New([]byte(w.value))
	meta, err := prov.Write(ctx, provider.Ref{Path: ref}, val)
	must(t, err)
	key, err := prov.FingerprintKey(ctx)
	must(t, err)
	fp, err := fingerprint.Compute(key, val)
	key.Wipe()
	must(t, err)
	_, err = cat.AddVersion(ctx, org, sec.ID, meta.Version, fp, val.Len())
	must(t, err)
	must(t, pool.QueryRow(ctx, `SELECT id FROM secret_versions WHERE org_id=$1 AND secret_id=$2`, org, sec.ID).Scan(&w.version))

	rk, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, err)
	w.runner = uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO runners(id,org_id,host,cert_serial,cert_not_after,hpke_public_key,uid_shared,host_labels,attrs_source)
		VALUES($1,$2,'policy-host.example.test','01',now()+interval '1 day',$3,false,'{}','enroll_token')`, w.runner, org, rk.PublicKey().Bytes())
	must(t, err)

	// Another organization with its own secret and runner: a rule naming
	// either must be refused for acme.
	other, otherStore := uuid.New(), uuid.New()
	w.foreignSecret, w.foreignRunner = uuid.New(), uuid.New()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name) VALUES($1,'other')`, []any{other}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','default','org',$2)`, []any{otherStore, other}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'partner-signing','dev','generic',$3,'builtin://default/partner-signing')`, []any{w.foreignSecret, other, otherStore}},
		{`INSERT INTO runners(id,org_id,host,cert_serial,cert_not_after) VALUES($1,$2,'other-host','02',now()+interval '1 day')`, []any{w.foreignRunner, other}},
	} {
		_, err = pool.Exec(ctx, s.sql, s.args...)
		must(t, err)
	}
	return w
}

func (w *policyWorld) run(t *testing.T, args ...string) bindRun {
	t.Helper()
	var out, errb, logb bytes.Buffer
	code := setDeployPolicy(context.Background(), w.pool, obs.New(&logb), args, &out, &errb)
	return bindRun{code: code, stdout: out.String(), stderr: errb.String(), log: logb.String()}
}

// file writes a policy file in a temp dir and returns its path.
func policyFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	must(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func (w *policyWorld) fileRule(t *testing.T, secretID uuid.UUID, runnerID, prefix string) string {
	t.Helper()
	b, err := json.Marshal(deployment.Policy{Rules: []deployment.Rule{{SecretID: secretID, RunnerID: runnerID, Kind: runnerproto.TargetFile, PathPrefix: prefix}}})
	must(t, err)
	return policyFile(t, string(b))
}

func (w *policyWorld) submit(t *testing.T) deployment.Outcome {
	t.Helper()
	repo := deployment.NewRepo(w.pool, audit.NewJournal(w.pool))
	out, err := repo.Submit(context.Background(), deployment.Request{
		OrgID: w.org, Scope: tenancy.Org(w.org), SecretID: w.secret, VersionID: w.version, RunnerID: w.runner,
		RequestID: uuid.NewString(), Target: runnerproto.Target{Kind: runnerproto.TargetFile, Path: "/var/lib/partner/ext/signing.secret", Mode: 0o600, UID: 309, GID: 309},
		Actor: audit.Actor{Type: audit.ActorUser, ID: w.user.String(), Via: audit.ViaAPI},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return out
}

func (w *policyWorld) revision(t *testing.T) int64 {
	t.Helper()
	var rev int64
	if err := w.pool.QueryRow(context.Background(), `SELECT COALESCE((SELECT revision FROM deployment_policies WHERE org_id=$1),0)`, w.org).Scan(&rev); err != nil {
		t.Fatal(err)
	}
	return rev
}

// policyAudit returns the reasons of the org's deploy.policy_set records in
// order, each from an OK system/cli record at the org scope.
func (w *policyWorld) policyAudit(t *testing.T) []string {
	t.Helper()
	rows, err := w.pool.Query(context.Background(), `SELECT intent_reason FROM audit_records WHERE org_id=$1 AND action='deploy.policy_set'
		AND scope=$2 AND result_status='ok' AND actor_type='system' AND actor_id='keep-server-set-deploy-policy' AND actor_via='cli' ORDER BY ts`,
		w.org.String(), tenancy.Org(w.org).String())
	must(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		must(t, rows.Scan(&r))
		out = append(out, r)
	}
	must(t, rows.Err())
	return out
}

var setPolicyStdout = regexp.MustCompile(`^org_id=([0-9a-f-]{36}) revision=(\d+) rules=(\d+) exec_rules=(\d+) max_deploys_per_hour=(\d+)( dry_run=true)?\nchange: (.*)\n$`)

// Written before the command: the canary value of the secret a rule names
// is on no surface of the command — stdout, stderr, the log, or any column
// of the journal — through a stored change, a dry run and a refusal.
func TestSetDeployPolicy_NoValueOnAnySurface(t *testing.T) {
	w := newPolicyWorld(t)
	if !w.c.In("prefix "+w.value) || !w.c.In(hex.EncodeToString([]byte(w.value))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	good := w.fileRule(t, w.secret, w.runner.String(), "/var/lib/partner/ext")
	runs := []bindRun{
		w.run(t, "--org-id", w.org.String(), "--policy-file", good, "--dry-run"),
		w.run(t, "--org-id", w.org.String(), "--policy-file", good),
		w.run(t, "--org-id", w.org.String(), "--policy-file", w.fileRule(t, w.foreignSecret, w.runner.String(), "/var/lib/partner/ext")),
	}
	if runs[1].code != 0 || runs[2].code == 0 {
		t.Fatalf("exit codes %d/%d/%d, want the change stored and the foreign rule refused (stderr %q)", runs[0].code, runs[1].code, runs[2].code, runs[1].stderr)
	}
	var stdout, stderr, logs string
	for _, r := range runs {
		stdout, stderr, logs = stdout+r.stdout, stderr+r.stderr, logs+r.log
	}
	var journal string
	must(t, w.pool.QueryRow(context.Background(), `SELECT COALESCE(string_agg(row_to_json(a)::text, E'\n'),'') FROM audit_records a WHERE org_id=$1`, w.org.String()).Scan(&journal))
	if stdout == "" || stderr == "" || logs == "" || !strings.Contains(journal, "deploy.policy_set") {
		t.Fatalf("a surface is not captured: stdout %d, stderr %d, log %d bytes, journal has the record: %v", len(stdout), len(stderr), len(logs), strings.Contains(journal, "deploy.policy_set"))
	}
	for name, text := range map[string]string{"stdout": stdout, "stderr": stderr, "log": logs, "journal": journal} {
		if w.c.In(text) {
			t.Errorf("canary value in %s", name)
		}
	}
	// No fingerprint either: the policy carries none, so neither does the
	// journal record of its change.
	for _, reason := range w.policyAudit(t) {
		if strings.Contains(reason, "kfp1:") {
			t.Errorf("fingerprint in the journal reason %q", reason)
		}
	}
}

// The defect: without a rule every deployment waits for a person. After
// set-deploy-policy names the secret, runner, kind and directory, the same
// request becomes a job; a rule for another directory, or a rule naming
// another organization's secret (refused), does not.
func TestSetDeployPolicy_RuleTurnsApprovalIntoJob(t *testing.T) {
	w := newPolicyWorld(t)
	if out := w.submit(t); out.Status != deployment.NeedsApproval {
		t.Fatalf("without a policy: %s, want approval_required", out.Status)
	}

	res := w.run(t, "--org-id", w.org.String(), "--policy-file", w.fileRule(t, w.secret, w.runner.String(), "/var/lib/partner/ext"))
	m := setPolicyStdout.FindStringSubmatch(res.stdout)
	if res.code != 0 || m == nil || m[1] != w.org.String() || m[2] != "1" || m[3] != "1" || m[4] != "0" || m[5] != "10" || m[6] != "" {
		t.Fatalf("set: exit %d stdout %q stderr %q, want revision=1 rules=1 exec_rules=0 max_deploys_per_hour=10", res.code, res.stdout, res.stderr)
	}
	ruleKey := w.secret.String() + "/" + w.runner.String() + "/file//var/lib/partner/ext"
	if want := "revision=0->1 max_per_hour=10->10 +" + ruleKey; m[7] != want {
		t.Errorf("change line %q, want %q", m[7], want)
	}
	if out := w.submit(t); out.Status != deployment.Queued || out.JobID == uuid.Nil {
		t.Fatalf("with the rule: %s, want a queued job", out.Status)
	}

	// Another organization's secret: refused, nothing changes.
	res = w.run(t, "--org-id", w.org.String(), "--policy-file", w.fileRule(t, w.foreignSecret, w.runner.String(), "/var/lib/partner/ext"))
	if res.code == 0 || res.stdout != "" || !strings.Contains(res.stderr, "set-deploy-policy failed: error_class=invalid_argument: rules[0].secret_id is not a secret of this organization") {
		t.Fatalf("foreign secret: exit %d stdout %q stderr %q, want an invalid_argument refusal", res.code, res.stdout, res.stderr)
	}
	if rev := w.revision(t); rev != 1 {
		t.Fatalf("revision after a refusal = %d, want 1", rev)
	}

	// The red control: the same secret, another directory.
	res = w.run(t, "--org-id", w.org.String(), "--policy-file", w.fileRule(t, w.secret, w.runner.String(), "/srv/other"), "--max-deploys-per-hour", "20")
	if m = setPolicyStdout.FindStringSubmatch(res.stdout); res.code != 0 || m == nil || m[2] != "2" || m[5] != "20" {
		t.Fatalf("replace: exit %d stdout %q stderr %q, want revision=2 max_deploys_per_hour=20", res.code, res.stdout, res.stderr)
	}
	// Two full rule keys do not fit the 200-rune reason: the removed one is
	// counted, not cut in half.
	if want := "revision=1->2 max_per_hour=10->20 +" + w.secret.String() + "/" + w.runner.String() + "/file//srv/other (+1 more)"; m[7] != want {
		t.Errorf("change line %q, want %q", m[7], want)
	}
	if out := w.submit(t); out.Status != deployment.NeedsApproval {
		t.Fatalf("with a rule for another directory: %s, want approval_required", out.Status)
	}

	reasons := w.policyAudit(t)
	if len(reasons) != 2 || !strings.HasPrefix(reasons[0], "revision=0->1 ") || !strings.HasPrefix(reasons[1], "revision=1->2 max_per_hour=10->20 ") {
		t.Errorf("journal reasons %q, want two records, 0->1 and 1->2", reasons)
	}
}

func TestSetDeployPolicy_ExpectRevisionAndDryRun(t *testing.T) {
	w := newPolicyWorld(t)
	file := w.fileRule(t, w.secret, w.runner.String(), "/var/lib/partner/ext")

	dry := w.run(t, "--org-id", w.org.String(), "--policy-file", file, "--dry-run")
	if m := setPolicyStdout.FindStringSubmatch(dry.stdout); dry.code != 0 || m == nil || m[2] != "1" || m[6] != " dry_run=true" {
		t.Fatalf("dry run: exit %d stdout %q stderr %q, want the would-be revision 1 and dry_run=true", dry.code, dry.stdout, dry.stderr)
	}
	if rev, n := w.revision(t), len(w.policyAudit(t)); rev != 0 || n != 0 {
		t.Fatalf("after a dry run: revision %d, journal records %d, want nothing written", rev, n)
	}

	if res := w.run(t, "--org-id", w.org.String(), "--policy-file", file, "--expect-revision", "1"); res.code == 0 ||
		!strings.Contains(res.stderr, "set-deploy-policy failed: error_class=conflict: ") || res.stdout != "" {
		t.Fatalf("expect 1 on no policy: exit %d stdout %q stderr %q, want a conflict", res.code, res.stdout, res.stderr)
	}
	if res := w.run(t, "--org-id", w.org.String(), "--policy-file", file, "--expect-revision", "0"); res.code != 0 {
		t.Fatalf("expect 0 on no policy: exit %d stderr %q, want stored", res.code, res.stderr)
	}
	if res := w.run(t, "--org-id", w.org.String(), "--policy-file", file, "--expect-revision", "0"); res.code == 0 || !strings.Contains(res.stderr, "error_class=conflict") {
		t.Fatalf("stale expect 0: exit %d stderr %q, want a conflict", res.code, res.stderr)
	}
	if rev, n := w.revision(t), len(w.policyAudit(t)); rev != 1 || n != 1 {
		t.Fatalf("after a conflict: revision %d, journal records %d, want 1 and 1", rev, n)
	}
	if res := w.run(t, "--org-id", w.org.String(), "--policy-file", file, "--expect-revision", "1"); res.code != 0 || w.revision(t) != 2 {
		t.Fatalf("expect 1: exit %d stderr %q revision %d, want stored as revision 2", res.code, res.stderr, w.revision(t))
	}
}

// Every refusal leaves the policy and the journal as they were.
func TestSetDeployPolicy_Refusals(t *testing.T) {
	w := newPolicyWorld(t)
	sid, rid := w.secret.String(), w.runner.String()
	org := w.org.String()
	cases := map[string]struct {
		args  []string
		class string
	}{
		"unknown field":      {[]string{"--org-id", org, "--policy-file", policyFile(t, `{"rules":[],"allow_all":true}`)}, "invalid_argument"},
		"trailing data":      {[]string{"--org-id", org, "--policy-file", policyFile(t, `{"rules":[]} {"rules":[]}`)}, "invalid_argument"},
		"trailing brace":     {[]string{"--org-id", org, "--policy-file", policyFile(t, `{"rules":[]}}`)}, "invalid_argument"},
		"null file":          {[]string{"--org-id", org, "--policy-file", policyFile(t, "null\n")}, "invalid_argument"},
		"empty file":         {[]string{"--org-id", org, "--policy-file", policyFile(t, " \n")}, "invalid_argument"},
		"nil secret":         {[]string{"--org-id", org, "--policy-file", policyFile(t, `{"rules":[{"runner_id":"`+rid+`","kind":"file","path_prefix":"/srv/a"}]}`)}, "invalid_argument"},
		"foreign runner":     {[]string{"--org-id", org, "--policy-file", w.fileRule(t, w.secret, w.foreignRunner.String(), "/srv/a")}, "invalid_argument"},
		"runner not a uuid":  {[]string{"--org-id", org, "--policy-file", w.fileRule(t, w.secret, "mini", "/srv/a")}, "invalid_argument"},
		"foreign exec rule":  {[]string{"--org-id", org, "--policy-file", policyFile(t, `{"rules":[],"exec_rules":[{"secret_id":"`+w.foreignSecret.String()+`","template_id":"curl-get","runner_id":"`+rid+`"}]}`)}, "invalid_argument"},
		"no selector":        {[]string{"--org-id", org, "--policy-file", policyFile(t, `{"rules":[{"secret_id":"`+sid+`","kind":"file","path_prefix":"/srv/a"}]}`)}, "invalid_argument"},
		"limit zero":         {[]string{"--org-id", org, "--policy-file", w.fileRule(t, w.secret, rid, "/srv/a"), "--max-deploys-per-hour", "0"}, "invalid_argument"},
		"limit over":         {[]string{"--org-id", org, "--policy-file", w.fileRule(t, w.secret, rid, "/srv/a"), "--max-deploys-per-hour", "1001"}, "invalid_argument"},
		"unknown org":        {[]string{"--org-id", uuid.NewString(), "--policy-file", w.fileRule(t, w.secret, rid, "/srv/a")}, "not_found"},
		"org not a uuid":     {[]string{"--org-id", "acme", "--policy-file", w.fileRule(t, w.secret, rid, "/srv/a")}, "invalid_argument"},
		"missing file":       {[]string{"--org-id", org, "--policy-file", filepath.Join(t.TempDir(), "absent.json")}, "invalid_argument"},
		"negative expect":    {[]string{"--org-id", org, "--policy-file", w.fileRule(t, w.secret, rid, "/srv/a"), "--expect-revision", "-2"}, "invalid_argument"},
		"no policy file arg": {[]string{"--org-id", org}, ""},
		"extra argument":     {[]string{"--org-id", org, "--policy-file", w.fileRule(t, w.secret, rid, "/srv/a"), "extra"}, ""},
	}
	for name, tc := range cases {
		res := w.run(t, tc.args...)
		if res.code == 0 || res.stdout != "" {
			t.Errorf("%s: exit %d stdout %q, want a refusal", name, res.code, res.stdout)
			continue
		}
		if name == "nil secret" && !strings.Contains(res.stderr, "rules[0].secret_id is missing") {
			t.Errorf("nil secret: stderr %q, want it named as missing", res.stderr)
		}
		if tc.class == "" {
			if !strings.HasPrefix(res.stderr, "usage: keep-server set-deploy-policy") {
				t.Errorf("%s: stderr %q, want the usage line", name, res.stderr)
			}
		} else if !strings.HasPrefix(res.stderr, "set-deploy-policy failed: error_class="+tc.class+": ") {
			t.Errorf("%s: stderr %q, want error_class=%s", name, res.stderr, tc.class)
		}
	}
	var policies, records int
	must(t, w.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM deployment_policies), (SELECT count(*) FROM audit_records WHERE action='deploy.policy_set')`).Scan(&policies, &records))
	if policies != 0 || records != 0 {
		t.Errorf("after refusals: %d policies, %d journal records, want none", policies, records)
	}
}

// Failures before the database is open use the command's error format too;
// an unreachable database is reported without its DSN.
func TestSetDeployPolicy_StartupFailuresFormatted(t *testing.T) {
	c := canary.New()
	if !c.In("x" + c.Value(1)) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	args := []string{"--org-id", uuid.NewString(), "--policy-file", policyFile(t, `{"rules":[]}`)}
	for name, tc := range map[string]struct{ dsn, want string }{
		"no database url": {"", "set-deploy-policy failed: error_class=invalid_argument: KEEP_DATABASE_URL is required\n"},
		"unreachable":     {"postgres://keep:" + c.Value(1) + "@127.0.0.1:1/keep?sslmode=disable&connect_timeout=2", "set-deploy-policy failed: error_class=not_ready: cannot open the database\n"},
	} {
		t.Setenv("KEEP_DATABASE_URL", tc.dsn)
		var out, errb bytes.Buffer
		code := setDeployPolicyFromEnv(context.Background(), args, &out, &errb)
		if code == 0 || out.String() != "" || errb.String() != tc.want {
			t.Errorf("%s: exit %d stdout %q stderr %q, want %q", name, code, out.String(), errb.String(), tc.want)
		}
		if c.In(out.String() + errb.String()) {
			t.Errorf("%s: database password in the output", name)
		}
	}
}
