package deployment

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// An exec template belongs to one organization: another organization's request
// for the same template id finds nothing.
func TestExecTemplateIsScopedToItsOrganization(t *testing.T) {
	f := newFixture(t)
	f.putTemplate(t, noneTemplate())
	org2, user2, store2, secret2, version2, runner2 := mustID(t), mustID(t), mustID(t), mustID(t), mustID(t), mustID(t)
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name) VALUES($1,'other')`, []any{org2}},
		{`INSERT INTO users(id,org_id,email) VALUES($1,$2,'o@example.invalid')`, []any{user2, org2}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','o','org',$2)`, []any{store2, org2}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'DB_PASSWORD','dev','generic',$3,'builtin://o')`, []any{secret2, org2, store2}},
		{`INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'v1','kfp1:k1:abcdefghijklmnop',12)`, []any{version2, org2, secret2}},
		{`INSERT INTO runners(id,org_id,host,cert_serial,cert_not_after) VALUES($1,$2,'h2','serial2',$3)`, []any{runner2, org2, time.Now().Add(time.Hour)}},
	} {
		if _, err := f.pool.Exec(f.ctx, s.sql, s.args...); err != nil {
			t.Fatal("second organization setup failed")
		}
	}
	f.repo.trust = func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (Host, error) {
		return Host{AttributesKnown: true}, nil
	}
	in := f.execRequest(t, "db-check", map[string]string{"table": "users"})
	in.OrgID, in.SecretID, in.VersionID, in.RunnerID = org2, secret2, version2, runner2
	in.Scope = tenancy.Org(org2)
	in.Actor.ID = user2.String()
	if _, err := f.repo.SubmitExec(f.ctx, in); !errors.Is(err, ErrTemplateUnknown) {
		t.Fatal("another organization's template was used")
	}
}

// Every field the approver relies on moves the binding hash.
func TestExecBindingCoversEveryField(t *testing.T) {
	org, sec, ver, run := mustID(t), mustID(t), mustID(t), mustID(t)
	base := execSnapshot{TemplateID: "t", Digest: "d", Mode: "allowlist", Destinations: []string{"a:1", "b:1"}, Params: map[string]string{"p": "v"}}
	ref := execBinding(org, sec, ver, run, "org/x", base, "user", "u1", "s1", "api")
	other := func(mut func(*execSnapshot)) [32]byte {
		s := base
		s.Destinations = append([]string(nil), base.Destinations...)
		s.Params = map[string]string{"p": "v"}
		mut(&s)
		return execBinding(org, sec, ver, run, "org/x", s, "user", "u1", "s1", "api")
	}
	for name, h := range map[string][32]byte{
		"org":            execBinding(mustID(t), sec, ver, run, "org/x", base, "user", "u1", "s1", "api"),
		"secret":         execBinding(org, mustID(t), ver, run, "org/x", base, "user", "u1", "s1", "api"),
		"version":        execBinding(org, sec, mustID(t), run, "org/x", base, "user", "u1", "s1", "api"),
		"scope":          execBinding(org, sec, ver, run, "org/y", base, "user", "u1", "s1", "api"),
		"template id":    other(func(s *execSnapshot) { s.TemplateID = "t2" }),
		"digest":         other(func(s *execSnapshot) { s.Digest = "d2" }),
		"mode":           other(func(s *execSnapshot) { s.Mode = "none" }),
		"destination":    other(func(s *execSnapshot) { s.Destinations[1] = "c:1" }),
		"param value":    other(func(s *execSnapshot) { s.Params["p"] = "w" }),
		"runner":         execBinding(org, sec, ver, mustID(t), "org/x", base, "user", "u1", "s1", "api"),
		"requester":      execBinding(org, sec, ver, run, "org/x", base, "user", "u2", "s1", "api"),
		"requester type": execBinding(org, sec, ver, run, "org/x", base, "agent", "u1", "s1", "api"),
		"sponsor":        execBinding(org, sec, ver, run, "org/x", base, "user", "u1", "s2", "api"),
		"via":            execBinding(org, sec, ver, run, "org/x", base, "user", "u1", "s1", "mcp"),
	} {
		if h == ref {
			t.Fatal("binding ignores " + name)
		}
	}
	// Lists are length-framed: moving a value between destinations and
	// parameters cannot reproduce another request's hash.
	a := execSnapshot{TemplateID: "t", Digest: "d", Mode: "allowlist", Destinations: []string{"a", "1", "b"}}
	b := execSnapshot{TemplateID: "t", Digest: "d", Mode: "allowlist", Destinations: []string{"a"}, Params: map[string]string{"b": "0"}}
	if execBinding(org, sec, ver, run, "s", a, "user", "u", "", "api") == execBinding(org, sec, ver, run, "s", b, "user", "u", "", "api") {
		t.Fatal("binding framing is ambiguous")
	}
}

// The checks a deployment goes through at request time also hold for exec.
func TestExecRequestTimePolicyChecks(t *testing.T) {
	t.Run("production secret on a shared uid is denied", func(t *testing.T) {
		f := newFixture(t)
		f.putTemplate(t, noneTemplate())
		f.execPolicy(t, "db-check")
		if _, err := f.pool.Exec(f.ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.secret); err != nil {
			t.Fatal("make the secret production")
		}
		f.repo.trust = func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (Host, error) {
			return Host{AttributesKnown: true, UIDShared: true}, nil
		}
		out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "users"}))
		if err != nil || out.Status != Denied || f.jobs(t) != 0 {
			t.Fatal("production exec on a shared uid was not denied")
		}
	})
	t.Run("provider the runner cannot use", func(t *testing.T) {
		f := newFixture(t)
		f.putTemplate(t, noneTemplate())
		f.execPolicy(t, "db-check")
		if _, err := f.pool.Exec(f.ctx, `UPDATE stores SET provider='external-test' WHERE id=$1`, f.store); err != nil {
			t.Fatal("change provider")
		}
		out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "users"}))
		if err != nil || out.Status != UnsupportedProvider || f.jobs(t) != 0 {
			t.Fatal("undeliverable provider was queued")
		}
	})
	t.Run("hourly limit", func(t *testing.T) {
		f := newFixture(t)
		f.putTemplate(t, noneTemplate())
		f.execPolicy(t, "db-check")
		if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_policies SET max_deploys_per_hour=1 WHERE org_id=$1`, f.org); err != nil {
			t.Fatal("set limit")
		}
		first, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "users"}))
		if err != nil || first.Status != Queued {
			t.Fatal("control: the first request under the limit must queue")
		}
		second, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "orders"}))
		if err != nil || second.Status != RateLimited || f.jobs(t) != 1 {
			t.Fatal("exec got past the hourly limit")
		}
	})
	t.Run("unknown runner", func(t *testing.T) {
		f := newFixture(t)
		f.putTemplate(t, noneTemplate())
		in := f.execRequest(t, "db-check", map[string]string{"table": "users"})
		in.RunnerID = mustID(t)
		if _, err := f.repo.SubmitExec(f.ctx, in); !errors.Is(err, ErrNotFound) {
			t.Fatal("request for an unknown runner accepted")
		}
	})
}

// A human's approval does not lift what policy still refuses at decision time,
// and the decision is journaled as an exec record.
func TestExecDecisionRechecksPolicyAndJournalsKind(t *testing.T) {
	setup := func(t *testing.T) (fixture, Outcome, Approval, uuid.UUID) {
		f := newFixture(t)
		f.putTemplate(t, netTemplate("api.github.com"))
		out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/x"}))
		if err != nil || out.Status != NeedsApproval {
			t.Fatal("request was not held")
		}
		a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
		if err != nil {
			t.Fatal("read approval")
		}
		return f, out, a, f.approver(t)
	}
	decide := func(f fixture, out Outcome, a Approval, boss uuid.UUID) error {
		_, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash})
		return err
	}
	t.Run("provider changed", func(t *testing.T) {
		f, out, a, boss := setup(t)
		if _, err := f.pool.Exec(f.ctx, `UPDATE stores SET provider='external-test' WHERE id=$1`, f.store); err != nil {
			t.Fatal("change provider")
		}
		if err := decide(f, out, a, boss); !errors.Is(err, ErrRefused) || f.jobs(t) != 0 {
			t.Fatal("undeliverable provider approved")
		}
	})
	t.Run("production secret on a shared uid", func(t *testing.T) {
		f, out, a, boss := setup(t)
		if _, err := f.pool.Exec(f.ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.secret); err != nil {
			t.Fatal("make the secret production")
		}
		f.repo.trust = func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (Host, error) {
			return Host{AttributesKnown: true, UIDShared: true}, nil
		}
		if err := decide(f, out, a, boss); !errors.Is(err, ErrRefused) || f.jobs(t) != 0 {
			t.Fatal("production exec on a shared uid approved")
		}
	})
	t.Run("hourly limit", func(t *testing.T) {
		f, out, a, boss := setup(t)
		second, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/y"}))
		if err != nil {
			t.Fatal("second request")
		}
		a2, _ := f.repo.GetApproval(f.ctx, f.org, second.ApprovalID)
		if _, err = f.pool.Exec(f.ctx, `INSERT INTO deployment_policies(org_id,rules,max_deploys_per_hour) VALUES($1,'{"rules":[]}',1) ON CONFLICT (org_id) DO UPDATE SET max_deploys_per_hour=1`, f.org); err != nil {
			t.Fatal("set limit")
		}
		if err = decide(f, out, a, boss); err != nil {
			t.Fatal("control: the first approval under the limit must pass")
		}
		if err = decide(f, second, a2, boss); !errors.Is(err, ErrRefused) || f.jobs(t) != 1 {
			t.Fatal("exec approval got past the hourly limit")
		}
	})
	t.Run("decision record names exec", func(t *testing.T) {
		f, out, a, boss := setup(t)
		before := f.count(t, `SELECT count(*) FROM audit_records WHERE target_kind='exec'`)
		if err := decide(f, out, a, boss); err != nil {
			t.Fatal("approve")
		}
		if f.count(t, `SELECT count(*) FROM audit_records WHERE target_kind='exec'`) <= before {
			t.Fatal("the decision was not journaled as exec")
		}
	})
}

// The snapshot an approver is shown carries the template's real mode and
// destinations, and a deployment is never journaled as an exec.
func TestExecSnapshotModeAndKinds(t *testing.T) {
	f := newFixture(t)
	f.putTemplate(t, netTemplate("api.github.com"))
	out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/x"}))
	if err != nil {
		t.Fatal("submit")
	}
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil || a.Exec == nil || a.Exec.Mode != "allowlist" || len(a.NetAllowlist) != 1 || a.NetAllowlist[0] != "api.github.com:443" {
		t.Fatal("the card does not carry the template's mode and destinations")
	}
	f.putTemplate(t, noneTemplate())
	out, err = f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "users"}))
	if err != nil {
		t.Fatal("submit none")
	}
	b, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil || b.Exec == nil || b.Exec.Mode != "none" || len(b.NetAllowlist) != 0 {
		t.Fatal("a network none template is shown with destinations")
	}
	before := f.count(t, `SELECT count(*) FROM audit_records WHERE target_kind='exec'`)
	if _, err = f.repo.Submit(f.ctx, f.request(t)); err != nil {
		t.Fatal("deploy submit")
	}
	if f.count(t, `SELECT count(*) FROM audit_records WHERE target_kind='exec'`) != before {
		t.Fatal("a deployment was journaled as an exec")
	}
}

// Incomplete identity is refused before anything is stored.
func TestExecSubmitRefusesIncompleteIdentity(t *testing.T) {
	f := newFixture(t)
	f.putTemplate(t, noneTemplate())
	f.execPolicy(t, "db-check")
	params := map[string]string{"table": "users"}
	for name, mut := range map[string]func(*ExecRequest){
		"nil org":       func(r *ExecRequest) { r.OrgID = uuid.Nil },
		"nil scope":     func(r *ExecRequest) { r.Scope = tenancy.Scope{} },
		"unknown actor": func(r *ExecRequest) { r.Actor.Type = "robot" },
		"bad via":       func(r *ExecRequest) { r.Actor.Via = "carrier-pigeon" },
		"empty actor":   func(r *ExecRequest) { r.Actor.ID = "" },
		"bad request":   func(r *ExecRequest) { r.RequestID = "not an id" },
	} {
		in := f.execRequest(t, "db-check", params)
		mut(&in)
		if _, err := f.repo.SubmitExec(f.ctx, in); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("accepted: " + name)
		}
	}
	if f.jobs(t) != 0 || f.count(t, `SELECT count(*) FROM deployment_requests`) != 0 {
		t.Fatal("a refused request left rows")
	}
}

// A stored template row that was edited behind the API is re-validated on
// every read; one that no longer validates or names another id is absent.
func TestExecStoredTemplateIsRevalidated(t *testing.T) {
	for name, edit := range map[string]string{
		"id differs":     `UPDATE exec_templates SET template=jsonb_set(template,'{id}','"other"')`,
		"became unsafe":  `UPDATE exec_templates SET template=jsonb_set(template,'{argv}','["/bin/sh","-c","{table}"]')`,
		"not a template": `UPDATE exec_templates SET template='{"id":"db-check"}'::jsonb`,
	} {
		f := newFixture(t)
		f.putTemplate(t, noneTemplate())
		f.execPolicy(t, "db-check")
		if _, err := f.pool.Exec(f.ctx, edit); err != nil {
			t.Fatal("edit the row: " + name)
		}
		if _, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "users"})); !errors.Is(err, ErrTemplateUnknown) {
			t.Fatal("edited template accepted: " + name)
		}
	}
}

// The approver sees every parameter name, in a stable order.
func TestExecApprovalListsParameterNamesSorted(t *testing.T) {
	f := newFixture(t)
	// Six names: map order is random, so an unsorted list passes by luck
	// once in 720 runs.
	names := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"}
	tpl := netTemplate("api.github.com")
	tpl.Argv = []string{"/usr/bin/curl", "https://api.github.com/repos"}
	tpl.Params = map[string]runnerproto.ExecParam{}
	values := map[string]string{}
	for _, n := range names {
		tpl.Argv = append(tpl.Argv, "--data-urlencode", "{"+n+"}")
		tpl.Params[n] = runnerproto.ExecParam{Pattern: `^[a-z]{1,10}$`}
		values[n] = "x"
	}
	f.putTemplate(t, tpl)
	out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", values))
	if err != nil {
		t.Fatal("submit")
	}
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil || a.Exec == nil || strings.Join(a.Exec.ParamNames, ",") != strings.Join(names, ",") {
		t.Fatal("approval does not list the parameter names in order")
	}
}
