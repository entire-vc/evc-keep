package deployment

import (
	"errors"
	"fmt"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/execpolicy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

func (f fixture) putTemplate(t *testing.T, tpl runnerproto.ExecTemplate) {
	t.Helper()
	if err := f.repo.PutExecTemplate(f.ctx, f.org, tpl); err != nil {
		t.Fatal("register exec template")
	}
}

func netTemplate(hosts ...string) runnerproto.ExecTemplate {
	t := runnerproto.ExecTemplate{ID: "gh-issues", Argv: []string{"/usr/bin/curl", "https://api.github.com/repos", "-d", "{path}"}, SecretEnv: []string{"API_KEY"},
		Params:  map[string]runnerproto.ExecParam{"path": {Pattern: `^[a-z][a-z0-9_/-]{0,63}$`}},
		Network: runnerproto.ExecNetwork{Mode: "allowlist"}}
	for _, h := range hosts {
		t.Network.Destinations = append(t.Network.Destinations, runnerproto.ExecDestination{Host: h, Port: 443})
	}
	return t
}

func noneTemplate() runnerproto.ExecTemplate {
	return runnerproto.ExecTemplate{ID: "db-check", Argv: []string{"/usr/local/bin/dbcheck", "--table", "{table}"}, SecretEnv: []string{"DB_PASSWORD"},
		Params:  map[string]runnerproto.ExecParam{"table": {Pattern: `^[a-z_]{1,30}$`}},
		Network: runnerproto.ExecNetwork{Mode: "none"}}
}

func (f fixture) execRequest(t *testing.T, tpl string, params map[string]string) ExecRequest {
	t.Helper()
	return ExecRequest{OrgID: f.org, Scope: tenancy.Org(f.org), SecretID: f.secret, VersionID: f.version, RunnerID: f.runner,
		RequestID: mustID(t).String(), TemplateID: tpl, Params: params,
		Actor: audit.Actor{Type: audit.ActorUser, ID: f.user.String(), Via: audit.ViaAPI}}
}

// execPolicy names one secret/template/runner in the organization's exec rules.
func (f fixture) execPolicy(t *testing.T, template string) {
	t.Helper()
	rules := `{"rules":[],"exec_rules":[{"secret_id":"` + f.secret.String() + `","template_id":"` + template + `","runner_id":"` + f.runner.String() + `"}]}`
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO deployment_policies(org_id,rules) VALUES($1,$2) ON CONFLICT (org_id) DO UPDATE SET rules=EXCLUDED.rules`, f.org, rules); err != nil {
		t.Fatal("insert exec policy")
	}
}

func (f fixture) jobs(t *testing.T) int { return f.count(t, `SELECT count(*) FROM deployment_jobs`) }

// The AC8 test: a network template creates an approval and no job at all.
func TestExecNetworkTemplateCreatesNoJobBeforeApproval(t *testing.T) {
	f := newFixture(t)
	f.putTemplate(t, netTemplate("api.github.com"))
	f.execPolicy(t, "gh-issues") // a matching rule must not be enough for a network template
	out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/x"}))
	if err != nil || out.Status != NeedsApproval || out.ApprovalID == uuid.Nil || out.JobID != uuid.Nil {
		t.Fatal("network template was not held for approval")
	}
	if f.jobs(t) != 0 {
		t.Fatal("job row exists before approval")
	}
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil || len(a.NetAllowlist) != 1 || a.NetAllowlist[0] != "api.github.com:443" {
		t.Fatal("approver is not shown the destinations")
	}
}

// Positive control: network none follows policy and is queued without a human.
func TestExecNoneTemplateQueuesByPolicyAndCarriesTheTemplate(t *testing.T) {
	f := newFixture(t)
	f.putTemplate(t, noneTemplate())
	f.execPolicy(t, "db-check")
	out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "users"}))
	if err != nil || out.Status != Queued || out.JobID == uuid.Nil || out.ApprovalID != uuid.Nil {
		t.Fatal("network none template was not queued by policy")
	}
	var payload []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT job_payload FROM deployment_jobs WHERE id=$1`, out.JobID).Scan(&payload); err != nil {
		t.Fatal("read job")
	}
	job, err := runnerproto.DecodeJob(payload)
	tpl, _ := noneTemplate().Template()
	if err != nil || job.Action != runnerproto.ActionExec || job.Exec == nil || job.Exec.TemplateID != "db-check" ||
		job.Exec.Digest != execpolicy.Digest(tpl) || job.Exec.Params["table"] != "users" || job.Target != (runnerproto.Target{}) {
		t.Fatal("job does not carry the registered template")
	}
}

// Without a rule naming this secret, template and host, a network none exec
// waits for a human, exactly like a deployment of that secret.
func TestExecNoneTemplateWithoutAMatchingRuleWaitsForApproval(t *testing.T) {
	f := newFixture(t)
	f.putTemplate(t, noneTemplate())
	other := noneTemplate()
	other.ID = "db-other"
	f.putTemplate(t, other)
	// Ordered: the first case must run before any rule exists.
	for i, c := range []struct{ name, tpl string }{{"no policy", "db-check"}, {"rule names another template", "db-other"}} {
		if i == 1 {
			f.execPolicy(t, "db-check")
		}
		out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, c.tpl, map[string]string{"table": "users"}))
		if err != nil || out.Status != NeedsApproval || out.JobID != uuid.Nil || f.jobs(t) != 0 {
			t.Fatal("exec ran without a rule: " + c.name)
		}
	}
}

func TestExecProductionSecretWaitsEvenWithNetworkNone(t *testing.T) {
	f := newFixture(t)
	f.putTemplate(t, noneTemplate())
	f.execPolicy(t, "db-check")
	if _, err := f.pool.Exec(f.ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.secret); err != nil {
		t.Fatal("set prod")
	}
	out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "users"}))
	if err != nil || out.Status != NeedsApproval || f.jobs(t) != 0 {
		t.Fatal("production secret ran without a human")
	}
}

func TestExecApprovalCreatesExactlyTheShownJob(t *testing.T) {
	f := newFixture(t)
	boss := f.approver(t)
	f.putTemplate(t, netTemplate("api.github.com"))
	out, _ := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/x"}))
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil {
		t.Fatal("read approval")
	}
	res, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash})
	if err != nil || res.Status != "approved" || res.JobID == uuid.Nil || f.jobs(t) != 1 {
		t.Fatal("approval did not create the job")
	}
	var payload []byte
	_ = f.pool.QueryRow(f.ctx, `SELECT job_payload FROM deployment_jobs WHERE id=$1`, res.JobID).Scan(&payload)
	job, err := runnerproto.DecodeJob(payload)
	if err != nil || job.Action != runnerproto.ActionExec || job.Exec.TemplateID != "gh-issues" || job.Exec.Params["path"] != "repos/x" {
		t.Fatal("approved job is not the requested one")
	}
	rej, _ := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/y"}))
	ra, _ := f.repo.GetApproval(f.ctx, f.org, rej.ApprovalID)
	if _, err = f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: rej.ApprovalID, ApproverID: boss, ApproverIsUser: true, Reason: "no", BindingHash: ra.BindingHash}); err != nil || f.jobs(t) != 1 {
		t.Fatal("rejection created a job")
	}
}

// Approving with a different destination set is refused, in both ways it can
// happen: the stored request edited behind the console, and the organization's
// template replaced after the approver looked.
func TestExecApprovalRefusedWhenDestinationsChange(t *testing.T) {
	f := newFixture(t)
	boss := f.approver(t)
	decide := func(out Outcome, hash string) error {
		_, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: hash})
		return err
	}
	t.Run("stored destinations edited", func(t *testing.T) {
		f.putTemplate(t, netTemplate("api.github.com"))
		out, _ := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/x"}))
		a, _ := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
		for _, sql := range []string{`ALTER TABLE deployment_requests DISABLE TRIGGER deployment_requests_frozen`,
			`UPDATE deployment_requests SET exec=jsonb_set(exec,'{destinations}','["attacker.example:443"]') WHERE id=(SELECT deployment_request_id FROM approval_requests WHERE id='` + out.ApprovalID.String() + `')`,
			`ALTER TABLE deployment_requests ENABLE TRIGGER deployment_requests_frozen`} {
			if _, err := f.pool.Exec(f.ctx, sql); err != nil {
				t.Fatal("tamper setup failed")
			}
		}
		if err := decide(out, a.BindingHash); !errors.Is(err, ErrBindingMismatch) || f.jobs(t) != 0 {
			t.Fatal("approval of other destinations was accepted")
		}
	})
	t.Run("stored parameters edited", func(t *testing.T) {
		f.putTemplate(t, netTemplate("api.github.com"))
		out, _ := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/p"}))
		a, _ := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
		for _, sql := range []string{`ALTER TABLE deployment_requests DISABLE TRIGGER deployment_requests_frozen`,
			`UPDATE deployment_requests SET exec=jsonb_set(exec,'{params,path}','"other"') WHERE id=(SELECT deployment_request_id FROM approval_requests WHERE id='` + out.ApprovalID.String() + `')`,
			`ALTER TABLE deployment_requests ENABLE TRIGGER deployment_requests_frozen`} {
			if _, err := f.pool.Exec(f.ctx, sql); err != nil {
				t.Fatal("tamper setup failed")
			}
		}
		if err := decide(out, a.BindingHash); !errors.Is(err, ErrBindingMismatch) || f.jobs(t) != 0 {
			t.Fatal("approval of other parameters was accepted")
		}
	})
	t.Run("template replaced after the request", func(t *testing.T) {
		f.putTemplate(t, netTemplate("api.github.com"))
		out, _ := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/z"}))
		a, _ := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
		f.putTemplate(t, netTemplate("api.github.com", "uploads.example.net"))
		if err := decide(out, a.BindingHash); !errors.Is(err, ErrRefused) || f.jobs(t) != 0 {
			t.Fatal("approval covered a template with other destinations")
		}
	})
}

func TestExecRequestIsIdempotentAndRefusesBadInput(t *testing.T) {
	f := newFixture(t)
	f.putTemplate(t, noneTemplate())
	f.execPolicy(t, "db-check")
	in := f.execRequest(t, "db-check", map[string]string{"table": "users"})
	first, err := f.repo.SubmitExec(f.ctx, in)
	again, err2 := f.repo.SubmitExec(f.ctx, in)
	if err != nil || err2 != nil || again.ID != first.ID || again.Created || f.jobs(t) != 1 {
		t.Fatal("replay was not idempotent")
	}
	in.Params = map[string]string{"table": "orders"}
	if _, err = f.repo.SubmitExec(f.ctx, in); !errors.Is(err, ErrConflict) {
		t.Fatal("changed params under the same request id")
	}
	if _, err = f.repo.SubmitExec(f.ctx, f.execRequest(t, "nope", nil)); !errors.Is(err, ErrTemplateUnknown) {
		t.Fatal("unknown template accepted")
	}
	if _, err = f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "users", "extra": "x"})); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("parameter the template does not declare accepted")
	}
	if _, err = f.repo.SubmitExec(f.ctx, f.execRequest(t, "db-check", map[string]string{"table": "users; rm"})); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("param outside its pattern accepted")
	}
	if err = f.repo.PutExecTemplate(f.ctx, f.org, runnerproto.ExecTemplate{ID: "sh", Argv: []string{"/bin/sh", "-c", "true"}, SecretEnv: []string{"A"}, Network: runnerproto.ExecNetwork{Mode: "none"}}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("interpreter template registered")
	}
}

// Leak test: the value of a parameter is bound by the hash and carried in the
// job, but never repeated in the journal (at request or at decision), in an
// error, or in what an approver is shown.
func TestExecLeaksNothingBeyondTheClosedFields(t *testing.T) {
	f := newFixture(t)
	boss := f.approver(t)
	can := canary.New()
	f.putTemplate(t, netTemplate("api.github.com"))
	out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": can.Value(1)}))
	if err != nil {
		t.Fatal("submit")
	}
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil {
		t.Fatal("read approval")
	}
	if _, err = f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash}); err != nil {
		t.Fatal("approve")
	}
	var journal string
	if err = f.pool.QueryRow(f.ctx, `SELECT coalesce(string_agg(r::text,' '),'') FROM audit_records r`).Scan(&journal); err != nil || journal == "" {
		t.Fatal("read journal")
	}
	if can.In(journal) {
		t.Fatal("parameter value reached the journal")
	}
	if f.count(t, `SELECT count(*) FROM audit_records WHERE target_kind='exec'`) < 3 {
		t.Fatal("journal does not say these were exec records")
	}
	if a.Exec == nil {
		t.Fatal("approval card has no exec part")
	}
	if can.In(fmt.Sprintf("%+v", *a.Exec)) {
		t.Fatal("approval card holds a parameter value")
	}
	// Positive control: the value is stored (it travels in the job), so the
	// scan below would see it if the card read it back.
	var stored string
	if err = f.pool.QueryRow(f.ctx, `SELECT exec::text FROM deployment_requests WHERE id=(SELECT deployment_request_id FROM approval_requests WHERE id=$1)`, out.ApprovalID).Scan(&stored); err != nil || !can.In(stored) {
		t.Fatal("positive control: the stored request does not hold the value")
	}
	_, err = f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "BAD " + can.Value(2)}))
	if !errors.Is(err, ErrInvalidArgument) || can.In(err.Error()) {
		t.Fatal("error repeats the rejected value")
	}
}

// A rule names one secret: another (non-production) secret with the same
// template and runner still waits for a human.
func TestExecRuleIsBoundToItsSecret(t *testing.T) {
	f := newFixture(t)
	f.putTemplate(t, noneTemplate())
	f.execPolicy(t, "db-check")
	other, otherVersion := mustID(t), mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'OTHER_SECRET',(SELECT class FROM secrets WHERE id=$3),'generic',$4,'builtin://other')`, other, f.org, f.secret, f.store); err != nil {
		t.Fatal("create second secret")
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'v1','kfp1:k1:abcdefghijklmnop',12)`, otherVersion, f.org, other); err != nil {
		t.Fatal("create second version")
	}
	in := f.execRequest(t, "db-check", map[string]string{"table": "users"})
	in.SecretID, in.VersionID = other, otherVersion
	out, err := f.repo.SubmitExec(f.ctx, in)
	if err != nil || out.Status != NeedsApproval || f.jobs(t) != 0 {
		t.Fatal("a rule for one secret admitted another")
	}
}

func TestPolicyRejectsMalformedExecRules(t *testing.T) {
	id := mustID(t)
	for name, r := range map[string]ExecRule{
		"no secret":         {TemplateID: "db-check", RunnerID: "r"},
		"bad template":      {SecretID: id, TemplateID: "DB check", RunnerID: "r"},
		"no host selection": {SecretID: id, TemplateID: "db-check"},
	} {
		if validPolicy(Policy{ExecRules: []ExecRule{r}}) {
			t.Fatal("accepted: " + name)
		}
	}
	if !validPolicy(Policy{ExecRules: []ExecRule{{SecretID: id, TemplateID: "db-check", RunnerID: "r"}}}) {
		t.Fatal("refused a well-formed rule")
	}
}
