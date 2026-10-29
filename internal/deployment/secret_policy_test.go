package deployment

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// Positive control: the explicitly selected secret may queue. The other
// secret in the same org has no target template and must require approval.
func TestReviewSecretPolicyIsolation(t *testing.T) {
	f := newFixture(t)
	f.policy(t, 10)
	rules, err := json.Marshal(map[string]any{"rules": []map[string]any{{
		"secret_id": f.secret.String(), "runner_id": f.runner.String(),
		"kind": "file", "path_prefix": "/srv/app",
	}}})
	if err != nil {
		t.Fatal("encode policy metadata")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_policies SET rules=$2 WHERE org_id=$1`, f.org, rules); err != nil {
		t.Fatal("set selected-secret template")
	}
	allowed, err := f.repo.Submit(f.ctx, f.request(t))
	if err != nil || allowed.Status != Queued || allowed.JobID == uuid.Nil {
		t.Fatal("positive control: selected secret did not queue")
	}
	t.Log("positive control: selected secret queued")
	otherSecret, otherVersion := mustID(t), mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'SECOND_SECRET','dev','generic',$3,'builtin://second')`, otherSecret, f.org, f.store); err != nil {
		t.Fatal("create second secret reference")
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'v1','kfp1:k1:abcdefghijklmnop',12)`, otherVersion, f.org, otherSecret); err != nil {
		t.Fatal("create second version metadata")
	}
	in := f.request(t)
	in.SecretID, in.VersionID = otherSecret, otherVersion
	out, err := f.repo.Submit(f.ctx, in)
	if err != nil {
		t.Fatal("submit second secret reference")
	}
	if out.Status != NeedsApproval || out.JobID != uuid.Nil || out.ApprovalID == uuid.Nil {
		t.Fatalf("secret without target template inherited organization rule: decision=%s job=%t approval=%t", out.Status, out.JobID != uuid.Nil, out.ApprovalID != uuid.Nil)
	}
	var jobs int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM deployment_jobs WHERE org_id=$1 AND secret_id=$2`, f.org, otherSecret).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("secret without template has a durable job")
	}
	t.Log("negative control: unselected secret requires approval without a job")
}

func TestSubmitUnboundSecretPolicyRequiresApproval(t *testing.T) {
	f := newFixture(t)
	f.policy(t, 10)
	// Existing organization-wide JSON is never an implicit wildcard.
	rules := `{"rules":[{"runner_id":"` + f.runner.String() + `","kind":"file","path_prefix":"/srv/app"}]}`
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_policies SET rules=$2 WHERE org_id=$1`, f.org, rules); err != nil {
		t.Fatal("set legacy policy metadata")
	}
	out, err := f.repo.Submit(f.ctx, f.request(t))
	if err != nil || out.Status != NeedsApproval || out.JobID != uuid.Nil || out.ApprovalID == uuid.Nil {
		t.Fatal("unbound policy created a job or missed approval")
	}
}

func TestSubmitSecretPolicyOrganizationIsolation(t *testing.T) {
	f := newFixture(t)
	otherOrg := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO organizations(id,name) VALUES($1,'other')`, otherOrg); err != nil {
		t.Fatal("create foreign organization")
	}
	rules, err := json.Marshal(Policy{Rules: []Rule{{SecretID: f.secret, RunnerID: f.runner.String(), Kind: "file", PathPrefix: "/srv/app"}}})
	if err != nil {
		t.Fatal("encode foreign organization policy metadata")
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO deployment_policies(org_id,rules) VALUES($1,$2)`, otherOrg, rules); err != nil {
		t.Fatal("set foreign organization policy metadata")
	}
	// The caller org has no policy. A foreign org's matching selectors cannot
	// authorize this request, even when its JSON names the same secret/runner.
	out, err := f.repo.Submit(f.ctx, f.request(t))
	if err != nil || out.Status != NeedsApproval || out.JobID != uuid.Nil || out.ApprovalID == uuid.Nil {
		t.Fatal("foreign organization policy authorized secret")
	}
}
