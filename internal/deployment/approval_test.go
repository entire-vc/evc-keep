package deployment

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// approver inserts a second human into the fixture organization.
func (f fixture) approver(t *testing.T) uuid.UUID {
	t.Helper()
	id := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO users(id,org_id,email) VALUES($1,$2,$3)`, id, f.org, id.String()+"@example.invalid"); err != nil {
		t.Fatal("insert approver")
	}
	return id
}

func (f fixture) pending(t *testing.T) (Request, Outcome, Approval) {
	t.Helper()
	in := f.request(t)
	out, err := f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != NeedsApproval {
		t.Fatal("request was not held for approval")
	}
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil {
		t.Fatal("read approval")
	}
	return in, out, a
}

func (f fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, query, args...).Scan(&n); err != nil {
		t.Fatal("count query failed")
	}
	return n
}

func TestApprovalShowsWhatWillRun(t *testing.T) {
	f := newFixture(t)
	in, out, a := f.pending(t)
	if a.Status != "requested" || a.Target != in.Target || a.SecretName != "DB_PASSWORD" || a.RunnerID != f.runner ||
		a.Requester.ID != f.user.String() || a.Requester.Type != audit.ActorUser || len(a.BindingHash) != 64 || a.ID != out.ApprovalID {
		t.Fatalf("approval card does not carry the full request: %+v", a)
	}
	if !a.ExpiresAt.After(a.RequestedAt) || a.ExpiresAt.Sub(a.RequestedAt).Hours() != 24 {
		t.Fatal("approval TTL is not 24h")
	}
	if n := f.count(t, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='approval.requested' AND policy_rule_id=$2`, f.org.String(), "approval-binding:"+a.BindingHash); n != 1 {
		t.Fatalf("approval.requested records = %d, want 1", n)
	}
}

func TestDecideApproveCreatesExactlyTheShownJob(t *testing.T) {
	f := newFixture(t)
	in, out, a := f.pending(t)
	boss := f.approver(t)
	res, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash, Reason: "ok"})
	if err != nil || res.Status != "approved" || res.JobID == uuid.Nil {
		t.Fatalf("approve failed: %v", err)
	}
	var payload []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT job_payload FROM deployment_jobs WHERE id=$1`, res.JobID).Scan(&payload); err != nil {
		t.Fatal("job missing")
	}
	job, err := runnerproto.DecodeJob(payload)
	if err != nil || job.Target != in.Target {
		t.Fatal("job target is not the approved target")
	}
	rep, err := f.repo.Report(f.ctx, f.org, in.RequestID)
	if err != nil || rep.ApprovalStatus != "approved" || rep.Done {
		t.Fatal("report must show an approved, still pending request")
	}
	rows := f.count(t, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='approval.decided' AND approval_approver_id=$2 AND approval_id=$3 AND policy_decision='allow' AND policy_rule_id=$4`,
		f.org.String(), boss.String(), out.ApprovalID.String(), "approval-binding:"+a.BindingHash)
	if rows != 1 {
		t.Fatal("approval.decided must carry who, the decision and the hash")
	}
	if f.count(t, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='approval.decided' AND actor_type='user' AND actor_id=$2`, f.org.String(), boss.String()) != 1 {
		t.Fatal("approval.decided must name the approver as the actor")
	}
	// A second decision on the same approval is refused and creates nothing.
	if _, err = f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash}); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatal("approval decided twice")
	}
	if n := f.count(t, `SELECT count(*) FROM deployment_jobs`); n != 1 {
		t.Fatal("second decision created another job")
	}
}

func TestDecideRejectCreatesNoJob(t *testing.T) {
	f := newFixture(t)
	_, out, a := f.pending(t)
	boss := f.approver(t)
	res, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, BindingHash: a.BindingHash, Reason: "no"})
	if err != nil || res.Status != "rejected" || res.JobID != uuid.Nil {
		t.Fatal("reject failed")
	}
	if n := f.count(t, `SELECT count(*) FROM deployment_jobs`); n != 0 {
		t.Fatal("rejected request created a job")
	}
	if n := f.count(t, `SELECT count(*) FROM audit_records WHERE action='approval.decided' AND policy_decision='deny' AND intent_reason='no'`); n != 1 {
		t.Fatal("rejection not journaled with its reason")
	}
}

// Test 1: approving A, then swapping the target, must not run the swapped one.
func TestApprovalBoundToHashTargetSwapRunsNothing(t *testing.T) {
	f := newFixture(t)
	boss := f.approver(t)

	t.Run("stale hash shown to the approver", func(t *testing.T) {
		_, out, a := f.pending(t)
		stale := strings.Repeat("0", len(a.BindingHash))
		_, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: stale})
		if !errors.Is(err, ErrBindingMismatch) {
			t.Fatal("approval with a hash that is not the shown one was accepted")
		}
		if n := f.count(t, `SELECT count(*) FROM deployment_jobs`); n != 0 {
			t.Fatal("job created for a stale hash")
		}
	})
	t.Run("changed target is a new request needing its own approval", func(t *testing.T) {
		in, out, a := f.pending(t)
		if _, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash}); err != nil {
			t.Fatal("approve A")
		}
		in.RequestID = mustID(t).String()
		in.Target.Path = "/srv/app/other"
		next, err := f.repo.Submit(f.ctx, in)
		if err != nil || next.Status != NeedsApproval || next.JobID != uuid.Nil || next.ApprovalID == out.ApprovalID {
			t.Fatal("approval of A covered a different target")
		}
	})
	t.Run("stored request edited behind the console", func(t *testing.T) {
		before := f.count(t, `SELECT count(*) FROM deployment_jobs`)
		_, out, a := f.pending(t)
		if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_requests SET target=jsonb_set(target,'{path}','"/etc/cron.d/x"') WHERE id=(SELECT deployment_request_id FROM approval_requests WHERE id=$1)`, out.ApprovalID); err == nil {
			t.Fatal("database let a stored request be edited")
		}
		// A database-level attacker removes the trigger as well. The hash recomputed from the stored row still refuses.
		for _, sql := range []string{`ALTER TABLE deployment_requests DISABLE TRIGGER deployment_requests_frozen`,
			`UPDATE deployment_requests SET target=jsonb_set(target,'{path}','"/etc/cron.d/x"') WHERE id=(SELECT deployment_request_id FROM approval_requests WHERE id='` + out.ApprovalID.String() + `')`,
			`ALTER TABLE deployment_requests ENABLE TRIGGER deployment_requests_frozen`} {
			if _, err := f.pool.Exec(f.ctx, sql); err != nil {
				t.Fatal("tamper setup failed")
			}
		}
		_, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash})
		if !errors.Is(err, ErrBindingMismatch) {
			t.Fatal("tampered request was approved")
		}
		if n := f.count(t, `SELECT count(*) FROM deployment_jobs`); n != before {
			t.Fatal("tampered request produced a job")
		}
	})
	t.Run("job payload swapped after approval", func(t *testing.T) {
		_, out, a := f.pending(t)
		res, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash})
		if err != nil {
			t.Fatal("approve")
		}
		if _, err = f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET job_payload='\x00'::bytea WHERE id=$1`, res.JobID); err == nil {
			t.Fatal("approved job payload could be swapped")
		}
	})
}

// Test 2 at the storage boundary: agents never approve, nobody approves their own request.
func TestDecideRefusesAgentAndSelf(t *testing.T) {
	f := newFixture(t)
	_, out, a := f.pending(t)
	cases := []struct {
		name string
		in   DecideInput
		want error
	}{
		{"agent", DecideInput{ApproverID: f.approver(t), ApproverIsUser: false}, ErrNotHuman},
		{"own request", DecideInput{ApproverID: f.user, ApproverIsUser: true}, ErrSelfApproval},
	}
	for _, c := range cases {
		c.in.OrgID, c.in.ApprovalID, c.in.Approve, c.in.BindingHash = f.org, out.ApprovalID, true, a.BindingHash
		if _, err := f.repo.Decide(f.ctx, c.in); !errors.Is(err, c.want) {
			t.Fatalf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM deployment_jobs`); n != 0 {
		t.Fatal("refused approval created a job")
	}
	if n := f.count(t, `SELECT count(*) FROM approval_requests WHERE status<>'requested'`); n != 0 {
		t.Fatal("refused approval changed the status")
	}
}

func TestDecideAgentRequestSponsorMayApprove(t *testing.T) {
	f := newFixture(t)
	agent := mustID(t)
	in := f.request(t)
	in.Actor = audit.Actor{Type: audit.ActorAgent, ID: agent.String(), SponsorID: f.user.String(), Via: audit.ViaAPI}
	out, err := f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != NeedsApproval {
		t.Fatal("agent request not held")
	}
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil || a.Requester.SponsorID != f.user.String() {
		t.Fatal("sponsor not on the card")
	}
	if _, err = f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: f.user, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash}); err != nil {
		t.Fatal("sponsor could not approve the agent request")
	}
}

// Test 3: after the TTL the approval is refused.
func TestDecideAfterTTLIsRefused(t *testing.T) {
	f := newFixture(t)
	_, out, a := f.pending(t)
	// Backdating needs the immutability trigger off; the trigger has its own test below.
	for _, sql := range []string{`ALTER TABLE approval_requests DISABLE TRIGGER approval_requests_frozen`,
		`UPDATE approval_requests SET expires_at=now()-interval '1 second'`,
		`ALTER TABLE approval_requests ENABLE TRIGGER approval_requests_frozen`} {
		if _, err := f.pool.Exec(f.ctx, sql); err != nil {
			t.Fatal("backdate setup failed")
		}
	}
	boss := f.approver(t)
	if got, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID); err != nil || got.Status != "expired" {
		t.Fatal("expired approval is not shown as expired")
	}
	if _, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash}); !errors.Is(err, ErrExpired) {
		t.Fatal("expired approval was accepted")
	}
	if n := f.count(t, `SELECT count(*) FROM deployment_jobs`); n != 0 {
		t.Fatal("expired approval created a job")
	}
}

func TestApprovalRowIsFrozenAfterDecision(t *testing.T) {
	f := newFixture(t)
	_, out, a := f.pending(t)
	boss := f.approver(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE approval_requests SET binding_hash=$2 WHERE id=$1`, out.ApprovalID, make([]byte, 32)); err == nil {
		t.Fatal("approval hash editable")
	}
	if _, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, BindingHash: a.BindingHash}); err != nil {
		t.Fatal("reject")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE approval_requests SET status='approved' WHERE id=$1`, out.ApprovalID); err == nil {
		t.Fatal("rejected approval flipped to approved")
	}
}

func TestApprovalListIsTenantScoped(t *testing.T) {
	f := newFixture(t)
	_, out, _ := f.pending(t)
	got, err := f.repo.ListApprovals(f.ctx, f.org, 50)
	if err != nil || len(got) != 1 || got[0].ID != out.ApprovalID {
		t.Fatal("list does not show the pending approval")
	}
	if other, err := f.repo.ListApprovals(f.ctx, mustID(t), 50); err != nil || len(other) != 0 {
		t.Fatal("list leaked another organization")
	}
	if _, err = f.repo.GetApproval(f.ctx, mustID(t), out.ApprovalID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign organization read an approval")
	}
}

// A human "yes" lifts only "needs approval". If the host became unsafe between
// the request and the decision, approving still creates nothing.
func TestDecideApproveRechecksPolicyAndHost(t *testing.T) {
	f := newFixture(t)
	_, out, a := f.pending(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.secret); err != nil {
		t.Fatal("make the secret production")
	}
	f.repo.trust = func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (Host, error) {
		return Host{AttributesKnown: true, UIDShared: true}, nil
	}
	boss := f.approver(t)
	_, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash})
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("a production secret on a shared UID was approved: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM deployment_jobs`); n != 0 {
		t.Fatal("refused approval created a job")
	}
	if got, gerr := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID); gerr != nil || got.Status != "requested" {
		t.Fatal("refused approval changed state")
	}
}

// The stored request cannot be edited while the approval is still open: the
// trigger, not the application, is what keeps "what was shown" fixed.
func TestApprovalContentIsImmutable(t *testing.T) {
	f := newFixture(t)
	_, out, _ := f.pending(t)
	for name, q := range map[string]string{
		"binding hash": `UPDATE approval_requests SET binding_hash=decode(repeat('00',32),'hex') WHERE id=$1`,
		"expiry":       `UPDATE approval_requests SET expires_at=expires_at+interval '1 year' WHERE id=$1`,
		"requester":    `UPDATE approval_requests SET requester_id='someone-else' WHERE id=$1`,
	} {
		if _, err := f.pool.Exec(f.ctx, q, out.ApprovalID); err == nil {
			t.Fatalf("%s of an open approval was editable", name)
		}
	}
}

// The hourly limit still applies when a human lifts "needs approval": the
// approval cannot be used to get past a rate limit the org has set.
func TestDecideApproveKeepsTheRateLimit(t *testing.T) {
	f := newFixture(t)
	_, first, a1 := f.pending(t)
	_, second, a2 := f.pending(t)
	f.policy(t, 1)
	boss := f.approver(t)
	if _, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: first.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a1.BindingHash}); err != nil {
		t.Fatalf("control: the first approval under the limit must pass: %v", err)
	}
	_, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: second.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a2.BindingHash})
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("approval got past the hourly limit: %v", err)
	}
	if f.count(t, `SELECT count(*) FROM deployment_jobs`) != 1 {
		t.Fatal("limited approval created a job")
	}
}

// A provider the runner cannot deliver from stays refused after approval.
func TestDecideApproveRefusesProviderTheRunnerCannotUse(t *testing.T) {
	f := newFixture(t)
	_, out, a := f.pending(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE stores SET provider='external-test' WHERE id=$1`, f.store); err != nil {
		t.Fatal("change provider")
	}
	boss := f.approver(t)
	_, err := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash})
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("approval of an undeliverable provider succeeded: %v", err)
	}
	if f.count(t, `SELECT count(*) FROM deployment_jobs`) != 0 {
		t.Fatal("undeliverable approval created a job")
	}
}
