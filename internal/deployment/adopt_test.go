package deployment

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// Adoption uses the real enrolled registry lookup. The older deployment
// fixture's trust adapter must not stand in for delivery authorization here.
func adoptionFixture(t *testing.T) (fixture, AdoptRequest) {
	t.Helper()
	f := newFixture(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate disposable runner key")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE runners SET hpke_public_key=$2,uid_shared=false,host_labels='{"platform":"linux"}',attrs_source='enroll_token' WHERE id=$1`, f.runner, key.PublicKey().Bytes()); err != nil {
		t.Fatal("enroll disposable delivery trust")
	}
	f.repo = NewRepo(f.pool, audit.NewJournal(f.pool))
	return f, AdoptRequest{OrgID: f.org, Scope: tenancy.Org(f.org), SecretID: f.secret, RunnerID: f.runner, RequestID: mustID(t).String(),
		Target: runnerproto.Target{Kind: runnerproto.TargetYAMLScalar, Path: "/srv/app/config.yaml", Field: "service.token", Mode: 0o600},
		Actor:  audit.Actor{Type: audit.ActorUser, ID: f.user.String(), Via: audit.ViaAPI}}
}

func (f fixture) adoptionPolicy(t *testing.T, in AdoptRequest) {
	t.Helper()
	p := Policy{Rules: []Rule{}, AdoptionRules: []AdoptionRule{{SecretID: in.SecretID, RunnerID: in.RunnerID, Kind: in.Target.Kind, Path: in.Target.Path, Field: in.Target.Field}}}
	if _, err := f.repo.SetPolicy(f.ctx, PolicyChange{OrgID: f.org, Policy: p, ExpectRevision: -1, Actor: in.Actor}); err != nil {
		t.Fatal("set exact adoption policy")
	}
}

func (f fixture) addAdoptionVersion(t *testing.T, version string) uuid.UUID {
	t.Helper()
	id := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,$4,'kfp1:k1:bbbbbbbbbbbbbbbb',12)`, id, f.org, f.secret, version); err != nil {
		t.Fatal("add disposable current version")
	}
	return id
}

func TestAdoptQueuesOnlyReadOfCurrentVersionAndIdempotentRetry(t *testing.T) {
	f, in := adoptionFixture(t)
	f.adoptionPolicy(t, in)
	current := f.addAdoptionVersion(t, "v2")
	out, err := f.repo.SubmitAdopt(f.ctx, in)
	if err != nil || out.Status != Queued || out.JobID == uuid.Nil || !out.Created {
		t.Fatalf("exact rule did not queue an adoption: %v", err)
	}
	var payload []byte
	var version uuid.UUID
	var action string
	var adoption bool
	if err = f.pool.QueryRow(f.ctx, `SELECT j.job_payload,j.version_id,j.action,d.adoption FROM deployment_jobs j JOIN deployment_requests d ON d.id=j.deployment_request_id WHERE j.id=$1`, out.JobID).Scan(&payload, &version, &action, &adoption); err != nil {
		t.Fatal("read stored adoption")
	}
	job, err := runnerproto.DecodeJob(payload)
	if err != nil || action != "adopt" || !adoption || version != current || job.Action != runnerproto.ActionAdopt ||
		job.Target != in.Target || job.ExpectedVersion != "v2" || job.NeedsValue() || !job.NeedsFingerprintKey() || job.NotAfter.Sub(job.IssuedAt) != runnerproto.MaxJobTTL {
		t.Fatal("stored job is not a bounded, current-version, key-only adoption")
	}
	f.addAdoptionVersion(t, "v3")
	again, err := f.repo.SubmitAdopt(f.ctx, in)
	if err != nil || again.Created || !sameDecision(again, out) || f.count(t, `SELECT count(*) FROM deployment_jobs`) != 1 {
		t.Fatal("retry after a version change created another job")
	}
	in.Target.Field = "other.token"
	if _, err = f.repo.SubmitAdopt(f.ctx, in); !errors.Is(err, ErrConflict) {
		t.Fatal("changed field reused the adoption request id")
	}
	if f.count(t, `SELECT count(*) FROM carriers`) != 0 || f.count(t, `SELECT count(*) FROM deployment_jobs WHERE action='deploy'`) != 0 ||
		f.count(t, `SELECT count(*) FROM audit_records WHERE action LIKE 'deploy.%' AND action<>'deploy.policy_set'`) != 0 ||
		f.count(t, `SELECT count(*) FROM audit_records WHERE action='carrier.adopt.requested'`) != 1 {
		t.Fatal("request created a carrier or claimed a deployment")
	}
}

func TestAdoptApprovalShowsReadAndCreatesOnlyTheBoundAction(t *testing.T) {
	f, in := adoptionFixture(t)
	// An ordinary deployment rule for the same YAML path does not grant adoption.
	p := Policy{Rules: []Rule{{SecretID: f.secret, RunnerID: f.runner.String(), Kind: runnerproto.TargetYAMLScalar, PathPrefix: "/srv/app"}}}
	if _, err := f.repo.SetPolicy(f.ctx, PolicyChange{OrgID: f.org, Policy: p, ExpectRevision: -1, Actor: in.Actor}); err != nil {
		t.Fatal("set ordinary policy")
	}
	out, err := f.repo.SubmitAdopt(f.ctx, in)
	if err != nil || out.Status != NeedsApproval || out.JobID != uuid.Nil {
		t.Fatal("ordinary deploy permission authorized adoption")
	}
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil || !a.Adopt || a.Exec != nil || a.Rotate || a.Target != in.Target {
		t.Fatal("approval did not show the exact read-only operation")
	}
	boss := f.approver(t)
	decide := DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash}
	wrong := decide
	wrong.BindingHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err = f.repo.Decide(f.ctx, wrong); !errors.Is(err, ErrBindingMismatch) {
		t.Fatal("unbound approval accepted")
	}
	wrong = decide
	wrong.ApproverID = f.user
	if _, err = f.repo.Decide(f.ctx, wrong); !errors.Is(err, ErrSelfApproval) {
		t.Fatal("requester approved their own adoption")
	}
	wrong = decide
	wrong.ApproverIsUser = false
	if _, err = f.repo.Decide(f.ctx, wrong); !errors.Is(err, ErrNotHuman) {
		t.Fatal("agent approved adoption")
	}
	res, err := f.repo.Decide(f.ctx, decide)
	if err != nil || res.Status != "approved" || res.JobID == uuid.Nil {
		t.Fatalf("bound human decision failed: %v", err)
	}
	var payload []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT job_payload FROM deployment_jobs WHERE id=$1`, res.JobID).Scan(&payload); err != nil {
		t.Fatal("read approved job")
	}
	job, err := runnerproto.DecodeJob(payload)
	if err != nil || job.Action != runnerproto.ActionAdopt || job.Target != in.Target || job.ExpectedVersion != "v1" || job.NeedsValue() {
		t.Fatal("approval created a different operation")
	}
	if _, err = f.repo.Decide(f.ctx, decide); !errors.Is(err, ErrAlreadyDecided) || f.count(t, `SELECT count(*) FROM deployment_jobs`) != 1 {
		t.Fatal("approval replay created another job")
	}
}

func TestAdoptApprovalCannotReviveStaleVersionOrTrust(t *testing.T) {
	for _, name := range []string{"version", "revoked", "expired", "keyless", "shared_prod"} {
		t.Run(name, func(t *testing.T) {
			f, in := adoptionFixture(t)
			out, err := f.repo.SubmitAdopt(f.ctx, in)
			if err != nil || out.Status != NeedsApproval {
				t.Fatal("create pending adoption")
			}
			a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
			if err != nil {
				t.Fatal("read pending adoption")
			}
			var mutation string
			switch name {
			case "version":
				f.addAdoptionVersion(t, "v2")
			case "revoked":
				mutation = `UPDATE runners SET revoked_at=now() WHERE id=$1`
			case "expired":
				mutation = `UPDATE runners SET cert_not_after=now()-interval '1 second' WHERE id=$1`
			case "keyless":
				mutation = `UPDATE runners SET hpke_public_key=NULL WHERE id=$1`
			case "shared_prod":
				if _, err = f.pool.Exec(f.ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.secret); err != nil {
					t.Fatal("mark disposable production class")
				}
				mutation = `UPDATE runners SET uid_shared=true WHERE id=$1`
			}
			if mutation != "" {
				if _, err = f.pool.Exec(f.ctx, mutation, f.runner); err != nil {
					t.Fatal("change disposable trust")
				}
			}
			_, err = f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: f.approver(t), ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash})
			if !errors.Is(err, ErrRefused) || f.count(t, `SELECT count(*) FROM deployment_jobs`) != 0 || f.count(t, `SELECT count(*) FROM carriers`) != 0 {
				t.Fatal("stale approval created delivery evidence")
			}
		})
	}
}

func TestAdoptProductionNeedsApprovalForEveryRequest(t *testing.T) {
	f, in := adoptionFixture(t)
	f.adoptionPolicy(t, in)
	if _, err := f.pool.Exec(f.ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.secret); err != nil {
		t.Fatal("mark disposable production class")
	}
	boss := f.approver(t)
	for range 2 {
		in.RequestID = mustID(t).String()
		out, err := f.repo.SubmitAdopt(f.ctx, in)
		if err != nil || out.Status != NeedsApproval || out.JobID != uuid.Nil {
			t.Fatal("production inherited a rule or an older approval")
		}
		a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
		if err != nil {
			t.Fatal("read prod approval")
		}
		if _, err = f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: a.ID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash}); err != nil {
			t.Fatal("approve exact production read")
		}
	}
}

func TestAdoptForeignReferencesAndRevokedTrustCreateNothing(t *testing.T) {
	for _, name := range []string{"runner", "secret", "org", "scope", "revoked"} {
		t.Run(name, func(t *testing.T) {
			f, in := adoptionFixture(t)
			f.adoptionPolicy(t, in)
			switch name {
			case "runner":
				in.RunnerID = mustID(t)
			case "secret":
				in.SecretID = mustID(t)
			case "org":
				in.OrgID = mustID(t)
				in.Scope = tenancy.Org(in.OrgID)
			case "scope":
				in.Scope = tenancy.Org(mustID(t))
			case "revoked":
				if _, err := f.pool.Exec(f.ctx, `UPDATE runners SET revoked_at=$2 WHERE id=$1`, f.runner, time.Now()); err != nil {
					t.Fatal("revoke disposable runner")
				}
			}
			if _, err := f.repo.SubmitAdopt(f.ctx, in); !errors.Is(err, ErrNotFound) || f.count(t, `SELECT count(*) FROM deployment_jobs`) != 0 {
				t.Fatal("foreign reference or revoked trust created a job")
			}
		})
	}
}

func TestAdoptionPolicyNeedsExactDestinationAndSeparatePermission(t *testing.T) {
	secret, runner := uuid.New(), uuid.New()
	target := runnerproto.Target{Kind: runnerproto.TargetYAMLScalar, Path: "/srv/app/config.yaml", Field: "service.token", Mode: 0o600}
	host := Host{ID: runner.String(), AttributesKnown: true}
	p := Policy{AdoptionRules: []AdoptionRule{{SecretID: secret, RunnerID: runner, Kind: target.Kind, Path: target.Path, Field: target.Field}}}
	if d, err := EvaluateAdoption(p, host, secret, "dev", target); err != nil || d != Allow {
		t.Fatal("exact positive control did not allow")
	}
	for _, change := range []func(*Policy){
		func(p *Policy) {
			p.AdoptionRules = nil
			p.Rules = []Rule{{SecretID: secret, RunnerID: runner.String(), Kind: target.Kind, PathPrefix: "/srv/app"}}
		},
		func(p *Policy) { p.AdoptionRules[0].Path += ".other" },
		func(p *Policy) { p.AdoptionRules[0].Field = "other.token" },
		func(p *Policy) { p.AdoptionRules[0].SecretID = uuid.New() },
		func(p *Policy) { p.AdoptionRules[0].RunnerID = uuid.New() },
	} {
		q := p
		q.AdoptionRules = append([]AdoptionRule(nil), p.AdoptionRules...)
		change(&q)
		if d, err := EvaluateAdoption(q, host, secret, "dev", target); err != nil || d != ApprovalRequired {
			t.Fatal("a neighboring destination or deployment rule granted adoption")
		}
	}
	q := p
	q.AdoptionRules = append(q.AdoptionRules, q.AdoptionRules[0])
	if validPolicy(q) {
		t.Fatal("duplicate adoption rules accepted")
	}
	raw, _ := json.Marshal(p)
	decoded, err := DecodePolicy(raw)
	if err != nil || !validPolicy(decoded) || len(policyKeys(decoded)) != 1 {
		t.Fatal("operator policy format cannot represent adoption")
	}
}
