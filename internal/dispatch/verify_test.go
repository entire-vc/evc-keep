package dispatch

import (
	"context"
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// verifyJob queues a verify job for one carrier on the fixture's host and
// claims it, returning its id and decoded job.
func (f fixture) verifyJob(t *testing.T) (string, runnerproto.Job) {
	t.Helper()
	ctx := context.Background()
	org := f.peer.OrgID
	var secret uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM secrets WHERE org_id=$1`, org).Scan(&secret); err != nil {
		t.Fatal("read secret")
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO carriers(id,org_id,secret_id,version,host,target_kind,target_path,last_fp,state)
	 VALUES($1,$2,$3,'1','synthetic-host','file','/srv/app/key','kfp1:key:abcdefghijklmnop','registered')`, uuid.New(), org, secret); err != nil {
		t.Fatal("seed carrier")
	}
	repo := deployment.NewRepo(f.pool, audit.NewJournal(f.pool))
	reqID := uuid.NewString()
	if _, err := repo.SubmitVerify(ctx, deployment.VerifyRequest{OrgID: org, Scope: tenancy.Org(org), SecretID: secret, RequestID: reqID,
		Actor: audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}}); err != nil {
		t.Fatal("submit verify")
	}
	var id string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM deployment_jobs WHERE org_id=$1 AND action='verify'`, org).Scan(&id); err != nil {
		t.Fatal("no verify job queued")
	}
	for i := 0; i < 2; i++ {
		signed, ok, err := f.service.Poll(ctx, f.peer)
		if err != nil || !ok {
			t.Fatal("claim job")
		}
		job, err := runnerproto.DecodeJob(signed.Payload)
		if err != nil {
			t.Fatal("decode job")
		}
		if job.JobID == id {
			return id, job
		}
	}
	t.Fatal("verify job was not claimed")
	return "", runnerproto.Job{}
}

func TestVerifyJobNeedsNoValueAndReportsAfterTheKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, job := f.verifyJob(t)
	if job.Action != runnerproto.ActionVerify || job.NeedsValue() || job.Exec != nil || job.Target.Consumer != "" {
		t.Fatal("verify job must be consumer-less and value-less")
	}
	if job.Target.Mode != 0o600 || job.Target.UID != 0 || job.Target.GID != 0 {
		t.Fatal("verify job must carry the fixed non-owner target, not anything read from the carrier")
	}
	env, err := f.service.Material(ctx, f.peer, id)
	if err != nil || env.JobID != id || len(env.Sealed) != 0 || len(env.SealedFingerprintKey) == 0 || f.issuer.calls.Load() != 1 {
		t.Fatal("a verify job must be issued the fingerprint key envelope and no value")
	}
	if _, err := f.service.Material(ctx, f.peer, id); !errors.Is(err, ErrNotFound) || f.issuer.calls.Load() != 1 {
		t.Fatal("the key of a verify job was issued twice")
	}
	res := runnerproto.Result{OK: true, Fingerprint: job.ExpectedFingerprint, Version: job.ExpectedVersion}
	if err := f.service.Result(ctx, f.peer, id, res); err != nil {
		t.Fatal("verify result after the key was rejected")
	}
	if err := f.service.Result(ctx, f.peer, id, res); err != nil {
		t.Fatal("exact retry was rejected")
	}
	var state string
	var verified bool
	if err := f.pool.QueryRow(ctx, `SELECT state,last_verified_at IS NOT NULL FROM carriers WHERE org_id=$1`, f.peer.OrgID).Scan(&state, &verified); err != nil || state != "registered" || !verified {
		t.Fatal("result did not reach the carrier")
	}
	var verifyRecords, deployRecords int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='carrier.verify' AND result_status='ok'), count(*) FILTER (WHERE action='deploy.result') FROM audit_records WHERE org_id=$1`, f.peer.OrgID.String()).Scan(&verifyRecords, &deployRecords); err != nil || verifyRecords != 1 || deployRecords != 0 {
		t.Fatal("a verify result must write exactly one carrier.verify record and no deploy.result")
	}
}

func TestVerifyMatchWithoutTheKeyIsRefusedButARefusalIsNot(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, job := f.verifyJob(t)
	match := runnerproto.Result{OK: true, Fingerprint: job.ExpectedFingerprint, Version: job.ExpectedVersion}
	if err := f.service.Result(ctx, f.peer, id, match); err == nil {
		t.Fatal("a match was accepted from a runner that never fetched the key")
	}
	denied := runnerproto.Result{ErrorClass: runnerproto.ErrClassPolicyDenied}
	if err := f.service.Result(ctx, f.peer, id, denied); err != nil {
		t.Fatal("a refusal before the key was fetched was rejected")
	}
}

func TestVerifyKeyIsRefusedAfterExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, _ := f.verifyJob(t)
	if _, err := f.pool.Exec(ctx, `WITH expired AS (DELETE FROM deployment_jobs WHERE id=$1 RETURNING *)
INSERT INTO deployment_jobs SELECT (jsonb_populate_record(NULL::deployment_jobs,
  to_jsonb(expired) || jsonb_build_object('created_at', clock_timestamp()-interval '2 minutes',
  'expires_at', clock_timestamp()-interval '1 minute'))).* FROM expired`, id); err != nil {
		t.Fatal("expire job")
	}
	if _, err := f.service.Material(ctx, f.peer, id); !errors.Is(err, ErrNotFound) || f.issuer.calls.Load() != 0 {
		t.Fatal("the key of an expired verify job was issued")
	}
}

func TestVerifyMismatchMayNameObservedFingerprintOnlyForVerify(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, job := f.verifyJob(t)
	const observed = "kfp1:key:zzzzzzzzzzzzzzzz"
	if err := f.service.Result(ctx, f.peer, id, runnerproto.Result{OK: true, Fingerprint: observed, Version: job.ExpectedVersion}); err == nil {
		t.Fatal("a success naming another fingerprint was accepted")
	}
	if err := f.service.Result(ctx, f.peer, id, runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: observed, Version: "other"}); err == nil {
		t.Fatal("a mismatch naming another version was accepted")
	}
	if err := f.service.Result(ctx, f.peer, id, runnerproto.Result{ErrorClass: runnerproto.ErrClassInvalidJob, Fingerprint: observed}); err == nil {
		t.Fatal("a failure other than a mismatch named another fingerprint and was accepted")
	}
	if err := f.service.Result(ctx, f.peer, id, runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: job.ExpectedFingerprint}); err == nil {
		t.Fatal("a mismatch naming the expected fingerprint was accepted")
	}
	if err := f.service.Result(ctx, f.peer, id, runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: observed}); err != nil {
		t.Fatal("verify mismatch with the observed fingerprint was rejected")
	}
	var state, fp string
	if err := f.pool.QueryRow(ctx, `SELECT state,last_fp FROM carriers WHERE org_id=$1`, f.peer.OrgID).Scan(&state, &fp); err != nil || state != "stale" || fp != observed {
		t.Fatal("mismatch did not mark the carrier stale")
	}
	var journaled string
	if err := f.pool.QueryRow(ctx, `SELECT coalesce(result_fingerprint,'') FROM audit_records WHERE org_id=$1 AND action='carrier.verify' AND result_status<>'pending'`, f.peer.OrgID.String()).Scan(&journaled); err != nil || journaled != "" {
		t.Fatal("the journal kept the fingerprint observed in a mismatching file")
	}
	// The exception is for verify jobs only: a deploy job still rejects it.
	g := newFixture(t)
	if _, ok, err := g.service.Poll(ctx, g.peer); err != nil || !ok {
		t.Fatal("claim deploy job")
	}
	if _, err := g.service.Material(ctx, g.peer, g.jobID); err != nil {
		t.Fatal("issue material")
	}
	if err := g.service.Result(ctx, g.peer, g.jobID, runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: observed}); err == nil {
		t.Fatal("a deploy job accepted a result naming another fingerprint")
	}
}
