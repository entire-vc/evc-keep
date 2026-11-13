package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

const otherFingerprint = "kfp1:k1:zzzzzzzzzzzzzzzz"

func (f fixture) carrier(t *testing.T, host, path string) uuid.UUID {
	t.Helper()
	id := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO carriers(id,org_id,secret_id,version,host,target_kind,target_path,last_fp,state)
	 VALUES($1,$2,$3,'v1',$4,'file',$5,'kfp1:k1:abcdefghijklmnop','registered')`, id, f.org, f.secret, host, path); err != nil {
		t.Fatal("insert carrier")
	}
	return id
}

func (f fixture) verifyRequest(t *testing.T) VerifyRequest {
	t.Helper()
	return VerifyRequest{OrgID: f.org, Scope: tenancy.Org(f.org), SecretID: f.secret, RequestID: mustID(t).String(),
		Actor: audit.Actor{Type: audit.ActorUser, ID: f.user.String(), Via: audit.ViaAPI}}
}

func states(rep VerifyReport) map[uuid.UUID]VerifyState {
	out := map[uuid.UUID]VerifyState{}
	for _, it := range rep.Items {
		out[it.CarrierID] = it.State
	}
	return out
}

func (f fixture) verifyJob(t *testing.T, carrier uuid.UUID) runnerproto.Job {
	t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT job_id FROM carrier_verification_items WHERE org_id=$1 AND carrier_id=$2 AND job_id IS NOT NULL`, f.org, carrier).Scan(&id); err != nil {
		t.Fatal("carrier has no verify job")
	}
	return runnerproto.Job{JobID: id.String(), ExpectedVersion: "v1", ExpectedFingerprint: "kfp1:k1:abcdefghijklmnop"}
}

func (f fixture) apply(t *testing.T, job runnerproto.Job, res runnerproto.Result) VerifyState {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal("begin")
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	state, known, err := ApplyVerifyResultTx(f.ctx, tx, f.org, job, res)
	if err != nil || !known {
		t.Fatal("apply verify result failed")
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal("commit")
	}
	return state
}

func (f fixture) carrierRow(t *testing.T, id uuid.UUID) (state, fp string, verified bool) {
	t.Helper()
	if err := f.pool.QueryRow(f.ctx, `SELECT state,last_fp,last_verified_at IS NOT NULL FROM carriers WHERE id=$1`, id).Scan(&state, &fp, &verified); err != nil {
		t.Fatal("read carrier")
	}
	return
}

func TestVerifySubmitFansOutPerReachableCarrier(t *testing.T) {
	f := newFixture(t)
	reachable := f.carrier(t, "test-host", "/srv/a")
	orphan := f.carrier(t, "no-runner-host", "/srv/b")
	in := f.verifyRequest(t)
	rep, err := f.repo.SubmitVerify(f.ctx, in)
	if err != nil || !rep.Created {
		t.Fatal("submit verify failed")
	}
	got := states(rep)
	if got[reachable] != VerifyPending || got[orphan] != VerifyUnreachable || rep.Done() {
		t.Fatal("carrier without a runner must be unreachable at once, the other pending")
	}
	var jobs, deployJobs int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FILTER (WHERE action='verify'), count(*) FILTER (WHERE action='deploy') FROM deployment_jobs WHERE org_id=$1`, f.org).Scan(&jobs, &deployJobs); err != nil || jobs != 1 || deployJobs != 0 {
		t.Fatal("expected exactly one verify job")
	}
	var audits int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='carrier.verify' AND request_id=$2`, f.org.String(), in.RequestID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("verify request must write one carrier.verify audit record")
	}
	if rep.Fingerprint != "kfp1:k1:abcdefghijklmnop" || rep.Version != "v1" {
		t.Fatal("expected state must come from the catalog")
	}
}

func TestVerifySubmitIsIdempotentAndBound(t *testing.T) {
	f := newFixture(t)
	f.carrier(t, "test-host", "/srv/a")
	in := f.verifyRequest(t)
	if _, err := f.repo.SubmitVerify(f.ctx, in); err != nil {
		t.Fatal("first submit failed")
	}
	again, err := f.repo.SubmitVerify(f.ctx, in)
	if err != nil || again.Created || len(again.Items) != 1 {
		t.Fatal("replay must return the first verification")
	}
	var jobs, audits int
	_ = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM deployment_jobs WHERE org_id=$1`, f.org).Scan(&jobs)
	_ = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='carrier.verify'`, f.org.String()).Scan(&audits)
	if jobs != 1 || audits != 1 {
		t.Fatal("replay created a second job or audit record")
	}
	other := mustID(t)
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'OTHER','dev','generic',$3,'builtin://other')`, other, f.org, f.store); err != nil {
		t.Fatal("insert second secret")
	}
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'v1','kfp1:k1:bbbbbbbbbbbbbbbb',4)`, mustID(t), f.org, other); err != nil {
		t.Fatal("insert second version")
	}
	in.SecretID = other
	if _, err = f.repo.SubmitVerify(f.ctx, in); !errors.Is(err, ErrConflict) {
		t.Fatal("same request id for another secret must conflict")
	}
}

func TestVerifyRunnerMustBeLiveAndOnTheCarrierHost(t *testing.T) {
	f := newFixture(t)
	c := f.carrier(t, "test-host", "/srv/a")
	for name, stmt := range map[string]string{
		"revoked": `UPDATE runners SET revoked_at=now() WHERE id=$1`,
		"expired": `UPDATE runners SET cert_not_after=now()-interval '1 minute' WHERE id=$1`,
		"moved":   `UPDATE runners SET host='elsewhere' WHERE id=$1`,
	} {
		if _, err := f.pool.Exec(f.ctx, stmt, f.runner); err != nil {
			t.Fatal("break runner " + name)
		}
		rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
		if err != nil || states(rep)[c] != VerifyUnreachable {
			t.Fatal("runner " + name + " must not receive a verify job")
		}
		if _, err = f.pool.Exec(f.ctx, `UPDATE runners SET revoked_at=NULL,cert_not_after=now()+interval '1 hour',host='test-host' WHERE id=$1`, f.runner); err != nil {
			t.Fatal("restore runner")
		}
	}
	var jobs int
	_ = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM deployment_jobs`).Scan(&jobs)
	if jobs != 0 {
		t.Fatal("a job was created for an unusable runner")
	}
}

func TestVerifyIsolatedByOrganization(t *testing.T) {
	f := newFixture(t)
	f.carrier(t, "test-host", "/srv/a")
	in := f.verifyRequest(t)
	if _, err := f.repo.SubmitVerify(f.ctx, in); err != nil {
		t.Fatal("submit failed")
	}
	if _, err := f.repo.VerifyReport(f.ctx, mustID(t), in.RequestID); !errors.Is(err, ErrNotFound) {
		t.Fatal("another organization read this verification")
	}
	foreign := in
	foreign.OrgID, foreign.RequestID = mustID(t), mustID(t).String()
	if _, err := f.repo.SubmitVerify(f.ctx, foreign); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown organization must not verify")
	}
}

func TestVerifyLimits(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < MaxVerifyCarriers+1; i++ {
		f.carrier(t, "test-host", "/srv/"+uuid.NewString())
	}
	if _, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t)); !errors.Is(err, ErrTooManyCarriers) {
		t.Fatal("more than the carrier cap must be refused")
	}
	g := newFixture(t)
	g.carrier(t, "test-host", "/srv/a")
	for i := 0; i < MaxVerifiesPerHour; i++ {
		if _, err := g.repo.SubmitVerify(g.ctx, g.verifyRequest(t)); err != nil {
			t.Fatal("verify under the hourly cap failed")
		}
	}
	if _, err := g.repo.SubmitVerify(g.ctx, g.verifyRequest(t)); !errors.Is(err, ErrVerifyRateLimited) {
		t.Fatal("hourly verify cap not enforced")
	}
	// Verify jobs do not spend the deploy allowance of the same pair.
	g.policy(t, 1)
	if out, err := g.repo.Submit(g.ctx, g.request(t)); err != nil || out.Status != Queued {
		t.Fatal("verify jobs consumed the deploy allowance")
	}
}

func TestVerifyResultUpdatesCarrierState(t *testing.T) {
	f := newFixture(t)
	match := f.carrier(t, "test-host", "/srv/match")
	mismatch := f.carrier(t, "test-host", "/srv/mismatch")
	gone := f.carrier(t, "test-host", "/srv/gone")
	refused := f.carrier(t, "test-host", "/srv/refused")
	if _, err := f.pool.Exec(f.ctx, `UPDATE carriers SET state='stale' WHERE id=$1`, match); err != nil {
		t.Fatal("stage carrier")
	}
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil {
		t.Fatal("submit failed")
	}
	expected := rep.Fingerprint
	if f.apply(t, f.verifyJob(t, match), runnerproto.Result{OK: true}) != VerifyMatch {
		t.Fatal("ok result must be a match")
	}
	if s, fp, ok := f.carrierRow(t, match); s != "registered" || fp != expected || !ok {
		t.Fatal("match must register the carrier and stamp the verification time")
	}
	if f.apply(t, f.verifyJob(t, mismatch), runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: otherFingerprint}) != VerifyMismatch {
		t.Fatal("fingerprint mismatch must be a mismatch")
	}
	if s, fp, _ := f.carrierRow(t, mismatch); s != "stale" || fp != otherFingerprint {
		t.Fatal("mismatch must mark the carrier stale with the observed fingerprint")
	}
	if f.apply(t, f.verifyJob(t, gone), runnerproto.Result{ErrorClass: runnerproto.ErrClassTargetWrite}) != VerifyUnreachable {
		t.Fatal("target error must be unreachable")
	}
	if s, _, ok := f.carrierRow(t, gone); s != "unknown" || ok {
		t.Fatal("unreachable must mark the carrier unknown and clear the verification time")
	}
	if f.apply(t, f.verifyJob(t, refused), runnerproto.Result{ErrorClass: runnerproto.ErrClassPolicyDenied}) != VerifyFailed {
		t.Fatal("refused job must be failed")
	}
	if s, _, ok := f.carrierRow(t, refused); s != "registered" || ok {
		t.Fatal("a refused job must not change the carrier")
	}
}

func TestVerifyResultIgnoredForSupersededCatalogVersion(t *testing.T) {
	f := newFixture(t)
	c := f.carrier(t, "test-host", "/srv/a")
	if _, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t)); err != nil {
		t.Fatal("submit failed")
	}
	job := f.verifyJob(t, c)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length,created_at) VALUES($1,$2,$3,'v2','kfp1:k1:cccccccccccccccc',12,now()+interval '1 second')`, mustID(t), f.org, f.secret); err != nil {
		t.Fatal("rotate catalog")
	}
	if f.apply(t, job, runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: otherFingerprint}) != VerifyMismatch {
		t.Fatal("the verification line must still record the answer")
	}
	if s, fp, _ := f.carrierRow(t, c); s != "registered" || fp != "kfp1:k1:abcdefghijklmnop" {
		t.Fatal("an answer about a superseded version changed the carrier")
	}
}

func TestVerifyAnswerOfAnotherKeyIsNotStored(t *testing.T) {
	f := newFixture(t)
	c := f.carrier(t, "test-host", "/srv/a")
	if _, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t)); err != nil {
		t.Fatal("submit failed")
	}
	f.apply(t, f.verifyJob(t, c), runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: "kfp1:k2:zzzzzzzzzzzzzzzz"})
	if s, fp, _ := f.carrierRow(t, c); s != "registered" || fp != "kfp1:k1:abcdefghijklmnop" {
		t.Fatal("a fingerprint under another key must not overwrite the carrier")
	}
}

func TestVerifyPendingPastDeadlineReadsAsUnreachable(t *testing.T) {
	f := newFixture(t)
	c := f.carrier(t, "test-host", "/srv/a")
	in := f.verifyRequest(t)
	if _, err := f.repo.SubmitVerify(f.ctx, in); err != nil {
		t.Fatal("submit failed")
	}
	if _, err := f.pool.Exec(f.ctx, `ALTER TABLE deployment_jobs DISABLE TRIGGER USER`); err != nil {
		t.Fatal("disable trigger")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET created_at=now()-interval '1 hour',expires_at=now()-interval '1 second' WHERE org_id=$1`, f.org); err != nil {
		t.Fatal("expire job")
	}
	rep, err := f.repo.VerifyReport(f.ctx, f.org, in.RequestID)
	if err != nil || states(rep)[c] != VerifyUnreachable || rep.Items[0].ErrorClass != runnerproto.ErrClassExpired || !rep.Done() {
		t.Fatal("a pending item past its job deadline must read as unreachable/job_expired")
	}
}

func TestVerifyMigrationDownKeepsDeploymentsAndAuditHistory(t *testing.T) {
	f := newFixture(t)
	f.carrier(t, "test-host", "/srv/a")
	f.policy(t, 5)
	deployed, err := f.repo.Submit(f.ctx, f.request(t))
	if err != nil || deployed.JobID == uuid.Nil {
		t.Fatal("seed deploy job")
	}
	if _, err = f.repo.SubmitVerify(f.ctx, f.verifyRequest(t)); err != nil {
		t.Fatal("seed verification")
	}
	count := func(q string) (n int) {
		t.Helper()
		if err := f.pool.QueryRow(f.ctx, q).Scan(&n); err != nil {
			t.Fatal("count failed")
		}
		return n
	}
	if count(`SELECT count(*) FROM deployment_jobs`) != 2 || count(`SELECT count(*) FROM deployment_requests`) != 2 {
		t.Fatal("seed did not create one deploy and one verify job")
	}
	mdb, err := store.OpenMigrationDB(f.ctx, f.pool.Config().ConnString())
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = mdb.Close() }()
	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err = provider.DownTo(f.ctx, 18); err != nil {
		t.Fatal("downgrade failed with verification data present")
	}
	if count(`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('carrier_verifications','carrier_verification_items')`) != 0 {
		t.Fatal("downgrade left the verification tables")
	}
	if count(`SELECT count(*) FROM information_schema.columns WHERE table_name='deployment_jobs' AND column_name='action'`) != 0 {
		t.Fatal("downgrade left the action column")
	}
	if count(`SELECT count(*) FROM deployment_jobs`) != 1 || count(`SELECT count(*) FROM deployment_requests`) != 1 || count(`SELECT count(*) FROM carriers`) != 1 {
		t.Fatal("downgrade must drop only the verify job and keep deployments and carriers")
	}
	if count(`SELECT count(*) FROM audit_records WHERE action='carrier.verify'`) != 1 {
		t.Fatal("downgrade lost audit history")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET status=status`); err != nil {
		t.Fatal("restored trigger rejects a harmless update")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET nonce='\x00'::bytea`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatal("restored trigger no longer freezes job metadata")
	}
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO audit_records(id,org_id,org_seq,ts,request_id,scope,actor_type,actor_id,actor_via,action,result_status,prev_hash,hash)
	 VALUES('01J8ZZZZZZZZZZZZZZZZZZZZZZ','x',1,now(),'r','org:x','user','u','api','carrier.verify','ok',repeat('0',64),repeat('0',64))`); err == nil {
		t.Fatal("downgraded registry accepted a new carrier.verify record")
	}
	if _, err = provider.Up(f.ctx); err != nil {
		t.Fatal("upgrade after downgrade failed")
	}
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil || len(rep.Items) != 1 {
		t.Fatal("verify does not work after down and up again")
	}
}

func TestVerifyCarrierWithBrokenTargetIsFailedNotDispatched(t *testing.T) {
	f := newFixture(t)
	ok := f.carrier(t, "test-host", "/srv/ok")
	relative := f.carrier(t, "test-host", "relative/path")
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil {
		t.Fatal("submit failed")
	}
	got := states(rep)
	if got[ok] != VerifyPending || got[relative] != VerifyFailed {
		t.Fatal("a carrier whose target is not a valid job target must be reported failed, not dispatched")
	}
	var jobs int
	_ = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM deployment_jobs WHERE action='verify'`).Scan(&jobs)
	if jobs != 1 {
		t.Fatal("a job was dispatched for the broken target")
	}
}

func TestVerifyJobActionIsFrozen(t *testing.T) {
	f := newFixture(t)
	f.carrier(t, "test-host", "/srv/a")
	if _, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t)); err != nil {
		t.Fatal("submit failed")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET action='deploy'`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatal("a queued verify job could be turned into a deploy job")
	}
}

func TestVerifyRunnerWithoutDeliveryTrustIsUnreachableAtOnce(t *testing.T) {
	f := newFixture(t)
	c := f.carrier(t, "test-host", "/srv/a")
	f.repo.trust = func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (Host, error) { return Host{}, ErrNotFound }
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil || states(rep)[c] != VerifyUnreachable || !rep.Done() {
		t.Fatal("a runner the registry does not trust must make the carrier unreachable at once")
	}
}

func TestVerifyRequestRowIsNotADeploymentReport(t *testing.T) {
	f := newFixture(t)
	f.carrier(t, "test-host", "/srv/a")
	if _, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t)); err != nil {
		t.Fatal("submit failed")
	}
	var internal string
	if err := f.pool.QueryRow(f.ctx, `SELECT r.request_id FROM deployment_requests r JOIN deployment_jobs j ON j.deployment_request_id=r.id WHERE j.action='verify'`).Scan(&internal); err != nil {
		t.Fatal("verify request row missing")
	}
	if _, err := f.repo.Report(f.ctx, f.org, internal); !errors.Is(err, ErrNotFound) {
		t.Fatal("a verification's internal request row was readable as a deployment")
	}
}

func TestVerifyMatchOnSupersededVersionDoesNotRegister(t *testing.T) {
	f := newFixture(t)
	c := f.carrier(t, "test-host", "/srv/a")
	if _, err := f.pool.Exec(f.ctx, `UPDATE carriers SET state='stale' WHERE id=$1`, c); err != nil {
		t.Fatal("stage carrier")
	}
	if _, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t)); err != nil {
		t.Fatal("submit failed")
	}
	job := f.verifyJob(t, c)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length,created_at) VALUES($1,$2,$3,'v2','kfp1:k1:cccccccccccccccc',12,now()+interval '1 second')`, mustID(t), f.org, f.secret); err != nil {
		t.Fatal("rotate catalog")
	}
	if f.apply(t, job, runnerproto.Result{OK: true}) != VerifyMatch {
		t.Fatal("the line must record the answer")
	}
	if s, _, _ := f.carrierRow(t, c); s != "stale" {
		t.Fatal("a match for a superseded version registered the carrier")
	}
}

func TestVerifyExpectsLatestEnabledVersion(t *testing.T) {
	f := newFixture(t)
	f.carrier(t, "test-host", "/srv/a")
	for _, v := range []struct {
		name, fp string
		disabled bool
		offset   int
	}{{"v2", "kfp1:k1:cccccccccccccccc", false, 1}, {"v3", "kfp1:k1:dddddddddddddddd", true, 2}} {
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length,disabled,created_at) VALUES($1,$2,$3,$4,$5,12,$6,now()+$7::int*interval '1 second')`,
			mustID(t), f.org, f.secret, v.name, v.fp, v.disabled, v.offset); err != nil {
			t.Fatal("insert version")
		}
	}
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil || rep.Version != "v2" || rep.Fingerprint != "kfp1:k1:cccccccccccccccc" {
		t.Fatal("verify must expect the newest version that is not disabled")
	}
}

func TestVerifyNetworkLookingTargetIsFailed(t *testing.T) {
	f := newFixture(t)
	c := f.carrier(t, "test-host", "/srv/host:8080/key")
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil || states(rep)[c] != VerifyFailed {
		t.Fatal("a carrier whose path looks like a network destination must not be dispatched")
	}
}

func TestVerifyTablesRejectInvalidRows(t *testing.T) {
	f := newFixture(t)
	f.carrier(t, "test-host", "/srv/a")
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil {
		t.Fatal("submit failed")
	}
	var vid uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT id FROM carrier_verifications LIMIT 1`).Scan(&vid); err != nil {
		t.Fatal("read verification")
	}
	_ = rep
	for name, stmt := range map[string]string{
		"unknown state":      `UPDATE carrier_verification_items SET state='weird',completed_at=now()`,
		"pending completed":  `UPDATE carrier_verification_items SET completed_at=now()`,
		"done not completed": `UPDATE carrier_verification_items SET state='match'`,
		"free-text class":    `UPDATE carrier_verification_items SET error_class='Bad Text!'`,
		"bad observed fp":    `UPDATE carrier_verification_items SET observed_fingerprint='not-a-fingerprint'`,
		"job without runner": `UPDATE carrier_verification_items SET runner_id=NULL`,
		"bad expected fp":    `UPDATE carrier_verifications SET expected_fingerprint='not-a-fingerprint'`,
		"bad request id":     `UPDATE carrier_verifications SET request_id='bad id'`,
		"unknown action":     `ALTER TABLE deployment_jobs DISABLE TRIGGER USER; UPDATE deployment_jobs SET action='write'`,
	} {
		if _, err := f.pool.Exec(f.ctx, stmt); err == nil {
			t.Fatal("constraint missing: " + name)
		}
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO carrier_verifications(id,org_id,request_id,request_hash,secret_id,secret_scope_level,secret_scope_id,expected_version,expected_fingerprint)
	 SELECT $1,org_id,request_id,request_hash,secret_id,secret_scope_level,secret_scope_id,expected_version,expected_fingerprint FROM carrier_verifications`, mustID(t)); err == nil {
		t.Fatal("a request id was accepted twice in one organization")
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO carrier_verification_items(verification_id,org_id,carrier_id,runner_id,job_id)
	 SELECT verification_id,org_id,$1,runner_id,job_id FROM carrier_verification_items`, mustID(t)); err == nil {
		t.Fatal("one job was attached to two verification lines")
	}
}

func (f fixture) credCarrier(t *testing.T, path string) uuid.UUID {
	t.Helper()
	id := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO carriers(id,org_id,secret_id,version,host,target_kind,target_path,last_fp,state)
	 VALUES($1,$2,$3,'v1','test-host','systemd-credential',$4,'kfp1:k1:abcdefghijklmnop','registered')`, id, f.org, f.secret, path); err != nil {
		t.Fatal("insert credential carrier")
	}
	return id
}

// deployCredential records a completed deploy of the secret to a credential
// file under the unit name.
func (f fixture) deployCredential(t *testing.T, path, unit string) {
	f.deployCredentialAs(t, path, unit, "completed")
}

func (f fixture) deployCredentialAs(t *testing.T, path, unit, final string) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO deployment_policies(org_id,rules,max_deploys_per_hour) VALUES($1,$2,10) ON CONFLICT (org_id) DO UPDATE SET rules=EXCLUDED.rules`, f.org,
		`{"rules":[{"secret_id":"`+f.secret.String()+`","runner_id":"`+f.runner.String()+`","kind":"systemd-credential","path_prefix":"/etc/creds"}]}`); err != nil {
		t.Fatal("insert policy")
	}
	in := f.request(t)
	in.Target = runnerproto.Target{Kind: runnerproto.TargetSystemdCredential, Path: path, Unit: unit, Mode: 0o600}
	out, err := f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != Queued {
		t.Fatal("credential deploy was not queued")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET status='issued',issued_at=now() WHERE id=$1`, out.JobID); err != nil {
		t.Fatal("issue")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET status=$2,result='{}' WHERE id=$1`, out.JobID, final); err != nil {
		t.Fatal("finish")
	}
}

func (f fixture) verifyTargetOf(t *testing.T, carrier uuid.UUID) runnerproto.Target {
	t.Helper()
	var raw []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT dr.target FROM carrier_verification_items i
	 JOIN deployment_jobs j ON j.org_id=i.org_id AND j.id=i.job_id
	 JOIN deployment_requests dr ON dr.org_id=j.org_id AND dr.id=j.deployment_request_id
	 WHERE i.org_id=$1 AND i.carrier_id=$2 AND j.action='verify' ORDER BY j.created_at DESC LIMIT 1`, f.org, carrier).Scan(&raw); err != nil {
		t.Fatal("carrier has no verify job target")
	}
	var tg runnerproto.Target
	if err := json.Unmarshal(raw, &tg); err != nil {
		t.Fatal("decode target")
	}
	return tg
}

func TestVerifyCredentialCarrierNamesTheUnitOfItsLastDeploy(t *testing.T) {
	f := newFixture(t)
	c := f.credCarrier(t, "/etc/creds/app")
	f.deployCredential(t, "/etc/creds/app", "keep-app.service")
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil || states(rep)[c] != VerifyPending {
		t.Fatal("a credential carrier with a deploy must be dispatched")
	}
	if got := f.verifyTargetOf(t, c); got.Unit != "keep-app.service" || got.Kind != runnerproto.TargetSystemdCredential || got.Field != "" {
		t.Fatal("the verify job must carry the unit of the last deploy and no field")
	}
}

func TestVerifyCredentialCarrierWithoutDeployFailsBeforeAnyJob(t *testing.T) {
	f := newFixture(t)
	c := f.credCarrier(t, "/etc/creds/app")
	f.deployCredential(t, "/etc/creds/other", "keep-other.service")
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil || states(rep)[c] != VerifyFailed {
		t.Fatal("a credential carrier with no deploy to its path must fail, not dispatch")
	}
	if got := rep.Items[0].ErrorClass; got != runnerproto.ErrClassInvalidJob {
		t.Fatal("the failed item must carry the closed class job_invalid")
	}
	if n := f.count(t, `SELECT count(*) FROM deployment_jobs WHERE action='verify'`); n != 0 {
		t.Fatal("a verify job was dispatched without a credential name")
	}
}

// The name is the Unit of the newest COMPLETED deploy: a newer deploy that did
// not complete, and a completed verify job on the same destination, name
// nothing.
func TestVerifyCredentialCarrierTakesTheNewestCompletedDeployOnly(t *testing.T) {
	f := newFixture(t)
	c := f.credCarrier(t, "/etc/creds/app")
	f.deployCredential(t, "/etc/creds/app", "keep-old.service")
	f.deployCredential(t, "/etc/creds/app", "keep-new.service")
	f.deployCredentialAs(t, "/etc/creds/app", "keep-failed.service", "failed")
	if _, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t)); err != nil {
		t.Fatal("first submit failed")
	}
	if got := f.verifyTargetOf(t, c); got.Unit != "keep-new.service" {
		t.Fatal("the newest completed deploy must name the credential")
	}
	// Finish that verify job; a later verification must not read its target.
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET status='issued',issued_at=now() WHERE action='verify'`); err != nil {
		t.Fatal("issue verify job")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET status='completed',result='{}' WHERE action='verify'`); err != nil {
		t.Fatal("complete verify job")
	}
	rep, err := f.repo.SubmitVerify(f.ctx, f.verifyRequest(t))
	if err != nil || states(rep)[c] != VerifyPending {
		t.Fatal("second submit failed")
	}
	if got := f.verifyTargetOf(t, c); got.Unit != "keep-new.service" {
		t.Fatal("a completed verify job was taken for a deploy")
	}
}
