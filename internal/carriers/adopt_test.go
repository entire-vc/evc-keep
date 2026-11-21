package carriers

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type adoptionReceiptFixture struct {
	pool                         *pgxpool.Pool
	org, runner, secret, version uuid.UUID
	job                          runnerproto.Job
	result                       runnerproto.Result
}

// This is a transaction-boundary test, not a simulated runner. Admission,
// enrollment, catalog locks and receipt persistence all use real PostgreSQL.
// Transport lifecycle columns place its authorized job at the result boundary.
func receiptFixture(t *testing.T) adoptionReceiptFixture {
	t.Helper()
	ctx := context.Background()
	dsn := pgscratch.New(t, nil)
	db, err := store.OpenMigrationDB(ctx, dsn)
	must(t, err)
	p, err := store.NewProvider(db)
	must(t, err)
	_, err = p.Up(ctx)
	must(t, err)
	must(t, db.Close())
	pool, err := pgxpool.New(ctx, dsn)
	must(t, err)
	t.Cleanup(pool.Close)
	f := adoptionReceiptFixture{pool: pool, org: uuid.New(), runner: uuid.New(), secret: uuid.New(), version: uuid.New()}
	st := uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name) VALUES($1,'adoption-receipt-test')`, []any{f.org}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','test','org',$2)`, []any{st, f.org}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'TEST','dev','generic',$3,'synthetic-reference')`, []any{f.secret, f.org, st}},
		{`INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'1','kfp1:key:abcdefghijklmnop',12)`, []any{f.version, f.org, f.secret}},
	} {
		_, err = pool.Exec(ctx, q.sql, q.args...)
		must(t, err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, err)
	shared := false
	must(t, registry.NewRepo(pool).CreateEnrolled(ctx, f.org, f.runner, "disposable-yaml-host", "1", time.Now().Add(time.Hour), registry.Enrollment{HPKEPublicKey: key.PublicKey().Bytes(), HostAttrs: &enrolltoken.HostAttrs{UIDShared: &shared}}))
	r := deployment.NewRepo(pool, audit.NewJournal(pool))
	target := runnerproto.Target{Kind: runnerproto.TargetYAMLScalar, Path: "/srv/app/config.yaml", Field: "service.token", Mode: 0o600}
	actor := audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}
	_, err = r.SetPolicy(ctx, deployment.PolicyChange{OrgID: f.org, ExpectRevision: -1, Actor: actor, Policy: deployment.Policy{AdoptionRules: []deployment.AdoptionRule{{SecretID: f.secret, RunnerID: f.runner, Kind: target.Kind, Path: target.Path, Field: target.Field}}}})
	must(t, err)
	out, err := r.SubmitAdopt(ctx, deployment.AdoptRequest{OrgID: f.org, Scope: tenancy.Org(f.org), SecretID: f.secret, RunnerID: f.runner, RequestID: uuid.NewString(), Actor: actor, Target: target})
	if err != nil || out.Status != deployment.Queued {
		t.Fatal("real admission did not queue read-only adoption")
	}
	var payload []byte
	must(t, pool.QueryRow(ctx, `UPDATE deployment_jobs SET status='issued',issued_at=clock_timestamp(),material_issued_at=clock_timestamp() WHERE org_id=$1 AND id=$2 RETURNING job_payload`, f.org, out.JobID).Scan(&payload))
	f.job, err = runnerproto.DecodeJob(payload)
	must(t, err)
	f.result = runnerproto.Result{OK: true, Version: f.job.ExpectedVersion, Fingerprint: f.job.ExpectedFingerprint}
	return f
}

func (f adoptionReceiptFixture) apply(t *testing.T, commit bool) error {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	err = ApplyAdoptionResultTx(ctx, tx, f.org, f.runner, f.job, f.result)
	if err == nil && commit {
		err = tx.Commit(ctx)
	}
	return err
}

func (f adoptionReceiptFixture) count(t *testing.T, sql string) int {
	t.Helper()
	var n int
	must(t, f.pool.QueryRow(context.Background(), sql).Scan(&n))
	return n
}

func TestAdoptReceiptCommitsExactCurrentCarrierAndRemainsImmutable(t *testing.T) {
	f := receiptFixture(t)
	must(t, f.apply(t, true))
	got, err := NewService(f.pool).List(context.Background(), f.org, f.secret)
	if err != nil || len(got) != 1 {
		t.Fatal("ordinary carrier list lost adoption")
	}
	c := got[0]
	if c.OrgID != f.org || c.SecretID != f.secret || c.Version != f.job.ExpectedVersion || c.Host != "disposable-yaml-host" || c.TargetKind != f.job.Target.Kind || c.TargetPath != f.job.Target.Path || c.TargetField != f.job.Target.Field || c.Provenance != "adoption" || c.RunnerID != f.runner || c.AttestationJobID.String() != f.job.JobID || c.Consumer != "" || c.HealthcheckRef != "" || c.LastVerifiedAt == nil {
		t.Fatal("carrier is not the exact attested catalog destination")
	}
	if f.count(t, `SELECT count(*) FROM carrier_adoption_receipts`) != 1 || f.count(t, `SELECT count(*) FROM deployment_jobs WHERE action='deploy' AND status='completed'`) != 0 {
		t.Fatal("adoption did not retain its independent one-use receipt")
	}
	if f.apply(t, true) == nil || f.count(t, `SELECT count(*) FROM carrier_adoption_receipts`) != 1 || f.count(t, `SELECT count(*) FROM carriers`) != 1 {
		t.Fatal("a receipt was consumed twice")
	}
	for _, sql := range []string{`UPDATE carrier_adoption_receipts SET host='changed'`, `DELETE FROM carrier_adoption_receipts`} {
		if _, err := f.pool.Exec(context.Background(), sql); err == nil {
			t.Fatal("an accepted receipt was mutable")
		}
	}
}

func TestAdoptReceiptAndCarrierRollBackTogether(t *testing.T) {
	f := receiptFixture(t)
	must(t, f.apply(t, false))
	if f.count(t, `SELECT count(*) FROM carrier_adoption_receipts`) != 0 || f.count(t, `SELECT count(*) FROM carriers`) != 0 {
		t.Fatal("an uncommitted result left adoption metadata")
	}
	must(t, f.apply(t, true)) // Positive control: rollback did not consume it.
}

func TestAdoptReceiptRejectsChangedBindingTrustCurrentAndHealth(t *testing.T) {
	for _, name := range []string{"org", "runner", "field", "path", "nonce", "action", "version", "fingerprint", "health", "failed", "unissued_key", "expired", "revoked", "keyless", "current", "disabled", "production_without_approval"} {
		t.Run(name, func(t *testing.T) {
			f := receiptFixture(t)
			ctx := context.Background()
			var sql string
			var args []any
			switch name {
			case "org":
				f.org = uuid.New()
			case "runner":
				f.runner = uuid.New()
			case "field":
				f.job.Target.Field = "other.token"
			case "path":
				f.job.Target.Path += ".other"
			case "nonce":
				f.job.Nonce[0] ^= 1
			case "action":
				f.job.Action = runnerproto.ActionVerify
			case "version":
				f.result.Version = "other"
			case "fingerprint":
				f.result.Fingerprint = "kfp1:key:zzzzzzzzzzzzzzzz"
			case "health":
				f.result.Healthcheck = &runnerproto.Healthcheck{Status: runnerproto.HealthOK}
			case "failed":
				f.result = runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: "kfp1:key:zzzzzzzzzzzzzzzz"}
			case "unissued_key":
				sql = `UPDATE deployment_jobs SET material_issued_at=NULL`
			case "expired":
				// Lifecycle fixtures may replace frozen rows; production may not.
				sql = `WITH expired AS (DELETE FROM deployment_jobs RETURNING *) INSERT INTO deployment_jobs SELECT (jsonb_populate_record(NULL::deployment_jobs,to_jsonb(expired)||jsonb_build_object('created_at',clock_timestamp()-interval '2 minutes','expires_at',clock_timestamp()-interval '1 minute'))).* FROM expired`
			case "revoked":
				sql = `UPDATE runners SET revoked_at=clock_timestamp()`
			case "keyless":
				sql = `UPDATE runners SET hpke_public_key=NULL`
			case "current":
				sql = `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'2','kfp1:key:abcdefghijklmnop',12)`
				args = []any{uuid.New(), f.org, f.secret} // Same FP, distinct catalog version.
			case "disabled":
				sql = `UPDATE secret_versions SET disabled=true`
			case "production_without_approval":
				sql = `UPDATE secrets SET class='prod'`
			}
			if sql != "" {
				_, err := f.pool.Exec(ctx, sql, args...)
				must(t, err)
			}
			if f.apply(t, true) == nil || f.count(t, `SELECT count(*) FROM carrier_adoption_receipts`) != 0 || f.count(t, `SELECT count(*) FROM carriers`) != 0 {
				t.Fatal("an invalid attestation produced adoption metadata")
			}
		})
	}
}
