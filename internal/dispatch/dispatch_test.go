package dispatch

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testSigner struct{}

func (testSigner) SignJob(_ context.Context, _ pgx.Tx, _ uuid.UUID, j runnerproto.Job) (runnerproto.SignedJob, error) {
	b, err := runnerproto.EncodeJob(j)
	return runnerproto.SignedJob{Payload: b}, err
}

type testIssuer struct {
	calls     atomic.Int32
	fail      bool
	recipient []byte
}

func (i *testIssuer) SealMaterial(_ context.Context, s Snapshot, recipient []byte) (runnerproto.ValueEnvelope, error) {
	i.calls.Add(1)
	if !bytes.Equal(recipient, i.recipient) {
		return runnerproto.ValueEnvelope{}, errors.New("unexpected delivery recipient")
	}
	if i.fail {
		return runnerproto.ValueEnvelope{}, errors.New("synthetic backend failure")
	}
	if s.Job.NeedsFingerprintKey() {
		return runnerproto.ValueEnvelope{JobID: s.Job.JobID, SealedFingerprintKey: []byte("sealed-key")}, nil
	}
	return runnerproto.ValueEnvelope{JobID: s.Job.JobID, Sealed: []byte("sealed-value"), SealedFingerprintKey: []byte("sealed-key")}, nil
}

type fixture struct {
	service *Service
	pool    *pgxpool.Pool
	peer    mtls.Principal
	jobID   string
	issuer  *testIssuer
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	dsn := pgscratch.New(t, nil)
	mdb, err := store.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration DB")
	}
	defer func() { _ = mdb.Close() }()
	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatal("migration provider")
	}
	if _, err = provider.Up(ctx); err != nil {
		t.Fatal("migrate scratch DB")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open scratch pool")
	}
	t.Cleanup(pool.Close)
	id := func() uuid.UUID {
		x, err := uuid.NewV7()
		if err != nil {
			t.Fatal("generate id")
		}
		return x
	}
	org, runner, st, sec, ver := id(), id(), id(), id(), id()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name) VALUES($1,'dispatch-test')`, []any{org}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','test','org',$2)`, []any{st, org}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'DB_PASSWORD','dev','generic',$3,'synthetic-reference')`, []any{sec, org, st}},
		{`INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'1','kfp1:key:abcdefghijklmnop',12)`, []any{ver, org, sec}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("seed catalog")
		}
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate delivery recipient")
	}
	reg := registry.NewRepo(pool)
	f := false
	if err := reg.CreateEnrolled(ctx, org, runner, "synthetic-host", "1", time.Now().Add(time.Hour), registry.Enrollment{HPKEPublicKey: key.PublicKey().Bytes(), HostAttrs: &enrolltoken.HostAttrs{UIDShared: &f}}); err != nil {
		t.Fatal("seed enrolled runner")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployment_policies(org_id,rules) VALUES($1,$2)`, org, `{"rules":[{"secret_id":"`+sec.String()+`","runner_id":"`+runner.String()+`","kind":"file","path_prefix":"/srv/app"}]}`); err != nil {
		t.Fatal("seed policy")
	}
	journal := audit.NewJournal(pool)
	admit := deployment.NewRepo(pool, journal)
	out, err := admit.Submit(ctx, deployment.Request{OrgID: org, Scope: tenancy.Org(org), SecretID: sec, VersionID: ver, RunnerID: runner, RequestID: id().String(), Target: runnerproto.Target{Kind: runnerproto.TargetFile, Path: "/srv/app/key", Mode: 0o600, UID: 1001, GID: 1001}, Actor: audit.Actor{Type: audit.ActorUser, ID: id().String(), Via: audit.ViaAPI}})
	if err != nil || out.Status != deployment.Queued {
		t.Fatal("admit test job")
	}
	issuer := &testIssuer{recipient: key.PublicKey().Bytes()}
	return fixture{service: New(pool, journal, testSigner{}, issuer), pool: pool, peer: mtls.Principal{OrgID: org, RunnerID: runner, Serial: "1"}, jobID: out.JobID.String(), issuer: issuer}
}

func TestPollClaimsOnceAndHonorsCancellation(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	signed, ok, err := f.service.Poll(ctx, f.peer)
	if err != nil || !ok {
		t.Fatal("queued job not returned")
	}
	j, err := runnerproto.DecodeJob(signed.Payload)
	if err != nil || j.JobID != f.jobID {
		t.Fatal("wrong frozen job")
	}
	second, cancelSecond := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelSecond()
	if _, ok, err := f.service.Poll(second, f.peer); ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("issued job was claimed again")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, ok, err := f.service.Poll(ctx2, f.peer); ok || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled poll did not stop")
	}
}

func TestMaterialUsesRegisteredRecipient(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, ok, err := f.service.Poll(ctx, f.peer); err != nil || !ok {
		t.Fatal("claim job")
	}
	env, err := f.service.Material(ctx, f.peer, f.jobID)
	if err != nil || env.JobID != f.jobID || len(env.Sealed) == 0 || len(env.SealedFingerprintKey) == 0 || f.issuer.calls.Load() != 1 {
		t.Fatal("material issuer did not receive the registered recipient")
	}
}

func TestMaterialConcurrentOneWinner(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, ok, err := f.service.Poll(ctx, f.peer); err != nil || !ok {
		t.Fatal("claim job")
	}
	var winners, refused atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			env, err := f.service.Material(ctx, f.peer, f.jobID)
			if err == nil && len(env.Sealed) > 0 && len(env.SealedFingerprintKey) > 0 {
				winners.Add(1)
			} else if errors.Is(err, ErrNotFound) {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 || refused.Load() != 15 || f.issuer.calls.Load() != 1 {
		t.Fatal("material issuance was not exactly once")
	}
}

func TestMaterialRejectsWrongPeerAndState(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.service.Material(ctx, f.peer, f.jobID); !errors.Is(err, ErrNotFound) {
		t.Fatal("unissued job released material")
	}
	if _, ok, err := f.service.Poll(ctx, f.peer); err != nil || !ok {
		t.Fatal("claim job")
	}
	for _, change := range []func(*mtls.Principal){func(p *mtls.Principal) { p.OrgID = uuid.New() }, func(p *mtls.Principal) { p.RunnerID = uuid.New() }, func(p *mtls.Principal) { p.Serial = "stale" }} {
		p := f.peer
		change(&p)
		if _, err := f.service.Material(ctx, p, f.jobID); !errors.Is(err, ErrNotFound) {
			t.Fatal("wrong peer was not uniformly refused")
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE runners SET revoked_at=now() WHERE id=$1`, f.peer.RunnerID); err != nil {
		t.Fatal("revoke runner")
	}
	if _, err := f.service.Material(ctx, f.peer, f.jobID); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked peer released material")
	}
	if f.issuer.calls.Load() != 0 {
		t.Fatal("rejected request reached material issuer")
	}
}

func TestTerminalResultIsImmutable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	signed, ok, err := f.service.Poll(ctx, f.peer)
	if err != nil || !ok {
		t.Fatal("claim job")
	}
	j, err := runnerproto.DecodeJob(signed.Payload)
	if err != nil {
		t.Fatal("decode job")
	}
	result := runnerproto.Result{OK: true, Fingerprint: j.ExpectedFingerprint, Version: j.ExpectedVersion}
	if err := f.service.Result(ctx, f.peer, f.jobID, result); !errors.Is(err, ErrNotFound) {
		t.Fatal("success accepted before material delivery")
	}
	if _, err := f.service.Material(ctx, f.peer, f.jobID); err != nil {
		t.Fatal("issue material")
	}
	if err := f.service.Result(ctx, f.peer, f.jobID, result); err != nil {
		t.Fatal("store terminal result")
	}
	if err := f.service.Result(ctx, f.peer, f.jobID, runnerproto.Result{ErrorClass: runnerproto.ErrClassInternal}); !errors.Is(err, ErrNotFound) {
		t.Fatal("terminal result changed")
	}
}

func TestMaterialExpiredJobAndBackendFailure(t *testing.T) {
	for _, expired := range []bool{true, false} {
		t.Run(map[bool]string{true: "expiry", false: "backend_failure"}[expired], func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			if _, ok, err := f.service.Poll(ctx, f.peer); err != nil || !ok {
				t.Fatal("claim job")
			}
			if expired {
				if _, err := f.pool.Exec(ctx, `WITH expired AS (DELETE FROM deployment_jobs WHERE id=$1 RETURNING *)
INSERT INTO deployment_jobs SELECT (jsonb_populate_record(NULL::deployment_jobs,
  to_jsonb(expired) || jsonb_build_object('created_at', clock_timestamp()-interval '2 minutes',
  'expires_at', clock_timestamp()-interval '1 minute'))).* FROM expired`, f.jobID); err != nil {
					t.Fatal("expire job")
				}
			} else {
				f.issuer.fail = true
			}
			_, err := f.service.Material(ctx, f.peer, f.jobID)
			want := ErrUnavailable
			if expired {
				want = ErrNotFound
			}
			if !errors.Is(err, want) {
				t.Fatal("wrong refusal class")
			}
			if _, err := f.service.Material(ctx, f.peer, f.jobID); !errors.Is(err, ErrNotFound) {
				t.Fatal("expired or burned issuance was retried")
			}
			wantCalls := int32(1)
			if expired {
				wantCalls = 0
			}
			if f.issuer.calls.Load() != wantCalls {
				t.Fatal("material backend called after refusal")
			}
		})
	}
}

type failingJournal struct {
	audit.TransactionalJournaler
	err error
}

func (f failingJournal) AppendTx(context.Context, pgx.Tx, audit.Record) (audit.Record, error) {
	return audit.Record{}, f.err
}

func TestResultAuditFailureRollsBackWithoutLeak(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, ok, err := f.service.Poll(ctx, f.peer); err != nil || !ok {
		t.Fatal("claim job")
	}
	c := canary.New()
	f.service.journal = failingJournal{TransactionalJournaler: audit.NewJournal(f.pool), err: errors.New(c.Value(1))}
	err := f.service.Result(ctx, f.peer, f.jobID, runnerproto.Result{ErrorClass: runnerproto.ErrClassTargetWrite})
	if !errors.Is(err, ErrUnavailable) || c.In(err.Error()) {
		t.Fatal("audit failure was accepted or leaked")
	}
	var status string
	var noResult bool
	if err := f.pool.QueryRow(ctx, `SELECT status,result IS NULL FROM deployment_jobs WHERE id=$1`, f.jobID).Scan(&status, &noResult); err != nil || status != "issued" || !noResult {
		t.Fatal("result committed without audit")
	}
	f.service.journal = audit.NewJournal(f.pool)
	if err := f.service.Result(ctx, f.peer, f.jobID, runnerproto.Result{ErrorClass: runnerproto.ErrClassTargetWrite}); err != nil {
		t.Fatal("retry after audit rollback failed")
	}
}

func TestResultRejectsUnboundMetadata(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, ok, err := f.service.Poll(ctx, f.peer); err != nil || !ok {
		t.Fatal("claim job")
	}
	if _, err := f.service.Material(ctx, f.peer, f.jobID); err != nil {
		t.Fatal("issue material")
	}
	for _, r := range []runnerproto.Result{
		{OK: true, Fingerprint: "kfp1:other:abcdefghijklmnop", Version: "1"},
		{OK: true, Fingerprint: "kfp1:key:abcdefghijklmnop", Version: "2"},
		{ErrorClass: runnerproto.ErrClassInternal, Version: "unbound"},
		{ErrorClass: runnerproto.ErrClassInternal, Fingerprint: "kfp1:other:abcdefghijklmnop"},
	} {
		if err := f.service.Result(ctx, f.peer, f.jobID, r); !errors.Is(err, ErrNotFound) {
			t.Fatal("unbound result metadata accepted")
		}
	}
}

func TestResultAuditKeepsClosedFailureCategory(t *testing.T) {
	for _, tc := range []struct {
		class runnerproto.ErrorClass
		want  audit.ErrorClass
	}{
		{runnerproto.ErrClassPolicyDenied, audit.ErrClassPolicyDenied},
		{runnerproto.ErrClassRateLimited, audit.ErrClassPolicyDenied},
		{runnerproto.ErrClassProvider, audit.ErrClassProviderError},
		{runnerproto.ErrClassValueUnavailable, audit.ErrClassProviderError},
		{runnerproto.ErrClassTargetWrite, audit.ErrClassTargetError},
		{runnerproto.ErrClassHealthcheck, audit.ErrClassTargetError},
		{runnerproto.ErrClassSignature, audit.ErrClassPermissionDenied},
		{runnerproto.ErrClassWrongRunner, audit.ErrClassPermissionDenied},
		{runnerproto.ErrClassReplay, audit.ErrClassPermissionDenied},
		{runnerproto.ErrClassExpired, audit.ErrClassInvalidArgument},
		{runnerproto.ErrClassInvalidJob, audit.ErrClassInvalidArgument},
		{runnerproto.ErrClassFingerprintMismatch, audit.ErrClassInternal},
		{runnerproto.ErrClassVersionMismatch, audit.ErrClassInternal},
		{runnerproto.ErrClassInternal, audit.ErrClassInternal},
	} {
		t.Run(string(tc.class), func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			if _, ok, err := f.service.Poll(ctx, f.peer); err != nil || !ok {
				t.Fatal("claim job")
			}
			if err := f.service.Result(ctx, f.peer, f.jobID, runnerproto.Result{ErrorClass: tc.class}); err != nil {
				t.Fatal("store closed failure")
			}
			var got string
			if err := f.pool.QueryRow(ctx, `SELECT result_error_class FROM audit_records WHERE org_id=$1 AND action='deploy.result'`, f.peer.OrgID).Scan(&got); err != nil || got != string(tc.want) {
				t.Fatal("audit changed the closed failure category")
			}
		})
	}
}

func TestResultRetriesAfterLeaseExpiryWithoutSecondAudit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	signed, ok, err := f.service.Poll(ctx, f.peer)
	if err != nil || !ok {
		t.Fatal("claim job")
	}
	if _, err := f.service.Material(ctx, f.peer, f.jobID); err != nil {
		t.Fatal("issue material")
	}
	job, err := runnerproto.DecodeJob(signed.Payload)
	if err != nil {
		t.Fatal("decode job")
	}
	job.IssuedAt = time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	job.NotAfter = job.IssuedAt.Add(time.Minute)
	payload, err := runnerproto.EncodeJob(job)
	if err != nil {
		t.Fatal("encode expired fixture")
	}
	// Seed a historical issued job; production frozen metadata cannot be edited.
	if _, err := f.pool.Exec(ctx, `WITH expired AS (DELETE FROM deployment_jobs WHERE id=$1 RETURNING *)
INSERT INTO deployment_jobs SELECT (jsonb_populate_record(NULL::deployment_jobs,
 to_jsonb(expired) || jsonb_build_object('created_at', $3::timestamptz,
 'expires_at', $4::timestamptz, 'job_payload', $2::bytea))).* FROM expired`,
		f.jobID, payload, job.IssuedAt, job.NotAfter); err != nil {
		t.Fatal("seed historical issued job")
	}
	result := runnerproto.Result{OK: true, Fingerprint: job.ExpectedFingerprint, Version: job.ExpectedVersion,
		Healthcheck: &runnerproto.Healthcheck{Status: runnerproto.HealthSkipped, CheckedAt: time.Now().UTC().Truncate(time.Microsecond)}}
	if err := f.service.Result(ctx, f.peer, f.jobID, result); err != nil {
		t.Fatal("late result was not accepted")
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.service.Result(ctx, f.peer, f.jobID, result) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 16 {
		t.Fatal("exact result retry did not acknowledge committed result")
	}
	var records int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='deploy.result'`, f.peer.OrgID).Scan(&records); err != nil || records != 1 {
		t.Fatal("result retries duplicated audit")
	}
	different := result
	different.Healthcheck = &runnerproto.Healthcheck{Status: runnerproto.HealthSkipped, CheckedAt: result.Healthcheck.CheckedAt.Add(time.Second)}
	if err := f.service.Result(ctx, f.peer, f.jobID, different); !errors.Is(err, ErrNotFound) {
		t.Fatal("retry changed terminal health result")
	}
	for _, peer := range []mtls.Principal{
		{OrgID: uuid.New(), RunnerID: f.peer.RunnerID, Serial: f.peer.Serial},
		{OrgID: f.peer.OrgID, RunnerID: uuid.New(), Serial: f.peer.Serial},
		{OrgID: f.peer.OrgID, RunnerID: f.peer.RunnerID, Serial: "wrong"},
	} {
		if err := f.service.Result(ctx, peer, f.jobID, result); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign peer acknowledged result")
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE runners SET cert_not_after=clock_timestamp()-interval '1 minute' WHERE id=$1`, f.peer.RunnerID); err != nil {
		t.Fatal("expire peer certificate")
	}
	if err := f.service.Result(ctx, f.peer, f.jobID, result); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired peer acknowledged result")
	}
}
