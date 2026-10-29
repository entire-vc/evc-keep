package deployment

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixture struct {
	ctx                                       context.Context
	pool                                      *pgxpool.Pool
	repo                                      *Repo
	org, user, store, secret, version, runner uuid.UUID
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	ctx := context.Background()
	mdb, err := store.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database: " + migrationFixtureCause(err))
	}
	defer func() { _ = mdb.Close() }()
	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err = provider.Up(ctx); err != nil {
		t.Fatal("migrate test database")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open test pool")
	}
	t.Cleanup(pool.Close)
	f := fixture{ctx: ctx, pool: pool, org: mustID(t), user: mustID(t), store: mustID(t), secret: mustID(t), version: mustID(t), runner: mustID(t)}
	f.repo = NewRepo(pool, audit.NewJournal(pool))
	f.repo.trust = func(_ context.Context, _ pgx.Tx, _, runner uuid.UUID) (Host, error) {
		if runner != f.runner {
			return Host{}, ErrNotFound
		}
		return Host{AttributesKnown: true}, nil
	}
	f.insertCatalog(t, "dev")
	return f
}

func mustID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal("new id")
	}
	return id
}

func (f fixture) insertCatalog(t *testing.T, class string) {
	t.Helper()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name) VALUES($1,'test')`, []any{f.org}},
		{`INSERT INTO users(id,org_id,email) VALUES($1,$2,'test@example.invalid')`, []any{f.user, f.org}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','test','org',$2)`, []any{f.store, f.org}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'DB_PASSWORD',$3,'generic',$4,'builtin://test')`, []any{f.secret, f.org, class, f.store}},
		{`INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'v1','kfp1:k1:abcdefghijklmnop',12)`, []any{f.version, f.org, f.secret}},
		{`INSERT INTO runners(id,org_id,host,cert_serial,cert_not_after) VALUES($1,$2,'test-host','serial',$3)`, []any{f.runner, f.org, time.Now().Add(time.Hour)}},
	}
	for _, s := range statements {
		if _, err := f.pool.Exec(f.ctx, s.sql, s.args...); err != nil {
			t.Fatal("fixture insertion failed")
		}
	}
}

func (f fixture) request(t *testing.T) Request {
	t.Helper()
	return Request{OrgID: f.org, Scope: tenancy.Org(f.org), SecretID: f.secret, VersionID: f.version, RunnerID: f.runner,
		RequestID: mustID(t).String(), Target: runnerproto.Target{Kind: runnerproto.TargetFile, Path: "/srv/app/key", Mode: 0o600, UID: 1001, GID: 1001},
		Actor: audit.Actor{Type: audit.ActorUser, ID: f.user.String(), Via: audit.ViaAPI}}
}

func (f fixture) policy(t *testing.T, limit int) {
	t.Helper()
	_, err := f.pool.Exec(f.ctx, `INSERT INTO deployment_policies(org_id,rules,max_deploys_per_hour) VALUES($1,$2,$3)`, f.org, `{"rules":[{"secret_id":"`+f.secret.String()+`","runner_id":"`+f.runner.String()+`","kind":"file","path_prefix":"/srv/app"}]}`, limit)
	if err != nil {
		t.Fatal("insert policy")
	}
}

func TestSubmitApprovalAndIdempotency(t *testing.T) {
	f := newFixture(t)
	in := f.request(t)
	out, err := f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != NeedsApproval || out.ApprovalID == uuid.Nil || out.JobID != uuid.Nil {
		t.Fatal("missing policy created a runnable job or failed to request approval")
	}
	var jobs, records int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM deployment_jobs`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("approval created a job")
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1`, f.org.String()).Scan(&records); err != nil || records != 3 {
		t.Fatal("decision missing its audit pair")
	}
	again, err := f.repo.Submit(f.ctx, in)
	if err != nil || again.Created || !sameDecision(again, out) {
		t.Fatal("same request id was not idempotent")
	}
	in.Target.Path = "/srv/app/different"
	if _, err = f.repo.Submit(f.ctx, in); !errors.Is(err, ErrConflict) {
		t.Fatal("changed request reused an id")
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1`, f.org.String()).Scan(&records); err != nil || records != 3 {
		t.Fatal("idempotency retry appended audit")
	}
}

func TestSubmitProductionApprovalBindingAndSharedHost(t *testing.T) {
	f := newFixture(t)
	f.policy(t, 10)
	if _, err := f.pool.Exec(f.ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.secret); err != nil {
		t.Fatal("set prod")
	}
	in := f.request(t)
	out, err := f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != NeedsApproval {
		t.Fatal("new prod target was not held for approval")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE approval_requests SET status='approved',decided_by=$1,decided_at=now() WHERE id=$2`, f.user, out.ApprovalID); err != nil {
		t.Fatal("approve target")
	}
	in.RequestID = mustID(t).String()
	out, err = f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != Queued || out.JobID == uuid.Nil {
		t.Fatal("approved exact target did not queue")
	}
	// An approval is bound to a secret, runner and complete target. Changing
	// just one target field must not silently reuse it.
	in.RequestID = mustID(t).String()
	in.Target.UID++
	out, err = f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != NeedsApproval {
		t.Fatal("altered target inherited approval")
	}
	otherSecret, otherVersion := mustID(t), mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'SECOND_SECRET','prod','generic',$3,'builtin://second')`, otherSecret, f.org, f.store); err != nil {
		t.Fatal("create second secret")
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'v1','kfp1:k1:abcdefghijklmnop',12)`, otherVersion, f.org, otherSecret); err != nil {
		t.Fatal("create second version")
	}
	// Both secrets have a target template, so the template guard cannot mask
	// a regression that reuses the first secret's production approval.
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_policies SET rules=jsonb_set(rules,'{rules}',
	 (rules->'rules') || jsonb_build_object('secret_id',$2::text,'runner_id',$3::text,'kind','file','path_prefix','/srv/app'))
	 WHERE org_id=$1`, f.org, otherSecret.String(), f.runner.String()); err != nil {
		t.Fatal("bind second secret template")
	}
	in.Target.UID--
	in.SecretID, in.VersionID, in.RequestID = otherSecret, otherVersion, mustID(t).String()
	out, err = f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != NeedsApproval {
		t.Fatal("another secret inherited approval")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE approval_requests SET status='approved',decided_by=$1,decided_at=now() WHERE id=$2`, f.user, out.ApprovalID); err != nil {
		t.Fatal("approve second secret target")
	}
	in.RequestID = mustID(t).String()
	out, err = f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != Queued || out.JobID == uuid.Nil {
		t.Fatal("second secret with its own approval and template did not queue")
	}
	f.repo.trust = func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (Host, error) {
		return Host{AttributesKnown: true, UIDShared: true}, nil
	}
	in.RequestID = mustID(t).String()
	out, err = f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != Denied {
		t.Fatal("shared UID accepted production")
	}
}

func TestSubmitAtomicRateLimitAndTenantIsolation(t *testing.T) {
	f := newFixture(t)
	f.policy(t, 10)
	// Pin one authenticated actor across retries; new request ids remain
	// independent rate-limit attempts.
	base := f.request(t)
	var wg sync.WaitGroup
	results := make(chan Outcome, 16)
	errs := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in := base
			id, err := uuid.NewV7()
			if err != nil {
				errs <- err
				return
			}
			in.RequestID = id.String()
			out, err := f.repo.Submit(f.ctx, in)
			results <- out
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("concurrent request failed")
		}
	}
	queued, limited := 0, 0
	for out := range results {
		switch out.Status {
		case Queued:
			queued++
		case RateLimited:
			limited++
		default:
			t.Fatal("unexpected concurrent policy decision")
		}
	}
	if queued != 10 || limited != 6 {
		t.Fatalf("rate limit bypass: queued=%d limited=%d", queued, limited)
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM deployment_jobs WHERE org_id=$1 AND secret_id=$2 AND runner_id=$3`, f.org, f.secret, f.runner).Scan(&count); err != nil || count != 10 {
		t.Fatal("queue count bypassed limit")
	}
	wrongScope := base
	wrongScope.Scope = tenancy.Scope{Level: "ws", ID: mustID(t)}
	wrongScope.RequestID = mustID(t).String()
	if _, err := f.repo.Submit(f.ctx, wrongScope); !errors.Is(err, ErrNotFound) {
		t.Fatal("wrong tenancy scope reached a deployment decision")
	}
	otherOrg := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO organizations(id,name) VALUES($1,'other')`, otherOrg); err != nil {
		t.Fatal("other org")
	}
	in := base
	in.OrgID = otherOrg
	in.Scope = tenancy.Org(otherOrg)
	in.RequestID = mustID(t).String()
	if _, err := f.repo.Submit(f.ctx, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-org secret or runner accepted")
	}
}

type failSecondJournal struct {
	inner *audit.Journal
	calls int
}

func (j *failSecondJournal) AppendTx(ctx context.Context, tx pgx.Tx, r audit.Record) (audit.Record, error) {
	j.calls++
	if j.calls == 2 {
		return audit.Record{}, errors.New("synthetic audit failure")
	}
	return j.inner.AppendTx(ctx, tx, r)
}
func (*failSecondJournal) LogCommitted(context.Context, audit.Record) {}

func TestSubmitRollsBackOnAuditFailureAndNoCanary(t *testing.T) {
	f := newFixture(t)
	f.policy(t, 10)
	in := f.request(t)
	canary := "KEEP_TEST_SECRET_CANARY_7fe1"
	in.Target.Path = "/srv/app/" + canary
	j := &failSecondJournal{inner: audit.NewJournal(f.pool)}
	f.repo.journal = j
	_, err := f.repo.Submit(f.ctx, in)
	if !errors.Is(err, ErrUnavailable) || containsCanary(err, canary) {
		t.Fatal("audit failure was not closed or leaked")
	}
	for _, table := range []string{"deployment_requests", "deployment_jobs", "approval_requests", "audit_records"} {
		var count int
		query := fmt.Sprintf("SELECT count(*) FROM %s", table) //nolint:gosec // fixed table list above
		if err := f.pool.QueryRow(f.ctx, query).Scan(&count); err != nil || count != 0 {
			t.Fatal("audit failure left committed state")
		}
	}
}

func TestSubmitUsesEnrolledRegistryTrust(t *testing.T) {
	f := newFixture(t)
	f.policy(t, 10)
	f.repo = NewRepo(f.pool, audit.NewJournal(f.pool))
	in := f.request(t)
	if _, err := f.repo.Submit(f.ctx, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("legacy runner without delivery key accepted")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic public key")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE runners SET hpke_public_key=$1,uid_shared=false,host_labels='{"environment":"production"}',attrs_source='enroll_token' WHERE org_id=$2 AND id=$3`, key.PublicKey().Bytes(), f.org, f.runner); err != nil {
		t.Fatal("enroll synthetic trust")
	}
	out, err := f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != Queued {
		t.Fatal("enrolled runner was not admitted")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE runners SET revoked_at=now() WHERE org_id=$1 AND id=$2`, f.org, f.runner); err != nil {
		t.Fatal("revoke synthetic runner")
	}
	in.RequestID = mustID(t).String()
	if _, err := f.repo.Submit(f.ctx, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked runner accepted")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE runners SET revoked_at=NULL,cert_not_after=now()-interval '1 minute' WHERE org_id=$1 AND id=$2`, f.org, f.runner); err != nil {
		t.Fatal("expire synthetic runner")
	}
	in.RequestID = mustID(t).String()
	if _, err := f.repo.Submit(f.ctx, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired runner accepted")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE runners SET cert_not_after=now()+interval '1 hour',uid_shared=NULL,host_labels=NULL,attrs_source=NULL WHERE org_id=$1 AND id=$2`, f.org, f.runner); err != nil {
		t.Fatal("set legacy host attributes")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE secrets SET class='prod' WHERE org_id=$1 AND id=$2`, f.org, f.secret); err != nil {
		t.Fatal("set production class")
	}
	in.RequestID = mustID(t).String()
	out, err = f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != Denied {
		t.Fatal("unknown host attributes accepted production")
	}
	otherOrg := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO organizations(id,name) VALUES($1,'other')`, otherOrg); err != nil {
		t.Fatal("create second organization")
	}
	in.OrgID, in.Scope, in.RequestID = otherOrg, tenancy.Org(otherOrg), mustID(t).String()
	if _, err := f.repo.Submit(f.ctx, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("runner accepted through another organization")
	}
}

func TestQueuedJobMetadataCannotBeRewritten(t *testing.T) {
	f := newFixture(t)
	f.policy(t, 10)
	out, err := f.repo.Submit(f.ctx, f.request(t))
	if err != nil || out.Status != Queued {
		t.Fatal("queue fixture failed")
	}
	for _, sql := range []string{
		`UPDATE deployment_jobs SET job_payload=decode('00','hex') WHERE id=$1`,
		`UPDATE deployment_jobs SET provider_ref='builtin://other' WHERE id=$1`,
		`UPDATE deployment_jobs SET expires_at=expires_at+interval '1 hour' WHERE id=$1`,
	} {
		if _, err := f.pool.Exec(f.ctx, sql, out.JobID); err == nil {
			t.Fatal("frozen job metadata changed")
		}
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET status='issued',issued_at=now() WHERE id=$1`, out.JobID); err != nil {
		t.Fatal("lifecycle update refused")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET status='completed' WHERE id=$1`, out.JobID); err == nil {
		t.Fatal("terminal job accepted without result")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE deployment_jobs SET status='completed',result='{}' WHERE id=$1`, out.JobID); err != nil {
		t.Fatal("terminal lifecycle update refused")
	}
}

func TestUnsupportedProviderNeverQueuesMaterialClaim(t *testing.T) {
	f := newFixture(t)
	f.policy(t, 10)
	if _, err := f.pool.Exec(f.ctx, `UPDATE stores SET provider='external' WHERE org_id=$1 AND id=$2`, f.org, f.store); err != nil {
		t.Fatal("set synthetic external provider")
	}
	in := f.request(t)
	out, err := f.repo.Submit(f.ctx, in)
	if err != nil || out.Status != UnsupportedProvider || out.JobID != uuid.Nil || out.ApprovalID != uuid.Nil {
		t.Fatal("unsupported provider created a runnable job or approval")
	}
	var jobs, records int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM deployment_jobs`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("unsupported provider queued material claim")
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1`, f.org.String()).Scan(&records); err != nil || records != 2 {
		t.Fatal("unsupported provider refusal missed atomic audit")
	}
	again, err := f.repo.Submit(f.ctx, in)
	if err != nil || again.Created || !sameDecision(again, out) {
		t.Fatal("unsupported provider retry changed decision")
	}
}

func TestSubmitUnsupportedProviderPreservesPolicyDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, class, path string
		host              Host
		want              Status
	}{
		{"outside-template", "dev", "/srv/other/key", Host{AttributesKnown: true}, NeedsApproval},
		{"new-production-target", "prod", "/srv/app/key", Host{AttributesKnown: true}, NeedsApproval},
		{"shared-production-host", "prod", "/srv/app/key", Host{AttributesKnown: true, UIDShared: true}, Denied},
		{"unknown-production-host", "prod", "/srv/app/key", Host{}, Denied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.policy(t, 10)
			if _, err := f.pool.Exec(f.ctx, `UPDATE stores SET provider='external' WHERE org_id=$1 AND id=$2`, f.org, f.store); err != nil {
				t.Fatal("set synthetic external provider")
			}
			if _, err := f.pool.Exec(f.ctx, `UPDATE secrets SET class=$3 WHERE org_id=$1 AND id=$2`, f.org, f.secret, tc.class); err != nil {
				t.Fatal("set secret class")
			}
			f.repo.trust = func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (Host, error) {
				return tc.host, nil
			}
			in := f.request(t)
			in.Target.Path = tc.path
			out, err := f.repo.Submit(f.ctx, in)
			if err != nil || out.Status != tc.want || out.JobID != uuid.Nil {
				t.Fatal("unsupported provider replaced policy decision")
			}
			wantApprovals := 0
			if tc.want == NeedsApproval {
				wantApprovals = 1
			}
			if (out.ApprovalID != uuid.Nil) != (wantApprovals == 1) {
				t.Fatal("unsupported provider changed required approval")
			}
			again, err := f.repo.Submit(f.ctx, in)
			if err != nil || again.Created || !sameDecision(again, out) {
				t.Fatal("unsupported provider policy retry changed decision")
			}
			var approvals, jobs, records int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM approval_requests WHERE org_id=$1 AND deployment_request_id=$2 AND status='requested' AND binding_hash=(SELECT request_hash FROM deployment_requests WHERE org_id=$1 AND id=$2)`, f.org, out.ID).Scan(&approvals); err != nil || approvals != wantApprovals {
				t.Fatal("unsupported provider did not persist the bound requested approval exactly once")
			}
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM deployment_jobs WHERE org_id=$1`, f.org).Scan(&jobs); err != nil || jobs != 0 {
				t.Fatal("unsupported provider policy decision queued material claim")
			}
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1`, f.org.String()).Scan(&records); err != nil || records != 2+wantApprovals {
				t.Fatal("unsupported provider policy decision missed atomic idempotent audit")
			}
		})
	}
}

func containsCanary(err error, canary string) bool {
	return err != nil && len(canary) > 0 && stringContains(err.Error(), canary)
}
func stringContains(s, part string) bool {
	return len(part) > 0 && len(s) >= len(part) && findPart(s, part)
}
func findPart(s, part string) bool {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return true
		}
	}
	return false
}

// sameDecision compares two outcomes by decision; Created differs by design on a replay.
func sameDecision(a, b Outcome) bool {
	a.Created, b.Created = false, false
	return a == b
}
