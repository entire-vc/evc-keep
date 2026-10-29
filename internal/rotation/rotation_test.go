package rotation

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kstore "github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	fpNew = "kfp1:k1:abcdefghijklmnop"
	fpBad = "kfp1:k1:zzzzzzzzzzzzzzzz"
)

// cid is the canonical carrier id the tests use for carrier number n.
func cid(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func cids(ns ...int) string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = cid(n)
	}
	return strings.Join(out, ",")
}

type fakes struct {
	mu        sync.Mutex
	carriers  []Carrier
	deployErr map[string]error
	verifyFP  map[string]string
	unhealthy map[string]bool
	verifyErr map[string]error
	revokeErr error
	prepErr   error
	listErr   error
	incErr    error

	deployed        []string
	revokes         int
	prepares        int
	incidents       []IncidentRecord
	resolved        []IncidentRecord
	resolveErr      error
	resolveCalls    int
	incidentCalls   int
	incidentNoEpoch int
	incidentEpoch   int64
	inFlight        int32
	maxFlight       int32
	gate            chan struct{} // when set, Deploy blocks on it
	killAt          int           // when > 0, the Nth Deploy call cancels killCtx and dies
	killCtx         context.CancelFunc
	calls           int32
	entered         chan struct{}
}

func newFakes(n int) *fakes {
	f := &fakes{deployErr: map[string]error{}, verifyFP: map[string]string{}, unhealthy: map[string]bool{}, verifyErr: map[string]error{}}
	for i := 1; i <= n; i++ {
		f.carriers = append(f.carriers, Carrier{ID: cid(i)})
	}
	return f
}

func (f *fakes) Prepare(context.Context, Ref, uuid.UUID) (Version, error) {
	f.mu.Lock()
	f.prepares++
	f.mu.Unlock()
	if f.prepErr != nil {
		return Version{}, f.prepErr
	}
	return Version{Old: "1", New: "2", Fingerprint: fpNew}, nil
}
func (f *fakes) List(context.Context, Ref) ([]Carrier, error) { return f.carriers, f.listErr }
func (f *fakes) Deploy(ctx context.Context, _ Ref, _ uuid.UUID, c Carrier, _ string) error {
	n := atomic.AddInt32(&f.inFlight, 1)
	defer atomic.AddInt32(&f.inFlight, -1)
	for {
		m := atomic.LoadInt32(&f.maxFlight)
		if n <= m || atomic.CompareAndSwapInt32(&f.maxFlight, m, n) {
			break
		}
	}
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.killAt > 0 && int(atomic.AddInt32(&f.calls, 1)) == f.killAt {
		f.killCtx()
		return context.Canceled
	}
	time.Sleep(5 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deployed = append(f.deployed, c.ID)
	return f.deployErr[c.ID]
}
func (f *fakes) Verify(_ context.Context, _ Ref, c Carrier, _ string) (Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.verifyErr[c.ID]; err != nil {
		return Report{}, err
	}
	fp := fpNew
	if v, ok := f.verifyFP[c.ID]; ok {
		fp = v
	}
	return Report{Fingerprint: fp, Healthy: !f.unhealthy[c.ID]}, nil
}
func (f *fakes) Revoke(context.Context, Ref, uuid.UUID, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes++
	return f.revokeErr
}
func (f *fakes) Open(ctx context.Context, r IncidentRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Like a fenced collaborator: a call carries the lease epoch and one
	// lower than an epoch already accepted is refused.
	ep, ok := Epoch(ctx)
	if !ok {
		f.incidentNoEpoch++
	} else if ep < f.incidentEpoch {
		return errors.New("stale epoch")
	} else {
		f.incidentEpoch = ep
	}
	f.incidentCalls++
	if f.incErr != nil {
		return f.incErr
	}
	for _, have := range f.incidents { // idempotent per RunID, as the contract says
		if have.RunID == r.RunID {
			return nil
		}
	}
	f.incidents = append(f.incidents, r)
	return nil
}
func (f *fakes) Resolve(ctx context.Context, r IncidentRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := Epoch(ctx); !ok {
		f.incidentNoEpoch++
	}
	f.resolveCalls++
	if ep, ok := Epoch(ctx); ok {
		if ep < f.incidentEpoch {
			return errors.New("stale epoch")
		}
		f.incidentEpoch = ep
	}
	if f.resolveErr != nil {
		return f.resolveErr
	}
	for _, have := range f.resolved {
		if have.RunID == r.RunID {
			return nil
		}
	}
	f.resolved = append(f.resolved, r)
	return nil
}
func (f *fakes) deps() Deps {
	return Deps{Versions: f, Carriers: f, Deployer: f, Verifier: f, Revoker: f, Incident: f}
}

type fx struct {
	ctx  context.Context
	pool *pgxpool.Pool
	ref  Ref
}

func newFx(t *testing.T) fx {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	ctx := context.Background()
	mdb, err := kstore.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = mdb.Close() }()
	prov, err := kstore.NewProvider(mdb)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err = prov.Up(ctx); err != nil {
		t.Fatal("migrate test database")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open test pool")
	}
	t.Cleanup(pool.Close)
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES ($1,'rot')`, org); err != nil {
		t.Fatal("insert organization")
	}
	return fx{ctx: ctx, pool: pool, ref: Ref{OrgID: org, SecretID: uuid.New()}}
}

// (1) five carriers, the third refuses: no revoke, an incident, failed.
func TestPartialFailureNeverRevokes(t *testing.T) {
	x, f := newFx(t), newFakes(5)
	f.deployErr[cid(3)] = errors.New("boom")
	e := New(x.pool, f.deps())
	res, err := e.Rotate(x.ctx, x.ref, Options{Concurrency: 1})
	if !errors.Is(err, ErrFailed) || res.State != StateFailed || res.Class != ClassDeployFailed {
		t.Fatalf("want failed/deploy_failed, got %+v %v", res, err)
	}
	if f.revokes != 0 {
		t.Fatalf("revoker called %d times on partial success", f.revokes)
	}
	if strings.Join(f.deployed, ",") != cids(1, 2, 3) {
		t.Fatalf("layout went on after the failure: %v", f.deployed)
	}
	if len(f.incidents) != 1 || f.incidents[0].Class != ClassDeployFailed || strings.Join(f.incidents[0].Carriers, ",") != cid(3) {
		t.Fatalf("incident: %+v", f.incidents)
	}
}

// (2) everything ok: exactly one revoke; a replay of the finished run does nothing.
func TestAllOKRevokesExactlyOnce(t *testing.T) {
	x, f := newFx(t), newFakes(5)
	e := New(x.pool, f.deps())
	id := uuid.New()
	res, err := e.Rotate(x.ctx, x.ref, Options{RunID: id})
	if err != nil || res.State != StateDone || res.NewVersion != "2" || res.OldVersion != "1" || res.Fingerprint != fpNew {
		t.Fatalf("got %+v %v", res, err)
	}
	if f.revokes != 1 || len(f.deployed) != 5 || len(f.incidents) != 0 {
		t.Fatalf("revokes=%d deployed=%d incidents=%d", f.revokes, len(f.deployed), len(f.incidents))
	}
	if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); err != nil {
		t.Fatal(err)
	}
	if f.revokes != 1 || len(f.deployed) != 5 {
		t.Fatalf("replay repeated work: revokes=%d deployed=%d", f.revokes, len(f.deployed))
	}
}

// (3) a wrong fingerprint after layout, on any carrier, counts as a failure.
func TestFingerprintMismatchOnAnyCarrierFails(t *testing.T) {
	for i := 1; i <= 5; i++ {
		id := cid(i)
		t.Run(id, func(t *testing.T) {
			x, f := newFx(t), newFakes(5)
			f.verifyFP[id] = fpBad
			res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
			if !errors.Is(err, ErrFailed) || res.Class != ClassFingerprintMismatch {
				t.Fatalf("got %+v %v", res, err)
			}
			if f.revokes != 0 || len(f.incidents) != 1 || len(f.deployed) != 5 {
				t.Fatalf("revokes=%d incidents=%d deployed=%d", f.revokes, len(f.incidents), len(f.deployed))
			}
		})
	}
	t.Run("malformed fingerprint", func(t *testing.T) {
		x, f := newFx(t), newFakes(2)
		f.verifyFP[cid(1)] = "not-a-fingerprint"
		res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
		if !errors.Is(err, ErrFailed) || res.Class != ClassFingerprintMismatch || f.revokes != 0 {
			t.Fatalf("got %+v %v revokes=%d", res, err, f.revokes)
		}
	})
}

func TestUnhealthyCarrierFails(t *testing.T) {
	x, f := newFx(t), newFakes(3)
	f.unhealthy[cid(2)] = true
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
	if !errors.Is(err, ErrFailed) || res.Class != ClassUnhealthy || f.revokes != 0 || len(f.incidents) != 1 {
		t.Fatalf("got %+v %v revokes=%d", res, err, f.revokes)
	}
}

func TestVerifyErrorFails(t *testing.T) {
	x, f := newFx(t), newFakes(3)
	f.verifyErr[cid(1)] = errors.New("unreachable")
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
	if !errors.Is(err, ErrFailed) || res.Class != ClassVerifyFailed || f.revokes != 0 {
		t.Fatalf("got %+v %v", res, err)
	}
}

// A secret with no carriers is not "100% ok": nothing proves the new version
// is anywhere, so the old one stays.
func TestNoCarriersNeverRevokes(t *testing.T) {
	x, f := newFx(t), newFakes(0)
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
	if !errors.Is(err, ErrFailed) || res.Class != ClassNoCarriers || f.revokes != 0 || len(f.incidents) != 1 {
		t.Fatalf("got %+v %v", res, err)
	}
}

// An id the engine cannot store as a label fails the run instead of leaving
// it open in new_version.
func TestInvalidCarrierIDFailsRun(t *testing.T) {
	x, f := newFx(t), newFakes(0)
	f.carriers = []Carrier{{ID: cid(1)}, {ID: "has space"}}
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
	if !errors.Is(err, ErrFailed) || res.Class != ClassPrepareFailed || len(f.deployed) != 0 || f.revokes != 0 {
		t.Fatalf("got %+v %v", res, err)
	}
}

func TestPrepareFailureFailsRun(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.prepErr = errors.New("provider down")
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
	if !errors.Is(err, ErrFailed) || res.Class != ClassPrepareFailed || len(f.deployed) != 0 || f.revokes != 0 {
		t.Fatalf("got %+v %v", res, err)
	}
}

// A failed Revoke is not terminal: the run stays in revoking_old, the
// incident "old key alive" is opened once, and the same run id retries only the
// revoke until the old version is gone.
func TestRevokeFailureLeavesRunRevokingAndRetrySucceeds(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.revokeErr = errors.New("revoke refused")
	id := uuid.New()
	e := New(x.pool, f.deps())
	res, err := e.Rotate(x.ctx, x.ref, Options{RunID: id})
	if !errors.Is(err, ErrRevokePending) || errors.Is(err, ErrFailed) || res.State != StateRevokingOld || res.Class != ClassRevokeFailed || len(f.incidents) != 1 {
		t.Fatalf("got %+v %v incidents=%d", res, err, len(f.incidents))
	}
	var st, cl string
	if err := x.pool.QueryRow(x.ctx, `SELECT state, error_class FROM rotation_runs WHERE id=$1`, id).Scan(&st, &cl); err != nil || st != string(StateRevokingOld) || cl != string(ClassRevokeFailed) {
		t.Fatalf("stored run: state=%q class=%q %v", st, cl, err)
	}
	// Still failing: the run stays pending, no second incident.
	res, err = e.Rotate(x.ctx, x.ref, Options{RunID: id})
	if !errors.Is(err, ErrRevokePending) || res.State != StateRevokingOld || len(f.incidents) != 1 || f.incidentCalls != 1 || f.revokes != 2 {
		t.Fatalf("second failure: %+v %v incidents=%d revokes=%d", res, err, len(f.incidents), f.revokes)
	}
	deployed, prepares := len(f.deployed), f.prepares
	f.revokeErr = nil
	res, err = e.Rotate(x.ctx, x.ref, Options{RunID: id})
	if err != nil || res.State != StateDone || res.Class != ClassNone {
		t.Fatalf("retry: %+v %v", res, err)
	}
	if err := x.pool.QueryRow(x.ctx, `SELECT error_class FROM rotation_runs WHERE id=$1`, id).Scan(&cl); err != nil || cl != "" {
		t.Fatalf("class not cleared on done: %q %v", cl, err)
	}
	if f.revokes != 3 || len(f.deployed) != deployed || f.prepares != prepares || len(f.incidents) != 1 || f.incidentCalls != 1 {
		t.Fatalf("retry redid work: revokes=%d deployed=%d prepares=%d incidents=%d", f.revokes, len(f.deployed), f.prepares, len(f.incidents))
	}
	if len(f.resolved) != 1 || f.resolved[0].RunID != id || f.resolved[0].Class != ClassRevokeFailed || f.resolveCalls != 1 {
		t.Fatalf("the retry did not resolve the incident once: %+v calls=%d", f.resolved, f.resolveCalls)
	}
	// Done is final: another call replays it and revokes nothing.
	if res, err = e.Rotate(x.ctx, x.ref, Options{RunID: id}); err != nil || res.State != StateDone || f.revokes != 3 || f.resolveCalls != 1 {
		t.Fatalf("replay: %+v %v revokes=%d", res, err, f.revokes)
	}
}

// While the old key is alive the secret is busy: a new run id is refused as
// revoke-pending (not a plain conflict, not a second rotation).
func TestRevokePendingBlocksNewRun(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.revokeErr = errors.New("revoke refused")
	e := New(x.pool, f.deps())
	if _, err := e.Rotate(x.ctx, x.ref, Options{}); !errors.Is(err, ErrRevokePending) {
		t.Fatal(err)
	}
	prepares := f.prepares
	if _, err := e.Rotate(x.ctx, x.ref, Options{}); !errors.Is(err, ErrRevokePending) || errors.Is(err, ErrConflict) || f.prepares != prepares {
		t.Fatalf("new run id: %v prepares=%d", err, f.prepares-prepares)
	}
}

// The retry still refuses to revoke on anything less than every carrier
// verified: the database is asked again.
func TestRevokeRetryRechecksVerification(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.revokeErr = errors.New("revoke refused")
	id := uuid.New()
	e := New(x.pool, f.deps())
	if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); !errors.Is(err, ErrRevokePending) {
		t.Fatal(err)
	}
	if _, err := x.pool.Exec(x.ctx, `UPDATE rotation_steps SET verify_state='pending' WHERE run_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	f.revokeErr = nil
	revokes := f.revokes
	res, err := e.Rotate(x.ctx, x.ref, Options{RunID: id})
	if !errors.Is(err, ErrFailed) || res.Class != ClassVerifyFailed || f.revokes != revokes {
		t.Fatalf("got %+v %v revokes=%d->%d", res, err, revokes, f.revokes)
	}
}

// (4) the process dies between layout and revoke; a restart resumes, revokes
// once, and does not lay the carriers out again.
func TestResumeAfterKillBeforeRevoke(t *testing.T) {
	x, f := newFx(t), newFakes(5)
	id := uuid.New()
	dying := New(x.pool, f.deps())
	dying.afterState = func(s State) error {
		if s == StateRevokingOld {
			return errors.New("killed")
		}
		return nil
	}
	if _, err := dying.Rotate(x.ctx, x.ref, Options{RunID: id}); err == nil {
		t.Fatal("expected the simulated kill")
	}
	if f.revokes != 0 || len(f.deployed) != 5 {
		t.Fatalf("before restart: revokes=%d deployed=%d", f.revokes, len(f.deployed))
	}
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{RunID: id})
	if err != nil || res.State != StateDone {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if f.revokes != 1 || len(f.deployed) != 5 {
		t.Fatalf("after restart: revokes=%d deployed=%d (double or lost)", f.revokes, len(f.deployed))
	}
}

// A killed process cannot release its lease: others are refused until it
// expires, then the run is taken over.
func TestLeaseOfDeadProcessExpires(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	id := uuid.New()
	if err := (&store{pool: x.pool}).start(x.ctx, x.ref, id); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := (&store{pool: x.pool}).claim(x.ctx, id, "dead", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	e := New(x.pool, f.deps())
	e.now = func() time.Time { return now.Add(30 * time.Second) }
	if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); !errors.Is(err, ErrConflict) {
		t.Fatalf("live lease must conflict, got %v", err)
	}
	e.now = func() time.Time { return now.Add(2 * time.Minute) }
	res, err := e.Rotate(x.ctx, x.ref, Options{RunID: id})
	if err != nil || res.State != StateDone || f.revokes != 1 {
		t.Fatalf("takeover: %+v %v revokes=%d", res, err, f.revokes)
	}
}

// (6) two runs of one secret: one executes, the other is refused.
func TestParallelRotateOfOneSecretConflicts(t *testing.T) {
	x, f := newFx(t), newFakes(3)
	f.gate = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	e := New(x.pool, f.deps())
	first := make(chan error, 1)
	go func() { _, err := e.Rotate(x.ctx, x.ref, Options{}); first <- err }()
	<-f.entered
	short, stop := context.WithTimeout(x.ctx, 5*time.Second)
	defer stop()
	if _, err := e.Rotate(short, x.ref, Options{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second run: want ErrConflict, got %v", err)
	}
	close(f.gate)
	if err := <-first; err != nil {
		t.Fatalf("first run: %v", err)
	}
	if f.revokes != 1 {
		t.Fatalf("revokes=%d", f.revokes)
	}
	// A finished run frees the secret for the next one.
	if _, err := e.Rotate(x.ctx, x.ref, Options{}); err != nil {
		t.Fatalf("next run after done: %v", err)
	}
}

func TestSameRunIDInParallelConflicts(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.gate = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	e := New(x.pool, f.deps())
	id := uuid.New()
	first := make(chan error, 1)
	go func() { _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); first <- err }()
	<-f.entered
	short, stop := context.WithTimeout(x.ctx, 5*time.Second)
	defer stop()
	if _, err := e.Rotate(short, x.ref, Options{RunID: id}); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	close(f.gate)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestRunIDOfAnotherSecretIsUnavailable(t *testing.T) {
	x, f := newFx(t), newFakes(1)
	e := New(x.pool, f.deps())
	id := uuid.New()
	if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); err != nil {
		t.Fatal(err)
	}
	other := Ref{OrgID: x.ref.OrgID, SecretID: uuid.New()}
	if _, err := e.Rotate(x.ctx, other, Options{RunID: id}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	x, f := newFx(t), newFakes(8)
	if _, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{Concurrency: 2}); err != nil {
		t.Fatal(err)
	}
	if m := atomic.LoadInt32(&f.maxFlight); m != 2 {
		t.Fatalf("max parallel layouts %d, want 2", m)
	}
}

// A failed incident hook is retried on resume, once.
func TestIncidentRetriedOnResume(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.deployErr[cid(1)] = errors.New("boom")
	f.incErr = errors.New("journal down")
	id := uuid.New()
	e := New(x.pool, f.deps())
	if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); !errors.Is(err, ErrIncident) || strings.Contains(err.Error(), "journal") {
		t.Fatalf("incident failure must surface as the closed error, got %v", err)
	}
	f.incErr = nil
	if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); !errors.Is(err, ErrFailed) {
		t.Fatal(err)
	}
	if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); !errors.Is(err, ErrFailed) {
		t.Fatal(err)
	}
	if len(f.incidents) != 1 || f.revokes != 0 {
		t.Fatalf("incidents=%d revokes=%d", len(f.incidents), f.revokes)
	}
}

// The database refuses to revoke on anything short of every carrier deployed
// and verified with the expected fingerprint, even when the state column is
// forced forward.
func TestRevokeGateReadsTheDatabase(t *testing.T) {
	for name, tamper := range map[string]string{
		"one carrier unverified": `UPDATE rotation_steps SET deploy_state='ok', verify_state='ok', observed_fp='` + fpNew + `' WHERE carrier_id <> '` + cid(3) + `'`,
		"one carrier wrong fp":   `UPDATE rotation_steps SET deploy_state='ok', verify_state='ok', observed_fp=CASE WHEN carrier_id='` + cid(3) + `' THEN '` + fpBad + `' ELSE '` + fpNew + `' END`,
		"no steps at all":        `DELETE FROM rotation_steps`,
		"empty expected fp":      `UPDATE rotation_steps SET deploy_state='ok', verify_state='ok', observed_fp=''; UPDATE rotation_runs SET expected_fp=''`,
		"one carrier undeployed": `UPDATE rotation_steps SET verify_state='ok', observed_fp='` + fpNew + `', deploy_state=CASE WHEN carrier_id='` + cid(3) + `' THEN 'pending' ELSE 'ok' END`,
	} {
		t.Run(name, func(t *testing.T) {
			x, f := newFx(t), newFakes(3)
			id := uuid.New()
			e := New(x.pool, f.deps())
			e.afterState = func(s State) error {
				if s == StateDeploying {
					return errors.New("killed")
				}
				return nil
			}
			if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); err == nil {
				t.Fatal("expected kill")
			}
			if _, err := x.pool.Exec(x.ctx, tamper); err != nil {
				t.Fatal(err)
			}
			if _, err := x.pool.Exec(x.ctx, `UPDATE rotation_runs SET state='revoking_old' WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
			res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{RunID: id})
			if !errors.Is(err, ErrFailed) || f.revokes != 0 {
				t.Fatalf("got %+v %v revokes=%d", res, err, f.revokes)
			}
		})
	}
}

// The process dies in the middle of the layout: the restart lays out only (each carrier once)
// the carriers that are not done.
func TestResumeAfterKillMidLayout(t *testing.T) {
	x, f := newFx(t), newFakes(5)
	ctx, cancel := context.WithCancel(x.ctx)
	f.killAt, f.killCtx = 3, cancel
	id := uuid.New()
	if _, err := New(x.pool, f.deps()).Rotate(ctx, x.ref, Options{RunID: id, Concurrency: 1}); err == nil {
		t.Fatal("expected the simulated kill")
	}
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1})
	if err != nil || res.State != StateDone {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if strings.Join(f.deployed, ",") != cids(1, 2, 3, 4, 5) || f.revokes != 1 {
		t.Fatalf("deployed=%v revokes=%d", f.deployed, f.revokes)
	}
}

// (5) a value that a collaborator drags into its errors is nowhere we store
// or return: database rows, incident records, result, returned errors.
func TestValueNeverReachesStateIncidentOrErrors(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind")
	}
	for name, setup := range map[string]func(*fakes){
		"deploy":  func(f *fakes) { f.deployErr[cid(2)] = errors.New("deploy of " + v) },
		"verify":  func(f *fakes) { f.verifyErr[cid(2)] = errors.New("read " + v) },
		"revoke":  func(f *fakes) { f.revokeErr = errors.New("revoke " + v) },
		"prepare": func(f *fakes) { f.prepErr = errors.New("prepare " + v) },
		"badfp":   func(f *fakes) { f.verifyFP[cid(2)] = v },
		"list":    func(f *fakes) { f.listErr = errors.New("list " + v) },
		"incident": func(f *fakes) {
			f.deployErr[cid(1)] = errors.New("deploy")
			f.incErr = errors.New("journal refused " + v)
		},
	} {
		t.Run(name, func(t *testing.T) {
			x, f := newFx(t), newFakes(3)
			setup(f)
			res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
			var dump strings.Builder
			fmt.Fprintf(&dump, "%+v %#v %v %+v", res, res, err, f.incidents)
			for _, q := range []string{`SELECT coalesce(string_agg(row_to_json(r)::text, ' '), '') FROM rotation_runs r`,
				`SELECT coalesce(string_agg(row_to_json(s)::text, ' '), '') FROM rotation_steps s`} {
				var s string
				if err := x.pool.QueryRow(x.ctx, q).Scan(&s); err != nil {
					t.Fatal(err)
				}
				if s == "" && !strings.Contains(q, "rotation_steps") {
					t.Fatal("interception saw no rows; the test proves nothing")
				}
				dump.WriteString(s)
			}
			if c.In(dump.String()) {
				// Never print the dump: a failing leak test must not itself
				// put the value into the test output.
				t.Fatalf("canary reached the result, an incident, an error or a row (%d bytes inspected)", dump.Len())
			}
		})
	}
}

// A live run that outlasts its lease TTL keeps the lease: the heartbeat
// renews it, so a second caller of the same run is still refused.
func TestLiveRunKeepsItsLeasePastTTL(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.gate = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	e := New(x.pool, f.deps())
	id := uuid.New()
	opts := Options{RunID: id, LeaseTTL: 900 * time.Millisecond}
	first := make(chan error, 1)
	go func() { _, err := e.Rotate(x.ctx, x.ref, opts); first <- err }()
	<-f.entered
	time.Sleep(2 * opts.LeaseTTL)
	short, stop := context.WithTimeout(x.ctx, 3*time.Second)
	defer stop()
	if _, err := e.Rotate(short, x.ref, opts); !errors.Is(err, ErrConflict) {
		t.Fatalf("live run past its TTL must still conflict, got %v", err)
	}
	close(f.gate)
	if err := <-first; err != nil {
		t.Fatalf("first run: %v", err)
	}
	if f.revokes != 1 {
		t.Fatalf("revokes=%d", f.revokes)
	}
}

func stealLease(t *testing.T, x fx, id uuid.UUID) {
	t.Helper()
	if _, err := x.pool.Exec(x.ctx, `UPDATE rotation_runs SET lease_owner='thief', lease_until=now()+interval '1 hour' WHERE id=$1`, id); err != nil {
		t.Fatal("steal lease")
	}
}

// A caller whose lease was taken over stops: it does not finish the run and
// never revokes.
func TestLostLeaseStopsTheRun(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.gate = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	e := New(x.pool, f.deps())
	id := uuid.New()
	first := make(chan error, 1)
	go func() {
		_, err := e.Rotate(x.ctx, x.ref, Options{RunID: id, LeaseTTL: 600 * time.Millisecond})
		first <- err
	}()
	<-f.entered
	stealLease(t, x, id)
	select {
	case err := <-first:
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("want ErrLeaseLost, got %v", err)
		}
	case <-time.After(10 * time.Second):
		close(f.gate)
		t.Fatal("run kept going after its lease was taken")
	}
	if f.revokes != 0 {
		t.Fatalf("revokes=%d after lease loss", f.revokes)
	}
	run, err := (&store{pool: x.pool}).load(x.ctx, id)
	if err != nil || run.State == StateDone {
		t.Fatalf("run state %q err %v", run.State, err)
	}
}

// The ownership check before the revoke does not depend on the heartbeat: a
// lease taken between verification and revoke blocks the revoke.
func TestRevokeIsFencedByTheLease(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	e := New(x.pool, f.deps())
	id := uuid.New()
	e.afterState = func(s State) error {
		if s == StateRevokingOld {
			stealLease(t, x, id)
		}
		return nil
	}
	_, err := e.Rotate(x.ctx, x.ref, Options{RunID: id})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("want ErrLeaseLost, got %v", err)
	}
	if f.revokes != 0 {
		t.Fatalf("revokes=%d without the lease", f.revokes)
	}
}

// The same check guards the layout: a lease taken before the first deploy
// stops the run before any carrier is touched.
func TestDeployIsFencedByTheLease(t *testing.T) {
	x, f := newFx(t), newFakes(3)
	e := New(x.pool, f.deps())
	id := uuid.New()
	e.afterState = func(s State) error {
		if s == StateDeploying {
			stealLease(t, x, id)
		}
		return nil
	}
	_, err := e.Rotate(x.ctx, x.ref, Options{RunID: id})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("want ErrLeaseLost, got %v", err)
	}
	if len(f.deployed) != 0 || f.revokes != 0 {
		t.Fatalf("deployed=%d revokes=%d without the lease", len(f.deployed), f.revokes)
	}
}

// fencedCarrier is a collaborator that honours the fencing contract: it takes
// the epoch from the call context and applies nothing for an epoch lower than
// one it has already seen.
type fencedCarrier struct {
	*fakes
	fmu      sync.Mutex
	maxEpoch int64
	deployed []int64 // epochs whose Deploy was applied
	revoked  []int64 // epochs whose Revoke was applied
	rejected int
	noEpoch  int
	errStale error
}

func newFenced(f *fakes) *fencedCarrier {
	return &fencedCarrier{fakes: f, errStale: errors.New("stale epoch")}
}

// admit applies the fencing rule and reports whether the call may act.
func (c *fencedCarrier) admit(ctx context.Context) bool {
	c.fmu.Lock()
	defer c.fmu.Unlock()
	epoch, ok := Epoch(ctx)
	if !ok {
		c.noEpoch++
		return false
	}
	if epoch < c.maxEpoch {
		c.rejected++
		return false
	}
	c.maxEpoch = epoch
	return true
}

func (c *fencedCarrier) Deploy(ctx context.Context, ref Ref, id uuid.UUID, car Carrier, v string) error {
	if !c.admit(ctx) {
		return c.errStale
	}
	epoch, _ := Epoch(ctx)
	c.fmu.Lock()
	c.deployed = append(c.deployed, epoch)
	c.fmu.Unlock()
	return c.fakes.Deploy(ctx, ref, id, car, v)
}

func (c *fencedCarrier) Revoke(ctx context.Context, ref Ref, id uuid.UUID, old string) error {
	if !c.admit(ctx) {
		return c.errStale
	}
	epoch, _ := Epoch(ctx)
	c.fmu.Lock()
	c.revoked = append(c.revoked, epoch)
	c.fmu.Unlock()
	return c.fakes.Revoke(ctx, ref, id, old)
}

func (c *fencedCarrier) deps() Deps {
	d := c.fakes.deps()
	d.Deployer, d.Revoker = c, c
	return d
}

// takeover expires the caller's lease and lets a second engine finish the run:
// what happens when the first caller stalls between its ownership check and the
// side effect for longer than the lease.
func takeover(t *testing.T, x fx, d Deps, id uuid.UUID, kind string) func(string) {
	var once sync.Once
	return func(got string) {
		if got != kind {
			return
		}
		once.Do(func() {
			if _, err := x.pool.Exec(x.ctx, `UPDATE rotation_runs SET lease_until=now()-interval '1 hour' WHERE id=$1`, id); err != nil {
				t.Error("expire lease")
				return
			}
			if _, err := New(x.pool, d).Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1}); err != nil && !errors.Is(err, ErrFailed) {
				t.Errorf("second caller: %v", err)
			}
		})
	}
}

// A caller that passed the ownership check and then lost its lease must not
// act on the carrier: the carrier refuses its stale epoch, and its own write
// of the outcome does not overwrite the new owner's.
func TestStaleOwnerCannotDeployAfterTakeover(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	c := newFenced(f)
	id := uuid.New()
	e := New(x.pool, c.deps())
	e.afterFence = takeover(t, x, c.deps(), id, "deploy")
	_, err := e.Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale caller: want ErrLeaseLost, got %v", err)
	}
	if c.noEpoch != 0 {
		t.Fatalf("%d side effects were called without a fencing epoch", c.noEpoch)
	}
	if c.rejected == 0 {
		t.Fatal("the stale caller never reached the carrier: the window was not exercised")
	}
	for _, ep := range c.deployed {
		if ep != 2 {
			t.Fatalf("a deploy was applied with epoch %d, only the new owner (2) may act", ep)
		}
	}
	if f.revokes != 1 || len(c.revoked) != 1 || c.revoked[0] != 2 {
		t.Fatalf("revokes=%d epochs=%v", f.revokes, c.revoked)
	}
	steps, err := (&store{pool: x.pool}).steps(x.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if s.Deploy != "ok" || s.Verify != "ok" {
			t.Fatalf("the stale caller overwrote a step: %+v", s)
		}
	}
	if run, err := (&store{pool: x.pool}).load(x.ctx, id); err != nil || run.State != StateDone {
		t.Fatalf("run state %q err %v", run.State, err)
	}
}

// The same for the revoke: only the owner of the current epoch retires the
// old version.
func TestStaleOwnerCannotRevokeAfterTakeover(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	c := newFenced(f)
	id := uuid.New()
	e := New(x.pool, c.deps())
	e.afterFence = takeover(t, x, c.deps(), id, "revoke")
	_, err := e.Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale caller: want ErrLeaseLost, got %v", err)
	}
	if c.noEpoch != 0 || c.rejected != 1 {
		t.Fatalf("noEpoch=%d rejected=%d", c.noEpoch, c.rejected)
	}
	if len(c.revoked) != 1 || c.revoked[0] != 2 {
		t.Fatalf("revoke epochs %v, want exactly [2]", c.revoked)
	}
	if run, err := (&store{pool: x.pool}).load(x.ctx, id); err != nil || run.State != StateDone || run.Class != ClassNone {
		t.Fatalf("run state %q class %q err %v", run.State, run.Class, err)
	}
}

// A caller that lost its lease releases nothing: the lease it gives up is
// not the one that is held now, even under the same owner token.
func TestStaleReleaseKeepsTheNewOwnersLease(t *testing.T) {
	x := newFx(t)
	st := &store{pool: x.pool}
	id := uuid.New()
	if err := st.start(x.ctx, x.ref, id); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	e1, err := st.claim(x.ctx, id, "a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := st.claim(x.ctx, id, "a", now.Add(2*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.release(x.ctx, id, &lease{owner: "a", epoch: e1}); err != nil {
		t.Fatal(err)
	}
	if err := st.release(x.ctx, id, &lease{owner: "b", epoch: e2}); err != nil {
		t.Fatal(err)
	}
	cur := &lease{owner: "a", epoch: e2}
	if ok, err := st.holds(x.ctx, id, cur, now.Add(2*time.Minute)); err != nil || !ok {
		t.Fatalf("a stale release took the current lease away: holds=%v err=%v", ok, err)
	}
	if err := st.release(x.ctx, id, cur); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.holds(x.ctx, id, cur, now.Add(2*time.Minute)); ok {
		t.Fatal("the current owner could not release its own lease")
	}
}

// The incident is opened and recorded by the caller that holds the lease: one
// that lost it between the check and the call opens nothing.
func TestStaleOwnerCannotOpenIncidentAfterTakeover(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.deployErr[cid(1)] = errors.New("write failed")
	id := uuid.New()
	e := New(x.pool, f.deps())
	e.afterFence = takeover(t, x, f.deps(), id, "incident")
	_, err := e.Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale caller: want ErrLeaseLost, got %v", err)
	}
	if f.incidentNoEpoch != 0 {
		t.Fatalf("%d incident calls carried no fencing epoch", f.incidentNoEpoch)
	}
	if len(f.incidents) != 1 || f.incidentCalls != 1 {
		t.Fatalf("want exactly one accepted call opening one incident (the new owner's), got %d calls, %d incidents", f.incidentCalls, len(f.incidents))
	}
}

// Every takeover raises the epoch, so a caller of an older lease is always
// distinguishable from the current one.
func TestEpochGrowsWithEveryClaim(t *testing.T) {
	x := newFx(t)
	st := &store{pool: x.pool}
	id := uuid.New()
	if err := st.start(x.ctx, x.ref, id); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a, err := st.claim(x.ctx, id, "a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.claim(x.ctx, id, "b", now.Add(2*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if b <= a {
		t.Fatalf("epoch did not grow: %d then %d", a, b)
	}
}

// The fencing epoch belongs to the secret, not to the run: a carrier keeps the
// highest epoch it has accepted for the secret, so the next run of the same
// secret must claim a strictly higher one, not start again from 1.
func TestEpochIsMonotonicAcrossRunsOfOneSecret(t *testing.T) {
	x := newFx(t)
	st := &store{pool: x.pool}
	now := time.Now()
	var last int64
	for i := 0; i < 3; i++ {
		id := uuid.New()
		if err := st.start(x.ctx, x.ref, id); err != nil {
			t.Fatal(err)
		}
		// Two claims per run (the second is a takeover), then the run ends.
		a, err := st.claim(x.ctx, id, "a", now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Minute)
		b, err := st.claim(x.ctx, id, "b", now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if a <= last || b <= a {
			t.Fatalf("run %d: epochs %d,%d after %d are not strictly increasing", i, a, b, last)
		}
		last = b
		if _, err := x.pool.Exec(x.ctx, `UPDATE rotation_runs SET state='done' WHERE id=$1`, id); err != nil {
			t.Fatal("finish run")
		}
	}
	other := Ref{OrgID: x.ref.OrgID, SecretID: uuid.New()}
	oid := uuid.New()
	if err := st.start(x.ctx, other, oid); err != nil {
		t.Fatal(err)
	}
	if e, err := st.claim(x.ctx, oid, "c", now, time.Minute); err != nil || e != 1 {
		t.Fatalf("another secret starts at its own 1, got %d %v", e, err)
	}
}

// The case that was seen: a takeover raises the epoch to 2 on run 1; run 2 of
// the same secret must pass the carrier that already accepted 2.
func TestSecondRunOfTheSecretPassesAfterATakeover(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	c := newFenced(f)
	first := uuid.New()
	e := New(x.pool, c.deps())
	e.afterFence = takeover(t, x, c.deps(), first, "deploy")
	if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: first, Concurrency: 1}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("run 1: want ErrLeaseLost from the stale caller, got %v", err)
	}
	if run, err := (&store{pool: x.pool}).load(x.ctx, first); err != nil || run.State != StateDone || c.maxEpoch < 2 {
		t.Fatalf("run 1 state %q err %v maxEpoch %d: the takeover did not happen", run.State, err, c.maxEpoch)
	}
	before := c.maxEpoch
	second := uuid.New()
	res, err := New(x.pool, c.deps()).Rotate(x.ctx, x.ref, Options{RunID: second, Concurrency: 1})
	if err != nil || res.State != StateDone {
		t.Fatalf("run 2 of the same secret: %+v %v (class %q)", res, err, res.Class)
	}
	if c.maxEpoch <= before {
		t.Fatalf("run 2 claimed epoch %d, not above the %d a carrier had accepted", c.maxEpoch, before)
	}
}

// versionLedger honours the Versions contract (idempotent per run) and counts
// what it creates: a second Prepare of the same run must not add a version.
type versionLedger struct {
	mu      sync.Mutex
	made    map[uuid.UUID]Version
	created int
	calls   int
}

func (l *versionLedger) Prepare(_ context.Context, _ Ref, run uuid.UUID) (Version, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if v, ok := l.made[run]; ok {
		return v, nil
	}
	l.created++
	v := Version{Old: fmt.Sprint(l.created), New: fmt.Sprint(l.created + 1), Fingerprint: fpNew}
	l.made[run] = v
	return v, nil
}

// Two Prepare calls for one run (the first caller died before the plan was
// stored) give one version, and the run ends with it. A run that is already
// past Prepare never calls it again.
func TestRepeatedPrepareMakesOneVersion(t *testing.T) {
	x, f := newFx(t), newFakes(3)
	led := &versionLedger{made: map[uuid.UUID]Version{}}
	d := f.deps()
	d.Versions = led
	id := uuid.New()
	dying := New(x.pool, d)
	dying.afterFence = nil
	dying.afterState = func(s State) error { return nil }
	f.listErr = errors.New("carrier list unavailable")
	if _, err := dying.Rotate(x.ctx, x.ref, Options{RunID: id}); !errors.Is(err, ErrFailed) {
		// A failed List fails the run; reopen it as a run that never got past
		// Prepare, which is what a caller killed there leaves behind.
		t.Logf("first attempt: %v", err)
	}
	if _, err := x.pool.Exec(x.ctx, `UPDATE rotation_runs SET state='new_version', error_class='', incident_opened=false WHERE id=$1`, id); err != nil {
		t.Fatal("reopen run")
	}
	f.listErr = nil
	res, err := New(x.pool, d).Rotate(x.ctx, x.ref, Options{RunID: id})
	if err != nil || res.State != StateDone {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if led.calls != 2 || led.created != 1 {
		t.Fatalf("Prepare called %d times, %d versions made: want 2 calls and one version", led.calls, led.created)
	}
	if res.NewVersion != "2" || res.OldVersion != "1" {
		t.Fatalf("the run ended with %s->%s, not the one version made", res.OldVersion, res.NewVersion)
	}
	// Finished run: a replay must not call Prepare, nor make a version.
	if _, err := New(x.pool, d).Rotate(x.ctx, x.ref, Options{RunID: id}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if led.calls != 2 || led.created != 1 {
		t.Fatalf("replay of a finished run called Prepare: calls=%d created=%d", led.calls, led.created)
	}
}

// A run killed after Prepare was stored resumes without Prepare.
func TestResumePastPrepareDoesNotPrepareAgain(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	led := &versionLedger{made: map[uuid.UUID]Version{}}
	d := f.deps()
	d.Versions = led
	id := uuid.New()
	dying := New(x.pool, d)
	dying.afterState = func(s State) error {
		if s == StateDeploying {
			return errors.New("killed")
		}
		return nil
	}
	if _, err := dying.Rotate(x.ctx, x.ref, Options{RunID: id}); err == nil {
		t.Fatal("expected the simulated kill")
	}
	res, err := New(x.pool, d).Rotate(x.ctx, x.ref, Options{RunID: id})
	if err != nil || res.State != StateDone {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if led.calls != 1 || led.created != 1 {
		t.Fatalf("resume past Prepare: calls=%d created=%d, want 1 and 1", led.calls, led.created)
	}
}

// Every write of a run is fenced by owner and epoch: a caller of a lease that
// has been taken over, even by the same owner token claiming again, changes
// nothing, and the current owner still can.
func TestStaleLeaseWritesNothing(t *testing.T) {
	x := newFx(t)
	st := &store{pool: x.pool}
	id := uuid.New()
	if err := st.start(x.ctx, x.ref, id); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	e1, err := st.claim(x.ctx, id, "a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	stale := withLease(x.ctx, &lease{owner: "a", epoch: e1})
	e2, err := st.claim(x.ctx, id, "a", now.Add(2*time.Minute), time.Minute) // same owner token, a later claim
	if err != nil || e2 == e1 {
		t.Fatalf("second claim: epoch %d then %d, err %v", e1, e2, err)
	}
	current := withLease(x.ctx, &lease{owner: "a", epoch: e2})
	other := withLease(x.ctx, &lease{owner: "b", epoch: e2})
	v := Version{Old: "1", New: "2", Fingerprint: fpNew}
	carrier := []string{cid(1)}
	for name, ctx := range map[string]context.Context{"older epoch": stale, "other owner": other} {
		if err := st.begin(ctx, id, v, carrier); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("%s: begin: want ErrLeaseLost, got %v", name, err)
		}
	}
	if err := st.begin(current, id, v, carrier); err != nil {
		t.Fatalf("current owner: begin: %v", err)
	}
	for name, ctx := range map[string]context.Context{"older epoch": stale, "other owner": other, "no lease": x.ctx} {
		if err := st.setDeploy(ctx, id, cid(1), "ok", ClassNone); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("%s: setDeploy: want ErrLeaseLost, got %v", name, err)
		}
		if err := st.setVerify(ctx, id, cid(1), "ok", fpNew, ClassNone); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("%s: setVerify: want ErrLeaseLost, got %v", name, err)
		}
		if err := st.setState(ctx, id, StateDeploying, StateFailed, ClassDeployFailed); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("%s: setState: want ErrLeaseLost, got %v", name, err)
		}
	}
	steps, err := st.steps(x.ctx, id)
	if err != nil || len(steps) != 1 || steps[0].Deploy != "pending" || steps[0].Verify != "pending" {
		t.Fatalf("a stale caller changed a step: %+v %v", steps, err)
	}
	if run, err := st.load(x.ctx, id); err != nil || run.State != StateDeploying {
		t.Fatalf("a stale caller changed the run: %q %v", run.State, err)
	}
	if err := st.setDeploy(current, id, cid(1), "ok", ClassNone); err != nil {
		t.Fatalf("current owner: setDeploy: %v", err)
	}
	if err := st.setVerify(current, id, cid(1), "ok", fpNew, ClassNone); err != nil {
		t.Fatalf("current owner: setVerify: %v", err)
	}
	if err := st.setState(current, id, StateDeploying, StateVerifying, ClassNone); err != nil {
		t.Fatalf("current owner: setState: %v", err)
	}
}

// A side effect runs under a context that is cancelled when the lease runs
// out: the call of a caller that lost its lease is cut, not left to finish.
func TestSideEffectsEndWithTheLease(t *testing.T) {
	for _, kind := range []string{"deploy", "revoke"} {
		t.Run(kind, func(t *testing.T) {
			x, f := newFx(t), newFakes(1)
			cut := make(chan error, 1)
			hold := func(ctx context.Context) error {
				l := leaseOf(ctx)
				if l == nil {
					return errors.New("no lease in the call context")
				}
				l.until.Store(time.Now().Add(-time.Second).UnixNano()) // the lease runs out under this call
				select {
				case <-ctx.Done():
					cut <- context.Cause(ctx)
				case <-time.After(5 * time.Second):
					cut <- nil
				}
				return ctx.Err()
			}
			d := f.deps()
			d.Deployer = deployFunc(func(ctx context.Context) error {
				if kind == "deploy" {
					return hold(ctx)
				}
				return nil
			})
			d.Revoker = revokeFunc(func(ctx context.Context) error {
				if kind == "revoke" {
					return hold(ctx)
				}
				return nil
			})
			id := uuid.New()
			_, err := New(x.pool, d).Rotate(x.ctx, x.ref, Options{RunID: id, LeaseTTL: time.Minute, Concurrency: 1})
			if !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("a call cut by the end of the lease: want ErrLeaseLost, got %v", err)
			}
			if n := len(f.incidents); n != 0 {
				t.Fatalf("a call cut by the end of the lease opened %d incidents", n)
			}
			if run, err := (&store{pool: x.pool}).load(x.ctx, id); err == nil && (run.State == StateFailed || run.Class != ClassNone) {
				t.Fatalf("a call cut by the end of the lease was recorded as a failure (%s, %s)", run.State, run.Class)
			}
			if cause := <-cut; !errors.Is(cause, ErrLeaseLost) {
				t.Fatalf("the %s call was not cut when the lease ran out: %v", kind, cause)
			}
		})
	}
}

type deployFunc func(ctx context.Context) error

func (f deployFunc) Deploy(ctx context.Context, _ Ref, _ uuid.UUID, _ Carrier, _ string) error {
	return f(ctx)
}

type revokeFunc func(ctx context.Context) error

func (f revokeFunc) Revoke(ctx context.Context, _ Ref, _ uuid.UUID, _ string) error {
	return f(ctx)
}

// A leak test that fails must not print what it inspected: the output of a
// red run is read by people and by tools.
func TestLeakTestsDoNotPrintWhatTheyInspect(t *testing.T) {
	for _, file := range []string{"rotation_test.go", "../../test/security/w3_rotation_attack_test.go"} {
		raw, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "dump.String()") && !strings.Contains(line, "c.In(dump.String())") && !strings.Contains(line, "TestLeakTestsDoNotPrint") {
				t.Fatalf("%s:%d prints the inspected text", file, i+1)
			}
		}
	}
}

// carrier ids and versions are public identifiers, never carriers of a value:
// a secret-shaped string in any of the three fields fails the run and is
// stored and returned nowhere.
func TestIdentifiersAcceptNoSecretShapedString(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	forms := map[string]string{
		"raw":       v,
		"hex":       hex.EncodeToString([]byte(v)),
		"base32":    strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(v)), "="),
		"base64":    strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(v)), "="),
		"base64url": base64.RawURLEncoding.EncodeToString([]byte(v)),
		"urlquery":  url.QueryEscape("a b" + v),
		"reversed":  reverseString(v),
		"digits":    "123456789012345678901234567890123",
	}
	for name, form := range forms {
		if len(form) < 32 {
			t.Fatalf("%s: canary form shorter than 32 chars", name)
		}
		for field, setup := range map[string]func(*fakes) Deps{
			"carrier_id": func(f *fakes) Deps { f.carriers = []Carrier{{ID: cid(1)}, {ID: form}}; return f.deps() },
			"version_new": func(f *fakes) Deps {
				d := f.deps()
				d.Versions = versionStub{Version{Old: "1", New: form, Fingerprint: fpNew}}
				return d
			},
			"version_old": func(f *fakes) Deps {
				d := f.deps()
				d.Versions = versionStub{Version{Old: form, New: "2", Fingerprint: fpNew}}
				return d
			},
		} {
			t.Run(name+"/"+field, func(t *testing.T) {
				x, f := newFx(t), newFakes(2)
				deps := setup(f)
				res, err := New(x.pool, deps).Rotate(x.ctx, x.ref, Options{})
				if !errors.Is(err, ErrFailed) || res.Class != ClassPrepareFailed || len(f.deployed) != 0 || f.revokes != 0 {
					t.Fatalf("%s %s accepted: state=%s class=%s err=%v", field, name, res.State, res.Class, errors.Is(err, ErrFailed))
				}
				var dump strings.Builder
				fmt.Fprintf(&dump, "%+v %#v %v %+v", res, res, err, f.incidents)
				for _, q := range []string{`SELECT coalesce(string_agg(row_to_json(r)::text, ' '), '') FROM rotation_runs r`,
					`SELECT coalesce(string_agg(row_to_json(s)::text, ' '), '') FROM rotation_steps s`} {
					var s string
					if err := x.pool.QueryRow(x.ctx, q).Scan(&s); err != nil {
						t.Fatal(err)
					}
					if s == "" && strings.Contains(q, "rotation_runs") {
						t.Fatal("interception saw no rows; the test proves nothing")
					}
					dump.WriteString(s)
				}
				if strings.Contains(dump.String(), form) || canary.Of(form).In(dump.String()) || c.In(dump.String()) {
					t.Fatalf("%s %s reached the result, an incident, an error or a row", field, name)
				}
			})
		}
	}
}

// Positive control: a canonical UUID and plain integer versions pass, so the
// test above rejects on the grammar and not on something unrelated.
func TestIdentifiersCanonicalFormsPass(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	d := f.deps()
	d.Versions = versionStub{Version{Old: "999999999", New: "1", Fingerprint: fpNew}}
	res, err := New(x.pool, d).Rotate(x.ctx, x.ref, Options{})
	if err != nil || res.State != StateDone {
		t.Fatalf("canonical identifiers refused: %+v %v", res, err)
	}
}

func TestIdentifierGrammar(t *testing.T) {
	for _, s := range []string{cid(1), "123e4567-e89b-42d3-a456-426614174000"} {
		if !validCarrierID(s) {
			t.Fatalf("%q refused", s)
		}
	}
	for _, s := range []string{"", "c1", "123E4567-E89B-42D3-A456-426614174000", " " + cid(1), cid(1) + "\n", "{" + cid(1) + "}", "urn:uuid:" + cid(1), strings.ReplaceAll(cid(1), "-", "")} {
		if validCarrierID(s) {
			t.Fatalf("%q accepted", s)
		}
	}
	for _, s := range []string{"1", "2", "999999999", "10"} {
		if !validVersion(s) {
			t.Fatalf("%q refused", s)
		}
	}
	for _, s := range []string{"", "0", "01", "-1", "+1", "1.0", "v1", "1000000000", " 1", "1\n", "\u0661"} {
		if validVersion(s) {
			t.Fatalf("%q accepted", s)
		}
	}
}

type versionStub struct{ v Version }

func (s versionStub) Prepare(context.Context, Ref, uuid.UUID) (Version, error) { return s.v, nil }

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// A clean run has no incident to resolve; a failed run keeps its incident open.
func TestResolveOnlyWhenIncidentWasOpened(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	if _, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{}); err != nil || f.resolveCalls != 0 {
		t.Fatalf("clean run: %v resolves=%d", err, f.resolveCalls)
	}
	x2, f2 := newFx(t), newFakes(2)
	f2.deployErr[cid(1)] = errors.New("refused")
	if _, err := New(x2.pool, f2.deps()).Rotate(x2.ctx, x2.ref, Options{}); !errors.Is(err, ErrFailed) || f2.resolveCalls != 0 || len(f2.incidents) != 1 {
		t.Fatalf("failed run: %v resolves=%d incidents=%d", err, f2.resolveCalls, len(f2.incidents))
	}
}

// If the incident cannot be resolved the run is not done: the old key is gone
// but the alert still says it is alive, so the same run id retries.
func TestResolveFailureKeepsRunRevoking(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.revokeErr = errors.New("revoke refused")
	id := uuid.New()
	e := New(x.pool, f.deps())
	if _, err := e.Rotate(x.ctx, x.ref, Options{RunID: id}); !errors.Is(err, ErrRevokePending) {
		t.Fatal(err)
	}
	f.revokeErr, f.resolveErr = nil, errors.New("journal down with secret-ish text")
	res, err := e.Rotate(x.ctx, x.ref, Options{RunID: id})
	if !errors.Is(err, ErrIncident) || strings.Contains(err.Error(), "journal") || res.State == StateDone {
		t.Fatalf("got %+v %v", res, err)
	}
	f.resolveErr = nil
	if res, err = e.Rotate(x.ctx, x.ref, Options{RunID: id}); err != nil || res.State != StateDone || len(f.resolved) != 1 {
		t.Fatalf("retry: %+v %v resolved=%d", res, err, len(f.resolved))
	}
	if f.incidentNoEpoch != 0 {
		t.Fatalf("%d incident calls carried no fencing epoch", f.incidentNoEpoch)
	}
}

// A caller that lost its lease between the fence and Resolve is refused by the
// stale epoch and reports ErrLeaseLost; the new owner's resolve is the only one accepted.
func TestStaleOwnerCannotResolveIncidentAfterTakeover(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	f.revokeErr = errors.New("revoke refused")
	id := uuid.New()
	if _, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{RunID: id}); !errors.Is(err, ErrRevokePending) {
		t.Fatal(err)
	}
	f.revokeErr = nil
	e := New(x.pool, f.deps())
	e.afterFence = takeover(t, x, f.deps(), id, "resolve")
	_, err := e.Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale caller: want ErrLeaseLost, got %v", err)
	}
	if f.incidentNoEpoch != 0 || len(f.resolved) != 1 || f.resolveCalls != 2 {
		t.Fatalf("no-epoch=%d resolved=%d calls=%d (want 0, 1, 2: new owner accepted, stale refused)", f.incidentNoEpoch, len(f.resolved), f.resolveCalls)
	}
}
