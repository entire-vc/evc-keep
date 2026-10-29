package app

import (
	"context"
	"errors"
	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	"github.com/google/uuid"
)

// recCards is the Mesh side: it records every card made and every cancel.
type recCards struct {
	mu        sync.Mutex
	specs     []gatecard.Spec
	cancelled []string
	createErr error
	cancelErr error // returned for the first failFor cancels
	failFor   int
	calls     int // every Cancel call, failed or not
}

func (c *recCards) Create(_ context.Context, s gatecard.Spec) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.createErr != nil {
		return "", c.createErr
	}
	c.specs = append(c.specs, s)
	return uuid.NewString(), nil
}

func (c *recCards) Cancel(_ context.Context, id, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.failFor > 0 {
		c.failFor--
		return c.cancelErr
	}
	c.cancelled = append(c.cancelled, id)
	return nil
}

func (c *recCards) snapshot() (specs, cancelled int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.specs), len(c.cancelled)
}

func gateConfig(enabled bool) config.Config {
	return config.Config{MeshExtension: true, MeshGate: config.MeshGate{Enabled: enabled, ProjectID: uuid.NewString(), URL: "https://mesh.example.test",
		CancelStatusID: uuid.NewString(), TokenFile: "/nonexistent/token", SweepEvery: time.Minute}}
}

func cardsOpt(c gatecard.Cards, calls *int) Options {
	return Options{Cards: func(config.MeshGate, GateTokenSource, *slog.Logger) (gatecard.Cards, error) {
		*calls++
		return c, nil
	}}
}

// Without the gate configuration Keep starts without Mesh: no tracker is built,
// Open and Sweep refuse, and nothing is wired into the approvals.
func TestMeshGateOffKeepsTheCoreWithoutMesh(t *testing.T) {
	pool := testPool(t)
	var calls int
	dep := deployment.NewRepo(pool, audit.NewJournal(pool))
	gates, err := wireMeshGate(context.Background(), gateConfig(false), cardsOpt(&recCards{}, &calls), pool, nil, dep, nil, obs.New(&syncBuf{}))
	if err != nil || gates == nil {
		t.Fatalf("wire = %v, %v", gates, err)
	}
	if calls != 0 {
		t.Fatal("a tracker was built without the gate configuration")
	}
	if _, err := gates.Open(context.Background(), meshgate.OpenInput{Org: uuid.New(), Workspace: uuid.New(), Approval: uuid.New()}); !errors.Is(err, meshgate.ErrUnavailable) {
		t.Fatalf("Open = %v, want ErrUnavailable", err)
	}
	if _, err := gates.Sweep(context.Background()); !errors.Is(err, meshgate.ErrUnavailable) {
		t.Fatalf("Sweep = %v, want ErrUnavailable", err)
	}
	// And with the extension routes off there is no service at all.
	cfg := gateConfig(false)
	cfg.MeshExtension = false
	if g, err := wireMeshGate(context.Background(), cfg, Options{}, pool, nil, dep, nil, nil); g != nil || err != nil {
		t.Fatalf("extension off: %v, %v", g, err)
	}
}

// A gate configuration the build cannot serve stops the start; the text the
// plugin returns is not printed.
func TestMeshGateConfiguredWithoutPluginOrWithRefusalStopsStart(t *testing.T) {
	pool := testPool(t)
	dep := deployment.NewRepo(pool, audit.NewJournal(pool))
	c := canary.New()
	refusing := Options{Cards: func(config.MeshGate, GateTokenSource, *slog.Logger) (gatecard.Cards, error) {
		return nil, errors.New("bad " + c.Value(1))
	}}
	for name, opts := range map[string]Options{"no plugin": {}, "plugin refuses": refusing, "plugin returns nothing": {Cards: func(config.MeshGate, GateTokenSource, *slog.Logger) (gatecard.Cards, error) { return nil, nil }}} {
		gates, err := wireMeshGate(context.Background(), gateConfig(true), opts, pool, nil, dep, nil, nil)
		if err == nil || gates != nil {
			t.Fatalf("%s: started (%v, %v)", name, gates, err)
		}
		if c.In(err.Error()) {
			t.Fatalf("%s: the plugin's text was printed: %v", name, err)
		}
	}
}

// gatedRotation starts a prod rotation of the fixture's secret with the Mesh
// gate wired, and returns the approval whose card was made.
func gatedRotation(t *testing.T, r *rotFixture, cards gatecard.Cards) (uuid.UUID, *meshgate.Service) {
	t.Helper()
	pool := r.f.pool
	if _, err := pool.Exec(context.Background(), `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by) VALUES($1,$2,'https://mesh.example.invalid',$3)`, uuid.New(), r.org, uuid.New()); err != nil {
		t.Fatal(err)
	}
	dep := deployment.NewRepo(pool, audit.NewJournal(pool))
	gates := meshgate.New(meshgate.NewPG(pool), deployment.GateApprovals{Src: dep}, cards, nil)
	r.svc.(*rotation.Service).WithConfirmer(deployment.GateConfirmer{Svc: gates})
	origin := rotation.Origin{Actor: audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}, Scope: "org:" + r.org.String(), Name: "rot-secret", Class: rotation.ClassProd}
	st, err := r.svc.(*rotation.Service).Start(context.Background(), rotation.Ref{OrgID: r.org, SecretID: r.secretID}, origin)
	if err != nil || st.Approval == nil {
		t.Fatalf("Start = %+v, %v", st, err)
	}
	return st.Approval.ID, gates
}

func lapse(t *testing.T, r *rotFixture) {
	t.Helper()
	if _, err := r.f.pool.Exec(context.Background(), `UPDATE mesh_gate_requests SET expires_at = now() - interval '1 minute' WHERE org_id=$1`, r.org); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// With the gate configured, the timer (not a call from the test) cancels the
// card of a lapsed request and records it.
func TestMeshGateSweepTimerCancelsTheCardOfALapsedRequest(t *testing.T) {
	r := newRotFixture(t, 1)
	cards := &recCards{}
	gatedRotation(t, r, cards)
	var calls int
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := cardsOpt(cards, &calls)
	opts.SweepEvery = 20 * time.Millisecond
	if _, err := wireMeshGate(ctx, gateConfig(true), opts, r.f.pool, nil, deployment.NewRepo(r.f.pool, audit.NewJournal(r.f.pool)), nil, obs.New(&syncBuf{})); err != nil {
		t.Fatal(err)
	}
	if _, c := cards.snapshot(); c != 0 {
		t.Fatal("a card was cancelled before its request lapsed")
	}
	lapse(t, r)
	waitFor(t, "the timer cancels the lapsed card", func() bool { _, c := cards.snapshot(); return c == 1 })
	waitFor(t, "the cancel is recorded", func() bool {
		var done bool
		return r.f.pool.QueryRow(context.Background(), `SELECT card_cancelled FROM mesh_gate_requests WHERE org_id=$1`, r.org).Scan(&done) == nil && done
	})
}

// Mesh failing does not stop the timer, and the timer stops with its context.
func TestMeshGateSweepTimerSurvivesMeshErrorsAndStopsWithContext(t *testing.T) {
	r := newRotFixture(t, 1)
	cards := &recCards{}
	gatedRotation(t, r, cards)
	cards.mu.Lock()
	cards.cancelErr, cards.failFor = gatecard.ErrUnavailable, 1<<30
	cards.mu.Unlock()
	var calls int
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := cardsOpt(cards, &calls)
	opts.SweepEvery = 20 * time.Millisecond
	var logs syncBuf
	if _, err := wireMeshGate(ctx, gateConfig(true), opts, r.f.pool, nil, deployment.NewRepo(r.f.pool, audit.NewJournal(r.f.pool)), nil, obs.New(&logs)); err != nil {
		t.Fatal(err)
	}
	lapse(t, r)
	attempts := func() int { cards.mu.Lock(); defer cards.mu.Unlock(); return cards.calls }
	waitFor(t, "three failed attempts: the timer keeps trying", func() bool { return attempts() >= 3 })
	cancel()
	time.Sleep(150 * time.Millisecond) // an attempt in flight finishes
	settled := attempts()
	time.Sleep(300 * time.Millisecond)
	if attempts() != settled {
		t.Fatal("the timer kept sweeping after its context ended")
	}
	if !strings.Contains(string(logs.Bytes()), "mesh gate card not cancelled") {
		t.Fatal("a Mesh failure left no trace in the log")
	}
}

// A request for a prod rotation gets a card before it commits; a card that
// cannot be made fails the start and leaves no approval.
func TestRotationApprovalAsksMeshInTheSameTransaction(t *testing.T) {
	r := newRotFixture(t, 1)
	pool := r.f.pool
	cards := &recCards{createErr: errors.New("mesh down")}
	svc := r.svc.(*rotation.Service)
	if _, err := pool.Exec(context.Background(), `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by) VALUES($1,$2,'https://mesh.example.invalid',$3)`, uuid.New(), r.org, uuid.New()); err != nil {
		t.Fatal(err)
	}
	dep := deployment.NewRepo(pool, audit.NewJournal(pool))
	svc.WithConfirmer(deployment.GateConfirmer{Svc: meshgate.New(meshgate.NewPG(pool), deployment.GateApprovals{Src: dep}, cards, nil)})
	origin := rotation.Origin{Actor: audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}, Scope: "org:" + r.org.String(), Name: "rot-secret", Class: rotation.ClassProd}
	ref := rotation.Ref{OrgID: r.org, SecretID: r.secretID}
	count := func(q string) (n int) {
		if err := pool.QueryRow(context.Background(), q, r.org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	journal := count(`SELECT count(*) FROM audit_records WHERE org_id=$1::text`)
	if _, err := svc.Start(context.Background(), ref, origin); !errors.Is(err, rotation.ErrUnavailable) {
		t.Fatalf("Start with Mesh down = %v, want ErrUnavailable", err)
	}
	if n := count(`SELECT count(*) FROM approval_requests WHERE org_id=$1`); n != 0 {
		t.Fatalf("approval rows after a refused card = %d", n)
	}
	if n := count(`SELECT count(*) FROM audit_records WHERE org_id=$1::text`); n != journal {
		t.Fatalf("journal grew by %d after a refused card", n-journal)
	}

	cards.createErr = nil
	st, err := svc.Start(context.Background(), ref, origin)
	if err != nil || st.Approval == nil {
		t.Fatalf("Start = %+v, %v", st, err)
	}
	specs, _ := cards.snapshot()
	if specs != 1 || !strings.Contains(cards.specs[0].Title, "rotate") || !strings.Contains(cards.specs[0].Title, "rot-secret") || cards.specs[0].ExternalRef != "keep:approval/"+st.Approval.ID.String() {
		t.Fatalf("card = %+v", cards.specs)
	}
	if n := count(`SELECT count(*) FROM mesh_gate_requests WHERE org_id=$1`); n != 1 {
		t.Fatalf("gate rows = %d, want 1", n)
	}
	var bound string
	var expires time.Time
	if err := pool.QueryRow(context.Background(), `SELECT encode(binding_hash,'hex'), expires_at FROM approval_requests WHERE id=$1`, st.Approval.ID).Scan(&bound, &expires); err != nil {
		t.Fatalf("read the approval: %v", err)
	}
	if sp := cards.specs[0]; bound == "" || sp.RequestHash != bound || !sp.Deadline.Equal(expires) {
		t.Fatalf("the card is not bound to the approval's own hash and expiry: %+v", sp)
	}
}

// wireMeshGate itself puts the card step into both approval paths: the
// deployments repo and the rotation service the server really runs.
func TestMeshGateWiringReachesDeploymentsAndRotations(t *testing.T) {
	r := newRotFixture(t, 1)
	pool := r.f.pool
	if _, err := pool.Exec(context.Background(), `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by) VALUES($1,$2,'https://mesh.example.invalid',$3)`, uuid.New(), r.org, uuid.New()); err != nil {
		t.Fatal(err)
	}
	dep := deployment.NewRepo(pool, audit.NewJournal(pool))
	if dep.Confirms() {
		t.Fatal("a fresh deployments repo already asks Mesh")
	}
	cards := &recCards{}
	var calls int
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := cardsOpt(cards, &calls)
	opts.SweepEvery = time.Hour
	if _, err := wireMeshGate(ctx, gateConfig(true), opts, pool, nil, dep, r.svc, obs.New(&syncBuf{})); err != nil {
		t.Fatal(err)
	}
	if !dep.Confirms() {
		t.Fatal("deployment approvals are not wired to ask Mesh")
	}
	origin := rotation.Origin{Actor: audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}, Scope: "org:" + r.org.String(), Name: "rot-secret", Class: rotation.ClassProd}
	st, err := r.svc.(*rotation.Service).Start(ctx, rotation.Ref{OrgID: r.org, SecretID: r.secretID}, origin)
	if err != nil || st.Approval == nil {
		t.Fatalf("Start = %+v, %v", st, err)
	}
	if specs, _ := cards.snapshot(); specs != 1 {
		t.Fatalf("cards after one rotation approval = %d, want 1", specs)
	}
}

// fakeSweeper counts sweeps and fails them when told to; it ignores ctx, as a
// slow Mesh call would, so only the loop itself can stop the timer.
type fakeSweeper struct {
	mu   sync.Mutex
	n    int
	fail bool
}

func (f *fakeSweeper) Sweep(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.fail {
		return 0, gatecard.ErrUnavailable
	}
	return 0, nil
}

func (f *fakeSweeper) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.n }

func TestMeshGateSweepLoopKeepsGoingOnErrorsAndStopsWithContext(t *testing.T) {
	fs := &fakeSweeper{fail: true}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runMeshSweep(ctx, fs, 10*time.Millisecond, obs.New(&syncBuf{})); close(done) }()
	waitFor(t, "three failed sweeps: the loop keeps trying", func() bool { return fs.count() >= 3 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep loop did not stop with its context")
	}
	settled := fs.count()
	time.Sleep(100 * time.Millisecond)
	if fs.count() != settled {
		t.Fatal("the loop swept after it returned")
	}
}

type confirmFunc func(context.Context, pgx.Tx, deployment.Confirmation) (func(context.Context), error)

func (c confirmFunc) Confirm(ctx context.Context, tx pgx.Tx, in deployment.Confirmation) (func(context.Context), error) {
	return c(ctx, tx, in)
}

// A rotation approval whose commit fails after the card exists takes the card
// back and leaves no rows.
func TestRotationApprovalUndoesTheCardWhenTheCommitFails(t *testing.T) {
	r := newRotFixture(t, 1)
	pool := r.f.pool
	if _, err := pool.Exec(context.Background(), `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by) VALUES($1,$2,'https://mesh.example.invalid',$3)`, uuid.New(), r.org, uuid.New()); err != nil {
		t.Fatal(err)
	}
	cards := &recCards{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dep := deployment.NewRepo(pool, audit.NewJournal(pool))
	inner := deployment.GateConfirmer{Svc: meshgate.New(meshgate.NewPG(pool), deployment.GateApprovals{Src: dep}, cards, nil)}
	r.svc.(*rotation.Service).WithConfirmer(confirmFunc(func(c context.Context, tx pgx.Tx, in deployment.Confirmation) (func(context.Context), error) {
		undo, err := inner.Confirm(c, tx, in)
		cancel() // the commit that follows cannot succeed
		return undo, err
	}))
	origin := rotation.Origin{Actor: audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}, Scope: "org:" + r.org.String(), Name: "rot-secret", Class: rotation.ClassProd}
	if _, err := r.svc.(*rotation.Service).Start(ctx, rotation.Ref{OrgID: r.org, SecretID: r.secretID}, origin); !errors.Is(err, rotation.ErrUnavailable) {
		t.Fatalf("Start = %v, want ErrUnavailable", err)
	}
	if specs, cancelled := cards.snapshot(); specs != 1 || cancelled != 1 {
		t.Fatalf("created %d, cancelled %d; want the card taken back", specs, cancelled)
	}
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM approval_requests WHERE org_id=$1`, r.org).Scan(&n); err != nil || n != 0 {
		t.Fatalf("approval rows after a failed commit = %d, %v", n, err)
	}
}

type foreignRotation struct{ api.RotationService }

// A rotation service of another type cannot be given a card step: the start
// must stop rather than leave prod rotations without a card.
func TestMeshGateRefusesARotationServiceItCannotWire(t *testing.T) {
	pool := testPool(t)
	var calls int
	_, err := wireMeshGate(context.Background(), gateConfig(true), cardsOpt(&recCards{}, &calls), pool, nil,
		deployment.NewRepo(pool, audit.NewJournal(pool)), foreignRotation{}, obs.New(&syncBuf{}))
	if err == nil {
		t.Fatal("started with a rotation service that cannot ask Mesh")
	}
}

// The first sweep runs at once, not after a whole interval.
func TestMeshGateSweepRunsAtOnce(t *testing.T) {
	fs := &fakeSweeper{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runMeshSweep(ctx, fs, time.Hour, obs.New(&syncBuf{}))
	waitFor(t, "the first sweep", func() bool { return fs.count() >= 1 })
}

type leakySweeper struct{ err error }

func (l leakySweeper) Sweep(context.Context) (int, error) { return 0, l.err }

// A Mesh error carrying text never reaches the log: only the class does.
func TestMeshGateSweepLogsOnlyTheClass(t *testing.T) {
	c := canary.New()
	var logs syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runMeshSweep(ctx, leakySweeper{errors.New("mesh said " + c.Value(2))}, 5*time.Millisecond, obs.New(&logs))
		close(done)
	}()
	waitFor(t, "a failed sweep is logged", func() bool { return strings.Contains(string(logs.Bytes()), "mesh gate sweep failed") })
	cancel()
	<-done
	if c.In(string(logs.Bytes())) {
		t.Fatal("the error text of a failed sweep reached the log")
	}
}

// The role check the gate is wired with is the console's: approve in the
// secret's exact scope, which only an admin of that scope holds.
func TestMeshGateApproversAreTheConsoleRole(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tr := tenancy.New(pool)
	org, err := tr.CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	user := func(role string) uuid.UUID {
		t.Helper()
		u, err := tr.CreateUser(ctx, org.ID, uuid.NewString()+"@example.test")
		if err != nil {
			t.Fatalf("user: %v", err)
		}
		if role != "" {
			if _, err := tr.CreateMembership(ctx, org.ID, u.ID, tenancy.Org(org.ID), role); err != nil {
				t.Fatalf("membership: %v", err)
			}
		}
		return u.ID
	}
	g := gateApprovers{ir: identity.NewRepo(pool)}
	for _, c := range []struct {
		role string
		want bool
	}{{"", false}, {"viewer", false}, {"member", false}, {"admin", true}} {
		got, err := g.CanApprove(ctx, org.ID, user(c.role), tenancy.Org(org.ID))
		if err != nil || got != c.want {
			t.Fatalf("role %q: CanApprove = %v, %v; want %v", c.role, got, err, c.want)
		}
	}
	admin := user("admin")
	if got, err := g.CanApprove(ctx, org.ID, admin, tenancy.Scope{Level: tenancy.LevelWorkspace, ID: uuid.New()}); err != nil || got {
		t.Fatalf("org admin in an unrelated workspace scope: %v, %v", got, err)
	}
	if got, err := g.CanApprove(ctx, uuid.New(), admin, tenancy.Org(org.ID)); err != nil || got {
		t.Fatalf("admin through another organization: %v, %v", got, err)
	}
}
