package security

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cid is the canonical carrier id the tests use for carrier number n.
func cid(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// rotWorld is a rotation engine over the real database with scripted
// collaborators. Fingerprints come from the real keyed function; no value is
// ever handed to the engine.
type rotWorld struct {
	t            *testing.T
	db           *pgxpool.Pool
	ref          rotation.Ref
	oldFP, newFP string

	mu        sync.Mutex
	n         int
	deployErr map[string]error
	verifyErr map[string]error
	verifyFP  map[string]string
	unhealthy map[string]bool
	revokeErr error
	listErr   error
	incErr    error
	listOrg   uuid.UUID // carriers exist for this org only
	events    []string
	prepares  int
	revokes   int
	incidents []rotation.IncidentRecord
	gate      chan struct{}
	entered   chan struct{}
	killAt    int
	killCtx   context.CancelFunc
	deploys   int32
}

func newRotWorld(t *testing.T, n int) *rotWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	_ = ctx
	db := attackDB(t)
	org := uuid.New()
	exec(t, db, `INSERT INTO organizations(id,name) VALUES($1,'rotation-attack')`, org)
	key := mustKey(t, "rotationattack")
	t.Cleanup(key.Wipe)
	return &rotWorld{t: t, db: db, ref: rotation.Ref{OrgID: org, SecretID: uuid.New()}, n: n, listOrg: org,
		oldFP: carrierFP(t, key, "synthetic old rotation value"), newFP: carrierFP(t, key, "synthetic new rotation value"),
		deployErr: map[string]error{}, verifyErr: map[string]error{}, verifyFP: map[string]string{}, unhealthy: map[string]bool{}}
}

func (w *rotWorld) log(s string) {
	w.mu.Lock()
	w.events = append(w.events, s)
	w.mu.Unlock()
}

func (w *rotWorld) Prepare(context.Context, rotation.Ref, uuid.UUID) (rotation.Version, error) {
	w.mu.Lock()
	w.prepares++
	w.mu.Unlock()
	return rotation.Version{Old: "1", New: "2", Fingerprint: w.newFP}, nil
}

func (w *rotWorld) List(_ context.Context, ref rotation.Ref) ([]rotation.Carrier, error) {
	if w.listErr != nil {
		return nil, w.listErr
	}
	if ref.OrgID != w.listOrg {
		return nil, nil
	}
	var out []rotation.Carrier
	for i := 1; i <= w.n; i++ {
		out = append(out, rotation.Carrier{ID: cid(i)})
	}
	return out, nil
}

func (w *rotWorld) Deploy(ctx context.Context, _ rotation.Ref, _ uuid.UUID, c rotation.Carrier, _ string) error {
	if w.entered != nil {
		select {
		case w.entered <- struct{}{}:
		default:
		}
	}
	if w.gate != nil {
		select {
		case <-w.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if w.killAt > 0 && int(atomic.AddInt32(&w.deploys, 1)) == w.killAt {
		w.killCtx()
		return context.Canceled
	}
	w.log("deploy " + c.ID)
	return w.deployErr[c.ID]
}

func (w *rotWorld) Verify(_ context.Context, _ rotation.Ref, c rotation.Carrier, _ string) (rotation.Report, error) {
	w.log("verify " + c.ID)
	if err := w.verifyErr[c.ID]; err != nil {
		return rotation.Report{}, err
	}
	fp := w.newFP
	if v, ok := w.verifyFP[c.ID]; ok {
		fp = v
	}
	return rotation.Report{Fingerprint: fp, Healthy: !w.unhealthy[c.ID]}, nil
}

func (w *rotWorld) Revoke(context.Context, rotation.Ref, uuid.UUID, string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.revokes++
	return w.revokeErr
}

func (w *rotWorld) Open(_ context.Context, r rotation.IncidentRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.incErr != nil {
		return w.incErr
	}
	w.incidents = append(w.incidents, r)
	return nil
}

func (w *rotWorld) Resolve(context.Context, rotation.IncidentRecord) error { return nil }

func (w *rotWorld) engine() *rotation.Engine {
	return rotation.New(w.db, rotation.Deps{Versions: w, Carriers: w, Deployer: w, Verifier: w, Revoker: w, Incident: w})
}

func (w *rotWorld) count(prefix string) int {
	n := 0
	for _, e := range w.events {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

// R-CAR-5, engine portion: a carrier that cannot be read or reached is
// "unknown", never "gone". No new version, no revocation, a human is told.
func TestW3_A01_LostCarrierNeverReissues(t *testing.T) {
	for name, set := range map[string]func(*rotWorld){
		"host unreachable on read": func(w *rotWorld) { w.verifyErr[cid(2)] = errors.New("host unreachable") },
		"scan failed on deploy":    func(w *rotWorld) { w.deployErr[cid(2)] = errors.New("scan failed") },
		"carrier list unreadable":  func(w *rotWorld) { w.listErr = errors.New("registry read failed") },
	} {
		func() {
			w := newRotWorld(t, 3)
			set(w)
			id := uuid.New()
			res, err := w.engine().Rotate(context.Background(), w.ref, rotation.Options{RunID: id})
			if !errors.Is(err, rotation.ErrFailed) || w.revokes != 0 || len(w.incidents) != 1 {
				t.Fatalf("lost carrier: %+v %v revokes=%d incidents=%d (%s)", res, err, w.revokes, len(w.incidents), name)
			}
			// Asking again must not mint another version.
			if _, err := w.engine().Rotate(context.Background(), w.ref, rotation.Options{RunID: id}); !errors.Is(err, rotation.ErrFailed) || w.prepares != 1 || w.revokes != 0 {
				t.Fatalf("reissue after a lost carrier: prepares=%d revokes=%d err=%v (%s)", w.prepares, w.revokes, err, name)
			}
		}()
	}
}

// R-ROT-1/2: of N carriers the k-th fails in any way, the old version stays
// and an incident is opened; the N-1 successes do not count.
func TestW3_A02_PartialDeployKeepsOldVersion(t *testing.T) {
	const n = 5
	for k := 1; k <= n; k++ {
		for kind, set := range map[string]func(*rotWorld, string){
			"write error": func(w *rotWorld, c string) { w.deployErr[c] = errors.New("write failed") },
			"timeout":     func(w *rotWorld, c string) { w.deployErr[c] = context.DeadlineExceeded },
			"red health":  func(w *rotWorld, c string) { w.unhealthy[c] = true },
		} {
			func() {
				w := newRotWorld(t, n)
				set(w, cid(k))
				res, err := w.engine().Rotate(context.Background(), w.ref, rotation.Options{})
				if !errors.Is(err, rotation.ErrFailed) || w.revokes != 0 || len(w.incidents) != 1 {
					t.Fatalf("partial success revoked or hid the failure: %+v %v revokes=%d incidents=%d (%s at %d)", res, err, w.revokes, len(w.incidents), kind, k)
				}
			}()
		}
	}
}

// Threat model 4.2/4.4: a canary dragged through a failed rotation by every
// collaborator is in no state row, incident, result or error, in any of the
// encodings the canary detector knows (base64 included).
func TestW3_A07_NoValueInRotationStateIncidentErrors(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind")
	}
	w := newRotWorld(t, 4)
	w.deployErr[cid(1)] = errors.New("deploy of " + v)
	w.verifyErr[cid(2)] = errors.New("read " + v)
	w.verifyFP[cid(3)] = v
	w.revokeErr = errors.New("revoke " + v)
	var dump strings.Builder
	res, err := w.engine().Rotate(context.Background(), w.ref, rotation.Options{})
	fmt.Fprintf(&dump, "%+v %#v %v %+v", res, res, err, w.incidents)
	// A second run reaches the verification and revoke paths too.
	w2 := newRotWorld(t, 4)
	w2.verifyErr[cid(2)] = errors.New("read " + v)
	w2.verifyFP[cid(3)] = v
	res2, err2 := w2.engine().Rotate(context.Background(), w2.ref, rotation.Options{})
	fmt.Fprintf(&dump, "%+v %v %+v", res2, err2, w2.incidents)
	w3 := newRotWorld(t, 2)
	w3.revokeErr = errors.New("revoke " + v)
	res3, err3 := w3.engine().Rotate(context.Background(), w3.ref, rotation.Options{})
	fmt.Fprintf(&dump, "%+v %v %+v", res3, err3, w3.incidents)
	// A canary as a carrier's fingerprint, with nothing else going wrong on
	// the way, reaches the fingerprint write; a list failure and a failing
	// incident hook carry it in their errors.
	w4 := newRotWorld(t, 3)
	w4.verifyFP[cid(3)] = v
	res4, err4 := w4.engine().Rotate(context.Background(), w4.ref, rotation.Options{})
	fmt.Fprintf(&dump, "%+v %v %+v", res4, err4, w4.incidents)
	w5 := newRotWorld(t, 3)
	w5.listErr = errors.New("list " + v)
	res5, err5 := w5.engine().Rotate(context.Background(), w5.ref, rotation.Options{})
	fmt.Fprintf(&dump, "%+v %v", res5, err5)
	w6 := newRotWorld(t, 3)
	w6.deployErr[cid(1)] = errors.New("deploy")
	w6.incErr = errors.New("journal refused " + v)
	res6, err6 := w6.engine().Rotate(context.Background(), w6.ref, rotation.Options{})
	fmt.Fprintf(&dump, "%+v %v", res6, err6)
	for _, q := range []string{`SELECT coalesce(string_agg(row_to_json(r)::text, ' '), '') FROM rotation_runs r WHERE org_id=ANY($1)`,
		`SELECT coalesce(string_agg(row_to_json(s)::text, ' '), '') FROM rotation_steps s JOIN rotation_runs r ON r.id=s.run_id WHERE r.org_id=ANY($1)`} {
		var s string
		if err := w.db.QueryRow(context.Background(), q, []uuid.UUID{w.ref.OrgID, w2.ref.OrgID, w3.ref.OrgID, w4.ref.OrgID, w5.ref.OrgID, w6.ref.OrgID}).Scan(&s); err != nil || s == "" {
			t.Fatalf("interception saw no rows (%v)", err)
		}
		dump.WriteString(s)
	}
	if c.In(dump.String()) {
		t.Fatal("canary reached rotation state, incident or error")
	}
}

// R-ROT-1: two simultaneous rotations of one secret: one runs, the other is
// refused; one new version, at most one revoke.
func TestW3_A08_ConcurrentRotationsSerialize(t *testing.T) {
	w := newRotWorld(t, 3)
	w.gate, w.entered = make(chan struct{}), make(chan struct{}, 1)
	e := w.engine()
	first := make(chan error, 1)
	go func() { _, err := e.Rotate(context.Background(), w.ref, rotation.Options{}); first <- err }()
	<-w.entered
	short, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if _, err := e.Rotate(short, w.ref, rotation.Options{}); !errors.Is(err, rotation.ErrConflict) {
		t.Fatalf("second simultaneous rotation: want conflict, got %v", err)
	}
	close(w.gate)
	if err := <-first; err != nil || w.prepares != 1 || w.revokes != 1 {
		t.Fatalf("first run: err=%v prepares=%d revokes=%d", err, w.prepares, w.revokes)
	}
}

// R-ROT-2: killed after k of N layouts: on restart the run resumes; the old
// version stays alive until then; the new one is neither lost nor duplicated;
// the unfinished run is visible to a human in the database.
func TestW3_A09_RestartMidRotationResumesSafely(t *testing.T) {
	w := newRotWorld(t, 5)
	ctx, cancel := context.WithCancel(context.Background())
	w.killAt, w.killCtx = 3, cancel
	id := uuid.New()
	if _, err := w.engine().Rotate(ctx, w.ref, rotation.Options{RunID: id, Concurrency: 1}); err == nil {
		t.Fatal("the simulated kill did not stop the run")
	}
	var state string
	if err := w.db.QueryRow(context.Background(), `SELECT state FROM rotation_runs WHERE id=$1`, id).Scan(&state); err != nil || state != "deploying" {
		t.Fatalf("unfinished run not visible as deploying: %q %v", state, err)
	}
	if w.revokes != 0 {
		t.Fatal("old version revoked before the run finished")
	}
	res, err := w.engine().Rotate(context.Background(), w.ref, rotation.Options{RunID: id, Concurrency: 1})
	if err != nil || res.State != rotation.StateDone {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if w.prepares != 1 || w.revokes != 1 || w.count("deploy ") != 5 || res.NewVersion != "2" {
		t.Fatalf("lost or duplicated: prepares=%d revokes=%d deploys=%d", w.prepares, w.revokes, w.count("deploy "))
	}
}

// Engine portion of the tenant scenario: a run belongs to its organization;
// another organization naming the same run id gets the "unavailable" answer
// and none of the carriers is touched on its behalf.
func TestW3_A10_ForeignTenantCarriersInvisible_Rotation(t *testing.T) {
	w := newRotWorld(t, 3)
	id := uuid.New()
	if _, err := w.engine().Rotate(context.Background(), w.ref, rotation.Options{RunID: id}); err != nil {
		t.Fatal(err)
	}
	before := len(w.events)
	foreign := rotation.Ref{OrgID: uuid.New(), SecretID: w.ref.SecretID}
	exec(t, w.db, `INSERT INTO organizations(id,name) VALUES($1,'rotation-foreign')`, foreign.OrgID)
	if _, err := w.engine().Rotate(context.Background(), foreign, rotation.Options{RunID: id}); !errors.Is(err, rotation.ErrNotFound) {
		t.Fatalf("foreign organization saw the run: %v", err)
	}
	if len(w.events) != before {
		t.Fatal("a collaborator was called for a foreign organization's run")
	}
	// A foreign organization's own run of that secret id sees no carriers of ours.
	res, err := w.engine().Rotate(context.Background(), foreign, rotation.Options{})
	if !errors.Is(err, rotation.ErrFailed) || res.Class != rotation.ClassNoCarriers || w.revokes != 1 {
		t.Fatalf("foreign run: %+v %v revokes=%d", res, err, w.revokes)
	}
}

// R-ROT-1: a carrier answering with the OLD version's fingerprint (replay or
// cache) fails verification and nothing is revoked; every verification is a
// fresh read that follows its own layout.
func TestW3_A12_StaleHealthEchoNotAccepted(t *testing.T) {
	w := newRotWorld(t, 3)
	w.verifyFP[cid(2)] = w.oldFP
	res, err := w.engine().Rotate(context.Background(), w.ref, rotation.Options{Concurrency: 1})
	if !errors.Is(err, rotation.ErrFailed) || res.Class != rotation.ClassFingerprintMismatch || w.revokes != 0 {
		t.Fatalf("stale echo accepted: %+v %v revokes=%d", res, err, w.revokes)
	}
	ok := newRotWorld(t, 3)
	if _, err := ok.engine().Rotate(context.Background(), ok.ref, rotation.Options{Concurrency: 1}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{cid(1), cid(2), cid(3)} {
		d, v := -1, -1
		for i, e := range ok.events {
			switch e {
			case "deploy " + c:
				d = i
			case "verify " + c:
				v = i
			}
		}
		if d < 0 || v < 0 || v < d {
			t.Fatalf("carrier %s verified without a fresh read after its layout (deploy@%d verify@%d)", c, d, v)
		}
	}
}

// Threat model I5, engine portion: nothing a caller passes to the engine can
// carry a value or choose the version: Options holds an idempotency id and four
// limits, the version source takes ids only. Who may start a rotation is the
// API's decision and stays pending with it.
func TestW3_A13_AgentCannotInjectRotationValue_Rotation(t *testing.T) {
	var opts rotation.Options
	ot := reflect.TypeOf(opts)
	for i := 0; i < ot.NumField(); i++ {
		f := ot.Field(i)
		low := strings.ToLower(f.Name)
		if strings.Contains(low, "value") || strings.Contains(low, "secret") || strings.Contains(low, "version") || strings.Contains(low, "plain") || f.Type.Kind() == reflect.Slice {
			t.Fatalf("Options.%s lets a caller steer the rotation", f.Name)
		}
	}
	if ot.NumField() != 5 {
		t.Fatalf("Options changed (%d fields): review it against threat model I5", ot.NumField())
	}
	// The layout-retry limits are a count and a delay: no text, no bytes.
	for _, name := range []string{"DeployAttempts", "RetryDelay"} {
		f, ok := ot.FieldByName(name)
		if !ok || (f.Type.Kind() != reflect.Int && f.Type != reflect.TypeOf(time.Duration(0))) {
			t.Fatalf("Options.%s is missing or can carry more than a number", name)
		}
	}
	m, ok := reflect.TypeOf((*rotation.Versions)(nil)).Elem().MethodByName("Prepare")
	if !ok || m.Type.NumIn() != 3 {
		t.Fatal("Prepare signature changed: review it against threat model I5")
	}
	for i := 0; i < m.Type.NumIn(); i++ {
		if k := m.Type.In(i).Kind(); k == reflect.Slice || k == reflect.String {
			t.Fatalf("Prepare takes a %v: a value could be passed in", k)
		}
	}
}
