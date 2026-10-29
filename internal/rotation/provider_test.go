package rotation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/provider/memory"
	prot "github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const provPath = "builtin://prov-test"

// events is the shared, ordered log of what the collaborators were asked.
type events struct {
	mu  sync.Mutex
	log []string
}

func (e *events) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.log = append(e.log, s)
}

func (e *events) all() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.log...)
}

func (e *events) reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.log = nil
}

func (e *events) count(prefix string) int {
	n := 0
	for _, s := range e.all() {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

func (e *events) exact(s string) int {
	n := 0
	for _, have := range e.all() {
		if have == s {
			n++
		}
	}
	return n
}

func (e *events) first(prefix string) int {
	for i, s := range e.all() {
		if strings.HasPrefix(s, prefix) {
			return i
		}
	}
	return -1
}

func (e *events) last(prefix string) int {
	at := -1
	for i, s := range e.all() {
		if strings.HasPrefix(s, prefix) {
			at = i
		}
	}
	return at
}

// stubProvider is a RotationProvider with a switchable capability. Forward
// only: Issue ends every earlier key at once.
type stubProvider struct {
	ev         *events
	dual       bool
	mu         sync.Mutex
	active     map[string]bool
	issueErr   error
	revokeErr  error
	checkErr   error
	stillOn    bool   // Check keeps answering Active after a Revoke
	origin     string // the key issued outside Keep that Current names
	nextID     string // the id Issue hands out next
	currentErr error
	value      string
	last       secret.Value // the handle Issue returned, to see it wiped
	n          int
	lastID     string
	badKeyID   bool
	emptyVal   bool
}

// wiped: the handle Issue returned holds zero bytes now. Equal against zeros of
// the same length, so the test never reads the value.
func (s *stubProvider) wiped() bool {
	return s.n > 0 && s.last.Equal(secret.New(make([]byte, s.n)))
}

func (s *stubProvider) Kind() string                    { return "stub" }
func (s *stubProvider) Capabilities() prot.Capabilities { return prot.Capabilities{DualKey: s.dual} }

func (s *stubProvider) Current(_ context.Context, _ string) (string, bool, error) {
	s.ev.add("current")
	if s.currentErr != nil {
		return "", false, s.currentErr
	}
	return s.origin, s.origin != "", nil
}

func (s *stubProvider) Issue(_ context.Context, _ prot.IssueRequest) (prot.Issued, error) {
	s.ev.add("issue")
	if s.issueErr != nil {
		return prot.Issued{}, s.issueErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dual {
		for k := range s.active {
			s.active[k] = false
		}
	}
	id := uuid.NewString()
	if s.nextID != "" {
		id = s.nextID
	}
	s.active[id] = true
	val := s.value
	if val == "" {
		val = "value-" + id
	}
	if s.emptyVal {
		val = ""
	}
	if s.badKeyID {
		id = "not-a-uuid"
	}
	s.lastID = id
	s.last, s.n = secret.New([]byte(val)), len(val)
	return prot.Issued{KeyID: id, Value: s.last}, nil
}

func (s *stubProvider) Check(_ context.Context, id string) (prot.Status, error) {
	s.ev.add("check")
	if s.checkErr != nil {
		return prot.Status{}, s.checkErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return prot.Status{Active: s.active[id] || s.stillOn}, nil
}

func (s *stubProvider) Revoke(_ context.Context, id string) error {
	s.ev.add("revoke " + id)
	if s.revokeErr != nil {
		return s.revokeErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active[id] = false
	return nil
}

// evStore wraps the reference provider so its calls enter the event log.
type evStore struct {
	provider.Provider
	ev       *events
	writeErr error
	disErr   error
	verErr   error
}

func (s *evStore) Write(ctx context.Context, r provider.Ref, v secret.Value) (provider.Meta, error) {
	s.ev.add("seal")
	if s.writeErr != nil {
		return provider.Meta{}, s.writeErr
	}
	return s.Provider.Write(ctx, r, v)
}

func (s *evStore) Version(ctx context.Context, r provider.Ref) (provider.Meta, error) {
	if s.verErr != nil {
		return provider.Meta{}, s.verErr
	}
	return s.Provider.Version(ctx, r)
}

func (s *evStore) Disable(ctx context.Context, r provider.Ref) error {
	s.ev.add("disable " + r.Version)
	if s.disErr != nil {
		return s.disErr
	}
	return s.Provider.Disable(ctx, r)
}

// evCollab is the carrier side: deploy, verify and incident, all logged.
type evCollab struct {
	*fakes
	ev     *events
	left   map[string]int // deploy failures left per carrier
	always bool           // every deploy fails
	fp     func() string
}

func (c *evCollab) Deploy(_ context.Context, _ Ref, _ uuid.UUID, car Carrier, _ string) error {
	c.ev.add("deploy " + car.ID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.always {
		return errors.New("deploy refused")
	}
	if c.left[car.ID] > 0 {
		c.left[car.ID]--
		return errors.New("deploy refused")
	}
	return nil
}

func (c *evCollab) Verify(_ context.Context, _ Ref, car Carrier, _ string) (Report, error) {
	c.ev.add("verify " + car.ID)
	c.mu.Lock()
	defer c.mu.Unlock()
	return Report{Fingerprint: c.fp(), Healthy: !c.unhealthy[car.ID]}, nil
}

func (c *evCollab) Open(ctx context.Context, r IncidentRecord) error {
	c.ev.add("incident")
	return c.fakes.Open(ctx, r)
}

// lastVersion remembers what Prepare returned so the verifier can report it.
type lastVersion struct {
	*ProviderVersions
	mu   sync.Mutex
	last Version
}

func (l *lastVersion) Prepare(ctx context.Context, r Ref, id uuid.UUID) (Version, error) {
	v, err := l.ProviderVersions.Prepare(ctx, r, id)
	if err == nil {
		l.mu.Lock()
		l.last = v
		l.mu.Unlock()
	}
	return v, err
}

func (l *lastVersion) fp() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last.Fingerprint
}

type provFx struct {
	fx
	ev     *events
	rp     *stubProvider
	store  *evStore
	mem    *memory.Provider
	col    *evCollab
	deps   ProviderDeps
	engine *Engine
}

func newProvFx(t *testing.T, dual bool, carriers int) *provFx {
	t.Helper()
	x := newFx(t)
	ev := &events{}
	mem := memory.New(nil)
	if _, err := mem.Write(x.ctx, provider.Ref{Path: provPath}, secret.New([]byte("initial-value"))); err != nil {
		t.Fatal(err)
	}
	p := &provFx{fx: x, ev: ev, mem: mem}
	p.store = &evStore{Provider: mem, ev: ev}
	p.rp = &stubProvider{ev: ev, dual: dual, active: map[string]bool{}}
	p.col = &evCollab{fakes: newFakes(carriers), ev: ev, left: map[string]int{}}
	p.deps = ProviderDeps{
		Provider: p.rp,
		Resolve: func(context.Context, Ref) (Target, error) {
			return Target{Store: p.store, Ref: provider.Ref{Path: provPath}, Subject: "subject"}, nil
		},
		Ledger:   NewLedger(x.pool),
		Incident: p.col,
		FingerprintKey: func(context.Context) (fingerprint.Key, error) {
			return fingerprint.NewKey("k1", []byte("0123456789abcdef0123456789abcdef"))
		},
	}
	lv := &lastVersion{ProviderVersions: NewProviderVersions(p.deps)}
	p.col.fp = lv.fp
	p.engine = New(x.pool, Deps{Versions: lv, Carriers: p.col, Deployer: p.col, Verifier: p.col,
		Revoker: NewProviderRevoker(p.deps), Incident: p.col})
	return p
}

func (p *provFx) rotate() (Result, error) {
	return p.engine.Rotate(p.ctx, p.ref, Options{RetryDelay: time.Millisecond})
}

// firstRun makes the stub's first key the one behind version 2, then clears
// the event log so the next run is read on its own.
func (p *provFx) firstRun(t *testing.T) Result {
	t.Helper()
	r, err := p.rotate()
	if err != nil || r.State != StateDone {
		t.Fatalf("first run: %+v %v", r, err)
	}
	p.ev.reset()
	return r
}

// DualKey: issue, seal, every layout, every verification, then the revoke of
// the old key and the disable of the old version, in that order.
func TestProviderDualKeyOrderIsStrict(t *testing.T) {
	p := newProvFx(t, true, 3)
	p.firstRun(t)
	r, err := p.rotate()
	if err != nil || r.State != StateDone {
		t.Fatalf("second run: %+v %v", r, err)
	}
	ev := p.ev
	chain := []int{ev.first("issue"), ev.first("seal"), ev.last("deploy"), ev.last("verify"), ev.first("revoke"), ev.first("check"), ev.first("disable 2")}
	prev := -1
	for i, at := range chain {
		if at <= prev {
			t.Fatalf("out of order at %d: %v", i, ev.all())
		}
		prev = at
	}
	if ev.count("deploy") != 3 || ev.count("verify") != 3 {
		t.Fatalf("not every carrier was laid out and verified: %v", ev.all())
	}
}

// DualKey: one carrier does not confirm; the old key and old version stay.
func TestProviderUnconfirmedCarrierRevokesNothing(t *testing.T) {
	p := newProvFx(t, true, 3)
	p.firstRun(t)
	p.col.unhealthy[cid(2)] = true
	r, err := p.rotate()
	if !errors.Is(err, ErrFailed) || r.State != StateFailed {
		t.Fatalf("want a failed run, got %+v %v", r, err)
	}
	if p.ev.count("revoke") != 0 || p.ev.count("disable") != 0 || p.ev.count("incident") != 1 {
		t.Fatalf("old key or version touched: %v", p.ev.all())
	}
}

// Forward only: the new key is sealed before any layout, the layout is
// retried, the provider is never asked to revoke (the old key is gone).
func TestProviderForwardOnlySealsAtPrepareAndRetriesLayout(t *testing.T) {
	p := newProvFx(t, false, 2)
	p.col.left[cid(1)] = 2
	r, err := p.rotate()
	if err != nil || r.State != StateDone {
		t.Fatalf("got %+v %v", r, err)
	}
	ev := p.ev
	if ev.count("issue") != 1 || ev.first("seal") < 0 || ev.first("seal") > ev.first("deploy") {
		t.Fatalf("new key not sealed before the first layout: %v", ev.all())
	}
	if ev.count("deploy "+cid(1)) != 3 {
		t.Fatalf("layout tried %d times, want 3: %v", ev.count("deploy "+cid(1)), ev.all())
	}
	if ev.count("revoke") != 0 || ev.count("check") != 0 || ev.count("disable 1") != 1 {
		t.Fatalf("forward-only run asked the provider to revoke, or kept the old version: %v", ev.all())
	}
	if m, err := p.mem.Version(p.ctx, provider.Ref{Path: provPath}); err != nil || m.Version != "2" {
		t.Fatalf("new version not current: %+v %v", m, err)
	}
}

// Forward only, layout never succeeds: an incident that says there is no way
// back, the attempts are spent, nothing is revoked or disabled.
func TestProviderForwardOnlyFailureIsAnIncidentWithoutRollback(t *testing.T) {
	p := newProvFx(t, false, 2)
	p.col.always = true
	r, err := p.engine.Rotate(p.ctx, p.ref, Options{RetryDelay: time.Millisecond, DeployAttempts: 3})
	if !errors.Is(err, ErrFailed) || r.Class != ClassDeployFailed {
		t.Fatalf("got %+v %v", r, err)
	}
	if n := p.ev.count("deploy"); n < 3 {
		t.Fatalf("%d layout attempts, want 3 per carrier: %v", n, p.ev.all())
	}
	if len(p.col.incidents) != 1 || !p.col.incidents[0].ForwardOnly || len(p.col.incidents[0].Carriers) == 0 {
		t.Fatalf("incident: %+v", p.col.incidents)
	}
	if p.ev.count("revoke") != 0 || p.ev.count("disable") != 0 {
		t.Fatalf("rolled back or revoked: %v", p.ev.all())
	}
	// The new key is sealed and current: it is the only copy there is.
	if m, err := p.mem.Version(p.ctx, provider.Ref{Path: provPath}); err != nil || m.Version != "2" {
		t.Fatalf("sealed version: %+v %v", m, err)
	}
}

// A provider that keeps the old key valid gets one layout attempt.
func TestProviderDualKeyDoesNotRetryLayout(t *testing.T) {
	p := newProvFx(t, true, 1)
	p.col.always = true
	r, err := p.rotate()
	if !errors.Is(err, ErrFailed) || len(p.col.incidents) != 1 || p.col.incidents[0].ForwardOnly {
		t.Fatalf("got %+v %v %+v", r, err, p.col.incidents)
	}
	if n := p.ev.count("deploy"); n != 1 {
		t.Fatalf("%d attempts, want 1", n)
	}
}

// Prepare is idempotent per run: the provider is asked once and the recorded
// version comes back; another secret cannot read it.
func TestProviderPrepareIsIdempotentPerRun(t *testing.T) {
	p := newProvFx(t, false, 1)
	vs := NewProviderVersions(p.deps)
	run := uuid.New()
	a, err := vs.Prepare(p.ctx, p.ref, run)
	if err != nil {
		t.Fatal(err)
	}
	b, err := vs.Prepare(p.ctx, p.ref, run)
	if err != nil || a != b || p.ev.count("issue") != 1 {
		t.Fatalf("got %+v %+v %v issues=%d", a, b, err, p.ev.count("issue"))
	}
	if _, err := vs.Prepare(p.ctx, Ref{OrgID: p.ref.OrgID, SecretID: uuid.New()}, run); !errors.Is(err, ErrPrepare) {
		t.Fatalf("another secret read the run's version: %v", err)
	}
}

// Dual key: when sealing fails the new key is ended again; forward only has
// no way back and does not pretend to.
func TestProviderSealFailureRollsBackOnlyWithDualKey(t *testing.T) {
	for _, dual := range []bool{true, false} {
		t.Run(fmt.Sprintf("dual=%v", dual), func(t *testing.T) {
			p := newProvFx(t, dual, 1)
			p.store.writeErr = errors.New("store down")
			if _, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New()); !errors.Is(err, ErrPrepare) {
				t.Fatalf("got %v", err)
			}
			if got := p.ev.count("revoke"); (got == 1) != dual || got > 1 {
				t.Fatalf("dual=%v but %d revokes: %v", dual, got, p.ev.all())
			}
		})
	}
}

// A ledger insert that fails after it committed must not end the key it
// recorded: the replayed version would stand on a dead key.
func TestProviderCommittedLedgerRowKeepsItsKey(t *testing.T) {
	p := newProvFx(t, true, 1)
	p.deps.Ledger.afterPut = func() error { return errors.New("lost response") }
	run := uuid.New()
	v, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, run)
	if err != nil || v.New == "" {
		t.Fatalf("got %+v, %v", v, err)
	}
	if got := p.ev.count("revoke"); got != 0 {
		t.Fatalf("%d revokes after a committed row: %v", got, p.ev.all())
	}
	p.deps.Ledger.afterPut = nil
	again, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, run)
	if err != nil || again != v {
		t.Fatalf("replay got %+v, %v want %+v", again, err, v)
	}
}

// A run that dies after the value was sealed and before the ledger row exists
// must not ask the provider again: with a forward-only provider the second Issue
// ends the key the first one made.
func TestProviderReplayAfterLostLedgerRowNeverIssuesAgain(t *testing.T) {
	for _, dual := range []bool{false, true} {
		t.Run(fmt.Sprintf("dual=%v", dual), func(t *testing.T) {
			p := newProvFx(t, dual, 1)
			p.deps.Ledger.beforePut = func() error { return errors.New("process died") }
			run := uuid.New()
			if _, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, run); !errors.Is(err, ErrPrepare) {
				t.Fatalf("got %v", err)
			}
			p.deps.Ledger.beforePut = nil
			if _, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, run); !errors.Is(err, ErrPrepare) {
				t.Fatalf("replay got %v", err)
			}
			if got := p.ev.count("issue"); got != 1 {
				t.Fatalf("%d issues for one run: %v", got, p.ev.all())
			}
		})
	}
}

// Revoke acts only for the run that made the new version and for the version
// that run replaced; nothing else reaches the provider.
func TestProviderRevokeRefusesAForeignRunOrVersion(t *testing.T) {
	p := newProvFx(t, true, 1)
	first := p.firstRun(t)
	rv := NewProviderRevoker(p.deps)
	other := Ref{OrgID: p.ref.OrgID, SecretID: uuid.New()}
	cases := map[string]func() error{
		"unknown run":   func() error { return rv.Revoke(p.ctx, p.ref, uuid.New(), "1") },
		"other version": func() error { return rv.Revoke(p.ctx, p.ref, first.RunID, "7") },
		"empty version": func() error { return rv.Revoke(p.ctx, p.ref, first.RunID, "") },
		"other secret":  func() error { return rv.Revoke(p.ctx, other, first.RunID, "1") },
	}
	for name, call := range cases {
		if err := call(); !errors.Is(err, ErrRevoke) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	if n := p.ev.count("revoke") + p.ev.count("disable"); n != 0 {
		t.Fatalf("a refused call reached the provider: %v", p.ev.all())
	}
}

// A provider that says the key is still active after Revoke fails the run
// and the old version stays enabled.
func TestProviderRevokeMustBeConfirmedByCheck(t *testing.T) {
	p := newProvFx(t, true, 1)
	p.firstRun(t)
	p.rp.stillOn = true
	r, err := p.rotate()
	if !errors.Is(err, ErrRevokePending) || r.State != StateRevokingOld || r.Class != ClassRevokeFailed {
		t.Fatalf("got %+v %v", r, err)
	}
	if p.ev.count("disable") != 0 {
		t.Fatalf("old version disabled although the old key is still active: %v", p.ev.all())
	}
}

// The canary is the issued value's lookalike in every error the provider and
// the store return. It reaches no error, result, incident, event or stored row.
func TestProviderCanaryReachesNothing(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind")
	}
	for name, setup := range map[string]func(*provFx){
		"issue error":  func(p *provFx) { p.rp.issueErr = errors.New("issue of " + v) },
		"seal error":   func(p *provFx) { p.store.writeErr = fmt.Errorf("write %s: %w", v, provider.ErrUnavailable) },
		"revoke error": func(p *provFx) { p.rp.revokeErr = errors.New("revoke " + v) },
		"check error":  func(p *provFx) { p.rp.checkErr = errors.New("check " + v) },
		"deploy error": func(p *provFx) { p.col.always = true },
		"happy path":   func(*provFx) {},
	} {
		t.Run(name, func(t *testing.T) {
			p := newProvFx(t, true, 2)
			p.rp.value = v
			p.firstRun(t)
			if !p.rp.wiped() {
				t.Fatal("issued value was not wiped")
			}
			setup(p)
			var dump strings.Builder
			for i := 0; i < 2; i++ {
				r, err := p.rotate()
				fmt.Fprintf(&dump, "%+v %#v %v|", r, r, err)
				if err != nil {
					fmt.Fprintf(&dump, "%+v|", err)
				}
			}
			fmt.Fprintf(&dump, "%+v|%s", p.col.incidents, strings.Join(p.ev.all(), "|"))
			for _, tbl := range []string{"rotation_runs", "rotation_steps", "rotation_keys"} {
				var s string
				if err := p.pool.QueryRow(p.ctx, `SELECT coalesce(string_agg(t::text, '|'), '') FROM `+tbl+` t`).Scan(&s); err != nil {
					t.Fatal("read rows")
				}
				dump.WriteString(s)
			}
			if dump.Len() < 200 {
				t.Fatalf("interception saw too little (%d bytes); the test proves nothing", dump.Len())
			}
			if c.In(dump.String()) {
				t.Fatalf("canary reached an error, result, incident, event or row (%d bytes inspected)", dump.Len())
			}
		})
	}
}

// Forward only, second run: the old key ended when the new one was issued, so
// the provider is neither asked to revoke nor to check; only the old version
// of the secret is disabled.
func TestProviderForwardOnlyNeverCallsProviderRevoke(t *testing.T) {
	p := newProvFx(t, false, 2)
	p.firstRun(t)
	if r, err := p.rotate(); err != nil || r.State != StateDone {
		t.Fatalf("second run: %+v %v", r, err)
	}
	if p.ev.count("revoke") != 0 || p.ev.count("check") != 0 || p.ev.count("disable 2") != 1 {
		t.Fatalf("forward-only second run: %v", p.ev.all())
	}
}

// The adapters return their own errors only. The engine drops what a
// revoker returns, so the adapters are read directly: the canary sits in every
// text the provider and the store hand back.
func TestProviderAdapterErrorsHoldNoCanary(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind")
	}
	surface := func(err error) string {
		var b strings.Builder
		for e := err; e != nil; e = errors.Unwrap(e) {
			fmt.Fprintf(&b, "%v|%+v|%#v|", e, e, e)
		}
		return b.String()
	}
	check := func(t *testing.T, want, got error) {
		t.Helper()
		if !errors.Is(got, want) {
			t.Fatalf("want %v, got %v", want, got)
		}
		s := surface(got)
		if len(s) < 20 || c.In(s) {
			t.Fatalf("canary reached the error, or nothing was inspected (%d bytes)", len(s))
		}
	}
	t.Run("issue", func(t *testing.T) {
		p := newProvFx(t, true, 1)
		p.rp.issueErr = errors.New("issue of " + v)
		_, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New())
		check(t, ErrPrepare, err)
	})
	t.Run("seal", func(t *testing.T) {
		p := newProvFx(t, true, 1)
		p.store.writeErr = fmt.Errorf("write %s: %w", v, provider.ErrUnavailable)
		_, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New())
		check(t, ErrPrepare, err)
	})
	t.Run("version", func(t *testing.T) {
		p := newProvFx(t, true, 1)
		p.store.verErr = fmt.Errorf("read %s: %w", v, provider.ErrUnavailable)
		_, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New())
		check(t, ErrPrepare, err)
	})
	t.Run("fingerprint key", func(t *testing.T) {
		p := newProvFx(t, true, 1)
		p.deps.FingerprintKey = func(context.Context) (fingerprint.Key, error) {
			return fingerprint.Key{}, errors.New("key " + v)
		}
		_, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New())
		check(t, ErrPrepare, err)
	})
	for name, set := range map[string]func(*provFx){
		"disable": func(p *provFx) { p.store.disErr = fmt.Errorf("disable %s: %w", v, provider.ErrUnavailable) },
		"resolve": func(p *provFx) {
			p.deps.Resolve = func(context.Context, Ref) (Target, error) { return Target{}, errors.New("resolve " + v) }
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newProvFx(t, true, 1)
			p.firstRun(t)
			run := uuid.New()
			got, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, run)
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			set(p)
			check(t, ErrRevoke, NewProviderRevoker(p.deps).Revoke(p.ctx, p.ref, run, got.Old))
		})
	}
	for name, set := range map[string]func(*stubProvider){
		"revoke": func(s *stubProvider) { s.revokeErr = errors.New("revoke " + v) },
		"check":  func(s *stubProvider) { s.checkErr = errors.New("check " + v) },
	} {
		t.Run(name, func(t *testing.T) {
			p := newProvFx(t, true, 1)
			p.firstRun(t)
			run := uuid.New()
			got, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, run)
			if err != nil || got.Old != "2" {
				t.Fatalf("setup: %+v %v", got, err)
			}
			set(p.rp)
			check(t, ErrRevoke, NewProviderRevoker(p.deps).Revoke(p.ctx, p.ref, run, got.Old))
		})
	}
}

// Forward only: a failure while sealing leaves a failed run with an incident
// that says there is no way back, and the provider is never asked to revoke.
func TestProviderForwardOnlySealFailureOpensAnIncident(t *testing.T) {
	p := newProvFx(t, false, 1)
	p.store.writeErr = errors.New("store down")
	r, err := p.rotate()
	if !errors.Is(err, ErrFailed) || r.Class != ClassPrepareFailed {
		t.Fatalf("got %+v %v", r, err)
	}
	if len(p.col.incidents) != 1 || !p.col.incidents[0].ForwardOnly || p.ev.count("revoke") != 0 || p.ev.count("deploy") != 0 {
		t.Fatalf("incidents %+v events %v", p.col.incidents, p.ev.all())
	}
}

// Nothing that can fail without a value runs after Issue: with the fingerprint
// key unavailable the provider is not asked to issue at all.
func TestProviderNoIssueWhenFingerprintKeyIsUnavailable(t *testing.T) {
	p := newProvFx(t, false, 1)
	p.deps.FingerprintKey = func(context.Context) (fingerprint.Key, error) { return fingerprint.Key{}, errors.New("no key") }
	if _, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New()); !errors.Is(err, ErrPrepare) {
		t.Fatalf("got %v", err)
	}
	if p.ev.count("issue") != 0 {
		t.Fatalf("issued with no fingerprint key: %v", p.ev.all())
	}
}

// Prepare wipes the issued value and the fingerprint key it used.
func TestProviderPrepareWipesValueAndKey(t *testing.T) {
	p := newProvFx(t, true, 1)
	var got fingerprint.Key
	mk := p.deps.FingerprintKey
	p.deps.FingerprintKey = func(ctx context.Context) (fingerprint.Key, error) {
		k, err := mk(ctx)
		got = k
		return k, err
	}
	if _, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if !p.rp.wiped() {
		t.Fatal("issued value not wiped")
	}
	// A wiped key is refused by Compute: the test never reads the key.
	if _, err := fingerprint.Compute(got, secret.New([]byte("probe"))); err == nil {
		t.Fatal("fingerprint key not wiped")
	}
}

// A key id that is not a UUID, or an empty value, is refused before sealing; a
// provider that keeps the old key valid has the issued key ended again.
func TestProviderRefusesAMalformedIssue(t *testing.T) {
	for name, set := range map[string]func(*stubProvider){
		"key id":      func(s *stubProvider) { s.badKeyID = true },
		"empty value": func(s *stubProvider) { s.emptyVal = true },
	} {
		t.Run(name, func(t *testing.T) {
			p := newProvFx(t, true, 1)
			set(p.rp)
			if _, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New()); !errors.Is(err, ErrPrepare) {
				t.Fatalf("got %v", err)
			}
			if p.ev.count("seal") != 0 {
				t.Fatalf("a malformed issue was sealed: %v", p.ev.all())
			}
			if name == "empty value" && p.ev.exact("revoke "+p.rp.lastID) != 1 {
				t.Fatalf("the issued key was not ended again: %v", p.ev.all())
			}
		})
	}
}

// The recorded fingerprint is the fingerprint of the issued value, and when
// sealing fails the key that is ended is the one that was issued.
func TestProviderFingerprintIsOfTheIssuedValueAndRollbackEndsThatKey(t *testing.T) {
	p := newProvFx(t, true, 1)
	p.rp.value = "known-value-for-fingerprint"
	got, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.deps.FingerprintKey(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	want, err := fingerprint.Compute(key, secret.New([]byte(p.rp.value)))
	if err != nil || got.Fingerprint != want {
		t.Fatalf("fingerprint %q, want %q (%v)", got.Fingerprint, want, err)
	}
	p.ev.reset()
	p.store.writeErr = errors.New("store down")
	if _, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New()); !errors.Is(err, ErrPrepare) {
		t.Fatalf("got %v", err)
	}
	if p.ev.exact("revoke "+p.rp.lastID) != 1 || p.ev.count("revoke") != 1 {
		t.Fatalf("rollback ended another key: %v (issued %s)", p.ev.all(), p.rp.lastID)
	}
}

// The old key is looked up by organization, secret and version: a key another
// secret recorded under the same version number is never revoked, and a
// ledger row with an empty old version never leads to a revoke.
func TestProviderRevokerFindsOnlyThisSecretsKey(t *testing.T) {
	p := newProvFx(t, true, 1)
	first := p.firstRun(t)
	fk, ok, err := p.deps.Ledger.byRun(p.ctx, first.RunID)
	if err != nil || !ok {
		t.Fatalf("ledger: %v %v", ok, err)
	}
	foreign := uuid.NewString()
	for _, r := range []Ref{
		{OrgID: p.ref.OrgID, SecretID: uuid.New()},
		{OrgID: uuid.New(), SecretID: p.ref.SecretID},
	} {
		if _, err := p.pool.Exec(p.ctx, `INSERT INTO organizations(id,name) VALUES ($1,'other') ON CONFLICT DO NOTHING`, r.OrgID); err != nil {
			t.Fatal("insert organization")
		}
		if err := p.deps.Ledger.put(p.ctx, keyRow{ref: r, runID: uuid.New(), keyID: foreign, old: "1", new: fk.new, fp: fk.fp}); err != nil {
			t.Fatal(err)
		}
	}
	run := uuid.New()
	got, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, run)
	if err != nil {
		t.Fatal(err)
	}
	p.ev.reset()
	if err := NewProviderRevoker(p.deps).Revoke(p.ctx, p.ref, run, got.Old); err != nil {
		t.Fatal(err)
	}
	if p.ev.exact("revoke "+fk.keyID) != 1 || p.ev.exact("revoke "+foreign) != 0 {
		t.Fatalf("wrong key revoked: %v (own %s foreign %s)", p.ev.all(), fk.keyID, foreign)
	}
	// Empty old version recorded for a run: the revoker refuses it.
	empty := uuid.New()
	if err := p.deps.Ledger.put(p.ctx, keyRow{ref: p.ref, runID: empty, keyID: uuid.NewString(), old: "", new: "9", fp: fk.fp}); err != nil {
		t.Fatal(err)
	}
	p.ev.reset()
	if err := NewProviderRevoker(p.deps).Revoke(p.ctx, p.ref, empty, ""); !errors.Is(err, ErrRevoke) || p.ev.count("revoke")+p.ev.count("disable") != 0 {
		t.Fatalf("got %v, events %v", err, p.ev.all())
	}
}

// origKey makes the stub know a key issued outside Keep, active at the start.
func (p *provFx) origKey() string {
	id := uuid.NewString()
	p.rp.origin = id
	p.rp.active[id] = true
	return id
}

// First rotation of a DualKey secret: the key behind the original version was
// issued outside Keep. It is revoked, and only after every carrier verified.
func TestProviderFirstRotationRevokesOriginalKeyAfterVerify(t *testing.T) {
	p := newProvFx(t, true, 3)
	orig := p.origKey()
	if r, err := p.rotate(); err != nil || r.State != StateDone {
		t.Fatalf("run: %+v %v", r, err)
	}
	rv := p.ev.first("revoke " + orig)
	if rv < 0 || p.ev.exact("revoke "+orig) != 1 {
		t.Fatalf("original key not revoked exactly once: %v", p.ev.all())
	}
	if p.ev.count("verify") != 3 || rv < p.ev.last("verify") || rv < p.ev.last("deploy") {
		t.Fatalf("original key revoked before every carrier was verified: %v", p.ev.all())
	}
	if p.rp.active[orig] {
		t.Fatal("original key still active")
	}
	if p.ev.count("incident") != 0 || p.ev.count("disable 1") != 1 {
		t.Fatalf("incident or disable: %v", p.ev.all())
	}
}

// The provider does not know the original key, or cannot say: nothing is
// revoked that is not known, the old version is still disabled and an incident
// of class original_key_unknown is recorded.
func TestProviderUnknownOriginalKeyIsNotRevoked(t *testing.T) {
	for name, set := range map[string]func(*provFx){
		"not-known": func(p *provFx) {},
		"error":     func(p *provFx) { p.rp.currentErr = errors.New("provider down") },
	} {
		t.Run(name, func(t *testing.T) {
			p := newProvFx(t, true, 2)
			set(p)
			if r, err := p.rotate(); err != nil || r.State != StateDone {
				t.Fatalf("run: %+v %v", r, err)
			}
			if p.ev.count("revoke") != 0 || p.ev.count("disable 1") != 1 {
				t.Fatalf("unknown key revoked or version kept: %v", p.ev.all())
			}
			if len(p.col.incidents) != 1 || p.col.incidents[0].Class != ClassOriginalKeyUnknown {
				t.Fatalf("incidents: %+v", p.col.incidents)
			}
		})
	}
}

// A carrier that does not verify: neither the original key nor any ledger key
// is revoked.
func TestProviderFailedCarrierSparesOriginalKey(t *testing.T) {
	p := newProvFx(t, true, 3)
	orig := p.origKey()
	p.col.unhealthy[cid(2)] = true
	if _, err := p.rotate(); !errors.Is(err, ErrFailed) {
		t.Fatalf("want a failed run: %v", err)
	}
	if p.ev.count("revoke") != 0 || !p.rp.active[orig] {
		t.Fatalf("original key touched: %v", p.ev.all())
	}
}

// If recording the incident fails nothing is disabled: the run is retried.
func TestProviderUnknownOriginalKeyNeedsTheIncident(t *testing.T) {
	p := newProvFx(t, true, 1)
	p.col.incErr = errors.New("journal down")
	if _, err := p.rotate(); err == nil {
		t.Fatal("run finished although the incident could not be recorded")
	}
	if p.ev.count("revoke") != 0 {
		t.Fatalf("an unknown key was revoked: %v", p.ev.all())
	}
}

// The canary sits in the error of Current: it reaches no error, result,
// incident, event or row.
func TestProviderCurrentErrorHoldsNoCanary(t *testing.T) {
	c := canary.New()
	p := newProvFx(t, true, 2)
	p.rp.currentErr = errors.New("current: " + c.Value(1))
	r, err := p.rotate()
	var dump strings.Builder
	fmt.Fprintf(&dump, "%+v|%v|%+v|%s", r, err, p.col.incidents, strings.Join(p.ev.all(), "|"))
	for _, tbl := range []string{"rotation_runs", "rotation_steps", "rotation_keys"} {
		var s string
		if err := p.pool.QueryRow(p.ctx, `SELECT coalesce(string_agg(t::text, '|'), '') FROM `+tbl+` t`).Scan(&s); err != nil {
			t.Fatal("read rows")
		}
		dump.WriteString(s)
	}
	if dump.Len() < 200 {
		t.Fatalf("saw too little (%d bytes)", dump.Len())
	}
	if c.In(dump.String()) {
		t.Fatal("canary reached an error, result, incident, event or row")
	}
}

// Issue hands back the key Current names (a resumed run after a crash between
// Issue and the ledger write): it is the new key and is never revoked.
func TestProviderNewKeyIsNeverRevoked(t *testing.T) {
	p := newProvFx(t, true, 2)
	k := p.origKey()
	p.rp.nextID = k
	if r, err := p.rotate(); err != nil || r.State != StateDone {
		t.Fatalf("run: %+v %v", r, err)
	}
	if p.ev.count("revoke") != 0 || !p.rp.active[k] {
		t.Fatalf("the new key was revoked: %v", p.ev.all())
	}
	if len(p.col.incidents) != 1 || p.col.incidents[0].Class != ClassOriginalKeyUnknown {
		t.Fatalf("incidents: %+v", p.col.incidents)
	}
}

// The incident names the last failure: unknown original key and a disable that
// fails ends as revoke_failed, not as original_key_unknown.
func TestProviderUnknownKeyThenDisableFailureIsRevokeFailed(t *testing.T) {
	p := newProvFx(t, true, 1)
	p.store.disErr = errors.New("store down")
	if _, err := p.rotate(); !errors.Is(err, ErrRevokePending) {
		t.Fatalf("want a pending revoke: %v", err)
	}
	if len(p.col.incidents) != 1 || p.col.incidents[0].Class != ClassRevokeFailed {
		t.Fatalf("incidents: %+v", p.col.incidents)
	}
}

// Current returns something that is not a key id (a value would not be): it is
// not stored, not used, and the original key counts as unknown.
func TestProviderCurrentNonIDIsDropped(t *testing.T) {
	c := canary.New()
	p := newProvFx(t, true, 1)
	p.rp.origin = c.Value(1)
	if r, err := p.rotate(); err != nil || r.State != StateDone {
		t.Fatalf("run: %+v %v", r, err)
	}
	var s string
	if err := p.pool.QueryRow(p.ctx, `SELECT coalesce(string_agg(t::text, '|'), '') FROM rotation_keys t`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	if c.In(s+strings.Join(p.ev.all(), "|")) || p.ev.count("revoke") != 0 || len(p.col.incidents) != 1 {
		t.Fatalf("non-id kept or used: %v %+v", p.ev.all(), p.col.incidents)
	}
}

// A DualKey provider without an incident sink issues nothing.
func TestProviderDualKeyNeedsAnIncidentSink(t *testing.T) {
	p := newProvFx(t, true, 1)
	p.deps.Incident = nil
	if _, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New()); !errors.Is(err, ErrPrepare) {
		t.Fatalf("got %v", err)
	}
	if p.ev.count("issue") != 0 {
		t.Fatalf("issued without an incident sink: %v", p.ev.all())
	}
}

// A ledger key does not hide an unknown Current: the second run revokes the key
// the first one recorded and still records the incident.
func TestProviderUnknownCurrentIsRecordedEvenWithALedgerKey(t *testing.T) {
	p := newProvFx(t, true, 2)
	p.firstRun(t)
	p.col.incidents = nil
	if r, err := p.rotate(); err != nil || r.State != StateDone {
		t.Fatalf("second run: %+v %v", r, err)
	}
	if p.ev.count("revoke") != 1 {
		t.Fatalf("ledger key not revoked exactly once: %v", p.ev.all())
	}
	if len(p.col.incidents) != 1 || p.col.incidents[0].Class != ClassOriginalKeyUnknown {
		t.Fatalf("incidents: %+v", p.col.incidents)
	}
}

// A rollback is confirmed like any revoke: a key the provider still reports
// active after it is an incident; a confirmed one is not.
func TestProviderRollbackIsConfirmedOrAnIncident(t *testing.T) {
	for _, stuck := range []bool{true, false} {
		t.Run(fmt.Sprintf("stuck=%v", stuck), func(t *testing.T) {
			p := newProvFx(t, true, 1)
			p.store.writeErr = errors.New("store down")
			p.rp.stillOn = stuck
			if _, err := NewProviderVersions(p.deps).Prepare(p.ctx, p.ref, uuid.New()); !errors.Is(err, ErrPrepare) {
				t.Fatalf("got %v", err)
			}
			if stuck != (len(p.col.incidents) == 1 && p.col.incidents[0].Class == ClassRollbackUnconfirmed) || (!stuck && len(p.col.incidents) != 0) {
				t.Fatalf("stuck=%v incidents: %+v", stuck, p.col.incidents)
			}
		})
	}
}

const adoptedFP = "kfp1:k1:abcdefghijklmnop"

// adoptNow checks a version and commits its record, as a start does with the run.
func adoptNow(p *provFx, vs *ProviderVersions, ref Ref, run uuid.UUID, v Version) error {
	write, err := vs.Adopt(p.ctx, ref, run, v)
	if err != nil {
		return err
	}
	tx, err := p.engine.store.pool.Begin(p.ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(p.ctx) }()
	if err = write(p.ctx, tx); err != nil {
		return err
	}
	return tx.Commit(p.ctx)
}

// A version a human entered is recorded under the run: asking again changes
// nothing, another version for the same run is refused, and Prepare on that run
// (a resume) returns the entered version instead of issuing a new one.
func TestProviderAdoptRecordsTheEnteredVersionPerRun(t *testing.T) {
	p := newProvFx(t, true, 1)
	vs := NewProviderVersions(p.deps)
	run := uuid.New()
	v := Version{Old: "1", New: "2", Fingerprint: adoptedFP}
	if err := adoptNow(p, vs, p.ref, run, v); err != nil {
		t.Fatal(err)
	}
	if err := adoptNow(p, vs, p.ref, run, v); err != nil {
		t.Fatalf("second adopt: %v", err)
	}
	if err := adoptNow(p, vs, p.ref, run, Version{Old: "1", New: "3", Fingerprint: adoptedFP}); !errors.Is(err, ErrPrepare) {
		t.Fatalf("another version for the same run: %v", err)
	}
	if err := adoptNow(p, vs, Ref{OrgID: p.ref.OrgID, SecretID: uuid.New()}, run, v); !errors.Is(err, ErrPrepare) {
		t.Fatalf("another secret adopted the run's version: %v", err)
	}
	got, err := vs.Prepare(p.ctx, p.ref, run)
	if err != nil || got != v || p.ev.count("issue") != 0 {
		t.Fatalf("resume must return the entered version: %+v %v issues=%d", got, err, p.ev.count("issue"))
	}
}

// StartPrepared records the version before the run starts.
func TestStartPreparedRecordsTheVersionBeforeTheRun(t *testing.T) {
	p := newProvFx(t, true, 1)
	svc := NewService(p.engine).WithJournal(audit.NewJournal(p.engine.store.pool))
	v := Version{Old: "1", New: "2", Fingerprint: adoptedFP}
	o := Origin{Actor: audit.Actor{Type: audit.ActorSystem, ID: "human-input", Via: audit.ViaAPI},
		Scope: "org:" + p.ref.OrgID.String(), Name: "db-password", Class: "credential"}
	st, err := svc.StartPrepared(p.ctx, p.ref, v, o)
	if err != nil {
		t.Fatal(err)
	}
	id := st.RunID
	svc.Wait()
	rec, ok, err := p.deps.Ledger.byRun(p.ctx, id)
	if err != nil || !ok || rec.new != "2" || rec.fp != adoptedFP {
		t.Fatalf("ledger row of the entered version: %+v ok=%v err=%v", rec, ok, err)
	}
	if p.ev.count("issue") != 0 {
		t.Fatal("a value was generated for an entered version")
	}
}

// A prepared start that loses the active-run slot leaves nothing behind: no run
// and no adopted version in the ledger (an orphan row would name a version no run
// lays out). The slot is taken first, so the loser never records anything.
func TestStartPreparedThatLosesTheSlotLeavesNoLedgerRow(t *testing.T) {
	p := newProvFx(t, true, 1)
	svc := NewService(p.engine).WithJournal(audit.NewJournal(p.engine.store.pool))
	o := Origin{Actor: audit.Actor{Type: audit.ActorSystem, ID: "human-input", Via: audit.ViaAPI},
		Scope: "org:" + p.ref.OrgID.String(), Name: "db-password", Class: "credential"}
	if _, err := p.engine.store.pool.Exec(p.ctx, `INSERT INTO rotation_runs(id, org_id, secret_id, state) VALUES ($1,$2,$3,'new_version')`,
		uuid.New(), p.ref.OrgID, p.ref.SecretID); err != nil {
		t.Fatal(err)
	}
	_, err := svc.StartPrepared(p.ctx, p.ref, Version{Old: "1", New: "2", Fingerprint: adoptedFP}, o)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("start over an active run: %v", err)
	}
	var keys int
	if err := p.engine.store.pool.QueryRow(p.ctx, `SELECT count(*) FROM rotation_keys WHERE secret_id=$1`, p.ref.SecretID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 0 {
		t.Fatalf("a start that lost the slot left %d ledger rows", keys)
	}
}

// A prepared start whose request record cannot be written (a record the journal
// refuses) rolls the run back and takes the adopted version with it.
func TestStartPreparedWithoutItsRecordLeavesNoLedgerRow(t *testing.T) {
	p := newProvFx(t, true, 1)
	svc := NewService(p.engine).WithJournal(audit.NewJournal(p.engine.store.pool))
	o := Origin{Actor: audit.Actor{Type: "nobody", ID: "human-input", Via: audit.ViaAPI}, Class: "credential"} // an actor type the journal refuses
	_, err := svc.StartPrepared(p.ctx, p.ref, Version{Old: "1", New: "2", Fingerprint: adoptedFP}, o)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("start with a record the journal refuses: %v", err)
	}
	var keys, runs int
	if err := p.engine.store.pool.QueryRow(p.ctx, `SELECT (SELECT count(*) FROM rotation_keys WHERE secret_id=$1), (SELECT count(*) FROM rotation_runs WHERE secret_id=$1)`, p.ref.SecretID).Scan(&keys, &runs); err != nil {
		t.Fatal(err)
	}
	if keys != 0 || runs != 0 {
		t.Fatalf("failed start left %d ledger rows and %d runs", keys, runs)
	}
}

// A prod secret has no prepared path: its human_input is refused before a link
// exists, so a prepared start for one must not slip past the approval gate.
func TestStartPreparedRefusesAProdSecret(t *testing.T) {
	p := newProvFx(t, true, 1)
	svc := NewService(p.engine).WithJournal(audit.NewJournal(p.engine.store.pool))
	o := Origin{Actor: audit.Actor{Type: audit.ActorSystem, ID: "human-input", Via: audit.ViaAPI},
		Scope: "org:" + p.ref.OrgID.String(), Name: "db-password", Class: ClassProd}
	if _, err := svc.StartPrepared(p.ctx, p.ref, Version{Old: "1", New: "2", Fingerprint: adoptedFP}, o); !errors.Is(err, ErrPreparedProd) {
		t.Fatalf("prod prepared start: %v", err)
	}
	// Refused before anything is written: no run, no adopted version.
	var runs, keys int
	if err := p.engine.store.pool.QueryRow(p.ctx, `SELECT (SELECT count(*) FROM rotation_runs WHERE secret_id=$1), (SELECT count(*) FROM rotation_keys WHERE secret_id=$1)`, p.ref.SecretID).Scan(&runs, &keys); err != nil {
		t.Fatal(err)
	}
	if runs != 0 || keys != 0 {
		t.Fatalf("a refused prod start wrote rows: runs=%d keys=%d", runs, keys)
	}
}

// Prepared starts of one secret, more of them than the pool has connections: the
// loser waits inside its transaction for the winner, so a start that needs a
// second connection while it holds one would deadlock the pool. Every start
// returns, one wins, and no ledger row is left without its run.
func TestStartPreparedConcurrentStartsDoNotExhaustThePool(t *testing.T) {
	p := newProvFx(t, true, 1)
	cfg := p.pool.Config().Copy()
	cfg.MaxConns = 2
	small, err := pgxpool.NewWithConfig(p.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(small.Close)
	deps := p.deps
	deps.Ledger = NewLedger(small)
	e := New(small, Deps{Versions: NewProviderVersions(deps), Carriers: p.col, Deployer: p.col, Verifier: p.col,
		Revoker: NewProviderRevoker(deps), Incident: p.col})
	svc := NewService(e).WithJournal(audit.NewJournal(small))
	o := Origin{Actor: audit.Actor{Type: audit.ActorSystem, ID: "human-input", Via: audit.ViaAPI},
		Scope: "org:" + p.ref.OrgID.String(), Name: "db-password", Class: "credential"}
	const starts = 8
	ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
	defer cancel()
	errs := make(chan error, starts)
	for i := 0; i < starts; i++ {
		go func() {
			_, err := svc.StartPrepared(ctx, p.ref, Version{Old: "1", New: "2", Fingerprint: adoptedFP}, o)
			errs <- err
		}()
	}
	won, lost := 0, 0
	for i := 0; i < starts; i++ {
		switch err := <-errs; {
		case err == nil:
			won++
		case errors.Is(err, ErrConflict):
			lost++
		default:
			t.Fatalf("start: %v", err)
		}
	}
	svc.Wait()
	if won != 1 || lost != starts-1 {
		t.Fatalf("won=%d lost=%d", won, lost)
	}
	var keys, runs int
	if err := p.pool.QueryRow(p.ctx, `SELECT (SELECT count(*) FROM rotation_keys WHERE secret_id=$1), (SELECT count(*) FROM rotation_runs WHERE secret_id=$1)`, p.ref.SecretID).Scan(&keys, &runs); err != nil {
		t.Fatal(err)
	}
	if keys != 1 || runs != 1 {
		t.Fatalf("keys=%d runs=%d", keys, runs)
	}
}
