package rotation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultConcurrency = 4
	defaultLease       = 5 * time.Minute
	leasePoll          = 100 * time.Millisecond

	defaultDeployAttempts = 4
	defaultRetryDelay     = 2 * time.Second
)

// forwardOnly reports whether the Versions collaborator says its provider
// cannot keep the old key valid (Capabilities().DualKey == false).
func (e *Engine) forwardOnly() bool {
	f, ok := e.versions.(interface{ ForwardOnly() bool })
	return ok && f.ForwardOnly()
}

// Engine drives runs. Safe for concurrent use.
type Engine struct {
	store    *store
	versions Versions
	carriers Carriers
	deployer Deployer
	verifier Verifier
	revoker  Revoker
	incident Incident
	now      func() time.Time
	// afterState, when set by a test, runs after a state is persisted; an
	// error simulates the process dying there.
	afterState func(State) error
	// afterFence, when set by a test, runs between the ownership check and the
	// external side effect ("deploy" or "revoke"): the window in which a stalled
	// caller can lose its lease.
	afterFence func(kind string)
}

type Deps struct {
	Versions Versions
	Carriers Carriers
	Deployer Deployer
	Verifier Verifier
	Revoker  Revoker
	Incident Incident
}

func New(pool *pgxpool.Pool, d Deps) *Engine {
	return &Engine{store: &store{pool: pool}, versions: d.Versions, carriers: d.Carriers,
		deployer: d.Deployer, verifier: d.Verifier, revoker: d.Revoker, incident: d.Incident, now: time.Now}
}

func ownerToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Rotate runs or resumes a rotation. A failed run returns its Result with
// ErrFailed; a run whose old version could not be revoked returns its Result
// with ErrRevokePending and is retried by calling Rotate with the same run id; a run that cannot be started because another is active returns
// ErrConflict.
func (e *Engine) Rotate(ctx context.Context, ref Ref, opts Options) (Result, error) {
	if opts.RunID == uuid.Nil {
		opts.RunID = uuid.New()
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.LeaseTTL <= 0 {
		opts.LeaseTTL = defaultLease
	}
	if opts.DeployAttempts <= 0 {
		opts.DeployAttempts = defaultDeployAttempts
	}
	if opts.RetryDelay <= 0 {
		opts.RetryDelay = defaultRetryDelay
	}
	if err := e.store.start(ctx, ref, opts.RunID); err != nil {
		return Result{}, err
	}
	l := &lease{owner: ownerToken()}
	claimedAt := e.now()
	epoch, err := e.store.claim(ctx, opts.RunID, l.owner, claimedAt, opts.LeaseTTL)
	if err != nil {
		if errors.Is(err, errNotClaimed) {
			// Finished runs replay their result; busy runs conflict.
			if run, lerr := e.store.load(ctx, opts.RunID); lerr == nil && (run.State == StateDone || run.State == StateFailed) {
				return e.finish(run)
			}
			return Result{}, ErrConflict
		}
		return Result{}, err
	}
	l.epoch = epoch
	l.until.Store(claimedAt.Add(opts.LeaseTTL).UnixNano())
	ctx = withRunID(withLease(ctx, l), opts.RunID)
	defer func() { _ = e.store.release(context.WithoutCancel(ctx), opts.RunID, l) }()

	// The lease is renewed while the run works, so a run that outlasts the
	// TTL is not taken over; if renewal fails the lease is gone and the run
	// stops at once.
	runCtx, cancel := context.WithCancelCause(ctx)
	var hb sync.WaitGroup
	hb.Add(1)
	go func() {
		defer hb.Done()
		e.keepLease(runCtx, cancel, opts.RunID, l, opts.LeaseTTL)
	}()
	defer func() { cancel(nil); hb.Wait() }()
	res, err := e.drive(runCtx, ref, opts)
	if err != nil && errors.Is(context.Cause(runCtx), ErrLeaseLost) {
		return res, ErrLeaseLost
	}
	return res, err
}

// keepLease renews the lease every third of the TTL until ctx ends. A failed
// renewal (taken over, or the database unreachable) cancels the run: a lease
// that cannot be renewed will expire, and another caller may then start.
func (e *Engine) keepLease(ctx context.Context, cancel context.CancelCauseFunc, id uuid.UUID, l *lease, ttl time.Duration) {
	t := time.NewTicker(max(ttl/3, time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			at := e.now()
			if err := e.store.renew(ctx, id, l, at, ttl); err != nil {
				if ctx.Err() == nil {
					cancel(ErrLeaseLost)
				}
				return
			}
			l.until.Store(at.Add(ttl).UnixNano())
		}
	}
}

// fence is the ownership check before an external side effect. It returns the
// context the side effect must run under: it carries the lease's epoch and is
// cancelled with ErrLeaseLost when the lease runs out (renewals move the end,
// so a long call under a live lease is not cut). The check and the call are
// still two steps, so a collaborator that changes anything outside this
// database also refuses a lower epoch (see Deployer).
func (e *Engine) fence(ctx context.Context, id uuid.UUID) (context.Context, context.CancelFunc, error) {
	l := leaseOf(ctx)
	if l == nil {
		return nil, nil, ErrLeaseLost
	}
	now := e.now()
	ok, err := e.store.holds(ctx, id, l, now)
	if err != nil {
		return nil, nil, err
	}
	if !ok || l.until.Load() <= now.UnixNano() {
		return nil, nil, ErrLeaseLost
	}
	sctx, cancel := context.WithCancelCause(withEpoch(ctx, l.epoch))
	go func() {
		for {
			rem := time.Duration(l.until.Load() - e.now().UnixNano())
			if rem <= 0 {
				cancel(ErrLeaseLost)
				return
			}
			t := time.NewTimer(min(rem, leasePoll))
			select {
			case <-sctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
	}()
	return sctx, func() { cancel(nil) }, nil
}

func (e *Engine) drive(ctx context.Context, ref Ref, opts Options) (Result, error) {
	for {
		run, err := e.store.load(ctx, opts.RunID)
		if err != nil {
			return Result{}, err
		}
		if run.Ref != ref {
			return Result{}, ErrNotFound
		}
		if run.State == StateDone || run.State == StateFailed {
			// A superseded run is not a failure of the rotation: a newer sealed
			// version replaced it, so there is nothing for a human to look at.
			if run.State == StateFailed && !run.IncidentOpened && run.Class != ClassSuperseded {
				if err := e.openIncident(ctx, run); err != nil {
					return Result{}, err
				}
			}
			return e.finish(run)
		}
		next, err := e.step(ctx, run, opts)
		if errors.Is(err, ErrRevokePending) {
			run.State, run.Class = next, ClassRevokeFailed
			res, _ := e.finish(run)
			return res, ErrRevokePending
		}
		if err != nil {
			return Result{}, err
		}
		if e.afterState != nil {
			if err := e.afterState(next); err != nil {
				return Result{}, err
			}
		}
	}
}

func (e *Engine) finish(run runRow) (Result, error) {
	res := Result{RunID: run.ID, State: run.State, OldVersion: run.OldVersion, NewVersion: run.NewVersion,
		Fingerprint: run.ExpectedFP, Class: run.Class}
	if run.State == StateFailed {
		return res, ErrFailed
	}
	return res, nil
}

func (e *Engine) openIncident(ctx context.Context, run runRow) error {
	bad, err := e.store.badCarriers(ctx, run.ID)
	if err != nil {
		return err
	}
	ictx, istop, err := e.fence(ctx, run.ID)
	if err != nil {
		return err
	}
	defer istop()
	if e.afterFence != nil {
		e.afterFence("incident")
	}
	if err := e.incident.Open(ictx, IncidentRecord{Ref: run.Ref, RunID: run.ID, Class: run.Class, Carriers: bad, ForwardOnly: e.forwardOnly()}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if ok, herr := e.store.holds(ctx, run.ID, leaseOf(ctx), e.now()); herr == nil && !ok {
			return ErrLeaseLost
		}
		return ErrIncident
	}
	return e.store.markIncident(ctx, run.ID)
}

// step performs the work of the run's current state and persists the next one.
func (e *Engine) step(ctx context.Context, run runRow, opts Options) (State, error) {
	switch run.State {
	case StateNewVersion:
		return e.prepare(ctx, run, opts)
	case StateDeploying:
		return e.deploy(ctx, run, opts)
	case StateVerifying:
		return e.verify(ctx, run, opts)
	case StateRevokingOld:
		return e.revoke(ctx, run)
	}
	return run.State, nil
}

func (e *Engine) fail(ctx context.Context, run runRow, c Class) (State, error) {
	if err := e.store.setState(ctx, run.ID, run.State, StateFailed, c); err != nil {
		return "", err
	}
	return StateFailed, nil
}

func (e *Engine) prepare(ctx context.Context, run runRow, opts Options) (State, error) {
	var v Version
	var err error
	if pv, ok := preparedFrom(ctx); ok {
		// The value was sealed before the run (a human entered it): the run
		// only lays that version out (Service.StartPrepared recorded it under the
		// run already).
		v = pv
	} else {
		v, err = e.versions.Prepare(ctx, run.Ref, run.ID)
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil || !validVersion(v.New) || !validOldVersion(v.Old) || !fingerprint.Valid(v.Fingerprint) {
		return e.fail(ctx, run, ClassPrepareFailed)
	}
	list, err := e.carriers.List(ctx, run.Ref)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return e.fail(ctx, run, ClassPrepareFailed)
	}
	ids := make([]string, 0, len(list))
	for _, c := range list {
		if !validCarrierID(c.ID) {
			return e.fail(ctx, run, ClassPrepareFailed)
		}
		ids = append(ids, c.ID)
	}
	if len(ids) == 0 {
		return e.fail(ctx, run, ClassNoCarriers)
	}
	if err := e.store.begin(ctx, run.ID, v, ids); err != nil {
		return "", err
	}
	return StateDeploying, nil
}

func (e *Engine) deploy(ctx context.Context, run runRow, opts Options) (State, error) {
	steps, err := e.store.steps(ctx, run.ID)
	if err != nil {
		return "", err
	}
	var todo []stepRow
	for _, s := range steps {
		if s.Deploy != "ok" {
			todo = append(todo, s)
		}
	}
	var lost atomic.Bool
	attempts := 1
	if e.forwardOnly() {
		attempts = opts.DeployAttempts
	}
	err = e.forEach(ctx, todo, opts.Concurrency, func(ctx context.Context, s stepRow) bool {
		sctx, stop, ferr := e.fence(ctx, run.ID)
		if ferr != nil {
			lost.Store(true)
			return true
		}
		defer stop()
		if e.afterFence != nil {
			e.afterFence("deploy")
		}
		derr := e.deployer.Deploy(sctx, run.Ref, run.ID, Carrier{ID: s.CarrierID}, run.NewVersion)
		// Forward-only: the old key is gone and the new value is the only
		// one, so a failed layout is tried again before it counts.
		for try := 1; derr != nil && try < attempts && ctx.Err() == nil && sctx.Err() == nil; try++ {
			select {
			case <-ctx.Done():
			case <-sctx.Done():
			case <-time.After(opts.RetryDelay):
				derr = e.deployer.Deploy(sctx, run.Ref, run.ID, Carrier{ID: s.CarrierID}, run.NewVersion)
			}
		}
		if ctx.Err() != nil {
			return true
		}
		if derr != nil {
			if errors.Is(context.Cause(sctx), ErrLeaseLost) { // cut by the end of the lease: not a verdict on the carrier
				lost.Store(true)
				return true
			}
			if errors.Is(e.store.setDeploy(ctx, run.ID, s.CarrierID, "failed", ClassDeployFailed), ErrLeaseLost) {
				lost.Store(true)
			}
			return false
		}
		werr := e.store.setDeploy(ctx, run.ID, s.CarrierID, "ok", ClassNone)
		if errors.Is(werr, ErrLeaseLost) {
			lost.Store(true)
		}
		return werr == nil
	})
	if err != nil {
		return "", err
	}
	if lost.Load() {
		return "", ErrLeaseLost
	}
	ok, err := e.store.allOK(ctx, run.ID, "deploy_state")
	if err != nil {
		return "", err
	}
	if !ok {
		return e.fail(ctx, run, ClassDeployFailed)
	}
	if err := e.store.setState(ctx, run.ID, StateDeploying, StateVerifying, ClassNone); err != nil {
		return "", err
	}
	return StateVerifying, nil
}

func (e *Engine) verify(ctx context.Context, run runRow, opts Options) (State, error) {
	steps, err := e.store.steps(ctx, run.ID)
	if err != nil {
		return "", err
	}
	var todo []stepRow
	for _, s := range steps {
		if s.Verify != "ok" {
			todo = append(todo, s)
		}
	}
	var lost atomic.Bool
	record := func(werr error) bool {
		if errors.Is(werr, ErrLeaseLost) {
			lost.Store(true)
		}
		return werr == nil
	}
	err = e.forEach(ctx, todo, opts.Concurrency, func(ctx context.Context, s stepRow) bool {
		rep, verr := e.verifier.Verify(ctx, run.Ref, Carrier{ID: s.CarrierID}, run.NewVersion)
		if ctx.Err() != nil {
			return true
		}
		switch {
		case verr != nil:
			record(e.store.setVerify(ctx, run.ID, s.CarrierID, "failed", "", ClassVerifyFailed))
		case !fingerprint.Valid(rep.Fingerprint) || rep.Fingerprint != run.ExpectedFP:
			seen := rep.Fingerprint
			if !fingerprint.Valid(seen) {
				seen = ""
			}
			record(e.store.setVerify(ctx, run.ID, s.CarrierID, "failed", seen, ClassFingerprintMismatch))
		case !rep.Healthy:
			record(e.store.setVerify(ctx, run.ID, s.CarrierID, "failed", rep.Fingerprint, ClassUnhealthy))
		default:
			return record(e.store.setVerify(ctx, run.ID, s.CarrierID, "ok", rep.Fingerprint, ClassNone))
		}
		return false
	})
	if err != nil {
		return "", err
	}
	if lost.Load() {
		return "", ErrLeaseLost
	}
	ok, err := e.store.allOK(ctx, run.ID, "verify_state")
	if err != nil {
		return "", err
	}
	if !ok {
		if c, isC := e.versions.(SupersedeChecker); isC {
			if newer, cerr := c.NewerSealed(ctx, run.Ref, run.NewVersion); cerr == nil && newer {
				return e.fail(ctx, run, ClassSuperseded)
			}
		}
		return e.fail(ctx, run, e.store.worstVerifyClass(ctx, run.ID))
	}
	if err := e.store.setState(ctx, run.ID, StateVerifying, StateRevokingOld, ClassNone); err != nil {
		return "", err
	}
	return StateRevokingOld, nil
}

func (e *Engine) revoke(ctx context.Context, run runRow) (State, error) {
	// The state machine reaches here only from verifying with every carrier
	// ok; the database is asked again so a resumed or tampered run cannot
	// revoke on anything less.
	ok, err := e.store.allVerified(ctx, run.ID)
	if err != nil {
		return "", err
	}
	if !ok {
		return e.fail(ctx, run, ClassVerifyFailed)
	}
	if m, ok := e.revoker.(DeployedMarker); ok {
		if err := m.MarkDeployed(ctx, run.Ref, run.ID, run.NewVersion); err != nil {
			return "", err
		}
	}
	if run.OldVersion != "" {
		sctx, stop, err := e.fence(ctx, run.ID)
		if err != nil {
			return "", err
		}
		defer stop()
		if e.afterFence != nil {
			e.afterFence("revoke")
		}
		if rerr := e.revoker.Revoke(sctx, run.Ref, run.ID, run.OldVersion); rerr != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if errors.Is(context.Cause(sctx), ErrLeaseLost) { // revoke cut by the end of the lease
				return "", ErrLeaseLost
			}
			return e.revokePending(ctx, run)
		}
		if run.IncidentOpened {
			// The old key is gone: the "old key alive" incident is over. Before
			// the run is marked done, so a failed resolve is retried with the
			// same run id (Revoke is idempotent) instead of leaving an open alert.
			if err := e.resolveIncident(sctx, ctx, run); err != nil {
				return "", err
			}
		}
	}
	if err := e.store.setState(ctx, run.ID, StateRevokingOld, StateDone, ClassNone); err != nil {
		return "", err
	}
	return StateDone, nil
}

func (e *Engine) resolveIncident(sctx, ctx context.Context, run runRow) error {
	if e.afterFence != nil {
		e.afterFence("resolve")
	}
	if err := e.incident.Resolve(sctx, IncidentRecord{Ref: run.Ref, RunID: run.ID, Class: ClassRevokeFailed}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(context.Cause(sctx), ErrLeaseLost) {
			return ErrLeaseLost
		}
		if ok, herr := e.store.holds(ctx, run.ID, leaseOf(ctx), e.now()); herr == nil && !ok {
			return ErrLeaseLost
		}
		return ErrIncident
	}
	return nil
}

// revokePending handles a refused Revoke: every carrier already holds the new
// version and the old one is alive, so the run is not over. It stays in
// revoking_old with the class recorded (the next Rotate of the same run id
// claims it and retries the revoke only), and the "old key alive" incident is
// opened once, on the first failure.
func (e *Engine) revokePending(ctx context.Context, run runRow) (State, error) {
	if err := e.store.setState(ctx, run.ID, StateRevokingOld, StateRevokingOld, ClassRevokeFailed); err != nil {
		return "", err
	}
	if !run.IncidentOpened {
		run.Class = ClassRevokeFailed
		if err := e.openIncident(ctx, run); err != nil {
			return "", err
		}
	}
	return StateRevokingOld, ErrRevokePending
}

// forEach runs fn over items with bounded parallelism. fn returns false on a
// failed item; no new item starts after the first failure, items already
// running finish. Item failures are recorded by fn itself; only a context
// error is returned.
func (e *Engine) forEach(ctx context.Context, items []stepRow, limit int, fn func(context.Context, stepRow) bool) error {
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	var failed, panicked atomic.Bool
	for _, it := range items {
		sem <- struct{}{}
		if failed.Load() || ctx.Err() != nil {
			<-sem
			break
		}
		wg.Add(1)
		go func(s stepRow) {
			defer wg.Done()
			defer func() { <-sem }()
			// A panic on this goroutine would end the process and print its
			// value; it is dropped here and re-raised below with a fixed text on
			// the caller's goroutine, where the run is failed.
			defer func() {
				if recover() != nil {
					panicked.Store(true)
					failed.Store(true)
				}
			}()
			if !fn(ctx, s) {
				failed.Store(true)
			}
		}(it)
	}
	wg.Wait()
	if panicked.Load() {
		panic("rotation: a collaborator panicked")
	}
	return ctx.Err()
}
