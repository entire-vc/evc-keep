package builtin

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/pkg/provider"
)

// TestWrite_DoesNotExhaustPool is the regression for a bug the fix in this
// file's other tests introduced: an earlier version of Write held the
// org's shared key-level lock on its own pool-acquired connection, on top of
// its own transaction and whatever connection Seal's internal Level/KEK
// lookups happened to borrow — up to three connections live at once for one
// Write. A pool sized for two connections could then be fully consumed by
// as few as two concurrent Write calls, each stuck wanting a third
// connection nothing would ever free — reproduced live under a real pool.
// Write now takes its lock as pg_advisory_xact_lock_shared inside its own
// single transaction, and runs every store call through that same
// transaction (store.withTx, Sealer.WithStore), so one Write needs exactly
// one connection for its entire duration. This test uses a two-connection
// pool and more concurrent writers than that, each under a bounded context
// so a real regression fails this test in seconds instead of hanging it.
func TestWrite_DoesNotExhaustPool(t *testing.T) {
	pool := testPoolSized(t, 2)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")

	const writers = 4
	var wg sync.WaitGroup
	errs := make([]error, writers)
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			p := New(pool, seal, sealer.Scope{Org: org, User: fmt.Sprintf("user%d", i)}, nil)
			_, err := p.Write(ctx, providerRef("s"), secretOf("v"))
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Write[%d]: %v (pool exhausted — Write needs more than one connection at a time again)", i, err)
		}
	}
}

// pausingEnvelopeStore wraps a real sealer.EnvelopeStore and lets a test
// observe, and hold open, the exact window between ChangeLevel acquiring its
// exclusive lock and it finishing Rewrap — the window a lock held only
// around the level row's own read/write (rather than the whole ChangeLevel
// call) used to leave unprotected.
type pausingEnvelopeStore struct {
	sealer.EnvelopeStore
	insideRewrap chan struct{} // closed once Rewrap is called, before delegating
	resume       chan struct{} // Rewrap blocks here until the test closes it
}

// BindToLock keeps the wrapper in place when ChangeLevel rebinds the store to
// its lock connection, so the tests below still pause inside Rewrap and still
// exercise the connection-bound path.
func (p *pausingEnvelopeStore) BindToLock(locked sealer.Store) sealer.EnvelopeStore {
	return &pausingEnvelopeStore{
		EnvelopeStore: p.EnvelopeStore.(sealer.LockBound).BindToLock(locked),
		insideRewrap:  p.insideRewrap,
		resume:        p.resume,
	}
}

func (p *pausingEnvelopeStore) Rewrap(ctx context.Context, org string, fn func(sealer.Ref, sealer.Envelope) (sealer.Envelope, error)) error {
	close(p.insideRewrap)
	<-p.resume
	return p.EnvelopeStore.Rewrap(ctx, org, fn)
}

// TestChangeLevel_LockCoversRewrap_NotJustTheLevelRow proves ChangeLevel's
// exclusive lock is held for its whole operation, including Rewrap — not
// only around reading and writing the level row. Before this, a concurrent
// Provider.Write could read the OLD level, then have its INSERT commit
// after ChangeLevel's Rewrap had already taken its snapshot of existing
// rows (Rewrap ran after the old, narrower lock had already been released):
// that write's envelope would be permanently missed by this ChangeLevel and
// stay under the level it was actually meant to move away from.
//
// This test pins ChangeLevel inside Rewrap (via pausingEnvelopeStore) after
// it has already committed the new level, then starts a concurrent Write
// and requires it to stay blocked until ChangeLevel finishes — proving
// Write's own lock (a pg_advisory_xact_lock_shared on the same key, taken
// inside Write's own transaction) actually contends with ChangeLevel's for
// the org, for the org's entire duration, not just a sliver of it.
func TestChangeLevel_LockCoversRewrap_NotJustTheLevelRow(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")

	pausing := &pausingEnvelopeStore{
		EnvelopeStore: newStore(pool),
		insideRewrap:  make(chan struct{}),
		resume:        make(chan struct{}),
	}
	var resumeOnce sync.Once
	resumeNow := func() { resumeOnce.Do(func() { close(pausing.resume) }) }
	// If an assertion below fails before this test reaches its own
	// close(pausing.resume), ChangeLevel's goroutine is left blocked
	// forever on <-pausing.resume, holding a connection t.Cleanup's
	// pool.Close (see testPool) would then wait for indefinitely — a
	// failing mutation must produce a clean --- FAIL, not hang the whole
	// test binary. resumeOnce makes the explicit close below and this
	// safety net idempotent together.
	t.Cleanup(resumeNow)

	changeErr := make(chan error, 1)
	go func() {
		_, err := seal.ChangeLevel(ctx, sealer.LevelChange{
			Org: org, To: sealer.LevelOrg, Actor: "admin", ConfirmWeakening: true,
		}, pausing)
		changeErr <- err
	}()

	select {
	case <-pausing.insideRewrap:
	case <-time.After(5 * time.Second):
		t.Fatal("ChangeLevel did not reach Rewrap in time")
	}

	// ChangeLevel has committed the new level and is now paused inside
	// Rewrap, still holding the exclusive lock. A concurrent Write for the
	// same org must not be able to acquire its shared lock, and so must not
	// be able to finish, until ChangeLevel releases it.
	p := New(pool, seal, sealer.Scope{Org: org, User: "alice"}, nil)
	writeErr := make(chan error, 1)
	go func() {
		_, err := p.Write(ctx, providerRef("s"), secretOf("v"))
		writeErr <- err
	}()

	select {
	case err := <-writeErr:
		t.Fatalf("Write finished (err=%v) while ChangeLevel was still inside Rewrap — Write is not serialised behind ChangeLevel's lock", err)
	case <-time.After(300 * time.Millisecond):
		// still blocked, as required
	}

	resumeNow()
	if err := <-changeErr; err != nil {
		t.Fatalf("ChangeLevel: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Write could only proceed after ChangeLevel released the lock, so it
	// must have read the level ChangeLevel just set (organization) and used
	// the organisation-wide KEK directly — never a per-user KEK that
	// Rewrap's already-taken snapshot would then have missed forever.
	scope := sealer.Scope{Org: org, User: "alice"}
	row, err := p.db.byVersion(ctx, scope, "s", 1)
	if err != nil {
		t.Fatal(err)
	}
	orgKEK, err := p.db.ActiveFor(ctx, org, scopeKeyForTest(sealer.Scope{Org: org}))
	if err != nil {
		t.Fatal(err)
	}
	if row.kekID != orgKEK.ID {
		t.Fatalf("write's kek_id = %s, want the organisation KEK %s — it escaped the level-change lock", row.kekID, orgKEK.ID)
	}
}

// TestChangeLevel_LockCoversRewrap_FingerprintKey is
// TestChangeLevel_LockCoversRewrap_NotJustTheLevelRow's counterpart for
// Provider.FingerprintKey's own first-call write path — the only other
// caller that takes this lock (see Provider.Write's and FingerprintKey's
// doc comments). Without it, nothing in this suite fails when
// FingerprintKey's lock is defeated: check-builtin-mutations.sh's
// fpkey-lock-is-noop mutation needs this test to be the one that goes red.
func TestChangeLevel_LockCoversRewrap_FingerprintKey(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")

	pausing := &pausingEnvelopeStore{
		EnvelopeStore: newStore(pool),
		insideRewrap:  make(chan struct{}),
		resume:        make(chan struct{}),
	}
	var resumeOnce sync.Once
	resumeNow := func() { resumeOnce.Do(func() { close(pausing.resume) }) }
	t.Cleanup(resumeNow)

	changeErr := make(chan error, 1)
	go func() {
		_, err := seal.ChangeLevel(ctx, sealer.LevelChange{
			Org: org, To: sealer.LevelOrg, Actor: "admin", ConfirmWeakening: true,
		}, pausing)
		changeErr <- err
	}()

	select {
	case <-pausing.insideRewrap:
	case <-time.After(5 * time.Second):
		t.Fatal("ChangeLevel did not reach Rewrap in time")
	}

	p := New(pool, seal, sealer.Scope{Org: org, User: "alice"}, nil)
	fpErr := make(chan error, 1)
	go func() {
		_, err := p.FingerprintKey(ctx)
		fpErr <- err
	}()

	select {
	case err := <-fpErr:
		t.Fatalf("FingerprintKey finished (err=%v) while ChangeLevel was still inside Rewrap — FingerprintKey is not serialised behind ChangeLevel's lock", err)
	case <-time.After(300 * time.Millisecond):
		// still blocked, as required
	}

	resumeNow()
	if err := <-changeErr; err != nil {
		t.Fatalf("ChangeLevel: %v", err)
	}
	if err := <-fpErr; err != nil {
		t.Fatalf("FingerprintKey: %v", err)
	}

	row, err := p.db.byVersion(ctx, sealer.Scope{Org: org, User: "alice"}, fpKeySecretID, 1)
	if err != nil {
		t.Fatal(err)
	}
	orgKEK, err := p.db.ActiveFor(ctx, org, scopeKeyForTest(sealer.Scope{Org: org}))
	if err != nil {
		t.Fatal(err)
	}
	if row.kekID != orgKEK.ID {
		t.Fatalf("fingerprint key's kek_id = %s, want the organisation KEK %s — it escaped the level-change lock", row.kekID, orgKEK.ID)
	}
}

// TestChangeLevel_DoesNotDeadlockOnTightPool: ChangeLevel holds its exclusive
// lock on one connection while writers queued behind it each hold one of
// their own (a Write takes its shared lock inside its own transaction). If
// Rewrap needs one more connection from the same pool, the pool can be
// exhausted by the waiting writers, and neither side can finish: the writers
// wait for the lock, ChangeLevel waits for a connection, and only the
// context deadline ends it. Rewrap runs on the lock's own connection, so a
// pool smaller than the number of writers, and even one with a single
// connection to spare, must still finish.
func TestChangeLevel_DoesNotDeadlockOnTightPool(t *testing.T) {
	for _, tc := range []struct {
		name     string
		poolSize int32
		writers  int
	}{
		{"pool 4, 6 writers", 4, 6},
		{"pool writers+1", 3, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := testPoolSized(t, tc.poolSize)
			seal, _ := testSealer(t, pool)
			org := randID(t, "org")
			admin := NewAdmin(pool, seal, org, nil)

			for i := 0; i < 5; i++ {
				p := New(pool, seal, sealer.Scope{Org: org, User: fmt.Sprintf("seed%d", i)}, nil)
				if _, err := p.Write(context.Background(), providerRef("s"), secretOf("v")); err != nil {
					t.Fatalf("seed write: %v", err)
				}
			}

			var wg sync.WaitGroup
			errs := make([]error, tc.writers+1)
			wg.Add(tc.writers + 1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				_, errs[0] = admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", true)
			}()
			for i := 0; i < tc.writers; i++ {
				go func(i int) {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					p := New(pool, seal, sealer.Scope{Org: org, User: fmt.Sprintf("late%d", i)}, nil)
					_, errs[i+1] = p.Write(ctx, providerRef("s"), secretOf("v"))
				}(i)
			}
			wg.Wait()

			for i, err := range errs {
				if err != nil {
					t.Fatalf("op[%d]: %v", i, err)
				}
			}
		})
	}
}

// TestChangeLevel_NeedsOnlyItsLockConnection is the deterministic form of the
// test above: with a two-connection pool and one connection held elsewhere,
// ChangeLevel has exactly one connection to work with — the one its lock is
// on. It must still finish (Rewrap and the KEK calls run on that connection);
// if any step borrows another from the pool it waits for a connection that
// never comes, and the short deadline turns that into a failure.
func TestChangeLevel_NeedsOnlyItsLockConnection(t *testing.T) {
	pool := testPoolSized(t, 2)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")
	admin := NewAdmin(pool, seal, org, nil)
	for i := 0; i < 3; i++ {
		p := New(pool, seal, sealer.Scope{Org: org, User: fmt.Sprintf("seed%d", i)}, nil)
		if _, err := p.Write(context.Background(), providerRef("s"), secretOf("v")); err != nil {
			t.Fatalf("seed write: %v", err)
		}
	}

	held, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", true)
	if err != nil {
		t.Fatalf("ChangeLevel with one usable connection: %v", err)
	}
	if res.Rewrapped == 0 {
		t.Fatal("nothing was re-wrapped: the test did not exercise Rewrap")
	}
}

// TestLevelLock_ExclusiveExcludesEverything and its two siblings pin down
// store.Lock's own contract directly (bypassing Sealer/Provider) — the
// primitive TestChangeLevel_LockCoversRewrap_NotJustTheLevelRow's higher
// level test builds on.
//
// TestLevelLock_DoesNotCrossOrgBoundary has a mutation
// (check-builtin-mutations.sh's level-lock-any-org). This one and
// TestLevelLock_SharedDoesNotExcludeShared do not: the property they check
// is which of store.Lock's two `if exclusive` branches runs, and swapping
// them does not fail cleanly — a goroutine here ends up waiting on a lock
// nothing will ever release, hanging `go test` itself rather than printing
// a `--- FAIL` a mutation script can grep for (confirmed by hand; see
// check-builtin-mutations.sh's own mutate() doc comment on why a mutant
// that does not reach a failing test is rejected, not just one that
// doesn't build). A mutation for this would need its own `go test
// -timeout` short enough to turn that hang into a clean failing line
// without also hanging the CI job it runs in — left as a follow-up rather
// than shipped half-working.
func TestLevelLock_ExclusiveExcludesEverything(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	db := newStore(pool)
	org := randID(t, "org")

	_, releaseExclusive, err := db.Lock(ctx, org, true)
	if err != nil {
		t.Fatalf("first Lock (exclusive): %v", err)
	}

	acquired := make(chan struct{})
	go func() {
		_, release, err := db.Lock(ctx, org, false)
		if err != nil {
			t.Errorf("second Lock (shared): %v", err)
			return
		}
		close(acquired)
		_ = release(ctx)
	}()

	select {
	case <-acquired:
		t.Fatal("shared Lock acquired while an exclusive Lock for the same org was still held")
	case <-time.After(300 * time.Millisecond):
	}

	if err := releaseExclusive(ctx); err != nil {
		t.Fatalf("release exclusive: %v", err)
	}
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("shared Lock did not acquire after the exclusive Lock was released")
	}
}

func TestLevelLock_SharedDoesNotExcludeShared(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	db := newStore(pool)
	org := randID(t, "org")

	_, release1, err := db.Lock(ctx, org, false)
	if err != nil {
		t.Fatalf("first Lock (shared): %v", err)
	}
	defer func() { _ = release1(ctx) }()

	acquired := make(chan struct{})
	go func() {
		_, release2, err := db.Lock(ctx, org, false)
		if err != nil {
			t.Errorf("second Lock (shared): %v", err)
			return
		}
		close(acquired)
		_ = release2(ctx)
	}()

	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("second shared Lock did not acquire while only another shared Lock was held")
	}
}

func TestLevelLock_DoesNotCrossOrgBoundary(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	db := newStore(pool)
	orgA, orgB := randID(t, "org"), randID(t, "org")

	_, releaseA, err := db.Lock(ctx, orgA, true)
	if err != nil {
		t.Fatalf("Lock orgA: %v", err)
	}
	defer func() { _ = releaseA(ctx) }()

	acquired := make(chan struct{})
	go func() {
		_, releaseB, err := db.Lock(ctx, orgB, true)
		if err != nil {
			t.Errorf("Lock orgB: %v", err)
			return
		}
		close(acquired)
		_ = releaseB(ctx)
	}()

	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("exclusive Lock on a different org blocked behind orgA's lock — Lock is not scoped per organisation")
	}
}

// pausingSetLevel holds a ChangeLevel just before it persists the new level,
// while it already owns the exclusive lock.
type pausingSetLevel struct {
	sealer.Store
	armed  *atomic.Bool
	inside chan struct{}
	resume chan struct{}
	once   *sync.Once
}

func (p *pausingSetLevel) Lock(ctx context.Context, org string, exclusive bool) (sealer.Store, func(context.Context) error, error) {
	locked, release, err := p.Store.Lock(ctx, org, exclusive)
	if err != nil {
		return nil, nil, err
	}
	return &pausingSetLevel{Store: locked, armed: p.armed, inside: p.inside, resume: p.resume, once: p.once}, release, nil
}

func (p *pausingSetLevel) SetLevel(ctx context.Context, org string, l sealer.Level, actor string) error {
	if p.armed.Load() {
		p.once.Do(func() { close(p.inside) })
		<-p.resume
	}
	return p.Store.SetLevel(ctx, org, l, actor)
}

// TestKeyLevelLock_HoldsUnderRepeatableRead: a Write or FingerprintKey that
// waits for the key-level lock must read the level that ChangeLevel has just
// set. Under REPEATABLE READ a transaction's snapshot is taken when its first
// statement starts — the lock request, before it is granted — so a
// transaction that inherited that isolation from the server would read the
// old level and seal under the old KEK. The pool here makes every connection
// default to REPEATABLE READ; the transactions must ask for READ COMMITTED
// themselves.
func TestKeyLevelLock_HoldsUnderRepeatableRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		do   func(p *Provider) error
		row  func(p *Provider) (envelopeRow, error)
	}{
		{
			"Write",
			func(p *Provider) error {
				_, err := p.Write(context.Background(), providerRef("s"), secretOf("v"))
				return err
			},
			func(p *Provider) (envelopeRow, error) { return p.db.byVersion(context.Background(), p.scope, "s", 1) },
		},
		{
			"FingerprintKey",
			func(p *Provider) error { _, err := p.FingerprintKey(context.Background()); return err },
			func(p *Provider) (envelopeRow, error) {
				return p.db.byVersion(context.Background(), p.scope, fpKeySecretID, 1)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pool := testPoolParams(t, 0, map[string]string{"default_transaction_isolation": "repeatable read"})
			var iso string
			if err := pool.QueryRow(ctx, `SHOW default_transaction_isolation`).Scan(&iso); err != nil || iso != "repeatable read" {
				t.Fatalf("test pool isolation = %q, %v: the setting did not reach the connection", iso, err)
			}

			ps := &pausingSetLevel{Store: newStore(pool), armed: &atomic.Bool{}, inside: make(chan struct{}), resume: make(chan struct{}), once: &sync.Once{}}
			k := make([]byte, 32)
			if _, err := rand.Read(k); err != nil {
				t.Fatal(err)
			}
			root, err := sealer.NewLocalRootKey(randID(t, "root"), k)
			if err != nil {
				t.Fatal(err)
			}
			seal := sealer.New(root, &recAudit{}, ps)
			org := randID(t, "org")
			admin := NewAdmin(pool, seal, org, nil)
			if _, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", true); err != nil {
				t.Fatalf("set up organisation level: %v", err)
			}

			var resumeOnce sync.Once
			resumeNow := func() { resumeOnce.Do(func() { close(ps.resume) }) }
			t.Cleanup(resumeNow)
			ps.armed.Store(true)
			changeErr := make(chan error, 1)
			go func() {
				_, err := admin.ChangeLevel(ctx, sealer.LevelUser, "admin", false)
				changeErr <- err
			}()
			select {
			case <-ps.inside:
			case <-time.After(5 * time.Second):
				t.Fatal("ChangeLevel did not reach SetLevel in time")
			}

			p := New(pool, seal, sealer.Scope{Org: org, User: "alice"}, nil)
			done := make(chan error, 1)
			go func() { done <- tc.do(p) }()
			select {
			case err := <-done:
				t.Fatalf("the call finished (err=%v) while ChangeLevel held the lock", err)
			case <-time.After(400 * time.Millisecond):
			}
			resumeNow()
			if err := <-changeErr; err != nil {
				t.Fatalf("ChangeLevel: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatalf("call: %v", err)
			}

			row, err := tc.row(p)
			if err != nil {
				t.Fatal(err)
			}
			aliceKEK, err := p.db.ActiveFor(ctx, org, scopeKeyForTest(p.scope))
			if err != nil {
				t.Fatalf("no per-user KEK for alice: %v", err)
			}
			if row.kekID != aliceKEK.ID {
				t.Fatalf("the level is user, but the new version is sealed under KEK %s, not alice's %s: the call read the old level", row.kekID, aliceKEK.ID)
			}
		})
	}
}

// TestDisable_ConcurrentNeverLeavesZeroActive: N parallel Disable calls, one
// per active version of the same secret, must leave at least one version
// active — exactly N-1 succeed and one gets provider.ErrLastVersion. Read
// then write as separate steps lets every caller see "more than one active"
// and disable its own, leaving none. Repeated, since the window is narrow;
// run on a small pool so a second connection per call would also show up.
func TestDisable_ConcurrentNeverLeavesZeroActive(t *testing.T) {
	const versions = 4
	pool := testPoolSized(t, 3)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for iter := 0; iter < 100; iter++ {
		id := fmt.Sprintf("s%d", iter)
		for v := 1; v <= versions; v++ {
			if _, err := p.Write(ctx, providerRef(id), secretOf("v")); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		errs := make([]error, versions)
		var wg sync.WaitGroup
		wg.Add(versions)
		start := make(chan struct{})
		for v := 1; v <= versions; v++ {
			go func(v int) {
				defer wg.Done()
				<-start
				errs[v-1] = p.Disable(ctx, providerRefVersion(id, fmt.Sprint(v)))
			}(v)
		}
		close(start)
		wg.Wait()

		last := 0
		for _, err := range errs {
			switch {
			case err == nil:
			case errors.Is(err, provider.ErrLastVersion):
				last++
			default:
				t.Fatalf("iter %d: Disable: %v", iter, err)
			}
		}
		active := 0
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM keep_envelope WHERE store_org = $1 AND secret_id = $2 AND status = 'active'`, scope.Org, id).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if active != 1 || last != 1 {
			t.Fatalf("iter %d: %d active version(s), %d ErrLastVersion (errs=%v); want exactly 1 and 1", iter, active, last, errs)
		}
	}
}
