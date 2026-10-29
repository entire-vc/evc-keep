// Concurrency tests for the two TOCTOU findings closed by this change:
// CreateRef racing a concurrent CreateOverrideLock, and CreateStoreBinding
// racing a concurrent change to the store it is about to bind.
//
// Both force a deterministic overlap through the package's own
// beforeInsertHook seam instead of hoping the Go scheduler and Postgres
// round trips happen to collide — the same reason pkg/runnerproto's
// TestReplayConcurrent parks every claimer on a real mutex before releasing
// them together rather than just starting goroutines and hoping (see that
// test's own doc). Every round uses a bounded wait (time.After, never an
// unbounded channel receive) so a defect that causes a hang fails the test
// instead of hanging the suite.
package catalog

import (
	"fmt"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// awaitSignal blocks on ch for up to d, and reports whether it fired.
// Bounded like this rather than an unbounded <-ch: a hang is this test's own
// bug turning into a hung suite, not a useful failure.
func awaitSignal(ch <-chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// releaseAfterBoundedWait waits up to d to see whether the unpaused side of
// a round finishes on its own — on the fixed code it cannot, kept
// blocked by the other side's own lock — then closes proceed (releasing
// whichever side is paused at its beforeInsertHook) and drains done until
// both of the round's two completions have arrived, however many had
// already arrived before the release. It returns whether the unpaused side
// completed before release. done must have capacity for both.
func releaseAfterBoundedWait(t *testing.T, done <-chan struct{}, proceed chan<- struct{}, d time.Duration) bool {
	t.Helper()
	received := 0
	select {
	case <-done:
		received = 1
	case <-time.After(d):
	}
	early := received != 0
	close(proceed)
	for received < 2 {
		if !awaitSignal(done, 5*time.Second) {
			t.Fatal("operation never completed after releasing the paused transaction")
		}
		received++
	}
	return early
}

// TestCreateRef_OverrideLockRace pins finding #1's CreateRef half: a
// mode=store OverrideLock created at an ancestor scope and a concurrent
// CreateRef targeting a non-conforming store in that ancestor's chain must
// resolve as one of exactly two sequential orderings — never "CreateRef's
// check ran before the lock existed, but its INSERT landed after" (the
// TOCTOU the old, transaction-free CreateRef/CreateOverrideLock had: see
// this file's package doc and catalog.go's CreateRef doc).
//
// Every round pauses one side at its own beforeInsertHook and starts the
// other second, forcing a specific ordering instead of hoping the scheduler
// produces one: even rounds pause CreateRef, which by the time it pauses has
// already taken the ws advisory lock and already cached its ancestor locks
// (both happen before the hook) — so CreateOverrideLock, started after,
// blocks on that same lock and can only commit once CreateRef is released
// and finishes first; CreateRef's own already-cached read never saw the
// lock, so both succeed and the ref's commit must predate the lock's
// ("the ref wins"). Odd rounds pause CreateOverrideLock instead — it has
// already taken the ws lock but not yet inserted its row when it pauses, so
// CreateRef, started after, blocks acquiring that same lock and can only
// read ancestor locks once CreateOverrideLock is released, commits, and
// releases it — by which point the lock row exists, so CreateRef's own read
// sees it and refuses with override_locked ("the lock wins"). N=60 rounds,
// 30 of each — both outcomes are exercised directly, not left to scheduler
// luck.
//
// Red run (finding #1): with the ancestor lockScope calls removed from
// CreateRef and CreateOverrideLock (see scripts/check-tenancy-mutations.sh's
// createref-no-scope-lock / createoverridelock-no-scope-lock mutations),
// this test fails because the unpaused side completes before the paused
// transaction releases its lock. The two calls can then interleave freely.
// See the MR's "Red run" section for the captured output.
func TestCreateRef_OverrideLockRace(t *testing.T) {
	f := newFixture(t)
	orgScope := tenancy.Org(f.org.ID)
	// Both stores are owned by org, so both are in every round's chain
	// (requireUsableStore accepts either) — only the lock's own
	// allowed_store_ids decides which one is compliant.
	compliant := f.mustStore("race-compliant", orgScope)
	nonConforming := f.mustExternalStore("race-non-conforming", orgScope)

	const rounds = 60
	for round := 0; round < rounds; round++ {
		round := round
		t.Run(fmt.Sprintf("round-%02d", round), func(t *testing.T) {
			ws := f.mustWorkspace(fmt.Sprintf("race-ws-%d", round))
			proj := f.mustProject(ws, "proj")
			wsScope := tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}
			projScope := tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID}
			class := fmt.Sprintf("race-class-%d", round)

			refInput := CreateRefInput{
				Org: f.org.ID, Scope: projScope, Name: "SECRET", Class: class,
				Type: "generic", ProviderRef: "x", StoreID: nonConforming.ID,
			}

			reached := make(chan struct{})
			proceed := make(chan struct{})
			pausedCtx := withBeforeInsertHook(f.ctx, func() {
				close(reached)
				<-proceed
			})

			var (
				refErr, lockErr           error
				unpausedFinishedEarly     bool
				refFinished, lockFinished bool
			)
			done := make(chan struct{}, 2)

			if round%2 == 0 {
				// Pause CreateRef (it has already taken the ws lock and
				// already cached its — lock-free — ancestor read); let
				// CreateOverrideLock start and block behind it — expect
				// both to succeed, ref's commit first ("the ref wins").
				go func() {
					_, refErr = f.cat.CreateRef(pausedCtx, refInput)
					refFinished = true
					done <- struct{}{}
				}()
				if !awaitSignal(reached, 5*time.Second) {
					t.Fatal("CreateRef never reached its beforeInsertHook — the paused branch did not run")
				}
				go func() {
					_, lockErr = f.cat.CreateOverrideLock(f.ctx, f.org.ID, wsScope, ModeStore, "", class, []uuid.UUID{compliant.ID})
					lockFinished = true
					done <- struct{}{}
				}()
				// Bounded wait: on the fixed code CreateOverrideLock blocks
				// on the ws advisory lock CreateRef already holds, so this
				// window elapses without it finishing — that is expected,
				// not a failure. Release CreateRef either way.
				unpausedFinishedEarly = releaseAfterBoundedWait(t, done, proceed, 150*time.Millisecond)
			} else {
				// Pause CreateOverrideLock (it has already taken the ws
				// lock but not yet inserted its row); let CreateRef start
				// and block behind it, so CreateRef's own ancestor read
				// only happens after the lock row exists — expect
				// override_locked ("the lock wins").
				go func() {
					lockErr = func() error {
						_, err := f.cat.CreateOverrideLock(pausedCtx, f.org.ID, wsScope, ModeStore, "", class, []uuid.UUID{compliant.ID})
						return err
					}()
					lockFinished = true
					done <- struct{}{}
				}()
				if !awaitSignal(reached, 5*time.Second) {
					t.Fatal("CreateOverrideLock never reached its beforeInsertHook — the paused branch did not run")
				}
				go func() {
					_, refErr = f.cat.CreateRef(f.ctx, refInput)
					refFinished = true
					done <- struct{}{}
				}()
				unpausedFinishedEarly = releaseAfterBoundedWait(t, done, proceed, 150*time.Millisecond)
			}

			if !refFinished || !lockFinished {
				t.Fatalf("round %d: refFinished=%v lockFinished=%v — a goroutine never returned", round, refFinished, lockFinished)
			}

			// Observe the lock before releasing the paused transaction. Client
			// completion timestamps do not represent PostgreSQL commit order:
			// network acknowledgements and goroutine scheduling can reverse them.
			if unpausedFinishedEarly {
				t.Fatalf("round %d: unpaused operation completed before the paused transaction released its scope lock", round)
			}
			if lockErr != nil {
				t.Fatalf("round %d: CreateOverrideLock failed: %v", round, lockErr)
			}
			if round%2 == 0 {
				if refErr != nil {
					t.Fatalf("round %d: CreateRef should win before the lock: %v", round, refErr)
				}
			} else {
				var ae *apperr.Error
				if !isAppErr(refErr, &ae) || ae.Class != apperr.ClassOverrideLocked {
					t.Fatalf("round %d: CreateRef failed with %v, want apperr.ClassOverrideLocked", round, refErr)
				}
			}
		})
	}
}

// TestCreateStoreBinding_DisableRace pins finding #1's CreateStoreBinding
// half: requireUsableStore's check and the binding INSERT it gates must be
// atomic with respect to a concurrent status change on the same store row.
// CreateStoreBinding reads the store row FOR SHARE inside its own
// transaction (see store.go's own doc); this test proves that lock is load
// bearing by racing a raw SQL status flip against it directly (there is no
// store-mutating admin surface yet — see requireUsableStore's doc).
//
// Red run (finding #1): with CreateStoreBinding's transaction removed (its
// requireUsableStore check and INSERT done as two separate round trips, the
// way the pre-fix code did it — see scripts/check-tenancy-mutations.sh's
// binding-store-unchecked-style mutations for the same shape applied
// elsewhere), nothing blocks the disable below while CreateStoreBinding is
// paused, so it completes well inside the bounded wait — the test below
// catches exactly that. See the MR's "Red run" section for the captured
// output.
func TestCreateStoreBinding_DisableRace(t *testing.T) {
	f := newFixture(t)
	orgScope := tenancy.Org(f.org.ID)

	const rounds = 50
	for round := 0; round < rounds; round++ {
		round := round
		t.Run(fmt.Sprintf("round-%02d", round), func(t *testing.T) {
			ws := f.mustWorkspace(fmt.Sprintf("disable-ws-%d", round))
			wsScope := tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}
			store := f.mustExternalStore(fmt.Sprintf("disable-store-%d", round), orgScope)

			reached := make(chan struct{})
			proceed := make(chan struct{})
			pausedCtx := withBeforeInsertHook(f.ctx, func() {
				close(reached)
				<-proceed
			})

			var (
				bindErr, disableErr error
				bindFinished        bool
				disableFinished     bool
			)
			bindDoneCh := make(chan struct{})
			go func() {
				_, bindErr = f.cat.CreateStoreBinding(pausedCtx, f.org.ID, wsScope, store.ID)
				bindFinished = true
				close(bindDoneCh)
			}()
			if !awaitSignal(reached, 5*time.Second) {
				t.Fatal("CreateStoreBinding never reached its beforeInsertHook")
			}

			disableDoneCh := make(chan struct{})
			go func() {
				_, disableErr = f.cat.pool.Exec(f.ctx, `UPDATE stores SET status = 'disabled' WHERE id = $1`, store.ID)
				disableFinished = true
				close(disableDoneCh)
			}()
			// The assertion is this select's outcome, not a wall-clock
			// comparison taken after both sides finish: two independent
			// goroutines' client-side "done" timestamps race each other's
			// own scheduling and network-ack jitter regardless of which DB
			// event truly happened first, so comparing time.Now() readings
			// across them is not a reliable proxy for server-side lock
			// order (confirmed directly — the version of this test that did
			// that flaked a real, non-mutated tree about 1 round in 100).
			// What is reliable: on the fixed code, the store row is held
			// FOR SHARE by CreateStoreBinding's own open transaction, so
			// this UPDATE cannot even start until that transaction commits
			// — it must still be blocked when the bounded wait below
			// elapses, 150ms being enormously larger than one local round
			// trip once unblocked.
			disabledEarly := false
			select {
			case <-disableDoneCh:
				disabledEarly = true
			case <-time.After(150 * time.Millisecond):
			}
			close(proceed)
			<-bindDoneCh
			<-disableDoneCh

			if !bindFinished || !disableFinished {
				t.Fatalf("round %d: bindFinished=%v disableFinished=%v", round, bindFinished, disableFinished)
			}
			if bindErr != nil {
				t.Fatalf("round %d: CreateStoreBinding failed: %v (store was active when checked)", round, bindErr)
			}
			if disableErr != nil {
				t.Fatalf("round %d: disable UPDATE failed: %v", round, disableErr)
			}
			if disabledEarly {
				t.Fatalf("round %d: the disable UPDATE completed while CreateStoreBinding was still paused inside its own open transaction — the store row's FOR SHARE lock did not block a concurrent write to it", round)
			}
		})
	}
}
