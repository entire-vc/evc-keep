package app

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/reqid"
)

// claimFree reports whether no session holds the claim of request id of org.
func claimFree(t *testing.T, f *meshFixture, org, id string) bool {
	t.Helper()
	free, err := freeKeyLevelClaims(context.Background(), f.pool, org, []string{id})
	if err != nil {
		t.Fatalf("read claims: %v", err)
	}
	return free[id]
}

func waitClaimFree(t *testing.T, f *meshFixture, org, id string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if claimFree(t, f, org, id) {
			return
		}
	}
	t.Fatal("the claim is still held")
}

// drainWithin stops a, giving up on outcomes a journal that never takes them
// still holds: a test's journal may fail on purpose to the end.
func drainWithin(a *keyLevelAuditor, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	_ = a.Drain(ctx)
}

func newClaimingAuditor(t *testing.T, f *meshFixture, j audit.Journaler) *keyLevelAuditor {
	t.Helper()
	claims := newKeyLevelClaims(f.pool)
	a := newKeyLevelAuditor(j, f.logger, claims)
	t.Cleanup(func() { drainWithin(a, 2*time.Second); claims.Close() })
	return a
}

// The claim outlives the change until its outcome is in the journal, not
// merely queued for it.
func TestKeyLevelClaimHeldUntilItsOutcomeIsJournaled(t *testing.T) {
	f := newMeshFixture(t, false)
	j := &slowJournal{release: make(chan struct{})}
	a := newClaimingAuditor(t, f, j)
	// slowJournal waits for release alone: let it go before the drain on a
	// failed run, or the drain waits on it for good.
	opened := false
	t.Cleanup(func() {
		if !opened {
			close(j.release)
		}
	})
	org, id := f.org.ID.String(), reqid.New()
	if err := a.claim(context.Background(), org, id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	a.record(builtin.KeyEvent{Action: "key_level_changed", Org: org, RequestID: id, From: "user", To: "project"})
	a.settle(org, id)
	time.Sleep(50 * time.Millisecond)
	if claimFree(t, f, org, id) {
		t.Fatal("the claim went free while its outcome waits for the journal")
	}
	opened = true
	close(j.release)
	waitWritten(t, j, 1)
	waitClaimFree(t, f, org, id)
}

// A change that reported nothing (its request was refused) frees its claim.
func TestKeyLevelClaimReleasedWhenNoOutcomeFollows(t *testing.T) {
	f := newMeshFixture(t, false)
	a := newClaimingAuditor(t, f, audit.NewJournal(f.pool))
	org, id := f.org.ID.String(), reqid.New()
	if err := a.claim(context.Background(), org, id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimFree(t, f, org, id) {
		t.Fatal("a claim just taken reads as free")
	}
	a.settle(org, id)
	waitClaimFree(t, f, org, id)
}

// A mark settled after the stop began may stand behind an outcome still on
// its way: the claim stays until the flush reaches the mark or the claims are
// closed with the process.
func TestKeyLevelClaimKeptAfterStopUntilClose(t *testing.T) {
	f := newMeshFixture(t, false)
	claims := newKeyLevelClaims(f.pool)
	a := newKeyLevelAuditor(audit.NewJournal(f.pool), f.logger, claims)
	org, id := f.org.ID.String(), reqid.New()
	if err := a.claim(context.Background(), org, id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := a.Drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	a.settle(org, id)
	if claimFree(t, f, org, id) {
		t.Fatal("a claim settled after the stop went free before the claims were closed")
	}
	claims.Close()
	if !claimFree(t, f, org, id) {
		t.Fatal("closing the claims left the claim held")
	}
}

// withoutClaimKeeper stops the periodic check for claims made in the test, so
// what the test sees is the path it names.
func withoutClaimKeeper(t *testing.T) {
	old := keyLevelClaimKeepEvery
	keyLevelClaimKeepEvery = time.Hour
	t.Cleanup(func() { keyLevelClaimKeepEvery = old })
}

// killClaimSession ends the claim connection's session on the server side and
// returns once the session is gone, so a claim seen held afterwards was taken again.
func killClaimSession(t *testing.T, f *meshFixture, c *keyLevelClaims) {
	t.Helper()
	c.mu.Lock()
	pid := c.conn.PgConn().PID()
	c.mu.Unlock()
	if _, err := f.pool.Exec(context.Background(), `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var alive bool
		if err := f.pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1)`, pid).Scan(&alive); err != nil {
			t.Fatalf("read sessions: %v", err)
		}
		if !alive {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the claim session outlived its termination")
		}
	}
}

func waitClaimHeld(t *testing.T, f *meshFixture, org, id string, within time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if !claimFree(t, f, org, id) {
			return
		}
	}
	t.Fatal("a claim lost with its session was not taken again")
}

// With no further change in the process, a claim lost with its session is
// taken again by the periodic check, not left free until the next change.
func TestKeyLevelClaimKeptAfterItsSessionBroke(t *testing.T) {
	old := keyLevelClaimKeepEvery
	keyLevelClaimKeepEvery = 100 * time.Millisecond
	t.Cleanup(func() { keyLevelClaimKeepEvery = old })
	f := newMeshFixture(t, false)
	a := newClaimingAuditor(t, f, audit.NewJournal(f.pool))
	org, id := f.org.ID.String(), reqid.New()
	if err := a.claim(context.Background(), org, id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	killClaimSession(t, f, a.claims)
	waitClaimHeld(t, f, org, id, 3*time.Second)
}

// The writer takes a lost claim again before it appends the outcome, so a
// retrying outcome is not left without its claim.
func TestKeyLevelOutcomeWriteTakesALostClaimAgain(t *testing.T) {
	withoutClaimKeeper(t)
	f := newMeshFixture(t, false)
	j := &slowJournal{release: make(chan struct{}), failFirst: 1 << 30}
	close(j.release)
	a := newClaimingAuditor(t, f, j)
	a.backoff = 20 * time.Millisecond
	org, id := f.org.ID.String(), reqid.New()
	if err := a.claim(context.Background(), org, id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	a.record(builtin.KeyEvent{Action: "key_level_changed", Org: org, RequestID: id, From: "user", To: "project"})
	a.settle(org, id)
	killClaimSession(t, f, a.claims)
	waitClaimHeld(t, f, org, id, 3*time.Second)
}

// A broken claim connection loses its locks; the next claim reopens it and
// takes every claim still held again.
func TestKeyLevelClaimTakenAgainAfterItsConnectionBroke(t *testing.T) {
	withoutClaimKeeper(t)
	f := newMeshFixture(t, false)
	a := newClaimingAuditor(t, f, audit.NewJournal(f.pool))
	ctx := context.Background()
	org, first := f.org.ID.String(), reqid.New()
	if err := a.claim(ctx, org, first); err != nil {
		t.Fatalf("claim: %v", err)
	}
	killClaimSession(t, f, a.claims)
	waitClaimFree(t, f, org, first) // the lock went with the session
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		err := a.claim(ctx, org, reqid.New())
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("claim after the connection broke: %v", err)
		}
	}
	if claimFree(t, f, org, first) {
		t.Fatal("a claim held before the connection broke was not taken again")
	}
}

// A request whose claim is held belongs to a change whose outcome is on its
// way, whichever process holds it and however old the request.
func TestReconcileSkipsARequestWhoseClaimIsHeld(t *testing.T) {
	f := newMeshFixture(t, false)
	ctx := context.Background()
	id := journalRequest(t, f, uuid.New(), "project")
	claims := newKeyLevelClaims(f.pool)
	t.Cleanup(claims.Close)
	if err := claims.take(ctx, f.org.ID.String(), id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	j := audit.NewJournal(f.pool)
	if n, err := reconcileKeyLevels(ctx, f.pool, j, f.logger, 0); err != nil || n != 0 {
		t.Fatalf("with the claim held = %d, %v; want 0", n, err)
	}
	claims.release(f.org.ID.String(), id)
	if n, err := reconcileKeyLevels(ctx, f.pool, j, f.logger, 0); err != nil || n != 1 {
		t.Fatalf("with the claim free = %d, %v; want 1", n, err)
	}
}

// A change that cannot claim its request does not start: nothing is journaled
// and the level stays.
func TestKeyLevelChangeRefusedWithoutAClaim(t *testing.T) {
	f := newMeshFixture(t, false)
	svc := keyLevelService{pool: f.pool, local: f.local, j: audit.NewJournal(f.pool), log: f.logger}
	if _, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true); err == nil {
		t.Fatal("a change without a claim ran")
	}
	if got := outcomeReasons(t, f); len(got) != 0 {
		t.Fatalf("journal = %q; want nothing", got)
	}
	if lvl := keyLevelOf(t, f); lvl != defaultKeyLevel {
		t.Fatalf("level = %q; want %q", lvl, defaultKeyLevel)
	}
}

// runServe hands the claims to the outcome sink and the sink to the change
// service: without either a change holds no claim in production.
func TestServeWiresTheClaimsIntoTheChange(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal("read main.go")
	}
	src := string(raw)
	for _, want := range []string{
		"auditor := newKeyLevelAuditor(journal, logger, claims)",
		"meshDeps(cfg, pool, local, auditor, gates, journal, logger)",
		"keyLevelService{pool: pool, local: local, j: journal, log: logger, outcomes: outcomes}",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("main.go does not wire %q", want)
		}
	}
}

// A client that hangs up while its change takes the claim does not cost the
// claims other changes hold: the claim runs on its own deadline.
func TestKeyLevelClaimIgnoresTheRequestCancel(t *testing.T) {
	withoutClaimKeeper(t)
	f := newMeshFixture(t, false)
	a := newClaimingAuditor(t, f, audit.NewJournal(f.pool))
	org, held := f.org.ID.String(), reqid.New()
	if err := a.claim(context.Background(), org, held); err != nil {
		t.Fatalf("claim: %v", err)
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.claim(gone, org, reqid.New()); err != nil {
		t.Fatalf("claim on a cancelled request: %v", err)
	}
	if claimFree(t, f, org, held) {
		t.Fatal("a cancelled request dropped another change's claim")
	}
}
