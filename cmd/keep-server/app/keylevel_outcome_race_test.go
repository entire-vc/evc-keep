package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
)

// heldTxOutcomes is the journal a keep-server instance appends with, holding
// every outcome inside the append until release closes; entered receives once
// for each outcome that reached the hold. The outcome of a finished change is
// on its way, its transaction on the claim connection already open.
type heldTxOutcomes struct {
	*audit.Journal
	release chan struct{}
	entered chan struct{}
}

func newHeldTxOutcomes(j *audit.Journal) heldTxOutcomes {
	return heldTxOutcomes{Journal: j, release: make(chan struct{}), entered: make(chan struct{}, 16)}
}

func (h heldTxOutcomes) hold(ctx context.Context, r audit.Record) error {
	if r.Action == audit.ActionOrgKeyLevelRequested {
		return nil
	}
	select {
	case h.entered <- struct{}{}:
	default:
	}
	select {
	case <-h.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h heldTxOutcomes) Append(ctx context.Context, r audit.Record) (audit.Record, error) {
	if err := h.hold(ctx, r); err != nil {
		return audit.Record{}, err
	}
	return h.Journal.Append(ctx, r)
}

func (h heldTxOutcomes) AppendTx(ctx context.Context, tx pgx.Tx, r audit.Record) (audit.Record, error) {
	if err := h.hold(ctx, r); err != nil {
		return audit.Record{}, err
	}
	return h.Journal.AppendTx(ctx, tx, r)
}

// claimSessionPID opens the claim connection of c, with a claim taken and
// given up, and returns its server process id: the writer later holds the
// connection's mutex for as long as its outcome is held.
func claimSessionPID(t *testing.T, f *meshFixture, c *keyLevelClaims) uint32 {
	t.Helper()
	org, id := f.org.ID.String(), uuid.NewString()
	if err := c.take(context.Background(), org, id); err != nil {
		t.Fatalf("warm-up claim: %v", err)
	}
	c.release(org, id)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.PgConn().PID()
}

func terminateSession(t *testing.T, f *meshFixture, pid uint32) {
	t.Helper()
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

func waitEntered(t *testing.T, h heldTxOutcomes) {
	t.Helper()
	select {
	case <-h.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the outcome never reached the journal")
	}
}

// A change finished and its outcome is held; the claim session breaks, and a
// reconcile elsewhere, past the grace, finds the claim free and writes
// change_failed. The writer then gets its claim back and must find that
// outcome: one request, one outcome, whichever came first.
func TestReconcileOverALostClaimLeavesOneOutcome(t *testing.T) {
	withoutClaimKeeper(t)
	f := newMeshFixture(t, false)
	ctx := context.Background()
	base := audit.NewJournal(f.pool)
	held := newHeldTxOutcomes(base)
	first := newKeepServerInstance(t, f, held)
	pid := claimSessionPID(t, f, first.auditor.claims)

	if _, err := first.svc.Change(ctx, f.org.ID, uuid.New(), "project", true); err != nil {
		t.Fatalf("change on the first instance: %v", err)
	}
	waitEntered(t, held)
	terminateSession(t, f, pid)
	n, err := reconcileKeyLevels(ctx, f.pool, base, f.logger, 0)
	if err != nil || n != 1 {
		t.Fatalf("reconcile with the claim lost = %d, %v; want 1", n, err)
	}

	close(held.release)
	if err := first.auditor.Drain(ctx); err != nil {
		t.Fatalf("drain the first instance: %v", err)
	}
	got := outcomeReasons(t, f)
	if len(got) != 2 || !strings.HasPrefix(got[1], "org.key_level.change_failed ") {
		t.Fatalf("journal = %q; want the request and the one reconciled outcome", got)
	}
}

// The reverse order: the writer holds its claim and its outcome is on the way
// when the reconcile runs. The reconcile writes nothing, and the outcome that
// lands is the change's own.
func TestOutcomeUnderAHeldClaimIsTheOnlyOne(t *testing.T) {
	withoutClaimKeeper(t)
	f := newMeshFixture(t, false)
	ctx := context.Background()
	base := audit.NewJournal(f.pool)
	held := newHeldTxOutcomes(base)
	first := newKeepServerInstance(t, f, held)

	if _, err := first.svc.Change(ctx, f.org.ID, uuid.New(), "project", true); err != nil {
		t.Fatalf("change on the first instance: %v", err)
	}
	waitEntered(t, held)
	if n, err := reconcileKeyLevels(ctx, f.pool, base, f.logger, 0); err != nil || n != 0 {
		t.Fatalf("reconcile with the claim held = %d, %v; want 0", n, err)
	}
	close(held.release)
	if err := first.auditor.Drain(ctx); err != nil {
		t.Fatalf("drain the first instance: %v", err)
	}
	if n, err := reconcileKeyLevels(ctx, f.pool, base, f.logger, 0); err != nil || n != 0 {
		t.Fatalf("reconcile after the outcome landed = %d, %v; want 0", n, err)
	}
	got := outcomeReasons(t, f)
	if len(got) != 2 || !strings.HasPrefix(got[1], "org.key_level.changed ") {
		t.Fatalf("journal = %q; want the request and its changed outcome", got)
	}
}

// A claim seen free before the level lock may be taken again before the
// reconcile writes: the reconcile decides by the claim it holds in its own
// transaction, never by the earlier look.
func TestReconcileOrgFencesAClaimTakenAgainAfterTheFirstLook(t *testing.T) {
	f := newMeshFixture(t, false)
	ctx := context.Background()
	org := f.org.ID.String()
	id := journalRequest(t, f, uuid.New(), "project")
	base := audit.NewJournal(f.pool)
	free, err := freeKeyLevelClaims(ctx, f.pool, org, []string{id})
	if err != nil || !free[id] {
		t.Fatalf("first look = %v, %v; want the claim free", free, err)
	}
	claims := newKeyLevelClaims(f.pool)
	t.Cleanup(claims.Close)
	if err := claims.take(ctx, org, id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	reconcile := func() int {
		t.Helper()
		lctx, release, ok, err := builtin.TryLockKeyLevel(ctx, f.pool, org)
		if err != nil || !ok {
			t.Fatalf("level lock = %v, %v", ok, err)
		}
		defer release(ctx)
		n, err := reconcileOrg(lctx, base, org, 0, free)
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		return n
	}
	if n := reconcile(); n != 0 {
		t.Fatalf("reconciled %d requests whose claim was taken again; want 0", n)
	}
	claims.release(org, id)
	if n := reconcile(); n != 1 {
		t.Fatalf("with the claim free again = %d; want 1", n)
	}
}
