package app

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
)

// heldOutcomes passes the request through and holds every outcome until
// release closes: the outcome of a finished change is still on its way to the
// journal, as when the journal is slow or the writer is behind.
type heldOutcomes struct {
	audit.Journaler
	release chan struct{}
}

func (h heldOutcomes) Append(ctx context.Context, r audit.Record) (audit.Record, error) {
	if r.Action != audit.ActionOrgKeyLevelRequested {
		select {
		case <-h.release:
		case <-ctx.Done():
			return audit.Record{}, ctx.Err()
		}
	}
	return h.Journaler.Append(ctx, r)
}

// keepServerInstance is one keep-server process over the shared database: its
// own outcome sink and its own sealer, as main wires them.
type keepServerInstance struct {
	auditor *keyLevelAuditor
	svc     keyLevelService
}

func newKeepServerInstance(t *testing.T, f *meshFixture, j audit.Journaler) keepServerInstance {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("root key")
	}
	claims := newKeyLevelClaims(f.pool)
	a := newKeyLevelAuditor(j, f.logger, claims)
	t.Cleanup(func() { drainWithin(a, 2*time.Second); claims.Close() })
	local, err := builtin.NewLocal(f.pool, "instance-root-"+uuid.NewString(), raw, f.logger, a.record)
	if err != nil {
		t.Fatalf("local backend: %v", err)
	}
	return keepServerInstance{auditor: a, svc: keyLevelService{pool: f.pool, local: local, j: audit.NewJournal(f.pool), log: f.logger, outcomes: a}}
}

// Two keep-server instances over one database. The first finished a change and
// its outcome is not in the journal yet; the second runs its reconcile past the
// grace. What the first still has to write is not visible in the second
// process, so the decision has to come from the database: the second instance
// must not write change_failed over a change that succeeded.
func TestReconcileOfAnotherInstanceLeavesAPendingOutcomeAlone(t *testing.T) {
	f := newMeshFixture(t, false)
	ctx := context.Background()
	base := audit.NewJournal(f.pool)
	held := heldOutcomes{Journaler: base, release: make(chan struct{})}
	first := newKeepServerInstance(t, f, held)

	if _, err := first.svc.Change(ctx, f.org.ID, uuid.New(), "project", true); err != nil {
		t.Fatalf("change on the first instance: %v", err)
	}
	if got := outcomeReasons(t, f); len(got) != 1 || !strings.HasPrefix(got[0], "org.key_level.requested ") {
		t.Fatalf("journal before the outcome is written = %q", got)
	}
	n, err := reconcileKeyLevels(ctx, f.pool, base, f.logger, 0)
	if err != nil {
		t.Fatalf("reconcile on the second instance: %v", err)
	}
	if n != 0 {
		t.Fatalf("the second instance reconciled %d requests whose outcome the first still holds; want 0", n)
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
