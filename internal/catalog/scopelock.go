package catalog

import (
	"context"
	"fmt"

	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// lockScope takes a Postgres transaction-scoped advisory lock keyed by
// (org, scope) — released automatically at commit or rollback, never held
// past the transaction that took it.
//
// CreateRef's ancestor walk and CreateOverrideLock's own write both take
// this same lock for the scope an OverrideLock could be created at, before
// either one reads or writes anything else: whichever gets there first
// blocks the other for the rest of its transaction, so the pair can only
// resolve two ways — the loser's transaction sees the winner's committed
// change (a lock CreateRef must obey, or a secret CreateOverrideLock has no
// reason to care about), or the loser starts and finishes only after the
// winner has fully committed. Either way the final state matches some
// sequential order of the two calls; see catalog.go's CreateRef doc and
// concurrency_test.go, which exercises exactly this pair.
//
// Two int4 keys (hashtext of the org and of the scope's own "level:id"
// text) rather than packing both into one bigint, so a false collision
// between two unrelated (org, scope) pairs needs both halves to coincide,
// not just one 32-bit hash.
func lockScope(ctx context.Context, db dbtx, org uuid.UUID, scope tenancy.Scope) error {
	_, err := db.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
		org.String(), scope.String())
	if err != nil {
		return fmt.Errorf("catalog: acquire scope lock: %w", err)
	}
	return nil
}
