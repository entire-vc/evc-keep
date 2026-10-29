package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Override-lock modes (tenancy model §3).
const (
	ModeName  = "name"
	ModeClass = "class"
	ModeStore = "store"
)

// OverrideLock is an override_locks row: "below this level, this selector
// cannot be (re)defined" (mode name/class), or "must live in one of these
// stores" (mode store) — tenancy model §3.
type OverrideLock struct {
	ID              uuid.UUID
	OrgID           uuid.UUID
	Scope           tenancy.Scope
	SelectorName    *string
	SelectorClass   *string
	Mode            string
	AllowedStoreIDs []uuid.UUID
	CreatedAt       time.Time
}

// CreateOverrideLock inserts a name or class lock at scope. selectorName is
// used (and required) only for mode=[ModeName]; selectorClass for
// mode=[ModeClass] or mode=[ModeStore]. Pass "" for whichever does not
// apply. allowedStores is required (and used) only for mode=[ModeStore].
//
// scope must name an existing org/ws/proj scope of org — gated the same way
// as [tenancy.Repo.CreateService], via the schema's own keep_validate_scope,
// so an org that scope does not belong to is refused as
// [apperr.ClassInvalidArgument] instead of surfacing the table's CHECK
// constraint unclassified.
//
// The INSERT runs inside a transaction that first takes [lockScope] on
// (org, scope) — the same lock CreateRef's ancestor walk takes before
// reading locks at that scope — so a lock created here and a CreateRef
// racing against it can only ever resolve as one of the two sequential
// orderings; see concurrency_test.go.
func (c *Catalog) CreateOverrideLock(ctx context.Context, org uuid.UUID, scope tenancy.Scope, mode, selectorName, selectorClass string, allowedStores []uuid.UUID) (OverrideLock, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return OverrideLock{}, fmt.Errorf("catalog: generate override lock id: %w", err)
	}
	var namePtr, classPtr *string
	if selectorName != "" {
		namePtr = &selectorName
	}
	if selectorClass != "" {
		classPtr = &selectorClass
	}
	var storeIDs any
	if len(allowedStores) > 0 {
		storeIDs = allowedStores
	}

	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return OverrideLock{}, fmt.Errorf("catalog: begin create override lock: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed below

	if err := lockScope(ctx, tx, org, scope); err != nil {
		return OverrideLock{}, err
	}

	beforeInsertHook(ctx)

	var l OverrideLock
	err = tx.QueryRow(ctx,
		`INSERT INTO override_locks (id, org_id, scope_level, scope_id, selector_name, selector_class, mode, allowed_store_ids)
		 SELECT $1, $2, $3, $4, $5, $6, $7, $8 WHERE keep_validate_scope($2, $3, $4)
		 RETURNING id, org_id, scope_level, scope_id, selector_name, selector_class, mode, allowed_store_ids, created_at`,
		id, org, string(scope.Level), scope.ID, namePtr, classPtr, mode, storeIDs,
	).Scan(&l.ID, &l.OrgID, &l.Scope.Level, &l.Scope.ID, &l.SelectorName, &l.SelectorClass, &l.Mode, &l.AllowedStoreIDs, &l.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OverrideLock{}, invalidScope("scope does not belong to this organization")
		}
		return OverrideLock{}, fmt.Errorf("catalog: create override lock: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return OverrideLock{}, fmt.Errorf("catalog: commit create override lock: %w", err)
	}
	return l, nil
}

// locksAt returns every lock defined exactly at scope, all modes included —
// unlike internal/tenancy's own (name/class-only) reader, CreateRef also
// needs mode=[ModeStore] locks to police which store a new secret may land
// in. Rows are read FOR SHARE: called from inside CreateRef's transaction,
// after it has taken [lockScope] on the same scope, this is what lets a
// concurrent CreateOverrideLock's own [lockScope] wait rather than race it —
// see that function's doc.
func locksAt(ctx context.Context, db dbtx, org uuid.UUID, scope tenancy.Scope) ([]OverrideLock, error) {
	rows, err := db.Query(ctx,
		`SELECT id, org_id, scope_level, scope_id, selector_name, selector_class, mode, allowed_store_ids, created_at
		 FROM override_locks WHERE org_id = $1 AND scope_level = $2 AND scope_id = $3 FOR SHARE`,
		org, string(scope.Level), scope.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("catalog: lookup locks: %w", err)
	}
	defer rows.Close()
	var out []OverrideLock
	for rows.Next() {
		var l OverrideLock
		if err := rows.Scan(&l.ID, &l.OrgID, &l.Scope.Level, &l.Scope.ID, &l.SelectorName, &l.SelectorClass, &l.Mode, &l.AllowedStoreIDs, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("catalog: scan lock: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: lookup locks: %w", err)
	}
	return out, nil
}

func containsStore(ids []uuid.UUID, id uuid.UUID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// overrideLockedError is CreateRef's rejection for a name/class/store lock
// match — always names the selector and the blocking level, never anything
// about the secret's value (there is none to name).
func overrideLockedError(what, value string, at tenancy.Level) *apperr.Error {
	return apperr.New(apperr.ClassOverrideLocked,
		fmt.Sprintf("%s %q is locked at %s", what, value, at))
}
