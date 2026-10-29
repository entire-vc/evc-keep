package tenancy

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// secretAt looks up the secret named name defined exactly at scope (no
// hierarchy walk — that is [Repo.Resolve]'s job, which calls this once per
// level in the chain).
func (r *Repo) secretAt(ctx context.Context, org uuid.UUID, scope Scope, name string) (SecretRef, bool, error) {
	var s SecretRef
	s.Scope = scope
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, name, class, type, store_id, provider_ref, description, status, created_at, updated_at
		 FROM secrets
		 WHERE org_id = $1 AND scope_level = $2 AND scope_id = $3 AND name = $4`,
		org, string(scope.Level), scope.ID, name,
	).Scan(&s.ID, &s.OrgID, &s.Name, &s.Class, &s.Type, &s.StoreID, &s.ProviderRef, &s.Description, &s.Status, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SecretRef{}, false, nil
		}
		return SecretRef{}, false, fmt.Errorf("tenancy: lookup secret: %w", err)
	}
	return s, true, nil
}

// lockRow is the subset of an override_locks row [Repo.Resolve] needs to
// evaluate the blocking rule (tenancy model §3 step 2). It never reads
// mode='store' locks' allowed_store_ids — those only matter to
// internal/catalog.CreateRef's store-choice enforcement, never to name
// resolution (see the 00003_catalog.sql migration's comment on that table).
type lockRow struct {
	mode          string
	selectorName  *string
	selectorClass *string
}

// locksAt returns the name/class locks defined exactly at scope. It never
// returns mode='store' locks — Resolve has no use for them (see [lockRow]).
func (r *Repo) locksAt(ctx context.Context, org uuid.UUID, scope Scope) ([]lockRow, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT mode, selector_name, selector_class FROM override_locks
		 WHERE org_id = $1 AND scope_level = $2 AND scope_id = $3 AND mode IN ('name', 'class')`,
		org, string(scope.Level), scope.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("tenancy: lookup locks: %w", err)
	}
	defer rows.Close()
	var out []lockRow
	for rows.Next() {
		var l lockRow
		if err := rows.Scan(&l.mode, &l.selectorName, &l.selectorClass); err != nil {
			return nil, fmt.Errorf("tenancy: scan lock: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenancy: lookup locks: %w", err)
	}
	return out, nil
}
