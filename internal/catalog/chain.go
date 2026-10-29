package catalog

import (
	"context"
	"errors"
	"fmt"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AncestorChain returns scope followed by its ancestors up to and including
// org — the walk CreateRef and ResolveStore use (tenancy model §3: a
// project's ancestors are itself, its workspace, then org; a user's scope
// sits directly under org with no workspace/project in between, §1). It
// reads through the pool: CreateRef and CreateStoreBinding, which need this
// same walk from inside their own transaction, call [ancestorChainTx]
// instead.
func (c *Catalog) AncestorChain(ctx context.Context, org uuid.UUID, scope tenancy.Scope) ([]tenancy.Scope, error) {
	return ancestorChainTx(ctx, c.pool, org, scope)
}

// ancestorChainTx is [Catalog.AncestorChain]'s logic against an explicit db
// (the pool, or a transaction) instead of always c.pool.
func ancestorChainTx(ctx context.Context, db dbtx, org uuid.UUID, scope tenancy.Scope) ([]tenancy.Scope, error) {
	switch scope.Level {
	case tenancy.LevelOrg:
		if scope.ID != org {
			return nil, invalidScope("org scope id must equal org")
		}
		return []tenancy.Scope{scope}, nil

	case tenancy.LevelWorkspace:
		ok, err := existsIn(ctx, db, `SELECT 1 FROM workspaces WHERE org_id = $1 AND id = $2`, org, scope.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, invalidScope("workspace does not belong to org")
		}
		return []tenancy.Scope{scope, tenancy.Org(org)}, nil

	case tenancy.LevelProject:
		var wsID uuid.UUID
		err := db.QueryRow(ctx,
			`SELECT workspace_id FROM projects WHERE org_id = $1 AND id = $2`, org, scope.ID,
		).Scan(&wsID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, invalidScope("project does not belong to org")
			}
			return nil, fmt.Errorf("catalog: lookup project workspace: %w", err)
		}
		return []tenancy.Scope{scope, {Level: tenancy.LevelWorkspace, ID: wsID}, tenancy.Org(org)}, nil

	case tenancy.LevelUser:
		ok, err := existsIn(ctx, db, `SELECT 1 FROM users WHERE org_id = $1 AND id = $2`, org, scope.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, invalidScope("user does not belong to org")
		}
		return []tenancy.Scope{scope, tenancy.Org(org)}, nil

	default:
		return nil, invalidScope("unknown scope level")
	}
}

func existsIn(ctx context.Context, db dbtx, q string, args ...any) (bool, error) {
	var one int
	err := db.QueryRow(ctx, q, args...).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("catalog: exists check: %w", err)
	}
	return true, nil
}

func invalidScope(reason string) *apperr.Error {
	return apperr.New(apperr.ClassInvalidArgument, "invalid scope: "+reason)
}
