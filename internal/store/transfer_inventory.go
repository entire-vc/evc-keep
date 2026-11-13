package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrTransferInventory is the only error [ReadTransferInventory] returns. It
// carries no driver text, DSN, identifier or row content.
var ErrTransferInventory = errors.New("store: cannot read transfer inventory")

// scopeWhere builds the reviewed row filter for one registry table from its
// closed scope rule. Table and column names come only from the program's
// registry (checked against the migrations by its own test), never from
// input; the organization is always a bind parameter $1.
func scopeWhere(table string) (string, bool) {
	s, ok := scopedtransfer.TableScope(table)
	if !ok {
		return "", false
	}
	switch s.Kind {
	case scopedtransfer.ScopeColumn, scopedtransfer.ScopeSelf:
		return pgx.Identifier{s.Column}.Sanitize() + " = $1", true
	case scopedtransfer.ScopeParent:
		inner, ok := scopeWhere(s.Parent)
		if !ok {
			return "", false
		}
		return pgx.Identifier{s.Column}.Sanitize() + " IN (SELECT " + pgx.Identifier{s.ParentKey}.Sanitize() + " FROM " +
			pgx.Identifier{s.Parent}.Sanitize() + " WHERE " + inner + ")", true
	}
	return "", false
}

// CountSQL returns the fixed, parameterised count statement of one registry
// table. It exists so the statements can be reviewed and tested without a
// database.
func CountSQL(table string) (string, bool) {
	where, ok := scopeWhere(table)
	if !ok {
		return "", false
	}
	return "SELECT count(*) FROM " + pgx.Identifier{table}.Sanitize() + " WHERE " + where, true
}

// ReadTransferInventory reads the metadata the scoped-transfer profile needs
// for orgID inside one read-only repeatable-read transaction: schema version,
// the pin of the embedded migrations, the organization's workspaces and
// provider kinds, the Mesh mode, and the row count of every registry table.
// It writes nothing and returns no row content. Whether the result is
// acceptable is decided by [scopedtransfer.PlanSnapshot], not here.
func ReadTransferInventory(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID) (scopedtransfer.Inventory, error) {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return scopedtransfer.Inventory{}, ErrTransferInventory
	}
	defer func() { _ = tx.Rollback(ctx) }()
	in, err := readTransferInventory(ctx, tx, orgID)
	if err != nil {
		return scopedtransfer.Inventory{}, ErrTransferInventory
	}
	if err := tx.Commit(ctx); err != nil {
		return scopedtransfer.Inventory{}, ErrTransferInventory
	}
	return in, nil
}

// readTransferInventory reads the inventory inside tx, which the caller owns.
// The applied migration history must equal the embedded set exactly: a
// database whose history has a gap, an extra or an unknown migration is not
// the schema this binary reads, whatever its highest version says.
func readTransferInventory(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) (scopedtransfer.Inventory, error) {
	setID, err := scopedtransfer.MigrationSetIDOf(migrationFiles, "migrations")
	if err != nil {
		return scopedtransfer.Inventory{}, err
	}
	in := scopedtransfer.Inventory{OrgID: orgID.String(), MigrationSetID: setID}
	applied, err := appliedMigrationVersions(ctx, tx)
	if err != nil || checkMigrationHistory(applied) != nil {
		return scopedtransfer.Inventory{}, ErrTransferInventory
	}
	in.SchemaVersion = applied[len(applied)-1]
	if in.CatalogID, err = LiveCatalogID(ctx, tx); err != nil {
		return scopedtransfer.Inventory{}, ErrTransferInventory
	}
	if in.WorkspaceIDs, err = queryStrings(ctx, tx, `SELECT id::text FROM workspaces WHERE org_id = $1 ORDER BY id`, orgID); err != nil {
		return in, err
	}
	// The canonical workspace is the tenancy workspace when there is exactly
	// one. A native Mesh store-mode organization has none: its canonical
	// workspace is then the workspace of its one Mesh installation. Whether
	// that shape is acceptable is decided by scopedtransfer.PlanSnapshot.
	mesh, err := queryStrings(ctx, tx, `SELECT workspace_id::text FROM mesh_installations WHERE org_id = $1 ORDER BY workspace_id`, orgID)
	if err != nil {
		return in, err
	}
	if len(mesh) == 1 {
		in.MeshWorkspaceID = mesh[0]
	}
	switch {
	case len(in.WorkspaceIDs) == 1:
		in.WorkspaceID = in.WorkspaceIDs[0]
	case len(in.WorkspaceIDs) == 0:
		in.WorkspaceID = in.MeshWorkspaceID
	}
	if in.Providers, err = queryStrings(ctx, tx, `SELECT DISTINCT provider FROM stores WHERE org_id = $1 ORDER BY provider`, orgID); err != nil {
		return in, err
	}
	modes, err := queryStrings(ctx, tx, `SELECT mode FROM mesh_installations WHERE org_id = $1`, orgID)
	if err != nil {
		return in, err
	}
	if len(modes) == 1 {
		in.MeshMode = modes[0]
	}
	for _, p := range scopedtransfer.TablePolicies() {
		q, ok := CountSQL(p.Name)
		if !ok {
			return in, ErrTransferInventory
		}
		var n int64
		if err := tx.QueryRow(ctx, q, orgID).Scan(&n); err != nil {
			return in, err
		}
		in.Tables = append(in.Tables, scopedtransfer.TableCount{Name: p.Name, Rows: n})
	}
	return in, nil
}

// appliedMigrationVersions returns the versions whose latest goose state is
// applied, ascending.
func appliedMigrationVersions(ctx context.Context, tx pgx.Tx) ([]int64, error) {
	return queryInt64s(ctx, tx, `SELECT version_id FROM (
		SELECT DISTINCT ON (version_id) version_id, is_applied FROM goose_db_version ORDER BY version_id, id DESC
	) h WHERE is_applied AND version_id > 0 ORDER BY version_id`)
}

func queryInt64s(ctx context.Context, tx pgx.Tx, q string) ([]int64, error) {
	rows, err := tx.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query")
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var n int64
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("scan")
		}
		out = append(out, n)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("rows")
	}
	return out, nil
}

func queryStrings(ctx context.Context, tx pgx.Tx, q string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query")
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan")
		}
		out = append(out, s)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("rows")
	}
	return out, nil
}
