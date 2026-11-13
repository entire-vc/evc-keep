package store

import (
	"context"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// embeddedMigrationVersions lists the numeric versions of the migrations
// embedded in this binary, ascending.
func embeddedMigrationVersions() ([]int64, error) {
	paths, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return nil, ErrTransferInventory
	}
	var out []int64
	for _, p := range paths {
		head, _, ok := strings.Cut(path.Base(p), "_")
		n, err := strconv.ParseInt(head, 10, 64)
		if !ok || err != nil {
			return nil, ErrTransferInventory
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// checkMigrationHistory requires the applied versions (ascending, one entry
// per version) to equal the embedded set exactly.
func checkMigrationHistory(applied []int64) error {
	want, err := embeddedMigrationVersions()
	if err != nil || len(want) == 0 || len(applied) != len(want) {
		return ErrTransferInventory
	}
	for i := range want {
		if applied[i] != want[i] {
			return ErrTransferInventory
		}
	}
	return nil
}

// ReadTransferSource reads the inventory and every copied table of org in ONE
// read-only repeatable-read transaction, so metadata and rows are one
// snapshot. accept sees the inventory first and may refuse (its error is
// returned unchanged); no rows are read then. It writes nothing.
func ReadTransferSource(ctx context.Context, db *pgxpool.Pool, org uuid.UUID, accept func(scopedtransfer.Inventory) error) (scopedtransfer.Inventory, *TransferRows, error) {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return scopedtransfer.Inventory{}, nil, ErrTransferInventory
	}
	defer func() { _ = tx.Rollback(ctx) }()
	in, err := readTransferInventory(ctx, tx, org)
	if err != nil {
		return scopedtransfer.Inventory{}, nil, ErrTransferInventory
	}
	if accept != nil {
		if err := accept(in); err != nil {
			return in, nil, err // the caller's own refusal, returned as is
		}
	}
	rows, err := readTransferRows(ctx, tx, org)
	if err != nil {
		return in, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return in, nil, ErrTransferRows
	}
	return in, rows, nil
}

// RequireTransferTargetSchema checks, inside the import transaction, that the
// target's applied migration history equals the embedded set exactly: the
// same rule the source inventory applies, so both sides run the one schema
// the transfer profile pins.
func RequireTransferTargetSchema(ctx context.Context, tx pgx.Tx) error {
	applied, err := appliedMigrationVersions(ctx, tx)
	if err != nil || checkMigrationHistory(applied) != nil {
		return ErrTransferImport
	}
	if id, err := LiveCatalogID(ctx, tx); err != nil || id != scopedtransfer.CatalogID {
		return ErrTransferImport
	}
	return nil
}
