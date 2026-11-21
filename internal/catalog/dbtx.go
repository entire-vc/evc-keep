package catalog

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// dbtx is satisfied by both *pgxpool.Pool and pgx.Tx. CreateRef,
// CreateStoreBinding and CreateOverrideLock each open an explicit
// transaction and thread it through every helper they call (AncestorChain,
// locksAt, requireUsableStore, ResolveStore, scopeLock, ...) so their checks
// and the INSERT they gate run against the same snapshot and hold the same
// locks — a check that read the database through one connection while the
// INSERT went through another could never see its own reads. Every other
// caller keeps working exactly as before, through the exported wrappers
// that pass c.pool as db.
type dbtx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// uniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505) — nothing else is read from the underlying
// *pgconn.PgError (never .Message or .Detail, which can echo back the
// offending row's own values), matching internal/store's own rule for what
// may be pulled out of a database error. .ConstraintName is never copied
// out either; [providerRefViolation] only compares it with a constant.
func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// providerRefIndex is the unique index of migration 00069: one
// provider_ref per store, whatever the secret's status.
const providerRefIndex = "secrets_provider_ref_per_store"

// providerRefViolation reports whether err is a unique violation of
// [providerRefIndex]. ConstraintName is only compared with that constant,
// never copied into an error: it is our own index name, while Message and
// Detail can carry the row's values.
func providerRefViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" && pgErr.ConstraintName == providerRefIndex
	}
	return false
}
