package store

import (
	"context"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckReservedRefs counts the secrets rows whose provider_ref sits under
// prefix, which the caller takes from provider.ReservedRefPrefix: the locator
// Keep seals its own service credential at. The prefix is a parameter so this
// package does not import pkg/provider, and with it pkg/secret, into every
// package that reads the database. provider.ValidRef keeps such a ref out of every API, but a
// row written before that rule, or by hand, would still resolve in the
// built-in store and could be delivered to a runner from the same org scope.
// A non-zero count comes back with an apperr internal error, so the server
// refuses to serve.
//
// Neither the error nor the count carries the ref, the secret's name or any
// value: the operator finds the rows with a query of their own.
func CheckReservedRefs(ctx context.Context, pool *pgxpool.Pool, prefix string) (int, error) {
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE starts_with(provider_ref, $1)`, prefix).Scan(&n); err != nil {
		return 0, apperr.New(apperr.ClassInternal, "reserved provider reference check failed")
	}
	if n > 0 {
		return n, apperr.New(apperr.ClassInternal, "catalog holds a secret under a reserved provider reference")
	}
	return 0, nil
}
