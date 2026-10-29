package pgscratch

import (
	"context"
	"errors"
	"os"
	"regexp"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var scratchName = regexp.MustCompile(`^keep_scratch_[0-9a-f]{12}$`)
var errNotScratch = errors.New("constraint removal requires a scratch database")

// DropConstraint removes a database barrier for a tamper test, only on a
// database created by New. Identifiers are quoted and errors never echo SQL.
func DropConstraint(t *testing.T, pool *pgxpool.Pool, table, constraint string) {
	t.Helper()
	conn, err := pool.Acquire(Context(t))
	if err != nil {
		t.Fatalf("acquire scratch connection failed (%s)", sqlState(err))
	}
	defer conn.Release()
	if err := dropConstraint(Context(t), conn.Conn(), table, constraint); err != nil {
		t.Fatalf("drop scratch constraint failed (%s)", sqlState(err))
	}
}

func dropConstraint(ctx context.Context, conn *pgx.Conn, table, constraint string) error {
	var database string
	if err := conn.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
		return err
	}
	// A caller may itself use a scratch-named database as the shared base.
	// Naming alone must not authorize altering KEEP_DATABASE_URL's schema.
	base, err := pgx.ParseConfig(os.Getenv("KEEP_DATABASE_URL"))
	if err != nil {
		return err
	}
	if !scratchName.MatchString(database) || database == base.Database {
		return errNotScratch
	}
	_, err = conn.Exec(ctx, "ALTER TABLE "+pgx.Identifier{table}.Sanitize()+" DROP CONSTRAINT "+pgx.Identifier{constraint}.Sanitize())
	return err
}
