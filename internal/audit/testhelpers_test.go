package audit

import (
	"context"
	"testing"

	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool migrates a fresh scratch database for this test. Cleanup closes
// the pool before pgscratch drops the database; the shared schema is untouched.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	mdb, err := store.OpenMigrationDB(pgscratch.Context(t), dsn)
	if err != nil {
		t.Fatalf("open migration db: %v", err)
	}
	defer func() { _ = mdb.Close() }()

	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatalf("new migration provider: %v", err)
	}
	if _, err := provider.Up(pgscratch.MigrateContext(t)); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	pool, err := pgxpool.New(pgscratch.Context(t), dsn)
	if err != nil {
		t.Fatalf("open test pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// superuserExec runs sql directly against pool's own (superuser, in
// CI/local dev) login role — bypassing Journal and keep_app entirely. Tests
// use this to simulate the threat model's scenario of a change made
// outside the application (by a superuser) — a change made by something
// other than this package's own code.
func superuserExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...interface{}) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("superuser exec %q: %v", sql, err)
	}
}
