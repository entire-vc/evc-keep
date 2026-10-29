package tenancy

import (
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
