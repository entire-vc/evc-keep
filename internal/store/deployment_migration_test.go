package store

import (
	"database/sql"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

func TestDeploymentMigrationDowngradeAndUpgrade(t *testing.T) {
	dsn := pgscratch.New(t, nil)
	db, err := OpenMigrationDB(pgscratch.Context(t), dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = db.Close() }()
	provider, err := NewProvider(db)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatal("migrate up")
	}
	// A deployment rollback must preserve the runner trust and intake schema
	// supplied by earlier migrations, including the adjacent carrier registry.
	const neighborColumns = `SELECT count(*) FROM information_schema.columns
	 WHERE table_schema='public' AND table_name IN ('runners','intake_links','carriers')`
	var carrier sql.NullString
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT to_regclass('public.carriers')::text`).Scan(&carrier); err != nil || !carrier.Valid {
		t.Fatal("carrier registry missing before deployment rollback")
	}
	var before, after int
	if err := db.QueryRowContext(pgscratch.Context(t), neighborColumns).Scan(&before); err != nil || before == 0 {
		t.Fatal("read neighboring migration schema")
	}
	if _, err := provider.DownTo(pgscratch.Context(t), 15); err != nil {
		t.Fatal("downgrade deployment migration")
	}
	if err := db.QueryRowContext(pgscratch.Context(t), neighborColumns).Scan(&after); err != nil || after != before {
		t.Fatal("deployment downgrade changed neighboring migration schema")
	}
	var table sql.NullString
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT to_regclass('public.deployment_jobs')::text`).Scan(&table); err != nil || table.Valid {
		t.Fatal("downgrade retained deployment queue")
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatal("upgrade deployment migration")
	}
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT to_regclass('public.deployment_jobs')::text`).Scan(&table); err != nil || !table.Valid {
		t.Fatal("upgrade did not restore deployment queue")
	}
}
