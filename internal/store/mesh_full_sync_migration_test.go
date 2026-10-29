package store

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// 00045 adds mesh_sync_state.last_full_sync_at. The downgrade drops only that
// column, keeping the sync state rows, and the upgrade brings it back empty.
func TestMeshFullSyncMigration_DowngradeShown(t *testing.T) {
	dsn := pgscratch.New(t, nil)
	ctx := pgscratch.Context(t)
	db, err := OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = db.Close() }()
	provider, err := NewProvider(db)
	if err != nil {
		t.Fatal("create migration provider")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("migrate up")
	}
	const org, ws = "22222222-2222-2222-2222-222222222222", "44444444-4444-4444-4444-444444444444"
	for _, q := range []string{
		`INSERT INTO organizations (id, name) VALUES ('` + org + `', 'migration-org')`,
		`INSERT INTO mesh_installations (workspace_id, org_id, mesh_url, installed_by) VALUES ('` + ws + `', '` + org + `', 'https://mesh.example.test', gen_random_uuid())`,
		`INSERT INTO mesh_sync_state (workspace_id, cursor, last_full_sync_at) VALUES ('` + ws + `', 'c1', now())`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	const column = `SELECT count(*) FROM information_schema.columns WHERE table_name = 'mesh_sync_state' AND column_name = 'last_full_sync_at'`
	if _, err := provider.DownTo(ctx, 44); err != nil {
		t.Fatal("downgrade failed")
	}
	var n int
	if err := db.QueryRowContext(ctx, column).Scan(&n); err != nil || n != 0 {
		t.Fatal("downgrade left last_full_sync_at behind")
	}
	var cursor string
	if err := db.QueryRowContext(ctx, `SELECT cursor FROM mesh_sync_state WHERE workspace_id = $1`, ws).Scan(&cursor); err != nil || cursor != "c1" {
		t.Fatal("downgrade lost the sync state row")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
	var empty bool
	if err := db.QueryRowContext(ctx, `SELECT last_full_sync_at IS NULL FROM mesh_sync_state WHERE workspace_id = $1`, ws).Scan(&empty); err != nil || !empty {
		t.Fatal("upgrade did not bring last_full_sync_at back empty")
	}
}
