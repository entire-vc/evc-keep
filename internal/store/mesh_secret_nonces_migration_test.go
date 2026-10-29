package store

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// 00036 adds the replay table of the Mesh secrets API. It is additive: the
// downgrade drops only that table and the upgrade brings it back, empty, with
// the same rules (one row per workspace and nonce, a closed nonce shape).
func TestMeshSecretNoncesMigration_DowngradeShown(t *testing.T) {
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
	const ws = "11111111-1111-1111-1111-111111111111"
	if _, err := db.ExecContext(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'migration-org')`, ws); err != nil {
		t.Fatalf("setup organization: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO mesh_installations (workspace_id, org_id, mesh_url, installed_by) VALUES ($1, $1, 'https://mesh.example', $1)`, ws); err != nil {
		t.Fatalf("setup installation: %v", err)
	}
	const insert = `INSERT INTO mesh_secret_nonces (workspace_id, nonce) VALUES ($1, $2)`
	if _, err := db.ExecContext(ctx, insert, ws, "0123456789abcdef"); err != nil {
		t.Fatalf("new table rejected a valid nonce: %v", err)
	}
	if _, err := db.ExecContext(ctx, insert, ws, "0123456789abcdef"); err == nil {
		t.Fatal("table accepted the same nonce twice for one workspace")
	}
	if _, err := db.ExecContext(ctx, insert, ws, "short"); err == nil {
		t.Fatal("table accepted a nonce outside the closed shape")
	}
	if _, err := provider.DownTo(ctx, 35); err != nil {
		t.Fatal("downgrade failed")
	}
	var gone bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('mesh_secret_nonces') IS NULL`).Scan(&gone); err != nil || !gone {
		t.Fatal("downgrade left the nonce table behind")
	}
	var installs int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM mesh_installations`).Scan(&installs); err != nil || installs != 1 {
		t.Fatal("downgrade touched the installations")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
	if _, err := db.ExecContext(ctx, insert, ws, "0123456789abcdef"); err != nil {
		t.Fatalf("upgraded table rejected a valid nonce again: %v", err)
	}
}
