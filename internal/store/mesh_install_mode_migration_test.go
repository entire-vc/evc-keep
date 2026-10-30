package store

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// 00046 adds mesh_installations.mode. The one-off backfill marks "store" only
// an installation that never had a token delivered and never reconciled
// successfully; a delivered token, a full sync or a successful round keeps
// "extension". The downgrade drops only the column and the upgrade backfills
// the same way again.
func TestMeshInstallModeMigration(t *testing.T) {
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
	if _, err := provider.UpTo(ctx, 45); err != nil {
		t.Fatal("migrate up to 45")
	}
	const org = "22222222-2222-2222-2222-222222222222"
	want := map[string]string{
		"a0000000-0000-0000-0000-000000000001": "store",     // no token, no sync state at all
		"a0000000-0000-0000-0000-000000000002": "store",     // no token, every round failed
		"a0000000-0000-0000-0000-000000000003": "extension", // a token was delivered
		"a0000000-0000-0000-0000-000000000004": "extension", // a full snapshot was applied
		"a0000000-0000-0000-0000-000000000005": "extension", // a round answered ok
		"a0000000-0000-0000-0000-000000000006": "extension", // a round answered not modified
	}
	setup := []string{`INSERT INTO organizations (id, name) VALUES ('` + org + `', 'migration-org')`}
	for ws := range want {
		tok := "NULL"
		if ws[len(ws)-1] == '3' {
			tok = "1793294422"
		}
		setup = append(setup, `INSERT INTO mesh_installations (workspace_id, org_id, mesh_url, installed_by, token_signed_at) VALUES ('`+ws+`', '`+org+`', 'https://mesh.example.test', gen_random_uuid(), `+tok+`)`)
	}
	setup = append(setup,
		`INSERT INTO mesh_sync_state (workspace_id, last_result) VALUES ('a0000000-0000-0000-0000-000000000002', 'failed')`,
		`INSERT INTO mesh_sync_state (workspace_id, last_result) VALUES ('a0000000-0000-0000-0000-000000000003', 'failed')`,
		`INSERT INTO mesh_sync_state (workspace_id, last_result, last_full_sync_at) VALUES ('a0000000-0000-0000-0000-000000000004', 'failed', now())`,
		`INSERT INTO mesh_sync_state (workspace_id, last_result) VALUES ('a0000000-0000-0000-0000-000000000005', 'ok')`,
		`INSERT INTO mesh_sync_state (workspace_id, last_result) VALUES ('a0000000-0000-0000-0000-000000000006', 'not_modified')`,
	)
	for _, q := range setup {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	check := func(stage string) {
		t.Helper()
		for ws, m := range want {
			var got string
			if err := db.QueryRowContext(ctx, `SELECT mode FROM mesh_installations WHERE workspace_id = $1`, ws).Scan(&got); err != nil || got != m {
				t.Fatalf("%s: %s has mode %q, want %q (%v)", stage, ws, got, m, err)
			}
		}
	}
	if _, err := provider.UpTo(ctx, 46); err != nil {
		t.Fatal("migrate up to 46")
	}
	check("first upgrade")
	if _, err := db.ExecContext(ctx, `UPDATE mesh_installations SET mode = 'both' WHERE workspace_id = 'a0000000-0000-0000-0000-000000000001'`); err == nil {
		t.Fatal("a mode outside store|extension was accepted")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO mesh_installations (workspace_id, org_id, mesh_url, installed_by) VALUES ('a0000000-0000-0000-0000-000000000007', '`+org+`', 'https://mesh.example.test', gen_random_uuid())`); err != nil {
		t.Fatalf("insert without mode: %v", err)
	}
	var def string
	if err := db.QueryRowContext(ctx, `SELECT mode FROM mesh_installations WHERE workspace_id = 'a0000000-0000-0000-0000-000000000007'`).Scan(&def); err != nil || def != "extension" {
		t.Fatalf("column default is %q, want extension (%v)", def, err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM mesh_installations WHERE workspace_id = 'a0000000-0000-0000-0000-000000000007'`); err != nil {
		t.Fatal(err)
	}

	const column = `SELECT count(*) FROM information_schema.columns WHERE table_name = 'mesh_installations' AND column_name = 'mode'`
	if _, err := provider.DownTo(ctx, 45); err != nil {
		t.Fatal("downgrade failed")
	}
	var n int
	if err := db.QueryRowContext(ctx, column).Scan(&n); err != nil || n != 0 {
		t.Fatal("downgrade left mesh_installations.mode behind")
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM mesh_installations`).Scan(&n); err != nil || n != len(want) {
		t.Fatalf("downgrade kept %d installations, want %d", n, len(want))
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
	check("second upgrade")
}
