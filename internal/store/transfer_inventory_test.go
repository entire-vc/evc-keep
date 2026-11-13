package store

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/entire-vc/evc-keep/internal/testutil/transferfixture"
	"github.com/google/uuid"
)

func TestEmbeddedMigrationsMatchTransferPin(t *testing.T) {
	got, err := scopedtransfer.MigrationSetIDOf(migrationFiles, "migrations")
	if err != nil || got != scopedtransfer.MigrationSetID {
		t.Fatal("embedded migrations differ from the pinned transfer profile")
	}
}

func TestCountSQLCoversRegistryWithBoundOrg(t *testing.T) {
	for _, p := range scopedtransfer.TablePolicies() {
		q, ok := CountSQL(p.Name)
		if !ok || !strings.Contains(q, "$1") || strings.Count(q, "$1") != 1 ||
			!strings.HasPrefix(q, "SELECT count(*) FROM \""+p.Name+"\" WHERE ") {
			t.Fatalf("table %s: no reviewed count statement", p.Name)
		}
	}
	if _, ok := CountSQL("pg_authid"); ok {
		t.Fatal("unregistered table accepted")
	}
	if q, _ := CountSQL("rotation_steps"); !strings.Contains(q, `IN (SELECT "id" FROM "rotation_runs" WHERE "org_id" = $1)`) {
		t.Fatalf("parent join not applied: %s", q)
	}
	// Mesh tables are keyed by the Mesh workspace id, never by the
	// organization id; binding the organization to that column counts zero
	// rows and would silently export an empty Mesh state.
	for _, name := range []string{"mesh_events", "mesh_members", "mesh_projects", "mesh_agents",
		"mesh_agent_keys", "mesh_sync_state", "mesh_secret_nonces"} {
		q, _ := CountSQL(name)
		if !strings.Contains(q, `"workspace_id" IN (SELECT "workspace_id" FROM "mesh_installations" WHERE "org_id" = $1)`) {
			t.Fatalf("table %s: not joined through its installation: %s", name, q)
		}
	}
}

func TestReadTransferInventoryCountsOnlyTheSelectedOrg(t *testing.T) {
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("open")
	}
	t.Cleanup(db.Close)
	a, b := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{a, b} {
		if _, err := db.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, $2)`, id, "inv-"+id.String()); err != nil {
			t.Fatal("seed org")
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(ctx, `INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)`, uuid.New(), b, "u"+uuid.NewString()[:8]+"@example.test"); err != nil {
			t.Fatalf("seed users: %v", err)
		}
	}
	inA, err := ReadTransferInventory(ctx, db, a)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	inB, err := ReadTransferInventory(ctx, db, b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	count := func(in scopedtransfer.Inventory, name string) int64 {
		for _, tc := range in.Tables {
			if tc.Name == name {
				return tc.Rows
			}
		}
		return -1
	}
	if count(inA, "organizations") != 1 || count(inA, "users") != 0 || count(inB, "users") != 2 {
		t.Fatal("counts leak across organizations")
	}
	if inA.SchemaVersion != scopedtransfer.SchemaVersion || inA.MigrationSetID != scopedtransfer.MigrationSetID {
		t.Fatal("schema identity not reported")
	}
	if len(inA.Tables) != len(scopedtransfer.TablePolicies()) {
		t.Fatal("inventory is not closed over the registry")
	}
}

func TestReadTransferInventoryStoreModeTakesTheInstallationWorkspace(t *testing.T) {
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("open")
	}
	t.Cleanup(db.Close)
	org := uuid.New()
	transferfixture.Seed(t, ctx, db, org, strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))[:7]+"S")
	// With its tenancy workspace the fixture is the existing profile.
	in, err := ReadTransferInventory(ctx, db, org)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	plan, err := scopedtransfer.PlanSnapshot(in)
	if err != nil || plan.ProfileVersion() != scopedtransfer.ProfileVersion || plan.WorkspaceID() != in.WorkspaceIDs[0] {
		t.Fatal("tenancy-workspace profile not reported as profile 1")
	}
	transferfixture.DropTenancyWorkspaces(t, ctx, db, org)
	var mws string
	if err := db.QueryRow(ctx, `SELECT workspace_id::text FROM mesh_installations WHERE org_id = $1`, org).Scan(&mws); err != nil {
		t.Fatal("read installation")
	}
	in, err = ReadTransferInventory(ctx, db, org)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(in.WorkspaceIDs) != 0 || in.WorkspaceID != mws || in.MeshWorkspaceID != mws {
		t.Fatal("store-mode inventory does not take the installation workspace")
	}
	plan, err = scopedtransfer.PlanSnapshot(in)
	if err != nil || plan.ProfileVersion() != scopedtransfer.ProfileVersionStoreMode || plan.WorkspaceID() != mws {
		t.Fatalf("store-mode profile refused: %v", err)
	}
	// Two installations leave no single canonical workspace.
	if _, err := db.Exec(ctx, `INSERT INTO mesh_installations (workspace_id, org_id, mesh_url, installed_by, token_signed_at, mode)
		SELECT gen_random_uuid(), org_id, mesh_url, installed_by, token_signed_at, mode FROM mesh_installations WHERE org_id = $1`, org); err != nil {
		t.Fatalf("second installation: %v", err)
	}
	in, err = ReadTransferInventory(ctx, db, org)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := scopedtransfer.PlanSnapshot(in); err != scopedtransfer.ErrProfile || in.WorkspaceID != "" {
		t.Fatal("ambiguous installation accepted or canonical workspace guessed")
	}
}
