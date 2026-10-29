package store

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// The Mesh hierarchy tables arrive on top of live installations without
// touching them, refuse states outside the closed sets, go away on downgrade
// leaving the installation and its events alone, and come back on upgrade.
func TestMeshHierarchyMigrationDowngradeAndUpgrade(t *testing.T) {
	dsn := pgscratch.New(t, nil)
	ctx := pgscratch.Context(t)
	db, err := OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = db.Close() }()
	provider, err := NewProvider(db)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err := provider.UpTo(ctx, 34); err != nil {
		t.Fatal("migrate up to 34")
	}
	const ws = "00000000-0000-0000-0000-0000000000a1"
	for _, q := range []string{
		`INSERT INTO organizations(id,name) VALUES ('00000000-0000-0000-0000-0000000000f1','o')`,
		`INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by) VALUES ('` + ws + `','00000000-0000-0000-0000-0000000000f1','https://m.example.test','00000000-0000-0000-0000-0000000000c1')`,
		`INSERT INTO mesh_events(workspace_id,event_id,event_type) VALUES ('` + ws + `','e1','project.created')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed failed: %v", err)
		}
	}
	if _, err := provider.UpTo(ctx, 35); err != nil {
		t.Fatalf("migrate up to 35: %v", err)
	}
	bad := map[string]string{
		"member status":  `INSERT INTO mesh_members(workspace_id,user_id,role,status,state_at) VALUES ('` + ws + `','00000000-0000-0000-0000-0000000000d1','r','deleted',now())`,
		"project status": `INSERT INTO mesh_projects(workspace_id,project_id,status,state_at) VALUES ('` + ws + `','00000000-0000-0000-0000-0000000000d2','gone',now())`,
		"agent status":   `INSERT INTO mesh_agents(workspace_id,agent_id,status,state_at) VALUES ('` + ws + `','00000000-0000-0000-0000-0000000000d3','revoked',now())`,
		"key status":     `INSERT INTO mesh_agent_keys(workspace_id,agent_id,key_id,status,state_at) VALUES ('` + ws + `','00000000-0000-0000-0000-0000000000d3','k','deleted',now())`,
		"key id shape":   `INSERT INTO mesh_agent_keys(workspace_id,agent_id,key_id,status,state_at) VALUES ('` + ws + `','00000000-0000-0000-0000-0000000000d3','bad key','active',now())`,
		"unknown ws":     `INSERT INTO mesh_members(workspace_id,user_id,role,status,state_at) VALUES ('00000000-0000-0000-0000-0000000000a9','00000000-0000-0000-0000-0000000000d1','r','active',now())`,
	}
	for name, q := range bad {
		if _, err := db.ExecContext(ctx, q); err == nil {
			t.Errorf("%s: the database accepted a row outside the closed set", name)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO mesh_members(workspace_id,user_id,role,status,state_at) VALUES ('`+ws+`','00000000-0000-0000-0000-0000000000d1','r','orphaned',now())`); err != nil {
		t.Fatalf("a valid row was refused: %v", err)
	}
	if _, err := provider.DownTo(ctx, 34); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('mesh_members','mesh_projects','mesh_agents','mesh_agent_keys','mesh_sync_state')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("downgrade left %d hierarchy tables", n)
	}
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM mesh_installations)+(SELECT count(*) FROM mesh_events)`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("downgrade touched the installation or its events: %d rows, %v", n, err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
}
