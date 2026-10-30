package meshgate

import (
	"context"
	"testing"

	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A gate card goes only to a workspace where Keep is installed as an
// extension: a store-only installation of the organisation is not offered, so
// an organisation with one extension and one store workspace still has exactly
// one workspace to ask.
func TestWorkspacesOfTxListsExtensionsOnly(t *testing.T) {
	dsn := pgscratch.New(t, nil)
	ctx := context.Background()
	mdb, err := store.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = mdb.Close() }()
	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err = provider.Up(ctx); err != nil {
		t.Fatal("migrate test database")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open test pool")
	}
	t.Cleanup(pool.Close)
	org, ext, st := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,'gate')`, org); err != nil {
		t.Fatal("insert organization")
	}
	for ws, mode := range map[uuid.UUID]string{ext: "extension", st: "store"} {
		if _, err := pool.Exec(ctx, `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by,mode) VALUES($1,$2,'https://mesh.example.test',$3,$4)`, ws, org, uuid.New(), mode); err != nil {
			t.Fatalf("insert %s installation: %v", mode, err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	got, err := NewPG(pool).WorkspacesOfTx(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != ext {
		t.Fatalf("workspaces offered for a gate card: %v, want only the extension %v", got, ext)
	}
}
