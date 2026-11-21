package carriers

import (
	"context"
	"testing"

	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
)

// Downgrade is safe only before adoption is used, including policy-only setup.
// Exercise real goose transactions so a refused Down preserves the schema.
func TestAdoptMigrationRollbackPreservesAuthorization(t *testing.T) {
	ctx := context.Background()
	db, err := store.OpenMigrationDB(ctx, pgscratch.New(t, nil))
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	p, err := store.NewProvider(db)
	must(t, err)
	_, err = p.Up(ctx)
	must(t, err)
	// Leave main's Mesh approvals setting in place when removing adoption.
	_, err = p.DownTo(ctx, 54)
	must(t, err)
	var present bool
	must(t, db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='carriers' AND column_name='provenance')`).Scan(&present))
	if present {
		t.Fatal("unused adoption schema did not downgrade")
	}
	must(t, db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='mesh_installations' AND column_name='approvals_via_mesh')`).Scan(&present))
	if !present {
		t.Fatal("adoption downgrade removed the existing Mesh approvals setting")
	}
	_, err = p.Up(ctx)
	must(t, err)
	org := uuid.New()
	_, err = db.ExecContext(ctx, `INSERT INTO organizations(id,name) VALUES($1,'yaml-rollback')`, org)
	must(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO deployment_policies(org_id,rules) VALUES($1,'{"adoption_rules":[{"path":"/srv/app/config.yaml","field":"service.token"}]}'::jsonb)`, org)
	must(t, err)
	if _, err = p.DownTo(ctx, 54); err == nil {
		t.Fatal("downgrade discarded adoption policy")
	}
	must(t, db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='carriers' AND column_name='provenance')`).Scan(&present))
	if !present {
		t.Fatal("refused downgrade changed the adoption schema")
	}
}
