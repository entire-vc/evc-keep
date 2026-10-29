package store

import (
	"context"
	"strings"
	"testing"
)

func TestBuiltinStoreScopeMigration(t *testing.T) {
	ctx := context.Background()
	db := testMigrationDB(t)
	p, err := NewProvider(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.UpTo(ctx, 7); err != nil {
		t.Fatal(err)
	}
	const org = "019a0000-0000-7000-8000-000000000001"
	if _, err = db.Exec(`INSERT INTO organizations(id,name,key_level) VALUES($1,'scope migration','user')`, org); err != nil {
		t.Fatal(err)
	}
	insert := func() {
		t.Helper()
		if _, err = db.Exec(`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES(gen_random_uuid(),$1,'builtin','fixture','org',$1)`, org); err != nil {
			t.Fatal(err)
		}
	}
	insert()
	insert()
	if _, err = p.UpTo(ctx, 9); err == nil || !strings.Contains(err.Error(), "duplicate builtin stores at one owner scope") {
		t.Fatal("migration did not explain duplicate builtin scopes")
	}
	if _, err = db.Exec(`DELETE FROM stores WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	insert()
	if _, err = p.UpTo(ctx, 9); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES(gen_random_uuid(),$1,'builtin','fixture','org',$1)`, org); err == nil {
		t.Fatal("unique index did not reject duplicate")
	}
	if _, err = p.DownTo(ctx, 7); err != nil {
		t.Fatal(err)
	}
	insert()
	if _, err = db.Exec(`DELETE FROM stores WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
