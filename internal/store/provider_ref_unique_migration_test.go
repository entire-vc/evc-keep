package store

import (
	"context"
	"strings"
	"testing"
)

// 00069: a provider_ref is unique within its store, whatever the status. The
// built-in provider keys a value by (store owner scope, provider_ref), so two
// catalog rows with one locator in one store share one value: a ref created
// in a member's own scope would read and overwrite another scope's secret.
// A disabled row keeps its locator: disabling is reversible and the value is
// not erased.
//
// Existing duplicates, disabled ones included, stop the upgrade with an
// explanation and are never repaired silently; the explanation names no
// locator. A row in another store does not collide. The downgrade drops the
// index and the upgrade applies again.
func TestProviderRefUniqueMigration(t *testing.T) {
	ctx := context.Background()
	db := testMigrationDB(t)
	p, err := NewProvider(db)
	if err != nil {
		t.Fatal(err)
	}
	const before, version = 64, 69
	if _, err = p.UpTo(ctx, before); err != nil {
		t.Fatal(err)
	}
	const (
		org      = "019a0000-0000-7000-8000-0000000000a1"
		orgStore = "019a0000-0000-7000-8000-0000000000b1"
		other    = "019a0000-0000-7000-8000-0000000000b2"
		user     = "019a0000-0000-7000-8000-0000000000c1"
		locator  = "builtin://default/marker-locator-qzx"
	)
	for _, q := range []string{
		`INSERT INTO organizations(id,name,key_level) VALUES('` + org + `','provider ref migration','user')`,
		`INSERT INTO users(id,org_id,email) VALUES('` + user + `','` + org + `','u@example.test')`,
		`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES('` + orgStore + `','` + org + `','builtin','org','org','` + org + `')`,
		`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES('` + other + `','` + org + `','builtin','user','user','` + user + `')`,
	} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(scopeLevel, scopeID, name, store, status string) error {
		_, err := db.ExecContext(ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref,status)
			VALUES(gen_random_uuid(),$1,$2,$3,$4,'dev','generic',$5,$6,$7)`, org, scopeLevel, scopeID, name, store, locator, status)
		return err
	}
	mustInsert := func(scopeLevel, scopeID, name, store, status string) {
		t.Helper()
		if err := insert(scopeLevel, scopeID, name, store, status); err != nil {
			t.Fatal(err)
		}
	}

	// The org secret and a member's ref sharing its locator in the same store:
	// exactly the pair the index must refuse.
	mustInsert("org", org, "ORG_SECRET", orgStore, "active")
	mustInsert("user", user, "MINE", orgStore, "active")
	_, err = p.UpTo(ctx, version)
	if err == nil || !strings.Contains(err.Error(), "secrets share a provider_ref in one store") {
		t.Fatalf("migration did not explain the duplicate: %v", err)
	}
	if strings.Contains(err.Error(), "marker-locator-qzx") || strings.Contains(err.Error(), "MINE") {
		t.Fatal("migration error names the locator or the secret")
	}
	if v, verr := p.GetDBVersion(ctx); verr != nil || v != before {
		t.Fatalf("a failed upgrade moved the schema to %d (%v)", v, verr)
	}

	// Nothing was repaired: both rows are still there.
	var n int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM secrets WHERE org_id=$1 AND status='active'`, org).Scan(&n); err != nil || n != 2 {
		t.Fatalf("the failed upgrade changed the catalog: %d rows, %v", n, err)
	}

	// Disabling the member's row does not resolve the duplicate: the disabled
	// row still names the shared value.
	if _, err = db.ExecContext(ctx, `UPDATE secrets SET status='disabled' WHERE org_id=$1 AND name='MINE'`, org); err != nil {
		t.Fatal(err)
	}
	if _, err = p.UpTo(ctx, version); err == nil || !strings.Contains(err.Error(), "secrets share a provider_ref in one store") {
		t.Fatalf("a disabled duplicate did not stop the upgrade: %v", err)
	}

	// Resolved by the operator: the member's row is removed. A row with the
	// same locator in another store is not a duplicate.
	if _, err = db.ExecContext(ctx, `DELETE FROM secrets WHERE org_id=$1 AND name='MINE'`, org); err != nil {
		t.Fatal(err)
	}
	mustInsert("user", user, "MINE_OWN_STORE", other, "active")
	if _, err = p.UpTo(ctx, version); err != nil {
		t.Fatal(err)
	}

	if err = insert("user", user, "MINE_AGAIN", orgStore, "active"); err == nil {
		t.Fatal("index accepted a second active row with one provider_ref in one store")
	}
	if err = insert("user", user, "MINE_DISABLED", orgStore, "disabled"); err == nil {
		t.Fatal("index accepted a disabled row on a locator already held in the store")
	}

	if _, err = p.DownTo(ctx, before); err != nil {
		t.Fatal(err)
	}
	mustInsert("user", user, "AFTER_DOWNGRADE", orgStore, "active")
	if _, err = db.ExecContext(ctx, `DELETE FROM secrets WHERE org_id=$1 AND name='AFTER_DOWNGRADE'`, org); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
