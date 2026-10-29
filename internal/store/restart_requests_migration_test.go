package store

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// 00042 adds the restart queue. It is additive: the downgrade drops only that
// table and the upgrade brings it back, empty, with the same closed shapes.
func TestRestartRequestsMigration_DowngradeShown(t *testing.T) {
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
	const org = "22222222-2222-2222-2222-222222222222"
	if _, err := db.ExecContext(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'migration-org')`, org); err != nil {
		t.Fatalf("setup organization: %v", err)
	}
	const insert = `INSERT INTO restart_requests (request_id, org_id, lane, key_version, fingerprint) VALUES (gen_random_uuid(), $1, $2, $3, $4)`
	const fp = "kfp1:k1:abcdefghijklmnop"
	if _, err := db.ExecContext(ctx, insert, org, "Hugh", "key-1", fp); err != nil {
		t.Fatalf("new table rejected a valid request: %v", err)
	}
	for name, args := range map[string][]any{
		"lane with a space":      {org, "Hu gh", "key-1", fp},
		"empty version":          {org, "Hugh", "", fp},
		"value-shaped version":   {org, "Hugh", "a b", fp},
		"fingerprint not kfp1":   {org, "Hugh", "key-1", "sha256:abc"},
		"fingerprint too short":  {org, "Hugh", "key-1", "kfp1:k1:abc"},
		"organization not found": {"33333333-3333-3333-3333-333333333333", "Hugh", "key-1", fp},
	} {
		if _, err := db.ExecContext(ctx, insert, args...); err == nil {
			t.Errorf("table accepted: %s", name)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE restart_requests SET state = 'claimed'`); err == nil {
		t.Error("a claimed row without a lease was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE restart_requests SET state = 'claimed', lease_until = now()`); err == nil {
		t.Error("a claimed row without a claim token was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE restart_requests SET claim_token = '\x0102'`); err == nil {
		t.Error("a claim token of the wrong length was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE restart_requests SET state = 'bogus'`); err == nil {
		t.Error("an unknown state was accepted")
	}
	if _, err := provider.DownTo(ctx, 41); err != nil {
		t.Fatal("downgrade failed")
	}
	var gone bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('restart_requests') IS NULL`).Scan(&gone); err != nil || !gone {
		t.Fatal("downgrade left the queue table behind")
	}
	var orgs int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organizations`).Scan(&orgs); err != nil || orgs != 1 {
		t.Fatal("downgrade touched the organizations")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
	if _, err := db.ExecContext(ctx, insert, org, "Test", "key-2", fp); err != nil {
		t.Fatalf("upgraded table rejected a valid request again: %v", err)
	}
}
