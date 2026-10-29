package store

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgconn"
)

// 00035 adds the two Mesh secrets actions to the journal's closed registry.
// The downgrade keeps their history, refuses new records of them, keeps the
// previous actions, and the upgrade works again.
func TestMeshSecretAuditMigration_DowngradeShown(t *testing.T) {
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
	const insert = `INSERT INTO audit_records
		(id, org_id, org_seq, ts, request_id, scope, actor_type, actor_id, actor_via, action, result_status, prev_hash, hash)
		VALUES ($1, 'migration-org', $2, now(), 'migration-request', 'org:migration-org', 'service', 'migration-ws', 'mesh-plugin', $3, 'ok', repeat('0',64), repeat('0',64))`
	for i, a := range []string{"mesh.secret.put", "mesh.secret.resolve"} {
		if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZ"+string(rune('A'+i)), i+1, a); err != nil {
			t.Fatalf("new migration rejected %s", a)
		}
	}
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZC", 3, "mesh.secret.delete"); err == nil {
		t.Fatal("registry accepted an action nobody registered")
	}
	if _, err := provider.DownTo(ctx, 34); err != nil {
		t.Fatal("downgrade failed")
	}
	var history int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_records WHERE action LIKE 'mesh.secret.%'`).Scan(&history); err != nil || history != 2 {
		t.Fatal("downgrade lost Mesh secrets history")
	}
	_, err = db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZD", 4, "mesh.secret.put")
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" || pgerr.ConstraintName != "audit_records_action_closed" {
		t.Fatal("downgraded registry did not reject a new mesh.secret.put record")
	}
	for i, a := range []string{"secret.rotate", "mesh.install"} {
		if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZ"+string(rune('E'+i)), 5+i, a); err != nil {
			t.Fatalf("downgraded registry rejected the previous action %s", a)
		}
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZG", 7, "mesh.secret.resolve"); err != nil {
		t.Fatal("upgraded registry rejected mesh.secret.resolve")
	}
}
