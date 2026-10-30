package store

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgconn"
)

// 00047 adds mesh.uninstall to the journal's closed registry. The downgrade
// keeps its history, refuses new records of it, keeps the previous actions,
// and the upgrade works again.
func TestMeshUninstallAuditMigration_DowngradeShown(t *testing.T) {
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
		VALUES ($1, 'migration-org', $2, now(), 'migration-request', 'org:migration-org', 'user', 'migration-admin', 'api', $3, 'ok', repeat('0',64), repeat('0',64))`
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZA", 1, "mesh.uninstall"); err != nil {
		t.Fatal("new migration rejected mesh.uninstall")
	}
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZB", 2, "mesh.uninstall.pending"); err == nil {
		t.Fatal("registry accepted an action nobody registered")
	}
	if _, err := provider.DownTo(ctx, 46); err != nil {
		t.Fatal("downgrade failed")
	}
	var history int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_records WHERE action = 'mesh.uninstall'`).Scan(&history); err != nil || history != 1 {
		t.Fatal("downgrade lost mesh.uninstall history")
	}
	_, err = db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZC", 3, "mesh.uninstall")
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" || pgerr.ConstraintName != "audit_records_action_closed" {
		t.Fatal("downgraded registry did not reject a new mesh.uninstall record")
	}
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZD", 4, "mesh.token"); err != nil {
		t.Fatal("downgraded registry rejected the previous action mesh.token")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZE", 5, "mesh.uninstall"); err != nil {
		t.Fatal("upgraded registry rejected mesh.uninstall")
	}
}
