package store

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgconn"
)

// 00064 adds mesh.approvals_channel to the journal's closed registry and the
// signed time of the last applied settings snapshot to mesh_installations.
// The downgrade keeps the journal's history, refuses new records of the
// action, keeps the previous actions and drops the column; the upgrade works
// again.
func TestMeshApprovalsChannelMigration_DowngradeShown(t *testing.T) {
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
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZA", 1, "mesh.approvals_channel"); err != nil {
		t.Fatal("new migration rejected mesh.approvals_channel")
	}
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZB", 2, "mesh.approvals_channel.x"); err == nil {
		t.Fatal("registry accepted an action nobody registered")
	}
	column := func() int {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'mesh_installations' AND column_name = 'settings_signed_at' AND data_type = 'bigint'`).Scan(&n); err != nil {
			t.Fatal("read the settings_signed_at column")
		}
		return n
	}
	if column() != 1 {
		t.Fatal("new migration did not add settings_signed_at BIGINT")
	}
	if _, err := provider.DownTo(ctx, 59); err != nil {
		t.Fatal("downgrade failed")
	}
	if column() != 0 {
		t.Fatal("downgrade kept settings_signed_at")
	}
	var history int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_records WHERE action = 'mesh.approvals_channel'`).Scan(&history); err != nil || history != 1 {
		t.Fatal("downgrade lost mesh.approvals_channel history")
	}
	_, err = db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZC", 3, "mesh.approvals_channel")
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" || pgerr.ConstraintName != "audit_records_action_closed" {
		t.Fatal("downgraded registry did not reject a new mesh.approvals_channel record")
	}
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZD", 4, "carrier.adopt.result"); err != nil {
		t.Fatal("downgraded registry rejected the previous action carrier.adopt.result")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
	if column() != 1 {
		t.Fatal("upgrade after the downgrade did not add settings_signed_at")
	}
	if _, err := db.ExecContext(ctx, insert, "01J8ZZZZZZZZZZZZZZZZZZZZZE", 5, "mesh.approvals_channel"); err != nil {
		t.Fatal("upgraded registry rejected mesh.approvals_channel")
	}
}
