package store

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

func TestRunnerRevokeMigration_DowngradePreservesHistory(t *testing.T) {
	dsn := pgscratch.New(t, nil)
	db, err := OpenMigrationDB(pgscratch.Context(t), dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = db.Close() }()
	provider, err := NewProvider(db)
	if err != nil {
		t.Fatal("create migration provider")
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatal("migrate up")
	}
	const insert = `INSERT INTO audit_records
		(id, org_id, org_seq, ts, request_id, scope, actor_type, actor_id, actor_via, action, result_status, prev_hash, hash)
		VALUES ($1, 'migration-org', $2, now(), 'migration-request', 'org:migration-org', 'user', 'migration-user', 'api', $3, 'ok', repeat('0',64), repeat('0',64))`
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZZ", 1, "runner.revoke"); err != nil {
		t.Fatal("new migration rejected runner revoke")
	}
	if _, err := provider.DownTo(pgscratch.Context(t), 10); err != nil {
		t.Fatal("downgrade rejected existing revoke history")
	}
	var count int
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT count(*) FROM audit_records WHERE action='runner.revoke'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("downgrade lost revoke history")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZY", 2, "runner.revoke"); err == nil {
		t.Fatal("downgraded registry accepted a new revoke record")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZY", 2, "runner.enroll"); err != nil {
		t.Fatal("downgraded registry rejected a previous action")
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatal("upgrade with existing revoke history failed")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZX", 3, "runner.revoke"); err != nil {
		t.Fatal("upgraded registry rejected runner revoke")
	}
}
