package store

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgconn"
)

// 00038 adds the key-level request action. The downgrade keeps the journal
// rows (request and outcome, contiguous org_seq), refuses new request
// records, and the upgrade works again.
func TestKeyLevelAuditMigration_DowngradeKeepsHistory(t *testing.T) {
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
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZZ", 1, "org.key_level.requested"); err != nil {
		t.Fatal("new migration rejected the request action")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZY", 2, "org.key_level.changed"); err != nil {
		t.Fatal("new migration rejected the outcome action")
	}
	for i, action := range []string{"mesh.secret.put", "mesh.secret.resolve"} {
		if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZ"+string(rune('A'+i)), 10+i, action); err != nil {
			t.Fatal("new migration dropped an action registered by an earlier migration")
		}
	}
	if _, err := provider.DownTo(pgscratch.Context(t), 37); err != nil {
		t.Fatal("downgrade failed")
	}
	var rows, maxSeq int
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT count(*), coalesce(max(org_seq),0) FROM audit_records WHERE org_id='migration-org'`).Scan(&rows, &maxSeq); err != nil || rows != 4 || maxSeq != 11 {
		t.Fatal("downgrade lost journal history or left a gap in org_seq")
	}
	for i, action := range []string{"mesh.secret.put", "mesh.secret.resolve"} {
		if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZ"+string(rune('C'+i)), 12+i, action); err != nil {
			t.Fatal("downgrade to 37 narrowed the registry below version 37")
		}
	}
	_, err = db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZX", 3, "org.key_level.requested")
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" || pgerr.ConstraintName != "audit_records_action_closed" {
		t.Fatal("downgraded action registry did not reject a new request record")
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZX", 3, "org.key_level.requested"); err != nil {
		t.Fatal("upgraded registry rejected the request action")
	}
}
