package store

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// 00028 adds the rotate action, a rotation approval and the run's value
// length. The downgrade keeps journal history, removes what the older schema
// cannot hold, refuses new rotate records, and the upgrade works again.
func TestRotateAuditMigration_DowngradeShown(t *testing.T) {
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
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZZ", 1, "secret.rotate"); err != nil {
		t.Fatal("new migration rejected the rotate action")
	}
	org, secretID, run := uuid.New(), uuid.New(), uuid.New()
	if _, err := db.ExecContext(pgscratch.Context(t), `INSERT INTO organizations(id,name) VALUES($1,'rotate migration')`, org); err != nil {
		t.Fatal("insert organization")
	}
	const approval = `INSERT INTO approval_requests(id,org_id,deployment_request_id,rotation_secret_id,rotation_run_id,binding_hash,target_key)
		VALUES($1,$2,$3,$4,$5,decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'))`
	// A request that is both a deployment and a rotation, or neither, is refused.
	if _, err := db.ExecContext(pgscratch.Context(t), approval, uuid.New(), org, nil, nil, nil); err == nil {
		t.Fatal("an approval with no subject was accepted")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), approval, uuid.New(), org, nil, secretID, nil); err == nil {
		t.Fatal("a rotation approval with no run id was accepted")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), approval, uuid.New(), org, nil, secretID, run); err != nil {
		t.Fatal("new migration rejected a rotation approval")
	}
	if _, err := provider.DownTo(pgscratch.Context(t), 27); err != nil {
		t.Fatal("downgrade failed")
	}
	var history, approvals, cols int
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT count(*) FROM audit_records WHERE action='secret.rotate'`).Scan(&history); err != nil || history != 1 {
		t.Fatal("downgrade lost rotate history")
	}
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT count(*) FROM approval_requests`).Scan(&approvals); err != nil || approvals != 0 {
		t.Fatal("downgrade kept a rotation approval the older schema cannot hold")
	}
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT count(*) FROM information_schema.columns WHERE table_name='approval_requests' AND column_name IN ('rotation_run_id','rotation_secret_id')`).Scan(&cols); err != nil || cols != 0 {
		t.Fatal("downgrade kept the rotation columns")
	}
	_, err = db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZY", 2, "secret.rotate")
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" || pgerr.ConstraintName != "audit_records_action_closed" {
		t.Fatal("downgraded action registry did not reject a new rotate record")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZY", 2, "approval.decided"); err != nil {
		t.Fatal("downgraded registry rejected a previous action")
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZX", 3, "secret.rotate"); err != nil {
		t.Fatal("upgraded registry rejected the rotate action")
	}
}
