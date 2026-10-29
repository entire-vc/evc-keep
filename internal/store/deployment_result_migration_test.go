package store

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgconn"
)

// Each database operation takes its own deadline from pgscratch.Context: one
// shared 10s budget across up, down and up again expired on a loaded CI server.
func TestDeploymentResultMigrationPreservesHistory(t *testing.T) {
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
		t.Fatalf("migrate up failed (%s)", pgscratch.ErrClass(err))
	}
	const insert = `INSERT INTO audit_records
		(id, org_id, org_seq, ts, request_id, scope, actor_type, actor_id, actor_via, action, result_status, prev_hash, hash)
		VALUES ($1, 'migration-org', $2, now(), 'migration-request', 'org:migration-org', 'runner', 'migration-runner', 'api', $3, 'ok', repeat('0',64), repeat('0',64))`
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZZ", 1, "deploy.result"); err != nil {
		t.Fatalf("new migration rejected deploy result (%s)", pgscratch.ErrClass(err))
	}
	if _, err := provider.DownTo(pgscratch.Context(t), 16); err != nil {
		t.Fatalf("downgrade rejected existing result history (%s)", pgscratch.ErrClass(err))
	}
	var history, neighbors int
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT count(*) FROM audit_records WHERE action='deploy.result'`).Scan(&history); err != nil || history != 1 {
		t.Fatal("downgrade lost result history")
	}
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('deployment_jobs','approval_requests','carriers','runners','intake_links')`).Scan(&neighbors); err != nil || neighbors != 5 {
		t.Fatal("result downgrade changed prerequisite schema")
	}
	_, err = db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZY", 2, "deploy.result")
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" || pgerr.ConstraintName != "audit_records_action_closed" {
		t.Fatal("downgraded action registry did not reject a new result")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZY", 2, "deploy.requested"); err != nil {
		t.Fatal("downgraded registry rejected admission action")
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatalf("upgrade with existing result history failed (%s)", pgscratch.ErrClass(err))
	}
	if _, err := db.ExecContext(pgscratch.Context(t), insert, "01J8ZZZZZZZZZZZZZZZZZZZZZX", 3, "deploy.result"); err != nil {
		t.Fatal("upgraded registry rejected deploy result")
	}
}
