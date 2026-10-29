package audit

import (
	"context"
	"strings"
	"testing"
)

// TestAppRoleCannotUpdateOrDeleteAuditRecords is the red run for the
// requirement "grant the application role UPDATE → the rights test fails."
// The grants themselves
// live in internal/store/migrations/00005_audit.sql — this test proves
// they actually take effect against a real database, the same role, same
// SET LOCAL ROLE mechanism Journal.Append itself uses (see journal.go), not
// against a description of what the migration says it does.
//
// Red-run proof: add `GRANT UPDATE ON audit_records TO
// keep_app;` to the migration's Up block and re-run — this test must go
// red with "expected UPDATE to be denied ... succeeded". Verified by hand in a
// scratch copy of the tree.
func TestAppRoleCannotUpdateOrDeleteAuditRecords(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()

	stored, err := j.Append(ctx, newRecord("org-rights", nil))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	// UPDATE and DELETE are each tried in their OWN transaction: Postgres
	// aborts a transaction on the first error within it (subsequent
	// statements fail with "current transaction is aborted", masking
	// whether the second statement itself would have been denied), so
	// proving both requires two clean transactions, not one transaction
	// with two attempts.
	runDenied := func(name, sql string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("%s: begin: %v", name, err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE keep_app"); err != nil {
			t.Fatalf("%s: set local role keep_app: %v", name, err)
		}
		if _, err := tx.Exec(ctx, sql, stored.ID); err == nil {
			t.Fatalf("expected %s on audit_records to be denied for keep_app, but it succeeded", name)
		} else if !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s was rejected, but not for the expected reason (want a permission-denied error): %v", name, err)
		}
	}

	runDenied("UPDATE", `UPDATE audit_records SET actor_id = 'should-not-work' WHERE id = $1`)
	runDenied("DELETE", `DELETE FROM audit_records WHERE id = $1`)
}

// TestAppRoleCannotTruncateAuditRecords is the third grant TestAppRoleCannotUpdateOrDeleteAuditRecords's
// own name promises but its body never tried: TRUNCATE bypasses row-level
// DELETE privilege entirely (it needs its own grant) and empties the table
// in one statement with no per-row trace — the migration's comment
// ("No UPDATE, no DELETE ... Deliberately no explicit REVOKE") only reasons
// about UPDATE/DELETE, so a reviewer reading just that comment could easily
// assume TRUNCATE was covered by the same absence-of-grant argument without
// anyone having actually run it against keep_app.
//
// Red-run proof (mirroring this file's UPDATE/DELETE red-run note above):
// add `GRANT TRUNCATE ON audit_records TO keep_app;` to the migration's Up
// block and re-run — this test must go red with "expected TRUNCATE to be
// denied ... succeeded". See scripts/check-audit-mutations.sh's
// keep-app-grant-truncate mutation for the automated version of that
// red run.
func TestAppRoleCannotTruncateAuditRecords(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()

	if _, err := j.Append(ctx, newRecord("org-rights-truncate", nil)); err != nil {
		t.Fatalf("Append: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE keep_app"); err != nil {
		t.Fatalf("set local role keep_app: %v", err)
	}
	if _, err := tx.Exec(ctx, `TRUNCATE audit_records`); err == nil {
		t.Fatal("expected TRUNCATE on audit_records to be denied for keep_app, but it succeeded")
	} else if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("TRUNCATE was rejected, but not for the expected reason (want a permission-denied error): %v", err)
	}
}

// TestAppRoleCanInsertAndSelect is the positive counterpart: keep_app must
// still be able to do its actual job (INSERT via Append; SELECT is
// exercised directly here under SET LOCAL ROLE keep_app, the same way
// TestAppRoleCannotUpdateOrDeleteAuditRecords exercises the denied
// statements — Verify itself runs as the pool's own login role, not
// keep_app, since keep-server audit verify is a read-only CLI operation
// with no need for keep_app's narrower grant) — a rights test that only
// ever asserts denial could pass even if the grants were completely broken
// in the other direction.
func TestAppRoleCanInsertAndSelect(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()

	stored, err := j.Append(ctx, newRecord("org-rights-positive", nil))
	if err != nil {
		t.Fatalf("Append (exercises keep_app INSERT): %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE keep_app"); err != nil {
		t.Fatalf("set local role keep_app: %v", err)
	}
	var gotID string
	if err := tx.QueryRow(ctx, `SELECT id FROM audit_records WHERE id = $1`, stored.ID).Scan(&gotID); err != nil {
		t.Fatalf("keep_app SELECT on audit_records: %v", err)
	}
	if gotID != stored.ID {
		t.Errorf("SELECT returned id %q, want %q", gotID, stored.ID)
	}

	res, err := Verify(ctx, pool, "org-rights-positive")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Errorf("Verify: OK=false, broken at %s/%d", res.BrokenID, res.BrokenPosition)
	}
}
