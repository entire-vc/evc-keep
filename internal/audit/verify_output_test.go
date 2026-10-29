package audit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgconn"
)

// Verify's result is read by operators and pasted into terminals and CI
// logs: a record id is returned only if it has the shape Append generates.
// A writer with INSERT on audit_records can put any text in the id column
// (here a canary followed by a newline and an ANSI erase-line that fakes a
// "chain OK" line); the id CHECK in the migration is dropped first because
// this test is about the output barrier that must hold without it.
func TestVerify_NeverReturnsAMalformedRecordID(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	j := NewJournal(pool)
	org := "org-badid"
	first, err := j.Append(ctx, newRecord(org, nil))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	pgscratch.DropConstraint(t, pool, "audit_records", "audit_records_id_shape")

	c := canary.New()
	badID := c.Value(1) + "\n\x1b[2Kchain OK"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE forged ON COMMIT DROP AS SELECT * FROM audit_records WHERE id = $1`, first.ID); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE forged SET id = $1, org_seq = 2`, badID); err != nil {
		t.Fatalf("forge: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_records SELECT * FROM forged`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	res, err := Verify(ctx, pool, org)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("forged record verified OK")
	}
	if res.BrokenID != MalformedID {
		t.Error("BrokenID is not the fixed placeholder")
	}
	if c.In(res.BrokenID) || strings.ContainsAny(res.BrokenID, "\n\x1b") {
		t.Error("BrokenID carries text from the id column")
	}
}

// dbErr is what keeps a database error's text (host and user in a pgx
// connection error, the failing row in a server error) out of what callers
// print. No database needed: every branch is exercised directly.
func TestDbErrKeepsOnlySQLStateAndContextSentinels(t *testing.T) {
	c := canary.New()
	leaky := c.Value(1)

	pgErr := &pgconn.PgError{Code: "23514", Message: "violates " + leaky, Detail: "Failing row contains (" + leaky + ")"}
	got := dbErr("op", pgErr)
	if c.In(got.Error()) || errors.As(got, new(*pgconn.PgError)) {
		t.Errorf("server error passed through: %v", got)
	}
	if !strings.Contains(got.Error(), "SQLSTATE 23514") {
		t.Errorf("SQLSTATE lost: %v", got)
	}

	got = dbErr("op", errors.New("failed to connect to host="+leaky+" user=u"))
	if c.In(got.Error()) {
		t.Errorf("connection error text passed through: %v", got)
	}

	if !errors.Is(dbErr("op", context.Canceled), context.Canceled) {
		t.Error("context.Canceled sentinel lost")
	}
	if !errors.Is(dbErr("op", context.DeadlineExceeded), context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded sentinel lost")
	}
}
