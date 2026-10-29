package app

import (
	"context"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool migrates a fresh scratch database for this test. Cleanup closes
// the pool before pgscratch drops the database; the shared schema is untouched.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	mdb, err := store.OpenMigrationDB(pgscratch.Context(t), dsn)
	if err != nil {
		t.Fatalf("open migration db: %v", err)
	}
	defer func() { _ = mdb.Close() }()

	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatalf("new migration provider: %v", err)
	}
	if _, err := provider.Up(pgscratch.MigrateContext(t)); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	pool, err := pgxpool.New(pgscratch.Context(t), dsn)
	if err != nil {
		t.Fatalf("open test pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestPrintAuditVerify_CleanChain is the "green" half of the CLI's own
// contract: a clean chain reports OK and a count, exit 0.
func TestPrintAuditVerify_CleanChain(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	j := audit.NewJournal(pool)

	for i := 0; i < 3; i++ {
		if _, err := j.Append(ctx, audit.Record{
			OrgID:  "org-cli-clean",
			Action: "secret.create_ref",
			Actor:  audit.Actor{Type: audit.ActorAgent, ID: "agent-1", Via: audit.ViaAPI},
			Result: audit.Result{Status: audit.StatusOK},
		}); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}

	var out strings.Builder
	code := printAuditVerify(ctx, &out, pool, "org-cli-clean")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "chain OK") || !strings.Contains(out.String(), "3") {
		t.Errorf("output = %q, want it to mention chain OK and a count of 3", out.String())
	}
}

// TestPrintAuditVerify_BrokenChainReportsOnlyIDAndPosition is the "red" half
// — the CLI's own requirement: it prints the id and position of the first
// broken record, and never prints field values. A canary placed in a
// tampered record's Intent.Reason must never appear in the CLI's stdout,
// even though the CLI is the thing that DETECTED the break.
//
// The tamper below hits Scope, NOT Intent.Reason: the canary must still be a
// LIVE value in the database at the moment printAuditVerify runs, or this
// test can't tell a real leak from a leak that can't happen because the
// value it would leak was already overwritten by the tamper itself.
// Tampering intent_reason directly (an earlier version of this test)
// replaced the canary with the literal string "tampered" before Verify ever
// read the row back — so a mutant that made VerifyResult.BrokenID carry
// rec.Intent.Reason would print "tampered", not the canary, and this test
// would stay green either way.
func TestPrintAuditVerify_BrokenChainReportsOnlyIDAndPosition(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	j := audit.NewJournal(pool)

	c := canary.New()
	secret := c.Value(1)

	if _, err := j.Append(ctx, audit.Record{
		OrgID:  "org-cli-broken",
		Action: "secret.create_ref",
		Actor:  audit.Actor{Type: audit.ActorAgent, ID: "agent-1", Via: audit.ViaAPI},
		Result: audit.Result{Status: audit.StatusOK},
	}); err != nil {
		t.Fatalf("Append #0: %v", err)
	}
	target, err := j.Append(ctx, audit.Record{
		OrgID:  "org-cli-broken",
		Action: "secret.create_ref",
		Actor:  audit.Actor{Type: audit.ActorAgent, ID: "agent-1", Via: audit.ViaAPI},
		Scope:  "proj:demo",
		Intent: audit.Intent{Reason: secret},
		Result: audit.Result{Status: audit.StatusOK},
	})
	if err != nil {
		t.Fatalf("Append #1: %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE audit_records SET scope = 'tampered' WHERE id = $1`, target.ID); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	var out strings.Builder
	code := printAuditVerify(ctx, &out, pool, "org-cli-broken")
	if code == 0 {
		t.Fatal("exit code = 0, want nonzero for a broken chain")
	}
	got := out.String()
	if !strings.Contains(got, target.ID) {
		t.Errorf("output %q does not name the broken record's id %q", got, target.ID)
	}
	if !strings.Contains(got, "2") {
		t.Errorf("output %q does not name the broken record's position (2)", got)
	}
	if c.In(got) {
		t.Errorf("canary leaked into CLI output: %q", got)
	}
}

// The CLI prints a record id only when it has the shape Append generates:
// a keep_app-level writer can put any text in the id column, including a
// newline and an ANSI erase-line that fakes a "chain OK" line in an
// operator's terminal or a CI log. The migration's id CHECK is dropped first
// because this is about the output barrier that must hold without it — on a
// scratch database, so the shared KEEP_DATABASE_URL one keeps its constraint.
func TestPrintAuditVerify_NeverEchoesAForgedRecordID(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	j := audit.NewJournal(pool)
	first, err := j.Append(ctx, audit.Record{
		OrgID:  "org-cli-badid",
		Action: "secret.create_ref",
		Actor:  audit.Actor{Type: audit.ActorAgent, ID: "agent-1", Via: audit.ViaAPI},
		Result: audit.Result{Status: audit.StatusOK},
	})
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

	var out strings.Builder
	if code := printAuditVerify(ctx, &out, pool, "org-cli-badid"); code == 0 {
		t.Fatal("exit code = 0 for a chain with a forged record")
	}
	got := out.String()
	if c.In(got) || strings.ContainsAny(got, "\x1b") || strings.Count(got, "\n") != 1 {
		t.Error("CLI output carries text from the id column")
	}
	if !strings.Contains(got, audit.MalformedID) {
		t.Error("CLI output does not show the placeholder for the malformed id")
	}
}
