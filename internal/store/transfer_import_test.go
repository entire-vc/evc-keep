package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/internal/testutil/transferfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func importFixture(t *testing.T) (context.Context, *TransferRows, uuid.UUID, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	ctx := context.Background()
	src, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("open source")
	}
	t.Cleanup(src.Close)
	org := uuid.New()
	run := strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))
	transferfixture.Seed(t, ctx, src, org, run[:7]+"A")
	rows := readRowsOf(t, ctx, src, org)
	tdsn := pgscratch.New(t, nil)
	migrateScratch(t, ctx, tdsn)
	dst, err := Open(ctx, tdsn)
	if err != nil {
		t.Fatal("open target")
	}
	t.Cleanup(dst.Close)
	return ctx, rows, org, dst
}

func ledgerEntry(org uuid.UUID, c string) TransferLedgerEntry {
	return TransferLedgerEntry{
		TransferID: uuid.New(), RecipientFingerprint: strings.Repeat(c, 64), OrgID: org,
		SourceID: uuid.New(), SnapshotID: uuid.New(),
		CiphertextChecksum: strings.Repeat("a", 64), AuditHead: strings.Repeat("b", 64),
	}
}

// runImport performs the import steps in one transaction; failAfter names a
// step after which a failure is injected.
func runImport(ctx context.Context, db *pgxpool.Pool, rows *TransferRows, e TransferLedgerEntry, failAfter string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	steps := []struct {
		name string
		fn   func() error
	}{
		{"lock", func() error { return LockTransferTarget(ctx, tx) }},
		{"empty", func() error { return RequireEmptyTransferTarget(ctx, tx) }},
		{"rows", func() error { return InsertTransferRows(ctx, tx, rows) }},
		{"seq", func() error { return RestartSealSeq(ctx, tx, rows.MaxSealSeq()) }},
		{"ledger", func() error { return InsertTransferLedger(ctx, tx, e) }},
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			return err
		}
		if s.name == failAfter {
			return errors.New("injected")
		}
	}
	return tx.Commit(ctx)
}

func countRows(t *testing.T, ctx context.Context, db *pgxpool.Pool, table string) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal("count")
	}
	return n
}

func seqState(t *testing.T, ctx context.Context, db *pgxpool.Pool) (last int64, called bool) {
	t.Helper()
	if err := db.QueryRow(ctx, "SELECT last_value, is_called FROM secret_versions_seal_seq_seq").Scan(&last, &called); err != nil {
		t.Fatal("seq")
	}
	return last, called
}

// Positive import, then every injected failure point leaves zero rows, no
// ledger entry and the sequence untouched; replay and a non-empty target are
// refused.
func TestTransferImportAtomic(t *testing.T) {
	ctx, rows, org, dst := importFixture(t)
	lastBefore, calledBefore := seqState(t, ctx, dst)
	for _, at := range []string{"lock", "empty", "rows", "seq", "ledger"} {
		if err := runImport(ctx, dst, rows, ledgerEntry(org, "c"), at); err == nil {
			t.Fatalf("injected failure after %s was not reported", at)
		}
		last, called := seqState(t, ctx, dst)
		if countRows(t, ctx, dst, "organizations") != 0 || countRows(t, ctx, dst, "audit_records") != 0 ||
			countRows(t, ctx, dst, "scoped_transfer_ledger") != 0 || last != lastBefore || called != calledBefore {
			t.Fatalf("partial effects after failure at %s", at)
		}
	}
	e := ledgerEntry(org, "d")
	if err := runImport(ctx, dst, rows, e, ""); err != nil {
		t.Fatalf("import: %v", err)
	}
	if countRows(t, ctx, dst, "organizations") != 1 || countRows(t, ctx, dst, "scoped_transfer_ledger") != 1 {
		t.Fatal("import did not land")
	}
	var next int64
	if err := dst.QueryRow(ctx, "SELECT nextval('secret_versions_seal_seq_seq')").Scan(&next); err != nil || next <= rows.MaxSealSeq() {
		t.Fatal("sequence not past the copied versions")
	}
	if err := runImport(ctx, dst, rows, ledgerEntry(org, "e"), ""); !errors.Is(err, ErrTransferTargetNotEmpty) {
		t.Fatal("non-empty target was not refused")
	}
	// Ledger replay on its own: same transfer id, then same recipient.
	for _, dup := range []TransferLedgerEntry{
		{TransferID: e.TransferID, RecipientFingerprint: strings.Repeat("f", 64)},
		{TransferID: uuid.New(), RecipientFingerprint: e.RecipientFingerprint},
	} {
		dup.OrgID, dup.SourceID, dup.SnapshotID = org, e.SourceID, e.SnapshotID
		dup.CiphertextChecksum, dup.AuditHead = e.CiphertextChecksum, e.AuditHead
		tx, err := dst.Begin(ctx)
		if err != nil {
			t.Fatal("begin")
		}
		if InsertTransferLedger(ctx, tx, dup) == nil {
			t.Fatal("ledger replay accepted")
		}
		_ = tx.Rollback(ctx)
	}
}

func TestRestartSealSeqRefusesOverflow(t *testing.T) {
	if RestartSealSeq(context.Background(), nil, int64(1)<<62) == nil || RestartSealSeq(context.Background(), nil, -1) == nil {
		t.Fatal("out-of-range sequence accepted")
	}
}

// While the importer holds its locks, no other session can write to any
// registry table: a writer waits (here: times out) instead of adding a row
// between the emptiness check and the commit.
func TestLockTransferTargetBlocksEveryWriter(t *testing.T) {
	ctx, _, _, dst := importFixture(t)
	probe := func(table string) error {
		tx, err := dst.Begin(ctx)
		if err != nil {
			t.Fatal("begin probe")
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '150ms'"); err != nil {
			t.Fatal("set timeout")
		}
		_, err = tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{table}.Sanitize()+" IN ROW EXCLUSIVE MODE")
		return err
	}
	tables := scopedtransfer.TablePolicies()
	for _, p := range tables {
		if err := probe(p.Name); err != nil {
			t.Fatalf("positive control: %s is locked before the importer took its locks: %v", p.Name, err)
		}
	}
	holder, err := dst.Begin(ctx)
	if err != nil {
		t.Fatal("begin holder")
	}
	if err := LockTransferTarget(ctx, holder); err != nil {
		t.Fatal("lock")
	}
	for _, p := range tables {
		if err := probe(p.Name); err == nil {
			t.Errorf("a writer could enter %s while the importer held the locks", p.Name)
		}
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal("release")
	}
	for _, p := range tables {
		if err := probe(p.Name); err != nil {
			t.Errorf("%s stays locked after the importer finished: %v", p.Name, err)
		}
	}
}
