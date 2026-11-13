package store

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/internal/testutil/transferfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func readRowsOf(t *testing.T, ctx context.Context, db *pgxpool.Pool, org uuid.UUID) *TransferRows {
	t.Helper()
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("begin")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := readTransferRows(ctx, tx, org)
	if err != nil {
		t.Fatalf("read rows: %v", err)
	}
	return rows
}

func TestTransferRowsRoundTripAcrossDatabases(t *testing.T) {
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
	a, b := uuid.New(), uuid.New()
	run := strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))
	transferfixture.Seed(t, ctx, src, a, run[:7]+"A")
	transferfixture.Seed(t, ctx, src, b, run[7:14]+"B")
	got := readRowsOf(t, ctx, src, a)

	// Positive control: every copied table has rows, so an empty comparison
	// cannot pass. Foreign rows of org b must not appear in a's snapshot.
	v := reflect.ValueOf(*got)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Len() == 0 {
			t.Fatalf("fixture leaves %s empty", v.Type().Field(i).Name)
		}
	}
	if len(got.Organizations) != 1 || got.Organizations[0].ID != a || len(got.Users) != 2 {
		t.Fatal("snapshot crossed organizations")
	}

	// Insert into an independent, freshly migrated database and read back.
	tdsn := pgscratch.New(t, nil)
	migrateScratch(t, ctx, tdsn)
	dst, err := Open(ctx, tdsn)
	if err != nil {
		t.Fatal("open target")
	}
	t.Cleanup(dst.Close)
	tx, err := dst.Begin(ctx)
	if err != nil {
		t.Fatal("begin target")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertTransferRows(ctx, tx, got); err != nil {
		t.Fatalf("insert rows: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit target")
	}
	back := readRowsOf(t, ctx, dst, a)
	if !reflect.DeepEqual(got, back) {
		t.Fatal("rows changed across the round trip")
	}
	// No upsert: a second insert of the same rows fails and changes nothing.
	tx2, err := dst.Begin(ctx)
	if err != nil {
		t.Fatal("begin second target")
	}
	defer func() { _ = tx2.Rollback(ctx) }()
	if err := insertTransferRows(ctx, tx2, got); err == nil {
		t.Fatal("second insert of the same rows succeeded")
	}
}

func migrateScratch(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	db, err := OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = db.Close() }()
	p, err := NewProvider(db)
	if err != nil {
		t.Fatal("create migration provider")
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal("migrate up")
	}
}
