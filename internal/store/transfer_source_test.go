package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/google/uuid"
)

func embeddedVersions(t *testing.T) []int64 {
	t.Helper()
	v, err := embeddedMigrationVersions()
	if err != nil || len(v) == 0 {
		t.Fatal("embedded versions")
	}
	return v
}

func TestCheckMigrationHistoryRefusesDrift(t *testing.T) {
	good := embeddedVersions(t)
	if err := checkMigrationHistory(good); err != nil {
		t.Fatal("exact history refused")
	}
	cut := func(i int) []int64 { return append(append([]int64{}, good[:i]...), good[i+1:]...) }
	cases := map[string][]int64{
		"empty":   nil,
		"gap":     cut(len(good) / 2),
		"missing": good[:len(good)-1],
		"extra":   append(append([]int64{}, good...), good[len(good)-1]+1),
		"dup":     append(append([]int64{}, good...), good[len(good)-1]),
		"swapped": append([]int64{good[1], good[0]}, good[2:]...),
	}
	for name, h := range cases {
		if checkMigrationHistory(h) == nil {
			t.Fatalf("%s: drifted history accepted", name)
		}
	}
}

func TestReadTransferSourceIsOneSnapshot(t *testing.T) {
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("open")
	}
	t.Cleanup(db.Close)
	org := uuid.New()
	if _, err := db.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, "snap-"+org.String()); err != nil {
		t.Fatal("seed org")
	}
	// A writer commits between the inventory and the row read. One snapshot
	// must show neither in the inventory nor in the rows.
	in, rows, err := ReadTransferSource(ctx, db, org, func(scopedtransfer.Inventory) error {
		_, err := db.Exec(ctx, `INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)`, uuid.New(), org, "u"+uuid.NewString()[:8]+"@example.test")
		return err
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(rows.Users) != 0 {
		t.Fatal("rows saw a write committed after the inventory: not one snapshot")
	}
	for _, tc := range in.Tables {
		if tc.Name == "users" && tc.Rows != 0 {
			t.Fatal("inventory saw the write")
		}
	}
	// The accept hook can refuse; nothing is returned then.
	boom := errors.New("refuse")
	if _, r, err := ReadTransferSource(ctx, db, org, func(scopedtransfer.Inventory) error { return boom }); err == nil || r != nil {
		t.Fatal("refusal ignored")
	}
}

func TestRequireTransferTargetSchemaRefusesDriftedHistory(t *testing.T) {
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("open")
	}
	t.Cleanup(db.Close)
	try := func(mutate string) error {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal("begin")
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if mutate != "" {
			if _, err := tx.Exec(ctx, mutate); err != nil {
				t.Fatalf("mutate: %v", err)
			}
		}
		return RequireTransferTargetSchema(ctx, tx)
	}
	if err := try(""); err != nil {
		t.Fatal("the real history was refused")
	}
	// Rolled back with the transaction: nothing persists.
	if try(`INSERT INTO goose_db_version (version_id, is_applied) VALUES (99999, true)`) == nil {
		t.Fatal("a newer applied migration was accepted")
	}
	if try(`INSERT INTO goose_db_version (version_id, is_applied) VALUES ((SELECT max(version_id) FROM goose_db_version), false)`) == nil {
		t.Fatal("a rolled-back latest migration was accepted")
	}
	if try(`DELETE FROM goose_db_version WHERE version_id = 2`) == nil {
		t.Fatal("a missing migration was accepted")
	}
}
