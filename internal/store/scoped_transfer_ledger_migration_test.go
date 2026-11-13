package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgconn"
)

// The consumption ledger is append-only for every role, refuses a second use
// of one recipient, is not removed by deleting its organization, and the
// downgrade removes it cleanly.
func TestScopedTransferLedgerMigration(t *testing.T) {
	dsn := pgscratch.New(t, nil)
	ctx := pgscratch.Context(t)
	db, err := OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = db.Close() }()
	provider, err := NewProvider(db)
	if err != nil {
		t.Fatal("create migration provider")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("migrate up")
	}
	const org = "7d0e0a5e-0000-4000-8000-000000000001"
	if _, err := db.ExecContext(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'ledger')`, org); err != nil {
		t.Fatal("seed organization")
	}
	hex64 := func(c string) string { return strings.Repeat(c, 64) }
	const insert = `INSERT INTO scoped_transfer_ledger
		(transfer_id, recipient_fingerprint, org_id, source_id, snapshot_id, ciphertext_checksum, audit_head)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	const id1 = "7d0e0a5e-0000-4000-8000-0000000000a1"
	const id2 = "7d0e0a5e-0000-4000-8000-0000000000a2"
	const src = "7d0e0a5e-0000-4000-8000-0000000000b1"
	const snap = "7d0e0a5e-0000-4000-8000-0000000000c1"
	if _, err := db.ExecContext(ctx, insert, id1, hex64("a"), org, src, snap, hex64("b"), hex64("c")); err != nil {
		t.Fatal("valid ledger row rejected")
	}
	code := func(err error) string {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) {
			return pgerr.Code
		}
		return "none"
	}
	if _, err := db.ExecContext(ctx, insert, id2, hex64("a"), org, src, snap, hex64("b"), hex64("c")); code(err) != "23505" {
		t.Fatal("one recipient was consumed twice")
	}
	if _, err := db.ExecContext(ctx, insert, id2, "NOTHEX", org, src, snap, hex64("b"), hex64("c")); code(err) != "23514" {
		t.Fatal("malformed fingerprint accepted")
	}
	for name, stmt := range map[string]string{
		"update":   `UPDATE scoped_transfer_ledger SET audit_head = repeat('d', 64)`,
		"delete":   `DELETE FROM scoped_transfer_ledger`,
		"truncate": `TRUNCATE scoped_transfer_ledger`,
		"cascade":  `TRUNCATE organizations CASCADE`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err == nil {
			t.Fatal(name + " reached the append-only ledger")
		}
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM organizations WHERE id = $1`, org); code(err) != "23503" {
		t.Fatal("deleting an organization removed or bypassed its ledger")
	}
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM scoped_transfer_ledger`).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("ledger lost its row")
	}
	if _, err := provider.DownTo(ctx, 48); err != nil {
		t.Fatal("downgrade failed")
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('scoped_transfer_ledger') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatal("downgrade left the ledger")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("upgrade after the downgrade failed")
	}
}
