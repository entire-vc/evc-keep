package store

import (
	"context"
	"testing"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// The pin is what the supported migrations produce on the CI PostgreSQL.
func TestLiveCatalogMatchesPin(t *testing.T) {
	ctx := context.Background()
	dsn := pgscratch.New(t, nil)
	migrateScratch(t, ctx, dsn)
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("open")
	}
	t.Cleanup(db.Close)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal("begin")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	got, err := LiveCatalogID(ctx, tx)
	if err != nil || got != scopedtransfer.CatalogID {
		t.Fatalf("live catalog %s is not the pinned %s (err=%v)", got, scopedtransfer.CatalogID, err)
	}
	if err := RequireTransferTargetSchema(ctx, tx); err != nil {
		t.Fatal("pristine target refused")
	}
}

// A catalog altered by hand under an unchanged goose history must be refused
// on the target and must change the source inventory so the plan refuses it.
func TestCatalogGuardRefusesHandAlteredSchema(t *testing.T) {
	ctx := context.Background()
	for name, alter := range map[string]string{
		"added column":            `ALTER TABLE users ADD COLUMN extra_note text`,
		"dropped not null":        `ALTER TABLE users ALTER COLUMN email DROP NOT NULL`,
		"added index":             `CREATE INDEX hand_made_idx ON users (created_at)`,
		"changed default":         `ALTER TABLE users ALTER COLUMN email SET DEFAULT 'x'`,
		"added constraint":        `ALTER TABLE users ADD CONSTRAINT hand_made_chk CHECK (length(email) < 1000)`,
		"extra table":             `CREATE TABLE transfer_extra (id bigint)`,
		"extra partitioned table": `CREATE TABLE transfer_extra_part (id bigint) PARTITION BY RANGE (id)`,
		"extra view":              `CREATE VIEW transfer_extra_view AS SELECT id FROM users`,
		"extra materialized view": `CREATE MATERIALIZED VIEW transfer_extra_mv AS SELECT id FROM users`,
		"extra enum type":         `CREATE TYPE transfer_extra_enum AS ENUM ('a')`,
		"extra procedure":         `CREATE PROCEDURE transfer_extra_proc() LANGUAGE SQL AS 'SELECT 1'`,
		"extra aggregate":         `CREATE AGGREGATE transfer_extra_agg(int) (SFUNC = int4pl, STYPE = int)`,
		"extra domain":            `CREATE DOMAIN transfer_extra_domain AS text`,
		"sequence increment":      `ALTER SEQUENCE secret_versions_seal_seq_seq INCREMENT BY -1`,
		"sequence cycle":          `ALTER SEQUENCE secret_versions_seal_seq_seq CYCLE`,
		"sequence unowned":        `ALTER SEQUENCE secret_versions_seal_seq_seq OWNED BY NONE`,
		"disabled trigger":        `ALTER TABLE scoped_transfer_ledger DISABLE TRIGGER scoped_transfer_ledger_no_truncate`,
		"enabled row security":    `ALTER TABLE users ENABLE ROW LEVEL SECURITY`,
		"replaced function":       `CREATE OR REPLACE FUNCTION scoped_transfer_ledger_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`,
	} {
		dsn := pgscratch.New(t, nil)
		migrateScratch(t, ctx, dsn)
		db, err := Open(ctx, dsn)
		if err != nil {
			t.Fatal("open")
		}
		t.Cleanup(db.Close)
		if _, err := db.Exec(ctx, alter); err != nil {
			t.Fatalf("%s: setup statement failed", name)
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal("begin")
		}
		if err := RequireTransferTargetSchema(ctx, tx); err == nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("%s: altered target accepted", name)
		}
		_ = tx.Rollback(ctx)
		in, err := ReadTransferInventory(ctx, db, [16]byte{1})
		if err != nil || in.CatalogID == scopedtransfer.CatalogID {
			t.Fatalf("%s: altered source reports the pinned catalog", name)
		}
	}
}
