package store

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// The seal-order migration numbers existing versions deterministically, points
// each secret at the version its newest finished run laid out, continues the
// sequence after the backfill, and goes down and up again.
func TestSealSeqMigrationBackfillDowngradeAndUpgrade(t *testing.T) {
	dsn := pgscratch.New(t, nil)
	db, err := OpenMigrationDB(pgscratch.Context(t), dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = db.Close() }()
	provider, err := NewProvider(db)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err := provider.UpTo(pgscratch.Context(t), 29); err != nil {
		t.Fatal("migrate up to 29")
	}
	// Rows are inserted out of time order on purpose: the backfill numbers by
	// (created_at, id), not by physical order. Foreign keys are off for the
	// seed only; the migration does not depend on them.
	seed := []string{
		`SET session_replication_role = replica`,
		`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref)
		 VALUES ('00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000f1','org','00000000-0000-0000-0000-0000000000f1','s','c','t','00000000-0000-0000-0000-0000000000e1','p'),
		        ('00000000-0000-0000-0000-0000000000a2','00000000-0000-0000-0000-0000000000f1','org','00000000-0000-0000-0000-0000000000f1','s2','c','t','00000000-0000-0000-0000-0000000000e1','p2')`,
		`INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length,created_at) VALUES
		 ('00000000-0000-0000-0000-0000000000b3','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000a1','v-late','kfp1:k:aaaaaaaaaaaaaaaa',1,'2026-01-03'),
		 ('00000000-0000-0000-0000-0000000000b1','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000a1','v-early','kfp1:k:aaaaaaaaaaaaaaaa',1,'2026-01-01'),
		 ('00000000-0000-0000-0000-0000000000b2','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000a1','v-mid','kfp1:k:aaaaaaaaaaaaaaaa',1,'2026-01-02'),
		 ('00000000-0000-0000-0000-0000000000b4','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000a2','w-only','kfp1:k:aaaaaaaaaaaaaaaa',1,'2026-01-02')`,
		// A finished run of v-mid and an unfinished run of v-late: only the finished one deploys.
		`INSERT INTO rotation_runs(id,org_id,secret_id,state,new_version) VALUES
		 ('00000000-0000-0000-0000-0000000000c1','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000a1','done','v-mid'),
		 ('00000000-0000-0000-0000-0000000000c2','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000a1','failed','v-late')`,
		`RESET session_replication_role`,
	}
	for _, q := range seed {
		if _, err := db.ExecContext(pgscratch.Context(t), q); err != nil {
			t.Fatalf("seed failed: %v", err)
		}
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	rows, err := db.QueryContext(pgscratch.Context(t), `SELECT provider_version FROM secret_versions ORDER BY seal_seq`)
	if err != nil {
		t.Fatal("read seal order")
	}
	var order []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) != nil {
			t.Fatal("scan seal order")
		}
		order = append(order, v)
	}
	_ = rows.Close()
	if got := len(order); got != 4 || order[0] != "v-early" || order[3] != "v-late" || order[1] == "v-late" {
		t.Fatalf("seal order %v does not follow (created_at, id)", order)
	}
	var dep1 string
	var dep2 *string
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT deployed_version FROM secrets WHERE name='s'`).Scan(&dep1); err != nil || dep1 != "v-mid" {
		t.Fatalf("deployed_version of the run-deployed secret = %q (err %v), want v-mid", dep1, err)
	}
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT deployed_version FROM secrets WHERE name='s2'`).Scan(&dep2); err != nil || dep2 != nil {
		t.Fatal("a secret no run deployed must have no deployed_version")
	}
	var next, max int64
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT max(seal_seq) FROM secret_versions`).Scan(&max); err != nil {
		t.Fatal("read max seal_seq")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), `SET session_replication_role = replica`); err != nil {
		t.Fatal("replica role")
	}
	if err := db.QueryRowContext(pgscratch.Context(t), `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length)
		VALUES ('00000000-0000-0000-0000-0000000000b9','00000000-0000-0000-0000-0000000000f1','00000000-0000-0000-0000-0000000000a2','w-next','kfp1:k:aaaaaaaaaaaaaaaa',1) RETURNING seal_seq`).Scan(&next); err != nil || next <= max {
		t.Fatalf("a new version took seal_seq %d (err %v), want above the backfill max %d", next, err, max)
	}
	if _, err := provider.DownTo(pgscratch.Context(t), 29); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	var n int
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT count(*) FROM information_schema.columns WHERE table_name IN ('secret_versions','secrets') AND column_name IN ('seal_seq','deployed_version')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("downgrade left %d new columns", n)
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
}
