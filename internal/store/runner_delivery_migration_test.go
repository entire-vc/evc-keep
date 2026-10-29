package store

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

func TestRunnerDeliveryMigrationDowngradePreservesRunner(t *testing.T) {
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
		t.Fatal("migrate up")
	}
	const org = "018f4d1e-0000-7000-8000-000000000001"
	const runner = "018f4d1e-0000-7000-8000-000000000002"
	if _, err := db.ExecContext(pgscratch.Context(t), `INSERT INTO organizations (id, name) VALUES ($1, 'migration-test')`, org); err != nil {
		t.Fatal("seed organization")
	}
	for _, invalid := range []struct {
		id        string
		uidShared any
		labels    string
	}{
		{"018f4d1e-0000-7000-8000-000000000003", false, `{"platform":"linux"}`},
		{"018f4d1e-0000-7000-8000-000000000004", nil, `{"platform":"linux"}`},
	} {
		_, err := db.ExecContext(pgscratch.Context(t), `INSERT INTO runners (id, org_id, host, cert_serial, cert_not_after,
			uid_shared, host_labels, attrs_source)
			VALUES ($1, $2, 'invalid', 'serial', now() + interval '1 day', $3, $4, NULL)`,
			invalid.id, org, invalid.uidShared, invalid.labels)
		if err == nil {
			t.Fatal("runner accepted partial attributes without enrollment provenance")
		}
	}
	if _, err := db.ExecContext(pgscratch.Context(t), `INSERT INTO runners (id, org_id, host, cert_serial, cert_not_after,
		hpke_public_key, uid_shared, host_labels, attrs_source)
		VALUES ($1, $2, 'host.example.test', 'serial', now() + interval '1 day',
		decode(repeat('11', 32), 'hex'), false, '{"platform":"linux"}', 'enroll_token')`, runner, org); err != nil {
		t.Fatal("seed trusted runner")
	}
	if _, err := db.ExecContext(pgscratch.Context(t), `UPDATE runners SET attrs_source = NULL WHERE id = $1`, runner); err == nil {
		t.Fatal("runner update erased enrollment provenance but retained trusted attributes")
	}
	if _, err := provider.DownTo(pgscratch.Context(t), 12); err != nil {
		t.Fatal("downgrade delivery migration")
	}
	var count int
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT count(*) FROM runners WHERE id = $1`, runner).Scan(&count); err != nil || count != 1 {
		t.Fatal("downgrade lost runner identity")
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatal("upgrade delivery migration")
	}
	var key []byte
	if err := db.QueryRowContext(pgscratch.Context(t), `SELECT hpke_public_key FROM runners WHERE id = $1`, runner).Scan(&key); err != nil || key != nil {
		t.Fatal("upgraded legacy runner unexpectedly retained delivery trust")
	}
}
