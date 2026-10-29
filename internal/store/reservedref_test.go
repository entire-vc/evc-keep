package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A secrets row created outside the validated API (before an upgrade, or by
// hand) can carry Keep's own service-token locator; startup must refuse it,
// and neither the error nor anything it formats may carry the planted value
// or the locator itself — only a class and a row count.
func TestCheckReservedRefs(t *testing.T) {
	pool := migratedScratchPool(t)
	ctx := pgscratch.Context(t)
	c := canary.New()
	// the locator is planted with a canary tail so a leak of the ref is caught too
	ref := provider.ReservedRefPrefix + "-" + c.Value(1)
	org, st := uuid.New(), uuid.New()

	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name) VALUES($1,'reserved-ref')`, []any{org}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','reserved','org',$2)`, []any{st, org}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'ordinary','prod','generic',$3,'builtin://ordinary-secret')`, []any{uuid.New(), org, st}},
		// the prefix inside a longer ref is not a reserved ref
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'inside','prod','generic',$3,'builtin://x-mesh-service-token')`, []any{uuid.New(), org, st}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'inside-full','prod','generic',$3,$4)`, []any{uuid.New(), org, st, "x-" + provider.ReservedRefPrefix}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("seed catalog")
		}
	}
	// positive control: an ordinary ref passes
	if n, err := CheckReservedRefs(ctx, pool, provider.ReservedRefPrefix); err != nil || n != 0 {
		t.Fatalf("ordinary ref: rows=%d err=%v, want 0 and nil", n, err)
	}
	for i, suffix := range []string{"a", "b"} {
		if _, err := pool.Exec(ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref,description) VALUES($1,$2,'org',$2,$3,'prod','generic',$4,$5,$6)`,
			uuid.New(), org, c.Value(4)+suffix, st, ref+suffix, c.Value(2+i)); err != nil {
			t.Fatal("plant reserved ref")
		}
	}
	n, err := CheckReservedRefs(ctx, pool, provider.ReservedRefPrefix)
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Class != apperr.ClassInternal || n != 2 {
		t.Fatalf("reserved ref: rows=%d err class ok=%v, want 2 and an internal apperr", n, errors.As(err, &ae))
	}
	for _, text := range []string{err.Error(), ae.Message, string(ae.Class)} {
		if c.In(text) || strings.Contains(text, provider.ReservedRefPrefix) {
			t.Errorf("error text carries the planted ref or value: %q", text)
		}
	}
}

// migratedScratchPool is a pool on a fresh, fully migrated database of the
// test's own: planted reserved rows must not outlive the test or be seen by
// another package or job sharing KEEP_DATABASE_URL.
func migratedScratchPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	db, err := OpenMigrationDB(pgscratch.Context(t), pgscratch.DSN(t, dsn))
	if err != nil {
		t.Fatal("open migration db")
	}
	defer func() { _ = db.Close() }()
	provider, err := NewProvider(db)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err := provider.Up(pgscratch.MigrateContext(t)); err != nil {
		t.Fatal("migrate scratch database")
	}
	pool, err := pgxpool.New(pgscratch.Context(t), dsn)
	if err != nil {
		t.Fatal("open scratch pool")
	}
	t.Cleanup(pool.Close)
	return pool
}

// A database that cannot be read is a refusal, not a pass: a server that
// cannot count the rows must not start.
func TestCheckReservedRefsQueryFailure(t *testing.T) {
	pool := testPool(t)
	pool.Close()
	n, err := CheckReservedRefs(pgscratch.Context(t), pool, provider.ReservedRefPrefix)
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Class != apperr.ClassInternal || n != 0 {
		t.Fatalf("closed pool: rows=%d err=%v, want 0 and an internal apperr", n, err)
	}
}
