package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A secrets row under the reserved service-token locator makes the server
// refuse to start, before any listener, with no value and no locator in
// its output; the same database without that row starts.
func TestServeRefusesReservedRef(t *testing.T) {
	bin := buildKeepServer(t)
	dsn := pgscratch.New(t, requiredLogSettingsLiteral)
	migrate(t, bin, dsn)
	roleDSN := pgscratch.NewRole(t, dsn, "keep_app")
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open scratch database")
	}
	defer db.Close()
	c := canary.New()
	org, st := uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name) VALUES($1,'reserved-ref-serve')`, []any{org}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','reserved','org',$2)`, []any{st, org}},
	} {
		if _, err := db.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("seed catalog")
		}
	}
	file, id := serverRootKeyFile(t), "persistent-test"
	// positive control: without a reserved row this database starts
	if out, running, _ := runServeWithRoot(t, bin, roleDSN, 2*time.Second, file, id); !running {
		t.Fatalf("control start did not run: %q", out)
	}
	ref := provider.ReservedRefPrefix + "-" + c.Value(1)
	if _, err := db.Exec(ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref,description) VALUES($1,$2,'org',$2,$6,'prod','generic',$3,$4,$5)`,
		uuid.New(), org, st, ref, c.Value(2), c.Value(3)); err != nil {
		t.Fatal("plant reserved ref")
	}
	out, running, code := runServeWithRoot(t, bin, roleDSN, 2*time.Second, file, id)
	if running || code != 1 || strings.Contains(out, "listening") {
		t.Fatalf("server started over a reserved ref: running=%v code=%d", running, code)
	}
	if !strings.Contains(out, "reserved") || !strings.Contains(out, "rows=1") {
		t.Errorf("refusal names neither the class nor the row count: %q", out)
	}
	if c.In(out) || strings.Contains(out, provider.ReservedRefPrefix) {
		t.Error("planted value or locator leaked into server output")
	}
}
