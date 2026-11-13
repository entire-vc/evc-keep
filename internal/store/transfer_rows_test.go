package store

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
)

// The typed tables are exactly the registry's copied tables, in the order the
// registry lists them for classification, and every one has a scope rule.
func TestTransferTablesAreTheCopiedRegistryTables(t *testing.T) {
	want := map[string]bool{}
	for _, p := range scopedtransfer.TablePolicies() {
		if p.Disposition == scopedtransfer.CopyRows || p.Disposition == scopedtransfer.RewrapRows {
			want[p.Name] = true
		}
	}
	got := map[string]bool{}
	for _, tb := range transferTables {
		if got[tb.name] || !want[tb.name] {
			t.Fatalf("table %s is duplicated or not a copied registry table", tb.name)
		}
		got[tb.name] = true
		if _, ok := scopeWhere(tb.name); !ok {
			t.Fatalf("table %s has no scope rule", tb.name)
		}
	}
	if len(got) != len(want) {
		t.Fatal("a copied registry table has no typed rows")
	}
}

// The column lists are the whole live column list of each table, in order:
// a column added to a migration without a reviewed profile change fails here
// (the migration pin fails first, this names the table).
func TestTransferRowsMatchSchema(t *testing.T) {
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
	for _, tb := range transferTables {
		rows, err := db.Query(ctx, `SELECT column_name FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position`, tb.name)
		if err != nil {
			t.Fatal("query columns")
		}
		var live []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal("scan column")
			}
			live = append(live, c)
		}
		rows.Close()
		if !reflect.DeepEqual(live, tb.cols) {
			t.Fatalf("table %s: typed columns differ from the live schema", tb.name)
		}
	}
}
