package catalog

import (
	"context"
	"sort"
	"testing"
)

// closedSecretsColumns and closedSecretVersionsColumns are the closed list
// of every column these two tables may ever have. No column here can hold
// a secret's value or ciphertext; those live in the built-in provider's own
// tables or an external provider entirely — see 00004_catalog.sql's comment
// and package doc.
//
// Red-run proof this test can fail: add a column to either table's
// migration (e.g. `value TEXT` on secrets) and re-run — this test must go
// red, naming the extra column.
var (
	closedSecretsColumns = []string{
		"id", "org_id", "scope_level", "scope_id", "name", "class", "type",
		"store_id", "provider_ref", "description", "status", "created_at", "updated_at",
		"deployed_version", // a provider version label, the version laid out (00030)
	}
	closedSecretVersionsColumns = []string{
		"id", "org_id", "secret_id", "provider_version", "fingerprint", "length", "disabled", "created_at",
		"seal_seq", // the order versions were sealed in (00030)
	}
)

func TestSecretsTableSchemaIsClosed(t *testing.T) {
	assertColumns(t, "secrets", closedSecretsColumns)
}

func TestSecretVersionsTableSchemaIsClosed(t *testing.T) {
	assertColumns(t, "secret_versions", closedSecretVersionsColumns)
}

func assertColumns(t *testing.T, table string, want []string) {
	t.Helper()
	pool := testPool(t)
	rows, err := pool.Query(context.Background(), `
		SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
	`, table)
	if err != nil {
		t.Fatalf("list columns of %s: %v", table, err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		got = append(got, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read columns of %s: %v", table, err)
	}
	// Positive control: the walker actually found rows for a real table —
	// an empty result (e.g. table name typo, wrong schema) would otherwise
	// make an empty diff look identical to "verified closed".
	if len(got) == 0 {
		t.Fatalf("information_schema returned no columns for %s — the query is broken, not the table clean", table)
	}

	sort.Strings(got)
	wantSorted := append([]string{}, want...)
	sort.Strings(wantSorted)

	extra := diffStrings(got, wantSorted)
	missing := diffStrings(wantSorted, got)
	for _, c := range extra {
		t.Errorf("%s has an undeclared column %q — not in the closed list", table, c)
	}
	for _, c := range missing {
		t.Errorf("%s is missing declared column %q — closed list is stale", table, c)
	}
}

func diffStrings(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}
	var out []string
	for _, s := range a {
		if !inB[s] {
			out = append(out, s)
		}
	}
	return out
}
