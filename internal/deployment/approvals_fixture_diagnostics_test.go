package deployment

import (
	"errors"
	"strings"
	"testing"
)

// Match only whole, known sanitized store errors. Never retain driver text.
func migrationFixtureCause(err error) string {
	if err == nil {
		return "unknown"
	}
	text := err.Error()
	switch text {
	case "open migration database handle: invalid KEEP_DATABASE_URL":
		return "invalid_dsn"
	case "open migration database handle: connection failed (database operation deadline exceeded)":
		return "database_deadline"
	case "open migration database handle: connection failed (unclassified)":
		return "connection_unclassified"
	case `default_query_exec_mode=simple_protocol would write parameter values into the server log — see "Database requirements" in README.md`,
		`default_query_exec_mode=exec would write parameter values into the server log — see "Database requirements" in README.md`:
		return "unsafe_query_mode"
	}
	for _, code := range []string{"08000", "08001", "08006", "28000", "28P01", "3D000", "53300", "57P03", "57014"} {
		if text == "open migration database handle: connection failed ("+code+")" {
			return "connection_sqlstate code=" + code
		}
	}
	return "unknown"
}

func TestMigrationFixtureCauseSafeAllowlist(t *testing.T) {
	const canary = "private-fixture-canary"
	cases := []struct {
		input string
		want  string
	}{
		{"open migration database handle: invalid KEEP_DATABASE_URL", "invalid_dsn"},
		{"open migration database handle: connection failed (database operation deadline exceeded)", "database_deadline"},
		{"open migration database handle: connection failed (unclassified)", "connection_unclassified"},
		{`default_query_exec_mode=exec would write parameter values into the server log — see "Database requirements" in README.md`, "unsafe_query_mode"},
		{`default_query_exec_mode=simple_protocol would write parameter values into the server log — see "Database requirements" in README.md`, "unsafe_query_mode"},
		{canary, "unknown"},
		{"open migration database handle: invalid KEEP_DATABASE_URL " + canary, "unknown"},
		{"open migration database handle: connection failed (28P01) " + canary, "unknown"},
		{canary + "open migration database handle: connection failed (28P01)", "unknown"},
		{"open migration database handle: connection failed (ZZZZZ)", "unknown"},
		{"open migration database handle: connection failed (" + canary + ")", "unknown"},
		{"open migration database handle: connection failed (28p01)", "unknown"},
	}
	for _, code := range []string{"08000", "08001", "08006", "28000", "28P01", "3D000", "53300", "57P03", "57014"} {
		cases = append(cases, struct{ input, want string }{"open migration database handle: connection failed (" + code + ")", "connection_sqlstate code=" + code})
	}
	for i, c := range cases {
		got := migrationFixtureCause(errors.New(c.input))
		if got != c.want || strings.Contains(got, canary) {
			t.Errorf("case %d: unsafe or incorrect classification", i)
		}
	}
	if migrationFixtureCause(nil) != "unknown" {
		t.Fatal("nil error must remain unknown")
	}
}
