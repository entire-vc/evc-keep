package audit

import (
	"context"
	"testing"
)

// TestAppRoleHasNoUpdatePrivilegeOnAnyAuditRecordsColumn closes the gap the
// table-level UPDATE test leaves: a column-level grant (GRANT UPDATE (scope)
// ...) lets keep_app rewrite that column and the single-column UPDATE the
// other rights test tries would never notice. Every column is asked
// directly.
func TestAppRoleHasNoUpdatePrivilegeOnAnyAuditRecordsColumn(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
		SELECT column_name,
		       has_column_privilege('keep_app', 'audit_records', column_name, 'UPDATE'),
		       has_column_privilege('keep_app', 'audit_records', column_name, 'INSERT'),
		       has_column_privilege('keep_app', 'audit_records', column_name, 'SELECT')
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'audit_records'`)
	if err != nil {
		t.Fatalf("query column privileges: %v", err)
	}
	defer rows.Close()

	var n int
	for rows.Next() {
		var col string
		var upd, ins, sel bool
		if err := rows.Scan(&col, &upd, &ins, &sel); err != nil {
			t.Fatalf("scan: %v", err)
		}
		n++
		if upd {
			t.Errorf("keep_app may UPDATE audit_records.%s", col)
		}
		// Positive control for the probe itself: the privileges keep_app is
		// meant to have are reported as held, so a false above is a real
		// "no" and not a probe that always answers "no".
		if !ins || !sel {
			t.Errorf("keep_app lacks INSERT/SELECT on audit_records.%s (insert=%v select=%v)", col, ins, sel)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if n < 30 {
		t.Fatalf("only %d columns inspected — the probe did not see the table", n)
	}
}
