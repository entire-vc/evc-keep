package audit

import (
	"context"
	"strings"
	"testing"
)

// TestAppendRunsAsKeepApp proves Journal.Append's `SET LOCAL ROLE keep_app`
// is actually in effect for the INSERT. The pool's login role is a
// superuser in CI and local dev, so without the switch every other test
// passes anyway. A BEFORE INSERT trigger, installed here by the superuser,
// refuses any insert not running as keep_app.
func TestAppendRunsAsKeepApp(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	for _, stmt := range []string{
		`CREATE FUNCTION audit_probe_role() RETURNS trigger LANGUAGE plpgsql AS $fn$
		 BEGIN
		   IF current_user <> 'keep_app' THEN
		     RAISE EXCEPTION 'probe: insert ran as %', current_user;
		   END IF;
		   RETURN NEW;
		 END $fn$`,
		`CREATE TRIGGER audit_probe BEFORE INSERT ON audit_records
		 FOR EACH ROW EXECUTE FUNCTION audit_probe_role()`,
	} {
		superuserExec(t, pool, stmt)
	}

	// Positive control: the trigger really fires for a non-keep_app insert.
	_, err := pool.Exec(ctx, `INSERT INTO audit_records (
		id, org_id, org_seq, ts, request_id, scope, actor_type, actor_id, actor_via,
		action, result_status, prev_hash, hash
	) VALUES ('probe', 'org-probe', 1, now(), '', '', 'system', '', 'api',
		'probe.run', 'ok', '', '')`)
	if err == nil || !strings.Contains(err.Error(), "probe: insert ran as") {
		t.Fatalf("probe trigger did not fire for a superuser insert: %v", err)
	}

	if _, err := NewJournal(pool).Append(ctx, newRecord("org-probe", nil)); err != nil {
		t.Fatalf("Append did not run as keep_app: %v", err)
	}
}
