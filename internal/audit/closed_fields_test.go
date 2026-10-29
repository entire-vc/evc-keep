package audit

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/jackc/pgx/v5/pgconn"
)

// closedFieldCases sets one closed field at a time to a canary; each must be
// refused by Append before anything is stored, and the refusal must name the
// field, never carry the offending text.
func closedFieldCases(bad string) map[string]func(*Record) {
	return map[string]func(*Record){
		"actor.type":         func(r *Record) { r.Actor.Type = ActorType(bad) },
		"actor.via":          func(r *Record) { r.Actor.Via = ActorVia(bad) },
		"policy.decision":    func(r *Record) { r.Policy.Decision = PolicyDecision(bad) },
		"result.status":      func(r *Record) { r.Result.Status = ResultStatus(bad) },
		"result.health":      func(r *Record) { r.Result.Health = HealthStatus(bad) },
		"result.error_class": func(r *Record) { r.Result.ErrorClass = ErrorClass(bad) },
		"result.fingerprint": func(r *Record) { r.Result.Fingerprint = bad },
		"action":             func(r *Record) { r.Action = Action(bad) },
		"request_id":         func(r *Record) { r.RequestID = bad },
	}
}

func TestAppend_ClosedFieldsRefuseArbitraryText(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()
	c := canary.New()
	bad := "vault said " + c.Value(1)

	cases := closedFieldCases(bad)
	if len(cases) != 9 {
		t.Fatalf("expected 9 closed fields under test, have %d", len(cases))
	}
	for field, set := range cases {
		t.Run(field, func(t *testing.T) {
			_, err := j.Append(ctx, newRecord("org-closed", set))
			if err == nil {
				t.Fatalf("Append accepted arbitrary text in %s", field)
			}
			if !errors.Is(err, errInvalidRecord) {
				t.Errorf("%s was refused by something other than Record.validate (the database CHECK is only the second barrier): %v", field, err)
			}
			if c.In(err.Error()) {
				t.Errorf("error for %s carries the offending text: %v", field, err)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error does not name the field %s: %v", field, err)
			}
		})
	}

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id = 'org-closed'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("%d refused records reached the journal", n)
	}
}

// outsideRegistryActions are Action values with the right shape (a dotted
// lower-case name) that no component has registered. "secret." + hex(canary)
// is the probe that got a 28-byte encoded value through the old shape-only
// check and into the service log.
func outsideRegistryActions(c canary.Canary) map[string]string {
	return map[string]string{
		"wildcard family":       "secret.rotate.*",
		"unregistered verb":     "secret.unregistered_verb",
		"unregistered family":   "vault.read",
		"hex of a canary":       "secret." + hex.EncodeToString([]byte(c.Value(1))[:28]),
		"registered plus tail":  string(ActionSecretDeploy) + ".x",
		"registered upper case": "SECRET.DEPLOY",
	}
}

// An Action in the right shape but outside the registry is refused before
// anything is stored or logged: Action is the one record field that reaches
// the service log, so its values must be names this package defines.
func TestAppend_ActionOutsideRegistryIsRefused(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	c := canary.New()

	var logBuf strings.Builder
	j := NewJournal(pool).WithLogger(obs.New(&logBuf))

	for name, action := range outsideRegistryActions(c) {
		t.Run(name, func(t *testing.T) {
			_, err := j.Append(ctx, newRecord("org-registry", func(r *Record) { r.Action = Action(action) }))
			if !errors.Is(err, errInvalidRecord) || !strings.Contains(err.Error(), "action") {
				t.Fatalf("Append accepted %q or refused it for another reason: %v", action, err)
			}
			if strings.Contains(err.Error(), action) || c.In(err.Error()) {
				t.Errorf("error carries the refused action text: %v", err)
			}
		})
	}
	if logBuf.Len() != 0 || c.In(logBuf.String()) {
		t.Errorf("a refused Append wrote to the service log: %s", logBuf.String())
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id = 'org-registry'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("%d refused records reached the journal", n)
	}
}

// The database repeats the registry as a CHECK, so a writer that skips
// validate still cannot park a well-shaped free-form action in the table.
func TestAuditRecordsRejectActionOutsideRegistry(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := NewJournal(pool).Append(ctx, newRecord("org-registry-db", nil)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	for name, action := range outsideRegistryActions(canary.New()) {
		t.Run(name, func(t *testing.T) {
			_, err := pool.Exec(ctx, `UPDATE audit_records SET action = $1 WHERE org_id = 'org-registry-db'`, action)
			if err == nil {
				t.Fatalf("the database accepted action %q", action)
			}
			if !strings.Contains(err.Error(), "audit_records_action_closed") {
				t.Errorf("%q refused for another reason than the action CHECK: %v", action, err)
			}
		})
	}
}

// The Go registry and the migration's CHECK list are the same set. Neither
// is derived from the other, so a constant added to one alone would make
// every Append of it fail (or, the other way, leave a database-only action
// no Go caller can name).
func TestActionRegistryMatchesMigrationCheck(t *testing.T) {
	pool := testPool(t)
	var def string
	if err := pool.QueryRow(context.Background(),
		`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'audit_records_action_closed'`).Scan(&def); err != nil {
		t.Fatalf("read the action CHECK: %v", err)
	}
	var inDB []string
	for _, m := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(def, -1) {
		inDB = append(inDB, m[1])
	}
	var inGo []string
	for _, a := range registeredActions {
		inGo = append(inGo, string(a))
	}
	sort.Strings(inDB)
	sort.Strings(inGo)
	if len(inGo) == 0 || strings.Join(inDB, ",") != strings.Join(inGo, ",") {
		t.Errorf("registry and CHECK differ:\n  Go:       %v\n  database: %v", inGo, inDB)
	}
}

// freeTextFields are the record's free-text string fields, each with a
// setter, by the name validate must report them under.
func freeTextFields() map[string]func(*Record, string) {
	return map[string]func(*Record, string){
		"org_id":               func(r *Record, v string) { r.OrgID = v },
		"scope":                func(r *Record, v string) { r.Scope = v },
		"actor.id":             func(r *Record, v string) { r.Actor.ID = v },
		"actor.sponsor_id":     func(r *Record, v string) { r.Actor.SponsorID = v },
		"intent.task_ref":      func(r *Record, v string) { r.Intent.TaskRef = v },
		"intent.session_ref":   func(r *Record, v string) { r.Intent.SessionRef = v },
		"intent.reason":        func(r *Record, v string) { r.Intent.Reason = v },
		"secret.id":            func(r *Record, v string) { r.Secret.ID = v },
		"secret.name":          func(r *Record, v string) { r.Secret.Name = v },
		"secret.version":       func(r *Record, v string) { r.Secret.Version = v },
		"target.runner_id":     func(r *Record, v string) { r.Target.RunnerID = v },
		"target.host":          func(r *Record, v string) { r.Target.Host = v },
		"target.kind":          func(r *Record, v string) { r.Target.Kind = v },
		"target.path":          func(r *Record, v string) { r.Target.Path = v },
		"policy.rule_id":       func(r *Record, v string) { r.Policy.RuleID = v },
		"approval.id":          func(r *Record, v string) { r.Approval.ID = v },
		"approval.approver_id": func(r *Record, v string) { r.Approval.ApproverID = v },
	}
}

// Free text that is not valid UTF-8 is refused by validate, naming the field
// only. The database would refuse it too, but its own message echoes the
// offending byte, and the refusal must not depend on what a driver or a
// server puts in an error.
func TestAppend_InvalidUTF8InFreeTextIsRefused(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()

	fields := freeTextFields()
	if len(fields) != 17 {
		t.Fatalf("expected 17 free-text fields under test, have %d", len(fields))
	}
	for field, set := range fields {
		t.Run(field, func(t *testing.T) {
			_, err := j.Append(ctx, newRecord("org-utf8", func(r *Record) { set(r, "abc\xff") }))
			if !errors.Is(err, errInvalidRecord) {
				t.Fatalf("invalid UTF-8 in %s: want errInvalidRecord, got %v", field, err)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error does not name the field %s: %v", field, err)
			}
			if strings.Contains(err.Error(), "abc") || strings.ContainsRune(err.Error(), 0xff) || strings.ContainsRune(err.Error(), '\ufffd') {
				t.Errorf("error for %s echoes the offending bytes: %q", field, err.Error())
			}
			// Positive control: the same field holding valid multi-byte text passes.
			if _, err := j.Append(ctx, newRecord("org-utf8-ok", func(r *Record) { set(r, "été 日本") })); err != nil {
				t.Errorf("valid multi-byte text in %s refused: %v", field, err)
			}
		})
	}

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id = 'org-utf8'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("%d refused records reached the journal", n)
	}
}

// Positive control: the same helper with in-set values is accepted, so the
// refusals above come from the field under test and not from the fixture.
func TestAppend_ClosedFieldsAcceptTheirSets(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	_, err := j.Append(context.Background(), newRecord("org-closed-ok", func(r *Record) {
		r.Actor.Type, r.Actor.Via = ActorRunner, ViaMeshPlugin
		r.Policy.Decision = DecisionApprovalRequired
		r.Result.Status, r.Result.Health, r.Result.ErrorClass = StatusFailed, HealthSkipped, ErrClassProviderError
	}))
	if err != nil {
		t.Fatalf("Append refused an in-set record: %v", err)
	}
	for _, a := range registeredActions {
		if _, err := j.Append(context.Background(), newRecord("org-closed-ok", func(r *Record) { r.Action = a })); err != nil {
			t.Errorf("Append refused the registered action %q: %v", a, err)
		}
	}
}

// The migration's CHECK constraints are the second barrier: a writer that
// skips validate (a superuser, another binary) still cannot park free text
// in an enumerated column.
func TestAuditRecordsRejectFreeTextInClosedColumns(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	j := NewJournal(pool)
	if _, err := j.Append(ctx, newRecord("org-check", nil)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	for _, col := range []string{
		"actor_type", "actor_via", "policy_decision", "result_status",
		"result_health", "result_error_class", "result_fingerprint", "action", "request_id", "id",
	} {
		t.Run(col, func(t *testing.T) {
			_, err := pool.Exec(ctx, `UPDATE audit_records SET `+col+` = 'free text from a backend' WHERE org_id = 'org-check'`)
			if err == nil {
				t.Fatalf("column %s accepted free text", col)
			}
			if !strings.Contains(err.Error(), "audit_records_") {
				t.Errorf("column %s refused for another reason than its CHECK constraint: %v", col, err)
			}
		})
	}
}

func TestAppend_NegativeLengthIsRefused(t *testing.T) {
	pool := testPool(t)
	_, err := NewJournal(pool).Append(context.Background(), newRecord("org-neg", func(r *Record) { r.Result.Length = -1 }))
	if !errors.Is(err, errInvalidRecord) {
		t.Fatalf("Append accepted a negative length or refused it for another reason: %v", err)
	}
}

// The 200-rune cap on intent.reason (multi-byte runes count as one, so the
// cap is exercised on characters, not bytes).
func TestAppend_BoundsAreEnforced(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()

	_, err := j.Append(ctx, newRecord("org-bounds", func(r *Record) { r.Intent.Reason = strings.Repeat("é", 201) }))
	if !errors.Is(err, errInvalidRecord) || !strings.Contains(err.Error(), "intent.reason") {
		t.Errorf("201-rune reason: want errInvalidRecord naming intent.reason, got %v", err)
	}
	if _, err := j.Append(ctx, newRecord("org-bounds", func(r *Record) { r.Intent.Reason = strings.Repeat("é", 200) })); err != nil {
		t.Errorf("200-rune reason (400 bytes) refused: %v", err)
	}
}

// The same bounds as CHECK constraints, for a writer that skips validate.
func TestAuditRecordsRejectOutOfBoundsValues(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := NewJournal(pool).Append(ctx, newRecord("org-bounds-db", nil)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	for name, set := range map[string]string{
		"negative result_length":    `result_length = -1`,
		"reason longer than 200":    `intent_reason = repeat('x', 201)`,
		"request_id longer than 36": `request_id = repeat('r', 37)`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := pool.Exec(ctx, `UPDATE audit_records SET `+set+` WHERE org_id = 'org-bounds-db'`)
			if err == nil {
				t.Fatalf("%s accepted", name)
			}
			if !strings.Contains(err.Error(), "audit_records_") {
				t.Errorf("%s refused for another reason than its CHECK constraint: %v", name, err)
			}
		})
	}
}

// A database error reaches the caller as its SQLSTATE only: the server's
// message and the failing row's Detail can hold whatever a caller put in a
// free-text field. The probe trigger makes the server put a canary from the
// record into its own error message.
func TestAppendErrorsCarryOnlySQLState(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		`CREATE FUNCTION audit_probe_fail() RETURNS trigger LANGUAGE plpgsql AS $fn$
		 BEGIN RAISE EXCEPTION 'probe failure for %', NEW.intent_reason USING DETAIL = NEW.secret_name; END $fn$`,
		`CREATE TRIGGER audit_probe BEFORE INSERT ON audit_records
		 FOR EACH ROW EXECUTE FUNCTION audit_probe_fail()`,
	} {
		superuserExec(t, pool, stmt)
	}

	c := canary.New()
	_, err := NewJournal(pool).Append(ctx, newRecord("org-dberr", func(r *Record) {
		r.Intent.Reason = c.Value(1)
		r.Secret.Name = c.Value(2)
	}))
	if err == nil {
		t.Fatal("Append succeeded although the probe trigger raises")
	}
	if c.In(err.Error()) {
		t.Errorf("error text carries a canary: %v", err)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Errorf("error still wraps the raw *pgconn.PgError (Detail: %d bytes)", len(pgErr.Detail))
	}
	if !strings.Contains(err.Error(), "SQLSTATE P0001") {
		t.Errorf("error does not carry the SQLSTATE: %v", err)
	}
}
