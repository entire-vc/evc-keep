package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// failingJournal is a journal that cannot be written.
type failingJournal struct{ calls int }

func (f *failingJournal) Append(context.Context, audit.Record) (audit.Record, error) {
	f.calls++
	return audit.Record{}, errors.New("journal down")
}

func keyLevelOf(t *testing.T, f *meshFixture) string {
	t.Helper()
	st, err := keyLevelService{pool: f.pool}.Get(context.Background(), f.org.ID)
	if err != nil {
		t.Fatal("read level")
	}
	return st.Level
}

// actionsOf waits briefly for the writer goroutine: outcomes are journaled
// after the change returns.
func actionsOf(t *testing.T, f *meshFixture) []string {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	rows, err := f.pool.Query(context.Background(), `SELECT action FROM audit_records WHERE org_id = $1 AND action LIKE 'org.key_level.%' ORDER BY org_seq`, f.org.ID)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal("scan")
		}
		out = append(out, a)
	}
	return out
}

func seedSecret(t *testing.T, f *meshFixture, value string) {
	t.Helper()
	p := f.local.Provider(f.org.ID.String(), "", "", uuid.NewString())
	if _, err := p.Write(context.Background(), provider.Ref{Path: "builtin://" + uuid.NewString()}, secret.New([]byte(value))); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// keyLevelProbe is a fixed canary base so a red run can plant the same literal
// in production code (journal reason, secret id, error text) and see this test fail.
const keyLevelProbe = "kcprobe0keylevel0leak"

func TestKeyLevelChangeJournalsRequestAndOutcomeWithoutValues(t *testing.T) {
	f := newMeshFixture(t, false)
	c := canary.Of(keyLevelProbe)
	seedSecret(t, f, c.Value(1))
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: audit.NewJournal(f.pool), log: f.logger}

	res, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true)
	if err != nil || res.Level != "project" || res.Rewrapped+res.Unchanged < 1 {
		t.Fatalf("change: %+v err=%v", res, err)
	}
	if got := strings.Join(actionsOf(t, f), ","); got != "org.key_level.requested,org.key_level.changed" {
		t.Fatalf("journal actions = %s", got)
	}
	if lvl := keyLevelOf(t, f); lvl != "project" {
		t.Fatalf("level = %s", lvl)
	}
	var dump strings.Builder
	rows, err := f.pool.Query(context.Background(), `SELECT to_jsonb(a)::text FROM audit_records a WHERE org_id = $1`, f.org.ID)
	if err != nil {
		t.Fatalf("dump journal: %v", err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal("scan journal")
		}
		dump.WriteString(s)
	}
	rows.Close()
	dump.WriteString(f.logbuf.String())
	// The refusal paths: denied (weakening), invalid, and the error text of
	// every ErrLevel* the sealer and the API expose.
	for _, err := range []error{builtin.ErrLevelInvalid, builtin.ErrLevelWeakening, api.ErrKeyLevelInvalid, api.ErrKeyLevelWeakening} {
		dump.WriteString(err.Error())
	}
	_, derr := svc.Change(context.Background(), f.org.ID, uuid.New(), "organization", false)
	if !errors.Is(derr, api.ErrKeyLevelWeakening) {
		t.Fatalf("weakening not refused: %v", derr)
	}
	_, ierr := svc.Change(context.Background(), f.org.ID, uuid.New(), "nonsense", true)
	if !errors.Is(ierr, api.ErrKeyLevelInvalid) {
		t.Fatalf("invalid not refused: %v", ierr)
	}
	dump.WriteString(derr.Error() + ierr.Error())
	time.Sleep(300 * time.Millisecond)
	rows, err = f.pool.Query(context.Background(), `SELECT to_jsonb(a)::text FROM audit_records a WHERE org_id = $1`, f.org.ID)
	if err != nil {
		t.Fatalf("dump journal: %v", err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal("scan journal")
		}
		dump.WriteString(s)
	}
	rows.Close()
	dump.WriteString(f.logbuf.String())
	// Positive controls: the dump holds the journaled actions, and the scan
	// finds the canary when it is placed on the same surface.
	if !strings.Contains(dump.String(), "org.key_level.requested") || !strings.Contains(dump.String(), "org.key_level.changed") {
		t.Fatal("dump misses the journaled actions")
	}
	if !c.In(dump.String() + c.Value(1)) {
		t.Fatal("canary scan is blind")
	}
	if c.In(dump.String()) {
		t.Fatal("canary reached the journal or the log")
	}
}

// Red input: with the journal unreachable the change must not start.
func TestKeyLevelChangeRefusedWhenJournalUnavailable(t *testing.T) {
	f := newMeshFixture(t, false)
	seedSecret(t, f, "x-value-for-seed")
	fj := &failingJournal{}
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: fj, log: f.logger}

	_, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true)
	if err == nil || fj.calls != 1 {
		t.Fatalf("err=%v journal calls=%d", err, fj.calls)
	}
	if errors.Is(err, api.ErrKeyLevelInvalid) || errors.Is(err, api.ErrKeyLevelWeakening) {
		t.Fatalf("wrong refusal: %v", err)
	}
	if !strings.Contains(err.Error(), "audit journal unavailable") {
		t.Fatalf("refusal = %q, want the audit-journal refusal, not a generic failure", err)
	}
	if lvl := keyLevelOf(t, f); lvl != "user" {
		t.Fatalf("level changed to %s without a journal", lvl)
	}
	if n := len(actionsOf(t, f)); n != 0 {
		t.Fatalf("%d key-level records written", n)
	}
}

func TestKeyLevelChangeWeakeningAndInvalid(t *testing.T) {
	f := newMeshFixture(t, false)
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: audit.NewJournal(f.pool), log: f.logger}
	ctx := context.Background()
	if _, err := svc.Change(ctx, f.org.ID, uuid.New(), "nonsense", true); !errors.Is(err, api.ErrKeyLevelInvalid) {
		t.Fatalf("invalid: %v", err)
	}
	if n := len(actionsOf(t, f)); n != 0 {
		t.Fatalf("an invalid level was journaled: %d", n)
	}
	if _, err := svc.Change(ctx, f.org.ID, uuid.New(), "organization", false); !errors.Is(err, api.ErrKeyLevelWeakening) {
		t.Fatalf("weakening: %v", err)
	}
	if got := strings.Join(actionsOf(t, f), ","); got != "org.key_level.requested,org.key_level.change_denied" {
		t.Fatalf("journal actions = %s", got)
	}
	if lvl := keyLevelOf(t, f); lvl != "user" {
		t.Fatalf("level = %s", lvl)
	}
}

// The org acted on is the one passed from the session; another org is untouched.
func TestKeyLevelChangeActsOnlyOnGivenOrg(t *testing.T) {
	f := newMeshFixture(t, false)
	other, err := tenancyCreate(f)
	if err != nil {
		t.Fatal("other org")
	}
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: audit.NewJournal(f.pool), log: f.logger}
	if _, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true); err != nil {
		t.Fatalf("change: %v", err)
	}
	st, _ := svc.Get(context.Background(), other)
	if st.Level != "user" {
		t.Fatalf("other org level = %s", st.Level)
	}
}

func TestEventRecordMapsEverySealerAction(t *testing.T) {
	for _, a := range []string{"key_level_changed", "key_level_change_denied", "key_level_change_failed", "kek_purged", "kek_purge_failed"} {
		r, ok := eventRecord(builtin.KeyEvent{Action: a, Org: uuid.NewString(), Actor: "a", From: "user", To: "project"})
		if !ok || !r.Action.Known() {
			t.Fatalf("%s: ok=%v action=%q", a, ok, r.Action)
		}
	}
	if _, ok := eventRecord(builtin.KeyEvent{Action: "unmapped"}); ok {
		t.Fatal("an unknown event must not be journaled")
	}
}

func TestNewLocalRefusesNilAuditor(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 1
	if _, err := builtin.NewLocal(nil, "k", raw, nil, nil); err == nil {
		t.Fatal("nil auditor accepted")
	}
}

func tenancyCreate(f *meshFixture) (uuid.UUID, error) {
	o, err := tenancy.New(f.pool).CreateOrganization(context.Background(), f.t.Name()+"-other", "")
	return o.ID, err
}

// The request id of a client is not unique (retries repeat it): every change
// journals its own server-issued id, so the outcome pairs with its request alone.
func TestKeyLevelChangeIssuesItsOwnRequestID(t *testing.T) {
	f := newMeshFixture(t, false)
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: audit.NewJournal(f.pool), log: f.logger}
	ctx := reqid.WithContext(context.Background(), "client-retry-id")
	for _, to := range []string{"project", "user"} {
		if _, err := svc.Change(ctx, f.org.ID, uuid.New(), to, true); err != nil {
			t.Fatalf("change to %s: %v", to, err)
		}
	}
	actionsOf(t, f) // outcomes reach the journal through the async auditor
	rows, err := f.pool.Query(context.Background(), `SELECT action, request_id FROM audit_records WHERE org_id = $1 AND action LIKE 'org.key_level.%' ORDER BY org_seq`, f.org.ID)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	defer rows.Close()
	requests := map[string]bool{}
	outcomes := map[string]bool{}
	for rows.Next() {
		var action, id string
		if err := rows.Scan(&action, &id); err != nil {
			t.Fatal("scan journal")
		}
		if id == "client-retry-id" {
			t.Fatalf("%s journaled the client's request id", action)
		}
		if action == "org.key_level.requested" {
			requests[id] = true
		} else {
			outcomes[id] = true
		}
	}
	if len(requests) != 2 || len(outcomes) != 2 {
		t.Fatalf("distinct request ids = %d, outcome ids = %d; want 2 and 2", len(requests), len(outcomes))
	}
	for id := range outcomes {
		if !requests[id] {
			t.Fatal("an outcome carries an id no request has")
		}
	}
}

// The client's X-Request-Id is caller-chosen text that passes the id alphabet:
// a secret of that shape must not settle in any journal column.
func TestKeyLevelChangeKeepsClientRequestIDOutOfJournal(t *testing.T) {
	f := newMeshFixture(t, false)
	c := canary.Of(keyLevelProbe)
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: audit.NewJournal(f.pool), log: f.logger}
	ctx := reqid.WithContext(context.Background(), c.Value(1))
	if !reqid.Valid(c.Value(1)) {
		t.Fatal("probe is not id-shaped: the test would prove nothing")
	}
	for _, to := range []string{"project", "user"} {
		if _, err := svc.Change(ctx, f.org.ID, uuid.New(), to, true); err != nil {
			t.Fatalf("change to %s: %v", to, err)
		}
	}
	actionsOf(t, f) // outcomes reach the journal through the async auditor
	rows, err := f.pool.Query(context.Background(), `SELECT to_jsonb(a)::text FROM audit_records a WHERE org_id = $1`, f.org.ID)
	if err != nil {
		t.Fatalf("dump journal: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal("scan journal")
		}
		n++
		if c.In(s) {
			t.Fatal("a journal row carries the client's request id")
		}
	}
	if n < 4 {
		t.Fatalf("journal rows = %d; want requests and outcomes of both changes", n)
	}
	if c.In(f.logbuf.String()) {
		t.Fatal("the log carries the client's request id")
	}
}
