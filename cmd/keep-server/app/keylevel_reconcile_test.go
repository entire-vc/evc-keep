package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// reconcileProbe is a fixed canary base, like keyLevelProbe, so a red run can
// plant the same literal in the reconcile code and see these tests fail.
const reconcileProbe = "kcprobe0reconcile0leak"

// journalRequest is what keyLevelService.Change writes before it starts: the
// process then dies, so no outcome follows.
// It returns the request's id.
func journalRequest(t *testing.T, f *meshFixture, actor uuid.UUID, to string) string {
	t.Helper()
	id := reqid.New()
	_, err := audit.NewJournal(f.pool).Append(context.Background(), audit.Record{
		RequestID: id,
		OrgID:     f.org.ID.String(),
		Scope:     keyLevelScope,
		Actor:     audit.Actor{Type: audit.ActorUser, ID: actor.String(), Via: audit.ViaAPI},
		Intent:    audit.Intent{Reason: audit.NewReason("to=" + to + " confirm_weakening=true")},
		Action:    audit.ActionOrgKeyLevelRequested,
		Result:    audit.Result{Status: audit.StatusPending},
	})
	if err != nil {
		t.Fatalf("journal request: %v", err)
	}
	return id
}

// persistLevel is the half of a change that reached the database before the crash.
func persistLevel(t *testing.T, f *meshFixture, level string, actor uuid.UUID) {
	t.Helper()
	_, err := f.pool.Exec(context.Background(), `INSERT INTO keep_org_key_level (org_id, level, updated_by) VALUES ($1, $2, $3)
		ON CONFLICT (org_id) DO UPDATE SET level = EXCLUDED.level, updated_by = EXCLUDED.updated_by, updated_at = now()`,
		f.org.ID.String(), level, actor.String())
	if err != nil {
		t.Fatalf("persist level: %v", err)
	}
}

func outcomeReasons(t *testing.T, f *meshFixture) []string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT action || ' ' || intent_reason FROM audit_records WHERE org_id = $1 AND action LIKE 'org.key_level.%' ORDER BY org_seq`, f.org.ID.String())
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal("scan")
		}
		out = append(out, s)
	}
	return out
}

func TestReconcileGivesInterruptedRequestItsOutcome(t *testing.T) {
	for _, tc := range []struct {
		name      string
		persisted bool
		reason    string
	}{
		{"level differs", false, "reason=interrupted_level_differs"},
		{"level applied, rewrap unverified", true, "reason=interrupted_unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMeshFixture(t, false)
			actor := uuid.New()
			journalRequest(t, f, actor, "project")
			if tc.persisted {
				persistLevel(t, f, "project", actor)
			}
			j := audit.NewJournal(f.pool)
			n, err := reconcileKeyLevels(context.Background(), f.pool, j, f.logger, 0)
			if err != nil || n != 1 {
				t.Fatalf("reconcile = %d, %v; want 1", n, err)
			}
			got := outcomeReasons(t, f)
			if len(got) != 2 || !strings.HasPrefix(got[0], "org.key_level.requested ") ||
				!strings.HasPrefix(got[1], "org.key_level.change_failed ") || !strings.Contains(got[1], tc.reason) ||
				!strings.Contains(got[1], "to=project ") || !strings.Contains(got[1], "request_seq=") {
				t.Fatalf("journal = %q", got)
			}
		})
	}
}

func TestReconcileIsIdempotent(t *testing.T) {
	f := newMeshFixture(t, false)
	journalRequest(t, f, uuid.New(), "workspace")
	j := audit.NewJournal(f.pool)
	if n, err := reconcileKeyLevels(context.Background(), f.pool, j, f.logger, 0); err != nil || n != 1 {
		t.Fatalf("first = %d, %v", n, err)
	}
	for i := 0; i < 2; i++ {
		if n, err := reconcileKeyLevels(context.Background(), f.pool, j, f.logger, 0); err != nil || n != 0 {
			t.Fatalf("restart %d = %d, %v; want 0", i+1, n, err)
		}
	}
	if got := outcomeReasons(t, f); len(got) != 2 {
		t.Fatalf("journal = %q", got)
	}
}

func TestReconcileLeavesFinishedChangeAlone(t *testing.T) {
	f := newMeshFixture(t, false)
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: audit.NewJournal(f.pool), log: f.logger}
	if _, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true); err != nil {
		t.Fatalf("change: %v", err)
	}
	want := strings.Join(actionsOf(t, f), ",")
	if n, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, 0); err != nil || n != 0 {
		t.Fatalf("reconcile = %d, %v; want 0", n, err)
	}
	if got := strings.Join(actionsOf(t, f), ","); got != want {
		t.Fatalf("journal changed: %s -> %s", want, got)
	}
}

// An earlier request that never got its outcome stays reconcilable after the
// operator retried a different change: the retry's own outcome does not close it.
func TestReconcileClosesEarlierRequestBehindALaterOne(t *testing.T) {
	f := newMeshFixture(t, false)
	journalRequest(t, f, uuid.New(), "workspace") // crash, no outcome
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: audit.NewJournal(f.pool), log: f.logger}
	if _, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true); err != nil {
		t.Fatalf("change: %v", err)
	}
	actionsOf(t, f)
	if n, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, 0); err != nil || n != 1 {
		t.Fatalf("reconcile = %d, %v; want 1", n, err)
	}
	if n, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, 0); err != nil || n != 0 {
		t.Fatalf("second = %d, %v; want 0", n, err)
	}
}

func TestReconcileJournalsAndLogsNoValue(t *testing.T) {
	f := newMeshFixture(t, false)
	c := canary.Of(reconcileProbe)
	seedSecret(t, f, c.Value(1))
	actor := uuid.New()
	journalRequest(t, f, actor, "project")
	persistLevel(t, f, "project", actor)
	if _, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, 0); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var dump strings.Builder
	rows, err := f.pool.Query(context.Background(), `SELECT to_jsonb(a)::text FROM audit_records a WHERE org_id = $1`, f.org.ID.String())
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
	if !strings.Contains(dump.String(), "org.key_level.change_failed") {
		t.Fatal("dump misses the reconciled outcome: the scan proves nothing")
	}
	if !c.In(dump.String() + c.Value(1)) {
		t.Fatal("canary scan is blind")
	}
	if c.In(dump.String()) {
		t.Fatal("canary reached the journal or the log")
	}
}

// A level row that is not the requested one never reads as unverified: the
// default level (no row) and another level both say "differs".
func TestReconcileLevelDiffersWhenPersistedLevelIsNotTheRequestedOne(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, f *meshFixture, actor uuid.UUID)
	}{
		{"another level", func(t *testing.T, f *meshFixture, a uuid.UUID) { persistLevel(t, f, "workspace", a) }},
		{"default level, no row", func(t *testing.T, f *meshFixture, a uuid.UUID) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMeshFixture(t, false)
			actor := uuid.New()
			journalRequest(t, f, actor, "project")
			tc.write(t, f, actor)
			if n, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, 0); err != nil || n != 1 {
				t.Fatalf("reconcile = %d, %v", n, err)
			}
			got := outcomeReasons(t, f)
			if len(got) != 2 || !strings.Contains(got[1], "reason=interrupted_level_differs") {
				t.Fatalf("journal = %q", got)
			}
		})
	}
}

// A request younger than the grace may belong to a change that is still running.
func TestReconcileLeavesAFreshRequestAlone(t *testing.T) {
	f := newMeshFixture(t, false)
	journalRequest(t, f, uuid.New(), "project")
	if n, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, time.Hour); err != nil || n != 0 {
		t.Fatalf("fresh = %d, %v; want 0", n, err)
	}
	if got := outcomeReasons(t, f); len(got) != 1 {
		t.Fatalf("journal = %q", got)
	}
}

// A change running in another process holds the org's level lock (the key
// ChangeLevel uses): reconcile leaves that org alone, then picks it up.
func TestReconcileSkipsOrgWhileAChangeHoldsTheLevelLock(t *testing.T) {
	f := newMeshFixture(t, false)
	journalRequest(t, f, uuid.New(), "project")
	ctx := context.Background()
	conn, err := f.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	t.Cleanup(conn.Release) // a failed assertion must not leave the pool waiting for this connection
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, "keep_org_key_level:"+f.org.ID.String()); err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	j := audit.NewJournal(f.pool)
	if n, err := reconcileKeyLevels(ctx, f.pool, j, f.logger, 0); err != nil || n != 0 {
		t.Fatalf("while locked = %d, %v; want 0", n, err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, "keep_org_key_level:"+f.org.ID.String()); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	conn.Release()
	if n, err := reconcileKeyLevels(ctx, f.pool, j, f.logger, 0); err != nil || n != 1 {
		t.Fatalf("after release = %d, %v; want 1", n, err)
	}
}

// runServe reconciles before it binds a listener, so no traffic sees a bare request.
func TestServeReconcilesBeforeItListens(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal("read main.go")
	}
	src := string(raw)
	call := strings.Index(src, "reconcileKeyLevels(ctx, pool, journal, logger, keyLevelReconcileGrace)")
	serve := strings.Index(src, "serveBoth(")
	if call < 0 || serve < 0 || call > serve {
		t.Fatalf("reconcile call at %d, serveBoth at %d: reconcile must come first", call, serve)
	}
}

// The settings may name the top level "org"; the sealer's outcome says "organization".
func TestReconcileSeesAliasAndCanonicalLevelAsOne(t *testing.T) {
	f := newMeshFixture(t, false)
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: audit.NewJournal(f.pool), log: f.logger}
	if _, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "org", true); err != nil {
		t.Fatalf("change: %v", err)
	}
	actionsOf(t, f)
	if n, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, 0); err != nil || n != 0 {
		t.Fatalf("reconcile = %d, %v; want 0", n, err)
	}
}

// The request names "org", the persisted level is "organization": one level, so
// the interrupted change is unverified, not a different level.
func TestReconcileReadsRequestedAliasAsTheCanonicalLevel(t *testing.T) {
	f := newMeshFixture(t, false)
	actor := uuid.New()
	journalRequest(t, f, actor, "org")
	persistLevel(t, f, "organization", actor)
	if n, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, 0); err != nil || n != 1 {
		t.Fatalf("reconcile = %d, %v", n, err)
	}
	got := outcomeReasons(t, f)
	if len(got) != 2 || !strings.Contains(got[1], "reason=interrupted_unverified") {
		t.Fatalf("journal = %q", got)
	}
}

// recID is a row that carries the id of the request it belongs to.
func recID(org, action, actor, reason, id string, seq int64) keyLevelRecord {
	r := rec(org, action, actor, reason, seq)
	r.reqID = id
	return r
}

// Two requests of one (org, actor, level) in a row, outcomes by request id:
// the outcome closes its own request, whatever the order.
func TestDanglingRequestsPairByRequestID(t *testing.T) {
	for _, tc := range []struct {
		name string
		recs []keyLevelRecord
		want []int64
	}{
		{"outcomes in reverse order close their own", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project x", "r1", 1), recID("o", reqA, "u1", "to=project x", "r2", 2),
			recID("o", chgA, "u1", "from=user to=project", "r2", 3), recID("o", chgA, "u1", "from=user to=project", "r1", 4)}, []int64{}},
		{"only the later request finished: the earlier one is dangling", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project x", "r1", 1), recID("o", reqA, "u1", "to=project x", "r2", 2),
			recID("o", chgA, "u1", "from=user to=project", "r2", 3)}, []int64{1}},
		{"an outcome without an id closes nothing", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project x", "r1", 1),
			rec("o", chgA, "u1", "from=user to=project", 2)}, []int64{1}},
		{"an outcome of another request id closes nothing", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project x", "r1", 1),
			recID("o", chgA, "u1", "from=user to=project", "r9", 2)}, []int64{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := seqsOf(danglingRequests(tc.recs)); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("dangling = %v; want %v", got, tc.want)
			}
		})
	}
}

// A client may repeat its X-Request-Id, so two requests can carry one id. The
// outcome that follows answers the later request; the earlier one, which got
// none, stays dangling.
func TestDanglingRequestsSurviveARepeatedClientRequestID(t *testing.T) {
	for _, tc := range []struct {
		name string
		recs []keyLevelRecord
		want []int64
	}{
		{"crashed request then a retry with the same id", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project x", "x", 1), recID("o", reqA, "u1", "to=project x", "x", 2),
			recID("o", chgA, "u1", "from=user to=project", "x", 3)}, []int64{1}},
		{"both finished", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project x", "x", 1), recID("o", chgA, "u1", "from=user to=project", "x", 2),
			recID("o", reqA, "u1", "to=project x", "x", 3), recID("o", chgA, "u1", "from=user to=project", "x", 4)}, []int64{}},
		{"same id in another org is not shared", []keyLevelRecord{
			recID("o1", reqA, "u1", "to=project x", "x", 1), recID("o2", reqA, "u1", "to=project x", "x", 1),
			recID("o2", chgA, "u1", "from=user to=project", "x", 2)}, []int64{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := seqsOf(danglingRequests(tc.recs)); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("dangling = %v; want %v", got, tc.want)
			}
		})
	}
}

func rec(org, action, actor, reason string, seq int64) keyLevelRecord {
	return keyLevelRecord{org: org, action: action, actor: actor, reason: reason, seq: seq}
}

const (
	reqA  = "org.key_level.requested"
	chgA  = "org.key_level.changed"
	denA  = "org.key_level.change_denied"
	failA = "org.key_level.change_failed"
)

func seqsOf(rs []keyLevelRecord) []int64 {
	out := []int64{}
	for _, r := range rs {
		out = append(out, r.seq)
	}
	return out
}

// danglingRequests needs no database: the pairing rules are checked here.
func TestDanglingRequestsPairing(t *testing.T) {
	for _, tc := range []struct {
		name string
		recs []keyLevelRecord
		want []int64
	}{
		{"request alone", []keyLevelRecord{recID("o", reqA, "u1", "to=project confirm_weakening=true", "r1", 1)}, []int64{1}},
		{"request and outcome", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project confirm_weakening=true", "r1", 1), recID("o", chgA, "u1", "from=user to=project rewrapped=1", "r1", 2)}, []int64{}},
		{"two concurrent requests, both finished", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project x", "r1", 1), recID("o", reqA, "u2", "to=workspace x", "r2", 2),
			recID("o", chgA, "u1", "from=user to=project", "r1", 3), recID("o", chgA, "u2", "from=project to=workspace", "r2", 4)}, []int64{}},
		{"two concurrent requests, one outcome missing", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project x", "r1", 1), recID("o", reqA, "u2", "to=workspace x", "r2", 2),
			recID("o", chgA, "u1", "from=user to=project", "r1", 3)}, []int64{2}},
		{"denied closes", []keyLevelRecord{
			recID("o", reqA, "u1", "to=user x", "r1", 1), recID("o", denA, "u1", "from=project to=user reason=weakening_not_confirmed", "r1", 2)}, []int64{}},
		{"reconcile outcome closes", []keyLevelRecord{
			recID("o", reqA, "u1", "to=project x", "r1", 1), recID("o", failA, "u1", "to=project reason=interrupted_unverified request_seq=1", "r1", 2)}, []int64{}},
		{"outcome before any request closes nothing", []keyLevelRecord{
			recID("o", chgA, "u1", "from=user to=project", "r1", 1), recID("o", reqA, "u1", "to=project x", "r1", 2)}, []int64{2}},
		{"other org does not close", []keyLevelRecord{
			recID("o1", reqA, "u1", "to=project x", "r1", 1), recID("o2", chgA, "u1", "from=user to=project", "r1", 1)}, []int64{1}},
		{"alias org and canonical organization still pair by id", []keyLevelRecord{
			recID("o", reqA, "u1", "to=org confirm_weakening=true", "r1", 1), recID("o", chgA, "u1", "from=project to=organization", "r1", 2)}, []int64{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := seqsOf(danglingRequests(tc.recs)); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("dangling = %v; want %v", got, tc.want)
			}
		})
	}
}

// holdAfterRequestJournal holds the caller after the request was journaled: the
// request goes through Append, so the hold is spent under the level lock.
type holdAfterRequestJournal struct {
	audit.Journaler
	entered chan struct{}
	proceed chan struct{}
}

func (s holdAfterRequestJournal) Append(ctx context.Context, r audit.Record) (audit.Record, error) {
	out, err := s.Journaler.Append(ctx, r)
	if err == nil && r.Action == audit.ActionOrgKeyLevelRequested {
		s.entered <- struct{}{}
		<-s.proceed
	}
	return out, err
}

// A handler that stalls after journaling its request, past the grace, still holds
// the level lock: the reconcile must not write interrupted over its real outcome.
func TestReconcileLeavesAWaitingHandlerAlone(t *testing.T) {
	f := newMeshFixture(t, false)
	base := audit.NewJournal(f.pool)
	sj := holdAfterRequestJournal{Journaler: base, entered: make(chan struct{}), proceed: make(chan struct{})}
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: sj, log: f.logger}
	done := make(chan error, 1)
	go func() {
		_, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true)
		done <- err
	}()
	<-sj.entered
	time.Sleep(50 * time.Millisecond)                                             // the request is older than a zero grace
	n, err := reconcileKeyLevels(context.Background(), f.pool, base, f.logger, 0) // grace long gone
	close(sj.proceed)
	if cerr := <-done; cerr != nil {
		t.Fatalf("change: %v", cerr)
	}
	if err != nil || n != 0 {
		t.Fatalf("reconcile with a live handler = %d, %v; want 0", n, err)
	}
	actionsOf(t, f)
	for _, row := range outcomeReasons(t, f) {
		if strings.HasPrefix(row, "org.key_level.change_failed") {
			t.Fatalf("a live change got a failed outcome: %s", row)
		}
	}
}

// The age of a request is measured on the clock that stamped it, so a database
// host whose clock differs from the app's does not move the grace.
func TestReconcileAgeFollowsTheAppClockNotTheDatabase(t *testing.T) {
	f := newMeshFixture(t, false)
	app := time.Now().Add(-3 * time.Hour) // the app host runs three hours behind the database
	old := keyLevelClock
	keyLevelClock = func() time.Time { return app }
	t.Cleanup(func() { keyLevelClock = old })
	j := audit.NewJournal(f.pool).WithClock(keyLevelClock)
	if _, err := j.Append(context.Background(), audit.Record{
		RequestID: reqid.New(), OrgID: f.org.ID.String(), Scope: keyLevelScope,
		Actor:  audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI},
		Intent: audit.Intent{Reason: audit.NewReason("to=project confirm_weakening=true")},
		Action: audit.ActionOrgKeyLevelRequested, Result: audit.Result{Status: audit.StatusPending},
	}); err != nil {
		t.Fatalf("journal request: %v", err)
	}
	if n, err := reconcileKeyLevels(context.Background(), f.pool, j, f.logger, keyLevelReconcileGrace); err != nil || n != 0 {
		t.Fatalf("fresh request on a skewed host = %d, %v; want 0", n, err)
	}
	app = app.Add(keyLevelReconcileGrace + time.Second)
	if n, err := reconcileKeyLevels(context.Background(), f.pool, j, f.logger, keyLevelReconcileGrace); err != nil || n != 1 {
		t.Fatalf("request past the grace on the app clock = %d, %v; want 1", n, err)
	}
}

// The reconciled outcome is the server's own, not the requester's.
func TestReconcileOutcomeIsASystemActor(t *testing.T) {
	f := newMeshFixture(t, false)
	journalRequest(t, f, uuid.New(), "project")
	if n, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, 0); err != nil || n != 1 {
		t.Fatalf("reconcile = %d, %v; want 1", n, err)
	}
	var typ, id string
	if err := f.pool.QueryRow(context.Background(), `SELECT actor_type, actor_id FROM audit_records WHERE org_id = $1 AND action = 'org.key_level.change_failed'`, f.org.ID.String()).Scan(&typ, &id); err != nil {
		t.Fatalf("read actor: %v", err)
	}
	if typ != "system" || id != keyLevelReconcileActor {
		t.Fatalf("actor = %q/%q; want system/%s", typ, id, keyLevelReconcileActor)
	}
}

// A handler that waits for a pool connection longer than the grace has not
// journaled its request yet: the reconcile finds nothing to close, and the
// change, once it gets a connection, writes the only outcome. Journaling the
// request before the level lock is taken would leave it open over that wait,
// and the reconcile would write interrupted for a change that then succeeds.
func TestReconcileLeavesAHandlerWaitingForAConnectionAlone(t *testing.T) {
	ctx := context.Background()
	big := testPool(t)
	cfg := big.Config().Copy()
	cfg.MaxConns = 2
	small, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(small.Close)
	// The sealer takes its level lock from the pool its fixture is built on:
	// with every connection of that pool held, the change waits before the lock.
	f := newMeshFixtureOn(t, small, false)
	var held []*pgxpool.Conn
	for range cfg.MaxConns {
		c, err := small.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	releaseHeld := func() {
		for _, c := range held {
			c.Release()
		}
		held = nil
	}
	t.Cleanup(releaseHeld)
	svc := keyLevelService{pool: small, local: f.local, outcomes: f.outcomes, j: audit.NewJournal(big), log: f.logger}
	done := make(chan error, 1)
	go func() {
		_, err := svc.Change(ctx, f.org.ID, uuid.New(), "project", true)
		done <- err
	}()
	grace := 100 * time.Millisecond
	time.Sleep(4 * grace) // the handler waits for the held connection, well past the grace
	n, rerr := reconcileKeyLevels(ctx, big, audit.NewJournal(big), f.logger, grace)
	select {
	case err := <-done:
		t.Fatalf("change returned while the pool was exhausted: %v", err)
	default:
	}
	releaseHeld()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("change: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("change did not finish after the connection was released")
	}
	if rerr != nil || n != 0 {
		t.Fatalf("reconcile with a handler waiting for a connection = %d, %v; want 0", n, rerr)
	}
	if got := strings.Join(actionsOf(t, f), ","); got != "org.key_level.requested,org.key_level.changed" {
		t.Fatalf("journal = %s; want exactly one outcome, changed", got)
	}
}

// Reconcile reads the journal and the level and writes the outcome on the
// connection the level lock is held on. A second pool connection taken under
// the lock starves when writers queued behind the lock hold the rest of the
// pool, and the reconcile context has no deadline: the loop would hang.
func TestReconcileNeedsNoSecondPoolConnection(t *testing.T) {
	cfg := testPool(t).Config().Copy()
	cfg.MaxConns = 2
	small, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Close waits for every acquired connection: one leaked under the lock
	// must fail this test, not hang the package.
	t.Cleanup(func() {
		closed := make(chan struct{})
		go func() { small.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Error("pool did not close: a connection taken under the lock was never released")
		}
	})
	f := newMeshFixtureOn(t, small, false)
	journalRequest(t, f, uuid.New(), "project")

	// The other connection stands for a writer queued behind the level lock:
	// reconcile gets exactly one, the one it locks on.
	held, err := small.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(held.Release)
	type result struct {
		n   int
		err error
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan result, 1)
	go func() {
		n, err := reconcileKeyLevels(ctx, small, audit.NewJournal(small).WithLogger(f.logger), f.logger, 0)
		done <- result{n, err}
	}()
	select {
	case r := <-done:
		if r.err != nil || r.n != 1 {
			t.Fatalf("reconcile = %d, %v; want 1", r.n, r.err)
		}
	case <-time.After(10 * time.Second):
		// End the waiting reconcile before the pool closes under it.
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		t.Fatal("reconcile did not finish within 10s: it waits for a second pool connection under the level lock")
	}
	assertLevelLockFree(t, held, f.org.ID.String())
	if got := outcomeReasons(t, f); len(got) != 2 || !strings.HasPrefix(got[1], "org.key_level.change_failed ") {
		t.Fatalf("journal = %q", got)
	}
	// The outcome is logged once its transaction has committed.
	if !strings.Contains(f.logbuf.String(), "org.key_level.change_failed") {
		t.Fatal("committed outcome was not logged")
	}
}

// assertLevelLockFree takes and drops org's level lock on conn: reconcile
// must have released it.
func assertLevelLockFree(t *testing.T, conn *pgxpool.Conn, org string) {
	t.Helper()
	ctx := context.Background()
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, "keep_org_key_level:"+org).Scan(&ok); err != nil {
		t.Fatalf("try lock: %v", err)
	}
	if !ok {
		t.Fatal("reconcile left the level lock held")
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, "keep_org_key_level:"+org); err != nil {
		t.Fatalf("unlock: %v", err)
	}
}

// budgetJournal appends normally until its budget runs out, then fails.
type budgetJournal struct {
	*audit.Journal
	left int
}

func (j *budgetJournal) AppendTx(ctx context.Context, tx pgx.Tx, r audit.Record) (audit.Record, error) {
	if j.left == 0 {
		return audit.Record{}, fmt.Errorf("journal unavailable")
	}
	j.left--
	return j.Journal.AppendTx(ctx, tx, r)
}

// The outcomes of one org are written in one transaction: two dangling
// requests get both outcomes in an intact chain, and a failure on the second
// leaves neither, with the level lock released.
func TestReconcileWritesAnOrgsOutcomesTogether(t *testing.T) {
	ctx := context.Background()
	t.Run("both", func(t *testing.T) {
		f := newMeshFixture(t, false)
		journalRequest(t, f, uuid.New(), "project")
		journalRequest(t, f, uuid.New(), "workspace")
		if n, err := reconcileKeyLevels(ctx, f.pool, audit.NewJournal(f.pool), f.logger, 0); err != nil || n != 2 {
			t.Fatalf("reconcile = %d, %v; want 2", n, err)
		}
		if got := outcomeReasons(t, f); len(got) != 4 {
			t.Fatalf("journal = %q", got)
		}
		res, err := audit.Verify(ctx, f.pool, f.org.ID.String())
		if err != nil || !res.OK {
			t.Fatalf("chain = %+v, %v", res, err)
		}
	})
	t.Run("second fails", func(t *testing.T) {
		f := newMeshFixture(t, false)
		journalRequest(t, f, uuid.New(), "project")
		journalRequest(t, f, uuid.New(), "workspace")
		j := &budgetJournal{Journal: audit.NewJournal(f.pool), left: 1}
		if n, err := reconcileKeyLevels(ctx, f.pool, j, f.logger, 0); err == nil || n != 0 {
			t.Fatalf("reconcile = %d, %v; want 0 and an error", n, err)
		}
		if got := outcomeReasons(t, f); len(got) != 2 {
			t.Fatalf("a failed reconcile left outcomes behind: %q", got)
		}
		conn, err := f.pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		assertLevelLockFree(t, conn, f.org.ID.String())
	})
}
