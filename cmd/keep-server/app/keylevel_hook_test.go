package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// hookProbe is a fixed canary base so a red run can plant the same literal in
// the request/hook path and see the leak test fail.
const hookProbe = "kcprobe0lockhook0leak"

// hookControlActor marks the record the hook leak test plants in the journal
// so the journal dump is shown to read this organization's rows.
const hookControlActor = "hook-leak-control"

// stallJournal stops the process right after the request is journaled — the
// instant a live process can freeze (GC pause, SIGSTOP, a starved scheduler)
// between writing `requested` and the rest of the change. It embeds the real
// journal, so the request goes through AppendTx on the lock connection, and
// stops in LogCommitted, which the caller runs once the request is committed.
type stallJournal struct {
	*audit.Journal
	journaled chan struct{}
	release   chan struct{}
	// afterJournaled runs first, still under the level lock.
	afterJournaled func()
}

// Append is the path of a request journaled outside the lock connection.
func (s *stallJournal) Append(ctx context.Context, r audit.Record) (audit.Record, error) {
	out, err := s.Journal.Append(ctx, r)
	if err == nil {
		s.stall(ctx, out)
	}
	return out, err
}

func (s *stallJournal) LogCommitted(ctx context.Context, r audit.Record) {
	s.Journal.LogCommitted(ctx, r)
	s.stall(ctx, r)
}

func (s *stallJournal) stall(ctx context.Context, r audit.Record) {
	if r.Action != audit.ActionOrgKeyLevelRequested {
		return
	}
	close(s.journaled)
	if s.afterJournaled != nil {
		s.afterJournaled()
	}
	select {
	case <-s.release:
	case <-ctx.Done():
	}
}

// A live process that freezes after it journaled the request, for longer than
// the reconcile window, must not end up with two outcomes for one request: the
// reconcile pass would close it as change_failed, and the resumed change would
// then write `changed`. The request is journaled under the level lock, so the
// pass finds the change running and leaves it alone.
func TestKeyLevelStalledChangeGetsOneOutcome(t *testing.T) {
	f := newMeshFixture(t, false)
	seedSecret(t, f, "x-value-for-seed")
	sj := &stallJournal{Journal: audit.NewJournal(f.pool), journaled: make(chan struct{}), release: make(chan struct{})}
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: sj, log: f.logger}

	type result struct {
		level string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		res, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true)
		done <- result{res.Level, err}
	}()
	select {
	case <-sj.journaled:
	case <-time.After(10 * time.Second):
		t.Fatal("request was never journaled")
	}

	// The frozen process outlives the reconcile window. The window is negative
	// so the test does not depend on how much time passed since the request.
	n, err := reconcileKeyLevels(context.Background(), f.pool, audit.NewJournal(f.pool), f.logger, -time.Hour)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	close(sj.release)

	select {
	case r := <-done:
		if r.err != nil || r.level != "project" {
			t.Fatalf("resumed change = %q, %v", r.level, r.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("change did not finish after the stall")
	}
	got := strings.Join(actionsOf(t, f), ",")
	if got != "org.key_level.requested,org.key_level.changed" {
		t.Fatalf("journal = %s (reconcile wrote %d); want exactly one outcome, changed", got, n)
	}
	if n != 0 {
		t.Fatalf("reconcile closed a request whose change was still running: %d", n)
	}
}

// failWith is a journal whose write error names the canary, the way a driver
// error can echo a connection string or a value-bearing statement.
type failWith struct{ text string }

func (f failWith) Append(context.Context, audit.Record) (audit.Record, error) {
	return audit.Record{}, errors.New(f.text)
}

// failWithTx is the same on the lock-connection path: a transactional journal
// whose AppendTx error names the canary.
type failWithTx struct {
	*audit.Journal
	text string
	hit  *bool
}

func (f failWithTx) AppendTx(context.Context, pgx.Tx, audit.Record) (audit.Record, error) {
	*f.hit = true
	return audit.Record{}, errors.New(f.text)
}

// The request is now journaled by a hook the sealer calls under the level
// lock. A failing hook's error travels through the sealer back to the caller:
// neither the caller's error (any verb, whole chain), the log, nor the journal
// may carry what the journal's own error said — only names, levels, counts.
func TestKeyLevelHookFailureLeaksNoValue(t *testing.T) {
	for _, tx := range []bool{false, true} {
		t.Run(fmt.Sprintf("lock_connection=%t", tx), func(t *testing.T) { hookFailureLeaksNoValue(t, tx) })
	}
}

func hookFailureLeaksNoValue(t *testing.T, onLockConn bool) {
	f := newMeshFixture(t, false)
	c := canary.Of(hookProbe)
	seedSecret(t, f, c.Value(1))
	var j audit.Journaler = failWith{text: "driver: " + c.Value(2)}
	hit := false
	if onLockConn {
		j = failWithTx{Journal: audit.NewJournal(f.pool), text: "driver: " + c.Value(2), hit: &hit}
	}
	svc := keyLevelService{pool: f.pool, local: f.local, outcomes: f.outcomes, j: j, log: f.logger}
	// A record the journal dump must find: an empty dump would pass the scan.
	if _, err := audit.NewJournal(f.pool).Append(context.Background(), audit.Record{
		OrgID:  f.org.ID.String(),
		Action: audit.ActionSecretRotate,
		Actor:  audit.Actor{Type: audit.ActorUser, ID: hookControlActor, Via: audit.ViaAPI},
		Result: audit.Result{Status: audit.StatusOK},
	}); err != nil {
		t.Fatalf("control record: %v", err)
	}

	_, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true)
	if err == nil {
		t.Fatal("change started although its request could not be journaled")
	}
	if onLockConn && !hit {
		t.Fatal("the lock-connection path was not taken: the test proves nothing about it")
	}
	var errText strings.Builder
	for e := error(err); e != nil; e = errors.Unwrap(e) {
		fmt.Fprintf(&errText, "%v %+v %#v|", e, e, e)
	}
	time.Sleep(300 * time.Millisecond)
	logText := f.logbuf.String()
	rows, qerr := f.pool.Query(context.Background(), `SELECT to_jsonb(a)::text FROM audit_records a WHERE org_id = $1`, f.org.ID)
	if qerr != nil {
		t.Fatalf("dump journal: %v", qerr)
	}
	var journal strings.Builder
	for rows.Next() {
		var s string
		if rows.Scan(&s) != nil {
			t.Fatal("scan journal")
		}
		journal.WriteString(s)
	}
	rows.Close()

	// Each surface is scanned only after it is shown to hold what this failure
	// writes there: a capture that misses the surface would pass the scan.
	for _, s := range []struct{ name, text, marker string }{
		{"error", errText.String(), "audit journal unavailable"},
		{"log", logText, "key level change refused"},
		{"log", logText, f.org.ID.String()},
		{"journal", journal.String(), hookControlActor},
	} {
		if !strings.Contains(s.text, s.marker) {
			t.Fatalf("%s surface lacks %q: the scan below would see nothing", s.name, s.marker)
		}
	}
	surfaces := errText.String() + logText + journal.String()
	if !c.In(surfaces + c.Value(2)) {
		t.Fatal("canary scan is blind")
	}
	if c.In(surfaces) {
		t.Fatalf("canary reached the error, log or journal: %q", surfaces)
	}
	if lvl := keyLevelOf(t, f); lvl != "user" {
		t.Fatalf("level changed to %s without a journaled request", lvl)
	}
	if n := len(actionsOf(t, f)); n != 0 {
		t.Fatalf("%d key-level records written without a request", n)
	}
}

// The request is journaled on the connection the level lock is held on. A
// second pool connection taken under the lock starves when writers queued
// behind the lock hold the rest of the pool: the hook then waits for its
// deadline and the change is refused as "journal unavailable".
func TestKeyLevelRequestNeedsNoSecondPoolConnection(t *testing.T) {
	cfg := testPool(t).Config().Copy()
	cfg.MaxConns = 2
	small, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(small.Close)
	f := newMeshFixtureOn(t, small, false)
	seedSecret(t, f, "x-value-for-seed")

	sj := &stallJournal{Journal: audit.NewJournal(small), journaled: make(chan struct{}), release: make(chan struct{})}
	svc := keyLevelService{pool: small, local: f.local, outcomes: f.outcomes, j: sj, log: f.logger}

	// With the request committed and the lock still held, a writer queues
	// behind the lock and takes the pool's other connection.
	writerDone := make(chan error, 1)
	sj.afterJournaled = func() {
		go func() {
			p := f.local.Provider(f.org.ID.String(), "", "", uuid.NewString())
			_, err := p.Write(context.Background(), provider.Ref{Path: "builtin://" + uuid.NewString()}, secret.New([]byte("x-queued-writer")))
			writerDone <- err
		}()
		time.Sleep(500 * time.Millisecond)
		close(sj.release)
	}
	// The hook runs with a pool whose second connection is taken only after
	// the request was journaled: the journal write itself must have needed
	// none. Hold the other connection now to prove it.
	held, err := small.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	type result struct {
		level string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		res, err := svc.Change(context.Background(), f.org.ID, uuid.New(), "project", true)
		done <- result{res.Level, err}
	}()
	select {
	case <-sj.journaled:
	case r := <-done:
		held.Release()
		t.Fatalf("change ended before the request was journaled (after %s): %q, %v", time.Since(start), r.level, r.err)
	case <-time.After(10 * time.Second):
		held.Release()
		t.Fatal("request was not journaled within 10s: the hook waits for a second pool connection")
	}
	held.Release()
	r := <-done
	if r.err != nil || r.level != "project" {
		t.Fatalf("change = %q, %v", r.level, r.err)
	}
	if err := <-writerDone; err != nil {
		t.Fatalf("queued writer: %v", err)
	}
}
