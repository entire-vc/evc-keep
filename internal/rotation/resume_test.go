package rotation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

var testResume = ResumeConfig{Stale: time.Nanosecond, MaxAttempts: 3, BackoffBase: time.Millisecond, BackoffMax: time.Millisecond}

// killAfterPrepare makes every Rotate of s die after its first persisted step
// while on is set: the first step of a new run is the prepared version, before
// any carrier got the layout, so this is the hook failing after commit.
func killAfterPrepare(s *Service, on *atomic.Bool) {
	s.e.afterState = func(State) error {
		if on.Load() {
			return errors.New("killed")
		}
		return nil
	}
}

func auditText(t *testing.T, x fx) string {
	t.Helper()
	var out string
	if err := x.pool.QueryRow(x.ctx, `SELECT COALESCE(string_agg(row_to_json(a)::text, E'\n'), '') FROM audit_records a`).Scan(&out); err != nil {
		t.Fatal("read journal")
	}
	return out
}

// The hook dies after the run and its version committed: the version has no
// layout and the run stays active. Resume lays it out, once, and journals the
// outcome.
func TestResumeLaysOutARunTheHookLeftActive(t *testing.T) {
	x, f := newFx(t), newFakes(3)
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(testResume)
	var kill atomic.Bool
	kill.Store(true)
	killAfterPrepare(s, &kill)
	id, err := startPlain(s, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wait()
	rep, err := s.Report(x.ctx, x.ref, id)
	if err != nil || rep.Done || rep.Failed || len(f.deployed) != 0 {
		t.Fatalf("setup: the run must be active with nothing laid out: %+v %v deployed=%d", rep, err, len(f.deployed))
	}
	kill.Store(false)
	n, err := s.Resume(x.ctx)
	if err != nil || n != 1 {
		t.Fatalf("Resume: n=%d err=%v", n, err)
	}
	s.Wait()
	rep, err = s.Report(x.ctx, x.ref, id)
	if err != nil || !rep.Done || rep.Version != "2" || len(f.deployed) != 3 || f.revokes != 1 {
		t.Fatalf("resumed run: %+v %v deployed=%d revokes=%d", rep, err, len(f.deployed), f.revokes)
	}
	var ok int
	if err := x.pool.QueryRow(x.ctx, `SELECT count(*) FROM audit_records WHERE request_id=$1 AND result_status='ok'`, id.String()).Scan(&ok); err != nil || ok != 1 {
		t.Fatalf("outcome records of the resumed run: %d %v", ok, err)
	}
	if n, _ := s.Resume(x.ctx); n != 0 {
		t.Fatalf("a finished run was resumed again (%d)", n)
	}
}

// A run a goroutine of this process is driving is not taken a second time.
func TestResumeLeavesALiveRunAlone(t *testing.T) {
	x, f := newFx(t), newFakes(1)
	f.gate = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(testResume)
	if _, err := startPlain(s, x.ctx, x.ref); err != nil {
		t.Fatal(err)
	}
	<-f.entered
	if n, err := s.Resume(x.ctx); err != nil || n != 0 {
		t.Fatalf("a live run was resumed: n=%d err=%v", n, err)
	}
	close(f.gate)
	s.Wait()
}

// A run younger than the threshold is left to its starter: the window between
// the commit and the claim is not an abandoned run.
func TestResumeLeavesAYoungRunAlone(t *testing.T) {
	x, f := newFx(t), newFakes(1)
	cfg := testResume
	cfg.Stale = time.Hour
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(cfg)
	var kill atomic.Bool
	kill.Store(true)
	killAfterPrepare(s, &kill)
	if _, err := startPlain(s, x.ctx, x.ref); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	kill.Store(false)
	if n, err := s.Resume(x.ctx); err != nil || n != 0 {
		t.Fatalf("a young run was resumed: n=%d err=%v", n, err)
	}
}

// Two servers sweeping at once take a run once between them.
func TestResumeTwoServersTakeARunOnce(t *testing.T) {
	x, f := newFx(t), newFakes(3)
	// The backoff outlasts the test: only the claim itself keeps the sweepers apart.
	cfg := testResume
	cfg.BackoffBase, cfg.BackoffMax = time.Hour, time.Hour
	a := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(cfg)
	b := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(cfg)
	var kill atomic.Bool
	kill.Store(true)
	killAfterPrepare(a, &kill)
	id, err := startPlain(a, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	a.Wait()
	kill.Store(false)
	var taken atomic.Int64
	var wg sync.WaitGroup
	sweepers := []*Service{a, b}
	for i := 0; i < 14; i++ {
		sweepers = append(sweepers, NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(cfg))
	}
	start := make(chan struct{})
	for _, s := range sweepers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			n, err := s.Resume(x.ctx)
			if err != nil {
				t.Error("Resume failed")
			}
			taken.Add(int64(n))
		}()
	}
	close(start)
	wg.Wait()
	for _, s := range sweepers {
		s.Wait()
	}
	if taken.Load() != 1 {
		t.Fatalf("the run was taken %d times", taken.Load())
	}
	rep, err := a.Report(x.ctx, x.ref, id)
	if err != nil || !rep.Done || len(f.deployed) != 3 || f.revokes != 1 {
		t.Fatalf("got %+v %v deployed=%d revokes=%d", rep, err, len(f.deployed), f.revokes)
	}
}

// A run another server is claiming right now (its row locked by an open
// claim) is skipped, not waited for: a sweep never blocks behind a peer.
func TestResumeSkipsARunAnotherServerIsClaiming(t *testing.T) {
	x, f := newFx(t), newFakes(1)
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(testResume)
	var kill atomic.Bool
	kill.Store(true)
	killAfterPrepare(s, &kill)
	if _, err := startPlain(s, x.ctx, x.ref); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	kill.Store(false)
	tx, err := x.pool.Begin(x.ctx)
	if err != nil {
		t.Fatal("begin")
	}
	defer func() { _ = tx.Rollback(x.ctx) }()
	if _, err := tx.Exec(x.ctx, `SELECT id FROM rotation_runs FOR UPDATE`); err != nil {
		t.Fatal("lock the run")
	}
	ctx, cancel := context.WithTimeout(x.ctx, 3*time.Second)
	defer cancel()
	if n, err := s.Resume(ctx); err != nil || n != 0 {
		t.Fatalf("a run another server holds was not skipped: n=%d err=%v", n, err)
	}
}

// A run that keeps dying is failed with a fixed class after MaxAttempts, so it
// does not block the next rotation of the secret; attempts are spaced by the backoff.
func TestResumeGivesUpAndFreesTheSecret(t *testing.T) {
	x, f := newFx(t), newFakes(1)
	// Each resume gets one step further before it dies, so the budget is one
	// attempt: a run that is still dying after it is given up on.
	cfg := testResume
	cfg.MaxAttempts = 1
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(cfg)
	var kill atomic.Bool
	kill.Store(true)
	killAfterPrepare(s, &kill)
	id, err := startPlain(s, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wait()
	for i := 0; i < 3; i++ {
		time.Sleep(5 * time.Millisecond)
		if _, err := s.Resume(x.ctx); err != nil {
			t.Fatal(err)
		}
		s.Wait()
	}
	rep, err := s.Report(x.ctx, x.ref, id)
	if err != nil || !rep.Failed || rep.Class != ClassInternalError {
		t.Fatalf("a run that keeps dying must end failed/internal_error: %+v %v", rep, err)
	}
	kill.Store(false)
	if _, err := startPlain(s, x.ctx, x.ref); err != nil {
		t.Fatalf("the failed run still blocks the secret: %v", err)
	}
	s.Wait()
}

func TestResumeBackoffSpacesAttempts(t *testing.T) {
	x, f := newFx(t), newFakes(1)
	cfg := testResume
	cfg.BackoffBase, cfg.BackoffMax = time.Hour, time.Hour
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(cfg)
	var kill atomic.Bool
	kill.Store(true)
	killAfterPrepare(s, &kill)
	if _, err := startPlain(s, x.ctx, x.ref); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	if n, _ := s.Resume(x.ctx); n != 1 {
		t.Fatalf("first resume: %d", n)
	}
	s.Wait()
	if n, _ := s.Resume(x.ctx); n != 0 {
		t.Fatalf("a second resume inside the backoff: %d", n)
	}
}

// The canary rides in every collaborator error of a resumed run; neither the
// report nor the journal holds it. The detector is shown to see it first.
func TestResumeNeverLeaksTheValue(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(fmt.Sprintf("%q", v)) {
		t.Fatal("canary detector is blind")
	}
	x, f := newFx(t), newFakes(2)
	f.verifyErr[cid(2)] = errors.New("read " + v)
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(testResume)
	var kill atomic.Bool
	kill.Store(true)
	killAfterPrepare(s, &kill)
	id, err := startPlain(s, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wait()
	kill.Store(false)
	if n, _ := s.Resume(x.ctx); n != 1 {
		t.Fatal("run not resumed")
	}
	s.Wait()
	rep, err := s.Report(x.ctx, x.ref, id)
	if err != nil || !rep.Failed {
		t.Fatalf("setup: the resumed run must fail on verify: %+v %v", rep, err)
	}
	if dump := fmt.Sprintf("%+v %#v\n%s", rep, rep, auditText(t, x)); c.In(dump) {
		t.Fatalf("canary reached the report or the journal (%d bytes inspected)", len(dump))
	}
}

// Each of the two ways a run is known to be driven holds on its own: the
// goroutine of this process, even when the database shows no lease, and a live
// lease of another process, even when this one has no goroutine for the run.
func TestResumeEachLiveRunGuardHoldsAlone(t *testing.T) {
	t.Run("goroutine of this process", func(t *testing.T) {
		x, f := newFx(t), newFakes(1)
		f.gate = make(chan struct{})
		f.entered = make(chan struct{}, 1)
		s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(testResume)
		if _, err := startPlain(s, x.ctx, x.ref); err != nil {
			t.Fatal(err)
		}
		<-f.entered
		if _, err := x.pool.Exec(x.ctx, `UPDATE rotation_runs SET lease_owner='', lease_until=NULL`); err != nil {
			t.Fatal("clear lease")
		}
		if n, err := s.Resume(x.ctx); err != nil || n != 0 {
			t.Fatalf("a run this process drives was taken: n=%d err=%v", n, err)
		}
		close(f.gate)
		s.Wait()
	})
	t.Run("lease of another process", func(t *testing.T) {
		x, f := newFx(t), newFakes(1)
		s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(testResume)
		var kill atomic.Bool
		kill.Store(true)
		killAfterPrepare(s, &kill)
		if _, err := startPlain(s, x.ctx, x.ref); err != nil {
			t.Fatal(err)
		}
		s.Wait()
		kill.Store(false)
		if _, err := x.pool.Exec(x.ctx, `UPDATE rotation_runs SET lease_owner='other', lease_until=now() + interval '1 hour'`); err != nil {
			t.Fatal("set lease")
		}
		if n, err := s.Resume(x.ctx); err != nil || n != 0 {
			t.Fatalf("a run another process holds was taken: n=%d err=%v", n, err)
		}
	})
}
