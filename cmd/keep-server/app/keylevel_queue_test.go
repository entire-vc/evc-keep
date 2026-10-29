package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
)

// slowJournal blocks the first append until released, then counts writes.
// failFirst makes the first n attempts fail to exercise the retry.
type slowJournal struct {
	release   chan struct{}
	failFirst int
	mu        sync.Mutex
	n         int
	attempts  int
}

func (s *slowJournal) Append(ctx context.Context, r audit.Record) (audit.Record, error) {
	<-s.release
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.attempts <= s.failFirst {
		return audit.Record{}, errors.New("journal down")
	}
	s.n++
	return r, nil
}

func (s *slowJournal) written() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func waitWritten(t *testing.T, j *slowJournal, want int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if j.written() == want {
			return
		}
	}
	t.Fatalf("journal got %d outcomes, want %d", j.written(), want)
}

// A delayed writer must not cost outcomes: far more events than any fixed
// queue are accepted while the journal is stuck, and all are written.
func TestKeyLevelAuditorKeepsEveryOutcomeWhileJournalIsSlow(t *testing.T) {
	j := &slowJournal{release: make(chan struct{})}
	sink := newKeyLevelAuditor(j, slog.New(slog.NewTextHandler(io.Discard, nil)), nil).record
	const total = 500
	for i := 0; i < total; i++ {
		sink(builtin.KeyEvent{Action: "key_level_changed", From: "user", To: "org"})
	}
	close(j.release)
	waitWritten(t, j, total)
}

// A transient journal failure is retried, not dropped.
func TestKeyLevelAuditorRetriesFailedWrite(t *testing.T) {
	j := &slowJournal{release: make(chan struct{}), failFirst: 1}
	close(j.release)
	sink := newKeyLevelAuditor(j, slog.New(slog.NewTextHandler(io.Discard, nil)), nil).record
	sink(builtin.KeyEvent{Action: "key_level_changed", From: "user", To: "org"})
	waitWritten(t, j, 1)
}

// An outage longer than the logged retry threshold still ends with the
// outcome journaled: the record is kept, not discarded.
func TestKeyLevelAuditorKeepsOutcomeThroughLongOutage(t *testing.T) {
	j := &slowJournal{release: make(chan struct{}), failFirst: 3 * journalWriteAttempts}
	close(j.release)
	a := newKeyLevelAuditor(j, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	a.backoff = time.Millisecond
	sink := a.record
	sink(builtin.KeyEvent{Action: "key_level_changed", From: "user", To: "org"})
	waitWritten(t, j, 1)
}

// The journaled outcome carries the request id of the change it answers.
func TestEventRecordCarriesRequestID(t *testing.T) {
	for _, action := range []string{"key_level_changed", "key_level_change_denied", "key_level_change_failed"} {
		r, ok := eventRecord(builtin.KeyEvent{Action: action, RequestID: "req-1", Org: "o", Actor: "u", From: "user", To: "project"})
		if !ok || r.RequestID != "req-1" {
			t.Fatalf("%s: record request id %q (ok=%v); want req-1", action, r.RequestID, ok)
		}
	}
}
