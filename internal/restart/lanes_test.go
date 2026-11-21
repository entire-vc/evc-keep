package restart

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// No lane given is no lane allowed: the queue has no built-in allowlist, so
// a server started without one refuses every restart request (fail-closed).
// Runs without a database: the refusal comes before any query.
func TestNewRepoWithoutLanesRefusesEveryLane(t *testing.T) {
	r := NewRepo(nil)
	if len(r.lanes) != 0 {
		t.Fatalf("a queue built without lanes allows %d lanes", len(r.lanes))
	}
	for _, lane := range []string{"worker", "other", "Test", "test", ""} {
		if r.Allows(lane) {
			t.Fatalf("lane %q allowed without an allowlist", lane)
		}
		if _, err := r.Enqueue(context.Background(), uuid.New(), lane, "key-1", testFP); !errors.Is(err, ErrLane) {
			t.Fatalf("lane %q: %v, want ErrLane", lane, err)
		}
	}
}

// Given lanes are exactly the allowlist: nothing else, no other case.
func TestNewRepoAllowsOnlyTheGivenLanes(t *testing.T) {
	r := NewRepo(nil, "worker")
	if !r.Allows("worker") || len(r.lanes) != 1 {
		t.Fatalf("allowlist %v, want only worker", r.lanes)
	}
	for _, lane := range []string{"other", "Worker", "worker ", ""} {
		if r.Allows(lane) {
			t.Fatalf("lane %q allowed", lane)
		}
		if _, err := r.Enqueue(context.Background(), uuid.New(), lane, "key-1", testFP); !errors.Is(err, ErrLane) {
			t.Fatalf("lane %q: %v, want ErrLane", lane, err)
		}
	}
}
