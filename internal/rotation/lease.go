package rotation

import (
	"context"
	"sync/atomic"

	"github.com/google/uuid"
)

// lease is what one Rotate call holds on a run: its owner token, the fencing
// epoch of its claim, and the moment it ends in the engine's clock (unix
// nanoseconds), moved forward by every successful renewal.
type lease struct {
	owner string
	epoch int64
	until atomic.Int64
}

type (
	leaseKey struct{}
	epochKey struct{}
	runKey   struct{}
)

func withRunID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, runKey{}, id)
}

// RunID returns the id of the run a collaborator is called for, so a
// collaborator that must tell one run's work from another's (a verification
// per run) does not need it in its signature.
func RunID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(runKey{}).(uuid.UUID)
	return id, ok
}

func withLease(ctx context.Context, l *lease) context.Context {
	return context.WithValue(ctx, leaseKey{}, l)
}

// leaseOf is nil outside a Rotate call; every guarded write then refuses.
func leaseOf(ctx context.Context) *lease {
	l, _ := ctx.Value(leaseKey{}).(*lease)
	return l
}

func withEpoch(ctx context.Context, n int64) context.Context {
	return context.WithValue(ctx, epochKey{}, n)
}

// Epoch returns the fencing token of the lease under which a collaborator is
// called. It grows with every claim of the run, so a call made under an older
// lease carries a lower number than the current owner's.
func Epoch(ctx context.Context) (int64, bool) {
	n, ok := ctx.Value(epochKey{}).(int64)
	return n, ok
}

type preparedKey struct{}

// withPrepared carries a version that already exists to the prepare step. It
// travels in the context, not in Options: a caller of Rotate cannot steer the
// rotation to a value, only the service that sealed one can.
func withPrepared(ctx context.Context, v Version) context.Context {
	return context.WithValue(ctx, preparedKey{}, v)
}

func preparedFrom(ctx context.Context) (Version, bool) {
	v, ok := ctx.Value(preparedKey{}).(Version)
	return v, ok
}

type rollbackKey struct{}

func withRollback(ctx context.Context) context.Context { return WithRollback(ctx) }

// WithRollback marks ctx as the rollback of a failed run. The engine sets it on
// every Deploy and Verify of a rollback; it is exported so a collaborator's own
// tests can build the same call.
func WithRollback(ctx context.Context) context.Context {
	return context.WithValue(ctx, rollbackKey{}, true)
}

// IsRollback reports that a Deploy or Verify is part of the rollback of a
// failed run: the carrier is put back on, and checked against, the old version.
// A collaborator that derives request ids from the run and the carrier must
// keep these apart from the layout's.
func IsRollback(ctx context.Context) bool {
	v, _ := ctx.Value(rollbackKey{}).(bool)
	return v
}
