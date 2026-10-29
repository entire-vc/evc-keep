package catalog

import "context"

// hookKey is an unexported context key type so this package's hook can never
// collide with a key set by any other package.
type hookKey struct{}

// withBeforeInsertHook attaches fn to ctx so the write it wraps (CreateRef,
// CreateStoreBinding, CreateOverrideLock) calls it exactly once, immediately
// before its own INSERT, from inside the open transaction that also holds
// its scope locks.
// It exists only for concurrency_test.go, to force a deterministic overlap
// with a concurrent writer instead of hoping the scheduler produces one —
// the same reason pkg/runnerproto's TestReplayConcurrent parks every
// claimer on a mutex before releasing them together (see that test's own
// doc). No production caller ever sets it: ctx.Value on an unset key costs
// one map lookup and calls nothing.
func withBeforeInsertHook(ctx context.Context, fn func()) context.Context {
	return context.WithValue(ctx, hookKey{}, fn)
}

// beforeInsertHook runs the hook ctx carries, if any.
func beforeInsertHook(ctx context.Context) {
	if fn, ok := ctx.Value(hookKey{}).(func()); ok && fn != nil {
		fn()
	}
}
