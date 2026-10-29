package builtin

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
)

// KeyEvent is a key-level or KEK-purge event as plain strings and counts, so
// the server can journal it without importing the sealer. Names, levels and
// counts only: the sealer holds nothing else to give.
type KeyEvent struct {
	Action, Org, Actor, SecretID, Version, From, To, Reason, RequestID string
	Rewrapped, Unchanged, Retired, Purged                              int
}

// eventSink adapts a KeyEvent callback to the sealer's Auditor.
type eventSink func(KeyEvent)

func (f eventSink) Record(e sealer.Event) {
	f(KeyEvent{RequestID: e.RequestID, Action: e.Action, Org: e.Org, Actor: e.Actor, SecretID: e.SecretID, Version: e.Version,
		From: levelName(e.From), To: levelName(e.To), Reason: e.Reason,
		Rewrapped: e.Rewrapped, Unchanged: e.Unchanged, Retired: e.Retired, Purged: e.Purged})
}

// levelName is empty for the zero Level (an event that never read the level).
func levelName(l sealer.Level) string {
	if l == 0 {
		return ""
	}
	return l.String()
}

// Errors of ChangeLevelByName, matched with errors.Is.
var (
	ErrLevelInvalid   = errors.New("builtin: invalid key level")
	ErrLevelWeakening = errors.New("builtin: key level weakening not confirmed")
	// ErrLevelRequest is returned when the onLocked hook of ChangeLevelByName
	// failed: the change did not start.
	ErrLevelRequest = errors.New("builtin: key level request hook failed")
)

// KeyLevelResult is the outcome of a change: counts only.
type KeyLevelResult struct {
	Level                         string
	Rewrapped, Unchanged, Retired int
}

// ChangeLevelByName is ChangeLevel for a level given by its settings name.
// onLocked, when not nil, runs once under the level lock before anything is
// read or written (see sealer.LevelChange.OnLocked); if it fails the change
// does not start and the error is ErrLevelRequest.
func (a *Admin) ChangeLevelByName(ctx context.Context, to, actor string, confirmWeakening bool, onLocked func(context.Context) error) (KeyLevelResult, error) {
	level, err := sealer.ParseLevel(to)
	if err != nil {
		return KeyLevelResult{}, ErrLevelInvalid
	}
	res, err := a.changeLevel(ctx, level, actor, confirmWeakening, onLocked)
	if errors.Is(err, sealer.ErrOnLocked) {
		return KeyLevelResult{}, ErrLevelRequest
	}
	if errors.Is(err, sealer.ErrWeakeningNotConfirmed) {
		return KeyLevelResult{}, ErrLevelWeakening
	}
	if err != nil {
		return KeyLevelResult{}, err
	}
	return KeyLevelResult{Level: res.To.String(), Rewrapped: res.Rewrapped, Unchanged: res.Unchanged, Retired: res.Retired}, nil
}

// ValidKeyLevel reports whether name is a level the settings may name; the
// server checks it before it journals a request.
func ValidKeyLevel(name string) bool {
	_, err := sealer.ParseLevel(name)
	return err == nil
}

// TryLockKeyLevel takes org's exclusive key-level lock without waiting: the
// same lock ChangeLevel holds. ok is false while a change of org holds it.
// The request of a change is journaled under that lock, so a request without
// an outcome whose lock is free belongs to a change that is no longer running.
// When ok, lctx carries the connection the lock is held on (see LockConn):
// work done under the lock goes through it, since a second pool connection
// can starve while writers queued behind the lock hold the rest of the pool.
// release must be called once when ok.
func TryLockKeyLevel(ctx context.Context, pool *pgxpool.Pool, org string) (lctx context.Context, release func(context.Context), ok bool, err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, levelLockKey(org)).Scan(&ok); err != nil {
		// The server may have granted the lock before the reply was lost: do
		// not let the connection back into the pool.
		_ = conn.Conn().Close(context.WithoutCancel(ctx))
		conn.Release()
		return nil, nil, false, err
	}
	if !ok {
		conn.Release()
		return nil, nil, false, nil
	}
	return context.WithValue(ctx, lockConnKey{}, conn), func(c context.Context) {
		c = context.WithoutCancel(c)
		if _, err := conn.Exec(c, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, levelLockKey(org)); err != nil {
			// A connection that may still hold the lock must not go back to the pool.
			_ = conn.Conn().Close(c)
		}
		conn.Release()
	}, true, nil
}

// CanonicalKeyLevel is the settings name of level name, with aliases resolved
// ("org" is "organization"); false for a name that is no level.
func CanonicalKeyLevel(name string) (string, bool) {
	l, err := sealer.ParseLevel(name)
	if err != nil {
		return "", false
	}
	return l.String(), true
}
