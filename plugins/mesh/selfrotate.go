package mesh

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
)

// TokenStore is Keep's sealed store of the service token: the sink of a
// rotation and the source of the Authorization header. *svctoken.Store is the
// implementation.
type TokenStore interface {
	Sink
	Token(ctx context.Context) (string, error)
}

// RestartGraceSeconds is the shortest grace window of the replaced ext_ token
// when the restart goes through the queue. The queue settles a request at the
// latest when a lease that started just before the pending TTL ends (15 + 5
// minutes); until then the old token must keep working, since only an
// acknowledged restart proves the lane runs on the new one.
const RestartGraceSeconds = 1200

// SelfRotateConfig configures NewSelfRotation.
type SelfRotateConfig struct {
	BaseURL   string
	AccountID string
	Store     TokenStore
	// HookPath is an absolute path to the program run after the new token is
	// active. It is started without arguments; empty means no hook.
	HookPath string
	// Restarts is the restart queue, bound to the lane by the core. Set, a
	// rotation asks for the restart there and ends the old key only after the
	// poller acknowledged it; it excludes HookPath. A nil interface means none.
	Restarts     Restarts
	GraceSeconds int
	Log          *slog.Logger
}

// NewSelfRotation returns the function a scheduler calls to rotate the
// service account's own ext_ token once. The function returns a rotation class
// only; ids and outcome go to the log, never a value.
func NewSelfRotation(cfg SelfRotateConfig) (func(context.Context) error, error) {
	if cfg.Store == nil {
		return nil, ErrConfig
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	grace := cfg.GraceSeconds
	if cfg.Restarts != nil {
		grace = max(grace, RestartGraceSeconds)
	}
	x, err := NewExtSelf(ExtConfig{
		BaseURL: cfg.BaseURL, AccountID: cfg.AccountID, GraceSeconds: grace, Log: log,
		TokenSource: func(ctx context.Context) (Token, error) {
			tok, err := cfg.Store.Token(ctx)
			return Token(tok), err
		},
	})
	if err != nil {
		return nil, err
	}
	var hook Hook
	if cfg.Restarts != nil && cfg.HookPath != "" {
		return nil, ErrConfig
	}
	if cfg.Restarts != nil {
		h, err := NewRestartHook(cfg.Restarts)
		if err != nil {
			return nil, err
		}
		hook = h
	}
	if cfg.HookPath != "" {
		h, err := NewExecHook([]string{cfg.HookPath})
		if err != nil {
			return nil, err
		}
		hook = h
	}
	// pending is a rotation whose restart is queued and whose old key still
	// stands. It is kept in memory: a restart of the server forgets it and the
	// old key is then ended by hand (RotateSelf refuses with two active keys).
	var pending *RotateResult
	// fenced is a rotation whose restart failed or expired: both keys stay
	// valid and a person decides. No further rotation starts in this process,
	// since an ext_ rotation would end the old token the lane may still hold.
	var fenced *RotateResult
	return func(ctx context.Context) error {
		if fenced != nil {
			log.Info("mesh self-rotation", "status", "restart_failed", "old_key_id", fenced.OldKeyID, "new_key_id", fenced.NewKeyID)
			return errors.Join(ErrOrphaned, ErrHook)
		}
		if pending != nil {
			res, err := settle(ctx, x, cfg, hook, *pending)
			switch {
			case res.settled && errors.Is(err, ErrOrphaned):
				r := res.RotateResult
				fenced, pending = &r, nil
			case res.settled:
				pending = nil
			default:
				pending.RestartID = res.RestartID
			}
			log.Info("mesh self-rotation", "status", res.status, "old_key_id", res.OldKeyID, "new_key_id", res.NewKeyID)
			if pending != nil && err == nil {
				return ErrRestartPending
			}
			return err
		}
		res, err := RotateSelf(ctx, x, cfg.Store, hook, uuid.New())
		// After activation the rotation is forward-only: a failed revoke of the
		// old token is repeated once here, RevokeOld refuses to end a token in use.
		if err != nil && res.activated {
			res, err = RevokeOld(ctx, x, hook, res)
		}
		status := "rotated"
		if _, ok := hook.(*RestartHook); ok && res.activated && (err == nil || errors.Is(err, ErrHook)) {
			r := res
			pending = &r
			status = "restart_queued"
			if err != nil {
				status = "restart_not_queued"
			}
		}
		switch {
		case status == "restart_queued" || status == "restart_not_queued":
		case err != nil && errors.Is(err, ErrOrphaned):
			status = "orphaned"
		case err != nil:
			status = "failed"
		case res.HookFailed:
			status = "rotated_hook_failed"
		}
		log.Info("mesh self-rotation", "status", status, "old_key_id", res.OldKeyID, "new_key_id", res.NewKeyID)
		if status == "restart_queued" {
			return ErrRestartPending
		}
		return err
	}, nil
}

// settled carries the outcome of one settle step for the log line.
type settled struct {
	RotateResult
	settled bool
	status  string
}

// settle runs one step of a queued restart: queue it again if that failed, or
// read its outcome and end the old key, or report the failure and keep both keys.
func settle(ctx context.Context, x SelfRotator, cfg SelfRotateConfig, hook Hook, res RotateResult) (settled, error) {
	if res.RestartID == uuid.Nil {
		r, err := RevokeOld(ctx, x, hook, res)
		if err != nil {
			return settled{RotateResult: r, status: "restart_not_queued"}, err
		}
		return settled{RotateResult: r, status: "restart_queued"}, nil
	}
	r, done, err := SettleRestart(ctx, x, cfg.Restarts, res)
	st := "restart_pending"
	switch {
	case done && err == nil:
		st = "rotated"
	case done && errors.Is(err, ErrOrphaned):
		st = "restart_failed"
	case err != nil:
		st = "failed"
	}
	return settled{RotateResult: r, settled: done, status: st}, err
}
