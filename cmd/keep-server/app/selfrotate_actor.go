package app

import (
	"context"
	"errors"
	"log/slog"

	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrSelfRotateSameActor stops a start whose self-rotation account is the
// actor whose token the Mesh gate holds: one actor has one sealed copy and one
// owner of its rotation. It names neither the actor nor the token.
var ErrSelfRotateSameActor = errors.New("self-rotation account is the gate's actor")

// checkSelfRotateActor runs the plugin's actor check when the gate is
// configured and the service token rotates (not seal-only). It runs before
// the rotation starts, so a refused start has rotated nothing.
func checkSelfRotateActor(ctx context.Context, cfg config.Config, opts Options, pool *pgxpool.Pool, vault gateVault, logger *slog.Logger) error {
	if !cfg.MeshExtension || !cfg.MeshGate.Enabled || !cfg.MeshSelfRotate.Enabled || cfg.MeshSelfRotate.SealOnly {
		return nil
	}
	if opts.SelfRotate == nil {
		// wireSelfRotate refuses this build with its own reason.
		return nil
	}
	tokens, err := gateTokens(cfg.MeshGate, pool, vault)
	if err != nil {
		return err
	}
	return selfRotateActor(ctx, cfg, opts, tokens, logger)
}

// selfRotateActor asks the plugin and maps its answer: the same actor stops the
// start with ErrSelfRotateSameActor; any other refusal stops it without the
// plugin's text.
func selfRotateActor(ctx context.Context, cfg config.Config, opts Options, tokens GateTokenSource, logger *slog.Logger) error {
	if opts.SelfRotateActor == nil {
		return errors.New("mesh service token self-rotation with the Mesh gate needs an actor check this build does not have")
	}
	err := opts.SelfRotateActor(ctx, cfg.MeshGate, tokens, cfg.MeshSelfRotate.AccountID, logger)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrSelfRotateSameActor):
		logger.Error("mesh service token self-rotation refused", "error_class", "same_actor")
		return ErrSelfRotateSameActor
	default:
		// The plugin's own text is not printed: it is not Keep's to vouch for.
		return errors.New("mesh service token self-rotation actor check was refused by the Mesh plugin")
	}
}
