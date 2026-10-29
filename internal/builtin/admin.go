package builtin

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/reqid"
)

// Admin is the organisation-wide administrative surface of the built-in
// provider: a key-level change and a KEK purge touch every store of an
// organisation, unlike Provider, which is scoped to one. The caller has
// already checked the actor is an organisation administrator — this
// package has no notion of roles (see Sealer.ChangeLevel's doc comment).
type Admin struct {
	org  string
	seal *sealer.Sealer
	db   *store
	log  *slog.Logger
}

// NewAdmin returns an Admin for org, sealing and opening through seal and
// persisting to pool.
func NewAdmin(pool *pgxpool.Pool, seal *sealer.Sealer, org string, log *slog.Logger) *Admin {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Admin{org: org, seal: seal, db: newStore(pool), log: log}
}

// ChangeLevel moves the Admin's organisation to level to — see
// sealer.Sealer.ChangeLevel for what this does and does not touch. It takes
// no Org parameter, only to/actor/confirmWeakening: an Admin acts on the
// organisation it was constructed for and no other, so there is nothing a
// caller could set to redirect it at a different one (see
// TestChangeLevel_ActsOnlyOnAdminsOwnOrg — this used to take a full
// sealer.LevelChange, whose Org field a caller controlled independently of
// which Admin they called it on).
func (a *Admin) ChangeLevel(ctx context.Context, to sealer.Level, actor string, confirmWeakening bool) (sealer.ChangeResult, error) {
	return a.changeLevel(ctx, to, actor, confirmWeakening, nil)
}

// changeLevel is ChangeLevel with sealer.LevelChange.OnLocked set to onLocked.
func (a *Admin) changeLevel(ctx context.Context, to sealer.Level, actor string, confirmWeakening bool, onLocked func(context.Context) error) (sealer.ChangeResult, error) {
	c := sealer.LevelChange{Org: a.org, To: to, Actor: actor, RequestID: reqid.FromContext(ctx), ConfirmWeakening: confirmWeakening, OnLocked: onLocked}
	res, err := a.seal.ChangeLevel(ctx, c, a.db)
	// Level names and counts are not identifier-shaped, so internal/obs's
	// closed key allow-list (method/route/status/request_id/duration_ms/
	// error_class/stack, plus *_id and *_name) drops them; the full detail
	// of what a change did lives in the audit journal event this call
	// already produces (sealer.Event via a.seal's Auditor), not this line —
	// org_id/actor_id are what a log line usefully correlates by.
	a.log.Info("change level", "org_id", loggableID(a.org), "actor_id", loggableID(actor))
	return res, scrubDB("change level", err)
}

// Purge destroys the organisation's retired KEKs that nothing references any
// more — see sealer.Sealer.Purge.
func (a *Admin) Purge(ctx context.Context, actor string) (int, error) {
	n, err := a.seal.Purge(ctx, a.org, actor, a.db)
	a.log.Info("purge", "org_id", loggableID(a.org), "actor_id", loggableID(actor))
	return n, scrubDB("purge", err)
}
