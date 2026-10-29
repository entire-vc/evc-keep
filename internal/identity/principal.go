package identity

import (
	"context"

	"github.com/google/uuid"
)

// Principal is who an authenticated request is. [RequireAuth] is the only
// place that constructs one, and it does so from nothing but the bearer
// token — OrgID here is the ONLY source of org_id for the rest of the
// request's lifetime; a caller must never read org_id from a URL path or
// a request body again once it has a Principal (ADR-001 §6, tenancy model
// §1, this package's own acceptance requirement).
type Principal struct {
	Kind  Kind
	ID    uuid.UUID
	OrgID uuid.UUID
	// SponsorUserID is set only when Kind == KindAgent — the user who
	// connected the agent. An agent's rights are bounded by this user's,
	// recomputed fresh on every request; see [AgentPermissions] and
	// [Repo.EffectiveAgentPermissions].
	SponsorUserID *uuid.UUID
	// Scope is the token's own scope column, carried onto the Principal so
	// a caller downstream of [RequireAuth] can read it without a second
	// database round trip. Authorization against it (beyond what
	// [Repo.EffectiveAgentPermissions] already does for agents) belongs to
	// whatever package owns the resource being checked.
	Scope string
}

type principalCtxKey struct{}

// withContext attaches p to ctx. Unexported: [RequireAuth] is the only
// place a Principal may legitimately enter a request's context — an
// exported version would let any package forge one and bypass
// authentication entirely.
func withContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// FromContext returns the Principal attached by [RequireAuth], or ok=false
// if the request never went through it (e.g. an unauthenticated route).
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(Principal)
	return p, ok
}
