package catalog

import (
	"context"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// ResolveAuthorized wraps tr.Resolve with tenancy model §3 step 5 — the
// part [tenancy.Repo.Resolve] deliberately leaves out (see its own doc):
// checking the secret Resolve found against tc.Principal's rights in its
// scope. It lives here rather than in internal/tenancy so that package
// never has to import internal/identity: internal/catalog already depends
// on internal/tenancy (see this package's doc.go) and internal/identity
// depends on neither, so wiring both together here adds no import cycle.
//
// The gate is [identity.PermReadMetadata]: every role this package's
// identity layer currently defines (viewer, member, admin) grants it, and
// it is also one of an agent's [identity.DefaultAgentGrants] — so "has
// PermReadMetadata in a scope" is exactly "has some role there" for a
// user, and "sponsor has some role there" for an agent (its own grants can
// only narrow that further, never widen it — [identity.AgentPermissions]).
//
// Rights are checked TWICE, deliberately. [principalCanReachContext] runs
// first and checks every non-user level tc itself names (org, and
// workspace/project when set) BEFORE Resolve ever runs — Resolve's own
// bottom-up search would otherwise let a principal with no rights at all
// in, say, a project still tell "the name is ALSO defined at a project I
// cannot see" from "the name is defined nowhere", by watching a org-level
// resolve flip to secret_not_found the moment someone adds a closer
// definition (see TestResolveAuthorized_MultiLevelExistenceOracle for the
// full shape of that oracle).
// After Resolve returns, the found scope is checked again as defence in
// depth — but that second check is never independently observable by a
// mutation test: the found scope is always one of the levels
// principalCanReachContext already cleared (org/ws/proj), or the
// principal's own user-level scope (unconditional, see
// principalPermissions' doc), so nothing can reach tr.Resolve at all with
// a scope this function would deny at the end. Do not add a mutation for
// it in scripts/check-tenancy-mutations.sh for that reason — it would
// never go red.
//
// A caller denied at either gate gets back the exact same
// [tenancy.NotFoundError] text a name that resolves nowhere would — built
// from [tenancy.CheckedLevels], the same helper Resolve's own not-found
// path uses — see that constructor's doc for why the two must never be
// told apart.
func ResolveAuthorized(ctx context.Context, tr *tenancy.Repo, ir *identity.Repo, tc tenancy.Context, name string) (tenancy.SecretRef, error) {
	reachable, err := principalCanReachContext(ctx, ir, tc)
	if err != nil {
		return tenancy.SecretRef{}, err
	}
	if !reachable {
		return tenancy.SecretRef{}, tenancy.NotFoundError(name, tenancy.CheckedLevels(tc))
	}

	ref, err := tr.Resolve(ctx, tc, name)
	if err != nil {
		return tenancy.SecretRef{}, err
	}

	perms, err := principalPermissions(ctx, ir, tc, ref.Scope)
	if err != nil {
		return tenancy.SecretRef{}, err
	}
	if !perms[identity.PermReadMetadata] {
		return tenancy.SecretRef{}, tenancy.NotFoundError(name, tenancy.CheckedLevels(tc))
	}
	return ref, nil
}

// principalCanReachContext reports whether tc.Principal holds
// identity.PermReadMetadata at every non-user level tc names — org, and
// workspace/project when tc sets them. It reads nothing about where any
// particular secret lives; it is a property of tc alone, checked before
// Resolve ever runs (see ResolveAuthorized's doc for why). tc's own user
// level needs no check here: nobody but tc.Principal (or, for an agent,
// its sponsor) is ever seated there, see principalPermissions' doc — and
// [tenancy.CheckedLevels] omits it for a service entirely.
func principalCanReachContext(ctx context.Context, ir *identity.Repo, tc tenancy.Context) (bool, error) {
	for _, lv := range tenancy.CheckedLevels(tc) {
		var id uuid.UUID
		switch lv {
		case tenancy.LevelOrg:
			id = tc.Org
		case tenancy.LevelWorkspace:
			id = tc.Workspace
		case tenancy.LevelProject:
			id = tc.Project
		default: // LevelUser — always reachable, see this function's doc.
			continue
		}
		perms, err := principalPermissions(ctx, ir, tc, tenancy.Scope{Level: lv, ID: id})
		if err != nil {
			return false, err
		}
		if !perms[identity.PermReadMetadata] {
			return false, nil
		}
	}
	return true, nil
}

// PermissionsAt exposes principalPermissions for a caller (internal/api's
// list-in-scope and get-by-id routes) that names a scope directly rather
// than resolving it by name through [ResolveAuthorized] — the same
// role-based rights computation, just without the name-resolution step
// around it.
//
// principalPermissions' user-level branch assumes, unconditionally, that
// whatever LevelUser scope it is asked about belongs to tc's own principal
// (or, for an agent, its sponsor) — an invariant [tenancy.Repo.Resolve]'s
// own chain construction upholds by construction (see that branch's doc),
// but a scope named directly by a caller here carries no such guarantee: it
// can be literally any user id. Enforce the invariant here, once, rather
// than let a caller-supplied user id borrow another principal's rights —
// a scope naming someone else's personal level gets back no rights at all,
// the same nil principalPermissions returns for PrincipalService.
func PermissionsAt(ctx context.Context, ir *identity.Repo, tc tenancy.Context, scope tenancy.Scope) (map[identity.Permission]bool, error) {
	if scope.Level == tenancy.LevelUser && scope.ID != effectiveUserID(tc.Principal) {
		return nil, nil
	}
	return principalPermissions(ctx, ir, tc, scope)
}

// effectiveUserID is the user id principalPermissions' user-level branch
// grants ownership of: the principal's own id for a user, its sponsor's for
// an agent, and uuid.Nil (equal to no real scope id) for any other kind.
func effectiveUserID(p tenancy.Principal) uuid.UUID {
	switch p.Kind {
	case tenancy.PrincipalUser:
		return p.ID
	case tenancy.PrincipalAgent:
		return p.SponsorUserID
	default:
		return uuid.Nil
	}
}

// principalPermissions computes tc.Principal's permissions in scope — the
// role-based check §3 step 5 calls for.
//
// A user's own personal scope (level:user) is the one scope every
// principal that can even reach it owns outright: the identity schema does
// not allow a membership row at a user scope at all (see
// tenancy.CreateMembership's doc and [identity.Repo.UserRole]'s), and
// Resolve's own chain construction only ever puts the REQUESTING
// principal's effective user id at the user level — its own for a user
// principal, its sponsor's for an agent — never anyone else's. So a
// PrincipalUser here always owns whatever user-level scope Resolve found,
// and a PrincipalAgent's sponsor always owns theirs; there is no role to
// look up in either case, only the agent's own grants matter (tenancy
// model §4) — see [identity.Repo.AgentExplicitGrants]'s doc.
func principalPermissions(ctx context.Context, ir *identity.Repo, tc tenancy.Context, scope tenancy.Scope) (map[identity.Permission]bool, error) {
	switch tc.Principal.Kind {
	case tenancy.PrincipalUser:
		if scope.Level == tenancy.LevelUser {
			return identity.PermissionsForRole(identity.RoleAdmin), nil
		}
		return ir.UserPermissions(ctx, tc.Org, tc.Principal.ID, scope.String())

	case tenancy.PrincipalAgent:
		if scope.Level == tenancy.LevelUser {
			grants, err := ir.AgentExplicitGrants(ctx, tc.Org, tc.Principal.ID)
			if err != nil {
				return nil, err
			}
			out := make(map[identity.Permission]bool, len(identity.DefaultAgentGrants)+len(grants))
			for p := range identity.DefaultAgentGrants {
				out[p] = true
			}
			for p := range grants {
				out[p] = true
			}
			return out, nil
		}
		sponsor := tc.Principal.SponsorUserID
		p := identity.Principal{Kind: identity.KindAgent, ID: tc.Principal.ID, OrgID: tc.Org, SponsorUserID: &sponsor}
		return ir.EffectiveAgentPermissions(ctx, p, scope.String())

	default:
		// PrincipalService (or any future kind): the tenancy model defines
		// no rights algorithm for it (§4 covers only user and agent) —
		// fail closed rather than silently allow. A service that
		// legitimately needs to resolve secrets is a follow-up design
		// question, not a silent default here.
		return nil, nil
	}
}
