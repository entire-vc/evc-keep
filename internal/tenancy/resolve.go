package tenancy

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// Principal is who is asking: a user, an agent (acting for its sponsor —
// tenancy model §4), or a service (no sponsor, no user level).
type Principal struct {
	Kind string // PrincipalUser, PrincipalAgent or PrincipalService
	// ID is the principal's own id: the user's id, the agent's id, or the
	// service's id. Unused for the resolution algorithm itself when
	// Kind == PrincipalAgent (SponsorUserID is what matters there), but
	// kept for callers (journal, future grant checks).
	ID uuid.UUID
	// SponsorUserID is set only when Kind == PrincipalAgent.
	SponsorUserID uuid.UUID
}

// Context is the (org, workspace?, project?, principal) a request resolves
// a name in — tenancy model §3.
type Context struct {
	Org       uuid.UUID
	Workspace uuid.UUID // uuid.Nil if absent
	Project   uuid.UUID // uuid.Nil if absent
	Principal Principal
}

// Resolve implements the tenancy model's §3 algorithm: find name in tc's
// context, searching bottom-up (user → project → workspace → org) unless an
// OverrideLock restricts the search to a level and above.
//
// The two ways this can fail to find anything — the name is defined
// nowhere in the chain, or it is defined only outside a level tc's
// principal can reach — are reported through the exact same
// [apperr.ClassSecretNotFound] text; see [NotFoundError]'s doc. In this
// implementation the second case can only arise through
// internal/catalog.Meta's explicit by-id reachability check: Resolve itself
// never even looks at a scope outside tc's own chain, so there is nothing
// for it to reject — the chain it searches already IS what tc's principal
// can reach.
//
// Not implemented here: §3 step 5, checking the found secret against the
// principal's rights (role in the secret's scope; for an agent, its
// sponsor's role intersected with its explicit grants). The model defines
// that check as separate from name resolution, and it lives with the layer
// that owns rights (internal/identity) — this package must not import it
// (see this file's own package doc and internal/catalog's doc on the
// dependency direction). internal/catalog.ResolveAuthorized is that check:
// it wraps this method, and a principal with no rights in the scope this
// method found gets back the exact same [NotFoundError] text a name that
// resolves nowhere would (using [CheckedLevels] itself, so the two can
// never drift apart). Resolve returns a reference only and every caller
// that does not go through ResolveAuthorized must still authorize it
// itself. Resolve trusts tc.Principal (including SponsorUserID) as given by
// the caller, which must take it from an authenticated identity, never from
// request input.
func (r *Repo) Resolve(ctx context.Context, tc Context, name string) (SecretRef, error) {
	if tc.Org == uuid.Nil {
		return SecretRef{}, invalidContextError("org is required")
	}

	effectiveUser, sponsorGone, err := r.effectiveUser(ctx, tc)
	if err != nil {
		return SecretRef{}, err
	}

	// Ambiguous-context check (§7 scenario C3): only at the workspace
	// level, per the doc's own scenario. Extending the same check to
	// projects (member of two projects in the same workspace, project
	// omitted) is a reasonable symmetric generalization but is NOT what
	// C3 tests, so it is deliberately left out here rather than guessed at.
	if tc.Workspace == uuid.Nil && effectiveUser != uuid.Nil {
		wsIDs, err := r.distinctScopeIDs(ctx, tc.Org, effectiveUser, LevelWorkspace)
		if err != nil {
			return SecretRef{}, err
		}
		if len(wsIDs) > 1 {
			return SecretRef{}, ErrAmbiguousContext
		}
	}

	chain, scopeIDs, err := r.buildChain(ctx, tc, effectiveUser)
	if err != nil {
		return SecretRef{}, err
	}

	// §6, fail closed for every name: a removed sponsor's agent resolves
	// nothing. This is decided only after the context has been validated
	// and the ambiguity check has run, exactly like an ordinary lookup, so
	// the outcome for such an agent differs from an undefined name in no
	// way the caller can observe.
	//
	// Every not-found text below names the levels of the REQUEST's own
	// context (CheckedLevels) and nothing the server knows about: not where
	// an OverrideLock cuts the search short, not whether the agent's sponsor
	// is still active. Either would let a caller tell "locked" or "sponsor
	// removed" from "never defined" by the message alone.
	if sponsorGone {
		return SecretRef{}, NotFoundError(name, CheckedLevels(tc))
	}

	lockIdx, err := r.topmostBlockingLock(ctx, tc.Org, chain, scopeIDs, name)
	if err != nil {
		return SecretRef{}, err
	}
	searchChain, searchIDs := chain, scopeIDs
	if lockIdx >= 0 {
		searchChain, searchIDs = chain[:lockIdx+1], scopeIDs[:lockIdx+1]
	}

	for i := len(searchChain) - 1; i >= 0; i-- {
		secret, found, err := r.secretAt(ctx, tc.Org, Scope{Level: searchChain[i], ID: searchIDs[i]}, name)
		if err != nil {
			return SecretRef{}, err
		}
		if found {
			return secret, nil
		}
	}
	levels := CheckedLevels(tc)
	return SecretRef{}, NotFoundError(name, levels)
}

// CheckedLevels lists the level kinds tc's own context spans, top-down, the
// way the caller declared it: org, then workspace and project if given, then
// user for a user or an agent (an agent's user level is its sponsor's) and
// nothing for a service. It reads nothing but tc.
//
// Exported so internal/catalog.ResolveAuthorized can build the exact same
// [NotFoundError] Resolve itself would for a rights failure — see that
// function's doc.
func CheckedLevels(tc Context) []Level {
	levels := []Level{LevelOrg}
	if tc.Workspace != uuid.Nil {
		levels = append(levels, LevelWorkspace)
	}
	if tc.Project != uuid.Nil {
		levels = append(levels, LevelProject)
	}
	if tc.Principal.Kind == PrincipalUser || tc.Principal.Kind == PrincipalAgent {
		levels = append(levels, LevelUser)
	}
	return levels
}

// effectiveUser resolves tc's user-level identity: the principal itself for
// a user, the sponsor for an agent, or uuid.Nil for a service (§4: no user
// level in its chain at all). sponsorGone reports an agent whose sponsor is
// no longer active (§6): the caller must resolve nothing for it, and must do
// so through the ordinary not-found path.
func (r *Repo) effectiveUser(ctx context.Context, tc Context) (user uuid.UUID, sponsorGone bool, err error) {
	switch tc.Principal.Kind {
	case PrincipalUser:
		if tc.Principal.ID == uuid.Nil {
			return uuid.Nil, false, invalidContextError("user principal requires an id")
		}
		return tc.Principal.ID, false, nil
	case PrincipalAgent:
		if tc.Principal.SponsorUserID == uuid.Nil {
			return uuid.Nil, false, invalidContextError("agent principal requires a sponsor")
		}
		sponsor, err := r.GetUser(ctx, tc.Org, tc.Principal.SponsorUserID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return uuid.Nil, false, invalidContextError("sponsor not found in this organization")
			}
			return uuid.Nil, false, err
		}
		return sponsor.ID, sponsor.Status != "active", nil
	case PrincipalService:
		return uuid.Nil, false, nil
	default:
		return uuid.Nil, false, invalidContextError("unknown principal kind")
	}
}

// buildChain validates tc's declared workspace/project against the schema
// (they must actually nest under org, and under each other) and returns the
// top-down level/id chain Resolve searches: org, [workspace], [project],
// [user].
func (r *Repo) buildChain(ctx context.Context, tc Context, effectiveUser uuid.UUID) ([]Level, []uuid.UUID, error) {
	chain := []Level{LevelOrg}
	ids := []uuid.UUID{tc.Org}

	if tc.Workspace != uuid.Nil {
		ok, err := r.workspaceInOrg(ctx, tc.Org, tc.Workspace)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			return nil, nil, invalidContextError("workspace does not belong to org")
		}
		chain = append(chain, LevelWorkspace)
		ids = append(ids, tc.Workspace)
	}

	if tc.Project != uuid.Nil {
		if tc.Workspace == uuid.Nil {
			return nil, nil, invalidContextError("project requires workspace")
		}
		ok, err := r.projectInWorkspace(ctx, tc.Org, tc.Workspace, tc.Project)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			return nil, nil, invalidContextError("project does not belong to workspace")
		}
		chain = append(chain, LevelProject)
		ids = append(ids, tc.Project)
	}

	if effectiveUser != uuid.Nil {
		chain = append(chain, LevelUser)
		ids = append(ids, effectiveUser)
	}

	return chain, ids, nil
}

// topmostBlockingLock implements §3 step 2: the topmost level in chain that
// carries an OverrideLock covering name (mode='name'), or whose mode='class'
// covers the class of name's deepest definition at that level OR BELOW it
// (mode='class') — a class lock blocks a lower-level definition of name
// whose class it covers even when name is not itself (re)defined at the
// lock's own level. Returns -1 if none blocks. mode='store' locks never
// participate — they are create-time-only (internal/catalog.CreateRef), see
// 00004_catalog.sql.
func (r *Repo) topmostBlockingLock(ctx context.Context, org uuid.UUID, chain []Level, scopeIDs []uuid.UUID, name string) (int, error) {
	for i, lv := range chain {
		locks, err := r.locksAt(ctx, org, Scope{Level: lv, ID: scopeIDs[i]})
		if err != nil {
			return -1, err
		}
		if len(locks) == 0 {
			continue
		}
		// Computed at most once per level, and only when a class-mode lock
		// at this level actually needs it: what name's own value would be
		// if searched bottom-up from the deepest level down through this
		// one — the same direction Resolve's final loop searches — so a
		// class lock sees exactly the definition it would otherwise let
		// through.
		var (
			candidate      SecretRef
			candidateFound bool
			lookedUp       bool
		)
		for _, lk := range locks {
			switch {
			case lk.mode == "name" && lk.selectorName != nil && *lk.selectorName == name:
				return i, nil
			case lk.mode == "class" && lk.selectorClass != nil:
				if !lookedUp {
					candidate, candidateFound, err = r.deepestDefinition(ctx, org, chain, scopeIDs, name, i)
					if err != nil {
						return -1, err
					}
					lookedUp = true
				}
				if candidateFound && candidate.Class == *lk.selectorClass {
					return i, nil
				}
			}
		}
	}
	return -1, nil
}

// deepestDefinition returns the deepest definition of name among chain
// levels [from, len(chain)-1], searched bottom-up (deepest first) — the
// same order Resolve's own final loop uses once a blocking level has been
// found. It is [topmostBlockingLock]'s way of asking "what would a class
// lock at level from see if it looked past its own level", since a
// class-mode lock must block a matching lower definition even when from
// itself defines nothing named name.
func (r *Repo) deepestDefinition(ctx context.Context, org uuid.UUID, chain []Level, scopeIDs []uuid.UUID, name string, from int) (SecretRef, bool, error) {
	for i := len(chain) - 1; i >= from; i-- {
		secret, found, err := r.secretAt(ctx, org, Scope{Level: chain[i], ID: scopeIDs[i]}, name)
		if err != nil {
			return SecretRef{}, false, err
		}
		if found {
			return secret, true, nil
		}
	}
	return SecretRef{}, false, nil
}
