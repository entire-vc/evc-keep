// Tests for ResolveAuthorized — tenancy model §3 step 5, the principal
// rights check scenarios_test.go's own doc comment explicitly leaves out.
// Every test here goes through ResolveAuthorized, not the bare
// tenancy.Repo.Resolve scenarios_test.go exercises, against a real
// PostgreSQL database (CONTRIBUTING.md: no mocking).
package catalog

import (
	"fmt"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// setMembership replaces alice's membership row at scope with role, or
// removes it entirely when role is "" — tenancy.Repo has no
// Update/DeleteMembership (one role per scope is enforced by re-creating
// the row, the same way test/security/identity_attack_test.go's own
// world.setMembership does it for internal/identity's tests).
func (f *fixture) setMembership(user tenancy.User, scope tenancy.Scope, role identity.Role) {
	f.t.Helper()
	f.mustExec(`DELETE FROM memberships WHERE user_id = $1 AND scope = $2`, user.ID, scope.String())
	if role == "" {
		return
	}
	if _, err := f.rp.CreateMembership(f.ctx, f.org.ID, user.ID, scope, string(role)); err != nil {
		f.t.Fatalf("set membership %q at %v: %v", role, scope, err)
	}
}

// setAgentGrants replaces agent's explicit grants with exactly perms
// (possibly none).
func (f *fixture) setAgentGrants(agent tenancy.Agent, perms ...identity.Permission) {
	f.t.Helper()
	f.mustExec(`DELETE FROM agent_grants WHERE agent_id = $1`, agent.ID)
	for _, p := range perms {
		f.mustExec(`INSERT INTO agent_grants (id, org_id, agent_id, permission) VALUES ($1, $2, $3, $4)`,
			uuid.Must(uuid.NewV7()), f.org.ID, agent.ID, string(p))
	}
}

func (f *fixture) mustExec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

// TestResolveAuthorized_UserRoleGatesResolve is the direct §3 step 5 test:
// a user with no role at all in the secret's own scope must not resolve
// it, and the failure must be the exact same secret_not_found text a name
// that is not defined anywhere would produce — never an oracle. Any
// defined role (every one of them grants identity.PermReadMetadata) must
// let the user through.
func TestResolveAuthorized_UserRoleGatesResolve(t *testing.T) {
	for _, role := range []identity.Role{"", identity.RoleViewer, identity.RoleMember, identity.RoleAdmin} {
		role := role
		t.Run(fmt.Sprintf("role=%q", role), func(t *testing.T) {
			f := newFixture(t)
			f.mustBind(tenancy.Org(f.org.ID), f.mustStore("builtin", tenancy.Org(f.org.ID)))
			ws := f.mustWorkspace("ws")
			proj := f.mustProject(ws, "proj")
			alice := f.mustUser("Alice")
			scope := tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID}
			secret := f.mustRef(scope, "DEPLOY_TOKEN", "prod")
			f.setMembership(alice, scope, role)
			if role != "" {
				// The context gate (principalCanReachContext) checks every
				// non-user level tc names, not just the secret's own scope —
				// give Alice the same role at org and workspace too, or the
				// gate denies before this test's actual subject (the role
				// check at the secret's own scope) is ever reached.
				f.setMembership(alice, tenancy.Org(f.org.ID), role)
				f.setMembership(alice, tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}, role)
			}

			tc := tenancy.Context{
				Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
				Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: alice.ID},
			}

			got, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "DEPLOY_TOKEN")
			if role == "" {
				if err == nil {
					t.Fatalf("resolved %v with no role at all in the secret's scope, want secret_not_found", got)
				}
				classAppErr(t, err, apperr.ClassSecretNotFound)

				// Oracle check: the SAME name, in a context with the same
				// checked-levels shape (org, ws, proj, user) but where
				// "DEPLOY_TOKEN" is never defined at all, must produce a
				// byte-identical message — the name and the checked levels
				// are the only things NotFoundError's text carries (see its
				// doc), so an identical name in an identically-shaped
				// context that never resolves is the right control.
				ws2 := f.mustWorkspace("ws-undefined")
				proj2 := f.mustProject(ws2, "proj-undefined")
				undefinedTC := tenancy.Context{
					Org: f.org.ID, Workspace: ws2.ID, Project: proj2.ID,
					Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: alice.ID},
				}
				_, wantFromAuthorized := ResolveAuthorized(f.ctx, f.rp, f.ir, undefinedTC, "DEPLOY_TOKEN")
				if wantFromAuthorized == nil || err.Error() != wantFromAuthorized.Error() {
					t.Fatalf("no-role error %q, want byte-identical to undefined-name error %q", err, wantFromAuthorized)
				}
				_, wantFromResolve := f.rp.Resolve(f.ctx, undefinedTC, "DEPLOY_TOKEN")
				if wantFromResolve == nil || err.Error() != wantFromResolve.Error() {
					t.Fatalf("no-role error %q, want byte-identical to bare Resolve's undefined-name error %q", err, wantFromResolve)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve with role %q: %v", role, err)
			}
			if got.ID != secret.ID {
				t.Fatalf("resolved %v, want %v", got.ID, secret.ID)
			}
		})
	}
}

// TestResolveAuthorized_AgentPermissionsNeverExceedSponsor is the agent ⊆
// sponsor property (tenancy model §4), exercised through ResolveAuthorized
// rather than internal/identity in isolation (already covered there by
// TestAgentPermissionsNeverExceedsSponsor and
// TestIdentity_AgentNeverExceedsSponsor): an agent must never resolve a
// secret its sponsor's own role in that scope would not let it see, no
// matter what it was explicitly granted, and a sponsor's role change must
// take effect on the agent's very next call.
func TestResolveAuthorized_AgentPermissionsNeverExceedSponsor(t *testing.T) {
	f := newFixture(t)
	f.mustBind(tenancy.Org(f.org.ID), f.mustStore("builtin", tenancy.Org(f.org.ID)))
	ws := f.mustWorkspace("ws")
	proj := f.mustProject(ws, "proj")
	scope := tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID}
	grace := f.mustUser("Grace")
	hermes := f.mustAgent(grace, "Hermes")
	f.mustRef(scope, "DEPLOY_TOKEN", "prod")

	tc := tenancy.Context{
		Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
		Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: hermes.ID, SponsorUserID: grace.ID},
	}

	t.Run("sponsor has no role: every explicit grant still resolves nothing", func(t *testing.T) {
		f.setMembership(grace, scope, "")
		f.setAgentGrants(hermes, identity.PermRotate, identity.PermCreateRef)
		_, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "DEPLOY_TOKEN")
		if err == nil {
			t.Fatal("agent resolved a secret its unsponsored role should hide, despite holding every explicit grant — agent exceeded sponsor")
		}
		classAppErr(t, err, apperr.ClassSecretNotFound)

		// Oracle check, same control as TestResolveAuthorized_UserRoleGatesResolve:
		// the SAME name, same checked-levels shape (org, ws, proj, user), but a
		// workspace/project where "DEPLOY_TOKEN" is never defined at all — must
		// be byte-identical, both through ResolveAuthorized and through bare
		// Resolve.
		ws2 := f.mustWorkspace("ws-undefined-agent")
		proj2 := f.mustProject(ws2, "proj-undefined-agent")
		undefinedTC := tenancy.Context{
			Org: f.org.ID, Workspace: ws2.ID, Project: proj2.ID,
			Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: hermes.ID, SponsorUserID: grace.ID},
		}
		_, wantFromAuthorized := ResolveAuthorized(f.ctx, f.rp, f.ir, undefinedTC, "DEPLOY_TOKEN")
		if wantFromAuthorized == nil || err.Error() != wantFromAuthorized.Error() {
			t.Fatalf("unsponsored-agent error %q, want byte-identical to undefined-name error %q", err, wantFromAuthorized)
		}
		_, wantFromResolve := f.rp.Resolve(f.ctx, undefinedTC, "DEPLOY_TOKEN")
		if wantFromResolve == nil || err.Error() != wantFromResolve.Error() {
			t.Fatalf("unsponsored-agent error %q, want byte-identical to bare Resolve's undefined-name error %q", err, wantFromResolve)
		}
	})

	t.Run("sponsor gets a role: agent resolves without any explicit grant", func(t *testing.T) {
		// The context gate needs grace to hold a role at every non-user
		// level tc names (org, ws, proj), not just the secret's own scope.
		f.setMembership(grace, tenancy.Org(f.org.ID), identity.RoleViewer)
		f.setMembership(grace, tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}, identity.RoleViewer)
		f.setMembership(grace, scope, identity.RoleViewer)
		f.setAgentGrants(hermes) // none at all — read_metadata is a default
		got, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "DEPLOY_TOKEN")
		if err != nil {
			t.Fatalf("agent could not resolve although its sponsor now has a role: %v", err)
		}
		if got.Name != "DEPLOY_TOKEN" {
			t.Fatalf("resolved %+v, want DEPLOY_TOKEN", got)
		}
	})

	t.Run("sponsor demoted to no role: the agent's very next call loses it", func(t *testing.T) {
		// Explicit, not inherited from the previous subtest's state: the
		// context gate needs grace's role at org/ws independently of proj.
		f.setMembership(grace, tenancy.Org(f.org.ID), identity.RoleViewer)
		f.setMembership(grace, tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}, identity.RoleViewer)
		f.setMembership(grace, scope, identity.RoleAdmin)
		if _, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "DEPLOY_TOKEN"); err != nil {
			t.Fatalf("control: admin sponsor must allow resolve: %v", err)
		}
		f.setMembership(grace, scope, "")
		_, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "DEPLOY_TOKEN")
		if err == nil {
			t.Fatal("stale rights: agent still resolves after its sponsor's membership was removed")
		}
		classAppErr(t, err, apperr.ClassSecretNotFound)
	})
}

// TestResolveAuthorized_PersonalScopeIsAlwaysOwn covers the one scope the
// identity schema forbids a membership row at all (tenancy.CreateMembership
// rejects a user-level scope) — the model's own scenario C2 (two users,
// each with their own personal-scope secret and their own agent) already
// proves the bare tenancy.Repo.Resolve side of this works; this proves
// ResolveAuthorized does not turn every personal secret unreadable by
// requiring a role that can never exist there. A membership-less user is
// not a real scenario though (tenancy model §1/§6.5: a user belongs to
// exactly one org, and leaving it loses access to it entirely) — every
// case here gives Alice an ordinary org role, the context gate's own
// precondition, and the personal (user-level) scope itself still needs no
// role of its own, per principalPermissions' doc.
func TestResolveAuthorized_PersonalScopeIsAlwaysOwn(t *testing.T) {
	f := newFixture(t)
	alice := f.mustUser("Alice")
	scope := tenancy.Scope{Level: tenancy.LevelUser, ID: alice.ID}
	store := f.mustStore("alice-builtin", scope)
	f.mustBind(scope, store)
	secret := f.mustRef(scope, "OPENAI_API_KEY", "dev")
	f.setMembership(alice, tenancy.Org(f.org.ID), identity.RoleViewer)

	t.Run("the owner resolves it with an ordinary org role, no role at user level at all", func(t *testing.T) {
		tc := tenancy.Context{Org: f.org.ID, Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: alice.ID}}
		got, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "OPENAI_API_KEY")
		if err != nil {
			t.Fatalf("owner could not resolve their own personal secret: %v", err)
		}
		if got.ID != secret.ID {
			t.Fatalf("resolved %v, want %v", got.ID, secret.ID)
		}
	})

	t.Run("its agent resolves it by default, with zero explicit grants", func(t *testing.T) {
		a1 := f.mustAgent(alice, "a1")
		f.setAgentGrants(a1) // none
		tc := tenancy.Context{Org: f.org.ID, Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: a1.ID, SponsorUserID: alice.ID}}
		got, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "OPENAI_API_KEY")
		if err != nil {
			t.Fatalf("agent could not resolve its sponsor's own personal secret by default: %v", err)
		}
		if got.ID != secret.ID {
			t.Fatalf("resolved %v, want %v", got.ID, secret.ID)
		}
	})

	t.Run("no org membership at all: secret_not_found, byte-identical whether or not the name actually exists", func(t *testing.T) {
		bob := f.mustUser("Bob")
		bobScope := tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID}
		bobStore := f.mustStore("bob-builtin", bobScope)
		f.mustBind(bobScope, bobStore)
		f.mustRef(bobScope, "OPENAI_API_KEY", "dev")
		// Bob is never given any membership row in f.org at all — not even
		// at his own personal scope, which never has one.
		tc := tenancy.Context{Org: f.org.ID, Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: bob.ID}}
		_, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "OPENAI_API_KEY")
		if err == nil {
			t.Fatal("resolved a personal secret for a user with no org membership at all — context gate did not deny")
		}
		classAppErr(t, err, apperr.ClassSecretNotFound)

		// Oracle check: Carol, same shape of context (org only, no
		// membership at all), but her own personal scope never defines
		// "OPENAI_API_KEY" at all. The gate must deny both identically —
		// Bob's actual (but unreachable) secret must not be distinguishable
		// from Carol's secret that simply does not exist.
		carol := f.mustUser("Carol")
		undefinedTC := tenancy.Context{Org: f.org.ID, Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: carol.ID}}
		_, wantErr := ResolveAuthorized(f.ctx, f.rp, f.ir, undefinedTC, "OPENAI_API_KEY")
		if wantErr == nil || err.Error() != wantErr.Error() {
			t.Fatalf("no-membership error %q, want byte-identical to the undefined-name control %q", err, wantErr)
		}
	})
}

// TestResolveAuthorized_MultiLevelExistenceOracle closes the finding
// filed against this card (Mesh #b460ee1d): a name defined at a level of
// tc's chain the principal cannot reach must never be distinguishable,
// through ResolveAuthorized's success/failure, from that name not being
// defined anywhere at all. principalCanReachContext (the context gate in
// ResolveAuthorized) denies the whole request up front — a "context
// reachable?" decision, made before Resolve ever runs — whenever the
// principal lacks identity.PermReadMetadata at ANY non-user level tc
// itself names (org, and workspace/project when set). See
// principalCanReachContext's own doc for why the per-scope check that
// runs after Resolve is intentionally left without its own mutation: every
// scope Resolve can return is already one the gate cleared.
func TestResolveAuthorized_MultiLevelExistenceOracle(t *testing.T) {
	t.Run("a: role at every level tc names — org-level definition resolves", func(t *testing.T) {
		f := newFixture(t)
		f.mustBind(tenancy.Org(f.org.ID), f.mustStore("builtin", tenancy.Org(f.org.ID)))
		ws := f.mustWorkspace("ws")
		proj := f.mustProject(ws, "proj")
		alice := f.mustUser("Alice")
		f.setMembership(alice, tenancy.Org(f.org.ID), identity.RoleViewer)
		f.setMembership(alice, tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}, identity.RoleViewer)
		f.setMembership(alice, tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID}, identity.RoleViewer)
		f.mustRef(tenancy.Org(f.org.ID), "NAME", "dev")

		tc := tenancy.Context{
			Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
			Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: alice.ID},
		}
		if _, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "NAME"); err != nil {
			t.Fatalf("role at every level tc names should resolve an org-level definition: %v", err)
		}
	})

	t.Run("b: role only in org, context org/ws/proj — secret_not_found, unchanged by a project-level definition appearing", func(t *testing.T) {
		f := newFixture(t)
		f.mustBind(tenancy.Org(f.org.ID), f.mustStore("builtin", tenancy.Org(f.org.ID)))
		ws := f.mustWorkspace("ws")
		proj := f.mustProject(ws, "proj")
		alice := f.mustUser("Alice")
		// Alice has a role at org level only — nowhere in ws/proj.
		f.setMembership(alice, tenancy.Org(f.org.ID), identity.RoleViewer)
		// NAME is already defined where Alice DOES have a role. Without the
		// context gate, Resolve's bottom-up search would find it here and
		// the post-Resolve check alone would let it through (Alice has
		// PermReadMetadata at org) — this is what makes the gate itself,
		// not just defense-in-depth, necessary for this scenario.
		f.mustRef(tenancy.Org(f.org.ID), "NAME", "dev")

		tc := tenancy.Context{
			Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
			Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: alice.ID},
		}

		_, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "NAME")
		if err == nil {
			t.Fatal("resolved with no role in ws/proj (though org — where NAME lives — grants one) — context gate did not deny")
		}
		classAppErr(t, err, apperr.ClassSecretNotFound)

		// The SAME name now ALSO appears at project level — a scope Alice
		// has no role in at all, and one Resolve's bottom-up search reaches
		// before org. If the gate only checked the scope Resolve happened
		// to return, this flips which definition backs the (still denied)
		// answer — an oracle a sufficiently sensitive difference in the
		// error could reveal. The context gate already denied above before
		// Resolve ever ran, so this must produce the exact same text again.
		projScope := tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID}
		f.mustRef(projScope, "NAME", "dev")
		errAfter, err2 := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "NAME")
		if err2 == nil {
			t.Fatalf("a project-level definition Alice cannot see flipped a denied resolve to success (%v) — existence oracle", errAfter)
		}
		classAppErr(t, err2, apperr.ClassSecretNotFound)
		if err.Error() != err2.Error() {
			t.Fatalf("denial before the project-level definition %q, want byte-identical to denial after %q", err, err2)
		}
	})

	t.Run("c: agent version of b — sponsor role only in org", func(t *testing.T) {
		f := newFixture(t)
		f.mustBind(tenancy.Org(f.org.ID), f.mustStore("builtin", tenancy.Org(f.org.ID)))
		ws := f.mustWorkspace("ws")
		proj := f.mustProject(ws, "proj")
		grace := f.mustUser("Grace")
		hermes := f.mustAgent(grace, "Hermes")
		f.setMembership(grace, tenancy.Org(f.org.ID), identity.RoleViewer)
		f.setAgentGrants(hermes) // none — defaults only
		// See b's fixture comment: NAME already lives where the sponsor
		// does have a role, so only the context gate — not the
		// post-Resolve check alone — can deny this.
		f.mustRef(tenancy.Org(f.org.ID), "NAME", "dev")

		tc := tenancy.Context{
			Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
			Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: hermes.ID, SponsorUserID: grace.ID},
		}

		_, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "NAME")
		if err == nil {
			t.Fatal("agent resolved with its sponsor holding no role in ws/proj (though org — where NAME lives — grants one) — context gate did not deny")
		}
		classAppErr(t, err, apperr.ClassSecretNotFound)

		projScope := tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID}
		f.mustRef(projScope, "NAME", "dev")
		_, err2 := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "NAME")
		if err2 == nil {
			t.Fatal("a project-level definition the sponsor cannot see let the agent resolve — existence oracle")
		}
		classAppErr(t, err2, apperr.ClassSecretNotFound)
		if err.Error() != err2.Error() {
			t.Fatalf("denial before the project-level definition %q, want byte-identical to denial after %q", err, err2)
		}
	})

	t.Run("d: role in org and proj, none in ws — secret_not_found", func(t *testing.T) {
		f := newFixture(t)
		f.mustBind(tenancy.Org(f.org.ID), f.mustStore("builtin", tenancy.Org(f.org.ID)))
		ws := f.mustWorkspace("ws")
		proj := f.mustProject(ws, "proj")
		alice := f.mustUser("Alice")
		f.setMembership(alice, tenancy.Org(f.org.ID), identity.RoleViewer)
		f.setMembership(alice, tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID}, identity.RoleViewer)
		// No membership at ws at all.
		f.mustRef(tenancy.Org(f.org.ID), "NAME", "dev")

		tc := tenancy.Context{
			Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
			Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: alice.ID},
		}
		_, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "NAME")
		if err == nil {
			t.Fatal("resolved with no role at ws, though org and proj both have one — context gate must check every named level, not just some")
		}
		classAppErr(t, err, apperr.ClassSecretNotFound)
	})

	t.Run("e: context is only org (ws/proj unset in tc) — gate checks only the levels tc actually names", func(t *testing.T) {
		f := newFixture(t)
		f.mustBind(tenancy.Org(f.org.ID), f.mustStore("builtin", tenancy.Org(f.org.ID)))
		alice := f.mustUser("Alice")
		f.setMembership(alice, tenancy.Org(f.org.ID), identity.RoleViewer)
		f.mustRef(tenancy.Org(f.org.ID), "NAME", "dev")

		tc := tenancy.Context{Org: f.org.ID, Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: alice.ID}}
		got, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "NAME")
		if err != nil {
			t.Fatalf("org-only context with an org role should resolve an org-level definition: %v", err)
		}
		if got.Name != "NAME" {
			t.Fatalf("resolved %+v, want NAME", got)
		}
	})
}

// TestResolveAuthorized_ServiceNeverResolves documents a deliberate,
// fail-closed choice rather than a silent one: the tenancy model defines a
// rights algorithm for a user and (through its sponsor) for an agent, §4,
// but none at all for a service. Until that is designed, ResolveAuthorized
// must refuse a service outright rather than default to allow.
func TestResolveAuthorized_ServiceNeverResolves(t *testing.T) {
	f := newFixture(t)
	f.mustBind(tenancy.Org(f.org.ID), f.mustStore("builtin", tenancy.Org(f.org.ID)))
	ws := f.mustWorkspace("ws")
	scope := tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}
	f.mustRef(scope, "SHARED_NAME", "dev")

	tc := tenancy.Context{
		Org: f.org.ID, Workspace: ws.ID,
		Principal: tenancy.Principal{Kind: tenancy.PrincipalService, ID: uuid.Must(uuid.NewV7())},
	}
	_, err := ResolveAuthorized(f.ctx, f.rp, f.ir, tc, "SHARED_NAME")
	if err == nil {
		t.Fatal("service resolved a secret despite no rights model existing for services yet")
	}
	classAppErr(t, err, apperr.ClassSecretNotFound)

	// Oracle check: same name, same checked-levels shape, a workspace where
	// "SHARED_NAME" is never defined — must be byte-identical.
	ws2 := f.mustWorkspace("ws-undefined-service")
	undefinedTC := tenancy.Context{
		Org: f.org.ID, Workspace: ws2.ID,
		Principal: tenancy.Principal{Kind: tenancy.PrincipalService, ID: tc.Principal.ID},
	}
	_, wantFromAuthorized := ResolveAuthorized(f.ctx, f.rp, f.ir, undefinedTC, "SHARED_NAME")
	if wantFromAuthorized == nil || err.Error() != wantFromAuthorized.Error() {
		t.Fatalf("service denial error %q, want byte-identical to undefined-name error %q", err, wantFromAuthorized)
	}
	_, wantFromResolve := f.rp.Resolve(f.ctx, undefinedTC, "SHARED_NAME")
	if wantFromResolve == nil || err.Error() != wantFromResolve.Error() {
		t.Fatalf("service denial error %q, want byte-identical to bare Resolve's undefined-name error %q", err, wantFromResolve)
	}
}
