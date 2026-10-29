// Table tests for the tenancy model's scenarios C1-C5, one t.Run per
// scenario. C6 (key level) belongs to internal/builtin/sealer, not this
// package.
//
// Every scenario here exercises internal/tenancy.Resolve and
// internal/catalog.CreateRef/ResolveStore together against a real
// PostgreSQL database. The two packages' own boundary is respected: these
// tests assert what Resolve/CreateRef actually decide (which definition
// wins, which store a new secret lands in, whether a lock blocks it), not
// rights enforcement — that is authz_test.go's job, against
// [ResolveAuthorized].
package catalog

import (
	"context"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fixture bundles a Repo+Catalog+identity.Repo trio over one shared pool,
// plus the org every scenario below creates first — every table in the
// schema requires one. pool itself is kept too: authz_test.go's
// membership/grant helpers need raw SQL that neither Repo exposes (there is
// no UpdateMembership/DeleteMembership — see tenancy.Repo.CreateMembership's
// doc).
type fixture struct {
	t    *testing.T
	ctx  context.Context
	pool *pgxpool.Pool
	rp   *tenancy.Repo
	cat  *Catalog
	ir   *identity.Repo
	org  tenancy.Organization
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := testPool(t)
	f := &fixture{
		t:    t,
		ctx:  context.Background(),
		pool: pool,
		rp:   tenancy.New(pool),
		cat:  New(pool),
		ir:   identity.NewRepo(pool),
	}
	// Subtest paths can exceed the metadata limit; this label is not a test ID.
	org, err := f.rp.CreateOrganization(f.ctx, "catalog fixture", "")
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	f.org = org
	return f
}

func (f *fixture) mustWorkspace(name string) tenancy.Workspace {
	f.t.Helper()
	ws, err := f.rp.CreateWorkspace(f.ctx, f.org.ID, name)
	if err != nil {
		f.t.Fatalf("create workspace %s: %v", name, err)
	}
	return ws
}

func (f *fixture) mustProject(ws tenancy.Workspace, name string) tenancy.Project {
	f.t.Helper()
	p, err := f.rp.CreateProject(f.ctx, f.org.ID, ws.ID, name)
	if err != nil {
		f.t.Fatalf("create project %s: %v", name, err)
	}
	return p
}

func (f *fixture) mustUser(name string) tenancy.User {
	f.t.Helper()
	u, err := f.rp.CreateUser(f.ctx, f.org.ID, strings.ToLower(name)+"@example.test")
	if err != nil {
		f.t.Fatalf("create user %s: %v", name, err)
	}
	return u
}

func (f *fixture) mustAgent(sponsor tenancy.User, name string) tenancy.Agent {
	f.t.Helper()
	a, err := f.rp.CreateAgent(f.ctx, f.org.ID, sponsor.ID, name)
	if err != nil {
		f.t.Fatalf("create agent %s: %v", name, err)
	}
	return a
}

func (f *fixture) mustStore(name string, owner tenancy.Scope) Store {
	f.t.Helper()
	s, err := f.cat.CreateStore(f.ctx, f.org.ID, "builtin", name, owner)
	if err != nil {
		f.t.Fatalf("create store %s: %v", name, err)
	}
	return s
}

// mustExternalStore supports catalog tests that need several stores at one
// owner scope without violating the built-in namespace invariant.
func (f *fixture) mustExternalStore(name string, owner tenancy.Scope) Store {
	f.t.Helper()
	s, err := f.cat.CreateStore(f.ctx, f.org.ID, "vault", name, owner)
	if err != nil {
		f.t.Fatalf("create external store: %v", err)
	}
	return s
}

func (f *fixture) mustBind(scope tenancy.Scope, store Store) {
	f.t.Helper()
	if _, err := f.cat.CreateStoreBinding(f.ctx, f.org.ID, scope, store.ID); err != nil {
		f.t.Fatalf("bind store at %v: %v", scope, err)
	}
}

func (f *fixture) mustRef(scope tenancy.Scope, name, class string) tenancy.SecretRef {
	f.t.Helper()
	s, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: scope, Name: name, Class: class, Type: "generic", ProviderRef: "ref:" + name,
	})
	if err != nil {
		f.t.Fatalf("create ref %s at %v: %v", name, scope, err)
	}
	return s
}

func classAppErr(t *testing.T, err error, want apperr.Class) {
	t.Helper()
	var ae *apperr.Error
	if !isAppErr(err, &ae) {
		t.Fatalf("error %v is not an *apperr.Error", err)
	}
	if ae.Class != want {
		t.Fatalf("error class = %q, want %q (message: %s)", ae.Class, want, ae.Message)
	}
}

func isAppErr(err error, target **apperr.Error) bool {
	ae, ok := err.(*apperr.Error)
	if ok {
		*target = ae
	}
	return ok
}

// C1. One org, one store shared by the whole tenant.
func scenarioC1OneOrgStore(t *testing.T) {
	f := newFixture(t)
	orgScope := tenancy.Org(f.org.ID)

	store := f.mustStore("evc-builtin", orgScope)
	f.mustBind(orgScope, store)
	if _, err := f.cat.CreateOverrideLock(f.ctx, f.org.ID, orgScope, ModeClass, "", "prod", nil); err != nil {
		t.Fatalf("lock prod at org: %v", err)
	}
	orgSecret := f.mustRef(orgScope, "PLATFORM_API_KEY", "prod")

	ws := f.mustWorkspace("main")
	proj := f.mustProject(ws, "ops")
	grace := f.mustUser("Grace")
	hermes := f.mustAgent(grace, "Hermes")

	tc := tenancy.Context{
		Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
		Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: hermes.ID, SponsorUserID: grace.ID},
	}
	got, err := f.rp.Resolve(f.ctx, tc, "PLATFORM_API_KEY")
	if err != nil {
		t.Fatalf("resolve PLATFORM_API_KEY for Hermes: %v", err)
	}
	if got.ID != orgSecret.ID {
		t.Fatalf("resolved secret id = %v, want the org-level one %v", got.ID, orgSecret.ID)
	}

	// Any user's attempt to create PLATFORM_API_KEY (class prod) at ws:main or
	// proj:ops is rejected override_locked.
	if _, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID},
		Name: "PLATFORM_API_KEY", Class: "prod", Type: "generic", ProviderRef: "x",
	}); err == nil {
		t.Fatal("expected creating PLATFORM_API_KEY (class prod) at ws:main to be override_locked, but it succeeded")
	} else {
		classAppErr(t, err, apperr.ClassOverrideLocked)
	}
	if _, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID},
		Name: "PLATFORM_API_KEY", Class: "prod", Type: "generic", ProviderRef: "x",
	}); err == nil {
		t.Fatal("expected creating PLATFORM_API_KEY (class prod) at proj:ops to be override_locked, but it succeeded")
	} else {
		classAppErr(t, err, apperr.ClassOverrideLocked)
	}
}

// C2. Two users share a project, each with their own store.
func scenarioC2PerUserStoreOnSharedProject(t *testing.T) {
	f := newFixture(t)
	ws := f.mustWorkspace("ws")
	proj := f.mustProject(ws, "shop")

	alice := f.mustUser("Alice")
	bob := f.mustUser("Bob")
	aliceStore := f.mustStore("alice-1password", tenancy.Scope{Level: tenancy.LevelUser, ID: alice.ID})
	bobStore := f.mustStore("bob-builtin", tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID})
	f.mustBind(tenancy.Scope{Level: tenancy.LevelUser, ID: alice.ID}, aliceStore)
	f.mustBind(tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID}, bobStore)

	aliceSecret := f.mustRef(tenancy.Scope{Level: tenancy.LevelUser, ID: alice.ID}, "OPENAI_API_KEY", "dev")
	bobSecret := f.mustRef(tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID}, "OPENAI_API_KEY", "dev")
	if aliceSecret.StoreID != aliceStore.ID {
		t.Fatalf("Alice's secret landed in store %v, want her own %v", aliceSecret.StoreID, aliceStore.ID)
	}
	if bobSecret.StoreID != bobStore.ID {
		t.Fatalf("Bob's secret landed in store %v, want his own %v", bobSecret.StoreID, bobStore.ID)
	}

	a1 := f.mustAgent(alice, "A1")
	b1 := f.mustAgent(bob, "B1")

	a1ctx := tenancy.Context{Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
		Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: a1.ID, SponsorUserID: alice.ID}}
	b1ctx := tenancy.Context{Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
		Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: b1.ID, SponsorUserID: bob.ID}}

	gotA, err := f.rp.Resolve(f.ctx, a1ctx, "OPENAI_API_KEY")
	if err != nil {
		t.Fatalf("A1 resolve: %v", err)
	}
	if gotA.ID != aliceSecret.ID {
		t.Fatalf("A1 resolved %v, want Alice's own %v", gotA.ID, aliceSecret.ID)
	}
	gotB, err := f.rp.Resolve(f.ctx, b1ctx, "OPENAI_API_KEY")
	if err != nil {
		t.Fatalf("B1 resolve: %v", err)
	}
	if gotB.ID != bobSecret.ID {
		t.Fatalf("B1 resolved %v, want Bob's own %v", gotB.ID, bobSecret.ID)
	}

	// A1 cannot reference user:Bob/OPENAI_API_KEY either by name or by id
	// (secret_not_found, not forbidden — no oracle).
	// By name: A1's own chain (user:Alice, not user:Bob) never reaches
	// Bob's definition — already proven above (gotA == Alice's secret).
	// By id: Meta with A1's reachable-scope set (its own chain) must not
	// resolve Bob's secret id, and must fail exactly like a nonexistent id.
	reachable := []tenancy.Scope{
		{Level: tenancy.LevelUser, ID: alice.ID},
		{Level: tenancy.LevelProject, ID: proj.ID},
		{Level: tenancy.LevelWorkspace, ID: ws.ID},
		tenancy.Org(f.org.ID),
	}
	_, errByID := f.cat.Meta(f.ctx, f.org.ID, bobSecret.ID, reachable)
	if errByID == nil {
		t.Fatal("expected Meta(bobSecret.ID, Alice's reachable set) to fail, but it succeeded")
	}
	nonexistentID := uuid.Must(uuid.NewV7())
	_, errNoSuchID := f.cat.Meta(f.ctx, f.org.ID, nonexistentID, reachable)
	if errNoSuchID == nil {
		t.Fatal("expected Meta(nonexistent id) to fail")
	}
	// The two ids differ (bobSecret.ID vs a freshly random one) and the
	// error text echoes back whichever id the caller itself supplied — that
	// is not new information, the caller already had it — so the oracle
	// check is that BOTH follow the exact same "secret %s not found"
	// template, not that the two full strings are byte-identical.
	wantByID := "secret " + bobSecret.ID.String() + " not found"
	wantNoSuch := "secret " + nonexistentID.String() + " not found"
	if errByID.Error() != wantByID {
		t.Fatalf("'exists but unreachable' error = %q, want template %q", errByID, wantByID)
	}
	if errNoSuchID.Error() != wantNoSuch {
		t.Fatalf("'does not exist' error = %q, want template %q", errNoSuchID, wantNoSuch)
	}
	classAppErr(t, errByID, apperr.ClassSecretNotFound)
	classAppErr(t, errNoSuchID, apperr.ClassSecretNotFound)

	// If the project defines proj:shop/DB_PASSWORD, the error is
	// no_store_bound — a user's own store is never used implicitly for a
	// project-scoped secret.
	_, err = f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID},
		Name: "DB_PASSWORD", Class: "dev", Type: "generic", ProviderRef: "x",
	})
	if err == nil {
		t.Fatal("expected creating proj:shop/DB_PASSWORD with no store binding anywhere above it to fail with no_store_bound")
	}
	classAppErr(t, err, apperr.ClassNoStoreBound)
}

// C3. An agent spans two workspaces.
func scenarioC3AgentInTwoWorkspaces(t *testing.T) {
	f := newFixture(t)
	main := f.mustWorkspace("main")
	lab := f.mustWorkspace("lab")

	orgScope := tenancy.Org(f.org.ID)
	store := f.mustStore("s", orgScope)
	f.mustBind(orgScope, store)

	mainToken := f.mustRef(tenancy.Scope{Level: tenancy.LevelWorkspace, ID: main.ID}, "DEPLOY_TOKEN", "dev")
	labToken := f.mustRef(tenancy.Scope{Level: tenancy.LevelWorkspace, ID: lab.ID}, "DEPLOY_TOKEN", "dev")

	grace := f.mustUser("Grace")
	orion := f.mustAgent(grace, "Orion")

	// Orion deploys DEPLOY_TOKEN to host-x in context (org, lab): resolves to
	// ws:lab/DEPLOY_TOKEN, never ws:main's.
	labCtx := tenancy.Context{Org: f.org.ID, Workspace: lab.ID,
		Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: orion.ID, SponsorUserID: grace.ID}}
	got, err := f.rp.Resolve(f.ctx, labCtx, "DEPLOY_TOKEN")
	if err != nil {
		t.Fatalf("resolve in ws:lab: %v", err)
	}
	if got.ID != labToken.ID {
		t.Fatalf("resolved %v, want ws:lab's token %v (never ws:main's %v)", got.ID, labToken.ID, mainToken.ID)
	}

	// A request with no workspace specified, while the principal belongs to
	// two, is ambiguous_context. Orion's membership comes from Grace (the
	// sponsor) — give Grace membership rows in both workspaces so the
	// C3-specific ambiguity check (distinctScopeIDs on the effective user)
	// has something to find.
	if _, err := f.rp.CreateMembership(f.ctx, f.org.ID, grace.ID,
		tenancy.Scope{Level: tenancy.LevelWorkspace, ID: main.ID}, "member"); err != nil {
		t.Fatalf("grant Grace membership in ws:main: %v", err)
	}
	if _, err := f.rp.CreateMembership(f.ctx, f.org.ID, grace.ID,
		tenancy.Scope{Level: tenancy.LevelWorkspace, ID: lab.ID}, "member"); err != nil {
		t.Fatalf("grant Grace membership in ws:lab: %v", err)
	}
	noWSCtx := tenancy.Context{Org: f.org.ID,
		Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: orion.ID, SponsorUserID: grace.ID}}
	_, err = f.rp.Resolve(f.ctx, noWSCtx, "DEPLOY_TOKEN")
	if err == nil {
		t.Fatal("expected resolve with no workspace, sponsor member of two, to fail ambiguous_context")
	}
	classAppErr(t, err, apperr.ClassAmbiguousContext)
}

// C4. A user leaves — the subset of §6 this package's own boundary covers
// (carriers, orphan alerts and runner cert revocation belong to later work;
// Resolve's doc lists what it leaves to the rights layer). What Resolve
// itself must do: an agent sponsored by a user whose org-wide status is no
// longer "active" resolves nothing, fail-closed, immediately (§6 point 1:
// agents sponsored by a removed user lose access immediately).
func scenarioC4SponsorRemovedAgentFailsClosed(t *testing.T) {
	f := newFixture(t)
	ws := f.mustWorkspace("ws")
	proj := f.mustProject(ws, "shop")
	bob := f.mustUser("Bob")
	bobStore := f.mustStore("bob-builtin", tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID})
	f.mustBind(tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID}, bobStore)
	f.mustRef(tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID}, "OPENAI_API_KEY", "dev")
	b1 := f.mustAgent(bob, "B1")

	tc := tenancy.Context{Org: f.org.ID, Workspace: ws.ID, Project: proj.ID,
		Principal: tenancy.Principal{Kind: tenancy.PrincipalAgent, ID: b1.ID, SponsorUserID: bob.ID}}

	if _, err := f.rp.Resolve(f.ctx, tc, "OPENAI_API_KEY"); err != nil {
		t.Fatalf("resolve before removal should still succeed: %v", err)
	}

	if err := f.rp.RemoveUser(f.ctx, f.org.ID, bob.ID); err != nil {
		t.Fatalf("remove Bob: %v", err)
	}

	_, err := f.rp.Resolve(f.ctx, tc, "OPENAI_API_KEY")
	if err == nil {
		t.Fatal("expected B1 to lose resolution immediately after its sponsor Bob is removed")
	}
	classAppErr(t, err, apperr.ClassSecretNotFound)
}

// C5. A forbidden override attempt.
func scenarioC5ForbiddenOverride(t *testing.T) {
	f := newFixture(t)
	orgScope := tenancy.Org(f.org.ID)
	orgStore := f.mustStore("evc-builtin", orgScope)
	f.mustBind(orgScope, orgStore)

	marco := f.mustUser("Marco")
	marcoStore := f.mustStore("marco-1password", tenancy.Scope{Level: tenancy.LevelUser, ID: marco.ID})

	if _, err := f.cat.CreateOverrideLock(f.ctx, f.org.ID, orgScope,
		ModeStore, "", "prod", []uuid.UUID{orgStore.ID}); err != nil {
		t.Fatalf("lock class=prod to store=evc-builtin at org: %v", err)
	}

	ws := f.mustWorkspace("main")
	proj := f.mustProject(ws, "ops")

	// Marco tries to create proj:ops/STRIPE_KEY (class prod) explicitly
	// into a store of his own choosing. A store that is not in the project's
	// chain at all (his personal 1Password store) is refused before the lock
	// is even consulted: a store is only usable for records in the scope
	// that owns it. The escape the lock exists for is a store that IS
	// available to the project, but is not the one class=prod is pinned to —
	// here the project's own store — and that is what override_locked stops.
	projScope := tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID}
	opsStore := f.mustStore("ops-own", projScope)
	_, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: projScope,
		Name: "STRIPE_KEY", Class: "prod", Type: "generic", ProviderRef: "x",
		StoreID: marcoStore.ID,
	})
	if err == nil {
		t.Fatal("expected a store outside the project's chain (Marco's personal store) to be refused")
	}
	classAppErr(t, err, apperr.ClassInvalidArgument)

	_, err = f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: projScope,
		Name: "STRIPE_KEY", Class: "prod", Type: "generic", ProviderRef: "x",
		StoreID: opsStore.ID,
	})
	if err == nil {
		t.Fatal("expected STRIPE_KEY (class prod) forced into a non-compliant store of the project's own chain to be override_locked")
	}
	classAppErr(t, err, apperr.ClassOverrideLocked)

	// Implicit store resolution (no StoreID given) is the OTHER half of the
	// same guarantee, not a second way to bypass it: proj:ops's own
	// ancestor walk (proj → ws → org) finds org's StoreBinding first — the
	// very store the lock names as the only allowed one for class=prod — so
	// this succeeds, landing in evc-builtin. The lock's job is to stop an
	// EXPLICIT escape to a different store (proven above); it was never
	// meant to block resolution that already complies on its own.
	implicit, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID},
		Name: "STRIPE_KEY", Class: "prod", Type: "generic", ProviderRef: "x",
	})
	if err != nil {
		t.Fatalf("implicit-store STRIPE_KEY (class prod) at proj:ops should resolve to the compliant org store, got error: %v", err)
	}
	if implicit.StoreID != orgStore.ID {
		t.Fatalf("implicit-store STRIPE_KEY landed in store %v, want the org's compliant store %v", implicit.StoreID, orgStore.ID)
	}

	// Now the case the scenario's "any user" wording is really about: even
	// a plain StoreBinding — no override attempted, no explicit StoreID — at
	// a scope BELOW the lock, if it named a non-compliant store, must not
	// let a class=prod secret land there. Bind the project's own store (a
	// legitimate binding, just one the org-level lock now forbids for this
	// class) directly at proj:ops and create without an explicit StoreID.
	// (Binding Marco's personal store there is refused outright, like an
	// explicit choice of it: see TestCreateStoreBinding_RefusesUnusableStores.)
	f.mustBind(projScope, opsStore)
	_, err = f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: tenancy.Scope{Level: tenancy.LevelProject, ID: proj.ID},
		Name: "ANOTHER_PROD_SECRET", Class: "prod", Type: "generic", ProviderRef: "x",
	})
	if err == nil {
		t.Fatal("expected a class=prod secret to be rejected when the nearest StoreBinding names a non-compliant store, even with no explicit StoreID")
	}
	classAppErr(t, err, apperr.ClassOverrideLocked)
}

// TestScenarios runs the scenarios as named subtests; each builds its own
// fixture (and so a freshly reset schema) and does not depend on the others.
func TestScenarios(t *testing.T) {
	for _, sc := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"C1_OneOrgStore", scenarioC1OneOrgStore},
		{"C2_PerUserStoreOnSharedProject", scenarioC2PerUserStoreOnSharedProject},
		{"C3_AgentInTwoWorkspaces", scenarioC3AgentInTwoWorkspaces},
		{"C4_SponsorRemovedAgentFailsClosed", scenarioC4SponsorRemovedAgentFailsClosed},
		{"C5_ForbiddenOverride", scenarioC5ForbiddenOverride},
	} {
		t.Run(sc.name, sc.run)
	}
}
