package tenancy

import (
	"context"
	"fmt"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// lockFixture is a raw-SQL fixture for Resolve's override-lock logic
// (tenancy model §3 step 2). Rows are inserted directly, bypassing
// internal/catalog (which this package must not import — see doc.go) and its
// creation-time policy: several cases below need a definition that exists
// BELOW a lock, which CreateRef would refuse to create.
type lockFixture struct {
	t     *testing.T
	pool  *pgxpool.Pool
	rp    *Repo
	org   uuid.UUID
	ws    uuid.UUID
	proj  uuid.UUID
	user  User
	store uuid.UUID
}

func newLockFixture(t *testing.T) *lockFixture {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()
	rp := New(pool)

	org, err := rp.CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	ws, err := rp.CreateWorkspace(ctx, org.ID, "ws")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	proj, err := rp.CreateProject(ctx, org.ID, ws.ID, "proj")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	user, err := rp.CreateUser(ctx, org.ID, "grace@example.test")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	f := &lockFixture{t: t, pool: pool, rp: rp, org: org.ID, ws: ws.ID, proj: proj.ID, user: user}
	f.store = uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(ctx,
		`INSERT INTO stores (id, org_id, provider, name, owner_scope_level, owner_scope_id)
		 VALUES ($1, $2, 'builtin', 's', 'org', $2)`, f.store, org.ID); err != nil {
		t.Fatalf("insert store: %v", err)
	}
	return f
}

func (f *lockFixture) secret(scope Scope, name, class string) uuid.UUID {
	f.t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO secrets (id, org_id, scope_level, scope_id, name, class, type, store_id, provider_ref)
		 VALUES ($1, $2, $3, $4, $5, $6, 'generic', $7, 'x')`,
		id, f.org, string(scope.Level), scope.ID, name, class, f.store); err != nil {
		f.t.Fatalf("insert secret %s at %s: %v", name, scope.Level, err)
	}
	return id
}

func (f *lockFixture) nameLock(scope Scope, name string) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO override_locks (id, org_id, scope_level, scope_id, selector_name, mode)
		 VALUES ($1, $2, $3, $4, $5, 'name')`,
		uuid.Must(uuid.NewV7()), f.org, string(scope.Level), scope.ID, name); err != nil {
		f.t.Fatalf("insert name lock: %v", err)
	}
}

func (f *lockFixture) classLock(scope Scope, class string) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO override_locks (id, org_id, scope_level, scope_id, selector_class, mode)
		 VALUES ($1, $2, $3, $4, $5, 'class')`,
		uuid.Must(uuid.NewV7()), f.org, string(scope.Level), scope.ID, class); err != nil {
		f.t.Fatalf("insert class lock: %v", err)
	}
}

func (f *lockFixture) resolve(name string) (SecretRef, error) {
	f.t.Helper()
	return f.rp.Resolve(context.Background(), Context{
		Org: f.org, Workspace: f.ws, Project: f.proj,
		Principal: Principal{Kind: PrincipalUser, ID: f.user.ID},
	}, name)
}

func (f *lockFixture) wantResolvesTo(name string, want uuid.UUID, why string) {
	f.t.Helper()
	got, err := f.resolve(name)
	if err != nil {
		f.t.Fatalf("resolve %s: %v (want the secret %s)", name, err, why)
	}
	if got.ID != want {
		f.t.Fatalf("resolve %s returned scope %q, want %s", name, got.Scope.Level, why)
	}
}

func (f *lockFixture) wantNotFound(name, why string) {
	f.t.Helper()
	got, err := f.resolve(name)
	if err == nil {
		f.t.Fatalf("resolve %s returned the secret at scope %q, want secret_not_found (%s)", name, got.Scope.Level, why)
	}
	ae, ok := err.(*apperr.Error)
	if !ok || ae.Class != apperr.ClassSecretNotFound {
		f.t.Fatalf("resolve %s error = %v, want class secret_not_found", name, err)
	}
}

// TestResolve_OverrideLocks pins §3 step 2 of the tenancy model: the topmost
// blocking lock in the chain restricts the bottom-up search to its own level
// and above. Every case pairs the blocking shape with a control that must NOT
// be blocked, so a Resolve that ignores locks altogether, or one that blocks
// too much, fails one of them.
func TestResolve_OverrideLocks(t *testing.T) {
	t.Run("name lock hides a lower definition", func(t *testing.T) {
		f := newLockFixture(t)
		orgScope := Org(f.org)
		atOrg := f.secret(orgScope, "LOCKED_NAME", "dev")
		f.secret(Scope{Level: LevelProject, ID: f.proj}, "LOCKED_NAME", "dev")
		f.nameLock(orgScope, "LOCKED_NAME")
		f.wantResolvesTo("LOCKED_NAME", atOrg, "the org-level one: the project definition is below the lock")

		// Control: an unlocked name defined at both levels resolves bottom-up.
		f.secret(orgScope, "OPEN_NAME", "dev")
		atProj := f.secret(Scope{Level: LevelProject, ID: f.proj}, "OPEN_NAME", "dev")
		f.wantResolvesTo("OPEN_NAME", atProj, "the project-level one: no lock covers this name")
	})

	t.Run("name lock: a definition only below the lock is ignored", func(t *testing.T) {
		f := newLockFixture(t)
		f.secret(Scope{Level: LevelProject, ID: f.proj}, "ONLY_BELOW", "dev")
		f.nameLock(Org(f.org), "ONLY_BELOW")
		f.wantNotFound("ONLY_BELOW", "the only definition is below a name lock at org")
	})

	t.Run("class lock hides a lower definition of that class", func(t *testing.T) {
		f := newLockFixture(t)
		orgScope := Org(f.org)
		atOrg := f.secret(orgScope, "PROD_KEY", "prod")
		f.secret(Scope{Level: LevelProject, ID: f.proj}, "PROD_KEY", "prod")
		f.classLock(orgScope, "prod")
		f.wantResolvesTo("PROD_KEY", atOrg, "the org-level one: the project definition is below the class lock")

		// Control: the lock is on class prod, so a dev-class name still
		// resolves bottom-up.
		f.secret(orgScope, "DEV_KEY", "dev")
		atProj := f.secret(Scope{Level: LevelProject, ID: f.proj}, "DEV_KEY", "dev")
		f.wantResolvesTo("DEV_KEY", atProj, "the project-level one: the lock covers class prod only")
	})

	t.Run("topmost of nested locks wins", func(t *testing.T) {
		f := newLockFixture(t)
		orgScope := Org(f.org)
		wsScope := Scope{Level: LevelWorkspace, ID: f.ws}
		atOrg := f.secret(orgScope, "NESTED", "dev")
		f.secret(wsScope, "NESTED", "dev")
		f.secret(Scope{Level: LevelProject, ID: f.proj}, "NESTED", "dev")
		f.nameLock(orgScope, "NESTED")
		f.nameLock(wsScope, "NESTED")
		f.wantResolvesTo("NESTED", atOrg, "the org-level one: the org lock is topmost, the ws lock cannot loosen it")
	})

	t.Run("a lock lower in the chain restricts only what is below it", func(t *testing.T) {
		f := newLockFixture(t)
		wsScope := Scope{Level: LevelWorkspace, ID: f.ws}
		atWS := f.secret(wsScope, "WS_LOCKED", "dev")
		f.secret(Scope{Level: LevelProject, ID: f.proj}, "WS_LOCKED", "dev")
		f.nameLock(wsScope, "WS_LOCKED")
		f.wantResolvesTo("WS_LOCKED", atWS, "the workspace-level one: the project definition is below the ws lock")
	})

	// tenancy model v3 §3 step 2: a class lock blocks a matching lower
	// definition even when the lock's own level defines nothing by that
	// name at all — not just when it defines the name itself, which is all
	// the "class lock hides a lower definition" case above pins (there the
	// org, the lock's own level, ALSO has a PROD_KEY of its own).
	t.Run("class lock blocks a lower definition even when its own level defines nothing by that name", func(t *testing.T) {
		f := newLockFixture(t)
		orgScope := Org(f.org)
		f.classLock(orgScope, "prod")
		// No secret named UNDEFINED_AT_LOCK exists at org at all — only in
		// the workspace, below the lock.
		f.secret(Scope{Level: LevelWorkspace, ID: f.ws}, "UNDEFINED_AT_LOCK", "prod")
		f.wantNotFound("UNDEFINED_AT_LOCK", "the only definition is below an org class=prod lock, and its class matches")

		// Same shape of text as a name that was never defined at all (§3
		// step 4 / TestResolve_NotFoundTextIsContextOnly): the message
		// names only UNDEFINED_AT_LOCK and the request's own levels — the
		// exact template an undefined name gets, nothing about the lock
		// that actually did the blocking.
		blocked, err := f.resolve("UNDEFINED_AT_LOCK")
		if err == nil {
			f.t.Fatalf("resolve UNDEFINED_AT_LOCK returned scope %q, want secret_not_found", blocked.Scope.Level)
		}
		wantText := `secret "UNDEFINED_AT_LOCK" not found (checked: org, ws, proj, user)`
		if err.Error() != wantText {
			f.t.Fatalf("blocked-by-class-lock text = %q, want %q (the undefined-name template)", err.Error(), wantText)
		}

		// Control: a class=dev definition, same shape, is not covered by
		// the class=prod lock and resolves normally.
		wsScope := Scope{Level: LevelWorkspace, ID: f.ws}
		atWS := f.secret(wsScope, "OPEN_CLASS", "dev")
		f.wantResolvesTo("OPEN_CLASS", atWS, "the workspace-level one: the lock covers class prod only")
	})
}

// TestResolve_NotFoundTextIsContextOnly pins §3 step 4: the text of
// secret_not_found is a function of the name and the request's own context
// and of nothing else. A name under an OverrideLock, a name defined only
// below that lock, and an agent whose sponsor has been removed must each
// read exactly like a name that is defined nowhere; otherwise probing names
// would list the locked ones, and the message would announce that a sponsor
// has left.
func TestResolve_NotFoundTextIsContextOnly(t *testing.T) {
	f := newLockFixture(t)
	ctx := context.Background()

	// LOCKED: locked at the org, and defined BELOW the lock (workspace),
	// where the lock hides it. DEFINED_ORG: an ordinary org definition.
	f.nameLock(Org(f.org), "LOCKED")
	f.secret(Scope{Level: LevelWorkspace, ID: f.ws}, "LOCKED", "dev")
	f.secret(Org(f.org), "DEFINED_ORG", "dev")

	want := func(name, checked string) string {
		return fmt.Sprintf("secret %q not found (checked: %s)", name, checked)
	}
	userCtx := Context{Org: f.org, Workspace: f.ws, Project: f.proj, Principal: Principal{Kind: PrincipalUser, ID: f.user.ID}}
	notFound := func(tc Context, name string) string {
		t.Helper()
		_, err := f.rp.Resolve(ctx, tc, name)
		ae, ok := err.(*apperr.Error)
		if !ok || ae.Class != apperr.ClassSecretNotFound {
			t.Fatalf("Resolve(%s) = %v, want a secret_not_found error", name, err)
		}
		return err.Error()
	}

	t.Run("user: locked name reads like an undefined one", func(t *testing.T) {
		// Positive control: the same lock does hide LOCKED (it is not found
		// because of the lock, not because nothing was defined) while the
		// unlocked definition resolves.
		if _, err := f.rp.Resolve(ctx, userCtx, "DEFINED_ORG"); err != nil {
			t.Fatalf("control: DEFINED_ORG must resolve: %v", err)
		}
		locked := notFound(userCtx, "LOCKED")
		undefined := notFound(userCtx, "NEVER_DEFINED")
		if locked != want("LOCKED", "org, ws, proj, user") {
			t.Fatalf("locked-name error = %q, want the request's own levels", locked)
		}
		if undefined != want("NEVER_DEFINED", "org, ws, proj, user") {
			t.Fatalf("undefined-name error = %q", undefined)
		}
	})

	t.Run("service: no user level, locked or not", func(t *testing.T) {
		svc := Context{Org: f.org, Workspace: f.ws, Project: f.proj, Principal: Principal{Kind: PrincipalService, ID: uuid.Must(uuid.NewV7())}}
		if got := notFound(svc, "LOCKED"); got != want("LOCKED", "org, ws, proj") {
			t.Fatalf("service, locked name: %q", got)
		}
		if got := notFound(svc, "NEVER_DEFINED"); got != want("NEVER_DEFINED", "org, ws, proj") {
			t.Fatalf("service, undefined name: %q", got)
		}
	})

	t.Run("agent: a removed sponsor reads like an active one", func(t *testing.T) {
		agent, err := f.rp.CreateAgent(ctx, f.org, f.user.ID, "bot")
		if err != nil {
			t.Fatalf("create agent: %v", err)
		}
		agentCtx := Context{Org: f.org, Workspace: f.ws, Project: f.proj,
			Principal: Principal{Kind: PrincipalAgent, ID: agent.ID, SponsorUserID: f.user.ID}}

		// While the sponsor is active: a defined name resolves, an
		// undefined one is not found with the full context.
		if _, err := f.rp.Resolve(ctx, agentCtx, "DEFINED_ORG"); err != nil {
			t.Fatalf("control: an active sponsor's agent must resolve DEFINED_ORG: %v", err)
		}
		activeUndefined := notFound(agentCtx, "NEVER_DEFINED")

		if err := f.rp.RemoveUser(ctx, f.org, f.user.ID); err != nil {
			t.Fatalf("remove sponsor: %v", err)
		}
		// Now every name fails closed, defined or not, and all of them read
		// exactly like the undefined one did.
		for _, name := range []string{"DEFINED_ORG", "LOCKED", "NEVER_DEFINED"} {
			if got := notFound(agentCtx, name); got != want(name, "org, ws, proj, user") {
				t.Fatalf("removed sponsor, %s: %q, want the same text as an active sponsor's undefined name (%q)", name, got, activeUndefined)
			}
		}
	})
}

// A lock below the org (workspace or project level) must not shape the
// not-found text either: the message names the request's levels, however
// deep the lock that hid the name sits.
func TestResolve_NotFoundTextIgnoresLockDepth(t *testing.T) {
	f := newLockFixture(t)
	ctx := context.Background()
	f.nameLock(Scope{Level: LevelWorkspace, ID: f.ws}, "LOCKED_WS")
	f.secret(Scope{Level: LevelProject, ID: f.proj}, "LOCKED_WS", "dev")
	f.nameLock(Scope{Level: LevelProject, ID: f.proj}, "LOCKED_PROJ")
	f.secret(Scope{Level: LevelUser, ID: f.user.ID}, "LOCKED_PROJ", "dev")

	userCtx := Context{Org: f.org, Workspace: f.ws, Project: f.proj, Principal: Principal{Kind: PrincipalUser, ID: f.user.ID}}
	for _, name := range []string{"LOCKED_WS", "LOCKED_PROJ", "NEVER_DEFINED"} {
		_, err := f.rp.Resolve(ctx, userCtx, name)
		want := fmt.Sprintf("secret %q not found (checked: org, ws, proj, user)", name)
		if err == nil || err.Error() != want {
			t.Errorf("Resolve(%s) = %v, want %q", name, err, want)
		}
	}
}

// An agent whose sponsor was removed must get the same answer as one whose
// sponsor is active, also when the context omits the workspace and the
// sponsor belongs to two: ambiguous_context, not secret_not_found.
func TestResolve_RemovedSponsorAgentSeesSameAmbiguity(t *testing.T) {
	f := newLockFixture(t)
	ctx := context.Background()
	ws2, err := f.rp.CreateWorkspace(ctx, f.org, "ws2")
	if err != nil {
		t.Fatalf("create second workspace: %v", err)
	}
	for _, w := range []uuid.UUID{f.ws, ws2.ID} {
		if _, err := f.rp.CreateMembership(ctx, f.org, f.user.ID, Scope{Level: LevelWorkspace, ID: w}, "member"); err != nil {
			t.Fatalf("membership: %v", err)
		}
	}
	agent, err := f.rp.CreateAgent(ctx, f.org, f.user.ID, "bot")
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	noWS := Context{Org: f.org, Principal: Principal{Kind: PrincipalAgent, ID: agent.ID, SponsorUserID: f.user.ID}}

	answer := func() string {
		_, err := f.rp.Resolve(ctx, noWS, "ANY_NAME")
		ae, ok := err.(*apperr.Error)
		if !ok || ae.Class != apperr.ClassAmbiguousContext {
			t.Fatalf("Resolve without a workspace = %v, want class ambiguous_context", err)
		}
		return err.Error()
	}
	active := answer()
	if err := f.rp.RemoveUser(ctx, f.org, f.user.ID); err != nil {
		t.Fatalf("remove sponsor: %v", err)
	}
	if removed := answer(); removed != active {
		t.Fatalf("removed sponsor's agent: %q, active sponsor's agent: %q — they must be identical", removed, active)
	}
}
