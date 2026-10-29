package catalog

import (
	"context"
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/jackc/pgx/v5"
)

// TestEveryQueryFiltersByOrg pins the org_id predicate of each catalog SQL
// query on its own. Every id in this schema is a globally unique UUIDv7, so
// a query that dropped its org_id predicate would still return the right row
// for a caller that only ever asks about its own tenant, and higher layers
// (scopeReachable in Meta, the chain walk in CreateRef) would hide the
// defect. Here org A's identity asks about org B's ids directly, handing
// every query the ids of org B's rows as if they were legitimate inputs —
// including a reachable set that names org B's scopes, so that only the
// query's own org_id predicate stands between org A and org B's rows. A
// positive control (the same call under org B's identity finds the row)
// precedes each check so an empty result is not just an empty table.
func TestEveryQueryFiltersByOrg(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	rp := tenancy.New(pool)
	cat := New(pool)

	orgA, err := rp.CreateOrganization(ctx, "org-a", "")
	if err != nil {
		t.Fatalf("create org A: %v", err)
	}
	orgB, err := rp.CreateOrganization(ctx, "org-b", "")
	if err != nil {
		t.Fatalf("create org B: %v", err)
	}
	scopeB := tenancy.Org(orgB.ID)

	wsB, err := rp.CreateWorkspace(ctx, orgB.ID, "ws")
	if err != nil {
		t.Fatalf("create workspace B: %v", err)
	}
	projB, err := rp.CreateProject(ctx, orgB.ID, wsB.ID, "proj")
	if err != nil {
		t.Fatalf("create project B: %v", err)
	}
	userB, err := rp.CreateUser(ctx, orgB.ID, "user@example.test")
	if err != nil {
		t.Fatalf("create user B: %v", err)
	}
	storeB, err := cat.CreateStore(ctx, orgB.ID, "builtin", "s", scopeB)
	if err != nil {
		t.Fatalf("create store B: %v", err)
	}
	if _, err := cat.CreateStoreBinding(ctx, orgB.ID, scopeB, storeB.ID); err != nil {
		t.Fatalf("bind store B: %v", err)
	}
	if _, err := cat.CreateOverrideLock(ctx, orgB.ID, scopeB, ModeClass, "", "prod", nil); err != nil {
		t.Fatalf("lock B: %v", err)
	}
	secretB, err := cat.CreateRef(ctx, CreateRefInput{
		Org: orgB.ID, Scope: scopeB, Name: "SECRET_B", Class: "dev", Type: "generic", ProviderRef: "b",
	})
	if err != nil {
		t.Fatalf("create secret B: %v", err)
	}
	if _, err := cat.AddVersion(ctx, orgB.ID, secretB.ID, "v1", "kfp1:test:AAAAAAAAAA", 8); err != nil {
		t.Fatalf("add version B: %v", err)
	}

	wsScopeB := tenancy.Scope{Level: tenancy.LevelWorkspace, ID: wsB.ID}
	projScopeB := tenancy.Scope{Level: tenancy.LevelProject, ID: projB.ID}
	userScopeB := tenancy.Scope{Level: tenancy.LevelUser, ID: userB.ID}
	reachableB := []tenancy.Scope{scopeB, wsScopeB, projScopeB, userScopeB}

	t.Run("Meta", func(t *testing.T) {
		if _, err := cat.Meta(ctx, orgB.ID, secretB.ID, reachableB); err != nil {
			t.Fatalf("positive control: Meta under org B failed: %v", err)
		}
		_, err := cat.Meta(ctx, orgA.ID, secretB.ID, reachableB)
		if err == nil {
			t.Fatal("Meta under org A's identity returned org B's secret: org_id predicate missing")
		}
		classAppErr(t, err, apperr.ClassSecretNotFound)
	})

	t.Run("List", func(t *testing.T) {
		if got, err := cat.List(ctx, orgB.ID, scopeB); err != nil || len(got) != 1 {
			t.Fatalf("positive control: List under org B = %v, %v; want one row", got, err)
		}
		got, err := cat.List(ctx, orgA.ID, scopeB)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("List under org A's identity returned %d of org B's rows: org_id predicate missing", len(got))
		}
	})

	t.Run("ListVersions", func(t *testing.T) {
		if got, err := cat.ListVersions(ctx, orgB.ID, secretB.ID); err != nil || len(got) != 1 {
			t.Fatalf("positive control: ListVersions under org B = %v, %v; want one row", got, err)
		}
		got, err := cat.ListVersions(ctx, orgA.ID, secretB.ID)
		if err != nil {
			t.Fatalf("ListVersions: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("ListVersions under org A's identity returned %d of org B's rows: org_id predicate missing", len(got))
		}
	})

	t.Run("AncestorChain", func(t *testing.T) {
		for _, sc := range []tenancy.Scope{wsScopeB, projScopeB, userScopeB} {
			if _, err := cat.AncestorChain(ctx, orgB.ID, sc); err != nil {
				t.Fatalf("positive control: AncestorChain(%s) under org B failed: %v", sc.Level, err)
			}
			if chain, err := cat.AncestorChain(ctx, orgA.ID, sc); err == nil {
				t.Errorf("AncestorChain(%s) under org A's identity accepted org B's scope (chain %v): org_id predicate missing", sc.Level, chain)
			}
		}
	})

	t.Run("storeBindingAt", func(t *testing.T) {
		if _, ok, err := storeBindingAt(ctx, cat.pool, orgB.ID, scopeB); err != nil || !ok {
			t.Fatalf("positive control: storeBindingAt under org B = %v, %v; want a binding", ok, err)
		}
		_, ok, err := storeBindingAt(ctx, cat.pool, orgA.ID, scopeB)
		if err != nil {
			t.Fatalf("storeBindingAt: %v", err)
		}
		if ok {
			t.Fatal("storeBindingAt under org A's identity found org B's binding: org_id predicate missing")
		}
	})

	t.Run("locksAt", func(t *testing.T) {
		if got, err := locksAt(ctx, cat.pool, orgB.ID, scopeB); err != nil || len(got) != 1 {
			t.Fatalf("positive control: locksAt under org B = %v, %v; want one lock", got, err)
		}
		got, err := locksAt(ctx, cat.pool, orgA.ID, scopeB)
		if err != nil {
			t.Fatalf("locksAt: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("locksAt under org A's identity returned %d of org B's locks: org_id predicate missing", len(got))
		}
	})

	t.Run("GetStore", func(t *testing.T) {
		if _, err := cat.GetStore(ctx, orgB.ID, storeB.ID); err != nil {
			t.Fatalf("positive control: GetStore under org B: %v", err)
		}
		_, err := cat.GetStore(ctx, orgA.ID, storeB.ID)
		if err == nil {
			t.Fatal("GetStore under org A's identity returned org B's store: org_id predicate missing")
		}
		// GetStore's id is never caller-supplied (see its own doc) — org A
		// finding nothing here reads exactly like the store row this org's own
		// secret pointed to having vanished, an unclassified internal error,
		// not the caller-input apperr.ClassInvalidArgument an explicitly named
		// store id at bind time would get (see storeNotUsableError's callers).
		var ae *apperr.Error
		if isAppErr(err, &ae) {
			t.Fatalf("GetStore across orgs returned an *apperr.Error (class %q) — it must stay unclassified, see GetStore's own doc", ae.Class)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("GetStore across orgs did not wrap pgx.ErrNoRows: %v", err)
		}
	})

	t.Run("requireUsableStore", func(t *testing.T) {
		if err := requireUsableStore(ctx, cat.pool, orgB.ID, []tenancy.Scope{scopeB}, storeB.ID); err != nil {
			t.Fatalf("positive control: org B's store under org B: %v", err)
		}
		// Org A's identity, handed org B's store id and a chain that names
		// org B's owner scope: only the query's own predicate refuses it.
		err := requireUsableStore(ctx, cat.pool, orgA.ID, []tenancy.Scope{scopeB}, storeB.ID)
		if err == nil {
			t.Fatal("requireUsableStore under org A's identity accepted org B's store: org_id predicate missing")
		}
		classAppErr(t, err, apperr.ClassInvalidArgument)
	})
}
