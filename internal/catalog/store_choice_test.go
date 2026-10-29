package catalog

import (
	"context"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// TestCreateRef_ExplicitStore pins the rule for a caller-chosen store: it
// must be active and owned by a scope in the target scope's chain. A store
// belongs to its owning scope (tenancy model section 3), so another user's
// personal store, a store of a sibling workspace, a disabled store, another
// organisation's store and an id that names nothing are all refused, and all
// with one and the same error.
func TestCreateRef_ExplicitStore(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	rp := tenancy.New(pool)
	cat := New(pool)

	org, err := rp.CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	other, err := rp.CreateOrganization(ctx, t.Name()+"-other", "")
	if err != nil {
		t.Fatalf("create other org: %v", err)
	}
	orgScope := tenancy.Org(org.ID)
	ws := mustCreateWorkspace(t, rp, ctx, org.ID, "ws")
	wsSibling := mustCreateWorkspace(t, rp, ctx, org.ID, "ws-sibling")
	alice, err := rp.CreateUser(ctx, org.ID, "alice@example.test")
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	bob, err := rp.CreateUser(ctx, org.ID, "bob@example.test")
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}
	wsScope := tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}
	siblingScope := tenancy.Scope{Level: tenancy.LevelWorkspace, ID: wsSibling.ID}
	aliceScope := tenancy.Scope{Level: tenancy.LevelUser, ID: alice.ID}
	bobScope := tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID}

	mkStore := func(o uuid.UUID, owner tenancy.Scope, name, kind string) Store {
		t.Helper()
		s, err := cat.CreateStore(ctx, o, kind, name, owner)
		if err != nil {
			t.Fatalf("create store %s: %v", name, err)
		}
		return s
	}
	orgStore := mkStore(org.ID, orgScope, "org-store", "builtin")
	aliceStore := mkStore(org.ID, aliceScope, "alice-store", "builtin")
	siblingStore := mkStore(org.ID, siblingScope, "sibling-store", "builtin")
	disabledStore := mkStore(org.ID, orgScope, "disabled-store", "vault")
	if _, err := pool.Exec(ctx, `UPDATE stores SET status = 'disabled' WHERE id = $1`, disabledStore.ID); err != nil {
		t.Fatalf("disable store: %v", err)
	}
	otherOrgStore := mkStore(other.ID, tenancy.Org(other.ID), "other-org-store", "builtin")

	create := func(scope tenancy.Scope, name string, storeID uuid.UUID) error {
		_, err := cat.CreateRef(ctx, CreateRefInput{
			Org: org.ID, Scope: scope, Name: name, Class: "dev", Type: "generic", ProviderRef: "x", StoreID: storeID,
		})
		return err
	}

	t.Run("stores of the target scope's own chain are accepted", func(t *testing.T) {
		for _, c := range []struct {
			name  string
			scope tenancy.Scope
			store uuid.UUID
		}{
			{"org store into a workspace", wsScope, orgStore.ID},
			{"org store into a user scope", bobScope, orgStore.ID},
			{"a user's own store into their scope", aliceScope, aliceStore.ID},
			{"a workspace's own store into it", siblingScope, siblingStore.ID},
		} {
			if err := create(c.scope, "OK_"+c.name, c.store); err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
			}
		}
	})

	t.Run("every other store is refused with one identical error", func(t *testing.T) {
		var texts []string
		for _, c := range []struct {
			name  string
			scope tenancy.Scope
			store uuid.UUID
		}{
			{"another user's personal store", bobScope, aliceStore.ID},
			{"a personal store into a workspace scope", wsScope, aliceStore.ID},
			{"a sibling workspace's store", wsScope, siblingStore.ID},
			{"a disabled store", wsScope, disabledStore.ID},
			{"another organisation's store", wsScope, otherOrgStore.ID},
			{"an id that names nothing", wsScope, uuid.Must(uuid.NewV7())},
		} {
			err := create(c.scope, "BAD_"+c.name, c.store)
			if err == nil {
				t.Errorf("%s: accepted", c.name)
				continue
			}
			classAppErr(t, err, apperr.ClassInvalidArgument)
			texts = append(texts, err.Error())
		}
		for i := 1; i < len(texts); i++ {
			if texts[i] != texts[0] {
				t.Errorf("refusal texts differ: %q vs %q — the answer must not say which stores exist or whose they are", texts[0], texts[i])
			}
		}
		// Nothing was created by a refused call.
		for _, sc := range []tenancy.Scope{wsScope, bobScope} {
			got, err := cat.List(ctx, org.ID, sc)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range got {
				if len(s.Name) >= 4 && s.Name[:4] == "BAD_" {
					t.Errorf("a refused CreateRef left %q in %s", s.Name, sc.Level)
				}
			}
		}
	})
}

// A StoreBinding is the implicit way of choosing a store for every later
// CreateRef, so it obeys the same rule as an explicit choice: active, and
// owned by the scope or an ancestor. Otherwise "bind my scope to someone
// else's store, then create without a StoreID" walks around the check.
func TestCreateStoreBinding_RefusesUnusableStores(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	rp := tenancy.New(pool)
	cat := New(pool)

	org, err := rp.CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	other, err := rp.CreateOrganization(ctx, t.Name()+"-other", "")
	if err != nil {
		t.Fatalf("create other org: %v", err)
	}
	orgScope := tenancy.Org(org.ID)
	alice, err := rp.CreateUser(ctx, org.ID, "alice@example.test")
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	bob, err := rp.CreateUser(ctx, org.ID, "bob@example.test")
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}
	aliceScope := tenancy.Scope{Level: tenancy.LevelUser, ID: alice.ID}
	bobScope := tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID}

	mkStore := func(o uuid.UUID, owner tenancy.Scope, name, kind string) Store {
		t.Helper()
		s, err := cat.CreateStore(ctx, o, kind, name, owner)
		if err != nil {
			t.Fatalf("create store %s: %v", name, err)
		}
		return s
	}
	aliceStore := mkStore(org.ID, aliceScope, "alice-store", "builtin")
	orgStore := mkStore(org.ID, orgScope, "org-store", "builtin")
	disabled := mkStore(org.ID, orgScope, "disabled-store", "vault")
	if _, err := pool.Exec(ctx, `UPDATE stores SET status = 'disabled' WHERE id = $1`, disabled.ID); err != nil {
		t.Fatalf("disable store: %v", err)
	}
	otherOrgStore := mkStore(other.ID, tenancy.Org(other.ID), "other-org-store", "builtin")

	// Controls: a user binds their own store, another user binds the org's.
	if _, err := cat.CreateStoreBinding(ctx, org.ID, aliceScope, aliceStore.ID); err != nil {
		t.Fatalf("control: alice's own store at alice's scope: %v", err)
	}
	if _, err := cat.CreateStoreBinding(ctx, org.ID, bobScope, orgStore.ID); err != nil {
		t.Fatalf("control: the org's store at bob's scope: %v", err)
	}

	var texts []string
	for _, c := range []struct {
		name  string
		scope tenancy.Scope
		store uuid.UUID
	}{
		{"alice's store at org level", orgScope, aliceStore.ID},
		{"a disabled store", tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID}, disabled.ID},
		{"another organisation's store", orgScope, otherOrgStore.ID},
		{"an id that names nothing", orgScope, uuid.Must(uuid.NewV7())},
	} {
		_, err := cat.CreateStoreBinding(ctx, org.ID, c.scope, c.store)
		if err == nil {
			t.Errorf("%s: bound", c.name)
			continue
		}
		classAppErr(t, err, apperr.ClassInvalidArgument)
		texts = append(texts, err.Error())
	}
	for i := 1; i < len(texts); i++ {
		if texts[i] != texts[0] {
			t.Errorf("refusal texts differ: %q vs %q", texts[0], texts[i])
		}
	}
	// bob has no personal store bound to alice's: the mutually-refused
	// binding must not have been created.
	if _, ok, err := storeBindingAt(ctx, cat.pool, org.ID, orgScope); err != nil || ok {
		t.Errorf("a refused binding left one at org level: ok=%v err=%v", ok, err)
	}
}

// A store that was usable when it was bound can be disabled later. CreateRef
// without a StoreID must not silently use it.
func TestCreateRef_ImplicitStoreDisabledSinceBinding(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	rp := tenancy.New(pool)
	cat := New(pool)

	org, err := rp.CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	orgScope := tenancy.Org(org.ID)
	store, err := cat.CreateStore(ctx, org.ID, "builtin", "s", orgScope)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if _, err := cat.CreateStoreBinding(ctx, org.ID, orgScope, store.ID); err != nil {
		t.Fatalf("bind: %v", err)
	}
	in := CreateRefInput{Org: org.ID, Scope: orgScope, Name: "K", Class: "dev", Type: "generic", ProviderRef: "x"}
	if _, err := cat.CreateRef(ctx, in); err != nil {
		t.Fatalf("control: CreateRef through an active bound store: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE stores SET status = 'disabled' WHERE id = $1`, store.ID); err != nil {
		t.Fatalf("disable store: %v", err)
	}
	in.Name = "K2"
	_, err = cat.CreateRef(ctx, in)
	if err == nil {
		t.Fatal("CreateRef used a store disabled after it was bound")
	}
	classAppErr(t, err, apperr.ClassInvalidArgument)
}
