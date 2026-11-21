// Findings #2 and #3 from the CreateRef/CreateStoreBinding transaction
// review: a race on a unique constraint, or an invalid scope caught only by
// the schema's own CHECK, must never leave this package as a raw,
// unclassified database error — always an *apperr.Error with a closed class
// and a template message.
package catalog

import (
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// TestCreateRef_DuplicateName pins finding #2 for the secrets table's own
// UNIQUE (org_id, scope_level, scope_id, name): a second CreateRef for the
// same (scope, name) is refused as apperr.ClassAlreadyExists, and the text
// carries neither the store the first ref landed in nor its provider_ref —
// the caller already knows the name and the scope it tried, which is all it
// is told.
func TestCreateRef_DuplicateName(t *testing.T) {
	f := newFixture(t)
	orgScope := tenancy.Org(f.org.ID)
	store := f.mustStore("marker-store-zzqx", orgScope)
	f.mustBind(orgScope, store)

	first := f.mustRef(orgScope, "DUP_NAME", "dev")

	_, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: orgScope, Name: "DUP_NAME", Class: "dev",
		Type: "generic", ProviderRef: "ref:second-attempt-marker",
	})
	if err == nil {
		t.Fatal("expected a second CreateRef for the same (scope, name) to fail")
	}
	classAppErr(t, err, apperr.ClassAlreadyExists)

	// The exact template, not just an absence of specific markers: a
	// classifier that falls back to appending the raw *pgconn.PgError's own
	// Message/Detail (constraint name, "Key (org_id, scope_level, scope_id,
	// name)=(...)" with the actual name in it) would still dodge every one
	// of the substring checks below it individually names, since none of
	// those markers happen to appear in this particular constraint's own
	// wording — only comparing against the whole template catches that.
	const wantMsg = "a secret with this name already exists at this scope"
	msg := err.Error()
	if msg != wantMsg {
		t.Fatalf("duplicate-name error = %q, want exactly %q (anything else is either wrong text or a leak riding along with it)", msg, wantMsg)
	}
	if strings.Contains(msg, store.Name) {
		t.Fatalf("duplicate-name error %q names the store %q — infrastructure leak", msg, store.Name)
	}
	if strings.Contains(msg, "ref:") {
		t.Fatalf("duplicate-name error %q echoes a provider_ref — infrastructure leak", msg)
	}
	if strings.Contains(msg, "second-attempt-marker") {
		t.Fatalf("duplicate-name error %q echoes the losing attempt's own provider_ref", msg)
	}
	if strings.Contains(msg, first.ID.String()) {
		t.Fatalf("duplicate-name error %q names the existing secret's id — an oracle the caller has no other way to get", msg)
	}
	if strings.Contains(msg, "DUP_NAME") || strings.Contains(strings.ToLower(msg), "duplicate key") || strings.Contains(msg, "Key (") || strings.Contains(msg, "23505") {
		t.Fatalf("duplicate-name error %q looks like it carries raw database text, not the hand-built template", msg)
	}
}

// TestCreateStoreBinding_DuplicateBinding pins finding #2 for
// store_bindings' own UNIQUE (org_id, scope_level, scope_id): a second
// CreateStoreBinding at an already-bound scope is refused as
// apperr.ClassAlreadyExists, and the text carries neither store's name.
func TestCreateStoreBinding_DuplicateBinding(t *testing.T) {
	f := newFixture(t)
	orgScope := tenancy.Org(f.org.ID)
	first := f.mustStore("first-store", orgScope)
	second := f.mustExternalStore("second-store", orgScope)
	f.mustBind(orgScope, first)

	_, err := f.cat.CreateStoreBinding(f.ctx, f.org.ID, orgScope, second.ID)
	if err == nil {
		t.Fatal("expected a second CreateStoreBinding at an already-bound scope to fail")
	}
	classAppErr(t, err, apperr.ClassAlreadyExists)

	// Exact template, for the same reason as TestCreateRef_DuplicateName
	// above: individual substring checks can all pass while a raw
	// PgError.Message/Detail fallback still rides along in the text.
	const wantMsg = "a store binding already exists at this scope"
	msg := err.Error()
	if msg != wantMsg {
		t.Fatalf("duplicate-binding error = %q, want exactly %q", msg, wantMsg)
	}
	if strings.Contains(msg, first.Name) || strings.Contains(msg, second.Name) {
		t.Fatalf("duplicate-binding error %q names a store — infrastructure leak", msg)
	}
	if strings.Contains(strings.ToLower(msg), "duplicate key") || strings.Contains(msg, "Key (") || strings.Contains(msg, "23505") {
		t.Fatalf("duplicate-binding error %q looks like it carries raw database text, not the hand-built template", msg)
	}
}

// TestCreateOverrideLock_InvalidScope pins finding #3: an OverrideLock whose
// scope does not belong to org (here: a workspace id that was never
// created) is refused as apperr.ClassInvalidArgument, gated the same way as
// tenancy.Repo.CreateService/CreateMembership, instead of surfacing the
// override_locks table's own keep_validate_scope CHECK unclassified.
func TestCreateOverrideLock_InvalidScope(t *testing.T) {
	f := newFixture(t)
	bogus := tenancy.Scope{Level: tenancy.LevelWorkspace, ID: uuid.Must(uuid.NewV7())}

	_, err := f.cat.CreateOverrideLock(f.ctx, f.org.ID, bogus, ModeClass, "", "prod", nil)
	if err == nil {
		t.Fatal("expected CreateOverrideLock at a nonexistent workspace scope to fail")
	}
	classAppErr(t, err, apperr.ClassInvalidArgument)

	// Positive control: the exact same call against a real org scope
	// succeeds, so the refusal above is the scope gate, not some unrelated
	// argument validation.
	if _, err := f.cat.CreateOverrideLock(f.ctx, f.org.ID, tenancy.Org(f.org.ID), ModeClass, "", "prod", nil); err != nil {
		t.Fatalf("positive control: CreateOverrideLock at org scope: %v", err)
	}
}

// TestCreateStore_InvalidScope pins finding #3 for CreateStore's own
// ownerScope, the same way as CreateOverrideLock above.
func TestCreateStore_InvalidScope(t *testing.T) {
	f := newFixture(t)
	bogus := tenancy.Scope{Level: tenancy.LevelWorkspace, ID: uuid.Must(uuid.NewV7())}

	_, err := f.cat.CreateStore(f.ctx, f.org.ID, "builtin", "s", bogus)
	if err == nil {
		t.Fatal("expected CreateStore with a nonexistent workspace owner scope to fail")
	}
	classAppErr(t, err, apperr.ClassInvalidArgument)

	if _, err := f.cat.CreateStore(f.ctx, f.org.ID, "builtin", "s-ok", tenancy.Org(f.org.ID)); err != nil {
		t.Fatalf("positive control: CreateStore at org scope: %v", err)
	}
}

// classProviderRefInUse is spelled out rather than taken from apperr so this
// test compiles against a tree without the class and fails there on the
// behaviour (the second ref is accepted), not on a missing identifier.
const classProviderRefInUse apperr.Class = "provider_ref_in_use"

// TestCreateRef_ProviderRefInUse: the built-in provider keys a value by
// (store owner scope, provider_ref), so two refs with one locator in
// one store are one value. A member with create_ref in their own user scope
// who reuses the locator of an org secret in the org's store would read that
// value through a deploy of their ref and overwrite it through an input link
// or a rotation of their ref (threat model §4.1). Such a ref is refused,
// whichever way the store is chosen; the refusal carries neither the locator
// nor anything about the secret that holds it, and creates nothing. The same
// locator in another store is a different value and is accepted.
func TestCreateRef_ProviderRefInUse(t *testing.T) {
	f := newFixture(t)
	orgScope := tenancy.Org(f.org.ID)
	orgStore := f.mustStore("org-store", orgScope)
	f.mustBind(orgScope, orgStore)
	alice := f.mustUser("alice")
	aliceScope := tenancy.Scope{Level: tenancy.LevelUser, ID: alice.ID}
	aliceStore := f.mustStore("alice-store", aliceScope)

	const locator = "builtin://default/ORG_DB_PASSWORD-marker-qzx"
	orgSecret, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: orgScope, Name: "ORG_DB_PASSWORD", Class: "prod", Type: "generic", ProviderRef: locator,
	})
	if err != nil {
		t.Fatalf("org secret: %v", err)
	}

	const wantMsg = "this provider reference is already in use in this store"
	for _, c := range []struct {
		name  string
		scope tenancy.Scope
		store uuid.UUID
	}{
		{"another scope, store found through the org binding", aliceScope, uuid.Nil},
		{"another scope, the org store chosen explicitly", aliceScope, orgStore.ID},
		{"the same scope under another name", orgScope, uuid.Nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.cat.CreateRef(f.ctx, CreateRefInput{
				Org: f.org.ID, Scope: c.scope, Name: "SHADOW", Class: "dev", Type: "generic",
				ProviderRef: locator, StoreID: c.store,
			})
			if err == nil {
				t.Fatal("a second active ref with the same provider_ref in the same store was accepted")
			}
			classAppErr(t, err, classProviderRefInUse)
			if msg := err.Error(); msg != wantMsg {
				t.Fatalf("refusal = %q, want exactly %q", msg, wantMsg)
			}
			got, err := f.cat.List(f.ctx, f.org.ID, c.scope)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range got {
				if s.Name == "SHADOW" {
					t.Fatal("a refused CreateRef left a row behind")
				}
			}
		})
	}

	// The refusal is no catch-all for every unique violation: a duplicate
	// name is still reported as one, also when the locator is fresh.
	_, err = f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: orgScope, Name: "ORG_DB_PASSWORD", Class: "prod", Type: "generic", ProviderRef: "builtin://default/fresh",
	})
	classAppErr(t, err, apperr.ClassAlreadyExists)

	// Positive control: the same locator in alice's own store is another
	// value and is accepted, as is a fresh locator in the org store.
	mine, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: aliceScope, Name: "MINE", Class: "dev", Type: "generic", ProviderRef: locator, StoreID: aliceStore.ID,
	})
	if err != nil {
		t.Fatalf("same locator in another store refused: %v", err)
	}
	if mine.StoreID != aliceStore.ID || mine.StoreID == orgSecret.StoreID {
		t.Fatalf("ref landed in store %s, want alice's %s", mine.StoreID, aliceStore.ID)
	}
	if _, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: aliceScope, Name: "MINE_IN_ORG_STORE", Class: "dev", Type: "generic", ProviderRef: "builtin://default/alice-own",
	}); err != nil {
		t.Fatalf("fresh locator in the org store refused: %v", err)
	}

	// Two user scopes: bob reusing the locator alice's ref holds in the org
	// store is refused the same way.
	bob := f.mustUser("bob")
	bobScope := tenancy.Scope{Level: tenancy.LevelUser, ID: bob.ID}
	_, err = f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: bobScope, Name: "BOB_SHADOW", Class: "dev", Type: "generic", ProviderRef: "builtin://default/alice-own",
	})
	if err == nil {
		t.Fatal("another user scope reused a locator held by a user-scope ref in the same store")
	}
	classAppErr(t, err, classProviderRefInUse)

	// A disabled secret still owns its locator: disabling is reversible and
	// the built-in value is not erased, so a new ref on that locator would
	// reach the retired value.
	retired, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: orgScope, Name: "RETIRED", Class: "prod", Type: "generic", ProviderRef: "builtin://default/retired-marker-qzx",
	})
	if err != nil {
		t.Fatalf("retired secret: %v", err)
	}
	f.mustExec(`UPDATE secrets SET status = 'disabled' WHERE id = $1`, retired.ID)
	_, err = f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: bobScope, Name: "BOB_ON_RETIRED", Class: "dev", Type: "generic", ProviderRef: "builtin://default/retired-marker-qzx",
	})
	if err == nil {
		t.Fatal("a locator held by a disabled secret was handed to a new ref")
	}
	classAppErr(t, err, classProviderRefInUse)
}
