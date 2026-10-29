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
