package tenancy

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSecretAt_RejectsMismatchedOrg checks the cross-tenant isolation
// property (any call under org A's identity sees none of org B's rows,
// checked at the level of the SQL query) aimed directly at secretAt's own
// org_id filter — package-internal (white-box) specifically so it can call
// secretAt directly, bypassing Resolve's own buildChain validation.
//
// This is deliberate, not redundant with the end-to-end
// internal/catalog isolation test: every scope id in this schema is a
// globally unique UUIDv7, so two different organizations' rows can never
// naturally collide on (scope_level, scope_id) — an end-to-end call through
// Resolve can never even ASK secretAt to look at a foreign org's scope,
// because buildChain only ever derives a scope id from tc.Org itself or
// from a workspace/project/user already validated as belonging to tc.Org.
// secretAt's own org_id filter is therefore defense-in-depth against a bug
// in that validation, not a currently-reachable leak through Resolve's
// public API — and defense-in-depth only means something if this test
// exercises the layer it defends, by calling secretAt directly with the
// SAME scope id a real secret lives at but the WRONG org.
//
// To see it fail: remove the "org_id = $1" clause from secretAt's query in
// catalog_reads.go and re-run — this test goes red, finding org A's secret
// under org B's identity.
func TestSecretAt_RejectsMismatchedOrg(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	rp := New(pool)

	orgA, err := rp.CreateOrganization(ctx, "org-a", "")
	if err != nil {
		t.Fatalf("create org A: %v", err)
	}
	orgB, err := rp.CreateOrganization(ctx, "org-b", "")
	if err != nil {
		t.Fatalf("create org B: %v", err)
	}

	// A secret at org A's own org-level scope — org A's scope id here is
	// literally orgA.ID, the schema's normal shape (see doc.go).
	secretID := mustInsertOrgSecret(t, pool, orgA.ID, "SHARED_NAME")

	// Positive control: looking it up with the correct org finds it.
	got, found, err := rp.secretAt(ctx, orgA.ID, Org(orgA.ID), "SHARED_NAME")
	if err != nil {
		t.Fatalf("secretAt(correct org): %v", err)
	}
	if !found || got.ID != secretID {
		t.Fatalf("secretAt(correct org) = (%+v, found=%v), want org A's own secret", got, found)
	}

	// The actual isolation check: same scope id (orgA.ID, since org-level
	// scope id IS the org id), but org B's identity passed as the caller's
	// own org. A correct org_id filter must refuse this — org B never
	// created anything at this scope — not silently hand back org A's row.
	_, found, err = rp.secretAt(ctx, orgB.ID, Scope{Level: LevelOrg, ID: orgA.ID}, "SHARED_NAME")
	if err != nil {
		t.Fatalf("secretAt(org B, org A's scope id): %v", err)
	}
	if found {
		t.Fatal("secretAt found org A's secret while called under org B's identity — org_id filter is not enforced")
	}
}

// mustInsertOrgSecret inserts a minimal secrets row directly at org's own
// org-level scope via raw SQL, bypassing internal/catalog (this package
// does not import it — see doc.go) since this test only needs a row to
// exist, not the catalog's own creation policy. It also inserts the one
// store the row's NOT NULL store_id foreign key requires.
func mustInsertOrgSecret(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, name string) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	storeID := uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(ctx,
		`INSERT INTO stores (id, org_id, provider, name, owner_scope_level, owner_scope_id)
		 VALUES ($1, $2, 'builtin', 's', 'org', $2)`,
		storeID, org,
	); err != nil {
		t.Fatalf("insert store: %v", err)
	}

	secretID := uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(ctx,
		`INSERT INTO secrets (id, org_id, scope_level, scope_id, name, class, type, store_id, provider_ref)
		 VALUES ($1, $2, 'org', $2, $3, 'dev', 'generic', $4, 'x')`,
		secretID, org, name, storeID,
	); err != nil {
		t.Fatalf("insert secret: %v", err)
	}
	return secretID
}
