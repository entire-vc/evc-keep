package tenancy

import (
	"context"
	"errors"
	"testing"
)

// TestEveryTenancyQueryFiltersByOrg pins the org_id predicate of each
// internal/tenancy SQL query on its own (secretAt has its own test in
// isolation_internal_test.go). Ids in this schema are globally unique
// UUIDv7, so a query that dropped its org_id predicate would still return
// the right row for a caller that only asks about its own tenant; here org
// A's identity is handed org B's ids directly, so that only the query's own
// predicate stands between org A and org B's rows. A positive control (the
// same call under org B's identity finds the row) precedes each check, so an
// empty result is not just an empty table.
func TestEveryTenancyQueryFiltersByOrg(t *testing.T) {
	f := newLockFixture(t) // org B: workspace, project, user, store
	ctx := context.Background()
	rp := f.rp
	orgB := f.org

	orgA, err := rp.CreateOrganization(ctx, "org-a", "")
	if err != nil {
		t.Fatalf("create org A: %v", err)
	}

	agentB, err := rp.CreateAgent(ctx, orgB, f.user.ID, "agent")
	if err != nil {
		t.Fatalf("create agent B: %v", err)
	}
	f.nameLock(Org(orgB), "SOME_NAME")
	if _, err := rp.CreateMembership(ctx, orgB, f.user.ID, Scope{Level: LevelWorkspace, ID: f.ws}, "member"); err != nil {
		t.Fatalf("create membership B: %v", err)
	}

	t.Run("GetUser", func(t *testing.T) {
		if _, err := rp.GetUser(ctx, orgB, f.user.ID); err != nil {
			t.Fatalf("positive control: GetUser under org B: %v", err)
		}
		if u, err := rp.GetUser(ctx, orgA.ID, f.user.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetUser under org A's identity = (%+v, %v), want ErrNotFound: org_id predicate missing", u, err)
		}
	})

	t.Run("GetAgent", func(t *testing.T) {
		if _, err := rp.GetAgent(ctx, orgB, agentB.ID); err != nil {
			t.Fatalf("positive control: GetAgent under org B: %v", err)
		}
		if a, err := rp.GetAgent(ctx, orgA.ID, agentB.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetAgent under org A's identity = (%+v, %v), want ErrNotFound: org_id predicate missing", a, err)
		}
	})

	t.Run("locksAt", func(t *testing.T) {
		if got, err := rp.locksAt(ctx, orgB, Org(orgB)); err != nil || len(got) != 1 {
			t.Fatalf("positive control: locksAt under org B = %v, %v; want one lock", got, err)
		}
		got, err := rp.locksAt(ctx, orgA.ID, Org(orgB))
		if err != nil {
			t.Fatalf("locksAt: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("locksAt under org A's identity returned %d of org B's locks: org_id predicate missing", len(got))
		}
	})

	t.Run("workspaceInOrg", func(t *testing.T) {
		if ok, err := rp.workspaceInOrg(ctx, orgB, f.ws); err != nil || !ok {
			t.Fatalf("positive control: workspaceInOrg under org B = %v, %v", ok, err)
		}
		if ok, err := rp.workspaceInOrg(ctx, orgA.ID, f.ws); err != nil || ok {
			t.Fatalf("workspaceInOrg under org A's identity = %v, %v; want false: org_id predicate missing", ok, err)
		}
	})

	t.Run("projectInWorkspace", func(t *testing.T) {
		if ok, err := rp.projectInWorkspace(ctx, orgB, f.ws, f.proj); err != nil || !ok {
			t.Fatalf("positive control: projectInWorkspace under org B = %v, %v", ok, err)
		}
		if ok, err := rp.projectInWorkspace(ctx, orgA.ID, f.ws, f.proj); err != nil || ok {
			t.Fatalf("projectInWorkspace under org A's identity = %v, %v; want false: org_id predicate missing", ok, err)
		}
	})

	t.Run("distinctScopeIDs", func(t *testing.T) {
		if got, err := rp.distinctScopeIDs(ctx, orgB, f.user.ID, LevelWorkspace); err != nil || len(got) != 1 {
			t.Fatalf("positive control: distinctScopeIDs under org B = %v, %v; want one workspace", got, err)
		}
		got, err := rp.distinctScopeIDs(ctx, orgA.ID, f.user.ID, LevelWorkspace)
		if err != nil {
			t.Fatalf("distinctScopeIDs: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("distinctScopeIDs under org A's identity returned %d of org B's memberships: org_id predicate missing", len(got))
		}
	})

	// RemoveUser mutates, so it goes last: the subtests above still need the
	// user active.
	t.Run("RemoveUser", func(t *testing.T) {
		if err := rp.RemoveUser(ctx, orgA.ID, f.user.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("RemoveUser under org A's identity = %v, want ErrNotFound: org_id predicate missing", err)
		}
		if u, err := rp.GetUser(ctx, orgB, f.user.ID); err != nil || u.Status != "active" {
			t.Fatalf("org B's user after org A's RemoveUser = (%+v, %v), want still active", u, err)
		}
		if err := rp.RemoveUser(ctx, orgB, f.user.ID); err != nil {
			t.Fatalf("positive control: RemoveUser under org B: %v", err)
		}
		if u, err := rp.GetUser(ctx, orgB, f.user.ID); err != nil || u.Status != "removed" {
			t.Fatalf("org B's user after its own RemoveUser = (%+v, %v), want removed", u, err)
		}
	})
}
