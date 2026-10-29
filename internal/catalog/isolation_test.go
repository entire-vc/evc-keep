package catalog

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// TestCrossTenantIsolation checks that two organizations with secrets of the
// same name are isolated: any call made under org A's identity sees none of
// org B's rows, checked at the level of the SQL query, not just the result.
// It is the end-to-end shape of that check, through the public API a real
// caller uses. It does not by itself catch a dropped org_id predicate: every
// scope id in this schema is a globally unique UUIDv7, so a caller asking
// about its own tenant gets the right rows either way. The per-query
// predicates are pinned by TestEveryQueryFiltersByOrg here and by
// internal/tenancy's TestSecretAt_RejectsMismatchedOrg. Two organizations
// define the SAME secret name at the SAME scope shape (org-level), and every
// read path — Resolve, List, and a raw SQL count — is checked from org A's
// side.
func TestCrossTenantIsolation(t *testing.T) {
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

	storeA, err := cat.CreateStore(ctx, orgA.ID, "builtin", "s", tenancy.Org(orgA.ID))
	if err != nil {
		t.Fatalf("create store A: %v", err)
	}
	storeB, err := cat.CreateStore(ctx, orgB.ID, "builtin", "s", tenancy.Org(orgB.ID))
	if err != nil {
		t.Fatalf("create store B: %v", err)
	}
	if _, err := cat.CreateStoreBinding(ctx, orgA.ID, tenancy.Org(orgA.ID), storeA.ID); err != nil {
		t.Fatalf("bind store A: %v", err)
	}
	if _, err := cat.CreateStoreBinding(ctx, orgB.ID, tenancy.Org(orgB.ID), storeB.ID); err != nil {
		t.Fatalf("bind store B: %v", err)
	}

	// Same name, same scope shape (org-level), different organizations.
	secretA, err := cat.CreateRef(ctx, CreateRefInput{
		Org: orgA.ID, Scope: tenancy.Org(orgA.ID), Name: "SHARED_NAME", Class: "dev", Type: "generic", ProviderRef: "a",
	})
	if err != nil {
		t.Fatalf("create secret in org A: %v", err)
	}
	secretB, err := cat.CreateRef(ctx, CreateRefInput{
		Org: orgB.ID, Scope: tenancy.Org(orgB.ID), Name: "SHARED_NAME", Class: "dev", Type: "generic", ProviderRef: "b",
	})
	if err != nil {
		t.Fatalf("create secret in org B: %v", err)
	}
	if secretA.ID == secretB.ID {
		t.Fatal("org A and org B secrets share an id — fixture is broken")
	}

	// Resolve from org A's side must find A's row, never B's — even though
	// B's row would satisfy the same name at the same scope shape.
	resolved, err := rp.Resolve(ctx, tenancy.Context{Org: orgA.ID, Principal: tenancy.Principal{Kind: tenancy.PrincipalService}}, "SHARED_NAME")
	if err != nil {
		t.Fatalf("resolve from org A: %v", err)
	}
	if resolved.ID != secretA.ID {
		t.Fatalf("org A resolved secret %v, want its own %v (got org B's %v?)", resolved.ID, secretA.ID, secretB.ID)
	}
	if resolved.OrgID != orgA.ID {
		t.Fatalf("resolved secret's OrgID = %v, want %v", resolved.OrgID, orgA.ID)
	}

	// List from org A's side must return exactly one row, org A's own.
	listedA, err := cat.List(ctx, orgA.ID, tenancy.Org(orgA.ID))
	if err != nil {
		t.Fatalf("list org A: %v", err)
	}
	if len(listedA) != 1 || listedA[0].ID != secretA.ID {
		t.Fatalf("List(org A) = %+v, want exactly org A's own secret", listedA)
	}

	// Meta by org B's id, called with org A's org_id, must not find it. This
	// is the end-to-end shape only: Meta's scopeReachable check also rejects
	// it, so it does not pin Meta's own org_id predicate —
	// TestEveryQueryFiltersByOrg does that, one query at a time.
	if _, err := cat.Meta(ctx, orgA.ID, secretB.ID, []tenancy.Scope{tenancy.Org(orgA.ID)}); err == nil {
		t.Fatal("Meta(orgA.ID, secretB.ID) succeeded — org A can read org B's secret by id")
	} else {
		classAppErr(t, err, apperr.ClassSecretNotFound)
	}

	// SQL-level check, not just the Go API's result: a raw count scoped to
	// org A must never include org B's row, proven by counting without any
	// org_id filter first (positive control — the row really is there) and
	// then with org A's filter (must exclude it).
	var totalRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE name = 'SHARED_NAME'`).Scan(&totalRows); err != nil {
		t.Fatalf("count all SHARED_NAME rows: %v", err)
	}
	if totalRows != 2 {
		t.Fatalf("expected 2 SHARED_NAME rows across both orgs (positive control), got %d", totalRows)
	}
	var orgARows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE org_id = $1 AND name = 'SHARED_NAME'`, orgA.ID).Scan(&orgARows); err != nil {
		t.Fatalf("count org A's SHARED_NAME rows: %v", err)
	}
	if orgARows != 1 {
		t.Fatalf("org_id-scoped count = %d, want 1", orgARows)
	}
}

// TestResolve_OracleByName is scenario C2's by-id oracle check's
// counterpart for name resolution directly: a name that is genuinely
// undefined anywhere in the chain, and a name that IS defined but only at a
// scope the principal's context never visits, must produce byte-identical
// error text (tenancy model §3 step 4).
func TestResolve_OracleByName(t *testing.T) {
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
		t.Fatalf("bind store: %v", err)
	}

	wsVisible := mustCreateWorkspace(t, rp, ctx, org.ID, "visible")
	wsHidden := mustCreateWorkspace(t, rp, ctx, org.ID, "hidden")

	// Defined, but only in a workspace the caller's context never names.
	if _, err := cat.CreateRef(ctx, CreateRefInput{
		Org: org.ID, Scope: tenancy.Scope{Level: tenancy.LevelWorkspace, ID: wsHidden.ID},
		Name: "ONLY_IN_HIDDEN_WS", Class: "dev", Type: "generic", ProviderRef: "x",
	}); err != nil {
		t.Fatalf("create ref in hidden ws: %v", err)
	}

	callerCtx := tenancy.Context{Org: org.ID, Workspace: wsVisible.ID, Principal: tenancy.Principal{Kind: tenancy.PrincipalService}}

	_, errUndefined := rp.Resolve(ctx, callerCtx, "NEVER_DEFINED_ANYWHERE")
	if errUndefined == nil {
		t.Fatal("expected NEVER_DEFINED_ANYWHERE to fail to resolve")
	}
	_, errElsewhere := rp.Resolve(ctx, callerCtx, "ONLY_IN_HIDDEN_WS")
	if errElsewhere == nil {
		t.Fatal("expected ONLY_IN_HIDDEN_WS to fail to resolve from ws:visible's context")
	}

	wantUndefined := `secret "NEVER_DEFINED_ANYWHERE" not found (checked: org, ws)`
	wantElsewhere := `secret "ONLY_IN_HIDDEN_WS" not found (checked: org, ws)`
	if errUndefined.Error() != wantUndefined {
		t.Fatalf("undefined-name error = %q, want %q", errUndefined, wantUndefined)
	}
	if errElsewhere.Error() != wantElsewhere {
		t.Fatalf("defined-elsewhere error = %q, want %q", errElsewhere, wantElsewhere)
	}
	classAppErr(t, errUndefined, apperr.ClassSecretNotFound)
	classAppErr(t, errElsewhere, apperr.ClassSecretNotFound)
}

func mustCreateWorkspace(t *testing.T, rp *tenancy.Repo, ctx context.Context, org uuid.UUID, name string) tenancy.Workspace {
	t.Helper()
	ws, err := rp.CreateWorkspace(ctx, org, name)
	if err != nil {
		t.Fatalf("create workspace %s: %v", name, err)
	}
	return ws
}

// TestCanaryOnlySurvivesInItsOwnColumn is the leak test written before the
// feature it guards: a canary placed in provider_ref, description, and name
// must be found only in those columns of the secrets row it was placed into —
// scanning ALL columns of the table, not just the ones the test happens to
// remember, so a leak into an unexpected column (or a future column added
// without updating this test) is still caught.
func TestCanaryOnlySurvivesInItsOwnColumn(t *testing.T) {
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
		t.Fatalf("bind store: %v", err)
	}

	c := canary.New()
	name := "n-" + c.Value(1) // name is also the primary key text — must stay a legal-ish identifier prefix
	providerRef := c.Value(2)
	description := c.Value(3)

	s, err := cat.CreateRef(ctx, CreateRefInput{
		Org: org.ID, Scope: orgScope, Name: name, Class: "dev", Type: "generic",
		ProviderRef: providerRef, Description: description,
	})
	if err != nil {
		t.Fatalf("create ref: %v", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT column_name, value
		FROM secrets, LATERAL (
			SELECT column_name, (to_jsonb(secrets) ->> column_name) AS value
			FROM information_schema.columns
			WHERE table_name = 'secrets' AND table_schema = 'public'
		) cols
		WHERE secrets.id = $1
	`, s.ID)
	if err != nil {
		t.Fatalf("query all columns: %v", err)
	}
	defer rows.Close()

	placements := map[string]string{
		"name":         name,
		"provider_ref": providerRef,
		"description":  description,
	}
	var checked int
	for rows.Next() {
		var col string
		var val *string
		if err := rows.Scan(&col, &val); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		checked++
		if val == nil {
			continue
		}
		if c.In(*val) {
			want, placed := placements[col]
			if !placed {
				t.Errorf("canary leaked into unexpected column %q: %q", col, *val)
				continue
			}
			if *val != want {
				t.Errorf("column %q carries a canary but not the one placed there: got %q, want %q", col, *val, want)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read columns: %v", err)
	}
	if checked < 10 {
		t.Fatalf("only inspected %d columns — the column walker is broken, not the row clean", checked)
	}
}

// TestCanaryAbsentFromLogsAndErrors runs every read and write path of the
// package with canaries in provider_ref and description (and, separately, in
// the name), capturing everything sent to the default slog logger and the
// standard log package, and every error text returned by failing calls. A
// canary may show up in an error only as the secret's name, and only when the
// name is what carries it. The packages log nothing today; this pins that, so
// a log line added later that echoes a definition's fields turns the test red.
func TestCanaryAbsentFromLogsAndErrors(t *testing.T) {
	var logged bytes.Buffer
	prevSlog := slog.Default()
	prevLog, prevFlags := log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(&logged)
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevLog)
		log.SetFlags(prevFlags)
	})

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
		t.Fatalf("bind store: %v", err)
	}
	ws := mustCreateWorkspace(t, rp, ctx, org.ID, "ws")
	wsScope := tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}
	if _, err := cat.CreateOverrideLock(ctx, org.ID, orgScope, ModeClass, "", "prod", nil); err != nil {
		t.Fatalf("lock: %v", err)
	}

	c := canary.New()
	name := "n-" + c.Value(1)
	providerRef := c.Value(2)
	description := c.Value(3)
	in := CreateRefInput{Org: org.ID, Scope: orgScope, Name: name, Class: "dev", Type: "generic", ProviderRef: providerRef, Description: description}

	var errTexts []string
	note := func(err error) {
		if err != nil {
			errTexts = append(errTexts, err.Error())
		}
	}

	s, err := cat.CreateRef(ctx, in)
	if err != nil {
		t.Fatalf("create ref: %v", err)
	}
	_, err = cat.CreateRef(ctx, in) // duplicate: a database error path
	note(err)
	blocked := in // class prod is locked below org: override_locked path
	blocked.Scope, blocked.Class = wsScope, "prod"
	_, err = cat.CreateRef(ctx, blocked)
	note(err)
	_, err = cat.List(ctx, org.ID, orgScope)
	note(err)
	_, err = cat.Meta(ctx, org.ID, s.ID, nil) // present but unreachable: not-found path
	note(err)
	_, err = rp.Resolve(ctx, tenancy.Context{Org: org.ID, Workspace: ws.ID, Principal: tenancy.Principal{Kind: tenancy.PrincipalService}}, name)
	note(err)
	_, err = rp.Resolve(ctx, tenancy.Context{Org: org.ID, Workspace: ws.ID, Principal: tenancy.Principal{Kind: tenancy.PrincipalService}}, "absent-"+c.Value(4))
	note(err)

	if len(errTexts) < 3 {
		t.Fatalf("only %d failing calls produced an error — the error paths are not being exercised", len(errTexts))
	}
	if c.In(logged.String()) {
		t.Errorf("canary reached the log output: %q", logged.String())
	}
	for _, text := range errTexts {
		for label, v := range map[string]string{"provider_ref": providerRef, "description": description} {
			if strings.Contains(text, v) {
				t.Errorf("%s canary reached an error text: %q", label, text)
			}
		}
	}
}
