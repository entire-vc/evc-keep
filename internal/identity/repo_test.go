package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testDB opens a pool against a real, already-migrated PostgreSQL instance
// — see CONTRIBUTING.md: the database layer is never mocked. Same
// convention as internal/store's and
// internal/api's own testPool: it does NOT run migrations itself.
//
// That's deliberate, not an oversight: `go test ./...` runs different
// packages' test binaries as separate, concurrent OS processes, and this
// package is the first one whose tests actually touch real tables. An
// earlier version of this helper called store.NewProvider(...).Up() here,
// and it raced with internal/store's and cmd/keep-server's own tests
// doing the same against the one shared CI postgres service —
// "relation already exists" (42P07) even with goose's own
// session-advisory-lock enabled (see internal/store.NewProvider's doc).
// Migrating once, before any test binary starts, is the actual fix:
// migration always happens before the thing that depends on it runs, in CI
// the same as in production. See .gitlab-ci.yml's `test` job: `keep-server migrate
// up` runs once in before_script, before `go test` starts at all.
//
// Running this package's tests by hand (outside that CI job) needs the
// same step first: `go run ./cmd/keep-server migrate up`.
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seedOrg(t *testing.T, db *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO organizations (id, name) VALUES ($1, $2)`, id, "org-"+id.String())
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return id
}

func seedUser(t *testing.T, db *pgxpool.Pool, org uuid.UUID) uuid.UUID {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)`,
		id, org, id.String()+"@example.test")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedAgent(t *testing.T, db *pgxpool.Pool, org, sponsor uuid.UUID) uuid.UUID {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO agents (id, org_id, sponsor_user_id, name) VALUES ($1, $2, $3, $4)`,
		id, org, sponsor, "agent-"+id.String())
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	return id
}

func seedService(t *testing.T, db *pgxpool.Pool, org uuid.UUID, ownerScope string) uuid.UUID {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO services (id, org_id, owner_scope, name) VALUES ($1, $2, $3, $4)`,
		id, org, ownerScope, "service-"+id.String())
	if err != nil {
		t.Fatalf("seed service: %v", err)
	}
	return id
}

func seedMembership(t *testing.T, db *pgxpool.Pool, org, user uuid.UUID, scope string, role Role) uuid.UUID {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1, $2, $3, $4, $5)`,
		id, org, user, scope, string(role))
	if err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	return id
}

func deleteMembership(t *testing.T, db *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	if _, err := db.Exec(context.Background(), `DELETE FROM memberships WHERE id = $1`, id); err != nil {
		t.Fatalf("delete membership: %v", err)
	}
}

func seedAgentGrant(t *testing.T, db *pgxpool.Pool, org, agent uuid.UUID, perm Permission) {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO agent_grants (id, org_id, agent_id, permission) VALUES ($1, $2, $3, $4)`,
		id, org, agent, string(perm))
	if err != nil {
		t.Fatalf("seed agent grant: %v", err)
	}
}

// leaksIn reports whether needle appears in haystack under any encoding
// internal/testutil/canary's own detector covers — including the
// offset-1/2 base64 alignment a naive "encode needle on its own" check is
// blind to (canary.Of's own doc). needle here is a real token from
// [Repo.Issue], not a value canary.New generated itself, which is exactly
// what [canary.Of] is for.
func leaksIn(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	if canary.Of(needle).In(haystack) {
		return true
	}
	// The random part alone is the whole secret: a leak of it without the
	// "keep_<kind>_" prefix is a full leak that the prefixed needle above
	// never matches.
	if m := tokenRe.FindStringSubmatch(needle); m != nil {
		return canary.Of(m[2]).In(haystack)
	}
	return false
}

func TestIssueThenAuthenticateRoundTrips(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)
	agent := seedAgent(t, db, org, sponsor)

	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindAgent, PrincipalID: agent, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.Token.IsZero() {
		t.Fatal("Issue returned an empty token")
	}
	if res.Kind != KindAgent {
		t.Errorf("IssueResult.Kind = %q, want %q", res.Kind, KindAgent)
	}

	p, err := repo.Authenticate(ctx, res.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Kind != KindAgent {
		t.Errorf("Principal.Kind = %q, want %q", p.Kind, KindAgent)
	}
	if p.ID != agent {
		t.Errorf("Principal.ID = %s, want %s", p.ID, agent)
	}
	if p.OrgID != org {
		t.Errorf("Principal.OrgID = %s, want %s", p.OrgID, org)
	}
	if p.SponsorUserID == nil || *p.SponsorUserID != sponsor {
		t.Errorf("Principal.SponsorUserID = %v, want %s", p.SponsorUserID, sponsor)
	}
	if p.Scope != "org:"+org.String() {
		t.Errorf("Principal.Scope = %q, want %q — the token's own scope column must reach the Principal", p.Scope, "org:"+org.String())
	}
}

func TestIssueRejectsUnknownPrincipal(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	ghost, err := newID()
	if err != nil {
		t.Fatal(err)
	}

	_, err = repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindAgent, PrincipalID: ghost, Scope: "org:" + org.String()})
	if err == nil {
		t.Fatal("expected Issue to reject a principal id that doesn't exist")
	}
}

func TestIssueRejectsPrincipalFromAnotherOrg(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	sponsor := seedUser(t, db, orgA)
	agentInA := seedAgent(t, db, orgA, sponsor)

	// Same agent id, but claimed against orgB — must be rejected, not
	// silently issued under the wrong org.
	_, err := repo.Issue(ctx, IssueParams{OrgID: orgB, Kind: KindAgent, PrincipalID: agentInA, Scope: "org:" + orgB.String()})
	if err == nil {
		t.Fatal("expected Issue to reject a principal that belongs to a different org")
	}
}

func TestRevokeThenAuthenticateFails(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	svc := seedService(t, db, org, "proj:test")
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindService, PrincipalID: svc, Scope: "proj:test"})
	if err != nil {
		t.Fatal(err)
	}
	caller := Principal{OrgID: org}

	if err := repo.Revoke(ctx, caller, res.TokenID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := repo.Authenticate(ctx, res.Token); err == nil {
		t.Fatal("expected Authenticate to fail for a revoked token")
	}

	// Revoking again — same sentinel as an unknown token, not a distinct
	// "already revoked" signal (Repo.Revoke's doc).
	if err := repo.Revoke(ctx, caller, res.TokenID); err == nil {
		t.Fatal("expected re-revoking an already-revoked token to fail")
	}
}

// TestRevokeRejectsTokenFromAnotherOrg is red run for Repo.Revoke's own
// org filter (check-identity-mutations.sh's revoke-no-org-filter mutation):
// a caller from org B must not be able to revoke a token issued in org A,
// and the failure must be the same ErrTokenUnknown sentinel as "no such
// token" — never a distinct signal an attacker could use to confirm the
// token exists in someone else's org.
func TestRevokeRejectsTokenFromAnotherOrg(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	svc := seedService(t, db, orgA, "proj:test")
	res, err := repo.Issue(ctx, IssueParams{OrgID: orgA, Kind: KindService, PrincipalID: svc, Scope: "proj:test"})
	if err != nil {
		t.Fatal(err)
	}

	callerB := Principal{OrgID: orgB}
	if err := repo.Revoke(ctx, callerB, res.TokenID); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("Revoke from org B on org A's token: err = %v, want ErrTokenUnknown", err)
	}

	// The token must still work — the cross-org revoke must not have had
	// any effect at all, not even a partial one.
	if _, err := repo.Authenticate(ctx, res.Token); err != nil {
		t.Fatalf("token stopped working after a rejected cross-org revoke: %v", err)
	}

	// The legitimate owner can still revoke it.
	callerA := Principal{OrgID: orgA}
	if err := repo.Revoke(ctx, callerA, res.TokenID); err != nil {
		t.Fatalf("Revoke from the owning org: %v", err)
	}
}

func TestAuthenticateExpiredTokenFails(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	svc := seedService(t, db, org, "proj:test")
	past := time.Now().Add(-time.Hour)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindService, PrincipalID: svc, Scope: "proj:test", ExpiresAt: &past})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := repo.Authenticate(ctx, res.Token); err == nil {
		t.Fatal("expected Authenticate to fail for an already-expired token")
	}
}

// TestAuthenticateFailureModesAreUniformlyUnauthenticated is the isolation
// / uniform-error side of this package's own acceptance requirement: garbage, an unknown but
// well-formed token, an expired token, and a revoked token must all
// produce byte-identical HTTP responses through RequireAuth — the client
// can never distinguish why.
func TestAuthenticateFailureModesAreUniformlyUnauthenticated(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	svc := seedService(t, db, org, "proj:test")

	past := time.Now().Add(-time.Hour)
	expired, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindService, PrincipalID: svc, Scope: "proj:test", ExpiresAt: &past})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindService, PrincipalID: svc, Scope: "proj:test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, Principal{OrgID: org}, revoked.TokenID); err != nil {
		t.Fatal(err)
	}
	garbage, err := GenerateToken(KindService) // well-formed, never issued
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"malformed": "not-a-keep-token-at-all",
		"unknown":   Reveal(garbage),
		"expired":   Reveal(expired.Token),
		"revoked":   Reveal(revoked.Token),
	}

	bodies := map[string]string{}
	handler := RequireAuth(repo, nil)(neverCalledHandler(t))
	for name, token := range cases {
		req := newAuthRequest(token)
		rec := serve(handler, req)
		if rec.Code != 401 {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
		body := stripRequestID(t, rec.Body.String())
		bodies[name] = body
	}

	// A request with no Authorization header at all must be
	// indistinguishable from every token-shaped failure above too.
	noHeaderRec := serve(handler, httptest.NewRequest(http.MethodGet, "/", nil))
	if noHeaderRec.Code != 401 {
		t.Errorf("missing header: status = %d, want 401", noHeaderRec.Code)
	}
	bodies["missing-header"] = stripRequestID(t, noHeaderRec.Body.String())

	var first string
	for name, body := range bodies {
		if first == "" {
			first = body
			continue
		}
		if body != first {
			t.Errorf("%s produced a different response body than the baseline: %q vs %q", name, body, first)
		}
	}
}

func TestEffectiveAgentPermissionsFollowsSponsorLive(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)
	agent := seedAgent(t, db, org, sponsor)
	scope := "proj:" + uuid.New().String()

	membershipID := seedMembership(t, db, org, sponsor, scope, RoleAdmin)
	seedAgentGrant(t, db, org, agent, PermRotate)
	seedAgentGrant(t, db, org, agent, PermCreateRef)

	principal := Principal{Kind: KindAgent, ID: agent, OrgID: org, SponsorUserID: &sponsor}

	got, err := repo.EffectiveAgentPermissions(ctx, principal, scope)
	if err != nil {
		t.Fatalf("EffectiveAgentPermissions: %v", err)
	}
	want := map[Permission]bool{PermReadMetadata: true, PermDeploy: true, PermRotate: true, PermCreateRef: true}
	if len(got) != len(want) {
		t.Fatalf("permissions = %v, want %v", got, want)
	}
	for p := range want {
		if !got[p] {
			t.Errorf("missing permission %q", p)
		}
	}

	// Sponsor loses the role: the very next call must reflect it with no
	// separate invalidation step — this package's own acceptance requirement.
	deleteMembership(t, db, membershipID)

	got, err = repo.EffectiveAgentPermissions(ctx, principal, scope)
	if err != nil {
		t.Fatalf("EffectiveAgentPermissions after role loss: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("agent still has permissions %v after its sponsor's membership was deleted — role loss did not take effect", got)
	}
}

// TestUserRoleIsScopedToOrg is red run for UserRole's own org filter
// (check-identity-mutations.sh's sponsor-role-any-org mutation): the same
// user id and scope that resolve to a role in org A must resolve to
// nothing when looked up under org B.
func TestUserRoleIsScopedToOrg(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	sponsor := seedUser(t, db, orgA)
	scope := "proj:" + uuid.New().String()
	seedMembership(t, db, orgA, sponsor, scope, RoleAdmin)

	role, ok, err := repo.UserRole(ctx, orgA, sponsor, scope)
	if err != nil {
		t.Fatalf("UserRole(orgA): %v", err)
	}
	if !ok || role != RoleAdmin {
		t.Fatalf("UserRole(orgA) = (%q, %v), want (%q, true)", role, ok, RoleAdmin)
	}

	if role, ok, err := repo.UserRole(ctx, orgB, sponsor, scope); err != nil {
		t.Fatalf("UserRole(orgB): %v", err)
	} else if ok {
		t.Fatalf("UserRole(orgB) = (%q, true), want ok=false — the membership belongs to org A", role)
	}
}

// TestAgentExplicitGrantsIsScopedToOrg is red run for AgentExplicitGrants'
// own org filter (check-identity-mutations.sh's agent-grants-any-org
// mutation).
func TestAgentExplicitGrantsIsScopedToOrg(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	sponsor := seedUser(t, db, orgA)
	agent := seedAgent(t, db, orgA, sponsor)
	seedAgentGrant(t, db, orgA, agent, PermRotate)

	grantsA, err := repo.AgentExplicitGrants(ctx, orgA, agent)
	if err != nil {
		t.Fatalf("AgentExplicitGrants(orgA): %v", err)
	}
	if !grantsA[PermRotate] {
		t.Fatalf("AgentExplicitGrants(orgA) = %v, want PermRotate", grantsA)
	}

	grantsB, err := repo.AgentExplicitGrants(ctx, orgB, agent)
	if err != nil {
		t.Fatalf("AgentExplicitGrants(orgB): %v", err)
	}
	if len(grantsB) != 0 {
		t.Fatalf("AgentExplicitGrants(orgB) = %v, want empty — the grant belongs to org A", grantsB)
	}
}

// TestAuthenticateRejectsDeletedPrincipal is red run for the
// [Repo.principalExists] check inside [Repo.Authenticate]
// (check-identity-mutations.sh's deleted-principal-still-authenticates,
// deleted-principal-check-skips-user and deleted-principal-check-skips-agent
// mutations): a token whose principal row has been deleted must stop
// authenticating even though the token row itself is untouched — still
// unexpired, unrevoked, and hashed correctly. A table test over all three
// kinds, not just service: principalExists switches on kind to pick a
// table, and a mutation narrowing that switch to only one kind (e.g. "kind
// != KindAgent" guarding the check) would have stayed green against a
// service-only test.
func TestAuthenticateRejectsDeletedPrincipal(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)

	cases := []struct {
		kind   Kind
		seed   func() uuid.UUID
		delete string
	}{
		{KindService, func() uuid.UUID { return seedService(t, db, org, "proj:test") }, "services"},
		{KindAgent, func() uuid.UUID { return seedAgent(t, db, org, sponsor) }, "agents"},
		{KindUser, func() uuid.UUID { return seedUser(t, db, org) }, "users"},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			principalID := tc.seed()
			res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: tc.kind, PrincipalID: principalID, Scope: "proj:test"})
			if err != nil {
				t.Fatal(err)
			}

			//nolint:gosec // G201: tc.delete is one of the three literal table names above, not external input
			if _, err := db.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, tc.delete), principalID); err != nil {
				t.Fatalf("delete %s: %v", tc.delete, err)
			}

			if _, err := repo.Authenticate(ctx, res.Token); !errors.Is(err, ErrTokenUnknown) {
				t.Fatalf("Authenticate after %s principal was deleted: err = %v, want ErrTokenUnknown", tc.kind, err)
			}
		})
	}
}

// TestTokenNeverStoredPlaintext is the DB side of the leak test: after
// Issue, no text column of any identity table contains the token or the
// hash search space narrows to something reconstructible — a SELECT over
// every text column of the identity tables, per this package's own leak
// test requirement.
func TestTokenNeverStoredPlaintext(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)
	agent := seedAgent(t, db, org, sponsor)

	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindAgent, PrincipalID: agent, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatal(err)
	}

	hash := HashToken(res.Token)
	var storedHash []byte
	if err := db.QueryRow(ctx, `SELECT token_hash FROM tokens WHERE id = $1`, res.TokenID).Scan(&storedHash); err != nil {
		t.Fatalf("read back token_hash: %v", err)
	}
	if !EqualHash(storedHash, hash) {
		t.Fatal("stored token_hash does not match SHA-256(token) — Issue is not hashing what it claims to")
	}
	if len(storedHash) != 32 {
		t.Fatalf("token_hash length = %d, want 32 — looks like something other than a raw SHA-256 digest was stored", len(storedHash))
	}

	rows, err := db.Query(ctx, `
		SELECT table_name, column_name
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name IN ('organizations','users','agents','services','memberships','agent_grants','tokens')
		  AND data_type IN ('text','character varying')`)
	if err != nil {
		t.Fatalf("list text columns: %v", err)
	}
	type col struct{ table, column string }
	var cols []col
	for rows.Next() {
		var c col
		if err := rows.Scan(&c.table, &c.column); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(cols) == 0 {
		t.Fatal("information_schema scan found no text columns at all — the query itself is broken, this test would pass vacuously")
	}

	for _, c := range cols {
		//nolint:gosec // G201: table/column names come only from information_schema above, not external input
		q := fmt.Sprintf(`SELECT %s::text FROM %s WHERE %s IS NOT NULL`, c.column, c.table, c.column)
		valRows, err := db.Query(ctx, q)
		if err != nil {
			t.Fatalf("scan %s.%s: %v", c.table, c.column, err)
		}
		for valRows.Next() {
			var v string
			if err := valRows.Scan(&v); err != nil {
				t.Fatalf("scan %s.%s value: %v", c.table, c.column, err)
			}
			if leaksIn(v, Reveal(res.Token)) {
				t.Errorf("%s.%s contains the issued token (or an encoding of it): %q", c.table, c.column, v)
			}
		}
		valRows.Close()
	}
}

// TestCanaryTokenNeverLeaksThroughItsFullLifecycle is the leak test this
// package's own acceptance requirement calls for in full: the token from
// Issue must not appear — in any encoding — in a successful
// Authenticate's result, in any of the
// uniform-failure responses for garbage/expired/revoked attempts, or in
// Revoke's own error path. The one sanctioned exception is the Issue
// response itself, which this test never inspects for absence (that
// would be the opposite bug).
func TestCanaryTokenNeverLeaksThroughItsFullLifecycle(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)
	agent := seedAgent(t, db, org, sponsor)

	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindAgent, PrincipalID: agent, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatal(err)
	}
	token := res.Token

	// Successful authentication: the Principal must carry no trace of the
	// token — checked field by field since Principal has no string field
	// wide enough to hold one anyway, but that invariant is exactly what
	// this asserts rather than assumes.
	p, err := repo.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if leaksIn(fmt.Sprintf("%+v", p), Reveal(token)) {
		t.Errorf("Principal representation contains the token: %+v", p)
	}

	// A malformed / unknown lookup must not echo the input back in its
	// error.
	if _, err := repo.Authenticate(ctx, NewToken("keep_a_garbage")); err == nil || leaksIn(err.Error(), Reveal(token)) {
		t.Errorf("malformed-token authentication error leaks the real token: %v", err)
	}

	// Through the HTTP surface: garbage first, while the real token is
	// still valid — using the real token here would authenticate
	// successfully and reach neverCalledHandler, which is a wiring bug in
	// the test, not the leak this test is checking for. The real token's
	// turn through this same surface comes after revoke, below, once it
	// is genuinely a failure case.
	handler := RequireAuth(repo, nil)(neverCalledHandler(t))
	garbageRec := serve(handler, newAuthRequest("keep_a_garbage"))
	if leaksIn(garbageRec.Body.String(), Reveal(token)) {
		t.Error("HTTP response body leaks the token on a garbage attempt (body suppressed)")
	}
	for k, vs := range garbageRec.Header() {
		for _, v := range vs {
			if leaksIn(v, Reveal(token)) {
				t.Errorf("HTTP response header %s leaks the token on a garbage attempt: %s", k, v)
			}
		}
	}

	if err := repo.Revoke(ctx, Principal{OrgID: org}, res.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Authenticate(ctx, token); err == nil || leaksIn(err.Error(), Reveal(token)) {
		t.Errorf("post-revoke authentication error leaks the token: %v", err)
	}
	rec := serve(handler, newAuthRequest(Reveal(token)))
	if leaksIn(rec.Body.String(), Reveal(token)) {
		t.Error("post-revoke HTTP response leaks the token (body suppressed)")
	}
}

// TestIssueResultNeverLeaksThroughJSONLogOrFormat is blocker #1 from
// review round 2: IssueResult is this package's own internal bookkeeping
// shape, never meant to reach the wire (see its own doc) — it must refuse
// json.Marshal outright, and must redact Token under every fmt verb
// (including %d/%t, which bypass a Stringer and print a struct's fields by
// reflection) and under slog, even when logged under an internal/obs
// allow-listed key such as "token_id" — obs filters keys, not values, so
// without IssueResult's own LogValue the allow-list does nothing here.
func TestIssueResultNeverLeaksThroughJSONLogOrFormat(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)
	agent := seedAgent(t, db, org, sponsor)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindAgent, PrincipalID: agent, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatal(err)
	}

	if b, err := json.Marshal(res); err == nil {
		t.Fatalf("json.Marshal(IssueResult) succeeded and returned %q, want an error — IssueResult must refuse to serialize directly", b)
	}

	for name, rendered := range map[string]string{
		"%v":  fmt.Sprintf("%v", res),
		"%+v": fmt.Sprintf("%+v", res),
		"%#v": fmt.Sprintf("%#v", res),
		"%d":  fmt.Sprintf("%d", res),
		"%t":  fmt.Sprintf("%t", res),
	} {
		if leaksIn(rendered, Reveal(res.Token)) {
			t.Errorf("IssueResult leaked the token through fmt %s: %q", name, rendered)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(obs.NewHandler(&buf, slog.LevelDebug))
	logger.Info("issued", "token_id", res) // "token_id" is on obs's own allow-list
	if buf.Len() == 0 {
		t.Fatal("nothing was logged — this test proves nothing")
	}
	if leaksIn(buf.String(), Reveal(res.Token)) {
		t.Errorf("logging IssueResult under an allowed key leaked the token: %s", buf.String())
	}

	// Same value through a bare slog handler: obs scrubs its own output, so
	// only this proves the type redacts itself (LogValue) without that layer.
	var raw bytes.Buffer
	slog.New(slog.NewJSONHandler(&raw, nil)).Info("issued", "token_id", res)
	if raw.Len() == 0 {
		t.Fatal("nothing was logged through the bare handler — this test proves nothing")
	}
	if leaksIn(raw.String(), Reveal(res.Token)) {
		t.Errorf("IssueResult leaked the token through a bare slog handler: %s", raw.String())
	}
}

// TestIssueResponseCarriesTokenOnlyOverJSONNeverLogOrFormat is the
// counterpart for [IssueResponse], the one shape allowed to carry a
// token's plaintext onto the wire: [IssueResponse.WireJSON] must return it
// — the whole point of the type — but json.Marshal, fmt and slog must not,
// since none of those is the sanctioned one-time channel.
func TestIssueResponseCarriesTokenOnlyOverJSONNeverLogOrFormat(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)
	agent := seedAgent(t, db, org, sponsor)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindAgent, PrincipalID: agent, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatal(err)
	}
	resp := res.Response()

	if b, err := json.Marshal(resp); err == nil {
		t.Fatalf("json.Marshal(IssueResponse) succeeded and returned %q, want an error — only WireJSON may write the token", b)
	}
	b, err := resp.WireJSON()
	if err != nil {
		t.Fatalf("IssueResponse.WireJSON: %v", err)
	}
	if !leaksIn(string(b), Reveal(resp.Token)) {
		t.Fatalf("WireJSON did not carry the token — this is the one path that must: %s", b)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatalf("WireJSON output is not JSON: %v", err)
	}
	for _, field := range []string{"token_id", "token", "last4", "kind", "scope", "created_at"} {
		if _, ok := wire[field]; !ok {
			t.Errorf("WireJSON output lacks %q: %s", field, b)
		}
	}
	if wire["token"] != Reveal(resp.Token) {
		t.Errorf("WireJSON token field is not the issued token")
	}

	for name, rendered := range map[string]string{
		"%v":  fmt.Sprintf("%v", resp),
		"%+v": fmt.Sprintf("%+v", resp),
		"%#v": fmt.Sprintf("%#v", resp),
		"%d":  fmt.Sprintf("%d", resp),
		"%t":  fmt.Sprintf("%t", resp),
	} {
		if leaksIn(rendered, Reveal(resp.Token)) {
			t.Errorf("IssueResponse leaked the token through fmt %s: %q", name, rendered)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(obs.NewHandler(&buf, slog.LevelDebug))
	logger.Info("issued", "token_id", resp) // "token_id" is on obs's own allow-list
	if buf.Len() == 0 {
		t.Fatal("nothing was logged — this test proves nothing")
	}
	if leaksIn(buf.String(), Reveal(resp.Token)) {
		t.Errorf("logging IssueResponse under an allowed key leaked the token: %s", buf.String())
	}

	// Same value through a bare slog handler: obs scrubs its own output, so
	// only this proves the type redacts itself (LogValue) without that layer.
	var raw bytes.Buffer
	slog.New(slog.NewJSONHandler(&raw, nil)).Info("issued", "token_id", resp)
	if raw.Len() == 0 {
		t.Fatal("nothing was logged through the bare handler — this test proves nothing")
	}
	if leaksIn(raw.String(), Reveal(resp.Token)) {
		t.Errorf("IssueResponse leaked the token through a bare slog handler: %s", raw.String())
	}
}

// TestIssueWireFieldsMatchIssueResponse pins issueWire's json shape to
// IssueResponse's: internal/api's own closed-field guard
// (TestResponseFieldsAreClosed) can only reflect over IssueResponse, since
// issueWire is unexported and unreachable from outside this package: a
// field added to issueWire alone (never touching IssueResponse) would
// reach the wire unchecked by that reflection walk. This test closes the
// gap at the one place that can
// see both types: this package's own test binary. A field added to either
// struct without the other fails here immediately, before it ever reaches
// internal/api's registry.
func TestIssueWireFieldsMatchIssueResponse(t *testing.T) {
	want := jsonFieldNames(t, reflect.TypeOf(IssueResponse{}))
	got := jsonFieldNames(t, reflect.TypeOf(issueWire{}))
	if len(want) == 0 {
		t.Fatal("IssueResponse has no json fields at all — this test would pass vacuously")
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("issueWire's json fields %v do not match IssueResponse's %v — WireJSON must carry exactly the same field set, see issueWire's own doc", got, want)
	}
}

// jsonFieldNames returns rt's exported fields' json tag names, in
// declaration order (the tag's name before any comma, e.g. "omitempty");
// a field tagged "-" or with no exported name is skipped, matching how
// encoding/json itself would render or omit it.
func jsonFieldNames(t *testing.T, rt reflect.Type) []string {
	t.Helper()
	var names []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		tag, ok := f.Tag.Lookup("json")
		if !ok {
			names = append(names, f.Name)
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		names = append(names, name)
	}
	return names
}
