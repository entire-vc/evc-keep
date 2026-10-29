package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// routeFixture bundles the real dependencies this package's routes need,
// against a real PostgreSQL database (CONTRIBUTING.md: never mocked) — the
// same fixture shape internal/catalog/scenarios_test.go uses, extended with
// identity.Repo.Issue so tests can mint real bearer tokens for httptest
// requests instead of reaching into the router's internals.
type routeFixture struct {
	t      *testing.T
	ctx    context.Context
	pool   *pgxpool.Pool
	tr     *tenancy.Repo
	cat    *catalog.Catalog
	ir     *identity.Repo
	router http.Handler
	logbuf *bytes.Buffer
	org    tenancy.Organization
}

func newRouteFixture(t *testing.T) *routeFixture {
	t.Helper()
	return newRouteFixtureOn(t, testPool(t))
}

// newRouteFixtureOn is newRouteFixture against an explicit pool, for tests
// that alter the schema and so need a scratch database of their own.
func newRouteFixtureOn(t *testing.T, pool *pgxpool.Pool) *routeFixture {
	t.Helper()
	var buf bytes.Buffer
	logger := obs.New(&buf)
	f := &routeFixture{
		t: t, ctx: context.Background(), pool: pool,
		tr: tenancy.New(pool), cat: catalog.New(pool), ir: identity.NewRepo(pool),
		router: NewRouter(logger, pool, Deps{Catalog: unlimitedCatalog}), logbuf: &buf,
	}
	org, err := f.tr.CreateOrganization(f.ctx, t.Name(), "")
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	f.org = org
	return f
}

func (f *routeFixture) mustUser(name string) tenancy.User {
	f.t.Helper()
	u, err := f.tr.CreateUser(f.ctx, f.org.ID, name+"@example.test")
	if err != nil {
		f.t.Fatalf("create user %s: %v", name, err)
	}
	return u
}

func (f *routeFixture) mustAgent(sponsor tenancy.User, name string) tenancy.Agent {
	f.t.Helper()
	a, err := f.tr.CreateAgent(f.ctx, f.org.ID, sponsor.ID, name)
	if err != nil {
		f.t.Fatalf("create agent %s: %v", name, err)
	}
	return a
}

// mustAdmin creates a user holding the org-level admin role — the right
// [requireOrgAdmin] checks for token issue/revoke, and PermCreateRef /
// PermReadMetadata for the secret routes.
func (f *routeFixture) mustAdmin(name string) tenancy.User {
	f.t.Helper()
	u := f.mustUser(name)
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, u.ID, tenancy.Org(f.org.ID), string(identity.RoleAdmin)); err != nil {
		f.t.Fatalf("grant org admin to %s: %v", name, err)
	}
	return u
}

// mustStore creates a store owned by owner and immediately binds it at that
// same scope — every test in this file needs a usable store the moment it
// creates one, unlike internal/catalog's own fixture (which keeps create
// and bind separate to test chain resolution itself).
func (f *routeFixture) mustStore(name string, owner tenancy.Scope) catalog.Store {
	f.t.Helper()
	s, err := f.cat.CreateStore(f.ctx, f.org.ID, "builtin", name, owner)
	if err != nil {
		f.t.Fatalf("create store %s: %v", name, err)
	}
	if _, err := f.cat.CreateStoreBinding(f.ctx, f.org.ID, owner, s.ID); err != nil {
		f.t.Fatalf("bind store %s at %v: %v", name, owner, err)
	}
	return s
}

// mustToken mints a real bearer token for principalID and returns its
// plaintext — the one and only place that plaintext ever exists outside
// [identity.Repo.Issue] itself (see IssueResult's own doc); Reveal is
// permitted here only because this is a _test.go file (.golangci.yml's
// token-reveal exclusion).
func (f *routeFixture) mustToken(kind identity.Kind, principalID uuid.UUID, scope string) string {
	f.t.Helper()
	res, err := f.ir.Issue(f.ctx, identity.IssueParams{OrgID: f.org.ID, Kind: kind, PrincipalID: principalID, Scope: scope})
	if err != nil {
		f.t.Fatalf("issue token: %v", err)
	}
	return identity.Reveal(res.Token)
}

func (f *routeFixture) do(method, path, bearer string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			f.t.Fatalf("marshal request body: %v", err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec
}

// --- functional: positive paths ---

func TestSecretRoutes_CreateListMetaVersions(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	f.mustStore("default", tenancy.Org(f.org.ID))

	create := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/secrets", bearer, map[string]any{
		"scope_level": "org", "scope_id": f.org.ID.String(),
		"name": "db-password", "class": "credential", "type": "generic",
		"provider_ref": "builtin://default/db-password",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create secret: status = %d, body = %s", create.Code, create.Body.String())
	}
	var created Secret
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created secret: %v", err)
	}
	if created.Name != "db-password" || created.ProviderRef != "builtin://default/db-password" {
		t.Fatalf("created secret fields wrong: %+v", created)
	}

	list := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets?scope_level=org&scope_id="+f.org.ID.String(), bearer, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list secrets: status = %d, body = %s", list.Code, list.Body.String())
	}
	var secrets []Secret
	if err := json.Unmarshal(list.Body.Bytes(), &secrets); err != nil {
		t.Fatalf("unmarshal secret list: %v", err)
	}
	if len(secrets) != 1 || secrets[0].ID != created.ID {
		t.Fatalf("list secrets: got %+v, want exactly [%s]", secrets, created.ID)
	}

	meta := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets/"+created.ID, bearer, nil)
	if meta.Code != http.StatusOK {
		t.Fatalf("get secret meta: status = %d, body = %s", meta.Code, meta.Body.String())
	}

	versions := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets/"+created.ID+"/versions", bearer, nil)
	if versions.Code != http.StatusOK {
		t.Fatalf("list versions: status = %d, body = %s", versions.Code, versions.Body.String())
	}
	var vs []SecretVersion
	if err := json.Unmarshal(versions.Body.Bytes(), &vs); err != nil {
		t.Fatalf("unmarshal versions: %v", err)
	}
	if vs == nil {
		t.Fatal("versions response must be an empty array, not null, when no version has been added yet")
	}
}

// --- functional: negative / anti-oracle paths ---

func TestSecretRoutes_Unauthenticated(t *testing.T) {
	f := newRouteFixture(t)
	rec := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets?scope_level=org&scope_id="+f.org.ID.String(), "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestSecretRoutes_CreateWithoutRightsAnswers404NotDistinctFromMissingScope(t *testing.T) {
	f := newRouteFixture(t)
	plain := f.mustUser("viewer") // no membership anywhere: no create_ref right
	bearer := f.mustToken(identity.KindUser, plain.ID, "org:"+f.org.ID.String())

	rec := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/secrets", bearer, map[string]any{
		"scope_level": "org", "scope_id": f.org.ID.String(),
		"name": "x", "class": "credential", "type": "generic",
		"provider_ref": "builtin://default/x",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (never 403)", rec.Code)
	}
}

func TestSecretRoutes_MetaOfUnknownIDAnswers404(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())

	rec := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets/"+uuid.New().String(), bearer, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestSecretRoutes_InvalidProviderRefRejected(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	f.mustStore("default", tenancy.Org(f.org.ID))

	rec := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/secrets", bearer, map[string]any{
		"scope_level": "org", "scope_id": f.org.ID.String(),
		"name": "x", "class": "credential", "type": "generic",
		"provider_ref": "not-a-locator",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-locator provider_ref, body = %s", rec.Code, rec.Body.String())
	}
}

// --- functional: tokens ---

func TestTokenRoutes_IssueAndRevoke(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	adminBearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	agent := f.mustAgent(admin, "ci-agent")

	issue := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/tokens", adminBearer, map[string]any{
		"kind": "a", "principal_id": agent.ID.String(), "scope": "org:" + f.org.ID.String(),
	})
	if issue.Code != http.StatusCreated {
		t.Fatal(issueProblem(issue, "x", "x"))
	}
	var issued struct {
		Token   string `json:"token"`
		TokenID string `json:"token_id"`
	}
	if err := json.Unmarshal(issue.Body.Bytes(), &issued); err != nil {
		t.Fatal("unmarshal issue response failed (body suppressed)")
	}
	if msg := issueProblem(issue, issued.Token, issued.TokenID); msg != "" {
		t.Fatal(msg)
	}

	// The minted token authenticates.
	rec := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets?scope_level=org&scope_id="+f.org.ID.String(), issued.Token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("minted token failed to authenticate: status = %d", rec.Code)
	}

	revoke := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/tokens/"+issued.TokenID+"/revoke", adminBearer, nil)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke: status = %d, body = %s", revoke.Code, revoke.Body.String())
	}

	// The revoked token no longer authenticates.
	rec = f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets?scope_level=org&scope_id="+f.org.ID.String(), issued.Token, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token still authenticates: status = %d", rec.Code)
	}
}

func TestTokenRoutes_IssueByNonAdminAnswers404(t *testing.T) {
	f := newRouteFixture(t)
	plain := f.mustUser("member")
	bearer := f.mustToken(identity.KindUser, plain.ID, "org:"+f.org.ID.String())
	agent := f.mustAgent(plain, "ci-agent")

	rec := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/tokens", bearer, map[string]any{
		"kind": "a", "principal_id": agent.ID.String(), "scope": "org:" + f.org.ID.String(),
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (never 403)", rec.Code)
	}
}

// TestTokenRoutes_IssueRejectsMalformedOrForeignScope: req.Scope reached
// identity.Repo.Issue as free text, unvalidated, and is copied verbatim
// into every audit record the token's
// actions later produce. A scope that doesn't parse as level:uuid, or that
// names an org level other than the caller's own, must be rejected before
// it ever reaches the journal.
func TestTokenRoutes_IssueRejectsMalformedOrForeignScope(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	adminBearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	agent := f.mustAgent(admin, "ci-agent")

	otherOrg, err := f.tr.CreateOrganization(f.ctx, t.Name()+"-other", "")
	if err != nil {
		t.Fatalf("create other organization: %v", err)
	}

	for _, scope := range []string{
		"not-a-scope-at-all",
		"org:not-a-uuid",
		"org:" + otherOrg.ID.String(),
		"planet:" + f.org.ID.String(),
		strings.Repeat("x", 200),
	} {
		t.Run(scope, func(t *testing.T) {
			rec := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/tokens", adminBearer, map[string]any{
				"kind": "a", "principal_id": agent.ID.String(), "scope": scope,
			})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("scope = %q: status = %d, want 400, body length = %d (body suppressed)", scope, rec.Code, rec.Body.Len())
			}
		})
	}
}

// --- guard (b): canary sweep across every new route, plus cross-org isolation ---

// TestNewRoutesNeverLeakCanary sweeps every one of this package's new
// routes with two independent canaries: content (a secret's own name+description,
// which the API legitimately echoes back wherever it shows that secret) and
// probe (sent only as a header, with no legitimate destination anywhere).
// Neither may ever reach a response header, the structured log, or the
// R-AUD-1 journal's own columns beyond the one (secret_name) the audit
// package's own doc says legitimately carries a secret's name — see
// keep-leak-test-first: a canary surviving detection on any of these
// surfaces is exactly the class of bug §4.1 exists to prevent.
func TestNewRoutesNeverLeakCanary(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	f.mustStore("default", tenancy.Org(f.org.ID))
	agent := f.mustAgent(admin, "ci-agent")

	content := canary.New()
	probe := canary.New()
	name := "sec-" + content.Value(1)
	desc := content.Value(2)
	headerProbe := probe.Value(1)

	doProbed := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var r *http.Request
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal request body: %v", err)
			}
			r = httptest.NewRequest(method, path, bytes.NewReader(b))
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("Authorization", "Bearer "+bearer)
		r.Header.Set("X-Canary-Probe", headerProbe)
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, r)
		return rec
	}

	create := doProbed(http.MethodPost, "/orgs/"+f.org.ID.String()+"/secrets", map[string]any{
		"scope_level": "org", "scope_id": f.org.ID.String(),
		"name": name, "class": "credential", "type": "generic",
		"provider_ref": "builtin://default/" + name, "description": desc,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create secret: status = %d, body = %s", create.Code, create.Body.String())
	}
	assertProbeAndHeadersClean(t, probe, content, create)
	var created Secret
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created secret: %v", err)
	}

	meta := doProbed(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets/"+created.ID, nil)
	if meta.Code != http.StatusOK {
		t.Fatalf("get meta: status = %d, body = %s", meta.Code, meta.Body.String())
	}
	assertProbeAndHeadersClean(t, probe, content, meta)
	if !content.In(meta.Body.String()) {
		t.Fatal("content canary did not appear even in the field that legitimately carries it (secret name/description) — the detector is blind, this test proves nothing")
	}

	list := doProbed(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets?scope_level=org&scope_id="+f.org.ID.String(), nil)
	assertProbeAndHeadersClean(t, probe, content, list)
	if !content.In(list.Body.String()) {
		t.Fatal("content canary did not appear in the list response — detector is blind, this test proves nothing")
	}

	versions := doProbed(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets/"+created.ID+"/versions", nil)
	assertProbeAndHeadersClean(t, probe, content, versions)

	issue := doProbed(http.MethodPost, "/orgs/"+f.org.ID.String()+"/tokens", map[string]any{
		"kind": "a", "principal_id": agent.ID.String(), "scope": "org:" + f.org.ID.String(),
	})
	if msg := issueProblem(issue, "x", "x"); msg != "" {
		t.Fatal(msg)
	}
	assertProbeAndHeadersClean(t, probe, content, issue)
	var issued struct {
		TokenID string `json:"token_id"`
	}
	if err := json.Unmarshal(issue.Body.Bytes(), &issued); err != nil {
		t.Fatalf("unmarshal issue response: %v", err)
	}

	revoke := doProbed(http.MethodPost, "/orgs/"+f.org.ID.String()+"/tokens/"+issued.TokenID+"/revoke", nil)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke: status = %d, body = %s", revoke.Code, revoke.Body.String())
	}
	assertProbeAndHeadersClean(t, probe, content, revoke)

	if content.In(f.logbuf.String()) {
		t.Errorf("content canary leaked into log output:\n%s", f.logbuf.String())
	}
	if probe.In(f.logbuf.String()) {
		t.Errorf("probe canary leaked into log output:\n%s", f.logbuf.String())
	}

	rows, err := f.pool.Query(f.ctx, `SELECT * FROM audit_records WHERE org_id = $1`, f.org.ID.String())
	if err != nil {
		t.Fatalf("query audit_records: %v", err)
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	found := 0
	for rows.Next() {
		found++
		vals, err := rows.Values()
		if err != nil {
			t.Fatalf("scan audit_records row: %v", err)
		}
		for i, v := range vals {
			col := fields[i].Name
			if col == "secret_name" {
				// The one column this test expects to legitimately carry
				// the content canary — audit.SecretRef.Name is the
				// secret's own name (internal/audit's own doc).
				continue
			}
			s := fmt.Sprintf("%v", v)
			if content.In(s) {
				t.Errorf("content canary leaked into audit_records.%s: %v", col, v)
			}
			if probe.In(s) {
				t.Errorf("probe canary leaked into audit_records.%s: %v", col, v)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit_records: %v", err)
	}
	if found == 0 {
		t.Fatal("no audit_records row was written for this org — the journal check ran against nothing, proves nothing")
	}

	if !probe.In("prefix "+probe.Value(9)) || !content.In("prefix "+content.Value(9)) {
		t.Fatal("canary detector is blind; this test proves nothing")
	}
}

// leakySurfaces is the one leak check both TestNewRoutesNeverLeakCanary
// (against the real router) and its own _RedRun proof (against a
// deliberately leaky fixture, below) call — a private closure duplicated
// between the two, or a RedRun using its own separate check, would let a
// regression in this exact detection logic go unnoticed by the RedRun test,
// which is meant to prove THIS check can fail, not just that canary.In
// itself is capable of matching something somewhere (that narrower property
// has its own assertion at the end of TestNewRoutesNeverLeakCanary). It
// returns one description per leak found, nil when the response is clean —
// a plain value rather than a *testing.T call so the RedRun proof can
// assert on it without depending on any testing.T internals. The probe has
// no legitimate destination on any surface: never in a body, and never in
// a header regardless of which canary it is.
func leakySurfaces(probe, content canary.Canary, rec *httptest.ResponseRecorder) []string {
	var found []string
	if probe.In(rec.Body.String()) {
		found = append(found, fmt.Sprintf("probe canary leaked into response body: %s", rec.Body.String()))
	}
	for k, vs := range rec.Header() {
		for _, v := range vs {
			if content.In(v) || probe.In(v) {
				found = append(found, fmt.Sprintf("canary leaked into response header %s: %q", k, v))
			}
		}
	}
	return found
}

func assertProbeAndHeadersClean(t *testing.T, probe, content canary.Canary, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, msg := range leakySurfaces(probe, content, rec) {
		t.Error(msg)
	}
}

// TestNewRoutesNeverLeakCanary_RedRun proves leakySurfaces itself — the
// exact function TestNewRoutesNeverLeakCanary relies on, not a disconnected
// inline check — catches a real leak: a deliberately leaky handler echoes
// the probe header straight into the response body, and leakySurfaces must
// report it. Without calling that same function, a regression in its own
// logic (e.g. a dropped `||`, a header loop that never ranges) would leave
// TestNewRoutesNeverLeakCanary green for the wrong reason, and this RedRun
// would never catch it — exactly the "check that cannot fail" keep-red-run
// exists to rule out.
func TestNewRoutesNeverLeakCanary_RedRun(t *testing.T) {
	probe := canary.New()
	content := canary.New()
	leaked := probe.Value(1)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /leaky", func(w http.ResponseWriter, r *http.Request) {
		// #nosec G705 -- deliberately unsafe: this handler exists only to prove
		// the leak detector below can actually fail (keep-red-run), never served
		// outside this test.
		_, _ = w.Write([]byte(`{"echo":"` + r.Header.Get("X-Canary-Probe") + `"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/leaky", nil)
	req.Header.Set("X-Canary-Probe", leaked)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if len(leakySurfaces(probe, content, rec)) == 0 {
		t.Fatal("leakySurfaces did not catch the fixture's real leak; the guard the main test relies on cannot fail, this red-run proves nothing")
	}
}

// TestSecretRoutes_CrossOrgIsolation: a secret created in org A must never
// appear in org B's list or be reachable by its id under org B's own path
// — the closed anti-oracle guarantee extended across organizations, not
// just scopes within one.
func TestSecretRoutes_CrossOrgIsolation(t *testing.T) {
	fa := newRouteFixture(t)
	adminA := fa.mustAdmin("admin-a")
	bearerA := fa.mustToken(identity.KindUser, adminA.ID, "org:"+fa.org.ID.String())
	fa.mustStore("default", tenancy.Org(fa.org.ID))

	c := canary.New()
	name := "cross-org-" + c.Value(1)
	create := fa.do(http.MethodPost, "/orgs/"+fa.org.ID.String()+"/secrets", bearerA, map[string]any{
		"scope_level": "org", "scope_id": fa.org.ID.String(),
		"name": name, "class": "credential", "type": "generic",
		"provider_ref": "builtin://default/" + name,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create secret in org A: status = %d, body = %s", create.Code, create.Body.String())
	}
	var created Secret
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created secret: %v", err)
	}

	// A second org, sharing the same router and database, with its own
	// admin — never granted any right in org A.
	orgB, err := fa.tr.CreateOrganization(fa.ctx, t.Name()+"-b", "")
	if err != nil {
		t.Fatalf("create organization B: %v", err)
	}
	adminB, err := fa.tr.CreateUser(fa.ctx, orgB.ID, "admin-b@example.test")
	if err != nil {
		t.Fatalf("create user in org B: %v", err)
	}
	if _, err := fa.tr.CreateMembership(fa.ctx, orgB.ID, adminB.ID, tenancy.Org(orgB.ID), string(identity.RoleAdmin)); err != nil {
		t.Fatalf("grant org B admin: %v", err)
	}
	issuedB, err := fa.ir.Issue(fa.ctx, identity.IssueParams{OrgID: orgB.ID, Kind: identity.KindUser, PrincipalID: adminB.ID, Scope: "org:" + orgB.ID.String()})
	if err != nil {
		t.Fatalf("issue token for org B admin: %v", err)
	}
	bearerB := identity.Reveal(issuedB.Token)

	// org B's own admin, using org A's URL, is rejected before rights even
	// come into it — RequireOrgMatch's own 404-never-403 contract.
	rec := fa.do(http.MethodGet, "/orgs/"+fa.org.ID.String()+"/secrets/"+created.ID, bearerB, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("org B's token against org A's URL: status = %d, want 404", rec.Code)
	}
	if c.In(rec.Body.String()) {
		t.Errorf("cross-org 404 leaked the secret's canary name: %s", rec.Body.String())
	}

	// org B's own list, at its own org_id, must never include org A's row.
	listB := fa.do(http.MethodGet, "/orgs/"+orgB.ID.String()+"/secrets?scope_level=org&scope_id="+orgB.ID.String(), bearerB, nil)
	if listB.Code != http.StatusOK {
		t.Fatalf("list in org B: status = %d, body = %s", listB.Code, listB.Body.String())
	}
	if c.In(listB.Body.String()) {
		t.Errorf("org B's own secret list leaked org A's canary-named secret: %s", listB.Body.String())
	}
}

// TestSecretRoutes_UserScopeIsolation proves a scope_level=user query names
// only the caller's own personal scope, never another principal's:
// [catalog.PermissionsAt] exposes principalPermissions directly (unlike
// [catalog.ResolveAuthorized],
// which only ever reaches principalPermissions' user-level branch through a
// scope [tenancy.Repo.Resolve] itself seated at the requesting principal's
// own effective user id), so a scope named by request input, not by
// Resolve's chain, could borrow the unconditional admin/grant rights that
// branch hands out for ANY user-level scope.id. A second org member (plain
// user, and separately an agent sponsored by someone else) must see the
// victim's personal-scope list as empty and be refused create_ref there —
// the same anti-oracle shapes org isolation already uses — while the
// victim's own personal-scope access (the positive control) keeps working.
func TestSecretRoutes_UserScopeIsolation(t *testing.T) {
	f := newRouteFixture(t)
	victim := f.mustUser("victim")
	victimBearer := f.mustToken(identity.KindUser, victim.ID, "user:"+victim.ID.String())
	victimScope := tenancy.Scope{Level: tenancy.LevelUser, ID: victim.ID}
	f.mustStore("victim-store", victimScope)

	c := canary.New()
	name := "personal-" + c.Value(1)
	create := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/secrets", victimBearer, map[string]any{
		"scope_level": "user", "scope_id": victim.ID.String(),
		"name": name, "class": "credential", "type": "generic",
		"provider_ref": "builtin://victim-store/" + name,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("positive control: victim creates in own personal scope: status = %d, body = %s", create.Code, create.Body.String())
	}

	listOwn := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets?scope_level=user&scope_id="+victim.ID.String(), victimBearer, nil)
	if listOwn.Code != http.StatusOK {
		t.Fatalf("positive control: victim lists own personal scope: status = %d, body = %s", listOwn.Code, listOwn.Body.String())
	}
	var ownSecrets []Secret
	if err := json.Unmarshal(listOwn.Body.Bytes(), &ownSecrets); err != nil || len(ownSecrets) != 1 {
		t.Fatalf("positive control: victim's own list = %s, %v; want exactly one row", listOwn.Body.String(), err)
	}

	// A second org member, with no relationship to the victim at all, asking
	// about the victim's personal scope by id.
	stranger := f.mustUser("stranger")
	strangerBearer := f.mustToken(identity.KindUser, stranger.ID, "org:"+f.org.ID.String())
	strangerAgent := f.mustAgent(stranger, "stranger-agent")
	strangerAgentBearer := f.mustToken(identity.KindAgent, strangerAgent.ID, "org:"+f.org.ID.String())

	for _, tc := range []struct {
		name   string
		bearer string
	}{
		{"user", strangerBearer},
		{"agent sponsored by a different user", strangerAgentBearer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets?scope_level=user&scope_id="+victim.ID.String(), tc.bearer, nil)
			if list.Code != http.StatusOK {
				t.Fatalf("list victim's personal scope: status = %d, want 200 (empty, not 403 — no-oracle rule)", list.Code)
			}
			var got []Secret
			if err := json.Unmarshal(list.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal list: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("listed %d of the victim's personal-scope secrets: user_id predicate missing — %s", len(got), list.Body.String())
			}
			if c.In(list.Body.String()) {
				t.Errorf("victim's personal-scope list leaked the canary name: %s", list.Body.String())
			}

			create := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/secrets", tc.bearer, map[string]any{
				"scope_level": "user", "scope_id": victim.ID.String(),
				"name": "attacker-planted", "class": "credential", "type": "generic",
				"provider_ref": "builtin://victim-store/attacker-planted",
			})
			if create.Code != http.StatusNotFound {
				t.Fatalf("create in victim's personal scope: status = %d, want 404 (never 403, and never 201): body = %s", create.Code, create.Body.String())
			}
		})
	}
}

// TestTokenRoutes_IssueRejectsAgentSponsoredByAnotherUser closes the bypass
// TestSecretRoutes_UserScopeIsolation's isolation would otherwise still
// leave open: [catalog.PermissionsAt] refuses an org admin DIRECT access to
// a victim's personal scope, but principalPermissions grants every agent
// token DefaultAgentGrants (read_metadata, deploy) at its sponsor's own
// personal scope unconditionally. Before this test's fix, an org admin
// could mint a token for a victim's own agent through this same route and
// use it to read the victim's personal-scope secrets — the exact isolation
// the direct-access check above exists to prevent, reached indirectly.
func TestTokenRoutes_IssueRejectsAgentSponsoredByAnotherUser(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	adminBearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())

	victim := f.mustUser("victim")
	victimBearer := f.mustToken(identity.KindUser, victim.ID, "user:"+victim.ID.String())
	victimScope := tenancy.Scope{Level: tenancy.LevelUser, ID: victim.ID}
	f.mustStore("victim-store", victimScope)
	victimAgent := f.mustAgent(victim, "victim-agent")

	c := canary.New()
	name := "personal-" + c.Value(1)
	create := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/secrets", victimBearer, map[string]any{
		"scope_level": "user", "scope_id": victim.ID.String(),
		"name": name, "class": "credential", "type": "generic",
		"provider_ref": "builtin://victim-store/" + name,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("positive control: victim creates in own personal scope: status = %d, body = %s", create.Code, create.Body.String())
	}

	issue := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/tokens", adminBearer, map[string]any{
		"kind": "a", "principal_id": victimAgent.ID.String(), "scope": "user:" + victim.ID.String(),
	})
	if issue.Code != http.StatusNotFound {
		// The body is never printed here, even on failure: a 201 on this path
		// means the bypass this test exists to catch has reopened, and the
		// body would then be a live, real bearer token, not a fixture value —
		// exactly the class of test-output leak keep-leak-test-first exists
		// to prevent.
		t.Fatalf("admin minting a token for the victim's own agent: status = %d, want 404 (never 403, and never 201)", issue.Code)
	}
	if c.In(issue.Body.String()) {
		t.Errorf("token-issue refusal body leaked the canary name: %s", issue.Body.String())
	}

	// The refusal must be at issuance, not merely at use: no token this
	// admin could have obtained through this route may see the victim's
	// personal-scope secret at all.
	list := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/secrets?scope_level=user&scope_id="+victim.ID.String(), adminBearer, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("admin lists victim's personal scope directly: status = %d, want 200 (empty, no-oracle rule)", list.Code)
	}
	if c.In(list.Body.String()) {
		t.Fatalf("admin's direct list leaked the victim's canary-named secret: %s", list.Body.String())
	}
}
