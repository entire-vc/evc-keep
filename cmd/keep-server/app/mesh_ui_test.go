package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/meshfake"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// fakeKeyLevels stands in for the audit-backed change side, which the server
// does not wire yet. It records every call so a refusal can be shown to have
// reached nothing.
// fakeChangedAfter is the time Change records, far from the seeded one.
var fakeChangedAfter = time.Date(2031, 3, 4, 5, 6, 0, 0, time.UTC)

type fakeKeyLevels struct {
	mu      sync.Mutex
	level   string
	calls   int
	weaken  bool
	changed time.Time
	by      string
}

func (k *fakeKeyLevels) Get(context.Context, uuid.UUID) (api.KeyLevelState, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return api.KeyLevelState{Level: k.level, ChangedAt: k.changed, ChangedBy: k.by}, nil
}

func (k *fakeKeyLevels) Change(_ context.Context, _, _ uuid.UUID, to string, confirm bool) (api.KeyLevelChange, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls++
	if to != "user" && to != "project" && to != "workspace" && to != "organization" {
		return api.KeyLevelChange{}, api.ErrKeyLevelInvalid
	}
	if k.weaken && !confirm {
		return api.KeyLevelChange{}, api.ErrKeyLevelWeakening
	}
	k.level, k.changed, k.by = to, fakeChangedAfter, "actor-after"
	return api.KeyLevelChange{Level: to, Rewrapped: 3, Unchanged: 1, Retired: 2}, nil
}

type uiFixture struct {
	*sessionFixture
	kl *fakeKeyLevels
}

func newUIFixture(t *testing.T) *uiFixture {
	t.Helper()
	kl := &fakeKeyLevels{level: "user", by: "actor-before", changed: time.Now().Add(-time.Hour)}
	f := newMeshFixtureOn(t, testPool(t), true, func(d *api.MeshDeps) { d.KeyLevels = kl })
	m := meshfake.New(meshfake.NewKey("k1"))
	t.Cleanup(m.Close)
	ws := uuid.New()
	cn := canary.New()
	b, _ := json.Marshal(map[string]string{"mesh_url": m.URL(), "workspace_id": ws.String(),
		"extension_token": cn.Value(8), "events_endpoint_secret": cn.Value(9)})
	if rec := f.post("/mesh/install", f.admin, b, nil); rec.Code != http.StatusOK {
		t.Fatalf("install: %d", rec.Code)
	}
	return &uiFixture{sessionFixture: &sessionFixture{meshFixture: f, mesh: m, ws: ws}, kl: kl}
}

const uiCookie = "keep_mesh_ui"

func (f *uiFixture) get(path string, cookie string, hdr map[string]string, tlsOn bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if tlsOn {
		r.TLS = &tls.ConnectionState{}
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: uiCookie, Value: cookie}) //nolint:gosec // G124: test client cookie, attributes are the server's concern
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec
}

func (f *uiFixture) postForm(path, cookie string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: uiCookie, Value: cookie}) //nolint:gosec // G124: test client cookie, attributes are the server's concern
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec
}

// login opens the screen the way Mesh does (?token=) and returns the cookie.
func (f *uiFixture) login(sub, email string) string {
	f.t.Helper()
	rec := f.get("/mesh/ui/secrets?token="+url.QueryEscape(f.token(sub, email)), "", nil, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/mesh/ui/secrets" {
		f.t.Fatalf("login: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == uiCookie {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteNoneMode || !c.Partitioned || c.Path != "/mesh/ui" {
				f.t.Fatalf("cookie attributes: %+v", c)
			}
			return c.Value
		}
	}
	f.t.Fatal("no screen cookie")
	return ""
}

func (f *uiFixture) grant(sub string, role identity.Role) {
	f.t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT id FROM users WHERE org_id=$1 AND external_ref LIKE $2`, f.org.ID, "%:"+meshSub(sub)).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	if _, err := tenancy.New(f.pool).CreateMembership(context.Background(), f.org.ID, id, tenancy.Org(f.org.ID), string(role)); err != nil {
		f.t.Fatal(err)
	}
}

// directive returns the source list of one CSP directive.
func directive(csp, name string) []string {
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) > 0 && f[0] == name {
			return f[1:]
		}
	}
	return nil
}

func hostOrigin(t *testing.T, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Scheme + "://" + u.Host
}

func TestMeshUIFrameAncestorsAreOnlyTheInstalledMesh(t *testing.T) {
	f := newUIFixture(t)
	ck := f.login("u1", "u1@example.test")
	want := hostOrigin(t, f.mesh.URL())
	// The request cannot move the policy: hostile headers are ignored.
	hostile := []map[string]string{nil,
		{"Origin": "https://evil.example.test", "Referer": "https://evil.example.test/x"},
		{"X-Forwarded-Host": "evil.example.test", "X-Forwarded-Proto": "https", "Forwarded": "host=evil.example.test"},
		{"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Site": "cross-site", "Origin": want + ".evil.example.test"}}
	for _, p := range []string{"/mesh/ui/secrets", "/mesh/ui/settings"} {
		for i, h := range hostile {
			rec := f.get(p, ck, h, true)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s #%d: %d", p, i, rec.Code)
			}
			csp := rec.Header().Get("Content-Security-Policy")
			if got := directive(csp, "frame-ancestors"); len(got) != 1 || got[0] != want {
				t.Fatalf("%s #%d: frame-ancestors = %v, want only %s (csp %q)", p, i, got, want, csp)
			}
			if strings.Contains(csp, "evil") || strings.Contains(csp, "unsafe") || strings.Contains(csp, "*") {
				t.Fatalf("csp is loose: %q", csp)
			}
			if got := directive(csp, "script-src"); len(got) != 1 || got[0] != "'self'" {
				t.Fatalf("script-src = %v", got)
			}
			if rec.Header().Get("X-Frame-Options") != "" {
				t.Fatal("X-Frame-Options would block the Mesh frame")
			}
		}
	}
	// Positive control for the harness: the directive reader sees a planted second origin.
	if got := directive("default-src 'none'; frame-ancestors "+want+" https://evil.example.test", "frame-ancestors"); len(got) != 2 {
		t.Fatal("directive reader is blind")
	}
}

func TestMeshUIRefusesWithoutAValidContext(t *testing.T) {
	f := newUIFixture(t)
	good := f.token("u1", "u1@example.test")
	parts := strings.Split(good, ".")
	other := sign(f.mesh.Key0(0), nil, f.mesh.Valid(uuid.NewString(), meshSub("u1"), "u1@example.test")) // workspace not installed
	cases := map[string]string{                                                                          //nolint:gosec // G101: a URL path, not a credential
		"no token":       "/mesh/ui/secrets",
		"garbage":        "/mesh/ui/secrets?token=x.y.z",
		"foreign key":    "/mesh/ui/secrets?token=" + sign(meshfake.NewKey("k1"), nil, f.mesh.Valid(f.ws.String(), meshSub("u1"), "u1@example.test")),
		"uninstalled ws": "/mesh/ui/secrets?token=" + other,
		"alg none":       "/mesh/ui/secrets?token=" + parts[0] + "." + parts[1] + ".",
		"settings":       "/mesh/ui/settings",
	}
	for name, p := range cases {
		rec := f.get(p, "", nil, true)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
		for _, c := range rec.Result().Cookies() {
			t.Errorf("%s: set cookie %s", name, c.Name)
		}
		if strings.Contains(rec.Body.String(), "<table") {
			t.Errorf("%s: secrets table in a refusal", name)
		}
		// The signed-out screen names the product, as the Mesh sidebar does.
		if !strings.Contains(rec.Body.String(), "<h1>Keep</h1>") {
			t.Errorf("%s: signed-out screen does not say Keep", name)
		}
		// A refusal never names a framing origin it cannot vouch for.
		anc := directive(rec.Header().Get("Content-Security-Policy"), "frame-ancestors")
		if name == "uninstalled ws" || name == "no token" || name == "settings" {
			if len(anc) != 1 || anc[0] != "'none'" {
				t.Errorf("%s: frame-ancestors = %v, want 'none'", name, anc)
			}
		}
	}
	// Cookies that are not this screen's session: a random one and the console's.
	if rec := f.get("/mesh/ui/secrets", "not-a-session-handle-0000", nil, true); rec.Code != http.StatusUnauthorized {
		t.Errorf("forged cookie: %d", rec.Code)
	}
	console := sessionCookie(f.signIn(good))
	if rec := f.get("/mesh/ui/secrets", console.Value+"x", nil, true); rec.Code != http.StatusUnauthorized {
		t.Errorf("tampered handle: %d", rec.Code)
	}
	// Positive control: the same request with the good token passes.
	if rec := f.get("/mesh/ui/secrets?token="+url.QueryEscape(good), "", nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("harness refuses a valid token: %d", rec.Code)
	}
	// A session handle that came from the agent kind, not a person, is no session of this screen.
	if f.count(`SELECT count(*) FROM users WHERE external_ref LIKE 'mesh:%' AND org_id=$1`, f.org.ID) != 1 {
		t.Fatal("refusals created users")
	}
}

func TestMeshUISessionRouteRefusesForeignOriginAndPlainHTTP(t *testing.T) {
	f := newUIFixture(t)
	body, _ := json.Marshal(map[string]string{"token": f.token("u1", "u1@example.test")})
	ok := map[string]string{"Sec-Fetch-Site": "same-origin", "Content-Type": "application/json"}
	if rec := f.post("/mesh/ui/session", "", body, ok); rec.Code != http.StatusOK {
		t.Fatalf("same-origin JSON refused: %d", rec.Code)
	}
	for name, h := range map[string]map[string]string{
		"cross-site":     {"Sec-Fetch-Site": "cross-site", "Content-Type": "application/json"},
		"foreign Origin": {"Origin": "https://evil.example.test", "Content-Type": "application/json"},
		"form post":      {"Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded"},
		"no headers":     {"Content-Type": "application/json"},
	} {
		rec := f.post("/mesh/ui/session", "", body, h)
		if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: %d cookies=%d", name, rec.Code, len(rec.Result().Cookies()))
		}
	}
	if rec := f.send("/mesh/ui/session", "", body, ok, false); rec.Code != http.StatusNotFound {
		t.Errorf("plain HTTP: %d", rec.Code)
	}
	if rec := f.post("/mesh/ui/session", "", []byte(`{"token":"x.y.z"}`), ok); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", rec.Code)
	}
	if rec := f.post("/mesh/ui/session", "", []byte(`{"token":"`+f.token("u1", "u1@example.test")+`","extra":1}`), ok); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", rec.Code)
	}
}

func TestMeshUIAbsentWhenExtensionOffOrPlainHTTP(t *testing.T) {
	f := newUIFixture(t)
	if rec := f.get("/mesh/ui/secrets", "", nil, false); rec.Code != http.StatusNotFound {
		t.Fatalf("plain HTTP served the screen: %d", rec.Code)
	}
	off := newMeshFixture(t, false)
	for _, p := range []string{"/mesh/ui/secrets", "/mesh/ui/settings", "/mesh/ui/app.js", "/mesh/ui/app.css"} {
		if rec := (&uiFixture{sessionFixture: &sessionFixture{meshFixture: off}}).get(p, "", nil, true); rec.Code != http.StatusNotFound {
			t.Fatalf("%s exists with the extension off: %d", p, rec.Code)
		}
	}
}

// seedSecret registers a secret whose value really sits sealed in the store,
// so a leak has something to leak.
func (f *uiFixture) seedSecret(name string, value string) {
	f.t.Helper()
	ctx := context.Background()
	local := f.local
	cat := catalog.New(f.pool)
	org := tenancy.Org(f.org.ID)
	storeID, err := cat.ResolveStore(ctx, f.org.ID, []tenancy.Scope{org})
	if err != nil { // the first secret of the org: bind a store
		st, err := cat.CreateStore(ctx, f.org.ID, "builtin", "ui-store", org)
		if err != nil {
			f.t.Fatal(err)
		}
		if _, err := cat.CreateStoreBinding(ctx, f.org.ID, org, st.ID); err != nil {
			f.t.Fatal(err)
		}
		storeID = st.ID
	}
	ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: org, Name: name, Class: "api_token", Type: "token", ProviderRef: "builtin://default/" + name, StoreID: storeID})
	if err != nil {
		f.t.Fatal(err)
	}
	meta, err := local.Provider(f.org.ID.String(), "", "", "").Write(ctx, provider.Ref{Path: "builtin://default/" + name}, secret.New([]byte(value)))
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := cat.AddVersion(ctx, f.org.ID, ref.ID, meta.Version, "kfp1:k1:ABCDEFGHIJKLMNOP", len(value)); err != nil {
		f.t.Fatal(err)
	}
}

func TestMeshUIListsOnlyTheClosedFieldsAndNeverTheValue(t *testing.T) {
	f := newUIFixture(t)
	cn := canary.New()
	if !cn.In("x"+cn.Value(1)) || !cn.In(strings.ToUpper(cn.Value(1))) {
		t.Fatal("canary detector is blind")
	}
	f.seedSecret("deploy-token", cn.Value(1))
	f.seedSecret("<script>hostile</script>", cn.Value(2))
	f.seedSecret("db-password", cn.Value(2))
	ck := f.login("viewer", "viewer@example.test")
	// A person with no role at the org sees nothing, whatever the table holds.
	if rec := f.get("/mesh/ui/secrets", ck, nil, true); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "deploy-token") {
		t.Fatalf("a person with no role saw the catalog: %d", rec.Code)
	}
	f.grant("viewer", identity.RoleViewer)

	surfaces := map[string]*httptest.ResponseRecorder{}
	for name, p := range map[string]string{ //nolint:gosec // G101: URL paths, not credentials
		"secrets": "/mesh/ui/secrets", "filtered": "/mesh/ui/secrets?q=deploy", "class": "/mesh/ui/secrets?class=api_token",
		"nomatch": "/mesh/ui/secrets?q=zzz", "settings": "/mesh/ui/settings", "js": "/mesh/ui/app.js", "css": "/mesh/ui/app.css",
	} {
		surfaces[name] = f.get(p, ck, nil, true)
		if surfaces[name].Code != http.StatusOK {
			t.Fatalf("%s: %d", name, surfaces[name].Code)
		}
	}
	page := surfaces["secrets"].Body.String()
	for _, w := range []string{"deploy-token", "db-password", "kfp1:k1:ABCDEFGHIJKLMNOP", "api_token"} {
		if !strings.Contains(page, w) {
			t.Fatalf("closed field %q missing from the list", w)
		}
	}
	if strings.Contains(surfaces["filtered"].Body.String(), "db-password") || !strings.Contains(surfaces["filtered"].Body.String(), "deploy-token") {
		t.Fatal("the name filter does not filter")
	}
	if !strings.Contains(surfaces["nomatch"].Body.String(), "No secret matches") {
		t.Fatal("empty filter state missing")
	}
	// The raw form of a hostile name is escaped, not interpreted.
	if !strings.Contains(page, "&lt;script&gt;hostile") || strings.Contains(page, "<script>hostile") {
		t.Fatal("a hostile secret name is not escaped on the list")
	}
	for name, rec := range surfaces {
		all := rec.Body.String()
		for k, v := range rec.Header() {
			all += "\n" + k + ": " + strings.Join(v, ",")
		}
		if cn.In(all) {
			t.Fatalf("canary on the %s surface", name)
		}
		if name != "js" && name != "css" && strings.Contains(all, "<script>") {
			t.Fatalf("inline script on %s", name)
		}
	}
	if cn.In(f.logbuf.String()) {
		t.Fatal("canary in the log")
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	// The stored session holds a hash, not the cookie handle.
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM console_sessions t WHERE row_to_json(t)::text LIKE '%'||$1||'%'`, ck).Scan(&n); err != nil || n != 0 {
		t.Fatalf("session handle stored in the clear (%v, %d)", err, n)
	}
}

func TestMeshUIKeyLevelSettings(t *testing.T) {
	f := newUIFixture(t)
	member := f.login("member", "m@example.test")
	f.grant("member", identity.RoleMember)
	admin := f.login("boss", "b@example.test")
	f.grant("boss", identity.RoleAdmin)

	csrfOf := func(body string) string {
		const mark = `name="csrf" value="`
		i := strings.Index(body, mark)
		if i < 0 {
			return ""
		}
		rest := body[i+len(mark):]
		return rest[:strings.Index(rest, `"`)]
	}
	form := func(csrf, level string, confirm bool) url.Values {
		v := url.Values{"csrf": {csrf}, "level": {level}}
		if confirm {
			v.Set("confirm_weakening", "yes")
		}
		return v
	}
	// A member reads the level and gets no form.
	mp := f.get("/mesh/ui/settings", member, nil, true)
	if mp.Code != http.StatusOK || !strings.Contains(mp.Body.String(), "<strong>user</strong>") || strings.Contains(mp.Body.String(), "<form") {
		t.Fatalf("member page: %d form=%v", mp.Code, strings.Contains(mp.Body.String(), "<form"))
	}
	ap := f.get("/mesh/ui/settings", admin, nil, true)
	csrf := csrfOf(ap.Body.String())
	if csrf == "" {
		t.Fatal("admin gets no form")
	}
	// The member has a valid session and CSRF token: only the role refuses.
	memberCSRF, err := identity.NewRepo(f.pool).LookupSession(context.Background(), member)
	if err != nil || memberCSRF.CSRF == "" {
		t.Fatalf("member session: %v", err)
	}
	// Refusals that must not reach the change.
	f.kl.weaken = true
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"member":       f.postForm("/mesh/ui/settings/key-level", member, form(memberCSRF.CSRF, "organization", true), nil),
		"no csrf":      f.postForm("/mesh/ui/settings/key-level", admin, form("", "organization", true), nil),
		"wrong csrf":   f.postForm("/mesh/ui/settings/key-level", admin, form("x"+csrf, "organization", true), nil),
		"member csrf":  f.postForm("/mesh/ui/settings/key-level", admin, form(csrfOf(mp.Body.String()), "organization", true), nil),
		"foreign site": f.postForm("/mesh/ui/settings/key-level", admin, form(csrf, "organization", true), map[string]string{"Sec-Fetch-Site": "cross-site"}),
		"foreign orig": f.postForm("/mesh/ui/settings/key-level", admin, form(csrf, "organization", true), map[string]string{"Origin": "https://evil.example.test"}),
		"no session":   f.postForm("/mesh/ui/settings/key-level", "", form(csrf, "organization", true), nil),
	} {
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d", name, rec.Code)
		}
	}
	if f.kl.calls != 0 {
		t.Fatalf("a refused request reached the change (%d calls)", f.kl.calls)
	}
	// Weakening needs its own confirmation; a bad level is refused.
	if rec := f.postForm("/mesh/ui/settings/key-level", admin, form(csrf, "organization", false), nil); rec.Code != http.StatusConflict || f.kl.level != "user" {
		t.Fatalf("unconfirmed weakening: %d level=%s", rec.Code, f.kl.level)
	}
	if rec := f.postForm("/mesh/ui/settings/key-level", admin, form(csrf, "everyone", true), nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid level: %d", rec.Code)
	}
	rec := f.postForm("/mesh/ui/settings/key-level", admin, form(csrf, "organization", true), nil)
	if rec.Code != http.StatusOK || f.kl.level != "organization" || !strings.Contains(rec.Body.String(), "Re-wrapped 3, unchanged 1, retired 2") {
		t.Fatalf("confirmed change: %d level=%s", rec.Code, f.kl.level)
	}
	if body := rec.Body.String(); !strings.Contains(body, "actor-after") || strings.Contains(body, "actor-before") {
		t.Fatal("the success page shows the previous change's actor, not the new one")
	}
	// The time must be the new change's, not the one read before it.
	if body := rec.Body.String(); !strings.Contains(body, "2031-03-04 05:06 UTC") || strings.Contains(body, time.Now().Add(-time.Hour).UTC().Format("2006-01-02 15:04")+" UTC") {
		t.Fatal("the success page shows the previous change's time, not the new one")
	}
	if !strings.Contains(rec.Body.String(), `data-toast="Key level changed to organization"`) {
		t.Fatal("success toast missing")
	}
}

// readOnlyLevels hides the change side of a key-level service.
type readOnlyLevels struct{ api.KeyLevelService }

func TestMeshUIKeyLevelReadOnlyWhenChangeIsNotWired(t *testing.T) {
	f := newMeshFixtureOn(t, testPool(t), true, func(d *api.MeshDeps) { d.KeyLevels = readOnlyLevels{d.KeyLevels} })
	m := meshfake.New(meshfake.NewKey("k1"))
	t.Cleanup(m.Close)
	ws := uuid.New()
	b, _ := json.Marshal(map[string]string{"mesh_url": m.URL(), "workspace_id": ws.String(), "extension_token": canary.New().Value(1), "events_endpoint_secret": canary.New().Value(2)})
	if rec := f.post("/mesh/install", f.admin, b, nil); rec.Code != http.StatusOK {
		t.Fatalf("install: %d", rec.Code)
	}
	u := &uiFixture{sessionFixture: &sessionFixture{meshFixture: f, mesh: m, ws: ws}}
	ck := u.login("boss", "b@example.test")
	u.grant("boss", identity.RoleAdmin)
	rec := u.get("/mesh/ui/settings", ck, nil, true)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "<form") || !strings.Contains(rec.Body.String(), "<strong>user</strong>") {
		t.Fatalf("read-only page: %d", rec.Code)
	}
	_, err := f.pool.Exec(context.Background(), `INSERT INTO keep_org_key_level(org_id, level, updated_by) VALUES ($1,'project','actor-9')`, f.org.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if rec := u.get("/mesh/ui/settings", ck, nil, true); !strings.Contains(rec.Body.String(), "<strong>project</strong>") || !strings.Contains(rec.Body.String(), "actor-9") {
		t.Fatal("persisted level not shown")
	}
}

// Production wiring: an admin changes the level through the page, and the
// request and the outcome land in the audit journal.
func TestMeshUIKeyLevelChangeWiredInProduction(t *testing.T) {
	f := newMeshFixtureOn(t, testPool(t), true)
	m := meshfake.New(meshfake.NewKey("k1"))
	t.Cleanup(m.Close)
	ws := uuid.New()
	b, _ := json.Marshal(map[string]string{"mesh_url": m.URL(), "workspace_id": ws.String(), "extension_token": canary.New().Value(1), "events_endpoint_secret": canary.New().Value(2)})
	if rec := f.post("/mesh/install", f.admin, b, nil); rec.Code != http.StatusOK {
		t.Fatalf("install: %d", rec.Code)
	}
	u := &uiFixture{sessionFixture: &sessionFixture{meshFixture: f, mesh: m, ws: ws}}
	ck := u.login("boss", "b@example.test")
	u.grant("boss", identity.RoleAdmin)
	sess, err := identity.NewRepo(f.pool).LookupSession(context.Background(), ck)
	if err != nil || sess.CSRF == "" {
		t.Fatalf("session: %v", err)
	}
	// A canary secret sealed at the default level (user).
	c := canary.New()
	seedSecret(t, f, c.Value(1))
	type sealed struct{ ct, dek []byte }
	snap := func() map[string]sealed {
		rows, err := f.pool.Query(context.Background(), `SELECT secret_id || '/' || version, ciphertext, wrapped_dek FROM keep_envelope WHERE store_org = $1`, f.org.ID.String())
		if err != nil {
			t.Fatalf("read envelopes: %v", err)
		}
		defer rows.Close()
		out := map[string]sealed{}
		for rows.Next() {
			var k string
			var e sealed
			if err := rows.Scan(&k, &e.ct, &e.dek); err != nil {
				t.Fatal("scan envelope")
			}
			out[k] = e
		}
		return out
	}
	before := snap()
	if len(before) < 1 {
		t.Fatal("no sealed row to observe")
	}
	form := url.Values{"csrf": {sess.CSRF}, "level": {"organization"}, "confirm_weakening": {"yes"}}
	rec := u.postForm("/mesh/ui/settings/key-level", ck, form, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Key level changed to organization") {
		t.Fatalf("change: %d", rec.Code)
	}
	if got := strings.Join(actionsOf(t, f), ","); got != "org.key_level.requested,org.key_level.changed" {
		t.Fatalf("journal actions = %s", got)
	}
	if lvl := keyLevelOf(t, f); lvl != "organization" {
		t.Fatalf("level = %s", lvl)
	}
	// The data key is re-wrapped under the new key; the ciphertext is untouched.
	after := snap()
	rewrapped := 0
	for k, e := range before {
		n, ok := after[k]
		if !ok || !bytes.Equal(e.ct, n.ct) {
			t.Fatal("ciphertext changed or a sealed row vanished")
		}
		if !bytes.Equal(e.dek, n.dek) {
			rewrapped++
		}
	}
	if rewrapped < 1 {
		t.Fatal("no wrapped data key was re-wrapped")
	}
	// The actor is the session's user, in the journal and in the level record.
	var requested, changed int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE action = 'org.key_level.requested'), count(*) FILTER (WHERE action = 'org.key_level.changed') FROM audit_records WHERE org_id = $1 AND actor_type = 'user' AND actor_id = $2`, f.org.ID, sess.Principal.ID.String()).Scan(&requested, &changed); err != nil || requested != 1 || changed != 1 {
		t.Fatalf("journal actor: requested=%d changed=%d err=%v", requested, changed, err)
	}
	var by string
	if err := f.pool.QueryRow(context.Background(), `SELECT updated_by FROM keep_org_key_level WHERE org_id = $1`, f.org.ID.String()).Scan(&by); err != nil || by != sess.Principal.ID.String() {
		t.Fatalf("level changed by %q err=%v", by, err)
	}
	// No value on any outward surface: page, log, journal.
	var dump strings.Builder
	dump.WriteString(rec.Body.String())
	dump.WriteString(f.logbuf.String())
	rows, err := f.pool.Query(context.Background(), `SELECT to_jsonb(a)::text FROM audit_records a WHERE org_id = $1`, f.org.ID)
	if err != nil {
		t.Fatalf("dump journal: %v", err)
	}
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			t.Fatal("scan journal")
		}
		dump.WriteString(j)
	}
	rows.Close()
	if !strings.Contains(dump.String(), "org.key_level.changed") || !c.In(dump.String()+c.Value(1)) {
		t.Fatal("positive control failed: dump misses the journal or the scan is blind")
	}
	if c.In(dump.String()) {
		t.Fatal("canary reached the page, the log or the journal")
	}
}
