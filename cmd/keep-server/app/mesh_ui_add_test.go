package app

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

const uiInputOrigin = "https://keep.example.test"

// linkRe takes the one-time input link out of its read-only field.
var linkRe = regexp.MustCompile(`value="(` + regexp.QuoteMeta(uiInputOrigin) + `/input/[^"]+)" readonly`)

// bindStore creates a store of provider at the org scope and binds it there,
// so both the org scope and every user's own scope resolve to it.
func (f *uiFixture) bindStore(provider, name string) catalog.Store {
	f.t.Helper()
	ctx := context.Background()
	cat := catalog.New(f.pool)
	st, err := cat.CreateStore(ctx, f.org.ID, provider, name, tenancy.Org(f.org.ID))
	if err != nil {
		f.t.Fatalf("store: %v", err)
	}
	if _, err := cat.CreateStoreBinding(ctx, f.org.ID, tenancy.Org(f.org.ID), st.ID); err != nil {
		f.t.Fatalf("binding: %v", err)
	}
	return st
}

func (f *uiFixture) csrf(cookie string) string {
	f.t.Helper()
	s, err := identity.NewRepo(f.pool).LookupSession(context.Background(), cookie)
	if err != nil || s.CSRF == "" {
		f.t.Fatal("session csrf")
	}
	return s.CSRF
}

// issuedToken is the token of the link on a result page; "" when none.
func issuedToken(t *testing.T, body string) (link, token string) {
	t.Helper()
	m := linkRe.FindStringSubmatch(body)
	if m == nil {
		return "", ""
	}
	link = html.UnescapeString(m[1])
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal("link URL")
	}
	return link, strings.TrimPrefix(u.Path, "/input/")
}

// TestMeshUIAddSecretOnRealStore drives "Add secret" through the real router,
// catalog, input-link service and journal: a record with a random locator,
// one working one-time link that stays on the page, a mesh-plugin audit
// record, and the token nowhere in the log or the journal.
func TestMeshUIAddSecretOnRealStore(t *testing.T) {
	f := newUIFixtureInput(t, uiInputOrigin)
	st := f.bindStore("builtin", "ui-store")
	ctx := context.Background()
	viewer := f.login("ann", "ann@example.test")
	f.grant("ann", identity.RoleViewer)
	csrf := f.csrf(viewer)

	list := f.get("/mesh/ui/secrets", viewer, nil, true).Body.String()
	if !strings.Contains(list, `action="/mesh/ui/secrets/new"`) || strings.Contains(list, `<option value="org"`) {
		t.Fatal("a viewer must get the form for their own scope only")
	}

	add := func(cookie, csrf, name, scope string) *http.Response {
		form := url.Values{"csrf": {csrf}, "name": {name}}
		if scope != "" {
			form.Set("scope", scope)
		}
		return f.postForm("/mesh/ui/secrets/new", cookie, form, nil).Result()
	}
	secrets := func(name string) int {
		return f.count(`SELECT count(*) FROM secrets WHERE org_id=$1 AND name=$2`, f.org.ID, name)
	}

	// A viewer cannot add at the org scope, even bypassing the screen.
	if res := add(viewer, csrf, "org-key", "org"); res.StatusCode != http.StatusNotFound || secrets("org-key") != 0 {
		t.Fatalf("viewer at org scope: %d, records %d", res.StatusCode, secrets("org-key"))
	}
	// Without the CSRF token nothing is created.
	if res := add(viewer, "", "no-csrf", ""); res.StatusCode != http.StatusForbidden || secrets("no-csrf") != 0 {
		t.Fatalf("no csrf: %d", res.StatusCode)
	}

	rec := f.postForm("/mesh/ui/secrets/new", viewer, url.Values{"csrf": {csrf}, "name": {"stripe key"}}, nil)
	body := rec.Body.String()
	link, token := issuedToken(t, body)
	if rec.Code != http.StatusOK || token == "" || rec.Header().Get("Location") != "" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("add: %d, link found %v", rec.Code, token != "")
	}
	if !strings.Contains(body, `href="`+html.EscapeString(link)+`" target="_blank" rel="noopener noreferrer"`) {
		t.Fatal("no Open input page link to a new tab")
	}
	var (
		id                                      uuid.UUID
		providerRef, level, class, typ, scopeID string
		storeID                                 uuid.UUID
	)
	if err := f.pool.QueryRow(ctx, `SELECT id,provider_ref,scope_level,scope_id::text,class,type,store_id FROM secrets WHERE org_id=$1 AND name='stripe key'`, f.org.ID).
		Scan(&id, &providerRef, &level, &scopeID, &class, &typ, &storeID); err != nil {
		t.Fatalf("record: %v", err)
	}
	loc, ok := strings.CutPrefix(providerRef, "builtin://ui-store/")
	locID, err := uuid.Parse(loc)
	if !ok || err != nil || locID.Version() != 7 || strings.Contains(providerRef, "stripe") {
		t.Fatalf("provider_ref is not builtin://<store>/<uuid v7>: %q", providerRef)
	}
	var userID string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM users WHERE org_id=$1 AND external_ref LIKE $2`, f.org.ID, "%:"+meshSub("ann")).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if level != "user" || scopeID != userID || class != "dev" || typ != "generic" || storeID != st.ID {
		t.Fatalf("record fields: %s:%s class %s type %s store %v", level, scopeID, class, typ, storeID == st.ID)
	}
	if n := f.count(`SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='secret.create_ref' AND actor_via='mesh-plugin' AND secret_name='stripe key' AND result_status='ok' AND actor_id=$2`, f.org.ID.String(), userID); n != 1 {
		t.Fatalf("create_ref audit records via mesh-plugin: %d", n)
	}

	// The link opens Keep's input page.
	page := f.get("/input/"+token, "", nil, true)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "stripe key") {
		t.Fatalf("input page: %d", page.Code)
	}

	// A retry reuses the record that still has no value and issues a new link.
	again := f.postForm("/mesh/ui/secrets/new", viewer, url.Values{"csrf": {csrf}, "name": {"stripe key"}}, nil)
	_, token2 := issuedToken(t, again.Body.String())
	if again.Code != http.StatusOK || token2 == "" || token2 == token || secrets("stripe key") != 1 {
		t.Fatalf("retry: %d, records %d", again.Code, secrets("stripe key"))
	}
	// The secret page of a record without a value issues a link too.
	sp := f.get("/mesh/ui/secrets/"+id.String(), viewer, nil, true).Body.String()
	if !strings.Contains(sp, `action="/mesh/ui/secrets/`+id.String()+`/input-link"`) || !strings.Contains(sp, `value="keep input-link &#39;stripe key&#39;" readonly`) {
		t.Fatal("no input link form on the secret page")
	}
	fromPage := f.postForm("/mesh/ui/secrets/"+id.String()+"/input-link", viewer, url.Values{"csrf": {csrf}}, nil)
	_, token3 := issuedToken(t, fromPage.Body.String())
	if fromPage.Code != http.StatusOK || token3 == "" {
		t.Fatalf("input link from the secret page: %d", fromPage.Code)
	}

	// An admin adds at the org scope; a name that already has a value is refused.
	admin := f.login("bob", "bob@example.test")
	f.grant("bob", identity.RoleAdmin)
	acsrf := f.csrf(admin)
	if res := add(admin, acsrf, "org-key", "org"); res.StatusCode != http.StatusOK || f.count(`SELECT count(*) FROM secrets WHERE org_id=$1 AND name='org-key' AND scope_level='org'`, f.org.ID) != 1 {
		t.Fatalf("admin at org scope: %d", res.StatusCode)
	}
	full, _ := f.seedSecret("has-value", "seeded-value")
	exists := f.postForm("/mesh/ui/secrets/new", admin, url.Values{"csrf": {acsrf}, "name": {"has-value"}, "scope": {"org"}}, nil)
	if exists.Code != http.StatusConflict || !strings.Contains(exists.Body.String(), `href="/mesh/ui/secrets/`+full.String()+`"`) || strings.Contains(exists.Body.String(), "/input/") {
		t.Fatalf("name with a value: %d", exists.Code)
	}

	logs := f.logbuf.String()
	if logs == "" {
		t.Fatal("positive control: the server logged nothing")
	}
	var journal string
	if err := f.pool.QueryRow(ctx, `SELECT coalesce(string_agg(to_jsonb(a)::text, E'\n'), '') FROM audit_records a WHERE org_id=$1`, f.org.ID.String()).Scan(&journal); err != nil || journal == "" {
		t.Fatal("journal")
	}
	for _, tok := range []string{token, token2, token3} {
		if strings.Contains(logs, tok) || strings.Contains(journal, tok) {
			t.Fatal("an input-link token reached the log or the journal")
		}
	}
}

// TestMeshUIAddSecretRefusesNonBuiltinStore: a scope bound to a store that is
// not the built-in one gets no button, and a POST past the screen is refused
// before any record is created.
func TestMeshUIAddSecretRefusesNonBuiltinStore(t *testing.T) {
	f := newUIFixtureInput(t, uiInputOrigin)
	f.bindStore("op", "vault-1p")
	cookie := f.login("ann", "ann@example.test")
	f.grant("ann", identity.RoleAdmin)
	list := f.get("/mesh/ui/secrets", cookie, nil, true).Body.String()
	if !strings.Contains(list, `disabled aria-describedby="add-why"`) || !strings.Contains(list, "Input links work only with the built-in store") {
		t.Fatal("the button must be disabled with the store reason")
	}
	for _, scope := range []string{"", "org"} {
		rec := f.postForm("/mesh/ui/secrets/new", cookie, url.Values{"csrf": {f.csrf(cookie)}, "name": {"op-key"}, "scope": {scope}}, nil)
		if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "/input/") {
			t.Fatalf("scope %q: %d", scope, rec.Code)
		}
	}
	if n := f.count(`SELECT count(*) FROM secrets WHERE org_id=$1`, f.org.ID); n != 0 {
		t.Fatalf("records created behind a non-builtin store: %d", n)
	}
}

// TestMeshUIAddSecretOffWithoutInputLinks: a server without input links
// shows the reason and creates nothing.
func TestMeshUIAddSecretOffWithoutInputLinks(t *testing.T) {
	f := newUIFixture(t)
	f.bindStore("builtin", "ui-store")
	cookie := f.login("ann", "ann@example.test")
	if body := f.get("/mesh/ui/secrets", cookie, nil, true).Body.String(); !strings.Contains(body, `id="add-why">Input links are not set up on this server.</span>`) {
		t.Fatal("no reason without input links")
	}
	rec := f.postForm("/mesh/ui/secrets/new", cookie, url.Values{"csrf": {f.csrf(cookie)}, "name": {"k"}}, nil)
	if rec.Code != http.StatusServiceUnavailable || f.count(`SELECT count(*) FROM secrets WHERE org_id=$1`, f.org.ID) != 0 {
		t.Fatalf("add without input links: %d", rec.Code)
	}
}
