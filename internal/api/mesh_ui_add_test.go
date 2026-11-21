package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// These tests drive "Add secret" of the Secrets screen through its real
// handlers, with the record and link side (meshUIAdder) behind a fake. The
// rights, store and record rules of the server's adder are proved on a real
// database in cmd/keep-server/app (mesh_ui_add_test.go).

// uiAdderFake answers like catalogAdder: a scope outside targets is
// errMeshUINotFound, and every call is counted so a refusal can be shown to
// have reached nothing.
type uiAdderFake struct {
	targets   []tenancy.Scope
	reason    string
	err       error // returned by Add and Link instead of a link
	adds      []meshUIAddInput
	links     []uuid.UUID
	token     string
	expiresAt time.Time
}

func (f *uiAdderFake) Targets(context.Context, identity.Principal) ([]tenancy.Scope, string, error) {
	return f.targets, f.reason, nil
}

func (f *uiAdderFake) issued(id uuid.UUID, name string, level tenancy.Level) meshUIIssued {
	return meshUIIssued{SecretID: id, Name: name, Scope: level, Link: intake.Issued{
		URL:       "https://keep.example.test/input/" + f.token + "#signing=SIG" + f.token + "&request=0192",
		ExpiresAt: f.expiresAt, RequestID: "0192"}}
}

func (f *uiAdderFake) Add(_ context.Context, _ identity.Principal, in meshUIAddInput) (meshUIIssued, error) {
	f.adds = append(f.adds, in)
	ok := false
	for _, s := range f.targets {
		ok = ok || s == in.Scope
	}
	if !ok {
		return meshUIIssued{}, errMeshUINotFound
	}
	if f.err != nil {
		return meshUIIssued{}, f.err
	}
	return f.issued(uuid.New(), in.Name, in.Scope.Level), nil
}

func (f *uiAdderFake) Link(_ context.Context, _ identity.Principal, id uuid.UUID) (meshUIIssued, error) {
	f.links = append(f.links, id)
	if f.err != nil {
		return meshUIIssued{}, f.err
	}
	return f.issued(id, "linked", tenancy.LevelOrg), nil
}

// withAdder puts a fake adder offering the user scope (and org when org).
func (h *uiHarness) withAdder(org bool) *uiAdderFake {
	f := &uiAdderFake{targets: []tenancy.Scope{{Level: tenancy.LevelUser, ID: h.p.ID}}, token: "TOKEN" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		expiresAt: time.Now().Add(30 * time.Minute)}
	if org {
		f.targets = append(f.targets, tenancy.Org(h.p.OrgID))
	}
	h.ui.add = f
	return f
}

func (h *uiHarness) post(path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, r)
	return rec
}

func addForm(name string, kv ...string) url.Values {
	v := url.Values{"csrf": {"csrf-fixed"}, "name": {name}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

var (
	formRe  = regexp.MustCompile(`(?s)<form[^>]*action="/mesh/ui/secrets/new"[^>]*>(.*?)</form>`)
	fieldRe = regexp.MustCompile(`<(?:input|select|textarea)[^>]*\bname="([^"]+)"`)
	// toastRe is the text the page hands Mesh as mesh.toast.
	toastRe = regexp.MustCompile(`data-toast="([^"]*)"`)
)

// addFields lists the names of the fields of the Add secret form on body.
func addFields(t *testing.T, body string) []string {
	t.Helper()
	m := formRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no Add secret form on the page")
	}
	var out []string
	for _, f := range fieldRe.FindAllStringSubmatch(m[1], -1) {
		out = append(out, f[1])
	}
	sort.Strings(out)
	return out
}

// TestMeshUIAddSecretFormIsClosed: the form has exactly name, scope, class and
// the CSRF token, nowhere a field a value could be typed into; a POST that
// carries any other field is refused before anything is created.
func TestMeshUIAddSecretFormIsClosed(t *testing.T) {
	h := newUIHarness(t, true, true)
	add := h.withAdder(true)
	empty := h.get("/mesh/ui/secrets").Body.String()
	page := h.get("/mesh/ui/secrets/new")
	if page.Code != http.StatusOK {
		t.Fatalf("new: %d", page.Code)
	}
	for name, body := range map[string]string{"empty list": empty, "new page": page.Body.String()} {
		if strings.Contains(body, "keep input-link ") {
			t.Errorf("%s: terminal command shown before a record exists", name)
		}
		if got := strings.Join(addFields(t, body), ","); got != "class,csrf,name,scope" {
			t.Errorf("%s: form fields %s", name, got)
		}
		if strings.Contains(body, `type="password"`) || strings.Contains(body, "<textarea") || strings.Contains(body, `name="value"`) {
			t.Errorf("%s: a field for a value", name)
		}
		if !strings.Contains(body, `<option value="user" selected>Only me</option>`) || !strings.Contains(body, `<option value="org">Organization</option>`) {
			t.Errorf("%s: scope choice", name)
		}
	}
	h.secret("db-password", "password", "v1")
	list := h.get("/mesh/ui/secrets").Body.String()
	if !strings.Contains(list, `<a class="btn btn-sm" href="/mesh/ui/secrets/new">`) {
		t.Fatal("no Add secret button above the list")
	}
	for _, extra := range []string{"value", "secret", "ttl", "provider_ref"} {
		if rec := h.post("/mesh/ui/secrets/new", addForm("api-key", extra, "x"), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("field %s: %d", extra, rec.Code)
		}
	}
	if len(add.adds) != 0 {
		t.Fatalf("a refused form reached the adder %d times", len(add.adds))
	}
}

// TestMeshUIAddSecretLinkStaysOnThePage: the link comes in the body of the
// POST answer and nowhere else: no redirect, no cache, not in a header and not
// in the log. The page carries it in a read-only field with Copy and Open, and
// the command for the terminal next to it.
func TestMeshUIAddSecretLinkStaysOnThePage(t *testing.T) {
	h := newUIHarness(t, true, true)
	add := h.withAdder(true)
	rec := h.post("/mesh/ui/secrets/new", addForm("stripe key"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("add: %d", rec.Code)
	}
	if len(add.adds) != 1 || add.adds[0].Scope != (tenancy.Scope{Level: tenancy.LevelUser, ID: h.p.ID}) || add.adds[0].Class != "dev" || add.adds[0].Name != "stripe key" {
		t.Fatalf("adder got %+v", add.adds)
	}
	body := rec.Body.String()
	link := "https://keep.example.test/input/" + add.token + "#signing=SIG" + add.token + "&amp;request=0192"
	if !strings.Contains(body, `value="`+link+`" readonly`) {
		t.Fatal("the link is not in a read-only field")
	}
	if !strings.Contains(body, `<a class="btn" href="`+link+`" target="_blank" rel="noopener noreferrer">Open input page</a>`) {
		t.Fatal("no Open input page link to a new tab")
	}
	if !strings.Contains(body, `value="keep input-link &#39;stripe key&#39;" readonly`) {
		t.Fatal("the command for the terminal is missing or not quoted")
	}
	if strings.Count(body, "data-copy-from=") != 2 || !strings.Contains(body, "One-time link") {
		t.Fatal("copy buttons or the one-time note missing")
	}
	// The toast goes to Mesh (mesh.toast): a fixed text, never the link.
	if toast := toastRe.FindStringSubmatch(body); toast == nil || toast[1] != "Input link created" {
		t.Fatal("the result page must toast the fixed text")
	}
	if rec.Header().Get("Location") != "" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers: %v", rec.Header())
	}
	for k, v := range rec.Header() {
		if strings.Contains(strings.Join(v, ","), add.token) {
			t.Fatalf("token in header %s", k)
		}
	}
	if h.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	if strings.Contains(h.logbuf.String(), add.token) {
		t.Fatal("token in the log")
	}
	// Organization scope when chosen; the class as given.
	if rec := h.post("/mesh/ui/secrets/new", addForm("deploy-key", "scope", "org", "class", "ssh"), nil); rec.Code != http.StatusOK ||
		add.adds[1].Scope != tenancy.Org(h.p.OrgID) || add.adds[1].Class != "ssh" {
		t.Fatalf("org scope: %d %+v", rec.Code, add.adds[1])
	}
}

// TestMeshUIAddSecretCSRF: a POST without the session's token, with another
// token or from another site reaches nothing.
func TestMeshUIAddSecretCSRF(t *testing.T) {
	h := newUIHarness(t, true, true)
	add := h.withAdder(true)
	id := h.secret("no-value", "key")
	noCSRF := addForm("api-key")
	noCSRF.Del("csrf")
	for name, c := range map[string]struct {
		path string
		form url.Values
		hdr  map[string]string
	}{
		"no token":       {"/mesh/ui/secrets/new", noCSRF, nil},
		"wrong token":    {"/mesh/ui/secrets/new", addForm("api-key", "csrf", "csrf-other"), nil},
		"cross site":     {"/mesh/ui/secrets/new", addForm("api-key"), map[string]string{"Sec-Fetch-Site": "cross-site"}},
		"link no token":  {"/mesh/ui/secrets/" + id.String() + "/input-link", url.Values{}, nil},
		"link wrong one": {"/mesh/ui/secrets/" + id.String() + "/input-link", url.Values{"csrf": {"x"}}, nil},
	} {
		if rec := h.post(c.path, c.form, c.hdr); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if len(add.adds) != 0 || len(add.links) != 0 {
		t.Fatalf("a forged request reached the adder: %d adds, %d links", len(add.adds), len(add.links))
	}
	// Positive control: the same request with the token goes through.
	if rec := h.post("/mesh/ui/secrets/new", addForm("api-key"), nil); rec.Code != http.StatusOK || len(add.adds) != 1 {
		t.Fatalf("control: %d", rec.Code)
	}
}

// TestMeshUIAddSecretRefusals: without a scope to add into the button is
// disabled with its reason in visible text; a scope outside the session's is
// 404 like the API; each refusal of the adder has its own answer.
func TestMeshUIAddSecretRefusals(t *testing.T) {
	h := newUIHarness(t, true, true)
	add := h.withAdder(false)
	if body := h.get("/mesh/ui/secrets/new").Body.String(); strings.Contains(body, `<option value="org"`) {
		t.Fatal("a scope without rights is offered")
	}
	if rec := h.post("/mesh/ui/secrets/new", addForm("api-key", "scope", "org"), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("org without rights: %d", rec.Code)
	}
	for _, sc := range []string{"workspace", "", "user:other"} {
		before := len(add.adds)
		if rec := h.post("/mesh/ui/secrets/new", addForm("api-key", "scope", sc), nil); rec.Code != http.StatusNotFound && (sc != "" || rec.Code != http.StatusOK) {
			t.Errorf("scope %q: %d", sc, rec.Code)
		}
		if sc != "" && len(add.adds) != before {
			t.Errorf("scope %q reached the adder", sc)
		}
	}
	for _, name := range []string{"", " api-key", "api-key ", "a\tb", strings.Repeat("n", 129)} {
		before := len(add.adds)
		if rec := h.post("/mesh/ui/secrets/new", addForm(name), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `role="alert"`) {
			t.Errorf("name %q: %d", name, rec.Code)
		}
		if len(add.adds) != before {
			t.Errorf("name %q reached the adder", name)
		}
	}
	existing := uuid.New()
	for _, c := range []struct {
		err  error
		code int
		text string
	}{
		{&errMeshUIExists{ID: existing}, http.StatusConflict, `href="/mesh/ui/secrets/` + existing.String() + `"`},
		{errMeshUINotBuiltin, http.StatusConflict, "Input links work only with the built-in store"},
		{errMeshUIInputOff, http.StatusServiceUnavailable, "not set up on this server"},
		{errors.New("db down"), http.StatusServiceUnavailable, "Nothing was stored"},
	} {
		add.err = c.err
		rec := h.post("/mesh/ui/secrets/new", addForm("api-key"), nil)
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.text) || strings.Contains(rec.Body.String(), "/input/") {
			t.Errorf("%v: %d", c.err, rec.Code)
		}
	}
	add.err = nil
	// No scope at all: the button is there, disabled, and says why in text.
	add.targets, add.reason = nil, "Your role cannot add secrets here. Ask an organization admin."
	for _, p := range []string{"/mesh/ui/secrets", "/mesh/ui/secrets/new"} {
		body := h.get(p).Body.String()
		if !regexp.MustCompile(`<button class="btn btn-sm" type="button" disabled aria-describedby="add-why">Add secret</button>\s*<span class="muted" id="add-why">Your role cannot add secrets here\. Ask an organization admin\.</span>`).MatchString(body) {
			t.Errorf("%s: no disabled button with a visible reason", p)
		}
		if formRe.MatchString(body) {
			t.Errorf("%s: a form without a scope to add into", p)
		}
	}
	h.secret("db-password", "password", "v1")
	if body := h.get("/mesh/ui/secrets").Body.String(); !strings.Contains(body, `id="add-why">Your role cannot`) {
		t.Fatal("list: no reason next to the disabled button")
	}
	// No adder at all (Mesh screen without input links): disabled with reason.
	h.ui.add = nil
	if body := h.get("/mesh/ui/secrets").Body.String(); !strings.Contains(body, `id="add-why">Input links are not set up on this server.</span>`) {
		t.Fatal("no adder: no reason")
	}
}

// TestMeshUISecretPageInputLink: a secret without a value offers its command
// and a one-time link of its own; a secret with a value does not.
func TestMeshUISecretPageInputLink(t *testing.T) {
	h := newUIHarness(t, true, true)
	add := h.withAdder(true)
	empty := h.secret("no-value", "key")
	full := h.secret("has-value", "key", "v1")
	body := h.get("/mesh/ui/secrets/" + empty.String()).Body.String()
	if !strings.Contains(body, `action="/mesh/ui/secrets/`+empty.String()+`/input-link"`) || !strings.Contains(body, `value="keep input-link no-value" readonly`) ||
		!strings.Contains(body, `<input type="hidden" name="csrf" value="csrf-fixed">`) {
		t.Fatal("no input link form or command on a secret without a value")
	}
	if strings.Contains(h.get("/mesh/ui/secrets/"+full.String()).Body.String(), "/input-link") {
		t.Fatal("input link offered for a secret with a value")
	}
	// Without create_ref and rotate at its scope: the button is disabled and
	// says why; there is no form to post.
	targets := add.targets
	add.targets, add.reason = nil, reasonNoRights
	off := h.get("/mesh/ui/secrets/" + empty.String()).Body.String()
	if strings.Contains(off, `/input-link"`) || !strings.Contains(off, `disabled aria-describedby="link-why">Create input link</button> <span class="muted" id="link-why">`+reasonNoRights+`</span>`) {
		t.Fatal("no disabled button with the reason on a secret the session cannot link")
	}
	add.targets, add.reason = targets, ""
	rec := h.post("/mesh/ui/secrets/"+empty.String()+"/input-link", url.Values{"csrf": {"csrf-fixed"}}, nil)
	if toast := toastRe.FindStringSubmatch(rec.Body.String()); toast == nil || toast[1] != "Input link created" {
		t.Fatal("the result page must toast the fixed text")
	}
	if rec.Code != http.StatusOK || len(add.links) != 1 || add.links[0] != empty || !strings.Contains(rec.Body.String(), "/input/"+add.token) {
		t.Fatalf("link: %d %v", rec.Code, add.links)
	}
	if strings.Contains(h.logbuf.String(), add.token) {
		t.Fatal("token in the log")
	}
	add.err = errMeshUINotFound
	if rec := h.post("/mesh/ui/secrets/"+uuid.NewString()+"/input-link", url.Values{"csrf": {"csrf-fixed"}}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown secret: %d", rec.Code)
	}
	if rec := h.post("/mesh/ui/secrets/not-an-id/input-link", url.Values{"csrf": {"csrf-fixed"}}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("bad id: %d", rec.Code)
	}
}

func TestMeshUIShellQuote(t *testing.T) {
	for in, want := range map[string]string{"api-key": "api-key", "a/b.c_d:e@f+g=h,i": "a/b.c_d:e@f+g=h,i", "stripe key": "'stripe key'",
		"it's": `'it'\''s'`, "$(rm -rf /)": "'$(rm -rf /)'", "naïve": "'naïve'"} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
