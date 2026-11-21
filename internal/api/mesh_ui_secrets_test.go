package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// These tests drive the Secrets screens through their real handlers, with
// the catalog, carriers and rotations behind fakes and no database: the
// session is given, every other input is the fake's.

// uiSecretsFake is the catalog as the screens read it. It holds secrets of
// two organizations and of two users; Readable answers only what Visible
// would list.
type uiSecretsFake struct {
	refs     []tenancy.SecretRef
	versions map[uuid.UUID][]catalog.SecretVersion
	readable map[tenancy.Level]bool // levels the session may read
}

func (f *uiSecretsFake) visibleTo(p identity.Principal, ref tenancy.SecretRef) bool {
	if ref.OrgID != p.OrgID || !f.readable[ref.Scope.Level] {
		return false
	}
	return ref.Scope.Level == tenancy.LevelOrg && ref.Scope.ID == p.OrgID || ref.Scope.Level == tenancy.LevelUser && ref.Scope.ID == p.ID
}

func (f *uiSecretsFake) Visible(_ context.Context, p identity.Principal) ([]tenancy.SecretRef, error) {
	var out []tenancy.SecretRef
	for _, r := range f.refs {
		if f.visibleTo(p, r) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *uiSecretsFake) Readable(_ context.Context, p identity.Principal, id uuid.UUID) (tenancy.SecretRef, error) {
	for _, r := range f.refs {
		if r.ID == id && f.visibleTo(p, r) {
			return r, nil
		}
	}
	return tenancy.SecretRef{}, errMeshUINotFound
}

func (f *uiSecretsFake) Versions(_ context.Context, _, id uuid.UUID) ([]catalog.SecretVersion, error) {
	return f.versions[id], nil
}

func (f *uiSecretsFake) Store(_ context.Context, org, id uuid.UUID) (catalog.Store, error) {
	return catalog.Store{ID: id, OrgID: org, Provider: "builtin", Name: "default"}, nil
}

type uiCarriersFake struct {
	list map[uuid.UUID][]carriers.Carrier
}

func (f *uiCarriersFake) List(_ context.Context, _, id uuid.UUID) ([]carriers.Carrier, error) {
	return f.list[id], nil
}

// Summary counts the fake's carriers the way the SQL does, against the
// newest enabled version the test registered in cur.
func (f *uiCarriersFake) Summary(context.Context, uuid.UUID) (map[uuid.UUID]carriers.Summary, error) {
	out := map[uuid.UUID]carriers.Summary{}
	for id, cs := range f.list {
		var s carriers.Summary
		for _, c := range cs {
			s.Total++
			switch {
			case c.State == carriers.Unknown:
				s.Unknown++
			case c.State == carriers.Stale || c.LastFP == "old":
				s.Stale++
			default:
				s.InSync++
			}
		}
		out[id] = s
	}
	return out, nil
}

type uiRotationsFake struct {
	runs map[uuid.UUID][]RunSummary // newest first
}

func (f *uiRotationsFake) Latest(_ context.Context, _ uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]RunSummary, error) {
	out := map[uuid.UUID]RunSummary{}
	for _, id := range ids {
		if rs := f.runs[id]; len(rs) > 0 {
			out[id] = rs[0]
		}
	}
	return out, nil
}

func (f *uiRotationsFake) List(_ context.Context, _, id uuid.UUID, limit, offset int) ([]RunSummary, int, error) {
	rs := f.runs[id]
	if offset >= len(rs) {
		return nil, len(rs), nil
	}
	return rs[offset:min(offset+limit, len(rs))], len(rs), nil
}

// canaryVault is the store of values the screens can reach: the only thing
// of it they may ever call is nothing. ResolveSecret answers the canary, so a
// page that reads a value carries it.
type canaryVault struct {
	MeshVault
	c     canary.Canary
	calls int
}

func (v *canaryVault) ResolveSecret(context.Context, string, string, string) ([]byte, MeshSecretMeta, error) {
	v.calls++
	return []byte(`{"value":"` + v.c.Value(1) + `"}`), MeshSecretMeta{Version: "v1", Length: len(v.c.Value(1))}, nil
}

type uiHarness struct {
	t      *testing.T
	h      http.Handler
	logbuf *bytes.Buffer
	p      identity.Principal
	src    *uiSecretsFake
	car    *uiCarriersFake
	rot    *uiRotationsFake
	vault  *canaryVault
	ui     *meshUI
}

func newUIHarness(t *testing.T, withCarriers, withRotations bool) *uiHarness {
	t.Helper()
	var buf bytes.Buffer
	h := &uiHarness{t: t, logbuf: &buf,
		p:     identity.Principal{Kind: identity.KindUser, ID: uuid.New(), OrgID: uuid.New()},
		src:   &uiSecretsFake{versions: map[uuid.UUID][]catalog.SecretVersion{}, readable: map[tenancy.Level]bool{tenancy.LevelOrg: true, tenancy.LevelUser: true}},
		car:   &uiCarriersFake{list: map[uuid.UUID][]carriers.Carrier{}},
		rot:   &uiRotationsFake{runs: map[uuid.UUID][]RunSummary{}},
		vault: &canaryVault{c: canary.New()},
	}
	deps := meshUIDeps{}
	if withCarriers {
		deps.Carriers = h.car
	}
	if withRotations {
		deps.Rotations = h.rot
	}
	u := &meshUI{m: &meshRoutes{deps: MeshDeps{Vault: h.vault}}, logger: obs.New(&buf), src: h.src, deps: deps}
	u.sessions = func(*http.Request) (identity.Session, []string, bool, error) {
		return identity.Session{Principal: h.p, CSRF: "csrf-fixed"}, []string{"https://mesh.example.test"}, true, nil
	}
	mux := http.NewServeMux()
	u.register(mux)
	h.h, h.ui = mux, u
	return h
}

func (h *uiHarness) get(path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, r)
	return rec
}

var uiT0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// secret adds an organization secret with versions (newest first, "old"
// marks none) and returns its id.
func (h *uiHarness) secret(name, class string, versions ...string) uuid.UUID {
	return h.secretAt(name, class, tenancy.Org(h.p.OrgID), h.p.OrgID, versions...)
}

func (h *uiHarness) secretAt(name, class string, sc tenancy.Scope, org uuid.UUID, versions ...string) uuid.UUID {
	id := uuid.New()
	desc := "about " + name
	h.src.refs = append(h.src.refs, tenancy.SecretRef{ID: id, OrgID: org, Scope: sc, Name: name, Class: class, Type: "token",
		StoreID: uuid.New(), ProviderRef: "builtin://default/" + name, Description: &desc, Status: "active", CreatedAt: uiT0})
	for i, v := range versions {
		h.src.versions[id] = append(h.src.versions[id], catalog.SecretVersion{ID: uuid.New(), OrgID: org, SecretID: id, ProviderVersion: v,
			Fingerprint: "kfp1:k1:" + strings.ToUpper(fmt.Sprintf("%010x", i+len(name))), Length: 32, CreatedAt: uiT0.Add(-time.Duration(i) * 24 * time.Hour)})
	}
	return id
}

// carrier lays one destination; old marks a registered one at an older version.
func (h *uiHarness) carrier(id uuid.UUID, host string, st carriers.State, version string, old bool) {
	fp := ""
	if old {
		fp = "old"
	}
	at := uiT0
	h.car.list[id] = append(h.car.list[id], carriers.Carrier{ID: uuid.New(), OrgID: h.p.OrgID, SecretID: id, Version: version,
		Metadata: carriers.Metadata{Host: host, TargetKind: runnerproto.TargetEnvFile, TargetPath: "/etc/" + host + "/app.env", Consumer: "app", HealthcheckRef: "http"},
		LastFP:   fp, State: st, LastVerifiedAt: &at})
}

var rowName = regexp.MustCompile(`class="row-link" href="/mesh/ui/secrets/[0-9a-f-]{36}">([^<]+)</a>`)

func rowNames(body string) []string {
	var out []string
	for _, m := range rowName.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// mixed seeds one secret per list state of §3.1 and returns their ids by name.
func (h *uiHarness) mixed() map[string]uuid.UUID {
	ids := map[string]uuid.UUID{}
	ids["failed"] = h.secret("failed", "api_token", "v2", "v1")
	h.carrier(ids["failed"], "a", carriers.Registered, "v2", false)
	h.rot.runs[ids["failed"]] = []RunSummary{{ID: uuid.New(), State: "failed", ErrorClass: "unhealthy", OldVersion: "v1", NewVersion: "v2", IncidentOpened: true, CreatedAt: uiT0}}
	ids["rotating"] = h.secret("rotating", "api_token", "v3")
	h.carrier(ids["rotating"], "b", carriers.Registered, "v3", false)
	h.rot.runs[ids["rotating"]] = []RunSummary{{ID: uuid.New(), State: "deploying", OldVersion: "v3", NewVersion: "v4", CreatedAt: uiT0}}
	ids["stale"] = h.secret("stale", "password", "v2", "v1")
	h.carrier(ids["stale"], "c", carriers.Registered, "v2", false)
	h.carrier(ids["stale"], "d", carriers.Registered, "v1", true)
	ids["unverified"] = h.secret("unverified", "password", "v1")
	h.carrier(ids["unverified"], "e", carriers.Unknown, "v1", false)
	ids["nocarriers"] = h.secret("nocarriers", "key", "v1")
	ids["novalue"] = h.secret("novalue", "key")
	ids["insync"] = h.secret("insync", "key", "v5")
	h.carrier(ids["insync"], "f", carriers.Registered, "v5", false)
	h.rot.runs[ids["insync"]] = []RunSummary{{ID: uuid.New(), State: "done", OldVersion: "v4", NewVersion: "v5", CreatedAt: uiT0}}
	return ids
}

// TestMeshUISecretPagesLeak: the store of values the screens can reach holds
// a canary; no list, filter, page, secret page or refusal carries it in any
// encoding, in the body, a header or the log.
func TestMeshUISecretPagesLeak(t *testing.T) {
	h := newUIHarness(t, true, true)
	cn := h.vault.c
	if !cn.In("x"+cn.Value(1)) || !cn.In(hex.EncodeToString([]byte(cn.Value(1)))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	ids := h.mixed()
	foreign := h.secretAt("foreign", "api_token", tenancy.Org(uuid.New()), uuid.New(), "v1")
	other := h.secretAt("other-user", "api_token", tenancy.Scope{Level: tenancy.LevelUser, ID: uuid.New()}, h.p.OrgID, "v1")
	paths := []string{"/mesh/ui/secrets/" + foreign.String(), "/mesh/ui/secrets/" + other.String(), "/mesh/ui/secrets/" + uuid.NewString(), "/mesh/ui/secrets/not-an-id"}
	for _, q := range []string{"", "?q=sta", "?q=zzz", "?class=key", "?scope=user", "?state=attention", "?state=rotating",
		"?sort=state", "?sort=rotated", "?page=2", "?page=x&sort=bogus&state=bogus"} {
		paths = append(paths, "/mesh/ui/secrets"+q)
	}
	for _, id := range ids {
		paths = append(paths, "/mesh/ui/secrets/"+id.String())
	}
	seen := 0
	for _, p := range paths {
		rec := h.get(p)
		if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", p, rec.Code)
		}
		all := rec.Body.String()
		for k, v := range rec.Header() {
			all += "\n" + k + ": " + strings.Join(v, ",")
		}
		if cn.In(all) {
			t.Fatalf("canary on %s", p)
		}
		if strings.Contains(all, "kfp1:k1:") {
			seen++
		}
	}
	// Positive control of the crawl: the pages carried the metadata they exist for.
	if seen < len(ids) {
		t.Fatalf("only %d pages carried a fingerprint; the crawl read empty pages", seen)
	}
	if h.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	if cn.In(h.logbuf.String()) {
		t.Fatal("canary in the log")
	}
	if h.vault.calls != 0 {
		t.Fatalf("the screens read a value %d times", h.vault.calls)
	}
}

func TestMeshUIStateFilters(t *testing.T) {
	h := newUIHarness(t, true, true)
	h.mixed()
	body := h.get("/mesh/ui/secrets?state=attention").Body.String()
	if got := strings.Join(rowNames(body), ","); got != "failed,stale,unverified" {
		t.Fatalf("attention = %q, want failed,stale,unverified", got)
	}
	for _, w := range []string{"Rotation failed", "1 stale", "1 not verified"} {
		if !strings.Contains(body, w) {
			t.Fatalf("attention page lacks %q", w)
		}
	}
	if got := strings.Join(rowNames(h.get("/mesh/ui/secrets?state=rotating").Body.String()), ","); got != "rotating" {
		t.Fatalf("rotating = %q", got)
	}
	all := h.get("/mesh/ui/secrets").Body.String()
	if got := strings.Join(rowNames(all), ","); got != "failed,insync,nocarriers,novalue,rotating,stale,unverified" {
		t.Fatalf("all = %q", got)
	}
	for _, w := range []string{"No carriers", "No value", "In sync", "Rotating", ">7<", ">3<", ">1<"} {
		if !strings.Contains(all, w) {
			t.Fatalf("list lacks %q", w)
		}
	}
	// One state per row, by the priority of the brief.
	if got := strings.Join(rowNames(h.get("/mesh/ui/secrets?sort=state").Body.String()), ","); got != "failed,rotating,stale,unverified,novalue,nocarriers,insync" {
		t.Fatalf("by state = %q", got)
	}
	// Other filters narrow within the state.
	if got := strings.Join(rowNames(h.get("/mesh/ui/secrets?state=attention&class=password&q=ST").Body.String()), ","); got != "stale" {
		t.Fatalf("attention+class+q = %q", got)
	}
	if got := strings.Join(rowNames(h.get("/mesh/ui/secrets?class=password").Body.String()), ","); got != "stale,unverified" {
		t.Fatalf("class = %q", got)
	}
	// Distinct dates prove the rotated order independently of the name order.
	for i, ref := range h.src.refs {
		if versions := h.src.versions[ref.ID]; len(versions) > 0 {
			versions[0].CreatedAt = uiT0.Add(time.Duration(i) * time.Hour)
		}
	}
	if got := strings.Join(rowNames(h.get("/mesh/ui/secrets?sort=rotated").Body.String()), ","); got != "insync,nocarriers,unverified,stale,rotating,failed,novalue" {
		t.Fatalf("by rotated = %q", got)
	}
	h.secretAt("personal", "key", tenancy.Scope{Level: tenancy.LevelUser, ID: h.p.ID}, h.p.OrgID, "v1")
	if got := strings.Join(rowNames(h.get("/mesh/ui/secrets?scope=user").Body.String()), ","); got != "personal" {
		t.Fatalf("scope = %q", got)
	}
	// Without a rotation reader there is no rotating state and no segment for it.
	h2 := newUIHarness(t, true, false)
	h2.mixed()
	body = h2.get("/mesh/ui/secrets").Body.String()
	if strings.Contains(body, "Rotating") || strings.Contains(body, "Rotation failed") {
		t.Fatal("rotation states shown without a rotation reader")
	}
	if got := strings.Join(rowNames(h2.get("/mesh/ui/secrets?state=attention").Body.String()), ","); got != "stale,unverified" {
		t.Fatalf("attention without rotations = %q", got)
	}
}

func TestMeshUIListPages(t *testing.T) {
	h := newUIHarness(t, true, false)
	for i := range 120 {
		h.secret(fmt.Sprintf("s%03d", i), "key", "v1")
	}
	names := func(p string) []string { return rowNames(h.get(p).Body.String()) }
	if got := names("/mesh/ui/secrets"); len(got) != 50 || got[0] != "s000" || got[49] != "s049" {
		t.Fatalf("page 1: %d rows %v", len(got), got)
	}
	body := h.get("/mesh/ui/secrets?page=2").Body.String()
	got := rowNames(body)
	if len(got) != 50 || got[0] != "s050" || got[49] != "s099" {
		t.Fatalf("page 2 holds rows %v, want s050..s099 (rows 51–100)", got)
	}
	if !strings.Contains(body, "51–100 of 120") || !strings.Contains(body, `href="/mesh/ui/secrets?page=1"`) || !strings.Contains(body, `href="/mesh/ui/secrets?page=3"`) {
		t.Fatal("page 2 counter or links")
	}
	if got := names("/mesh/ui/secrets?page=3"); len(got) != 20 || got[19] != "s119" {
		t.Fatalf("page 3: %v", got)
	}
	// Out of range clamps to the last page; garbage is the first.
	if got := names("/mesh/ui/secrets?page=99"); len(got) != 20 {
		t.Fatalf("page 99: %d rows", len(got))
	}
	if got := names("/mesh/ui/secrets?page=-1"); len(got) != 50 || got[0] != "s000" {
		t.Fatalf("page -1: %v", got)
	}
	// Filters are kept across pages.
	if body := h.get("/mesh/ui/secrets?q=s0&page=1").Body.String(); !strings.Contains(body, `href="/mesh/ui/secrets?page=2&amp;q=s0"`) {
		t.Fatal("next page drops the filter")
	}
}

// TestMeshUISecretNotFoundIsOneAnswer: an unknown id, another organization's
// secret, another user's secret, a scope without the right and a malformed
// id are byte-for-byte the same 404.
func TestMeshUISecretNotFoundIsOneAnswer(t *testing.T) {
	h := newUIHarness(t, true, true)
	own := h.secret("own", "key", "v1")
	foreign := h.secretAt("foreign", "key", tenancy.Org(uuid.New()), uuid.New(), "v1")
	other := h.secretAt("other", "key", tenancy.Scope{Level: tenancy.LevelUser, ID: uuid.New()}, h.p.OrgID, "v1")
	mine := h.secretAt("mine", "key", tenancy.Scope{Level: tenancy.LevelUser, ID: h.p.ID}, h.p.OrgID, "v1")
	if rec := h.get("/mesh/ui/secrets/" + own.String()); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<h1>own</h1>") {
		t.Fatalf("own secret: %d", rec.Code)
	}
	ref := h.get("/mesh/ui/secrets/" + uuid.NewString())
	if ref.Code != http.StatusNotFound || !strings.Contains(ref.Body.String(), "Secret not found") {
		t.Fatalf("unknown: %d", ref.Code)
	}
	same := func(name, p string) {
		t.Helper()
		rec := h.get(p)
		if rec.Code != ref.Code || !bytes.Equal(rec.Body.Bytes(), ref.Body.Bytes()) {
			t.Fatalf("%s: %d, body differs from the unknown id's", name, rec.Code)
		}
		for _, k := range []string{"Content-Security-Policy", "Content-Type", "Cache-Control"} {
			if rec.Header().Get(k) != ref.Header().Get(k) {
				t.Fatalf("%s: header %s differs", name, k)
			}
		}
	}
	same("foreign organization", "/mesh/ui/secrets/"+foreign.String())
	same("another user's", "/mesh/ui/secrets/"+other.String())
	same("malformed id", "/mesh/ui/secrets/not-an-id")
	// The session loses the right at the org scope: its secrets turn into the same 404,
	// and the user's own one stays readable (positive control).
	h.src.readable[tenancy.LevelOrg] = false
	same("no right", "/mesh/ui/secrets/"+own.String())
	if rec := h.get("/mesh/ui/secrets/" + mine.String()); rec.Code != http.StatusOK {
		t.Fatalf("own user secret: %d", rec.Code)
	}
	// Positive control of the comparison: a different page is not equal.
	if bytes.Equal(h.get("/mesh/ui/secrets/"+mine.String()).Body.Bytes(), ref.Body.Bytes()) {
		t.Fatal("comparison is blind")
	}
}

func TestMeshUISecretPageBlocks(t *testing.T) {
	h := newUIHarness(t, true, true)
	ids := h.mixed()
	// Names, hosts and paths carry <wbr> break points; the text is read without them.
	body := strings.ReplaceAll(h.get("/mesh/ui/secrets/"+ids["stale"].String()).Body.String(), "<wbr>", "")
	for _, w := range []string{"<h1>stale</h1>", "about stale", "1 of 2 in sync", "Stale · holds v1", "1 of 2 carriers are not on the current version (v2).",
		"d /etc/d/app.env holds v1.", "keep deploy stale", "/etc/c/app.env", "kfp1:k1:", `data-copy="kfp1:k1:`, "Current", "Previous", ">32<", "No rotations yet"} {
		if !strings.Contains(body, w) {
			t.Fatalf("stale page lacks %q", w)
		}
	}
	body = h.get("/mesh/ui/secrets/" + ids["failed"].String()).Body.String()
	for _, w := range []string{"banner-danger", "The last rotation failed: unhealthy.", "An incident is open.", "v1 → v2", "Failed · unhealthy",
		`href="/mesh/ui/secrets/` + ids["failed"].String() + `/rotations/`, `href="/mesh/ui/secrets/` + ids["failed"].String() + `/rotations"`} {
		if !strings.Contains(body, w) {
			t.Fatalf("failed page lacks %q", w)
		}
	}
	// The empty Carriers section says "Not laid out anywhere yet" and names the
	// deploy command too, so only the banner's own text and level prove the banner.
	body = h.get("/mesh/ui/secrets/" + ids["nocarriers"].String()).Body.String()
	if !strings.Contains(body, "Not laid out anywhere yet") || !strings.Contains(body, "keep deploy nocarriers") {
		t.Fatal("no-carriers state")
	}
	for _, w := range []string{`class="banner banner-warn"`, "<b>Not laid out anywhere yet.</b>", "Lay the current version out to a runner: <code>keep deploy nocarriers</code>"} {
		if !strings.Contains(body, w) {
			t.Fatalf("no-carriers banner lacks %q", w)
		}
	}
	body = h.get("/mesh/ui/secrets/" + ids["unverified"].String()).Body.String()
	if !strings.Contains(body, "Not verified") || !strings.Contains(body, "0 of 1 in sync") {
		t.Fatal("unknown carrier state")
	}
	body = h.get("/mesh/ui/secrets/" + ids["novalue"].String()).Body.String()
	if !strings.Contains(body, "No value yet") || !strings.Contains(body, "keep input-link novalue") || strings.Contains(body, "banner") {
		t.Fatal("no-value state")
	}
	if strings.Contains(h.get("/mesh/ui/secrets/"+ids["insync"].String()).Body.String(), `class="banner`) {
		t.Fatal("banner on a secret in sync")
	}
	// Five newest runs, a link to all of them with the total.
	var runs []RunSummary
	for i := range 7 {
		runs = append(runs, RunSummary{ID: uuid.New(), State: "done", OldVersion: fmt.Sprintf("r%d", i+1), NewVersion: fmt.Sprintf("r%d", i), CreatedAt: uiT0})
	}
	h.rot.runs[ids["insync"]] = runs
	body = h.get("/mesh/ui/secrets/" + ids["insync"].String()).Body.String()
	if n := strings.Count(body, "/rotations/"); n != 5 || !strings.Contains(body, "All rotations (7)") || !strings.Contains(body, "r1 → r0") || strings.Contains(body, "r6 → r5") {
		t.Fatalf("rotations block: %d runs", n)
	}
	// Nil readers hide their blocks.
	h2 := newUIHarness(t, false, false)
	id := h2.secret("bare", "key", "v1")
	body = h2.get("/mesh/ui/secrets/" + id.String()).Body.String()
	if strings.Contains(body, "<h2>Rotations") || strings.Contains(body, "<h2>Carriers") || !strings.Contains(body, "<h2>Versions") {
		t.Fatal("blocks of nil readers shown")
	}
	if list := h2.get("/mesh/ui/secrets").Body.String(); strings.Contains(list, "Carriers in sync") || strings.Contains(list, "Rotating now") || !strings.Contains(list, "Stored") {
		t.Fatal("list columns of nil readers shown")
	}
}

func TestMeshUISecretsEmptyAndEscaped(t *testing.T) {
	h := newUIHarness(t, true, true)
	if body := h.get("/mesh/ui/secrets").Body.String(); !strings.Contains(body, "No secrets yet") || strings.Contains(body, "keep input-link ") || strings.Contains(body, "<table") {
		t.Fatal("empty catalog state")
	}
	id := h.secret(`<script>alert(1)</script>`, "key", "v1")
	body := h.get("/mesh/ui/secrets?q=%3Cimg%20src%3Dx%3E").Body.String()
	if !strings.Contains(body, "No secret matches “&lt;img src=x&gt;”") || !strings.Contains(body, "Reset filters") || strings.Contains(body, "<img src=x>") {
		t.Fatal("no-match state or its escaping")
	}
	for _, p := range []string{"/mesh/ui/secrets", "/mesh/ui/secrets/" + id.String()} {
		body := h.get(p).Body.String()
		if strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
			t.Fatalf("%s: hostile name not escaped", p)
		}
	}
}

// TestMeshUISecretPageDrift: a carrier registered at the current version whose
// last check saw another fingerprint keeps its row's version, so the page must
// not say it holds that version or an old one: it is drift. Only a fingerprint
// equal to an older version's names that version.
func TestMeshUISecretPageDrift(t *testing.T) {
	h := newUIHarness(t, true, false)
	id := h.secret("drift", "api_token", "v2", "v1")
	h.carrier(id, "g", carriers.Stale, "v2", false)
	h.car.list[id][0].LastFP = "kfp1:k1:ZZZZZZZZZZ"
	body := strings.ReplaceAll(h.get("/mesh/ui/secrets/"+id.String()).Body.String(), "<wbr>", "")
	for _, w := range []string{"Drift · not v2", "1 of 1 carriers are not on the current version (v2).",
		"g /etc/g/app.env no longer matches v2 by fingerprint.", "Lay out v2 to it again", "keep deploy drift"} {
		if !strings.Contains(body, w) {
			t.Fatalf("drift page lacks %q", w)
		}
	}
	for _, w := range []string{"holds v2", "holds v1", "old version", "In sync"} {
		if strings.Contains(body, w) {
			t.Fatalf("drift page says %q", w)
		}
	}
	// The observed fingerprint is the older version's: the carrier holds v1.
	h.car.list[id][0].LastFP = h.src.versions[id][1].Fingerprint
	body = strings.ReplaceAll(h.get("/mesh/ui/secrets/"+id.String()).Body.String(), "<wbr>", "")
	for _, w := range []string{"Stale · holds v1", "g /etc/g/app.env holds v1."} {
		if !strings.Contains(body, w) {
			t.Fatalf("stale page lacks %q", w)
		}
	}
	if strings.Contains(body, "Drift") {
		t.Fatal("a carrier on a known older version is called drift")
	}
}

// Long names, hosts and paths get a break point after every separator and in
// every long run, so the page fits a 393 px frame under any stylesheet; joined
// back, the parts are the text itself.
func TestMeshUIWrapTextBreaksLongRuns(t *testing.T) {
	// The rendering limit is part of the narrow-frame contract, independent
	// of the implementation's wrapRun constant.
	if got := wrapText(strings.Repeat("x", 40)).Parts(); len(got) != 3 || len(got[0]) != 16 || len(got[1]) != 16 || len(got[2]) != 8 {
		t.Fatal("unbroken name must wrap after 16 characters")
	}
	for _, in := range []string{"", "a", "deploy-token", "/srv/a/very/deep/path/token.env", "a-host-with-a-long-name.example.test",
		strings.Repeat("x", 40), "name-" + strings.Repeat("\u00e9", 20)} {
		parts := wrapText(in).Parts()
		if strings.Join(parts, "") != in {
			t.Fatalf("%q: parts %q do not join back", in, parts)
		}
		for i, p := range parts {
			if n := len([]rune(p)); n > wrapRun || (i < len(parts)-1 && n < wrapRun && !strings.ContainsAny(p[len(p)-1:], "/.-_:@ ")) {
				t.Fatalf("%q: part %q is not cut at a separator or at %d runes", in, p, wrapRun)
			}
		}
	}
	if got := wrapText("/etc/app/db.env").Parts(); strings.Join(got, "|") != "/|etc/|app/|db.|env" {
		t.Fatalf("path parts %q", got)
	}
	h := newUIHarness(t, true, false)
	id := h.secret("a-very-long-secret-name", "api_token", "v2", "v1")
	h.carrier(id, "web-1.example.test", carriers.Stale, "v1", true)
	body := h.get("/mesh/ui/secrets/" + id.String()).Body.String()
	for _, w := range []string{"<h1>a-<wbr>very-<wbr>long-<wbr>secret-<wbr>name</h1>", "<b>web-<wbr>1.<wbr>example.<wbr>test</b>"} {
		if !strings.Contains(body, w) {
			t.Fatalf("secret page lacks the break points %q", w)
		}
	}
}

func TestMeshUIVersionLabel(t *testing.T) {
	for in, want := range map[string]string{"1": "v1", "12": "v12", "v3": "v3", "": "", "2024-01-01": "2024-01-01", "abc1": "abc1"} {
		if got := versionLabel(in); got != want {
			t.Fatalf("versionLabel(%q) = %q, want %q", in, got, want)
		}
	}
	h := newUIHarness(t, true, false)
	id := h.secret("numbered", "api_token", "2", "1")
	h.carrier(id, "web-1", carriers.Registered, "1", true)
	body := h.get("/mesh/ui/secrets/" + id.String()).Body.String()
	for _, w := range []string{"Stale · holds v1", "Lay out v2 to it again", "<b>v2</b>", "<b>v1</b>"} {
		if !strings.Contains(body, w) {
			t.Fatalf("secret page lacks %q", w)
		}
	}
	if list := h.get("/mesh/ui/secrets").Body.String(); !strings.Contains(list, "v2 <span class=\"mono\">") {
		t.Fatal("list does not label the current version")
	}
}
