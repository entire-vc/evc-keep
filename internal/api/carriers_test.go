package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

const carrierVersionFP = "kfp1:k1:abcdefghijklmnop"

// carrierRunner is the runner the fake service names on every carrier.
var carrierRunner = uuid.MustParse("5b0c1f3e-7a64-4d2e-9c11-0e5f6a7b8c9d")

type fakeCarriers struct {
	registered []carriers.Metadata
	versions   []string
	secrets    []uuid.UUID
	orgs       []uuid.UUID
	listOrgs   []uuid.UUID
	listed     []carriers.Carrier
	err        error
}

func (f *fakeCarriers) Register(_ context.Context, org, secret uuid.UUID, version string, md carriers.Metadata) (carriers.Carrier, error) {
	f.orgs, f.secrets, f.versions, f.registered = append(f.orgs, org), append(f.secrets, secret), append(f.versions, version), append(f.registered, md)
	if f.err != nil {
		return carriers.Carrier{}, f.err
	}
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	md.HealthcheckRef = "unit-active" // the real service takes it from the deployment record
	return carriers.Carrier{ID: uuid.New(), OrgID: org, SecretID: secret, Version: version, Metadata: md,
		LastFP: carrierVersionFP, RunnerID: carrierRunner, State: carriers.Registered, LastVerifiedAt: &now}, nil
}

func (f *fakeCarriers) List(_ context.Context, org, _ uuid.UUID) ([]carriers.Carrier, error) {
	f.listOrgs = append(f.listOrgs, org)
	if f.err != nil {
		return nil, f.err
	}
	return f.listed, nil
}

type carrierFixture struct {
	*routeFixture
	svc    *fakeCarriers
	bearer string
	secret tenancy.SecretRef
	path   string
}

func newCarrierFixture(t *testing.T) *carrierFixture {
	t.Helper()
	f := newRouteFixture(t)
	svc := &fakeCarriers{}
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Carriers: svc})
	admin := f.mustAdmin("admin")
	st := f.mustStore("default", tenancy.Org(f.org.ID))
	ref, err := f.cat.CreateRef(f.ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: tenancy.Org(f.org.ID), Name: "db-password", Class: "credential", Type: "generic", ProviderRef: "builtin://default/db-password", StoreID: st.ID})
	if err != nil {
		t.Fatalf("create ref: %v", err)
	}
	if _, err = f.cat.AddVersion(f.ctx, f.org.ID, ref.ID, "7", carrierVersionFP, 12); err != nil {
		t.Fatalf("add version: %v", err)
	}
	return &carrierFixture{routeFixture: f, svc: svc, bearer: f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String()), secret: ref,
		path: fmt.Sprintf("/orgs/%s/secrets/%s/carriers", f.org.ID, ref.ID)}
}

func carrierBody(mutate func(map[string]any)) map[string]any {
	b := map[string]any{"version": "7", "host": "host-a", "target_kind": "env-file", "target_path": "/srv/app/.env",
		"target_field": "DB_PASSWORD", "consumer": "systemd:app.service"}
	if mutate != nil {
		mutate(b)
	}
	return b
}

func decodeClosed(t *testing.T, raw []byte, into any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(into); err != nil {
		t.Fatalf("response is not the closed row: %v: %s", err, raw)
	}
}

func TestCarrierRoutes_RegisterAnswersTheClosedRow(t *testing.T) {
	f := newCarrierFixture(t)
	rec := f.do(http.MethodPost, f.path, f.bearer, carrierBody(nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	var row Carrier
	decodeClosed(t, rec.Body.Bytes(), &row)
	if row.Host != "host-a" || row.Target != (CarrierTarget{Kind: "env-file", Path: "/srv/app/.env"}) || row.Status != "registered" || !row.FingerprintMatch ||
		row.SecretID != f.secret.ID.String() || row.Healthcheck != "unit-active" || row.RunnerID != carrierRunner.String() || row.Consumer != "systemd:app.service" || row.LastVerifiedAt == nil {
		t.Fatalf("row: %+v", row)
	}
	want := carriers.Metadata{Host: "host-a", TargetKind: runnerproto.TargetEnvFile, TargetPath: "/srv/app/.env", TargetField: "DB_PASSWORD", Consumer: "systemd:app.service"}
	if len(f.svc.registered) != 1 || f.svc.registered[0] != want || f.svc.versions[0] != "7" || f.svc.orgs[0] != f.org.ID || f.svc.secrets[0] != f.secret.ID {
		t.Fatalf("service saw %+v %v", f.svc.registered, f.svc.versions)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", rec.Header().Get("Cache-Control"))
	}
}

func TestCarrierRoutes_RefusesAnyFieldOutsideTheMetadata(t *testing.T) {
	f := newCarrierFixture(t)
	c := canary.New()
	for _, key := range []string{"value", "plaintext", "fingerprint", "last_fp", "secret_value", "runner_id", "state", "version_id", "healthcheck_ref"} {
		rec := f.do(http.MethodPost, f.path, f.bearer, carrierBody(func(b map[string]any) { b[key] = c.Value(1) }))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error_class":"invalid_argument"`) {
			t.Fatalf("%s: %d %s", key, rec.Code, rec.Body)
		}
		if c.In(rec.Body.String()) || c.In(f.logbuf.String()) {
			t.Fatalf("%s: canary reached the answer or the log", key)
		}
	}
	// A complete, valid body with the extra key last: refusal must come from
	// the decoder, not from a field that went missing before it.
	for _, key := range []string{"value", "fingerprint", "zzz"} {
		valid, err := json.Marshal(carrierBody(nil))
		if err != nil {
			t.Fatal(err)
		}
		raw := json.RawMessage(string(valid[:len(valid)-1]) + `,"` + key + `":"` + c.Value(3) + `"}`)
		if rec := f.do(http.MethodPost, f.path, f.bearer, raw); rec.Code != http.StatusBadRequest || c.In(rec.Body.String()) {
			t.Fatalf("trailing %s: %d %s", key, rec.Code, rec.Body)
		}
	}
	nested := carrierBody(func(b map[string]any) { b["target"] = map[string]any{"value": c.Value(2)} })
	if rec := f.do(http.MethodPost, f.path, f.bearer, nested); rec.Code != http.StatusBadRequest || c.In(rec.Body.String()) || c.In(f.logbuf.String()) {
		t.Fatalf("nested: %d %s", rec.Code, rec.Body)
	}
	if len(f.svc.registered) != 0 {
		t.Fatalf("a refused body reached the service: %+v", f.svc.registered)
	}
}

func TestCarrierRoutes_RefusesMalformedMetadata(t *testing.T) {
	f := newCarrierFixture(t)
	for name, mutate := range map[string]func(map[string]any){
		"no version":       func(b map[string]any) { delete(b, "version") },
		"no host":          func(b map[string]any) { delete(b, "host") },
		"no path":          func(b map[string]any) { delete(b, "target_path") },
		"unknown kind":     func(b map[string]any) { b["target_kind"] = "network" },
		"newline in path":  func(b map[string]any) { b["target_path"] = "/srv/a\n/b" },
		"huge path":        func(b map[string]any) { b["target_path"] = "/" + strings.Repeat("a", 5000) },
		"control in host":  func(b map[string]any) { b["host"] = "h\x00" },
		"number as string": func(b map[string]any) { b["version"] = 7 },
	} {
		if rec := f.do(http.MethodPost, f.path, f.bearer, carrierBody(mutate)); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if len(f.svc.registered) != 0 {
		t.Fatalf("a refused body reached the service")
	}
}

func TestCarrierRoutes_ServiceRefusalsAreClosedAndQuoteNothing(t *testing.T) {
	f := newCarrierFixture(t)
	c := canary.New()
	secretHost, secretPath := "h-"+c.Value(1), "/srv/"+c.Value(2)
	body := carrierBody(func(b map[string]any) { b["host"], b["target_path"] = secretHost, secretPath })
	for _, tc := range []struct {
		err    error
		status int
		class  string
	}{
		{carriers.ErrMetadata, http.StatusForbidden, "metadata_not_approved"},
		{carriers.ErrDeployment, http.StatusConflict, "deployment_not_confirmed"},
		{carriers.ErrFingerprint, http.StatusConflict, "deployment_not_confirmed"},
		{carriers.ErrNotFound, http.StatusNotFound, "secret_not_found"},
		{carriers.ErrInternal, http.StatusInternalServerError, "internal"},
		{fmt.Errorf("pq: %s %s", secretHost, secretPath), http.StatusInternalServerError, "internal"},
		{context.DeadlineExceeded, http.StatusInternalServerError, "internal"},
	} {
		f.svc.err = tc.err
		rec := f.do(http.MethodPost, f.path, f.bearer, body)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), `"error_class":"`+tc.class+`"`) {
			t.Fatalf("%v: %d %s", tc.err, rec.Code, rec.Body)
		}
		if c.In(rec.Body.String()) || strings.Contains(rec.Body.String(), "host-") || c.In(f.logbuf.String()) {
			t.Fatalf("%v: host or path reached the answer or the log: %s", tc.err, rec.Body)
		}
	}
}

func TestCarrierRoutes_ForeignAndUnauthorizedAnswerLikeMissing(t *testing.T) {
	f := newCarrierFixture(t)
	missing := f.do(http.MethodPost, fmt.Sprintf("/orgs/%s/secrets/%s/carriers", f.org.ID, uuid.New()), f.bearer, carrierBody(nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing secret: %d %s", missing.Code, missing.Body)
	}
	f.svc.err = carriers.ErrNotFound
	if rec := f.do(http.MethodPost, f.path, f.bearer, carrierBody(nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("service not found: %d", rec.Code)
	}
	f.svc.err = nil
	foreignOrg := fmt.Sprintf("/orgs/%s/secrets/%s/carriers", uuid.New(), f.secret.ID)
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		if rec := f.do(method, foreignOrg, f.bearer, carrierBody(nil)); rec.Code != http.StatusNotFound {
			t.Fatalf("foreign org %s: %d %s", method, rec.Code, rec.Body)
		}
	}
	plain := f.mustUser("plain")
	plainToken := f.mustToken(identity.KindUser, plain.ID, "org:"+f.org.ID.String())
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		rec := f.do(method, f.path, plainToken, carrierBody(nil))
		if rec.Code != http.StatusNotFound || normalizedBody(rec) != normalizedBody(missing) {
			t.Fatalf("no rights %s: %d %s", method, rec.Code, rec.Body)
		}
	}
	if rec := f.do(http.MethodPost, f.path, "", carrierBody(nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
	if len(f.svc.registered) != 1 { // only the explicit ErrNotFound call above
		t.Fatalf("service called %d times", len(f.svc.registered))
	}
}

// A token bound to another scope sees the secret as missing, even for its owner.
func TestCarrierRoutes_TokenOfAnotherScopeAnswersLikeMissing(t *testing.T) {
	f := newCarrierFixture(t)
	admin := f.mustAdmin("scoped-admin")
	narrow := f.mustToken(identity.KindUser, admin.ID, "ws:"+uuid.NewString())
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		if rec := f.do(method, f.path, narrow, carrierBody(nil)); rec.Code != http.StatusNotFound {
			t.Fatalf("%s with a token of another scope: %d %s", method, rec.Code, rec.Body)
		}
	}
	if len(f.svc.registered) != 0 {
		t.Fatal("the service was reached")
	}
}

func normalizedBody(rec *httptest.ResponseRecorder) string {
	return uuidText.ReplaceAllString(rec.Body.String(), "-")
}

var uuidText = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func TestCarrierRoutes_ListShowsClosedRowsAndFingerprintMatch(t *testing.T) {
	f := newCarrierFixture(t)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	mk := func(host, fp string, st carriers.State) carriers.Carrier {
		return carriers.Carrier{ID: uuid.New(), OrgID: f.org.ID, SecretID: f.secret.ID, Version: "7", LastFP: fp, RunnerID: carrierRunner, State: st, LastVerifiedAt: &now,
			Metadata: carriers.Metadata{Host: host, TargetKind: runnerproto.TargetFile, TargetPath: "/srv/" + host, TargetField: "SLOT"}}
	}
	f.svc.listed = []carriers.Carrier{mk("a", carrierVersionFP, carriers.Registered), mk("b", "kfp1:k1:zzzzzzzzzzzzzzzz", carriers.Stale)}
	rec := f.do(http.MethodGet, f.path, f.bearer, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var rows []Carrier
	decodeClosed(t, rec.Body.Bytes(), &rows)
	if len(rows) != 2 || !rows[0].FingerprintMatch || rows[1].FingerprintMatch || rows[0].RunnerID != carrierRunner.String() || rows[1].RunnerID != carrierRunner.String() || rows[1].Status != "stale" {
		t.Fatalf("rows: %+v", rows)
	}
	if strings.Contains(rec.Body.String(), "kfp1") || strings.Contains(rec.Body.String(), "SLOT") {
		t.Fatalf("a fingerprint or a field name is on the wire: %s", rec.Body)
	}
	f.svc.listed = nil
	if rec = f.do(http.MethodGet, f.path, f.bearer, nil); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list must be []: %s", rec.Body)
	}
}

func TestCarrierRoutes_UnavailableServiceAnswersNotReady(t *testing.T) {
	f := newCarrierFixture(t)
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{})
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		if rec := f.do(method, f.path, f.bearer, carrierBody(nil)); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"error_class":"not_ready"`) {
			t.Fatalf("%s: %d %s", method, rec.Code, rec.Body)
		}
	}
}

func TestCarrierRoutes_NewErrorClassesAreInTheClosedList(t *testing.T) {
	have := map[string]bool{}
	for _, k := range apperr.Classes() {
		have[string(k)] = true
	}
	for _, class := range []string{"metadata_not_approved", "deployment_not_confirmed"} {
		if !have[class] {
			t.Fatalf("class %s is not in apperr.Classes()", class)
		}
	}
}

// Registering needs the right to deploy: a read-only member sees the list but
// registers nothing, and is answered as if the secret did not exist.
func TestCarrierRoutes_RegisterNeedsTheRightToDeploy(t *testing.T) {
	f := newCarrierFixture(t)
	reader := f.mustUser("reader")
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, reader.ID, tenancy.Org(f.org.ID), string(identity.RoleViewer)); err != nil {
		t.Fatalf("grant viewer: %v", err)
	}
	token := f.mustToken(identity.KindUser, reader.ID, "org:"+f.org.ID.String())
	if rec := f.do(http.MethodGet, f.path, token, nil); rec.Code != http.StatusOK {
		t.Fatalf("control: a viewer must read the list: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(http.MethodPost, f.path, token, carrierBody(nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("a viewer registered a carrier: %d %s", rec.Code, rec.Body)
	}
	if len(f.svc.registered) != 0 {
		t.Fatal("the service was reached by a caller without the right to deploy")
	}
}

func TestCarrierRoutes_ListUsesTheCallersOrgAndNoStore(t *testing.T) {
	f := newCarrierFixture(t)
	rec := f.do(http.MethodGet, f.path, f.bearer, nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("list: %d Cache-Control %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if len(f.svc.listOrgs) != 1 || f.svc.listOrgs[0] != f.org.ID {
		t.Fatalf("list asked for orgs %v, want %v", f.svc.listOrgs, f.org.ID)
	}
}

// doRaw posts the text as it is: the shared helper marshals the body and
// would drop the padding.
func (f *carrierFixture) doRaw(path, bearer, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec
}

func TestCarrierRoutes_LimitsOfTheRequest(t *testing.T) {
	f := newCarrierFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   int
	}{
		{"host 253", func(b map[string]any) { b["host"] = strings.Repeat("a", 253) }, http.StatusCreated},
		{"host 254", func(b map[string]any) { b["host"] = strings.Repeat("a", 254) }, http.StatusBadRequest},
		{"path 4096", func(b map[string]any) { b["target_path"] = "/" + strings.Repeat("a", 4095) }, http.StatusCreated},
		{"path 4097", func(b map[string]any) { b["target_path"] = "/" + strings.Repeat("a", 4096) }, http.StatusBadRequest},
		{"body under the limit", func(b map[string]any) {
			b["consumer"] = strings.Repeat("c", 256)
			b["target_field"] = strings.Repeat("f", 256)
		}, http.StatusCreated},
	} {
		if rec := f.do(http.MethodPost, f.path, f.bearer, carrierBody(tc.mutate)); rec.Code != tc.want {
			t.Fatalf("%s: want %d, got %d %s", tc.name, tc.want, rec.Code, rec.Body)
		}
	}
	// A valid body padded past 8 KiB with insignificant whitespace is refused
	// by the size limit, not by the content.
	valid, err := json.Marshal(carrierBody(nil))
	if err != nil {
		t.Fatal(err)
	}
	padded := strings.Repeat(" ", 9000) + string(valid)
	before := len(f.svc.registered)
	if rec := f.doRaw(f.path, f.bearer, padded); rec.Code != http.StatusBadRequest {
		t.Fatalf("a body over 8 KiB: %d", rec.Code)
	}
	small := strings.Repeat(" ", 3000) + string(valid)
	if rec := f.doRaw(f.path, f.bearer, small); rec.Code != http.StatusCreated {
		t.Fatalf("a body of 3 KiB: %d %s", rec.Code, rec.Body)
	}
	if len(f.svc.registered) != before+1 {
		t.Fatalf("the oversized body reached the service")
	}
}

// A disabled version is never the current one: a carrier holding the newest
// enabled version still matches.
func TestCarrierRoutes_DisabledVersionIsNotCurrent(t *testing.T) {
	f := newCarrierFixture(t)
	v, err := f.cat.AddVersion(f.ctx, f.org.ID, f.secret.ID, "8", "kfp1:k1:zzzzzzzzzzzzzzzz", 12)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE secret_versions SET disabled=true WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	rec := f.do(http.MethodPost, f.path, f.bearer, carrierBody(nil))
	var row Carrier
	decodeClosed(t, rec.Body.Bytes(), &row)
	if rec.Code != http.StatusCreated || !row.FingerprintMatch {
		t.Fatalf("a disabled newer version made the carrier look stale: %d %+v", rec.Code, row)
	}
}
