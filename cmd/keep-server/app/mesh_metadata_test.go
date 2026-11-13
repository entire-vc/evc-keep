package app

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// The metadata probe: GET /orgs/{org}/mesh/secrets/{ref}/metadata answers the
// version and the length of the newest active version, and nothing else.

func (f *meshFixture) metadataPath(org uuid.UUID, ref string) string {
	return "/orgs/" + org.String() + "/mesh/secrets/" + ref + "/metadata"
}

func (f *meshFixture) metadata(ws uuid.UUID, ref string) *httptest.ResponseRecorder {
	return f.secretsDo(secretCall{method: http.MethodGet, path: f.metadataPath(f.org.ID, ref), ws: ws, secret: meshTestEventsSecret})
}

var (
	metadataOKBody  = regexp.MustCompile(`^\{"version":"[1-9][0-9]*","length":[1-9][0-9]*,"request_id":"[A-Za-z0-9._-]{1,128}"\}\n?$`)
	metadata404Body = `{"error_class":"not_found","message":"not found","request_id":""}`
)

// effectTables are the tables a metadata call must leave exactly as they
// were: the target envelopes, the installation, the events and the other
// business and binding data. Only the nonce store and the journal may change.
var effectTables = []string{
	"keep_envelope", "mesh_installations", "mesh_events", "mesh_pending_installs", "stores", "organizations",
}

func (f *meshFixture) effectSnapshot() map[string]string {
	f.t.Helper()
	out := map[string]string{}
	for _, tb := range effectTables {
		var s string
		if err := f.pool.QueryRow(context.Background(),
			`SELECT coalesce(md5(string_agg(row_to_json(x)::text, E'\n' ORDER BY row_to_json(x)::text)), '') FROM `+tb+` x`).Scan(&s); err != nil {
			f.t.Fatalf("snapshot %s: %v", tb, err)
		}
		out[tb] = s
	}
	return out
}

// Leak test (written before the feature). The probe's answer is exactly
// version, length and a server request id; the value is on no surface:
// not in the body, a header, the log, the journal, any table, nor in a failure.
func TestMeshMetadataLeaksNothing(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	c := canary.New()
	val := c.Value(1)
	if !c.In("x"+val) || !c.In(hex.EncodeToString([]byte(val))) {
		t.Fatal("canary detector is blind")
	}
	if f.putSecret(ws, "smtp-password", val).Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	before := f.effectSnapshot()

	rec := f.metadata(ws, "smtp-password")
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, body = %s", rec.Code, answerDiag(rec))
	}
	if !metadataOKBody.MatchString(rec.Body.String()) {
		t.Fatalf("metadata body is not the closed 3-field shape: %s", answerDiag(rec))
	}
	if got := strings.Join(jsonKeys(t, rec.Body.Bytes()), ","); got != "length,request_id,version" {
		t.Fatalf("metadata fields = %s", got)
	}
	if !strings.Contains(rec.Body.String(), `"version":"1"`) || !strings.Contains(rec.Body.String(), `"length":`+strconv.Itoa(len(val))+`,`) {
		t.Fatalf("metadata does not describe the stored version: %s", answerDiag(rec))
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	// The header set is closed too: a ref or a length in a header is a leak
	// the body check would not see.
	for name := range rec.Header() {
		if name != "Cache-Control" && name != "Content-Type" && name != "X-Request-Id" {
			t.Errorf("unexpected response header %q", name)
		}
	}
	if c.In(rec.Body.String()) || c.In(headersText(rec)) {
		t.Fatal("value leaked in the metadata answer")
	}
	for name, r := range map[string]*httptest.ResponseRecorder{
		"missing ref": f.metadata(ws, "no-such-ref"),
		"bad ref":     f.metadata(ws, "a..b"),
		"bad sig": f.secretsDo(secretCall{method: http.MethodGet, path: f.metadataPath(f.org.ID, "smtp-password"),
			ws: ws, secret: "another-secret-0123456789"}),
	} {
		if r.Code < 400 || c.In(r.Body.String()) || c.In(headersText(r)) || r.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: status %d, a value or a cacheable failure answer", name, r.Code)
		}
	}
	for i, s := range f.surfaces() {
		if c.In(s) {
			t.Errorf("value found on surface %d (0=log 1=audit 2=installations 3=events 4=sealed storage)", i)
		}
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("log captured nothing; the test proves nothing")
	}
	after := f.effectSnapshot()
	for tb, h := range before {
		if after[tb] != h {
			t.Errorf("a metadata call changed table %s", tb)
		}
	}
}

// Every request that must not be served is refused, and a refusal reads
// nothing: the positive control after the whole table still answers.
func TestMeshMetadataRejectsRedInputs(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	c := canary.New()
	if f.putSecret(ws, "real", c.Value(1)).Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	path := f.metadataPath(f.org.ID, "real")
	now := time.Now()
	base := func() secretCall {
		return secretCall{method: http.MethodGet, path: path, ws: ws, secret: meshTestEventsSecret}
	}
	cases := []struct {
		name string
		mod  func(*secretCall)
		want int
	}{
		{"method tamper", func(s *secretCall) { s.signMethod = http.MethodPost }, 401},
		{"path tamper", func(s *secretCall) { s.signPath = f.metadataPath(f.org.ID, "other") }, 401},
		{"body tamper", func(s *secretCall) { s.body = []byte(`{}`); s.signBody = []byte{} }, 401},
		{"query tamper is a refusal after the HMAC", func(s *secretCall) { s.path = path + "?ref=other"; s.signPath = path }, 400},
		{"stale timestamp", func(s *secretCall) { s.ts = now.Add(-10 * time.Minute) }, 401},
		{"future timestamp", func(s *secretCall) { s.ts = now.Add(10 * time.Minute) }, 401},
		{"missing nonce", func(s *secretCall) { s.hdr = map[string]string{"X-Mesh-Nonce": ""} }, 401},
		{"short nonce", func(s *secretCall) { s.nonce = "abc" }, 401},
		{"bad nonce alphabet", func(s *secretCall) { s.nonce = strings.Repeat("!", 32) }, 401},
		{"wrong key", func(s *secretCall) { s.secret = meshTestWrongSecret }, 401},
		{"unsigned", func(s *secretCall) { s.secret = "" }, 401},
		{"foreign org in path", func(s *secretCall) {
			s.path = f.metadataPath(uuid.New(), "real")
		}, 403},
		{"signed non-empty body is a refusal after the HMAC", func(s *secretCall) { s.body = []byte(`{}`); s.signBody = []byte(`{}`) }, 400},
		{"invalid ref", func(s *secretCall) { s.path = f.metadataPath(f.org.ID, "a..b") }, 400},
		{"missing ref", func(s *secretCall) { s.path = f.metadataPath(f.org.ID, "absent") }, 404},
		{"HEAD", func(s *secretCall) { s.method = http.MethodHead }, 405},
		{"oversize body", func(s *secretCall) { s.body = []byte(strings.Repeat("x", 4097)); s.signBody = []byte{} }, 413},
	}
	for _, tc := range cases {
		sc := base()
		tc.mod(&sc)
		rec := f.secretsDo(sc)
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, rec.Code, tc.want, answerDiag(rec))
		}
		if strings.Contains(rec.Body.String(), `"version"`) || strings.Contains(rec.Body.String(), `"length"`) || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: metadata or a cacheable answer on a refusal", tc.name)
		}
	}
	if rec := f.metadata(ws, "real"); rec.Code != http.StatusOK {
		t.Fatalf("positive control after the red inputs = %d", rec.Code)
	}
}

// Replay: the same signed request is served once.
func TestMeshMetadataNonceIsSingleUse(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	if f.putSecret(ws, "k", "v-0123456789").Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	nonce := freshNonce(t)
	call := secretCall{method: http.MethodGet, path: f.metadataPath(f.org.ID, "k"), ws: ws, secret: meshTestEventsSecret, nonce: nonce}
	if rec := f.secretsDo(call); rec.Code != http.StatusOK {
		t.Fatalf("first use = %d", rec.Code)
	}
	rec := f.secretsDo(call)
	if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), `"version"`) {
		t.Fatalf("replay = %d %s, want 401 and no metadata", rec.Code, answerDiag(rec))
	}
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.secret.metadata' AND result_status='failed' AND result_error_class='permission_denied' AND secret_name=''`,
		f.org.ID.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audited nameless replays = %d (%v), want 1", n, err)
	}
}

// Another installation, a reinstalled one, and a missing, disabled or erased
// ref: foreign and missing are the same 404; the positive is restored.
func TestMeshMetadataNamespaceAndLifecycle(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	other := f.installedWorkspace()
	ctx := context.Background()
	for _, ref := range []string{"mine", "off", "gone"} {
		if f.putSecret(ws, ref, "value-"+ref+"-0123456789").Code != http.StatusOK {
			t.Fatal("setup PUT failed")
		}
	}
	if rec := f.putSecret(ws, "mine", "second-version-0123456789"); rec.Code != http.StatusOK {
		t.Fatal("setup second version failed")
	}
	rec := f.metadata(ws, "mine")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"version":"2"`) || !strings.Contains(rec.Body.String(), `"length":25,`) {
		t.Fatalf("newest active version not reported: %d %s", rec.Code, answerDiag(rec))
	}
	if _, err := f.pool.Exec(ctx, `UPDATE keep_envelope SET status='disabled' WHERE name=$1`, "mesh/"+ws.String()+"/secrets/off"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE keep_envelope SET status='erased', wrapped_dek=NULL, kek_id=NULL WHERE name=$1`, "mesh/"+ws.String()+"/secrets/gone"); err != nil {
		t.Fatal(err)
	}
	var shape []string
	for name, r := range map[string]*httptest.ResponseRecorder{
		"foreign namespace": f.metadata(other, "mine"),
		"missing":           f.metadata(ws, "never-written"),
		"disabled":          f.metadata(ws, "off"),
		"erased":            f.metadata(ws, "gone"),
	} {
		if r.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", name, r.Code)
		}
		shape = append(shape, name+"="+stripRequestID(r.Body.String()))
	}
	for _, s := range shape {
		if !strings.HasSuffix(s, "="+metadata404Body+"\n") && !strings.HasSuffix(s, "="+metadata404Body) {
			t.Errorf("404 differs from the one safe answer: %s", s)
		}
	}
	if f.metadata(ws, "mine").Code != http.StatusOK {
		t.Fatal("positive control after the 404s failed")
	}
	// Reinstall rotates the events secret: the old signature no longer serves.
	installedKeepSecret(t, f.install(f.admin, ws, "tok-2", meshTestRotatedSecret))
	if rec := f.metadata(ws, "mine"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old events secret still reads metadata: %d", rec.Code)
	}
	rec = f.secretsDo(secretCall{method: http.MethodGet, path: f.metadataPath(f.org.ID, "mine"), ws: ws, secret: meshTestRotatedSecret})
	if rec.Code != http.StatusOK {
		t.Fatalf("new events secret does not read metadata: %d", rec.Code)
	}
	// An uninstalled workspace is unknown: 401, no metadata.
	ghost := uuid.New()
	if rec := f.secretsDo(secretCall{method: http.MethodGet, path: f.metadataPath(f.org.ID, "mine"), ws: ghost, secret: meshTestEventsSecret}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown installation = %d, want 401", rec.Code)
	}
}

// The journal: a real record per verified call, chain intact, nothing but the
// nonce and the journal written, and a refusing journal or nonce store gives
// a 503 without metadata.
func TestMeshMetadataAuditedAndFailClosed(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws := f.installedWorkspace()
	val := "audited-value-0123456789"
	if f.putSecret(ws, "api-key", val).Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	before := f.effectSnapshot()
	if f.metadata(ws, "api-key").Code != http.StatusOK || f.metadata(ws, "missing").Code != http.StatusNotFound || f.metadata(ws, "a..b").Code != http.StatusBadRequest {
		t.Fatal("setup calls failed")
	}
	f.secretsDo(secretCall{method: http.MethodGet, path: f.metadataPath(uuid.New(), "api-key"), ws: ws, secret: meshTestEventsSecret})
	type row struct {
		status, actorType, actorID, via, name, version, fp, class string
		length                                                    int
	}
	rows, err := f.pool.Query(ctx, `SELECT result_status, actor_type, actor_id, actor_via, secret_name, secret_version, result_fingerprint, result_error_class, result_length
		FROM audit_records WHERE org_id=$1 AND action='mesh.secret.metadata' ORDER BY org_seq`, f.org.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.status, &r.actorType, &r.actorID, &r.via, &r.name, &r.version, &r.fp, &r.class, &r.length); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	rows.Close()
	want := []row{
		{"ok", "service", ws.String(), "mesh-plugin", "api-key", "1", "", "", len(val)},
		{"failed", "service", ws.String(), "mesh-plugin", "", "", "", "not_found", 0},
		{"failed", "service", ws.String(), "mesh-plugin", "", "", "", "invalid_argument", 0},
		{"failed", "service", ws.String(), "mesh-plugin", "", "", "", "permission_denied", 0},
	}
	// The probe is journaled as its own action and never as a resolve.
	var resolves int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.secret.resolve'`, f.org.ID.String()).Scan(&resolves); err != nil || resolves != 0 {
		t.Fatalf("metadata calls left %d resolve records (err %v)", resolves, err)
	}
	if len(got) != len(want) {
		t.Fatalf("journal records = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("record %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if res, err := audit.Verify(ctx, f.pool, f.org.ID.String()); err != nil || !res.OK {
		t.Fatalf("journal chain after the calls: ok=%v err=%v", res.OK, err)
	}
	after := f.effectSnapshot()
	for tb, h := range before {
		if after[tb] != h {
			t.Errorf("metadata calls changed table %s", tb)
		}
	}

	// A journal that refuses: no metadata, a 503.
	f.refuseAudit("mesh.secret.metadata", "ok")
	rec := f.metadata(ws, "api-key")
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), `"version"`) || strings.Contains(rec.Body.String(), `"length"`) {
		t.Errorf("success with a refusing journal = %d %s, want 503 and no metadata", rec.Code, answerDiag(rec))
	}
	f.dropAuditRefusal()
	f.refuseAudit("mesh.secret.metadata", "failed")
	if rec := f.metadata(ws, "absent"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("refusal with a refusing journal = %d, want 503", rec.Code)
	}
	f.dropAuditRefusal()
	if rec := f.metadata(ws, "api-key"); rec.Code != http.StatusOK {
		t.Fatalf("control with a working journal = %d", rec.Code)
	}

	// A nonce store that fails: no metadata.
	if _, err := f.pool.Exec(ctx, `ALTER TABLE mesh_secret_nonces RENAME TO mesh_secret_nonces_off`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(ctx, `ALTER TABLE IF EXISTS mesh_secret_nonces_off RENAME TO mesh_secret_nonces`)
	})
	rec = f.metadata(ws, "api-key")
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), `"version"`) {
		t.Errorf("nonce store failure = %d %s, want 503 and no metadata", rec.Code, answerDiag(rec))
	}
	if res, err := audit.Verify(ctx, f.pool, f.org.ID.String()); err != nil || !res.OK {
		t.Fatalf("journal chain after the failures: ok=%v err=%v", res.OK, err)
	}
}

// The route has its own bounded budget, and the unaffected resolve keeps its own.
func TestMeshMetadataIsRateLimited(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	if f.putSecret(ws, "k", "v-0123456789").Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	var ok, limited int
	for i := 0; i < 14; i++ {
		switch rec := f.metadata(ws, "k"); rec.Code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
			if !strings.Contains(rec.Body.String(), `"request rate limited"`) || strings.Contains(rec.Body.String(), `"version"`) {
				t.Errorf("429 answer = %s", answerDiag(rec))
			}
		default:
			t.Fatalf("call %d = %d", i, rec.Code)
		}
	}
	if ok != 10 || limited != 4 {
		t.Fatalf("burst 10: ok=%d limited=%d, want 10 and 4", ok, limited)
	}
	if f.resolveSecret(ws, "k").Code != http.StatusOK {
		t.Fatal("the metadata budget spent the resolve budget")
	}
}
