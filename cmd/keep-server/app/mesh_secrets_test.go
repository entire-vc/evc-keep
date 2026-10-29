package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

const meshTestEventsSecret = "events-secret-0123456789"

// Other signing keys of the red inputs: not the install's secret.
var (
	meshTestWrongSecret   = strings.Repeat("w", 24)
	meshTestRotatedSecret = strings.Repeat("r", 24)
)

// meshSecretMAC is the Mesh side of the K5.9 protocol, written independently
// of the server: HMAC-SHA256 under the events secret over the domain tag, the
// timestamp, the nonce, the method, the path and the sha256 of the body.
func meshSecretMAC(secret string, ts time.Time, nonce, method, path string, body []byte) map[string]string {
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	sum := sha256.Sum256(body)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("keep-mesh-secret-v1\n" + tsStr + "\n" + nonce + "\n" + method + "\n" + path + "\n" + hex.EncodeToString(sum[:])))
	return map[string]string{"X-Mesh-Timestamp": tsStr, "X-Mesh-Nonce": nonce, "X-Mesh-Signature": "v1=" + hex.EncodeToString(m.Sum(nil))}
}

type secretCall struct {
	method, path string
	body         []byte
	ws           uuid.UUID
	secret       string            // key the request is signed with; "" = unsigned
	nonce        string            // "" = a fresh random one per call
	ts           time.Time         // zero = now
	signPath     string            // sign a different path than the one sent
	signBody     []byte            // sign a different body than the one sent
	signMethod   string            // sign a different method than the one sent
	bearer       string            // an Authorization bearer to add
	hdr          map[string]string // overrides
}

func (f *meshFixture) secretsDo(c secretCall) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(c.method, c.path, bytes.NewReader(c.body))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	if c.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.secret != "" {
		ts, sp, sb, sm := c.ts, c.signPath, c.signBody, c.signMethod
		if ts.IsZero() {
			ts = time.Now()
		}
		if sp == "" {
			sp = c.path
		}
		if sb == nil {
			sb = c.body
		}
		if sm == "" {
			sm = c.method
		}
		r.Header.Set("X-Mesh-Workspace", c.ws.String())
		nonce := c.nonce
		if nonce == "" {
			nonce = freshNonce(f.t)
		}
		for k, v := range meshSecretMAC(c.secret, ts, nonce, sm, sp, sb) {
			r.Header.Set(k, v)
		}
	}
	for k, v := range c.hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec
}

var requestIDField = regexp.MustCompile(`"request_id":"[^"]*"`)

// stripRequestID blanks the one field that differs between two answers.
func stripRequestID(body string) string {
	return requestIDField.ReplaceAllString(body, `"request_id":""`)
}

// freshNonce is 32 hex characters from the system random source.
func freshNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func (f *meshFixture) secretPath(org uuid.UUID, ref string, resolve bool) string {
	p := "/orgs/" + org.String() + "/mesh/secrets/" + ref
	if resolve {
		p += "/resolve"
	}
	return p
}

func (f *meshFixture) putSecret(ws uuid.UUID, ref, value string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"value": value})
	return f.secretsDo(secretCall{method: http.MethodPut, path: f.secretPath(f.org.ID, ref, false), body: body, ws: ws, secret: meshTestEventsSecret})
}

func (f *meshFixture) resolveSecret(ws uuid.UUID, ref string) *httptest.ResponseRecorder {
	return f.secretsDo(secretCall{method: http.MethodPost, path: f.secretPath(f.org.ID, ref, true), ws: ws, secret: meshTestEventsSecret})
}

func (f *meshFixture) installedWorkspace() uuid.UUID {
	f.t.Helper()
	ws := uuid.New()
	installedKeepSecret(f.t, f.install(f.admin, ws, "tok-1", meshTestEventsSecret))
	return ws
}

func jsonKeys(t *testing.T, body []byte) []string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("not a JSON object (%d bytes)", len(body))
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// everywhereButResolveBody dumps every surface the value must never reach:
// the log, the audit journal, the metadata tables and the sealed storage.
func (f *meshFixture) surfaces() []string {
	f.t.Helper()
	ctx := context.Background()
	out := []string{f.logbuf.String()}
	for _, q := range []string{
		`SELECT coalesce(string_agg(row_to_json(a)::text, E'\n'), '') FROM audit_records a`,
		`SELECT coalesce(string_agg(row_to_json(m)::text, E'\n'), '') FROM mesh_installations m`,
		`SELECT coalesce(string_agg(row_to_json(e)::text, E'\n'), '') FROM mesh_events e`,
		`SELECT coalesce(string_agg(row_to_json(k)::text, E'\n'), '') FROM keep_envelope k`,
	} {
		var s string
		if err := f.pool.QueryRow(ctx, q).Scan(&s); err != nil {
			f.t.Fatalf("dump surface: %v", err)
		}
		out = append(out, s)
	}
	return out
}

func headersText(rec *httptest.ResponseRecorder) string {
	var b strings.Builder
	for k, vs := range rec.Header() {
		b.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
	}
	return b.String()
}

// Leak test (written before the feature). The value Mesh stores is on exactly
// one surface, the body of a successful resolve. It is not in the PUT answer,
// in any header, in the log, in the audit journal, in the metadata tables, in
// sealed storage, and not in any failure answer.
func TestMeshSecretValueOnlyInResolveBody(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	c := canary.New()
	val := c.Value(1)
	if !c.In("x"+val) || !c.In(hex.EncodeToString([]byte(val))) {
		t.Fatal("canary detector is blind")
	}

	put := f.putSecret(ws, "smtp-password", val)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", put.Code, answerDiag(put))
	}
	if got := jsonKeys(t, put.Body.Bytes()); strings.Join(got, ",") != "fingerprint,ref,version" {
		t.Fatalf("PUT answer fields = %v, want exactly fingerprint, ref, version", got)
	}
	var meta struct{ Ref, Version, Fingerprint string }
	_ = json.Unmarshal(put.Body.Bytes(), &meta)
	if meta.Ref != "smtp-password" || meta.Version == "" || !strings.HasPrefix(meta.Fingerprint, "kfp1:") {
		t.Fatalf("PUT answer = %s", answerDiag(put))
	}
	if cc := put.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("PUT Cache-Control = %q, want no-store", cc)
	}
	if c.In(put.Body.String()) || c.In(headersText(put)) {
		t.Fatal("value leaked in the PUT answer")
	}

	res := f.resolveSecret(ws, "smtp-password")
	if res.Code != http.StatusOK {
		t.Fatalf("resolve status = %d, body = %s", res.Code, answerDiag(res))
	}
	if got := jsonKeys(t, res.Body.Bytes()); strings.Join(got, ",") != "value,version" {
		t.Fatalf("resolve answer fields = %v, want exactly value, version", got)
	}
	var out struct{ Value, Version string }
	_ = json.Unmarshal(res.Body.Bytes(), &out)
	if out.Value != val || out.Version != meta.Version {
		t.Fatalf("resolve returned a different value or version than PUT stored (version %q vs %q)", out.Version, meta.Version)
	}
	if cc := res.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("resolve Cache-Control = %q, want no-store", cc)
	}
	if ct := res.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("resolve Content-Type = %q, want application/json", ct)
	}
	if c.In(headersText(res)) {
		t.Fatal("value leaked in a resolve header")
	}

	// A second PUT is a new version, and resolve returns the newest.
	val2 := c.Value(2)
	put2 := f.putSecret(ws, "smtp-password", val2)
	var meta2 struct{ Version, Fingerprint string }
	_ = json.Unmarshal(put2.Body.Bytes(), &meta2)
	if put2.Code != http.StatusOK || meta2.Version == meta.Version || meta2.Fingerprint == meta.Fingerprint {
		t.Fatalf("second PUT must be a new version: %s", answerDiag(put2))
	}
	res2 := f.resolveSecret(ws, "smtp-password")
	_ = json.Unmarshal(res2.Body.Bytes(), &out)
	if out.Value != val2 || out.Version != meta2.Version {
		t.Fatal("resolve did not return the newest version")
	}

	// Failure answers carry no value.
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"unknown ref": f.resolveSecret(ws, "no-such-ref"),
		"bad ref":     f.resolveSecret(ws, "a..b"),
		"bad sig": f.secretsDo(secretCall{method: http.MethodPost, path: f.secretPath(f.org.ID, "smtp-password", true),
			ws: ws, secret: "another-secret-0123456789"}),
	} {
		if rec.Code < 400 || c.In(rec.Body.String()) || c.In(headersText(rec)) {
			t.Errorf("%s: status %d or value on the failure answer", name, rec.Code)
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
}

// Every PUT and resolve is in the audit journal with the actor, the ref, the
// version and the fingerprint, and a refusal is journaled too without a value.
func TestMeshSecretAudited(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws := f.installedWorkspace()
	c := canary.New()
	var meta struct{ Version, Fingerprint string }
	put := f.putSecret(ws, "api-key", c.Value(1))
	_ = json.Unmarshal(put.Body.Bytes(), &meta)
	if put.Code != http.StatusOK || f.resolveSecret(ws, "api-key").Code != http.StatusOK {
		t.Fatal("setup PUT/resolve failed")
	}
	if f.resolveSecret(ws, "missing").Code != http.StatusNotFound {
		t.Fatal("setup: missing ref must be 404")
	}
	type row struct {
		action, status, actorType, actorID, via, name, version, fp string
		length                                                     int
	}
	rows, err := f.pool.Query(ctx, `SELECT action, result_status, actor_type, actor_id, actor_via, secret_name, secret_version, result_fingerprint, result_length
		FROM audit_records WHERE org_id=$1 AND action LIKE 'mesh.secret.%' ORDER BY org_seq`, f.org.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.action, &r.status, &r.actorType, &r.actorID, &r.via, &r.name, &r.version, &r.fp, &r.length); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 4 {
		t.Fatalf("audit records = %d, want 4 (put pending, put ok, resolve ok, refused resolve): %+v", len(got), got)
	}
	want := []row{
		{"mesh.secret.put", "pending", "service", ws.String(), "mesh-plugin", "api-key", "", "", 0},
		{"mesh.secret.put", "ok", "service", ws.String(), "mesh-plugin", "api-key", meta.Version, meta.Fingerprint, len(c.Value(1))},
		{"mesh.secret.resolve", "ok", "service", ws.String(), "mesh-plugin", "api-key", meta.Version, meta.Fingerprint, len(c.Value(1))},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("audit record %d = %+v, want %+v", i, got[i], w)
		}
	}
	if got[3].action != "mesh.secret.resolve" || got[3].status != "failed" || got[3].name != "missing" || got[3].fp != "" {
		t.Errorf("refused resolve record = %+v", got[3])
	}

	// A refusal after authentication is journaled under the action of the route
	// that was called: a malformed ref, and a foreign organization.
	failed := func(action, class string) (n int) {
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action=$2 AND result_status='failed' AND result_error_class=$3`,
			f.org.ID.String(), action, class).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	f.resolveSecret(ws, "a..b")
	f.putSecret(ws, "a..b", c.Value(2))
	other := uuid.New()
	f.secretsDo(secretCall{method: http.MethodPost, path: f.secretPath(other, "api-key", true), ws: ws, secret: meshTestEventsSecret})
	f.secretsDo(secretCall{method: http.MethodPut, path: f.secretPath(other, "api-key", false), body: []byte(`{"value":"v-0123456789"}`), ws: ws, secret: meshTestEventsSecret})
	for _, tc := range []struct{ action, class string }{
		{"mesh.secret.resolve", "invalid_argument"}, {"mesh.secret.put", "invalid_argument"},
		{"mesh.secret.resolve", "permission_denied"}, {"mesh.secret.put", "permission_denied"},
	} {
		if n := failed(tc.action, tc.class); n != 1 {
			t.Errorf("%s %s records = %d, want 1", tc.action, tc.class, n)
		}
	}
}

// Every refused request is refused, and a refusal has no effect: nothing is
// written, nothing is resolved.
func TestMeshSecretRejectsRedInputs(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws := f.installedWorkspace()
	c := canary.New()
	if f.putSecret(ws, "real", c.Value(1)).Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	body, _ := json.Marshal(map[string]string{"value": c.Value(2)})
	otherBody, _ := json.Marshal(map[string]string{"value": c.Value(3)})
	putPath := f.secretPath(f.org.ID, "real", false)
	resPath := f.secretPath(f.org.ID, "real", true)
	now := time.Now()

	// A second organisation with its own installed workspace and secret.
	g := newMeshFixtureOn(t, f.pool, true)
	otherWS := g.installedWorkspace()
	if g.putSecret(otherWS, "real", "foreign-value-0123456789").Code != http.StatusOK {
		t.Fatal("setup foreign PUT failed")
	}
	countSealed := func() (n int) {
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM keep_envelope WHERE name LIKE 'mesh/%/secrets/%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := countSealed()

	user := f.admin
	cases := []struct {
		name string
		call secretCall
		want int
	}{
		{"no credentials", secretCall{method: http.MethodPost, path: resPath}, http.StatusUnauthorized},
		{"user token only", secretCall{method: http.MethodPost, path: resPath, bearer: user}, http.StatusUnauthorized},
		{"user token on PUT", secretCall{method: http.MethodPut, path: putPath, body: body, bearer: user}, http.StatusUnauthorized},
		{"user token plus signature headers of nobody", secretCall{method: http.MethodPost, path: resPath, bearer: user,
			hdr: map[string]string{"X-Mesh-Workspace": ws.String(), "X-Mesh-Timestamp": "1", "X-Mesh-Signature": "v1=00"}}, http.StatusUnauthorized},
		{"wrong secret", secretCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestWrongSecret}, http.StatusUnauthorized},
		{"unknown workspace", secretCall{method: http.MethodPost, path: resPath, ws: uuid.New(), secret: meshTestEventsSecret}, http.StatusUnauthorized},
		{"stale timestamp", secretCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestEventsSecret, ts: now.Add(-6 * time.Minute)}, http.StatusUnauthorized},
		{"future timestamp", secretCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestEventsSecret, ts: now.Add(6 * time.Minute)}, http.StatusUnauthorized},
		{"body swapped after signing", secretCall{method: http.MethodPut, path: putPath, body: otherBody, signBody: body, ws: ws, secret: meshTestEventsSecret}, http.StatusUnauthorized},
		{"path swapped after signing", secretCall{method: http.MethodPost, path: f.secretPath(f.org.ID, "real", true), signPath: f.secretPath(f.org.ID, "other", true), ws: ws, secret: meshTestEventsSecret}, http.StatusUnauthorized},
		{"method swapped after signing", secretCall{method: http.MethodPost, path: resPath, signMethod: http.MethodPut, ws: ws, secret: meshTestEventsSecret}, http.StatusUnauthorized},
		{"event-style signature over ts.body", secretCall{method: http.MethodPost, path: resPath, ws: ws,
			hdr: eventStyleHeaders(ws, meshTestEventsSecret, now, nil)}, http.StatusUnauthorized},
		{"foreign org in the path", secretCall{method: http.MethodPost, path: g.secretPath(g.org.ID, "real", true), ws: ws, secret: meshTestEventsSecret}, http.StatusForbidden},
		{"foreign org PUT", secretCall{method: http.MethodPut, path: g.secretPath(g.org.ID, "real", false), body: body, ws: ws, secret: meshTestEventsSecret}, http.StatusForbidden},
		{"malformed org in the path", secretCall{method: http.MethodPost, path: "/orgs/not-a-uuid/mesh/secrets/real/resolve", ws: ws, secret: meshTestEventsSecret}, http.StatusForbidden},
	}
	// Signatures over a message that leaves one part out are refused: each part
	// of the signed message is bound.
	tsNow := strconv.FormatInt(now.Unix(), 10)
	emptySum := sha256.Sum256(nil)
	bh := hex.EncodeToString(emptySum[:])
	const tag = "keep-mesh-secret-v1"
	const sn = "0123456789abcdef0123456789abcdef"
	for name, msg := range map[string]string{
		"signature without path":      tag + "\n" + tsNow + "\n" + sn + "\nPOST\n" + bh,
		"signature without method":    tag + "\n" + tsNow + "\n" + sn + "\n" + resPath + "\n" + bh,
		"signature without body hash": tag + "\n" + tsNow + "\n" + sn + "\nPOST\n" + resPath,
		"signature without timestamp": tag + "\n" + sn + "\nPOST\n" + resPath + "\n" + bh,
		"signature without the tag":   tsNow + "\n" + sn + "\nPOST\n" + resPath + "\n" + bh,
		"signature without the nonce": tag + "\n" + tsNow + "\nPOST\n" + resPath + "\n" + bh,
	} {
		m := hmac.New(sha256.New, []byte(meshTestEventsSecret))
		m.Write([]byte(msg))
		cases = append(cases, struct {
			name string
			call secretCall
			want int
		}{name, secretCall{method: http.MethodPost, path: resPath, hdr: map[string]string{
			"X-Mesh-Workspace": ws.String(), "X-Mesh-Timestamp": tsNow, "X-Mesh-Nonce": sn, "X-Mesh-Signature": "v1=" + hex.EncodeToString(m.Sum(nil))}}, http.StatusUnauthorized})
	}
	// The secrets API takes only the "v1=" form: the bare hex Mesh uses for
	// events is refused here even with the right MAC.
	bare := meshSecretMAC(meshTestEventsSecret, now, sn, http.MethodPost, resPath, nil)
	bare["X-Mesh-Workspace"] = ws.String()
	bare["X-Mesh-Signature"] = strings.TrimPrefix(bare["X-Mesh-Signature"], "v1=")
	cases = append(cases, struct {
		name string
		call secretCall
		want int
	}{"bare hex signature", secretCall{method: http.MethodPost, path: resPath, hdr: bare}, http.StatusUnauthorized})
	cases = append(cases, struct {
		name string
		call secretCall
		want int
	}{"timestamp changed after signing", secretCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestEventsSecret,
		ts: now.Add(-time.Minute), hdr: map[string]string{"X-Mesh-Timestamp": tsNow}}, http.StatusUnauthorized},
		struct {
			name string
			call secretCall
			want int
		}{"user token with a valid workspace, fresh timestamp and garbage signature", secretCall{method: http.MethodPost, path: resPath, bearer: user,
			hdr: map[string]string{"X-Mesh-Workspace": ws.String(), "X-Mesh-Timestamp": tsNow, "X-Mesh-Nonce": sn, "X-Mesh-Signature": "v1=" + strings.Repeat("0", 64)}}, http.StatusUnauthorized})
	for _, tc := range cases {
		rec := f.secretsDo(tc.call)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", tc.name, rec.Code, tc.want, answerDiag(rec))
		}
		if strings.Contains(rec.Body.String(), "value") && tc.call.method == http.MethodPost {
			t.Errorf("%s: a refusal body mentions a value: %s", tc.name, answerDiag(rec))
		}
	}
	if after := countSealed(); after != before {
		t.Errorf("a refused request changed sealed secrets: %d -> %d", before, after)
	}
	var resolves int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.secret.resolve' AND result_status='ok'`, f.org.ID.String()).Scan(&resolves)
	if resolves != 0 {
		t.Errorf("a refused request was journaled as a successful resolve (%d)", resolves)
	}

	// The control: the same call, properly signed, works.
	if rec := f.resolveSecret(ws, "real"); rec.Code != http.StatusOK {
		t.Fatalf("control resolve = %d", rec.Code)
	}
}

func eventStyleHeaders(ws uuid.UUID, secret string, ts time.Time, body []byte) map[string]string {
	h := signedHeaders(ws, secret, ts, body)
	return h
}

// A workspace sees only its own namespace: another workspace's ref, and a
// ref nobody wrote, are the same answer.
func TestMeshSecretNamespaceIsolation(t *testing.T) {
	f := newMeshFixture(t, true)
	wsA, wsB := f.installedWorkspace(), f.installedWorkspace()
	c := canary.New()
	if f.putSecret(wsB, "shared-name", c.Value(1)).Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	foreign := f.resolveSecret(wsA, "shared-name")
	absent := f.resolveSecret(wsA, "nobody-wrote-this")
	if foreign.Code != http.StatusNotFound || absent.Code != http.StatusNotFound {
		t.Fatalf("foreign = %d, absent = %d, both must be 404", foreign.Code, absent.Code)
	}
	norm := func(rec *httptest.ResponseRecorder) string {
		var m map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		delete(m, "request_id")
		b, _ := json.Marshal(m)
		var hs []string
		for k, vs := range rec.Header() {
			if k != "X-Request-Id" {
				hs = append(hs, k+": "+strings.Join(vs, ","))
			}
		}
		sort.Strings(hs)
		return string(b) + strings.Join(hs, "\n")
	}
	if norm(foreign) != norm(absent) {
		t.Errorf("foreign and absent refs are distinguishable:\n%s\n%s", norm(foreign), norm(absent))
	}
	if c.In(foreign.Body.String()) {
		t.Fatal("value of another workspace returned")
	}
	// The same ref name in A is its own secret.
	valA := c.Value(2)
	if f.putSecret(wsA, "shared-name", valA).Code != http.StatusOK {
		t.Fatal("PUT in A failed")
	}
	var out struct{ Value string }
	_ = json.Unmarshal(f.resolveSecret(wsA, "shared-name").Body.Bytes(), &out)
	if out.Value != valA {
		t.Fatal("workspace A resolved something other than its own value")
	}
	_ = json.Unmarshal(f.resolveSecret(wsB, "shared-name").Body.Bytes(), &out)
	if out.Value != c.Value(1) {
		t.Fatal("workspace A's PUT overwrote workspace B's value")
	}
	// The install credentials of the workspace are not reachable as refs.
	for _, ref := range []string{"events_secret", "extension_token", "keep_secret", "secrets"} {
		if rec := f.resolveSecret(wsA, ref); rec.Code != http.StatusNotFound {
			t.Errorf("credential slot %q reachable through the secrets API: %d", ref, rec.Code)
		}
	}
}

// The ref is a closed alphabet: no separator, no dot-dot, no encoded form of
// either, no oversize.
func TestMeshSecretRefIsClosed(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	body := []byte(`{"value":"v-0123456789"}`)
	bad := []string{"a..b", "..", ".", "-lead", "a%2fb", "a%2Fb", "%2e%2e", "a%00b", "a%20b", strings.Repeat("a", 129), "a:b", "a\\b", "ü"}
	for _, ref := range bad {
		for _, call := range []secretCall{
			{method: http.MethodPut, path: f.secretPath(f.org.ID, ref, false), body: body},
			{method: http.MethodPost, path: f.secretPath(f.org.ID, ref, true)},
		} {
			call.ws, call.secret = ws, meshTestEventsSecret
			rec := f.secretsDo(call)
			// "." and ".." are cleaned by the mux into a redirect away from the
			// route (301 before Go 1.26, 307 after); no handler runs.
			redirect := rec.Code == http.StatusMovedPermanently || rec.Code == http.StatusTemporaryRedirect
			dotSegment := redirect && strings.Trim(ref, ".") == ""
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound && !dotSegment {
				t.Errorf("%s ref %q: status %d, want 400 or 404", call.method, ref, rec.Code)
			}
		}
	}
	// Nothing was sealed under a path outside the workspace's prefix.
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM keep_envelope WHERE name LIKE 'mesh/%' AND name NOT LIKE 'mesh/'||$1||'/%'`, ws.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d sealed rows outside the workspace prefix", n)
	}
	if rec := f.putSecret(ws, "ok.name_1-x", "v-0123456789"); rec.Code != http.StatusOK {
		t.Errorf("a valid ref was refused: %d", rec.Code)
	}
}

// The PUT body is a closed shape.
func TestMeshSecretPutBodyIsClosed(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	for name, body := range map[string]string{
		"empty value":        `{"value":""}`,
		"no value":           `{}`,
		"extra field":        `{"value":"v-0123456789","fingerprint":"x"}`,
		"not json":           `value`,
		"non-string":         `{"value":12}`,
		"oversize":           `{"value":"` + strings.Repeat("a", 70<<10) + `"}`,
		"trailing data":      `{"value":"v-0123456789"}{"value":"y"}`,
		"trailing brace":     `{"value":"v-0123456789"}}`,
		"trailing array end": `{"value":"v-0123456789"}]`,
	} {
		rec := f.secretsDo(secretCall{method: http.MethodPut, path: f.secretPath(f.org.ID, "x", false), body: []byte(body), ws: ws, secret: meshTestEventsSecret})
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: status %d, want 400/413", name, rec.Code)
		}
	}
	if rec := f.resolveSecret(ws, "x"); rec.Code != http.StatusNotFound {
		t.Errorf("a refused PUT left a secret behind: %d", rec.Code)
	}
}

// Resolve has no body: a signed request that carries one is refused and the
// value is not released.
func TestMeshSecretResolveBodyIsClosed(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	if f.putSecret(ws, "k", "v-0123456789").Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	for name, body := range map[string]string{
		"object":  `{"value":"x"}`,
		"scalar":  `1`,
		"newline": "\n",
	} {
		rec := f.secretsDo(secretCall{method: http.MethodPost, path: f.secretPath(f.org.ID, "k", true), body: []byte(body), ws: ws, secret: meshTestEventsSecret})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "v-0123456789") {
			t.Errorf("%s: the refusal carries the value", name)
		}
	}
	// Each refusal is an authenticated call, so it is in the journal, nameless.
	var audited int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.secret.resolve' AND result_status='failed' AND result_error_class='invalid_argument' AND actor_id=$2`,
		f.org.ID.String(), ws.String()).Scan(&audited); err != nil || audited != 3 {
		t.Errorf("refused resolves 3, audited %d (%v)", audited, err)
	}
	if rec := f.resolveSecret(ws, "k"); rec.Code != http.StatusOK {
		t.Errorf("a bodyless resolve was refused: %d", rec.Code)
	}
}

// Reinstall with a new events secret is the revocation: the old signature
// stops working at once.
func TestMeshSecretRevokedByReinstall(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	if f.putSecret(ws, "k", "v-0123456789").Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	installedKeepSecret(t, f.install(f.admin, ws, "tok-2", meshTestRotatedSecret))
	if rec := f.resolveSecret(ws, "k"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old events secret still resolves: %d", rec.Code)
	}
	rec := f.secretsDo(secretCall{method: http.MethodPost, path: f.secretPath(f.org.ID, "k", true), ws: ws, secret: meshTestRotatedSecret})
	if rec.Code != http.StatusOK {
		t.Fatalf("new events secret does not resolve: %d", rec.Code)
	}
}

// The secrets API is served only where the Mesh extension is on, only over
// TLS, and only with the methods it names.
func TestMeshSecretRoutesGated(t *testing.T) {
	off := newMeshFixture(t, false)
	off.org.ID = uuid.New()
	for _, call := range []secretCall{
		{method: http.MethodPut, path: off.secretPath(off.org.ID, "k", false), body: []byte(`{"value":"v-0123456789"}`)},
		{method: http.MethodPost, path: off.secretPath(off.org.ID, "k", true)},
	} {
		call.ws, call.secret = uuid.New(), meshTestEventsSecret
		if rec := off.secretsDo(call); rec.Code != http.StatusNotFound {
			t.Errorf("extension off: %s %s = %d, want 404", call.method, call.path, rec.Code)
		}
	}
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	if f.putSecret(ws, "k", "v-0123456789").Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	// Properly signed, but not over TLS: the same calls that work over TLS are
	// not served (the value is in the body), and nothing happens.
	plain := func(method, ref string, body []byte) *httptest.ResponseRecorder {
		path := f.secretPath(f.org.ID, ref, method == http.MethodPost)
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("X-Mesh-Workspace", ws.String())
		for k, v := range meshSecretMAC(meshTestEventsSecret, time.Now(), freshNonce(t), method, path, body) {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, r) // no r.TLS
		return rec
	}
	if rec := plain(http.MethodPost, "k", nil); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "value") {
		t.Errorf("plain HTTP resolve of an existing ref = %d %s, want 404", rec.Code, answerDiag(rec))
	}
	if rec := plain(http.MethodPut, "fresh", []byte(`{"value":"v-0123456789"}`)); rec.Code != http.StatusNotFound {
		t.Errorf("plain HTTP PUT = %d, want 404", rec.Code)
	}
	if rec := f.resolveSecret(ws, "fresh"); rec.Code != http.StatusNotFound {
		t.Errorf("a plain HTTP PUT stored a value: %d", rec.Code)
	}
	for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodPatch} {
		if rec := f.secretsDo(secretCall{method: m, path: f.secretPath(f.org.ID, "k", false), ws: ws, secret: meshTestEventsSecret}); rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
			t.Errorf("%s on a secret = %d, want 405/404", m, rec.Code)
		}
	}
	// resolve is POST only, even with a signature over GET.
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		rec := f.secretsDo(secretCall{method: m, path: f.secretPath(f.org.ID, "k", true), ws: ws, secret: meshTestEventsSecret})
		if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "value") {
			t.Errorf("%s on resolve = %d, want 405/404", m, rec.Code)
		}
	}
}

// resolve has a budget per workspace; PUT does not spend it.
func TestMeshSecretResolveIsRateLimited(t *testing.T) {
	// A frozen clock: the bucket never refills during the test, so a shared
	// bucket shows however slow the runner is.
	frozen := time.Now()
	f := newMeshFixtureOn(t, testPool(t), true, func(d *api.MeshDeps) {
		d.ResolveLimit = api.CatalogLimit{Now: func() time.Time { return frozen }}
	})
	ws := f.installedWorkspace()
	if f.putSecret(ws, "k", "v-0123456789").Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	// PUT does not spend the resolve budget: more PUTs than the burst, then a
	// resolve still passes.
	for i := 0; i < 150; i++ {
		if rec := f.putSecret(ws, "k", "v-0123456789"); rec.Code != http.StatusOK {
			t.Fatalf("PUT %d = %d", i, rec.Code)
		}
	}
	// The other workspace is set up before the budget is spent.
	other := f.installedWorkspace()
	if f.putSecret(other, "k", "v-0123456789").Code != http.StatusOK {
		t.Fatal("setup PUT for the other workspace failed")
	}
	limited := 0
	for i := 0; i < 400; i++ {
		rec := f.resolveSecret(ws, "k")
		if rec.Code == http.StatusTooManyRequests {
			limited++
			if rec.Header().Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
			break
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("resolve %d = %d", i, rec.Code)
		}
	}
	if limited == 0 {
		t.Fatal("400 resolves in a row were never limited")
	}
	// Another workspace is unaffected while ws is still empty.
	if f.resolveSecret(other, "k").Code != http.StatusOK {
		t.Fatal("one workspace's budget limited another")
	}
	// The throttled call is in the journal, with no name and no value.
	var audited int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.secret.resolve' AND result_status='failed' AND result_error_class='policy_denied' AND actor_id=$2`,
		f.org.ID.String(), ws.String()).Scan(&audited); err != nil || audited != limited {
		t.Fatalf("throttled resolves %d, audited %d (%v)", limited, audited, err)
	}
}

// Any value a workspace stores comes back byte for byte, and cannot break out
// of the answer's JSON: quotes, backslashes, control characters, and a value
// that looks like the rest of the object.
func TestMeshSecretResolveRoundTripsAnyValue(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	for i, val := range []string{
		`x","version":"evil`, `"`, `\`, `A`, "line1\nline2\r\n\ttab", "ctl\x01\x1f\x7f", "</script><!--&",
		"ünïcödé 日本語 🔑", "  ", `{"value":"inner"}`, strings.Repeat(`"\`, 4000),
	} {
		ref := "rt-" + strconv.Itoa(i)
		put, _ := json.Marshal(map[string]string{"value": val})
		if rec := f.secretsDo(secretCall{method: http.MethodPut, path: f.secretPath(f.org.ID, ref, false), body: put, ws: ws, secret: meshTestEventsSecret}); rec.Code != http.StatusOK {
			t.Fatalf("PUT %q: %d", val, rec.Code)
		}
		rec := f.resolveSecret(ws, ref)
		if rec.Code != http.StatusOK {
			t.Fatalf("resolve %q: %d", val, rec.Code)
		}
		var out map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 2 || out["value"] != val || out["version"] != "1" {
			t.Errorf("value %q came back as %s (%v)", val, answerDiag(rec), err)
		}
	}
}

// refuseAudit makes the journal refuse one kind of record, for the length of
// the test.
func (f *meshFixture) refuseAudit(action, status string) {
	f.t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`CREATE FUNCTION keep_test_refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'journal refused by the test'; END $$`,
		`CREATE TRIGGER keep_test_refuse_audit BEFORE INSERT ON audit_records FOR EACH ROW WHEN (NEW.action = '` + action + `' AND NEW.result_status = '` + status + `') EXECUTE FUNCTION keep_test_refuse_audit()`,
	} {
		if _, err := f.pool.Exec(ctx, q); err != nil {
			f.t.Fatalf("refuse audit: %v", err)
		}
	}
	f.t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS keep_test_refuse_audit ON audit_records`)
		_, _ = f.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS keep_test_refuse_audit()`)
	})
}

func (f *meshFixture) dropAuditRefusal() {
	f.t.Helper()
	for _, q := range []string{`DROP TRIGGER keep_test_refuse_audit ON audit_records`, `DROP FUNCTION keep_test_refuse_audit()`} {
		if _, err := f.pool.Exec(context.Background(), q); err != nil {
			f.t.Fatal(err)
		}
	}
}

// There is no answer without the record. When the journal refuses, resolve
// releases no value, and a PUT never stores a version that has no record.
func TestMeshSecretNoAnswerWithoutAuditRecord(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws := f.installedWorkspace()
	c := canary.New()
	if f.putSecret(ws, "kept", c.Value(1)).Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}

	f.refuseAudit("mesh.secret.resolve", "ok")
	rec := f.resolveSecret(ws, "kept")
	if rec.Code != http.StatusServiceUnavailable || c.In(rec.Body.String()) || c.In(headersText(rec)) || strings.Contains(rec.Body.String(), `"value"`) {
		t.Errorf("resolve with a refusing journal = %d %s, want 503 and no value", rec.Code, answerDiag(rec))
	}
	f.dropAuditRefusal()
	if rec := f.resolveSecret(ws, "kept"); rec.Code != http.StatusOK {
		t.Fatalf("control: resolve with a working journal = %d", rec.Code)
	}

	// The attempt is journaled first: if that record cannot be written nothing is stored.
	f.refuseAudit("mesh.secret.put", "pending")
	if rec := f.putSecret(ws, "never", c.Value(2)); rec.Code != http.StatusServiceUnavailable || c.In(rec.Body.String()) {
		t.Errorf("PUT with a refusing journal = %d, want 503", rec.Code)
	}
	f.dropAuditRefusal()
	if rec := f.resolveSecret(ws, "never"); rec.Code != http.StatusNotFound {
		t.Errorf("a PUT whose attempt was not journaled stored a value: %d", rec.Code)
	}

	// If only the final record fails, the answer is a 503 and the journal still
	// holds the pending record of that write.
	f.refuseAudit("mesh.secret.put", "ok")
	if rec := f.putSecret(ws, "half", c.Value(3)); rec.Code != http.StatusServiceUnavailable || c.In(rec.Body.String()) {
		t.Errorf("PUT whose final record fails = %d, want 503", rec.Code)
	}
	f.dropAuditRefusal()
	var pending int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.secret.put' AND result_status='pending' AND secret_name='half'`, f.org.ID.String()).Scan(&pending); err != nil || pending != 1 {
		t.Errorf("pending records of the half-recorded write = %d (%v), want 1", pending, err)
	}
	if rec := f.resolveSecret(ws, "kept"); rec.Code != http.StatusOK {
		t.Errorf("control after the refusals: %d", rec.Code)
	}
}

// A refusal is a call too: if its record cannot be written the answer is a 503,
// never the 400/404/429 that would acknowledge a call the journal does not hold.
func TestMeshSecretRefusalNeedsItsAuditRecord(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	if f.putSecret(ws, "kept", "v-0123456789").Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	// Each refusal is its own case, so a mutation that ignores a journal failure
	// for one class cannot hide behind another. The default budget is ample here.
	for name, ref := range map[string]string{"bad ref 400": "a..b", "unknown ref 404": "nobody-wrote-this"} {
		f.refuseAudit("mesh.secret.resolve", "failed")
		if rec := f.resolveSecret(ws, ref); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s with a refusing journal = %d, want 503", name, rec.Code)
		}
		f.dropAuditRefusal()
	}
	if rec := f.resolveSecret(ws, "a..b"); rec.Code != http.StatusBadRequest {
		t.Errorf("control: bad ref with a working journal = %d, want 400", rec.Code)
	}
	if rec := f.resolveSecret(ws, "nobody-wrote-this"); rec.Code != http.StatusNotFound {
		t.Errorf("control: unknown ref with a working journal = %d, want 404", rec.Code)
	}

	// The throttle: a frozen clock and a one-token budget make the second call
	// a certain 429, before and after the journal refuses.
	frozen := time.Now()
	g := newMeshFixtureOn(t, f.pool, true, func(d *api.MeshDeps) {
		d.ResolveLimit = api.CatalogLimit{PerMinute: 1, Burst: 1, Now: func() time.Time { return frozen }}
	})
	gws := g.installedWorkspace()
	if g.putSecret(gws, "kept", "v-0123456789").Code != http.StatusOK || g.resolveSecret(gws, "kept").Code != http.StatusOK {
		t.Fatal("throttle setup failed")
	}
	g.refuseAudit("mesh.secret.resolve", "failed")
	if rec := g.resolveSecret(gws, "kept"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("throttled call with a refusing journal = %d, want 503", rec.Code)
	}
	g.dropAuditRefusal()
	if rec := g.resolveSecret(gws, "kept"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("control: throttled call with a working journal = %d, want 429", rec.Code)
	}

	// A signed call naming another organisation is an authenticated refusal
	// too: with its record unwritable the answer is the same 503.
	f.refuseAudit("mesh.secret.resolve", "failed")
	foreign := secretCall{method: http.MethodPost, path: f.secretPath(uuid.New(), "kept", true), ws: ws, secret: meshTestEventsSecret}
	if rec := f.secretsDo(foreign); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("foreign org with a refusing journal = %d, want 503", rec.Code)
	}
	f.dropAuditRefusal()
	foreign.nonce = ""
	if rec := f.secretsDo(foreign); rec.Code != http.StatusForbidden {
		t.Errorf("control: foreign org with a working journal = %d, want 403", rec.Code)
	}

	f.refuseAudit("mesh.secret.put", "failed")
	if rec := f.putSecret(ws, "a..b", "v-0123456789"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("invalid PUT with a refusing journal = %d, want 503", rec.Code)
	}
	f.dropAuditRefusal()
	if rec := f.putSecret(ws, "a..b", "v-0123456789"); rec.Code != http.StatusBadRequest {
		t.Errorf("control: invalid PUT with a working journal = %d, want 400", rec.Code)
	}
}

// A version that was disabled is not served, and looks like a ref nobody wrote.
func TestMeshSecretDisabledVersionIsNotFound(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	if f.putSecret(ws, "off", "v-0123456789").Code != http.StatusOK || f.resolveSecret(ws, "off").Code != http.StatusOK {
		t.Fatal("setup failed")
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE keep_envelope SET status='disabled' WHERE name=$1`, "mesh/"+ws.String()+"/secrets/off"); err != nil {
		t.Fatal(err)
	}
	if rec := f.resolveSecret(ws, "off"); rec.Code != http.StatusNotFound {
		t.Errorf("resolve of a disabled version = %d, want 404", rec.Code)
	}
}

// A signed request is single use: sending the same headers again is refused
// like a bad signature, so a captured PUT cannot roll a value back after a
// rotation and a captured resolve cannot read the value again.
func TestMeshSecretSignedRequestIsSingleUse(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	old, current := "old-value-"+freshNonce(t), "new-value-"+freshNonce(t)

	putOld := secretCall{method: http.MethodPut, path: f.secretPath(f.org.ID, "k", false), ws: ws, secret: meshTestEventsSecret,
		body: []byte(`{"value":"` + old + `"}`), nonce: freshNonce(t), ts: time.Now()}
	if rec := f.secretsDo(putOld); rec.Code != http.StatusOK {
		t.Fatalf("first PUT = %d", rec.Code)
	}
	if rec := f.putSecret(ws, "k", current); rec.Code != http.StatusOK {
		t.Fatalf("rotation PUT = %d", rec.Code)
	}
	// The same request, replayed: refused, and the value stays the rotated one.
	replay := f.secretsDo(putOld)
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("replayed PUT = %d, want 401", replay.Code)
	}
	rec := f.resolveSecret(ws, "k")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), current) || strings.Contains(rec.Body.String(), old) {
		t.Fatalf("a replayed PUT changed the value: %d", rec.Code)
	}

	res := secretCall{method: http.MethodPost, path: f.secretPath(f.org.ID, "k", true), ws: ws, secret: meshTestEventsSecret,
		nonce: freshNonce(t), ts: time.Now()}
	first := f.secretsDo(res)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), current) {
		t.Fatalf("first resolve = %d", first.Code)
	}
	again := f.secretsDo(res)
	if again.Code != http.StatusUnauthorized || strings.Contains(again.Body.String(), current) {
		t.Fatalf("replayed resolve = %d, want 401 without the value", again.Code)
	}
	// The replay carried a valid signature, so it is an authenticated refusal
	// and is in the journal, without the name and without the value.
	var replays int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.secret.resolve' AND result_status='failed' AND result_error_class='permission_denied' AND actor_id=$2`,
		f.org.ID.String(), ws.String()).Scan(&replays); err != nil || replays != 1 {
		t.Fatalf("replayed resolves 1, audited %d (%v)", replays, err)
	}
	// A replay answers exactly like another failed signature: no oracle.
	bad := f.secretsDo(secretCall{method: http.MethodPost, path: f.secretPath(f.org.ID, "k", true), ws: ws, secret: meshTestWrongSecret})
	if again.Code != bad.Code || stripRequestID(again.Body.String()) != stripRequestID(bad.Body.String()) {
		t.Fatalf("replay answer %q differs from a bad signature %q", answerDiag(again), answerDiag(bad))
	}
	// The retry of a failed call is a new request with a new nonce.
	if rec := f.resolveSecret(ws, "k"); rec.Code != http.StatusOK {
		t.Fatalf("retry with a new nonce = %d", rec.Code)
	}
}

// Nonces are per workspace: another workspace may use the same string.
func TestMeshSecretNonceIsPerWorkspace(t *testing.T) {
	f := newMeshFixture(t, true)
	wsA := f.installedWorkspace()
	wsB := f.installedWorkspace()
	nonce := freshNonce(t)
	for _, ws := range []uuid.UUID{wsA, wsB} {
		rec := f.secretsDo(secretCall{method: http.MethodPut, path: f.secretPath(f.org.ID, "k", false), ws: ws, secret: meshTestEventsSecret,
			body: []byte(`{"value":"v-0123456789"}`), nonce: nonce})
		if rec.Code != http.StatusOK {
			t.Fatalf("workspace %s with a shared nonce string = %d, want 200", ws, rec.Code)
		}
	}
}

// A missing, short, long or oddly spelled nonce is refused even when the
// signature over it is valid, and a refused request spends nothing.
func TestMeshSecretNonceShapeIsClosed(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	path := f.secretPath(f.org.ID, "k", true)
	for name, nonce := range map[string]string{
		"15 characters": strings.Repeat("a", 15),
		"65 characters": strings.Repeat("a", 65),
		"padding":       strings.Repeat("a", 15) + "=",
		"slash":         strings.Repeat("a", 15) + "/",
		"plus":          strings.Repeat("a", 15) + "+",
		"space":         strings.Repeat("a", 15) + " ",
		"newline":       strings.Repeat("a", 15) + "\n",
		"non-ascii":     strings.Repeat("a", 15) + "é",
		"colon (a ref)": strings.Repeat("a", 15) + ":",
		"dot":           strings.Repeat("a", 15) + ".",
	} {
		rec := f.secretsDo(secretCall{method: http.MethodPost, path: path, ws: ws, secret: meshTestEventsSecret,
			nonce: nonce})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
	}
	// No header at all, signed over an empty nonce.
	noHeader := secretCall{method: http.MethodPost, path: path, ws: ws, secret: meshTestEventsSecret, hdr: map[string]string{"X-Mesh-Nonce": ""}}
	if rec := f.secretsDo(noHeader); rec.Code != http.StatusUnauthorized {
		t.Errorf("no nonce header: status = %d, want 401", rec.Code)
	}
	// The boundary lengths and both alphabets are accepted.
	for name, nonce := range map[string]string{
		"16 base64url": "Ab-_Ab-_Ab-_Ab-_",
		"64 hex":       strings.Repeat("0f", 32),
	} {
		rec := f.secretsDo(secretCall{method: http.MethodPost, path: path, ws: ws, secret: meshTestEventsSecret, nonce: nonce})
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("%s: refused", name)
		}
	}
}

// A nonce is spent only by a request whose signature holds: unsigned and
// badly signed traffic leaves the table empty.
func TestMeshSecretUnsignedTrafficSpendsNoNonce(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	path := f.secretPath(f.org.ID, "k", true)
	count := func() int {
		var n int
		if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM mesh_secret_nonces`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	f.secretsDo(secretCall{method: http.MethodPost, path: path, ws: ws, secret: meshTestWrongSecret})
	f.secretsDo(secretCall{method: http.MethodPost, path: path, hdr: map[string]string{"X-Mesh-Workspace": ws.String(), "X-Mesh-Nonce": freshNonce(t), "X-Mesh-Timestamp": strconv.FormatInt(time.Now().Unix(), 10), "X-Mesh-Signature": "v1=" + strings.Repeat("0", 64)}})
	if got := count(); got != before {
		t.Fatalf("refused traffic wrote %d nonce rows", got-before)
	}
	if rec := f.resolveSecret(ws, "k"); rec.Code == http.StatusUnauthorized {
		t.Fatalf("signed request refused: %d", rec.Code)
	}
	if got := count(); got != before+1 {
		t.Fatalf("a signed request left %d rows, want %d", got, before+1)
	}
}

// Rows older than the retention are pruned and fresh ones stay, so pruning
// cannot reopen the window the timestamp check keeps shut.
func TestMeshSecretNoncesArePruned(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	ctx := context.Background()
	for _, row := range []struct {
		nonce string
		age   string
	}{{"stale-nonce-0000001", "20 minutes"}, {"recent-nonce-000001", "11 minutes"}} {
		if _, err := f.pool.Exec(ctx, `INSERT INTO mesh_secret_nonces (workspace_id, nonce, seen_at) VALUES ($1, $2, now() - $3::interval)`, ws, row.nonce, row.age); err != nil {
			t.Fatal(err)
		}
	}
	if rec := f.resolveSecret(ws, "k"); rec.Code == http.StatusUnauthorized {
		t.Fatalf("signed request refused: %d", rec.Code)
	}
	var stale, recent int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM mesh_secret_nonces WHERE nonce = 'stale-nonce-0000001'`).Scan(&stale)
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM mesh_secret_nonces WHERE nonce = 'recent-nonce-000001'`).Scan(&recent)
	if stale != 0 || recent != 1 {
		t.Fatalf("stale rows = %d (want 0), recent rows = %d (want 1)", stale, recent)
	}
}

// A store that cannot record the nonce refuses the request and serves nothing.
func TestMeshSecretNonceStoreFailureFailsClosed(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	value := "closed-value-" + freshNonce(t)
	if f.putSecret(ws, "k", value).Code != http.StatusOK {
		t.Fatal("setup PUT failed")
	}
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `ALTER TABLE mesh_secret_nonces RENAME TO mesh_secret_nonces_off`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(ctx, `ALTER TABLE IF EXISTS mesh_secret_nonces_off RENAME TO mesh_secret_nonces`)
	})
	rec := f.resolveSecret(ws, "k")
	if rec.Code < 500 || strings.Contains(rec.Body.String(), value) {
		t.Fatalf("store failure answered %d: %s", rec.Code, answerDiag(rec))
	}
	// The refused call is a signed one: it is journaled as an internal failure.
	var audited int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.secret.resolve' AND result_status='failed' AND result_error_class='internal' AND actor_id=$2`,
		f.org.ID.String(), ws.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("store-failure resolves 1, audited %d (%v)", audited, err)
	}
}
