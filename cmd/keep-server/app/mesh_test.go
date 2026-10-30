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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// meshFixture is the real router over a real database and the real sealing
// vault. Mesh itself is a fake of the protocol only: the test signs events
// the way the Mesh side is specified to (HMAC-SHA256 over "<ts>.<body>").
type meshFixture struct {
	t       *testing.T
	pool    *pgxpool.Pool
	router  http.Handler
	logbuf  *bytes.Buffer
	logger  *slog.Logger
	repo    *meshext.Repo
	fetcher meshFetcher
	org     tenancy.Organization
	admin   string         // bearer of an org admin
	member  string         // bearer of a plain member
	local   *builtin.Local // the sealing backend the router was built over
	// outcomes is the sink local reports to; it holds each change's claim.
	outcomes *keyLevelAuditor
	// peer is the RemoteAddr of the requests sent; empty is httptest's.
	peer string
}

// answerDiag describes an answer for a failure message without its body: a
// failing leak test must not echo the value it found. The error class is
// printed only as the apperr constant it equals; any other string, however
// class-like, is answer text and stays out.
func answerDiag(rec *httptest.ResponseRecorder) string {
	var e struct {
		ErrorClass string `json:"error_class"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	class := "(none)"
	if e.ErrorClass != "" {
		class = "(not a known class)"
	}
	for _, c := range apperr.Classes() {
		if string(c) == e.ErrorClass {
			class = string(c)
		}
	}
	return fmt.Sprintf("body of %d bytes, error_class %s", rec.Body.Len(), class)
}

func newMeshFixture(t *testing.T, withMesh bool) *meshFixture {
	t.Helper()
	return newMeshFixtureOn(t, testPool(t), withMesh)
}

func newMeshFixtureOn(t *testing.T, pool *pgxpool.Pool, withMesh bool, opts ...func(*api.MeshDeps)) *meshFixture {
	t.Helper()
	ctx := context.Background()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("root key")
	}
	var buf bytes.Buffer
	logger := obs.New(&buf)
	journal := audit.NewJournal(pool)
	claims := newKeyLevelClaims(pool)
	outcomes := newKeyLevelAuditor(journal, logger, claims)
	t.Cleanup(func() { drainWithin(outcomes, 5*time.Second); claims.Close() })
	local, err := builtin.NewLocal(pool, "mesh-test-root", raw, logger, outcomes.record)
	if err != nil {
		t.Fatalf("local backend: %v", err)
	}
	deps := api.Deps{Mesh: meshDeps(config.Config{MeshExtension: withMesh}, pool, local, outcomes, meshgate.New(meshgate.NewPG(pool), nil, nil, logger), journal, logger)}
	if (deps.Mesh != nil) != withMesh {
		t.Fatalf("meshDeps(MeshExtension=%v) = %v", withMesh, deps.Mesh)
	}
	for _, o := range opts {
		o(deps.Mesh)
	}
	f := &meshFixture{t: t, pool: pool, local: local, outcomes: outcomes, router: api.NewRouter(logger, pool, deps), logbuf: &buf, logger: logger,
		repo: meshext.NewRepo(pool), fetcher: meshFetcher{local.MeshVault()}}
	tr := tenancy.New(pool)
	f.org, err = tr.CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	f.admin = f.bearer(tr, "admin", true)
	f.member = f.bearer(tr, "member", false)
	return f
}

func (f *meshFixture) bearer(tr *tenancy.Repo, name string, admin bool) string {
	ctx := context.Background()
	u, err := tr.CreateUser(ctx, f.org.ID, name+"@example.test")
	if err != nil {
		f.t.Fatalf("user: %v", err)
	}
	if admin {
		if _, err := tr.CreateMembership(ctx, f.org.ID, u.ID, tenancy.Org(f.org.ID), string(identity.RoleAdmin)); err != nil {
			f.t.Fatalf("admin role: %v", err)
		}
	}
	return f.wireToken(identity.IssueParams{OrgID: f.org.ID, Kind: identity.KindUser, PrincipalID: u.ID, Scope: "org:" + f.org.ID.String()})
}

// wireToken issues a token and reads its text off the wire answer.
func (f *meshFixture) wireToken(params identity.IssueParams) string {
	res, err := identity.NewRepo(f.pool).Issue(context.Background(), params)
	if err != nil {
		f.t.Fatalf("token: %v", err)
	}
	wire, err := res.Response().WireJSON()
	if err != nil {
		f.t.Fatalf("token wire: %v", err)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(wire, &tok); err != nil || tok.Token == "" {
		f.t.Fatalf("token wire shape")
	}
	return tok.Token
}

// pollerBearer seeds a service of the org and returns a token of the
// restart:poll role, the one bearer every non-restart route must refuse.
func (f *meshFixture) pollerBearer() string {
	ctx := context.Background()
	svc := uuid.New()
	if _, err := f.pool.Exec(ctx, `INSERT INTO services (id, org_id, owner_scope, name) VALUES ($1, $2, $3, $4)`,
		svc, f.org.ID, tenancy.Org(f.org.ID).String(), "poller-"+svc.String()); err != nil {
		f.t.Fatalf("service: %v", err)
	}
	return f.wireToken(identity.IssueParams{OrgID: f.org.ID, Kind: identity.KindService, PrincipalID: svc, Scope: api.PollerScopePrefix + ":" + f.org.ID.String()})
}

// post sends over TLS (the credential routes 404 on the plain listener).
func (f *meshFixture) post(path, bearer string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	return f.send(path, bearer, body, hdr, true)
}

func (f *meshFixture) send(path, bearer string, body []byte, hdr map[string]string, viaTLS bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if viaTLS {
		r.TLS = &tls.ConnectionState{}
	}
	if f.peer != "" {
		r.RemoteAddr = f.peer
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec
}

func (f *meshFixture) install(bearer string, ws uuid.UUID, token, eventsSecret string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{
		"mesh_url": "https://mesh.example.test", "workspace_id": ws.String(),
		"extension_token": token, "events_endpoint_secret": eventsSecret, "mode": "extension",
	})
	return f.post("/mesh/install", bearer, b, nil)
}

// signedHeaders is the Mesh side of the protocol, written independently of
// the server code.
func signedHeaders(ws uuid.UUID, secret string, ts time.Time, body []byte) map[string]string {
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tsStr + "."))
	m.Write(body)
	return map[string]string{
		"X-Mesh-Workspace": ws.String(), "X-Mesh-Timestamp": tsStr,
		"X-Mesh-Signature": "v1=" + hex.EncodeToString(m.Sum(nil)),
	}
}

func eventBody(ws uuid.UUID, id, typ string) []byte {
	b, _ := json.Marshal(map[string]string{"id": id, "type": typ, "workspace_id": ws.String()})
	return b
}

func (f *meshFixture) eventRows(ws uuid.UUID) int {
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM mesh_events WHERE workspace_id=$1`, ws).Scan(&n); err != nil {
		f.t.Fatalf("count events: %v", err)
	}
	return n
}

func installedKeepSecret(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("install status = %d, body = %s", rec.Code, answerDiag(rec))
	}
	var res struct {
		OK         bool   `json:"ok"`
		KeepSecret string `json:"keep_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || !res.OK || res.KeepSecret == "" {
		t.Fatalf("install response shape: %s", answerDiag(rec))
	}
	return res.KeepSecret
}

// Leak test (written before the feature): the Mesh actor token and the events
// secret that Mesh hands over must not be on any surface — response, headers,
// log, audit journal, metadata tables, sealed storage — on the success path or
// on any failure path. Keep's own secret is allowed in exactly one place: the
// install response body.
func TestMeshCredentialsNeverLeak(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	if !c.In(hex.EncodeToString([]byte(c.Value(1)))) || !c.In("x"+c.Value(1)) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	token, evSecret := c.Value(1), c.Value(2)
	ws := uuid.New()
	var surfaces []string
	collect := func(rec *httptest.ResponseRecorder) {
		surfaces = append(surfaces, rec.Body.String())
		for k, v := range rec.Header() {
			surfaces = append(surfaces, k+": "+strings.Join(v, ","))
		}
	}

	ok := f.install(f.admin, ws, token, evSecret)
	keepSecret := installedKeepSecret(t, ok)
	collect(ok)

	// Failure paths that carry the canaries: non-admin, malformed, wrong
	// signature, tampered body, stale timestamp, unknown workspace.
	collect(f.install(f.member, uuid.New(), token, evSecret))
	collect(f.post("/mesh/install", f.admin, []byte(`{"extension_token":"`+token+`","unknown":"`+evSecret+`"}`), nil))
	body := eventBody(ws, "evt-1", "project.created")
	collect(f.post("/mesh/events", "", body, signedHeaders(ws, evSecret+"x", time.Now(), body)))
	collect(f.post("/mesh/events", "", []byte(`{"id":"`+token+`"}`), signedHeaders(ws, evSecret, time.Now(), body)))
	collect(f.post("/mesh/events", "", body, signedHeaders(ws, evSecret, time.Now().Add(-time.Hour), body)))
	collect(f.post("/mesh/events", "", body, signedHeaders(uuid.New(), evSecret, time.Now(), body)))
	collect(f.post("/mesh/events", "", body, signedHeaders(ws, evSecret, time.Now(), body)))
	collect(f.post("/mesh/install", f.admin, []byte(`{"mesh_url":"https://m.example.test","workspace_id":"bad","extension_token":"`+token+`","events_endpoint_secret":"`+evSecret+`"}`), nil))
	// A correctly signed event that carries the canaries in its own fields.
	bad := []byte(`{"id":"bad id ` + token + `","type":"` + evSecret + `","workspace_id":"` + ws.String() + `"}`)
	collect(f.post("/mesh/events", "", bad, signedHeaders(ws, evSecret, time.Now(), bad)))

	// Durable surfaces.
	ctx := context.Background()
	for _, q := range []string{
		`SELECT row_to_json(t)::text FROM mesh_installations t`,
		`SELECT row_to_json(t)::text FROM mesh_events t`,
		`SELECT row_to_json(t)::text FROM audit_records t`,
		`SELECT encode(wrapped_dek,'hex')||encode(ciphertext,'hex')||secret_id||name FROM keep_envelope`,
	} {
		rows, err := f.pool.Query(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			surfaces = append(surfaces, s)
		}
		rows.Close()
	}
	// ciphertext is binary: search the raw bytes too.
	rows, err := f.pool.Query(ctx, `SELECT ciphertext FROM keep_envelope`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var b []byte
		_ = rows.Scan(&b)
		surfaces = append(surfaces, string(b))
	}
	rows.Close()

	if f.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	logs := f.logbuf.String()
	for _, name := range []string{"extension token", "events secret"} {
		cc := c
		if name == "events secret" {
			cc = canary.Of(evSecret)
		}
		for i, s := range append(surfaces, logs) {
			if cc.In(s) {
				t.Fatalf("%s leaked on surface #%d (%d bytes); the surface is not printed", name, i, len(s))
			}
		}
	}
	// Keep's own secret: present in the install response, nowhere else.
	ks := canary.Of(keepSecret)
	if !ks.In(ok.Body.String()) {
		t.Fatal("install response lacks keep_secret")
	}
	for i, s := range surfaces[1:] { // [0] is the install response body
		if ks.In(s) && s != ok.Body.String() {
			t.Fatalf("keep_secret leaked outside the install response on surface #%d (%d bytes)", i+1, len(s))
		}
	}
	if ks.In(logs) {
		t.Fatal("keep_secret leaked into the log")
	}
}

func TestMeshEventsRejectWrongSignatureAndCreateNoEffect(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	secret := "events-secret-" + uuid.NewString()
	installedKeepSecret(t, f.install(f.admin, ws, "tok-"+uuid.NewString(), secret))
	body := eventBody(ws, "evt-bad", "project.created")

	cases := map[string]map[string]string{
		"wrong secret":      signedHeaders(ws, secret+"x", time.Now(), body),
		"stale timestamp":   signedHeaders(ws, secret, time.Now().Add(-10*time.Minute), body),
		"future timestamp":  signedHeaders(ws, secret, time.Now().Add(10*time.Minute), body),
		"unknown workspace": signedHeaders(uuid.New(), secret, time.Now(), body),
		"no headers":        {},
		"signature not hex": {"X-Mesh-Workspace": ws.String(), "X-Mesh-Timestamp": strconv.FormatInt(time.Now().Unix(), 10), "X-Mesh-Signature": "v1=zz"},
	}
	for name, h := range cases {
		rec := f.post("/mesh/events", "", body, h)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"error_class":"unauthenticated"`) {
			t.Errorf("%s: status = %d body = %s, want 401 unauthenticated", name, rec.Code, answerDiag(rec))
		}
	}
	// Signature valid for another body (tampering after signing).
	other := eventBody(ws, "evt-bad", "project.updated")
	if rec := f.post("/mesh/events", "", other, signedHeaders(ws, secret, time.Now(), body)); rec.Code != http.StatusUnauthorized {
		t.Errorf("tampered body: status = %d, want 401", rec.Code)
	}
	if n := f.eventRows(ws); n != 0 {
		t.Fatalf("rejected events left %d rows in mesh_events", n)
	}
	// Positive control: the same request with the right signature is accepted.
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body)); rec.Code != http.StatusOK {
		t.Fatalf("valid event: status = %d body = %s", rec.Code, answerDiag(rec))
	}
	if n := f.eventRows(ws); n != 1 {
		t.Fatalf("valid event rows = %d, want 1", n)
	}
}

// meshSignedHeaders is what Mesh itself sends to an extension (evc-mesh
// sendSignedWith, the documented form): the bare lowercase hex of
// HMAC-SHA256(secret, "<unix ts>.<body>"), no X-Mesh-Workspace header (the
// workspace is named in the body).
func meshSignedHeaders(secret string, ts time.Time, body []byte) map[string]string {
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tsStr + "."))
	m.Write(body)
	return map[string]string{"X-Mesh-Timestamp": tsStr, "X-Mesh-Signature": hex.EncodeToString(m.Sum(nil))}
}

func TestMeshEventsAcceptBareHexSignature(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	secret := "events-secret-" + uuid.NewString()
	installedKeepSecret(t, f.install(f.admin, ws, "tok-"+uuid.NewString(), secret))
	body := eventBody(ws, "evt-bare", "project.created")
	good := meshSignedHeaders(secret, time.Now(), body)
	sig := good["X-Mesh-Signature"]
	with := func(s string) map[string]string {
		return map[string]string{"X-Mesh-Timestamp": good["X-Mesh-Timestamp"], "X-Mesh-Signature": s}
	}

	refused := map[string]map[string]string{
		"bare, wrong secret": meshSignedHeaders(secret+"x", time.Now(), body),
		"bare, other body":   meshSignedHeaders(secret, time.Now(), eventBody(ws, "evt-bare", "project.updated")),
		"bare, stale":        meshSignedHeaders(secret, time.Now().Add(-10*time.Minute), body),
		"double prefix":      with("v1=v1=" + sig),
		"63 chars":           with(sig[:63]),
		"65 chars":           with(sig + "0"),
		"uppercase":          with(strings.ToUpper(sig)),
		"v1 uppercase":       with("v1=" + strings.ToUpper(sig)),
		"other prefix":       with("sha256=" + sig),
		"leading space":      with(" " + sig),
	}
	for name, h := range refused {
		rec := f.post("/mesh/events", "", body, h)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"error_class":"unauthenticated"`) {
			t.Errorf("%s: status = %d body = %s, want 401 unauthenticated", name, rec.Code, answerDiag(rec))
		}
	}
	if n := f.eventRows(ws); n != 0 {
		t.Fatalf("refused events left %d rows in mesh_events", n)
	}

	// Mesh's own form is accepted and recorded.
	if rec := f.post("/mesh/events", "", body, good); rec.Code != http.StatusOK {
		t.Fatalf("bare hex from Mesh: status = %d body = %s, want 200", rec.Code, answerDiag(rec))
	}
	if n := f.eventRows(ws); n != 1 {
		t.Fatalf("bare hex event rows = %d, want 1", n)
	}
	// The v1= form keeps working: same MAC, the prefix is only a label.
	body2 := eventBody(ws, "evt-v1", "project.created")
	if rec := f.post("/mesh/events", "", body2, signedHeaders(ws, secret, time.Now(), body2)); rec.Code != http.StatusOK {
		t.Fatalf("v1= signature: status = %d body = %s, want 200", rec.Code, answerDiag(rec))
	}
	if n := f.eventRows(ws); n != 2 {
		t.Fatalf("event rows after v1= delivery = %d, want 2", n)
	}
}

func TestMeshEventReplayDoesNotDuplicateEffect(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	secret := "events-secret-" + uuid.NewString()
	installedKeepSecret(t, f.install(f.admin, ws, "tok-"+uuid.NewString(), secret))
	body := eventBody(ws, "evt-replay", "agent.key.revoked")
	for i := 0; i < 3; i++ {
		if rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body)); rec.Code != http.StatusOK {
			t.Fatalf("delivery %d: status = %d body = %s", i, rec.Code, answerDiag(rec))
		}
	}
	if n := f.eventRows(ws); n != 1 {
		t.Fatalf("three deliveries of one event id produced %d rows, want 1", n)
	}
	body2 := eventBody(ws, "evt-other", "agent.key.revoked")
	if rec := f.post("/mesh/events", "", body2, signedHeaders(ws, secret, time.Now(), body2)); rec.Code != http.StatusOK {
		t.Fatalf("second event id: status = %d", rec.Code)
	}
	if n := f.eventRows(ws); n != 2 {
		t.Fatalf("distinct event ids produced %d rows, want 2", n)
	}
}

func TestMeshEventsRejectMalformedSignedEvents(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	secret := "events-secret-" + uuid.NewString()
	installedKeepSecret(t, f.install(f.admin, ws, "tok-"+uuid.NewString(), secret))
	for name, body := range map[string][]byte{
		"unknown type":       eventBody(ws, "e1", "workspace.deleted"),
		"empty id":           eventBody(ws, "", "project.created"),
		"other workspace":    eventBody(uuid.New(), "e2", "project.created"),
		"not json":           []byte("nope"),
		"id with separators": eventBody(ws, "a b/c", "project.created"),
	} {
		rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
	if n := f.eventRows(ws); n != 0 {
		t.Fatalf("malformed events left %d rows", n)
	}
}

func TestMeshInstallAuthorizationAndOwnership(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	if rec := f.install("", ws, "tok", "events-secret-0123456789"); rec.Code != http.StatusUnauthorized {
		t.Errorf("no bearer: status = %d, want 401", rec.Code)
	}
	if rec := f.install(f.member, ws, "tok", "events-secret-0123456789"); rec.Code != http.StatusNotFound {
		t.Errorf("non-admin: status = %d, want 404", rec.Code)
	}
	// Each case starts from a valid body and breaks one field, so no
	// credential-shaped literal sits in the source.
	valid := func() map[string]any {
		return map[string]any{
			"mesh_url": "https://m.example.test", "workspace_id": ws.String(),
			"extension_token": "t", "events_endpoint_secret": strings.Repeat("e", 16), "mode": "store",
		}
	}
	bad := map[string]func(m map[string]any){
		"bad workspace": func(m map[string]any) { m["workspace_id"] = "x" },
		"ftp mesh url":  func(m map[string]any) { m["mesh_url"] = "ftp://m.example.test" },
		"http mesh url": func(m map[string]any) { m["mesh_url"] = "http://m.example.test" },
		"creds in url":  func(m map[string]any) { m["mesh_url"] = "https://u:p@m.example.test" },
		"short secret":  func(m map[string]any) { m["events_endpoint_secret"] = "short" },
		"empty token":   func(m map[string]any) { m["extension_token"] = "" },
		"unknown field": func(m map[string]any) { m["x"] = 1 },
		"url query":     func(m map[string]any) { m["mesh_url"] = "https://m.example.test/?a=1" },
		"url fragment":  func(m map[string]any) { m["mesh_url"] = "https://m.example.test/#a" },
		"url too long":  func(m map[string]any) { m["mesh_url"] = "https://m.example.test/" + strings.Repeat("a", 520) },
		"secret 15":     func(m map[string]any) { m["events_endpoint_secret"] = strings.Repeat("e", 15) },
		"secret long":   func(m map[string]any) { m["events_endpoint_secret"] = strings.Repeat("s", 513) },
		"token long":    func(m map[string]any) { m["extension_token"] = strings.Repeat("t", 4097) },
		"no mode":       func(m map[string]any) { delete(m, "mode") },
		"empty mode":    func(m map[string]any) { m["mode"] = "" },
		"unknown mode":  func(m map[string]any) { m["mode"] = "both" },
		"mode case":     func(m map[string]any) { m["mode"] = "Store" },
	}
	cases := map[string]string{"not json": "nope"}
	for name, brk := range bad {
		m := valid()
		brk(m)
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		cases[name] = string(raw)
	}
	// Padding before a valid body: only the size limit rejects it.
	padded, _ := json.Marshal(valid())
	cases["body too big"] = strings.Repeat(" ", 70000) + string(padded)
	for name, body := range cases {
		if rec := f.post("/mesh/install", f.admin, []byte(body), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
	var n int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM mesh_installations WHERE org_id=$1`, f.org.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("refused installs stored %d rows", n)
	}

	installedKeepSecret(t, f.install(f.admin, ws, "tok-1", "events-secret-AAAAAAAAAAAA"))
	// Re-install by the same org rotates the secrets: the old events secret stops working.
	installedKeepSecret(t, f.install(f.admin, ws, "tok-2", "events-secret-BBBBBBBBBBBB"))
	body := eventBody(ws, "after-reinstall", "project.created")
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, "events-secret-AAAAAAAAAAAA", time.Now(), body)); rec.Code != http.StatusUnauthorized {
		t.Errorf("old events secret after reinstall: status = %d, want 401", rec.Code)
	}
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, "events-secret-BBBBBBBBBBBB", time.Now(), body)); rec.Code != http.StatusOK {
		t.Errorf("new events secret after reinstall: status = %d, want 200", rec.Code)
	}

	// Another organisation cannot take over a connected workspace.
	tr := tenancy.New(f.pool)
	other, err := tr.CreateOrganization(context.Background(), t.Name()+"-other", "")
	if err != nil {
		t.Fatal(err)
	}
	g := &meshFixture{t: t, pool: f.pool, router: f.router, org: other}
	g.admin = g.bearer(tr, "admin2", true)
	if rec := g.install(g.admin, ws, "tok-x", "events-secret-CCCCCCCCCCCC"); rec.Code != http.StatusConflict {
		t.Errorf("foreign org takeover: status = %d, want 409", rec.Code)
	}
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, "events-secret-CCCCCCCCCCCC", time.Now(), body)); rec.Code != http.StatusUnauthorized {
		t.Errorf("takeover secret works for events: status = %d, want 401", rec.Code)
	}
}

// With the extension off, Keep serves no Mesh route at all and nothing else
// changes: the core does not depend on Mesh.
func TestMeshExtensionOffServesNoRoutes(t *testing.T) {
	f := newMeshFixture(t, false)
	for _, p := range []string{"/mesh/install", "/mesh/events"} {
		if rec := f.post(p, f.admin, []byte(`{}`), nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s with extension off: status = %d, want 404/405", p, rec.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz with extension off: status = %d", rec.Code)
	}
}

// The manifest the Mesh side reads must agree with what the server serves.
func TestMeshManifestMatchesServer(t *testing.T) {
	raw, err := os.ReadFile("../../../mesh-extension.json")
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var m struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Runtime string `json:"runtime"`
		Levels  struct {
			Project bool `json:"project"`
		} `json:"levels"`
		Capabilities struct {
			API     []string `json:"api"`
			Events  []string `json:"events"`
			Secrets []string `json:"secrets"`
		} `json:"capabilities"`
		External struct {
			HealthPath  string `json:"health_path"`
			InstallPath string `json:"install_path"`
			EventsPath  string `json:"events_path"`
			TokenPath   string `json:"token_path"`
			UI          map[string]struct {
				Path  string `json:"path"`
				Title string `json:"title"`
			} `json:"ui"`
		} `json:"external"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest is not JSON: %v", err)
	}
	if m.ID != "keep" || m.Runtime != "external" || m.External.InstallPath != "/mesh/install" || m.External.EventsPath != "/mesh/events" || m.External.HealthPath != "/healthz" {
		t.Fatalf("manifest identity/paths: %+v", m)
	}
	// Without token_path Mesh does not deliver the actor token to Keep: its
	// rotate-token hands the token back to the caller instead.
	if m.External.TokenPath != "/mesh/token" {
		t.Fatalf("manifest token_path %q, want /mesh/token", m.External.TokenPath)
	}
	if len(m.Capabilities.Secrets) != 0 {
		t.Fatal("manifest must not declare secrets capability")
	}
	if m.Levels.Project {
		t.Fatal("manifest must not offer the project level")
	}
	// The sidebar entry carries the product name; its path stays the screen
	// route, where the keep_mesh_ui cookie and the frame policy are scoped.
	side, ok := m.External.UI["sidebar.item"]
	if !ok || side.Title != m.Name || m.Name != "Keep" || side.Path != "/mesh/ui/secrets" {
		t.Fatalf("manifest sidebar item %+v (name %q), want title Keep at /mesh/ui/secrets", side, m.Name)
	}
	// Rotation rights belong to the keep-rotator manifest, not to this one
	// (TestMeshManifestsSplitRotationRights).
	if len(m.Capabilities.Events) != len(meshext.EventTypes) {
		t.Fatalf("manifest events %v != server event types", m.Capabilities.Events)
	}
	for _, e := range m.Capabilities.Events {
		if !meshext.EventTypes[e] {
			t.Errorf("manifest event %q is not accepted by the server", e)
		}
	}
}

// Mesh refuses to install a manifest that fails its schema, so the file is
// validated against a copy of manifest.v1.json from the Mesh repo
// (internal/extensions/schema/manifest.v1.json). Both manifests of the repo are
// checked.
func TestMeshManifestValidAgainstMeshSchema(t *testing.T) {
	schemaRaw, err := os.ReadFile("testdata/mesh-manifest.v1.json")
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("mesh-manifest.v1.json", schemaDoc); err != nil {
		t.Fatalf("schema resource: %v", err)
	}
	sch, err := c.Compile("mesh-manifest.v1.json")
	if err != nil {
		t.Fatalf("schema compile: %v", err)
	}
	// Positive control: an emptied or trivial schema copy would pass anything.
	if err := sch.Validate(map[string]any{}); err == nil {
		t.Fatal("schema copy accepts an empty manifest, it is not the Mesh schema")
	}
	for _, file := range meshManifestPaths {
		manifestRaw, err := os.ReadFile(file) //nolint:gosec // G304: one of the two manifest paths fixed in mesh_manifest_test.go
		if err != nil {
			t.Fatalf("manifest: %v", err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(manifestRaw))
		if err != nil {
			t.Fatalf("%s is not JSON: %v", file, err)
		}
		if err := sch.Validate(doc); err != nil {
			t.Errorf("%s does not match the Mesh manifest schema: %v", file, err)
		}
	}
}

// A signature made with one workspace's events secret never verifies for
// another workspace, whether it sits in the same organization or another one.
func TestMeshEventsAreBoundToTheirWorkspace(t *testing.T) {
	f := newMeshFixture(t, true)
	tr := tenancy.New(f.pool)
	otherOrg, err := tr.CreateOrganization(context.Background(), t.Name()+"-other", "")
	if err != nil {
		t.Fatal(err)
	}
	g := &meshFixture{t: t, pool: f.pool, router: f.router, org: otherOrg}
	g.admin = g.bearer(tr, "admin2", true)

	wsA, wsB, wsC := uuid.New(), uuid.New(), uuid.New()
	secA, secB, secC := "events-secret-AAAAAAAAAAAA", "events-secret-BBBBBBBBBBBB", "events-secret-CCCCCCCCCCCC"
	installedKeepSecret(t, f.install(f.admin, wsA, "tok-a", secA))
	installedKeepSecret(t, f.install(f.admin, wsB, "tok-b", secB)) // same org as A
	installedKeepSecret(t, g.install(g.admin, wsC, "tok-c", secC)) // another org

	for name, target := range map[string]uuid.UUID{"same org": wsB, "other org": wsC} {
		// The body names the target workspace, so only the key can be wrong.
		body := eventBody(target, "x-"+name[:3], "project.created")
		if rec := f.post("/mesh/events", "", body, signedHeaders(target, secA, time.Now(), body)); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: A's secret for another workspace: status = %d, want 401", name, rec.Code)
		}
	}
	// Positive controls: each workspace's own secret works.
	for ws, sec := range map[uuid.UUID]string{wsA: secA, wsB: secB, wsC: secC} {
		body := eventBody(ws, "own", "project.updated")
		if rec := f.post("/mesh/events", "", body, signedHeaders(ws, sec, time.Now(), body)); rec.Code != http.StatusOK {
			t.Errorf("own secret: status = %d body = %s", rec.Code, answerDiag(rec))
		}
	}
}

func TestMeshKeepSecretIsFreshRandom(t *testing.T) {
	f := newMeshFixture(t, true)
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		ks := installedKeepSecret(t, f.install(f.admin, uuid.New(), "tok", "events-secret-0123456789"))
		if len(ks) != 64 || strings.Trim(ks, "0123456789abcdef") != "" || strings.Trim(ks, "0") == "" {
			t.Fatalf("keep_secret is not 64 hex characters of fresh randomness: %d chars", len(ks))
		}
		if seen[ks] {
			t.Fatal("keep_secret repeated across installs")
		}
		seen[ks] = true
	}
}

// An install seals all three credentials, answers with no-store, and writes
// one audit record per outcome (success, refused non-admin, foreign owner).
func TestMeshInstallSealsAndAudits(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws := uuid.New()
	rec := f.install(f.admin, ws, "tok-1", "events-secret-0123456789")
	installedKeepSecret(t, rec)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	for _, kind := range []string{"extension_token", "events_secret", "keep_secret"} {
		var n int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM keep_envelope WHERE store_org=$1 AND name=$2`, f.org.ID.String(), "mesh/"+ws.String()+"/"+kind).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("%s was not sealed", kind)
		}
	}
	if rec := f.install(f.member, uuid.New(), "t", "events-secret-0123456789"); rec.Code != http.StatusNotFound {
		t.Fatalf("non-admin: %d", rec.Code)
	}
	tr := tenancy.New(f.pool)
	other, err := tr.CreateOrganization(ctx, t.Name()+"-o", "")
	if err != nil {
		t.Fatal(err)
	}
	g := &meshFixture{t: t, pool: f.pool, router: f.router, org: other}
	g.admin = g.bearer(tr, "admin2", true)
	if rec := g.install(g.admin, ws, "t", "events-secret-0123456789"); rec.Code != http.StatusConflict {
		t.Fatalf("foreign takeover: %d", rec.Code)
	}
	count := func(org, status string) (n int) {
		_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.install' AND result_status=$2`, org, status).Scan(&n)
		return n
	}
	if n := count(f.org.ID.String(), "ok"); n != 1 {
		t.Errorf("ok audit records = %d, want 1", n)
	}
	if n := count(f.org.ID.String(), "failed"); n != 1 {
		t.Errorf("denied audit records = %d, want 1", n)
	}
	if n := count(other.ID.String(), "failed"); n != 1 {
		t.Errorf("takeover audit records = %d, want 1", n)
	}
}

// A reinstall whose last step fails must not rotate anything: Mesh's previous
// events secret keeps authenticating, the secret from the failed attempt does
// not, and nothing of the failed attempt's credentials is disclosed.
func TestMeshFailedReinstallKeepsPreviousCredentials(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws := uuid.New()
	oldSecret := "events-old-" + uuid.NewString()
	newSecret := "events-new-" + uuid.NewString()
	installedKeepSecret(t, f.install(f.admin, ws, "tok-old", oldSecret))

	// Make the installation-row write (the last step) fail for this workspace.
	if _, err := f.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION mesh_test_fail_upsert() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	trg := "mesh_test_fail_" + strings.ReplaceAll(ws.String(), "-", "")
	if _, err := f.pool.Exec(ctx, `CREATE TRIGGER `+trg+` BEFORE UPDATE ON mesh_installations FOR EACH ROW WHEN (OLD.workspace_id = '`+ws.String()+`') EXECUTE FUNCTION mesh_test_fail_upsert()`); err != nil {
		t.Fatal(err)
	}
	dropped := false
	drop := func() {
		if !dropped {
			dropped = true
			_, _ = f.pool.Exec(ctx, `DROP TRIGGER `+trg+` ON mesh_installations`)
		}
	}
	defer drop()

	rec := f.install(f.admin, ws, "tok-new", newSecret)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("failed reinstall: status = %d, want 500", rec.Code)
	}
	drop()

	// The failed attempt's response, log and audit journal carry no credential.
	var auditText string
	_ = f.pool.QueryRow(ctx, `SELECT COALESCE(string_agg(row_to_json(a)::text, ' '), '') FROM audit_records a WHERE org_id=$1`, f.org.ID.String()).Scan(&auditText)
	for name, surface := range map[string]string{"response": rec.Body.String() + fmt.Sprint(rec.Header()), "log": f.logbuf.String(), "audit": auditText} {
		for _, v := range []string{oldSecret, newSecret, "tok-old", "tok-new"} {
			if strings.Contains(surface, v) {
				t.Errorf("%s of the failed reinstall contains a credential", name)
			}
		}
	}

	body := eventBody(ws, "evt-after-failed-reinstall", "project.created")
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, newSecret, time.Now(), body)); rec.Code != http.StatusUnauthorized {
		t.Errorf("secret of the failed attempt: status = %d, want 401", rec.Code)
	}
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, oldSecret, time.Now(), body)); rec.Code != http.StatusOK {
		t.Fatalf("previous secret after failed reinstall: status = %d, want 200", rec.Code)
	}
}

// /mesh/install carries the Mesh token and events secret in and Keep's secret
// out; on the plain listener it must not exist, and nothing of the attempt
// may reach any surface.
func TestMeshInstallNotServedOverPlainHTTP(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	tok, evs := "tok-plain-"+uuid.NewString(), "events-plain-"+uuid.NewString()
	b, _ := json.Marshal(map[string]string{
		"mesh_url": "https://mesh.example.test", "workspace_id": ws.String(),
		"extension_token": tok, "events_endpoint_secret": evs, "mode": "extension",
	})
	rec := f.send("/mesh/install", f.admin, b, nil, false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("plain install: status = %d, want 404", rec.Code)
	}
	for name, surface := range map[string]string{"response": rec.Body.String() + fmt.Sprint(rec.Header()), "log": f.logbuf.String()} {
		if strings.Contains(surface, tok) || strings.Contains(surface, evs) || strings.Contains(surface, "keep_secret") {
			t.Errorf("%s of the plain request carries a credential", name)
		}
	}
	if _, found, err := meshext.NewRepo(f.pool).Owner(context.Background(), ws); err != nil || found {
		t.Fatalf("plain install created an installation (found=%v err=%v)", found, err)
	}
	if rec := f.install(f.admin, ws, tok, evs); rec.Code != http.StatusOK {
		t.Fatalf("TLS positive control: status = %d", rec.Code)
	}
}

// Installs of one workspace are serialized: while another holder has the
// workspace lock an install waits, and it proceeds once the lock is released.
func TestMeshInstallWaitsForWorkspaceLock(t *testing.T) {
	f := newMeshFixture(t, true)
	repo := meshext.NewRepo(f.pool)
	ws := uuid.New()
	rawUnlock, err := repo.LockWorkspace(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	// Released on every path: a held lock would block the pool's cleanup.
	var once sync.Once
	unlock := func() { once.Do(rawUnlock) }
	defer unlock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.install(f.admin, ws, "tok-locked", "events-locked-0123456789") }()
	select {
	case <-done:
		t.Fatal("install completed while the workspace lock was held")
	case <-time.After(500 * time.Millisecond):
	}
	if _, found, _ := repo.Owner(context.Background(), ws); found {
		t.Fatal("install wrote the installation while the workspace lock was held")
	}
	unlock()
	select {
	case rec := <-done:
		installedKeepSecret(t, rec)
	case <-time.After(10 * time.Second):
		t.Fatal("install did not proceed after the lock was released")
	}
	// A different workspace is not blocked by this one's lock.
	other := uuid.New()
	unlock2, err := repo.LockWorkspace(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock2()
	installedKeepSecret(t, f.install(f.admin, uuid.New(), "tok-free", "events-free-0123456789"))
}

// N parallel installs of one workspace each succeed, get distinct Keep
// secrets, and leave exactly one events secret active: the winner's.
func TestMeshConcurrentInstallsLeaveOneConsistentPair(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	const n = 8
	secrets := make([]string, n)
	keep := make([]string, n)
	var wg sync.WaitGroup
	for i := range secrets {
		secrets[i] = fmt.Sprintf("events-par-%d-%s", i, uuid.NewString())
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := f.install(f.admin, ws, fmt.Sprintf("tok-par-%d", i), secrets[i])
			if rec.Code == http.StatusOK {
				var res struct {
					KeepSecret string `json:"keep_secret"`
				}
				_ = json.Unmarshal(rec.Body.Bytes(), &res)
				keep[i] = res.KeepSecret
			}
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for i, k := range keep {
		if k == "" || seen[k] {
			t.Fatalf("install %d: missing or duplicate keep secret", i)
		}
		seen[k] = true
	}
	active := 0
	for i, sec := range secrets {
		body := eventBody(ws, fmt.Sprintf("evt-par-%d", i), "project.created")
		if rec := f.post("/mesh/events", "", body, signedHeaders(ws, sec, time.Now(), body)); rec.Code == http.StatusOK {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("%d events secrets authenticate after %d concurrent installs, want exactly 1", active, n)
	}
}

// Parallel installs of one workspace on a pool no bigger than the number of
// installs must not exhaust it: every waiter holds a lock connection, and the
// holder still needs another for its own queries.
func TestMeshInstallsDoNotExhaustSmallPool(t *testing.T) {
	cfg := testPool(t).Config().Copy()
	cfg.MaxConns = 3
	small, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(small.Close)
	f := newMeshFixtureOn(t, small, true)
	ws := uuid.New()
	const n = 8
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			codes <- f.install(f.admin, ws, fmt.Sprintf("tok-small-%d", i), fmt.Sprintf("events-small-%d-%s", i, uuid.NewString())).Code
		}(i)
	}
	for i := 0; i < n; i++ {
		select {
		case c := <-codes:
			if c != http.StatusOK {
				t.Errorf("install: status = %d, want 200", c)
			}
		case <-time.After(60 * time.Second):
			t.Fatalf("only %d of %d installs finished: the pool is exhausted by lock waiters", i, n)
		}
	}
	// The rest of the API still gets a connection.
	if _, _, err := meshext.NewRepo(small).Owner(context.Background(), ws); err != nil {
		t.Fatalf("pool unusable after installs: %v", err)
	}
}
