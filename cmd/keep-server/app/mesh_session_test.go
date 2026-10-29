package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/meshfake"
	"github.com/google/uuid"
)

type sessionFixture struct {
	*meshFixture
	mesh *meshfake.Mesh
	ws   uuid.UUID
}

// newSessionFixture connects a workspace whose Mesh is a loopback fake.
func newSessionFixture(t *testing.T, opts ...func(*api.MeshDeps)) *sessionFixture {
	t.Helper()
	f := newMeshFixtureOn(t, testPool(t), true, opts...)
	m := meshfake.New(meshfake.NewKey("k1"))
	t.Cleanup(m.Close)
	ws := uuid.New()
	cn := canary.New()
	b, _ := json.Marshal(map[string]string{"mesh_url": m.URL(), "workspace_id": ws.String(),
		"extension_token": cn.Value(8), "events_endpoint_secret": cn.Value(9)})
	if rec := f.post("/mesh/install", f.admin, b, nil); rec.Code != http.StatusOK {
		t.Fatalf("install: %d", rec.Code)
	}
	return &sessionFixture{meshFixture: f, mesh: m, ws: ws}
}

func (f *sessionFixture) signIn(tok string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"ctx": tok})
	return f.post("/mesh/session", "", b, sameOriginJSON)
}

// sameOriginJSON is what the Keep screen inside Mesh's iframe sends.
var sameOriginJSON = map[string]string{"Sec-Fetch-Site": "same-origin", "Content-Type": "application/json"}

// token signs a context for the Mesh user named sub (see meshSub).
func (f *sessionFixture) token(sub, email string) string {
	return sign(f.mesh.Key0(0), nil, f.mesh.Valid(f.ws.String(), meshSub(sub), email))
}

// meshSub is the Mesh user id a test calls by name: Mesh names a user by
// UUID, and Keep refuses a context whose subject is not one.
func meshSub(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("mesh-user:"+name)).String()
}

func (f *sessionFixture) count(q string, args ...any) int {
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "keep_console" {
			return c
		}
	}
	return nil
}

func TestMeshSessionOpensForValidContextAndMapsUser(t *testing.T) {
	f := newSessionFixture(t)
	rec := f.signIn(f.token("mesh-user-1", "p@example.test"))
	ck := sessionCookie(rec)
	if rec.Code != http.StatusOK || ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteNoneMode {
		t.Fatalf("sign-in: %d cookie=%+v", rec.Code, ck)
	}
	s, err := identity.NewRepo(f.pool).LookupSession(context.Background(), ck.Value)
	if err != nil || s.Principal.Kind != identity.KindUser || s.Principal.OrgID != f.org.ID {
		t.Fatalf("session does not resolve to a user of the org: %v %+v", err, s.Principal)
	}
	ref := "mesh:" + f.mesh.URL() + ":" + meshSub("mesh-user-1")
	if n := f.count(`SELECT count(*) FROM users WHERE org_id=$1 AND external_ref=$2 AND id=$3`, f.org.ID, ref, s.Principal.ID); n != 1 {
		t.Fatalf("user not stored under external_ref")
	}
	// The Mesh user is linked, so a gate card they answer names this user.
	if n := f.count(`SELECT count(*) FROM mesh_user_links WHERE workspace_id=$1 AND mesh_user_id=$2 AND org_id=$3 AND user_id=$4`,
		f.ws, meshSub("mesh-user-1"), f.org.ID, s.Principal.ID); n != 1 {
		t.Fatalf("mesh user not linked at sign-in")
	}
	// A second visit is the same user, not a new one.
	rec2 := f.signIn(f.token("mesh-user-1", "p@example.test"))
	if rec2.Code != http.StatusOK || f.count(`SELECT count(*) FROM users WHERE external_ref=$1`, ref) != 1 {
		t.Fatalf("second sign-in created another user (%d)", rec2.Code)
	}
	// A different Mesh person is a different user.
	if f.signIn(f.token("mesh-user-2", "q@example.test")).Code != http.StatusOK || f.count(`SELECT count(*) FROM users WHERE org_id=$1 AND external_ref LIKE 'mesh:%'`, f.org.ID) != 2 {
		t.Fatal("second person not mapped separately")
	}
}

func TestMeshSessionRefusesBadContextsWithNoEffect(t *testing.T) {
	f := newSessionFixture(t)
	k := f.mesh.Key0(0)
	good := func() meshfake.Claims { return f.mesh.Valid(f.ws.String(), meshSub("u1"), "a@example.test") }
	expired := good()
	expired["exp"], expired["iat"] = int64(1_000_000), int64(999_990)
	foreignIss := good()
	foreignIss["iss"] = "https://evil.example.test"
	otherWS := f.mesh.Valid(uuid.NewString(), meshSub("u1"), "a@example.test") // not installed
	valid := sign(k, nil, good())
	parts := strings.Split(valid, ".")
	cases := map[string]string{
		"expired":        sign(k, nil, expired),
		"foreign iss":    sign(k, nil, foreignIss),
		"foreign kid":    sign(meshfake.Key{Kid: "evil", Priv: k.Priv}, nil, good()),
		"foreign key":    sign(meshfake.NewKey("k1"), nil, good()),
		"uninstalled ws": sign(k, nil, otherWS),
		"alg none":       parts[0] + "." + parts[1] + ".",
		"substituted ws": parts[0] + "." + strings.Replace(parts[1], parts[1][:8], "AAAAAAAA", 1) + "." + parts[2],
		"garbage":        "x.y.z",
	}
	for name, tok := range cases {
		rec := f.signIn(tok)
		if rec.Code != http.StatusUnauthorized || sessionCookie(rec) != nil {
			t.Errorf("%s: status %d cookie=%v", name, rec.Code, sessionCookie(rec))
		}
	}
	if n := f.count(`SELECT count(*) FROM users WHERE external_ref LIKE 'mesh:%'`); n != 0 {
		t.Fatalf("refused sign-ins created %d users", n)
	}
	// positive control: the same harness accepts the untouched token.
	if f.signIn(valid).Code != http.StatusOK {
		t.Fatal("harness refuses a valid token")
	}
}

func TestMeshSessionEmailNeverLinksAnExistingUser(t *testing.T) {
	f := newSessionFixture(t)
	// "member" exists in the org with some email; a Mesh person claiming it must not become them.
	var email string
	if err := f.pool.QueryRow(context.Background(), `SELECT email FROM users WHERE org_id=$1 LIMIT 1`, f.org.ID).Scan(&email); err != nil {
		t.Fatal(err)
	}
	rec := f.signIn(f.token("imposter", email))
	if rec.Code != http.StatusUnauthorized || sessionCookie(rec) != nil {
		t.Fatalf("email collision signed in: %d", rec.Code)
	}
	if f.count(`SELECT count(*) FROM users WHERE external_ref IS NOT NULL AND org_id=$1`, f.org.ID) != 0 {
		t.Fatal("a user was created or linked on email collision")
	}
}

func TestMeshSessionRemovedUserRefused(t *testing.T) {
	f := newSessionFixture(t)
	if f.signIn(f.token("gone", "g@example.test")).Code != http.StatusOK {
		t.Fatal("setup")
	}
	tag, err := f.pool.Exec(context.Background(), `UPDATE users SET status='removed', removed_at=now() WHERE external_ref LIKE '%:'||$1`, meshSub("gone"))
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("remove user: %v, rows=%d", err, tag.RowsAffected())
	}
	if rec := f.signIn(f.token("gone", "g@example.test")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("removed user signed in: %d", rec.Code)
	}
}

func TestMeshSessionNotServedOverPlainHTTPAndWhenMeshOff(t *testing.T) {
	f := newSessionFixture(t)
	b, _ := json.Marshal(map[string]string{"ctx": f.token("u", "u@example.test")})
	if rec := f.send("/mesh/session", "", b, sameOriginJSON, false); rec.Code != http.StatusNotFound || sessionCookie(rec) != nil {
		t.Fatalf("plain HTTP served the route: %d", rec.Code)
	}
	off := newMeshFixture(t, false)
	if rec := off.post("/mesh/session", "", b, sameOriginJSON); rec.Code != http.StatusNotFound {
		t.Fatalf("route exists with the extension off: %d", rec.Code)
	}
}

func TestMeshSessionNeverLeaksContextToken(t *testing.T) {
	f := newSessionFixture(t)
	cn := canary.New()
	if !cn.In("x" + cn.Value(1)) {
		t.Fatal("canary detector is blind")
	}
	var surfaces []string
	collect := func(rec *httptest.ResponseRecorder) {
		surfaces = append(surfaces, rec.Body.String())
		for k, v := range rec.Header() {
			surfaces = append(surfaces, k+": "+strings.Join(v, ","))
		}
	}
	// The canaries ride in the token itself (email) and as raw ctx values; the
	// subject is a Mesh user id, so it cannot carry one.
	sub := uuid.NewString()
	good := sign(f.mesh.Key0(0), nil, f.mesh.Valid(f.ws.String(), sub, cn.Value(2)+"@example.test"))
	collect(f.signIn(good))
	bad := sign(meshfake.NewKey("k1"), nil, f.mesh.Valid(f.ws.String(), sub, cn.Value(2)+"@example.test"))
	collect(f.signIn(bad))
	collect(f.signIn(cn.Value(3)))
	collect(f.post("/mesh/session", "", []byte(`{"ctx":"`+bad+`","extra":"`+cn.Value(3)+`"}`), sameOriginJSON))
	surfaces = append(surfaces, f.logbuf.String())
	for _, tok := range []string{good, bad} {
		for _, part := range strings.Split(tok, ".") {
			for _, s := range surfaces {
				if len(part) > 20 && strings.Contains(s, part) {
					t.Fatalf("token segment surfaced in a response or log")
				}
			}
		}
	}
	for i, s := range surfaces {
		if cn.In(s) && !strings.HasPrefix(s, "Set-Cookie") {
			t.Fatalf("canary surfaced in surface %d", i)
		}
	}
	// Durable: the stored session and token rows hold hashes only.
	for _, q := range []string{`SELECT row_to_json(t)::text FROM console_sessions t`, `SELECT row_to_json(t)::text FROM tokens t`, `SELECT row_to_json(t)::text FROM audit_records t`} {
		rows, err := f.pool.Query(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			if strings.Contains(s, good) || strings.Contains(s, bad) {
				t.Fatalf("token stored in the clear: %s", q)
			}
		}
		rows.Close()
	}
	// The user's email (not a secret, but stored) is the only place the email canary may land.
	if f.count(`SELECT count(*) FROM users WHERE email LIKE '%'||$1||'%'`, cn.Value(2)) != 1 {
		t.Fatal("positive control: accepted user not stored")
	}
}

// sign signs claims with k under header (ES256 by default), the way Mesh does.
func sign(k meshfake.Key, header map[string]any, c meshfake.Claims) string {
	if header == nil {
		header = map[string]any{"alg": "ES256", "typ": "JWT", "kid": k.Kid}
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(c)
	signing := meshfake.Enc(hb) + "." + meshfake.Enc(pb)
	d := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, k.Priv, d[:])
	if err != nil {
		panic(err)
	}
	return signing + "." + meshfake.Enc(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

// Login CSRF: a foreign page's auto-submitted form must not open a session in
// the visitor's browser. The same body with the iframe's headers is accepted.
func TestMeshSessionRefusesCrossSiteAndNonJSONPosts(t *testing.T) {
	f := newSessionFixture(t)
	body, _ := json.Marshal(map[string]string{"ctx": f.token("u1", "a@example.test")})
	for name, hdr := range map[string]map[string]string{
		"cross-site fetch metadata": {"Sec-Fetch-Site": "cross-site", "Content-Type": "application/json"},
		"foreign origin":            {"Origin": "https://evil.example.test", "Content-Type": "application/json"},
		"no origin, no metadata":    {"Content-Type": "application/json"},
		"form content type":         {"Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded"},
		"text/plain form":           {"Sec-Fetch-Site": "same-origin", "Content-Type": "text/plain"},
		"no content type":           {"Sec-Fetch-Site": "same-origin"},
	} {
		rec := f.post("/mesh/session", "", body, hdr)
		if rec.Code != http.StatusForbidden || sessionCookie(rec) != nil {
			t.Errorf("%s: status %d cookie=%v", name, rec.Code, sessionCookie(rec))
		}
	}
	if n := f.count(`SELECT count(*) FROM users WHERE external_ref LIKE 'mesh:%'`); n != 0 {
		t.Fatalf("refused posts created %d users", n)
	}
	if f.post("/mesh/session", "", body, sameOriginJSON).Code != http.StatusOK {
		t.Fatal("positive control: iframe-shaped post refused")
	}
}
