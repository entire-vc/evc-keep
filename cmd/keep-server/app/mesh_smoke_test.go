package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// smokeCall is one request of the Mesh extension over a real TLS connection.
type smokeCall struct {
	method, path string
	body         []byte
	ws           uuid.UUID
	secret       string // "" = unsigned
	nonce        string // "" = fresh
}

type smokeAnswer struct {
	code int
	hdr  http.Header
	body []byte
}

// smoke is the Mesh side of K5.9 over the wire: an httptest TLS listener in
// front of the real router and PostgreSQL, a stock net/http client, and the
// signer of meshSecretMAC. The request line is what the server's net/http
// parses, not a hand-built one, so the signed path is the path as sent.
type smoke struct {
	t      *testing.T
	f      *meshFixture
	url    string
	client *http.Client
}

func newSmoke(t *testing.T, f *meshFixture) *smoke {
	t.Helper()
	srv := httptest.NewUnstartedServer(f.router)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &smoke{t: t, f: f, url: srv.URL, client: srv.Client()}
}

func (s *smoke) do(c smokeCall) smokeAnswer {
	s.t.Helper()
	req, err := http.NewRequest(c.method, s.url+c.path, bytes.NewReader(c.body))
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		nonce := c.nonce
		if nonce == "" {
			nonce = freshNonce(s.t)
		}
		req.Header.Set("X-Mesh-Workspace", c.ws.String())
		for k, v := range meshSecretMAC(c.secret, time.Now(), nonce, c.method, c.path, c.body) {
			req.Header.Set(k, v)
		}
	}
	res, err := s.client.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return smokeAnswer{res.StatusCode, res.Header, b}
}

func (a smokeAnswer) text() string {
	var b strings.Builder
	for k, vs := range a.hdr {
		b.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
	}
	return b.String() + string(a.body)
}

// Failure messages of the smoke are built from booleans and lengths only: the
// fields of an answer are untrusted until the canary check has run on them, so
// a failing run must not echo them.
func putMalformedMsg(gotRef, wantRef, version, fingerprint string) string {
	return fmt.Sprintf("PUT answer malformed: ref ok=%v version present=%v fingerprint prefix ok=%v",
		gotRef == wantRef, version != "", strings.HasPrefix(fingerprint, "kfp1:"))
}

func roundtripMsg(code int, sameVersion, sameValue bool) string {
	return fmt.Sprintf("roundtrip failed: status %d, version equal=%v, value equal=%v", code, sameVersion, sameValue)
}

func cacheMsg(name, got string) string {
	return fmt.Sprintf("%s Cache-Control ok=false (length %d), want no-store", name, len(got))
}

// TestSmokeDiagnosticsDoNotEcho feeds the canary through every field the
// failure messages are built from, in every encoding the detector knows.
func TestSmokeDiagnosticsDoNotEcho(t *testing.T) {
	c := canary.New()
	v := c.Value(2)
	for _, x := range []string{v, hex.EncodeToString([]byte(v)), "x" + v} {
		for name, msg := range map[string]string{
			"put":       putMalformedMsg(x, "other", x, x),
			"roundtrip": roundtripMsg(500, false, false),
			"cache":     cacheMsg("PUT", x),
		} {
			if c.In(msg) {
				t.Errorf("%s diagnostic echoes its input", name)
			}
		}
	}
	// Positive control: the detector sees a message that does echo.
	if !c.In(fmt.Sprintf("ref=%q", v)) {
		t.Fatal("canary detector is blind")
	}
}

// TestMeshExtensionSmoke is the authenticated smoke of the Mesh extension
// against a stand built in the run itself: its own database, organizations,
// workspaces, events secrets and a synthetic value. Nothing from the fleet is
// used. The output carries names, versions, fingerprints and lengths only.
func TestMeshExtensionSmoke(t *testing.T) {
	f := newMeshFixture(t, true)
	s := newSmoke(t, f)
	ctx := context.Background()
	ws := f.installedWorkspace()
	ref := "smoke-" + hex.EncodeToString(uuid.NewSHA1(uuid.NameSpaceOID, []byte(t.Name())).NodeID())
	putPath := f.secretPath(f.org.ID, ref, false)
	resPath := f.secretPath(f.org.ID, ref, true)

	// Leak test, first: the detector must see the value in every encoding and
	// in a deliberately bad answer, or the checks below prove nothing.
	c := canary.New()
	val := c.Value(1)
	if !c.In("x"+val) || !c.In(hex.EncodeToString([]byte(val))) || !c.In(smokeAnswer{200, http.Header{"X": {val}}, nil}.text()) {
		t.Fatal("canary detector is blind")
	}

	// 2. Roundtrip: PUT then resolve return the same value (compared in
	// process, never printed).
	body, _ := json.Marshal(map[string]string{"value": val})
	put := s.do(smokeCall{method: http.MethodPut, path: putPath, body: body, ws: ws, secret: meshTestEventsSecret})
	if put.code != http.StatusOK {
		t.Fatalf("PUT status = %d (body not printed, %d bytes)", put.code, len(put.body))
	}
	var meta struct{ Ref, Version, Fingerprint string }
	_ = json.Unmarshal(put.body, &meta)
	if meta.Ref != ref || meta.Version == "" || !strings.HasPrefix(meta.Fingerprint, "kfp1:") {
		t.Fatal(putMalformedMsg(meta.Ref, ref, meta.Version, meta.Fingerprint))
	}
	res := s.do(smokeCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestEventsSecret})
	var out struct{ Value, Version string }
	_ = json.Unmarshal(res.body, &out)
	if res.code != http.StatusOK || out.Value != val || out.Version != meta.Version {
		t.Fatal(roundtripMsg(res.code, out.Version == meta.Version, out.Value == val))
	}

	// 3. No cache anywhere on the value's path.
	for name, a := range map[string]smokeAnswer{"PUT": put, "resolve": res} {
		if cc := a.hdr.Get("Cache-Control"); cc != "no-store" {
			t.Error(cacheMsg(name, cc))
		}
	}
	if c.In(put.text()) || c.In(headersOnly(res)) {
		t.Fatal("value outside the resolve body")
	}

	// 4. Organization isolation: a second organization with its own workspace
	// and the same ref cannot see this value, and the first workspace cannot
	// name the second organization.
	tr := tenancy.New(f.pool)
	org2, err := tr.CreateOrganization(ctx, t.Name()+"-b", "")
	if err != nil {
		t.Fatal(err)
	}
	g := *f
	g.org = org2
	g.admin = g.bearer(tr, "admin", true)
	ws2 := uuid.New()
	installedKeepSecret(t, g.install(g.admin, ws2, "tok-b", meshTestEventsSecret))
	own2 := s.do(smokeCall{method: http.MethodPost, path: g.secretPath(org2.ID, ref, true), ws: ws2, secret: meshTestEventsSecret})
	cross := s.do(smokeCall{method: http.MethodPost, path: g.secretPath(org2.ID, ref, true), ws: ws, secret: meshTestEventsSecret})
	cross2 := s.do(smokeCall{method: http.MethodPost, path: resPath, ws: ws2, secret: meshTestEventsSecret})
	if own2.code != http.StatusNotFound || cross.code != http.StatusForbidden || cross2.code != http.StatusForbidden {
		t.Fatalf("isolation: own-org other workspace %d (want 404), ws into foreign org %d, foreign ws into org %d (want 403)", own2.code, cross.code, cross2.code)
	}
	for name, a := range map[string]smokeAnswer{"own2": own2, "cross": cross, "cross2": cross2} {
		if c.In(a.text()) {
			t.Fatalf("%s: value on a refusal", name)
		}
	}

	// A second workspace of the same organization has its own namespace: the
	// same ref is a 404 for it, not the first workspace's value.
	ws3 := uuid.New()
	installedKeepSecret(t, f.install(f.admin, ws3, "tok-c", meshTestEventsSecret))
	if a := s.do(smokeCall{method: http.MethodPost, path: resPath, ws: ws3, secret: meshTestEventsSecret}); a.code != http.StatusNotFound || c.In(a.text()) {
		t.Fatalf("same-org other workspace: status %d, want 404 without the value", a.code)
	}

	// 5. Bad signature and replay are 401; so is no signature at all.
	for name, a := range map[string]smokeAnswer{
		"wrong key": s.do(smokeCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestWrongSecret}),
		"unsigned":  s.do(smokeCall{method: http.MethodPost, path: resPath}),
	} {
		if a.code != http.StatusUnauthorized || c.In(a.text()) {
			t.Errorf("%s: status %d, want 401", name, a.code)
		}
	}
	n := freshNonce(t)
	if a := s.do(smokeCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestEventsSecret, nonce: n}); a.code != http.StatusOK {
		t.Fatalf("first use of a nonce: %d", a.code)
	}
	if a := s.do(smokeCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestEventsSecret, nonce: n}); a.code != http.StatusUnauthorized {
		t.Errorf("replayed nonce: %d, want 401", a.code)
	}

	// Revoked actor: a reinstall rotates the events secret and the old one is
	// refused at once, on the same wire.
	installedKeepSecret(t, f.install(f.admin, ws, "tok-2", meshTestRotatedSecret))
	if a := s.do(smokeCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestEventsSecret}); a.code != http.StatusUnauthorized {
		t.Errorf("revoked actor: %d, want 401", a.code)
	}
	if a := s.do(smokeCall{method: http.MethodPost, path: resPath, ws: ws, secret: meshTestRotatedSecret}); a.code != http.StatusOK {
		t.Errorf("new secret: %d, want 200", a.code)
	}

	// 6. Audit: the successful calls are journaled with name, version,
	// fingerprint and length, and the value is on no stored surface.
	var puts, resolves, withFP int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='mesh.secret.put' AND result_status='ok'),
		count(*) FILTER (WHERE action='mesh.secret.resolve' AND result_status='ok'),
		count(*) FILTER (WHERE result_status='ok' AND secret_name=$2 AND secret_version=$3 AND result_fingerprint=$4 AND result_length=$5)
		FROM audit_records WHERE org_id=$1 AND action LIKE 'mesh.secret.%'`,
		f.org.ID.String(), ref, meta.Version, meta.Fingerprint, len(val)).Scan(&puts, &resolves, &withFP); err != nil {
		t.Fatal(err)
	}
	if puts != 1 || resolves < 2 || withFP != puts+resolves {
		t.Errorf("audit: put=%d resolve=%d complete=%d", puts, resolves, withFP)
	}
	for i, d := range f.surfaces() {
		if c.In(d) {
			t.Errorf("value found on surface %d (0=log 1=audit 2=installations 3=events 4=sealed storage)", i)
		}
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("log captured nothing; the test proves nothing")
	}
	if c.In(ref) || c.In(meta.Version) || c.In(meta.Fingerprint) {
		t.Fatal("value in the success line fields")
	}
	t.Logf("smoke ok: ref=%s version=%s fingerprint=%s length=%d", ref, meta.Version, meta.Fingerprint, len(val))
}

func headersOnly(a smokeAnswer) string { return smokeAnswer{hdr: a.hdr}.text() }
