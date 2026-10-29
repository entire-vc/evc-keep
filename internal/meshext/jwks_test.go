package meshext

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/meshfake"
	"github.com/google/uuid"
)

func b64s(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func fixture(t *testing.T) (*meshfake.Mesh, *Verifier, uuid.UUID) {
	t.Helper()
	m := meshfake.New(meshfake.NewKey("k1"))
	t.Cleanup(m.Close)
	return m, NewVerifier(ExtensionID, nil), uuid.New()
}

func verify(v *Verifier, m *meshfake.Mesh, ws uuid.UUID, tok string) (ContextClaims, error) {
	return v.Verify(context.Background(), m.URL(), ws, NewContextToken(tok))
}

func TestVerifyAcceptsValidContext(t *testing.T) {
	m, v, ws := fixture(t)
	c, err := verify(v, m, ws, sign(m.Key0(0), nil, m.Valid(ws.String(), "u-1", "a@example.test")))
	if err != nil || c.Subject != "u-1" || c.Email != "a@example.test" || c.Workspace != ws || len(c.Roles) != 1 {
		t.Fatalf("valid token refused or misread: %v %+v", err, c)
	}
}

// Every red input must be refused with the one verdict, and the same harness
// must accept the valid one above (positive control).
func TestVerifyRefusesBadContexts(t *testing.T) {
	m, v, ws := fixture(t)
	good := func() meshfake.Claims { return m.Valid(ws.String(), "u-1", "a@example.test") }
	k := m.Key0(0)
	other := meshfake.NewKey("k1") // same kid, a key Mesh does not publish
	now := time.Now()
	mut := func(f func(c meshfake.Claims)) string { c := good(); f(c); return sign(k, nil, c) }
	valid := sign(k, nil, good())
	parts := strings.Split(valid, ".")

	cases := map[string]string{
		"expired": mut(func(c meshfake.Claims) {
			c["exp"] = now.Add(-time.Second).Unix()
			c["iat"] = now.Add(-30 * time.Second).Unix()
		}),
		"lifetime over 60": mut(func(c meshfake.Claims) { c["exp"] = now.Add(10 * time.Minute).Unix() }),
		"foreign issuer":   mut(func(c meshfake.Claims) { c["iss"] = "https://evil.example.test" }),
		"foreign audience": mut(func(c meshfake.Claims) { c["aud"] = "other-ext" }),
		"other workspace":  mut(func(c meshfake.Claims) { c["workspace_id"] = uuid.NewString() }),
		"no subject":       mut(func(c meshfake.Claims) { c["sub"] = "" }),
		"no exp":           mut(func(c meshfake.Claims) { delete(c, "exp") }),
		"alg none":         parts[0] + "." + parts[1] + ".",
		"alg none header":  b64s(`{"alg":"none","kid":"k1"}`) + "." + parts[1] + ".",
		"alg HS256":        sign(k, map[string]any{"alg": "HS256", "kid": "k1"}, good()),
		"unknown kid":      sign(meshfake.Key{Kid: "zz", Priv: k.Priv}, nil, good()),
		"foreign key":      sign(other, nil, good()),
		"tampered payload": parts[0] + "." + b64s(strings.Replace(string(mustDecode(t, parts[1])), ws.String(), uuid.NewString(), 1)) + "." + parts[2],
		"tampered sig":     parts[0] + "." + parts[1] + "." + b64s(strings.Repeat("x", 64)),
		"garbage":          "not-a-jwt",
		"empty":            "",
		"huge":             strings.Repeat("a", maxTokenLen+1),
	}
	for name, tok := range cases {
		if _, err := verify(v, m, ws, tok); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: got %v, want ErrInvalidContext", name, err)
		}
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyWorkspaceMustMatchSignedClaim(t *testing.T) {
	m, v, ws := fixture(t)
	tok := sign(m.Key0(0), nil, m.Valid(ws.String(), "u", "a@example.test"))
	if _, err := verify(v, m, uuid.New(), tok); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("a token for another workspace verified: %v", err)
	}
}

func TestVerifyIssuerComesFromInstallRecordNotToken(t *testing.T) {
	// Two instances; a token signed by B (valid on B) must not verify against A's record.
	a, v, ws := fixture(t)
	b := meshfake.New(meshfake.NewKey("k1"))
	defer b.Close()
	tok := sign(b.Key0(0), nil, b.Valid(ws.String(), "u", "a@example.test"))
	if _, err := verify(v, a, ws, tok); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("token of another Mesh verified: %v", err)
	}
	if _, err := verify(v, b, ws, tok); err != nil {
		t.Fatalf("positive control failed: %v", err)
	}
}

func TestVerifyReloadsKeysOnUnknownKidButNotOnEveryRequest(t *testing.T) {
	m, v, ws := fixture(t)
	now := time.Now()
	v.now = func() time.Time { return now }
	if _, err := verify(v, m, ws, sign(m.Key0(0), nil, m.Valid(ws.String(), "u", "a@example.test"))); err != nil {
		t.Fatal(err)
	}
	k2 := meshfake.NewKey("k2")
	m.Publish(k2)
	tok2 := sign(k2, nil, m.Valid(ws.String(), "u", "a@example.test"))
	// Inside the reload floor the new kid is not fetched.
	if _, err := verify(v, m, ws, tok2); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("new kid accepted inside reload floor: %v", err)
	}
	hits := m.Hits
	for i := 0; i < 5; i++ {
		_, _ = verify(v, m, ws, sign(meshfake.NewKey("junk"), nil, m.Valid(ws.String(), "u", "a@example.test")))
	}
	if m.Hits != hits {
		t.Fatalf("garbage kids caused %d key fetches", m.Hits-hits)
	}
	now = now.Add(jwksMinReload + time.Second)
	if _, err := verify(v, m, ws, tok2); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
}

func TestVerifyKeysUnavailableIsNotAVerdict(t *testing.T) {
	m, v, ws := fixture(t)
	now := time.Now()
	v.now = func() time.Time { return now }
	good := sign(m.Key0(0), nil, claimsAt(m, ws, now))
	m.Down = true
	if _, err := verify(v, m, ws, good); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("got %v", err)
	}
	now = now.Add(jwksMinReload + time.Second)
	good = sign(m.Key0(0), nil, claimsAt(m, ws, now))
	m.Down, m.Wrong = false, true
	if _, err := verify(v, m, ws, good); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("non-EC key set: got %v", err)
	}
	now = now.Add(jwksMinReload + time.Second)
	good = sign(m.Key0(0), nil, claimsAt(m, ws, now))
	m.Wrong = false
	if _, err := verify(v, m, ws, good); err != nil {
		t.Fatalf("recovery: %v", err)
	}
}

func TestVerifyDoesNotFollowRedirectsOffTheInstalledMesh(t *testing.T) {
	m, _, ws := fixture(t)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", m.URL()+r.URL.Path)
		w.WriteHeader(http.StatusFound)
	}))
	defer redirector.Close()
	v := NewVerifier(ExtensionID, nil)
	c := m.Valid(ws.String(), "u", "a@example.test")
	c["iss"] = redirector.URL
	_, err := v.Verify(context.Background(), redirector.URL, ws, NewContextToken(sign(m.Key0(0), nil, c)))
	if !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("redirected key fetch was followed: %v", err)
	}
}

// Leak test: the token is a credential. No error, log line or formatted value
// the verifier produces may contain any encoding of it.
func TestVerifyNeverLeaksTokenText(t *testing.T) {
	m, v, ws := fixture(t)
	cn := canary.New()
	if !cn.In(base64.StdEncoding.EncodeToString([]byte(cn.Value(1)))) {
		t.Fatal("canary detector is blind")
	}
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	c := m.Valid(ws.String(), cn.Value(1), "a@example.test")
	c["iss"] = cn.Value(2)
	var seen []string
	for _, tok := range []string{
		sign(m.Key0(0), nil, c),
		sign(m.Key0(0), nil, m.Valid(ws.String(), cn.Value(1), cn.Value(2))) + cn.Value(3),
		cn.Value(1) + "." + cn.Value(2) + "." + cn.Value(3),
		sign(meshfake.NewKey("k1"), nil, c),
	} {
		_, err := verify(v, m, ws, tok)
		if err == nil {
			t.Fatal("bad token accepted")
		}
		seen = append(seen, err.Error(), fmt.Sprintf("%v %+v %#v %s", err, err, err, err))
		tk := NewContextToken(tok)
		seen = append(seen, fmt.Sprintf("%v %+v %#v %s", tk, tk, tk, tk))
	}
	seen = append(seen, logs.String())
	for _, s := range seen {
		for i := 1; i <= 3; i++ {
			if cn.Value(i) != "" && cn.In(s) {
				t.Fatalf("token text surfaced: %q", s)
			}
		}
	}
	// positive control: an uncensored print of a claim is caught.
	if !cn.In("sub=" + cn.Value(1)) {
		t.Fatal("canary missed a plain leak")
	}
}

func TestPeekWorkspaceReadsOnlyTheClaim(t *testing.T) {
	m, _, ws := fixture(t)
	tok := sign(m.Key0(0), nil, m.Valid(ws.String(), "u", "a@example.test"))
	if got, ok := PeekWorkspace(NewContextToken(tok)); !ok || got != ws {
		t.Fatalf("peek = %v %v", got, ok)
	}
	for _, bad := range []string{"", "a.b", "a.!!.c", "a." + b64s(`{"workspace_id":"nope"}`) + ".c"} {
		if _, ok := PeekWorkspace(NewContextToken(bad)); ok {
			t.Fatalf("peek accepted %q", bad)
		}
	}
}
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

func claimsAt(m *meshfake.Mesh, ws uuid.UUID, t time.Time) meshfake.Claims {
	c := m.Valid(ws.String(), "u", "a@example.test")
	c["iat"], c["nbf"], c["exp"] = t.Unix(), t.Unix(), t.Add(60*time.Second).Unix()
	return c
}

func TestVerifyRefusesMoreBadClaims(t *testing.T) {
	m, v, ws := fixture(t)
	k := m.Key0(0)
	now := time.Now()
	mut := func(f func(c meshfake.Claims)) string {
		c := m.Valid(ws.String(), "u", "a@example.test")
		f(c)
		return sign(k, nil, c)
	}
	cases := map[string]string{
		"nbf in future": mut(func(c meshfake.Claims) { c["nbf"] = now.Add(time.Hour).Unix() }),
		"iat in future": mut(func(c meshfake.Claims) {
			c["iat"] = now.Add(time.Hour).Unix()
			c["exp"] = now.Add(time.Hour + 30*time.Second).Unix()
		}),
		"no iat":         mut(func(c meshfake.Claims) { delete(c, "iat") }),
		"two audiences":  mut(func(c meshfake.Claims) { c["aud"] = []string{"keep", "other"} }),
		"empty email":    mut(func(c meshfake.Claims) { c["email"] = "" }),
		"colon in sub":   mut(func(c meshfake.Claims) { c["sub"] = "a:b" }),
		"empty kid":      sign(k, map[string]any{"alg": "ES256", "kid": ""}, m.Valid(ws.String(), "u", "a@example.test")),
		"DER-length sig": strings.Join(append(strings.Split(sign(k, nil, m.Valid(ws.String(), "u", "a@example.test")), ".")[:2], b64s(strings.Repeat("x", 70))), "."),
	}
	for name, tok := range cases {
		if _, err := verify(v, m, ws, tok); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: got %v, want ErrInvalidContext", name, err)
		}
	}
	// aud as a one-element list is the JWT-legal form and is accepted.
	c := m.Valid(ws.String(), "u", "a@example.test")
	c["aud"] = []string{"keep"}
	if _, err := verify(v, m, ws, sign(k, nil, c)); err != nil {
		t.Fatalf("aud list of one refused: %v", err)
	}
}

func TestVerifyIgnoresUnsuitableKeysAndBadKeySets(t *testing.T) {
	m, v, ws := fixture(t)
	k := m.Key0(0)
	tok := sign(k, nil, m.Valid(ws.String(), "u", "a@example.test"))
	raw := func(entries ...map[string]string) string {
		b, _ := json.Marshal(map[string]any{"keys": entries})
		return string(b)
	}
	for name, body := range map[string]string{
		"RS256 alg":       raw(meshfake.JWK(k, map[string]string{"alg": "RS256"})),
		"P-384 curve":     raw(meshfake.JWK(k, map[string]string{"crv": "P-384"})),
		"enc use":         raw(meshfake.JWK(k, map[string]string{"use": "enc"})),
		"off-curve point": raw(meshfake.JWK(k, map[string]string{"y": b64s(strings.Repeat("\x01", 32))})),
		"short x":         raw(meshfake.JWK(k, map[string]string{"x": b64s("ab")})),
		"duplicate kid":   raw(meshfake.JWK(k, nil), meshfake.JWK(meshfake.NewKey("k1"), nil)),
		"oversize body":   raw(meshfake.JWK(k, nil)) + strings.Repeat(" ", jwksMaxBody),
	} {
		m.Raw = body
		if _, err := verify(NewVerifier(ExtensionID, nil), m, ws, tok); !errors.Is(err, ErrKeysUnavailable) {
			t.Errorf("%s: got %v, want ErrKeysUnavailable", name, err)
		}
	}
	m.Raw = ""
	if _, err := verify(v, m, ws, tok); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

func TestVerifyCacheTTLRetiresKeysAndStaleSetHasACeiling(t *testing.T) {
	m, v, ws := fixture(t)
	now := time.Now()
	v.now = func() time.Time { return now }
	k1, k2 := m.Key0(0), meshfake.NewKey("k2")
	m.Publish(k2)
	tokFor := func(k meshfake.Key) string { return sign(k, nil, claimsAt(m, ws, now)) }
	if _, err := verify(v, m, ws, tokFor(k1)); err != nil {
		t.Fatal(err)
	}
	// Mesh retires k1; until the TTL passes, the cached set still knows it.
	m.Retire("k1")
	if _, err := verify(v, m, ws, tokFor(k1)); err != nil {
		t.Fatalf("cached key refused inside TTL: %v", err)
	}
	now = now.Add(jwksTTL + time.Second)
	if _, err := verify(v, m, ws, tokFor(k1)); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("retired key still accepted after TTL: %v", err)
	}
	if _, err := verify(v, m, ws, tokFor(k2)); err != nil {
		t.Fatalf("current key refused after reload: %v", err)
	}
	// Mesh goes away: the old set verifies for a while, then stops.
	m.Down = true
	now = now.Add(jwksTTL + time.Second)
	if _, err := verify(v, m, ws, tokFor(k2)); err != nil {
		t.Fatalf("stale set refused inside the stale ceiling: %v", err)
	}
	now = now.Add(jwksStaleMax)
	if _, err := verify(v, m, ws, tokFor(k2)); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("stale set used past the ceiling: %v", err)
	}
}

func TestVerifyFailedFetchesAreRateLimitedAndMeshesAreIndependent(t *testing.T) {
	m, v, ws := fixture(t)
	tok := sign(m.Key0(0), nil, m.Valid(ws.String(), "u", "a@example.test"))
	m.Down = true
	for i := 0; i < 5; i++ {
		_, _ = verify(v, m, ws, tok)
	}
	if m.Hits != 1 {
		t.Fatalf("a dead Mesh was contacted %d times in a burst", m.Hits)
	}
	// A slow Mesh must not hold up another one.
	slow := meshfake.New(meshfake.NewKey("k1"))
	defer slow.Close()
	slow.Delay = time.Second
	good := meshfake.New(meshfake.NewKey("k1"))
	defer good.Close()
	go func() {
		_, _ = verify(v, slow, ws, sign(slow.Key0(0), nil, slow.Valid(ws.String(), "u", "a@example.test")))
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if _, err := verify(v, good, ws, sign(good.Key0(0), nil, good.Valid(ws.String(), "u", "a@example.test"))); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("one Mesh's sign-in waited %v behind another's slow key fetch", d)
	}
}

func TestVerifyDefaultClientNeverDialsPrivateOrLoopbackForHTTPS(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close() // an https Mesh_url that resolves to loopback: must be refused at dial
	v := NewVerifier(ExtensionID, nil)
	ws := uuid.New()
	k := meshfake.NewKey("k1")
	c := meshfake.Claims{"iss": srv.URL, "aud": "keep", "sub": "u", "email": "a@example.test", "workspace_id": ws.String(),
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	if _, err := v.Verify(context.Background(), srv.URL, ws, NewContextToken(sign(k, nil, c))); !errors.Is(err, ErrKeysUnavailable) || conns.Load() != 0 {
		t.Fatalf("loopback https key fetch: err=%v connections=%d", err, conns.Load())
	}
	for ip, want := range map[string]bool{"10.1.2.3": true, "192.168.0.1": true, "172.16.0.1": true, "169.254.169.254": true, "100.64.0.1": true,
		"127.0.0.1": true, "::1": true, "0.0.0.0": true, "fe80::1": true, "fc00::1": true, "8.8.8.8": false, "2606:4700::1111": false} {
		if got := blockedAddr(net.ParseIP(ip)); got != want {
			t.Errorf("blockedAddr(%s) = %v, want %v", ip, got, want)
		}
	}
}

// sign signs claims with k under header (ES256 by default), the way Mesh does.
