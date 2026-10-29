// Package meshfake is the Mesh side of context-token federation, written
// independently of Keep's verifier: an ES256 key set served as a JWKS and the
// claims of a valid context token. Signing lives in each test package (the
// descriptor-sign lint rule allows signing only in _test.go files). Tests only.
package meshfake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Key is one signing key of the fake instance.
type Key struct {
	Kid  string
	Priv *ecdsa.PrivateKey
}

// Mesh is a fake Mesh instance.
type Mesh struct {
	Srv *httptest.Server

	mu    sync.Mutex
	keys  []Key
	Hits  int // JWKS requests served
	Down  bool
	Wrong bool          // serve a body that is not a key set
	Raw   string        // when set, served verbatim as the key set
	Delay time.Duration // held before every answer

	pages http.Handler
}

// SetPages makes h answer every path outside /api/ (a browser test serves the
// page that frames the extension screen from the Mesh origin).
func (m *Mesh) SetPages(h http.Handler) {
	m.mu.Lock()
	m.pages = h
	m.mu.Unlock()
}

// Enc is unpadded base64url.
func Enc(b []byte) string { return enc(b) }

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// NewKey makes a P-256 key with the given kid.
func NewKey(kid string) Key {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return Key{Kid: kid, Priv: k}
}

// New starts a fake instance publishing keys.
func New(keys ...Key) *Mesh {
	m := &Mesh{keys: keys}
	m.Srv = httptest.NewServer(http.HandlerFunc(m.serve))
	return m
}

// Close stops the server.
func (m *Mesh) Close() { m.Srv.Close() }

// URL is the instance's public origin.
func (m *Mesh) URL() string { return m.Srv.URL }

// Retire removes a key from the served set (the end of a rotation overlap).
func (m *Mesh) Retire(kid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keep []Key
	for _, k := range m.keys {
		if k.Kid != kid {
			keep = append(keep, k)
		}
	}
	m.keys = keep
}

// JWK renders k as one JWKS entry with the given overrides.
func JWK(k Key, over map[string]string) map[string]string {
	e := map[string]string{"kty": "EC", "crv": "P-256", "kid": k.Kid, "use": "sig", "alg": "ES256",
		"x": enc(k.Priv.X.FillBytes(make([]byte, 32))), "y": enc(k.Priv.Y.FillBytes(make([]byte, 32)))}
	for a, b := range over {
		e[a] = b
	}
	return e
}

// Publish adds a key to the served set (a rotation).
func (m *Mesh) Publish(k Key) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = append(m.keys, k)
}

func (m *Mesh) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	pages := m.pages
	m.mu.Unlock()
	if pages != nil && !strings.HasPrefix(r.URL.Path, "/api/") {
		pages.ServeHTTP(w, r)
		return
	}
	m.mu.Lock()
	m.Hits++
	delay, raw := m.Delay, m.Raw
	m.mu.Unlock()
	time.Sleep(delay)
	m.mu.Lock()
	defer m.mu.Unlock()
	if raw != "" {
		_, _ = w.Write([]byte(raw))
		return
	}
	if r.URL.Path != "/api/v1/.well-known/jwks.json" || m.Down {
		http.Error(w, "x", http.StatusServiceUnavailable)
		return
	}
	if m.Wrong {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"r"}]}`))
		return
	}
	var out []map[string]string
	for _, k := range m.keys {
		xb, yb := k.Priv.X.FillBytes(make([]byte, 32)), k.Priv.Y.FillBytes(make([]byte, 32))
		out = append(out, map[string]string{"kty": "EC", "crv": "P-256", "kid": k.Kid, "use": "sig", "alg": "ES256", "x": enc(xb), "y": enc(yb)})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": out})
}

// Claims are the claims of a context token; zero fields are filled by Sign
// with valid defaults only where noted.
type Claims map[string]any

// Valid returns claims for a good token issued now by m for the workspace.
func (m *Mesh) Valid(workspace, sub, email string) Claims {
	now := time.Now()
	return Claims{"iss": m.URL(), "aud": "keep", "sub": sub, "email": email, "workspace_id": workspace,
		"roles": []string{"admin"}, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(60 * time.Second).Unix()}
}

// Key0 returns the i-th published key.
func (m *Mesh) Key0(i int) Key {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[i]
}
