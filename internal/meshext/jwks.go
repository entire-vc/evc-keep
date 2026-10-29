package meshext

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// ErrInvalidContext is the one verdict for every context token that does not
// verify: malformed, wrong algorithm, unknown key, bad signature, foreign
// issuer or audience, expired, or too long-lived. It never carries the token
// or any part of it, and callers must not tell the cases apart to a client.
var ErrInvalidContext = errors.New("meshext: invalid context token")

// ErrKeysUnavailable means Mesh's key set could not be fetched. It is not a
// verdict on the token, so callers answer "temporarily unavailable".
var ErrKeysUnavailable = errors.New("meshext: mesh signing keys unavailable")

// ExtensionID is the audience Mesh puts in a context token for Keep: the id in
// mesh-extension.json.
const ExtensionID = "keep"

const (
	jwksPath      = "/api/v1/.well-known/jwks.json"
	jwksTTL       = 5 * time.Minute
	jwksMinReload = 10 * time.Second // floor between fetch attempts, failed ones included
	jwksStaleMax  = time.Hour        // how long an unrefreshable key set may still verify
	jwksMaxBody   = 64 << 10
	maxTokenLen   = 4096
	maxLifetime   = 60 * time.Second
	clockSkew     = 5 * time.Second
)

// ContextToken is a Mesh context token as received. Like a Keep token it is a
// credential: every formatter, logger and encoder prints a placeholder, and
// the text is readable only inside this package.
type ContextToken struct{ p *string }

// NewContextToken wraps the text a caller presented.
func NewContextToken(text string) ContextToken { return ContextToken{p: &text} }

func (t ContextToken) text() string {
	if t.p == nil {
		return ""
	}
	return *t.p
}

const redacted = "[REDACTED]"

func (ContextToken) String() string               { return redacted }
func (ContextToken) GoString() string             { return redacted }
func (ContextToken) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }
func (ContextToken) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (ContextToken) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (ContextToken) LogValue() slog.Value         { return slog.StringValue(redacted) }

// ContextClaims is what a verified context token says about the person.
type ContextClaims struct {
	Subject   string
	Email     string
	Workspace uuid.UUID
	Roles     []string
}

type jwtClaims struct {
	Iss   string   `json:"iss"`
	Aud   audience `json:"aud"`
	Sub   string   `json:"sub"`
	Email string   `json:"email"`
	WS    string   `json:"workspace_id"`
	Roles []string `json:"roles"`
	Exp   *int64   `json:"exp"`
	Iat   *int64   `json:"iat"`
	Nbf   *int64   `json:"nbf"`
}

// audience accepts the JWT forms "x" and ["x"].
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

type keySet struct {
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

// meshState is the key cache of one Mesh. Each has its own lock, so a slow or
// dead Mesh delays only its own sign-ins.
type meshState struct {
	mu          sync.Mutex
	set         *keySet
	lastAttempt time.Time
}

// Verifier checks Mesh context tokens against the key set Mesh publishes. The
// Mesh address always comes from the caller (the install record), never from
// the token: a token can only choose which of that Mesh's keys signs it.
type Verifier struct {
	client   *http.Client // https Mesh: never dials a private or loopback address
	devLocal *http.Client // http loopback Mesh (development), see ValidMeshURL
	aud      string
	now      func() time.Time

	mu    sync.Mutex
	state map[string]*meshState
}

// blockedAddr reports addresses a Mesh key fetch must never reach: this host,
// private ranges, link-local (cloud metadata), CGNAT, multicast, unspecified.
func blockedAddr(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64 {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

func fetchClient(allowLoopback bool) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || (blockedAddr(ip) && (!allowLoopback || !ip.IsLoopback())) {
			return errors.New("meshext: address not allowed")
		}
		return nil
	}}
	return &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{DialContext: d.DialContext, Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// NewVerifier returns a Verifier for tokens addressed to aud. A nil client
// gets the hardened default: no redirect, five seconds, and no connection to
// a private, loopback or link-local address (an installed Mesh_url is chosen
// by an organisation admin and fetched without authentication). Only an http
// Mesh_url, which ValidMeshURL admits for loopback hosts alone, may reach
// loopback, for development.
func NewVerifier(aud string, client *http.Client) *Verifier {
	v := &Verifier{client: client, devLocal: client, aud: aud, now: time.Now, state: map[string]*meshState{}}
	if client == nil {
		v.client, v.devLocal = fetchClient(false), fetchClient(true)
	}
	return v
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// PeekWorkspace reads workspace_id from a token WITHOUT trusting it. It only
// selects which installation's keys to verify with; Verify then requires the
// signed claim to be the same workspace.
func PeekWorkspace(tok ContextToken) (uuid.UUID, bool) {
	raw := tok.text()
	if len(raw) > maxTokenLen {
		return uuid.Nil, false
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return uuid.Nil, false
	}
	pl, err := b64(parts[1])
	if err != nil {
		return uuid.Nil, false
	}
	var c struct {
		WS string `json:"workspace_id"`
	}
	if json.Unmarshal(pl, &c) != nil {
		return uuid.Nil, false
	}
	ws, err := uuid.Parse(c.WS)
	return ws, err == nil
}

// Verify checks tok against meshURL's keys: ES256 only, signature, issuer equal
// to meshURL, audience equal to Keep's extension id, workspace equal to
// workspace, a lifetime of at most 60 seconds, and not expired.
func (v *Verifier) Verify(ctx context.Context, meshURL string, workspace uuid.UUID, tok ContextToken) (ContextClaims, error) {
	raw := tok.text()
	if raw == "" || len(raw) > maxTokenLen {
		return ContextClaims{}, ErrInvalidContext
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ContextClaims{}, ErrInvalidContext
	}
	hb, err1 := b64(parts[0])
	pb, err2 := b64(parts[1])
	sig, err3 := b64(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return ContextClaims{}, ErrInvalidContext
	}
	var head struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hb, &head) != nil || head.Alg != "ES256" || head.Kid == "" || len(head.Kid) > 128 || len(sig) != 64 {
		return ContextClaims{}, ErrInvalidContext
	}
	key, err := v.key(ctx, meshURL, head.Kid)
	if err != nil {
		return ContextClaims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return ContextClaims{}, ErrInvalidContext
	}
	var c jwtClaims
	if json.Unmarshal(pb, &c) != nil || c.Exp == nil || c.Iat == nil {
		return ContextClaims{}, ErrInvalidContext
	}
	now := v.now()
	exp, iat := time.Unix(*c.Exp, 0), time.Unix(*c.Iat, 0)
	if !exp.After(now) || exp.Sub(iat) > maxLifetime || iat.After(now.Add(clockSkew)) ||
		(c.Nbf != nil && time.Unix(*c.Nbf, 0).After(now.Add(clockSkew))) {
		return ContextClaims{}, ErrInvalidContext
	}
	if strings.TrimRight(c.Iss, "/") != strings.TrimRight(meshURL, "/") || len(c.Aud) != 1 || c.Aud[0] != v.aud {
		return ContextClaims{}, ErrInvalidContext
	}
	ws, err := uuid.Parse(c.WS)
	if err != nil || ws != workspace || c.Sub == "" || len(c.Sub) > 128 || strings.ContainsAny(c.Sub, ": \t\r\n") || c.Email == "" || len(c.Email) > 320 {
		return ContextClaims{}, ErrInvalidContext
	}
	return ContextClaims{Subject: c.Sub, Email: c.Email, Workspace: ws, Roles: c.Roles}, nil
}

func (v *Verifier) meshState(base string) *meshState {
	v.mu.Lock()
	defer v.mu.Unlock()
	st := v.state[base]
	if st == nil {
		st = &meshState{}
		v.state[base] = st
	}
	return st
}

// key returns the public key for kid. A set younger than jwksTTL answers from
// cache; an unknown kid (a rotation) or an expired set reloads it, but never
// more often than jwksMinReload, failures counted, so garbage tokens cannot
// turn this into a request amplifier. If Mesh cannot be reached, a set
// younger than jwksStaleMax still verifies the keys it holds: a revoked key
// must not outlive that.
func (v *Verifier) key(ctx context.Context, meshURL, kid string) (*ecdsa.PublicKey, error) {
	base := strings.TrimRight(meshURL, "/")
	st := v.meshState(base)
	st.mu.Lock()
	defer st.mu.Unlock()
	now := v.now()
	fresh := st.set != nil && now.Sub(st.set.fetchedAt) < jwksTTL
	if fresh {
		if k, ok := st.set.keys[kid]; ok {
			return k, nil
		}
	}
	stale := func() (*ecdsa.PublicKey, error) {
		if st.set != nil && now.Sub(st.set.fetchedAt) < jwksStaleMax {
			if k, ok := st.set.keys[kid]; ok {
				return k, nil
			}
		}
		return nil, ErrKeysUnavailable
	}
	if !st.lastAttempt.IsZero() && now.Sub(st.lastAttempt) < jwksMinReload {
		if fresh {
			return nil, ErrInvalidContext
		}
		return stale()
	}
	st.lastAttempt = now
	client := v.client
	if strings.HasPrefix(base, "http://") {
		client = v.devLocal
	}
	set, err := v.fetch(ctx, client, base)
	if err != nil {
		return stale()
	}
	set.fetchedAt = now
	st.set = set
	if k, ok := set.keys[kid]; ok {
		return k, nil
	}
	return nil, ErrInvalidContext
}

func (v *Verifier) fetch(ctx context.Context, client *http.Client, base string) (*keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+jwksPath, nil)
	if err != nil {
		return nil, ErrKeysUnavailable
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrKeysUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrKeysUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBody+1))
	if err != nil || len(body) > jwksMaxBody {
		return nil, ErrKeysUnavailable
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, ErrKeysUnavailable
	}
	set := &keySet{keys: map[string]*ecdsa.PublicKey{}}
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "ES256") {
			continue
		}
		x, ex := b64(k.X)
		y, ey := b64(k.Y)
		if ex != nil || ey != nil {
			continue
		}
		if len(x) != 32 || len(y) != 32 {
			continue
		}
		// Rejects a point that is not on the curve.
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, append(x, y...)...))
		if err != nil {
			continue
		}
		if _, dup := set.keys[k.Kid]; dup {
			return nil, ErrKeysUnavailable // two keys under one kid: ambiguous, trust neither
		}
		set.keys[k.Kid] = pub
	}
	if len(set.keys) == 0 {
		return nil, ErrKeysUnavailable
	}
	return set, nil
}
