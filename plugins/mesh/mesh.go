// Package mesh is the Keep rotation plugin for Mesh agent keys. It implements
// rotation.RotationProvider over the Mesh agent-keys API (a second key is
// issued while the old one lives, so Capabilities.DualKey is true):
//
//	POST   /api/v1/agents/{id}/keys            issue
//	GET    /api/v1/agents/{id}/keys            list metadata
//	DELETE /api/v1/agents/{id}/keys/{key_id}   revoke
//
// regenerate-key is never called. Keep's core does not import this module.
//
// The key value from the POST answer goes straight into a secret.Value. No
// response body is logged and no backend error text is forwarded: errors are
// a class from pkg/rotation, the journal carries ids, statuses and lengths.
package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// Kind is the provider type name.
const Kind = "mesh-agent-key"

// ErrConfig is returned by New for an unusable configuration.
var ErrConfig = errors.New("mesh plugin: invalid configuration")

// ErrBadAnswer: Mesh answered with something this client does not accept
// (an unreadable body, an empty or malformed key id, an empty value).
var ErrBadAnswer = errors.New("mesh plugin: unexpected answer from backend")

const (
	maxBody        = 1 << 20
	defaultTimeout = 15 * time.Second
	// primaryKeyID is how Mesh addresses an agent's original key.
	primaryKeyID = "primary"
)

// primaryNamespace is the UUID namespace of PrimaryAlias. It is part of the
// ledger format: changing it orphans every recorded alias, among them those of
// rotations in flight, so a golden test pins it.
var primaryNamespace = uuid.MustParse("ef80de33-2cb0-4dca-a3ac-c90cf2012f14")

// PrimaryAlias is the key id under which this plugin names the Mesh key
// "primary" of agentID: the agent's original key, which Mesh addresses by that
// word rather than by a UUID. Keep's core takes only canonical UUID key ids,
// so the plugin gives that key a stable name-based (v5) UUID of its own, a
// different one for every agent. Current reports it, Check and Revoke turn it
// back into "primary"; Mesh itself never sees it.
func PrimaryAlias(agentID string) string {
	return uuid.NewSHA1(primaryNamespace, []byte(agentID+"/"+primaryKeyID)).String()
}

// meshID is the path segment Mesh knows keyID by: "primary" for the alias,
// the id itself for every other key.
func (p *Provider) meshID(keyID string) string {
	if keyID == p.alias {
		return primaryKeyID
	}
	return keyID
}

// Token is the service token of Keep's Mesh account (right agent_key:rotate).
// Every formatting path renders it as [REDACTED], like secret.Value, so a
// Config printed or logged by a caller does not carry it.
type Token string

// String implements fmt.Stringer.
func (Token) String() string { return secret.Redacted }

// GoString implements fmt.GoStringer.
func (Token) GoString() string { return secret.Redacted }

// MarshalText covers JSON and other encoders that bypass fmt.
func (Token) MarshalText() ([]byte, error) { return []byte(secret.Redacted), nil }

// LogValue implements slog.LogValuer.
func (Token) LogValue() slog.Value { return slog.StringValue(secret.Redacted) }

// TokenSource returns the current service token. An error from it is not
// forwarded: the caller sees rotation.ErrUnavailable.
type TokenSource func(ctx context.Context) (Token, error)

// Config configures a Provider.
type Config struct {
	BaseURL string
	AgentID string // canonical lowercase UUID of the agent
	Token   Token
	// TokenSource, when set, is asked for the token on every call and wins over
	// Token. Keep supplies it from its sealed store; this package never caches it.
	TokenSource TokenSource
	HTTP        *http.Client
	Log         *slog.Logger
}

// Provider is the Mesh agent-key rotation provider for one agent.
type Provider struct {
	base  *url.URL
	agent string
	alias string // PrimaryAlias(agent)
	token Token
	src   TokenSource
	hc    *http.Client
	log   *slog.Logger
}

var _ rotation.RotationProvider = (*Provider)(nil)

// New validates cfg and returns a Provider.
func New(cfg Config) (*Provider, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (cfg.Token == "" && cfg.TokenSource == nil) || !rotation.ValidKeyID(cfg.AgentID) ||
		(u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname()))) {
		return nil, ErrConfig
	}
	hc := &http.Client{Timeout: defaultTimeout}
	if cfg.HTTP != nil {
		c := *cfg.HTTP
		hc = &c
	}
	// The agent-keys API does not redirect. A redirect would carry the bearer
	// token to wherever it points (an https to http hop included): refuse it.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Provider{base: u, agent: cfg.AgentID, alias: PrimaryAlias(cfg.AgentID), token: cfg.Token, src: cfg.TokenSource, hc: hc, log: log}, nil
}

// loopback: plain http is allowed only to the local machine (tests, a sidecar).
func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// String and GoString keep the provider, which holds the token, from printing
// its fields.
func (Provider) String() string   { return "mesh.Provider" }
func (Provider) GoString() string { return "mesh.Provider" }

// Kind implements rotation.RotationProvider.
func (p *Provider) Kind() string { return Kind }

// Capabilities: the old key stays valid until it is revoked.
func (p *Provider) Capabilities() rotation.Capabilities {
	return rotation.Capabilities{DualKey: true}
}

// keyMeta is one item of Mesh's key list: ids and dates, never a key. Mesh
// gives no status field: a key is active until it has a revoked_at.
type keyMeta struct {
	KeyID     string  `json:"id"`
	RevokedAt *string `json:"revoked_at"`
}

// A key is active only while revoked_at is null; any value there, even an
// empty one, is read as revoked (fail closed).
func (k keyMeta) active() bool { return k.RevokedAt == nil }

type issueAnswer struct {
	KeyID string `json:"key_id"`
	Key   string `json:"api_key"`
}

// Issue creates a second key; the old one stays valid.
func (p *Provider) Issue(ctx context.Context, req rotation.IssueRequest) (rotation.Issued, error) {
	// The keys that exist before the call: a key id named by the answer is
	// ended only if it is new, never one Mesh already held.
	before, err := p.list(ctx)
	if err != nil {
		p.journal("issue", "", req.RunID.String(), err)
		return rotation.Issued{}, err
	}
	body, err := p.do(ctx, http.MethodPost, "", http.StatusOK, http.StatusCreated)
	if err != nil {
		p.journal("issue", "", req.RunID.String(), err)
		return rotation.Issued{}, err
	}
	var a issueAnswer
	dec := json.NewDecoder(bytes.NewReader(body))
	derr := dec.Decode(&a)
	// The raw body held the value: drop it, and the decoded string as soon as
	// it is copied into a Value.
	clear(body)
	// An answer naming the alias names the original key: never a new one.
	if derr != nil || !rotation.ValidKeyID(a.KeyID) || a.KeyID == p.alias || a.Key == "" {
		// A well-formed id with no usable value is a key Mesh created and
		// Keep cannot use: end it rather than leave it unaccounted for.
		// The alias never reaches revokeOrphan's DELETE: a list that shows
		// it is refused, and one that does not leaves nothing to end.
		if rotation.ValidKeyID(a.KeyID) {
			p.revokeOrphan(ctx, a.KeyID, before)
		}
		p.journal("issue", "", req.RunID.String(), ErrBadAnswer)
		return rotation.Issued{}, ErrBadAnswer
	}
	v := secret.New([]byte(a.Key))
	a.Key = ""
	p.journal("issue", a.KeyID, req.RunID.String(), nil, slog.Int("length", v.Len()))
	return rotation.Issued{KeyID: a.KeyID, Value: v}, nil
}

// revokeOrphan ends the key an unusable answer named, but only if a fresh list
// shows it as new: absent before the call and present now. An id Mesh already
// held (the answer pointing at the live key) or one it does not list is left
// alone.
func (p *Provider) revokeOrphan(ctx context.Context, keyID string, before []keyMeta) {
	for _, k := range before {
		if k.KeyID == keyID {
			p.journal("revoke", keyID, "", ErrBadAnswer)
			return
		}
	}
	now, err := p.list(ctx)
	if err != nil {
		p.journal("revoke", keyID, "", err)
		return
	}
	for _, k := range now {
		if k.KeyID == keyID {
			_ = p.Revoke(ctx, keyID)
			return
		}
	}
}

func (p *Provider) list(ctx context.Context) ([]keyMeta, error) {
	body, err := p.do(ctx, http.MethodGet, "", http.StatusOK)
	if err != nil {
		return nil, err
	}
	var a struct {
		Keys []keyMeta `json:"keys"`
	}
	if json.Unmarshal(body, &a) != nil {
		return nil, ErrBadAnswer
	}
	for _, k := range a.Keys {
		// Mesh always lists the agent's original key, under the id "primary";
		// every other key id is a canonical UUID. Keep never sees "primary":
		// it names that key by the alias (PrimaryAlias).
		// A Mesh key that carries the alias as its own id would be confused
		// with the original key: refuse the whole answer.
		if (k.KeyID != primaryKeyID && !rotation.ValidKeyID(k.KeyID)) || k.KeyID == p.alias {
			return nil, ErrBadAnswer
		}
	}
	return a.Keys, nil
}

// Check reports whether keyID is an active key of the agent. An invalid id
// is a closed error, never "inactive"; a key Mesh does not list is ErrNotFound.
func (p *Provider) Check(ctx context.Context, keyID string) (rotation.Status, error) {
	if !rotation.ValidKeyID(keyID) {
		return rotation.Status{}, rotation.ErrNotFound
	}
	keys, err := p.list(ctx)
	if err != nil {
		p.journal("check", keyID, "", err)
		return rotation.Status{}, err
	}
	want := p.meshID(keyID)
	for _, k := range keys {
		if k.KeyID == want {
			return rotation.Status{Active: k.active()}, nil
		}
	}
	return rotation.Status{}, rotation.ErrNotFound
}

// Current returns the only active key; none or several: ok=false. The
// original key ("primary"), when it is the only active one, is returned as its
// alias (PrimaryAlias), so a rotation can retire it like any other key.
func (p *Provider) Current(ctx context.Context, _ string) (string, bool, error) {
	keys, err := p.list(ctx)
	if err != nil {
		return "", false, err
	}
	id := ""
	for _, k := range keys {
		if !k.active() {
			continue
		}
		if id != "" {
			return "", false, nil
		}
		id = k.KeyID
		if id == primaryKeyID {
			id = p.alias
		}
	}
	return id, id != "", nil
}

// Revoke ends a key. A key Mesh does not know counts as revoked, but an
// empty or foreign-shaped id is refused before any call, so it can never be
// turned into a different path. A 404 is believed only when a fresh list no
// longer shows the key; a listed key that answers 404 is not revoked.
func (p *Provider) Revoke(ctx context.Context, keyID string) error {
	if !rotation.ValidKeyID(keyID) {
		return rotation.ErrNotFound
	}
	// The path segment is the key id checked above or the constant "primary"
	// for the alias: never anything an answer or a caller spelled.
	_, err := p.do(ctx, http.MethodDelete, "/"+p.meshID(keyID), http.StatusOK, http.StatusNoContent)
	if errors.Is(err, rotation.ErrNotFound) {
		err = nil
		keys, lerr := p.list(ctx)
		switch {
		case lerr != nil:
			err = lerr
		case listed(keys, p.meshID(keyID)):
			err = rotation.ErrUnavailable
		}
	}
	p.journal("revoke", keyID, "", err)
	return err
}

func listed(keys []keyMeta, keyID string) bool {
	for _, k := range keys {
		if k.KeyID == keyID {
			return true
		}
	}
	return false
}

// do performs one call and returns the body of an accepted answer. Any other
// status becomes a class error; the body of such an answer is discarded unread
// beyond the limit and never reaches an error or a log.
func (p *Provider) do(ctx context.Context, method, suffix string, ok ...int) ([]byte, error) {
	u := *p.base
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/agents/" + p.agent + "/keys" + suffix
	r, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, rotation.ErrUnavailable
	}
	tok := p.token
	if p.src != nil {
		var terr error
		if tok, terr = p.src(ctx); terr != nil || tok == "" {
			// The source's error text is not forwarded.
			return nil, rotation.ErrUnavailable
		}
	}
	r.Header.Set("Authorization", "Bearer "+string(tok))
	r.Header.Set("Accept", "application/json")
	resp, err := p.hc.Do(r)
	if err != nil {
		// A transport error text may carry the URL; it is not forwarded.
		return nil, rotation.ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	for _, c := range ok {
		if resp.StatusCode == c {
			if rerr != nil {
				clear(body)
				return nil, rotation.ErrUnavailable
			}
			return body, nil
		}
	}
	clear(body)
	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, rotation.ErrNotFound
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, rotation.ErrDenied
	default:
		return nil, rotation.ErrUnavailable
	}
}

// journal records one operation: ids, run id, outcome class, lengths. The
// attribute set is closed on purpose; nothing from a response is added.
func (p *Provider) journal(op, keyID, runID string, err error, extra ...slog.Attr) {
	attrs := []slog.Attr{slog.String("op", op), slog.String("agent_id", p.agent)}
	if keyID != "" {
		attrs = append(attrs, slog.String("key_id", keyID))
	}
	if runID != "" {
		attrs = append(attrs, slog.String("run_id", runID))
	}
	attrs = append(attrs, extra...)
	if err != nil {
		attrs = append(attrs, slog.String("outcome", class(err)))
		p.log.LogAttrs(context.Background(), slog.LevelWarn, "mesh key "+op, attrs...)
		return
	}
	attrs = append(attrs, slog.String("outcome", "ok"))
	p.log.LogAttrs(context.Background(), slog.LevelInfo, "mesh key "+op, attrs...)
}

func class(err error) string {
	switch {
	case errors.Is(err, rotation.ErrNotFound):
		return "not_found"
	case errors.Is(err, rotation.ErrDenied):
		return "denied"
	case errors.Is(err, rotation.ErrUnavailable):
		return "unavailable"
	case errors.Is(err, ErrBadAnswer):
		return "bad_answer"
	}
	return "error"
}
