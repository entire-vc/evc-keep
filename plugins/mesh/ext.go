package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// This file rotates the service account when it is an extension actor of Mesh
// (token ext_…, capability ext_token:self_rotate). The account has no agent
// keys; its own token is replaced through two routes, authenticated by the
// token itself (the actor is never named in a path):
//
//	GET    /api/v1/ext/me                 probe the caller's token
//	POST   /api/v1/ext/me/token/rotate    issue the next token; the caller's
//	                                      token stays valid for grace_seconds
//	DELETE /api/v1/ext/me/token/previous  end the previous token (call it with
//	                                      the current one; the previous one gets 409)
//
// ExtSelf implements SelfRotator, so RotateSelf drives it unchanged: Issue is the
// POST, Verify is a probe with the new token, Revoke of the replaced token is
// the DELETE. Mesh gives tokens no ids; the key ids here are local labels so the
// sink and the hook have something to name.

const (
	defaultGrace = 300
	maxGrace     = 3600
	extPrefix    = "ext_"
)

// ExtConfig configures ExtSelf.
type ExtConfig struct {
	BaseURL string
	// AccountID is the actor id of the service account (a canonical UUID); it
	// is only reported in hook events and the journal.
	AccountID string
	// TokenSource returns the current token on every call; required.
	TokenSource TokenSource
	// GraceSeconds is how long the replaced token keeps working (0: Mesh's
	// default of 300; at most 3600).
	GraceSeconds int
	HTTP         *http.Client
	Log          *slog.Logger
}

// ExtSelf is the SelfRotator of an extension-actor service account.
type ExtSelf struct {
	base    *url.URL
	account string
	src     TokenSource
	grace   int
	hc      *http.Client
	log     *slog.Logger

	mu      sync.Mutex
	pending map[string]Token // key label -> new token, from Issue until Verify succeeds or it is revoked
	issued  map[string]bool  // labels Issue handed out: new tokens, which Revoke never ends at Mesh
}

var _ SelfRotator = (*ExtSelf)(nil)

// NewExtSelf validates cfg: https (or loopback http), a UUID account, a token
// source and a grace within Mesh's limit.
func NewExtSelf(cfg ExtConfig) (*ExtSelf, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || cfg.TokenSource == nil || !rotation.ValidKeyID(cfg.AccountID) ||
		cfg.GraceSeconds < 0 || cfg.GraceSeconds > maxGrace ||
		(u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname()))) {
		return nil, ErrConfig
	}
	hc := &http.Client{Timeout: defaultTimeout}
	if cfg.HTTP != nil {
		c := *cfg.HTTP
		hc = &c
	}
	// A redirect would carry the bearer token elsewhere: refuse it.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &ExtSelf{base: u, account: cfg.AccountID, src: cfg.TokenSource, grace: cfg.GraceSeconds,
		hc: hc, log: log, pending: map[string]Token{}, issued: map[string]bool{}}, nil
}

// String and GoString keep the value from printing its fields.
func (*ExtSelf) String() string   { return "mesh.ExtSelf" }
func (*ExtSelf) GoString() string { return "mesh.ExtSelf" }

// Account implements SelfRotator.
func (e *ExtSelf) Account() string { return e.account }

// AbandonKeepsNew implements SelfRotator: the replaced token expires after the
// grace window and Mesh cannot issue the new one a second time.
func (e *ExtSelf) AbandonKeepsNew() bool { return true }

// PerCallToken implements SelfRotator: the source is mandatory.
func (e *ExtSelf) PerCallToken() bool { return e.src != nil }

// Current probes the caller's token. There is exactly one current token, so a
// working probe is "one active key"; its label is local.
func (e *ExtSelf) Current(ctx context.Context, _ string) (string, bool, error) {
	if _, err := e.do(ctx, http.MethodGet, "/me", "", nil, http.StatusOK); err != nil {
		e.journal("current", "", err)
		return "", false, err
	}
	return uuid.NewString(), true, nil
}

// errSent marks a POST whose outcome at Mesh is unknown: the request may have
// been executed although no usable answer came back.
var errSent = errors.New("mesh ext: request sent, outcome unknown")

// Forget drops the held copy of a token Issue handed out, without any call to
// Mesh: the value is lost for good, nothing is revoked or discarded.
func (e *ExtSelf) Forget(keyID string) {
	e.mu.Lock()
	delete(e.pending, keyID)
	e.mu.Unlock()
}

type extAnswer struct {
	Token  string `json:"extension_token"`
	Length int    `json:"token_length"`
}

// Issue asks Mesh for the next token. The old one keeps working for the grace
// window; the new one is held (as a redacted Token) until Verify or Revoke.
func (e *ExtSelf) Issue(ctx context.Context, req rotation.IssueRequest) (rotation.Issued, error) {
	var body []byte
	if e.grace > 0 {
		body = []byte(`{"grace_seconds":` + strconv.Itoa(e.grace) + `}`)
	}
	raw, err := e.do(ctx, http.MethodPost, "/me/token/rotate", "application/json", body, http.StatusOK)
	if err != nil {
		if errors.Is(err, errSent) {
			// Mesh may have replaced the token and the new one never reached
			// us: the old one dies after the grace window.
			err = errors.Join(ErrOrphaned, err)
		}
		e.journal("issue", "", err, slog.String("run_id", req.RunID.String()))
		return rotation.Issued{}, err
	}
	var a extAnswer
	derr := json.NewDecoder(bytes.NewReader(raw)).Decode(&a)
	clear(raw)
	if derr != nil || !strings.HasPrefix(a.Token, extPrefix) || (a.Length != 0 && a.Length != len(a.Token)) {
		a.Token = ""
		// The POST succeeded, so the token was replaced and its value is lost.
		err = errors.Join(ErrOrphaned, ErrBadAnswer)
		e.journal("issue", "", err, slog.String("run_id", req.RunID.String()))
		return rotation.Issued{}, err
	}
	id := uuid.NewString()
	v := secret.New([]byte(a.Token))
	e.mu.Lock()
	e.pending[id] = Token(a.Token)
	e.issued[id] = true
	e.mu.Unlock()
	a.Token = ""
	e.journal("issue", id, nil, slog.String("run_id", req.RunID.String()), slog.Int("length", v.Len()))
	return rotation.Issued{KeyID: id, Value: v}, nil
}

// Verify probes with the new token while it is pending, afterwards with the
// source's current token (after Activate that is the new one). Mesh tokens have
// no ids, so an id this process did not issue is probed with the current token:
// RevokeOld's "new key is active" check is only as strong as that probe.
func (e *ExtSelf) Verify(ctx context.Context, keyID string) (rotation.Status, error) {
	if !rotation.ValidKeyID(keyID) {
		return rotation.Status{}, rotation.ErrNotFound
	}
	e.mu.Lock()
	tok, ok := e.pending[keyID]
	e.mu.Unlock()
	var err error
	if ok {
		_, err = e.doWith(ctx, tok, http.MethodGet, "/me", "", nil, http.StatusOK)
	} else {
		_, err = e.do(ctx, http.MethodGet, "/me", "", nil, http.StatusOK)
	}
	e.journal("verify", keyID, err)
	if errors.Is(err, rotation.ErrDenied) {
		return rotation.Status{Active: false}, nil
	}
	if err != nil {
		return rotation.Status{}, err
	}
	if ok {
		e.mu.Lock()
		delete(e.pending, keyID)
		e.mu.Unlock()
	}
	return rotation.Status{Active: true}, nil
}

// Revoke: a label Issue handed out is a new token. Mesh has no route that ends
// a freshly issued token (the next rotation replaces it), so abandoning one only
// drops the held value and sends nothing: a DELETE here would end the token
// still in use. Any other id is the token being replaced: it is ended by the
// previous-token route, authenticated by the current token.
func (e *ExtSelf) Revoke(ctx context.Context, keyID string) error {
	if !rotation.ValidKeyID(keyID) {
		return rotation.ErrNotFound
	}
	e.mu.Lock()
	fresh := e.issued[keyID]
	delete(e.pending, keyID)
	e.mu.Unlock()
	if fresh {
		e.journal("abandon", keyID, nil)
		return nil
	}
	_, err := e.do(ctx, http.MethodDelete, "/me/token/previous", "", nil, http.StatusNoContent, http.StatusOK)
	e.journal("revoke", keyID, err)
	return err
}

func (e *ExtSelf) do(ctx context.Context, method, suffix, ctype string, body []byte, ok ...int) ([]byte, error) {
	tok, err := e.src(ctx)
	if err != nil || tok == "" {
		// The source's error text is not forwarded.
		return nil, rotation.ErrUnavailable
	}
	return e.doWith(ctx, tok, method, suffix, ctype, body, ok...)
}

func (e *ExtSelf) doWith(ctx context.Context, tok Token, method, suffix, ctype string, body []byte, ok ...int) ([]byte, error) {
	u := *e.base
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/ext" + suffix
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, rotation.ErrUnavailable
	}
	r.Header.Set("Authorization", "Bearer "+string(tok))
	r.Header.Set("Accept", "application/json")
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	resp, err := e.hc.Do(r)
	if err != nil {
		// A transport error text may carry the URL; it is not forwarded.
		return nil, unknownIf(method, rotation.ErrUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	out, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	for _, c := range ok {
		if resp.StatusCode == c {
			if rerr != nil {
				clear(out)
				return nil, unknownIf(method, rotation.ErrUnavailable)
			}
			return out, nil
		}
	}
	clear(out)
	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, rotation.ErrNotFound
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, rotation.ErrDenied
	default: // 409 (the previous token called DELETE) and the rest
		if resp.StatusCode >= 500 {
			return nil, unknownIf(method, rotation.ErrUnavailable)
		}
		return nil, rotation.ErrUnavailable
	}
}

// unknownIf marks a failed POST as possibly executed.
func unknownIf(method string, err error) error {
	if method == http.MethodPost {
		return errors.Join(err, errSent)
	}
	return err
}

// journal records ids, outcome class and lengths; nothing from a response.
func (e *ExtSelf) journal(op, keyID string, err error, extra ...slog.Attr) {
	attrs := []slog.Attr{slog.String("op", op), slog.String("account", e.account)}
	if keyID != "" {
		attrs = append(attrs, slog.String("key_id", keyID))
	}
	attrs = append(attrs, extra...)
	if err != nil {
		attrs = append(attrs, slog.String("outcome", class(err)))
		e.log.LogAttrs(context.Background(), slog.LevelWarn, "mesh ext token "+op, attrs...)
		return
	}
	attrs = append(attrs, slog.String("outcome", "ok"))
	e.log.LogAttrs(context.Background(), slog.LevelInfo, "mesh ext token "+op, attrs...)
}
