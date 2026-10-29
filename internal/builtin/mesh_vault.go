package builtin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Credential kinds the Mesh extension keeps sealed, per Mesh workspace.
const (
	// MeshExtensionToken is the Mesh actor token Keep calls Mesh with.
	MeshExtensionToken = "extension_token"
	// MeshEventsSecret is the secret Mesh signs events to Keep with.
	MeshEventsSecret = "events_secret"
	// MeshKeepSecret is Keep's own secret, handed to Mesh once at install.
	MeshKeepSecret = "keep_secret"
)

var (
	meshWorkspaceRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	errMeshVault    = errors.New("builtin: mesh vault unavailable")
	errMeshRef      = errors.New("builtin: invalid mesh credential reference")

	// meshSecretRefRe is the closed alphabet of a Mesh secret ref: no
	// separator, no leading dot or dash. ".." inside a name is refused too.
	meshSecretRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

	// ErrMeshSecretInvalid is a malformed ref or an empty value.
	ErrMeshSecretInvalid = errors.New("builtin: invalid mesh secret request")
	// ErrMeshSecretNotFound is a ref the workspace never wrote (or whose
	// versions are all disabled): the same answer for another workspace's ref.
	ErrMeshSecretNotFound = errors.New("builtin: mesh secret not found")
)

// MeshSecretMeta describes a stored version without revealing it.
type MeshSecretMeta struct {
	Version     string
	Fingerprint string
	Length      int
}

// meshSecretPath is where a workspace keeps the value of ref. The prefix is
// the workspace's own, and the ref cannot leave it.
func meshSecretPath(workspace, ref string) (string, error) {
	if !meshWorkspaceRe.MatchString(workspace) || !meshSecretRefRe.MatchString(ref) || strings.Contains(ref, "..") {
		return "", ErrMeshSecretInvalid
	}
	return "mesh/" + workspace + "/secrets/" + ref, nil
}

// MeshVault seals the credentials of the Mesh extension in the organisation's
// own store. Values enter as strings from the HTTP layer and leave only as
// a bool (VerifyEvent), except the one secret Generate hands out at install.
type MeshVault struct{ local *Local }

// MeshVault returns the vault over this Local's sealer and pool.
func (l *Local) MeshVault() *MeshVault { return &MeshVault{local: l} }

func meshPath(workspace, kind string) (string, error) {
	if !meshWorkspaceRe.MatchString(workspace) {
		return "", errMeshRef
	}
	switch kind {
	case MeshExtensionToken, MeshEventsSecret, MeshKeepSecret:
		return "mesh/" + workspace + "/" + kind, nil
	}
	return "", errMeshRef
}

// Put seals value as a new version of kind for workspace.
func (m *MeshVault) Put(ctx context.Context, org, workspace, kind, value string) error {
	path, err := meshPath(workspace, kind)
	if err != nil {
		return err
	}
	if value == "" {
		return errMeshRef
	}
	b := []byte(value)
	v := secret.New(b)
	defer v.Wipe()
	if _, err := m.local.Provider(org, "", "", "").Write(ctx, provider.Ref{Path: path}, v); err != nil {
		return errMeshVault
	}
	return nil
}

// PutToken seals token as a new version of the Mesh actor token of workspace,
// replacing the one the gate and the hierarchy mirror read, and returns the
// version label, the HMAC fingerprint and the length: never the value.
func (m *MeshVault) PutToken(ctx context.Context, org, workspace, token string) (MeshSecretMeta, error) {
	path, err := meshPath(workspace, MeshExtensionToken)
	if err != nil || token == "" {
		return MeshSecretMeta{}, errMeshRef
	}
	v := secret.New([]byte(token))
	defer v.Wipe()
	p := m.local.Provider(org, "", "", "")
	fp, err := meshFingerprint(ctx, p, v)
	if err != nil {
		return MeshSecretMeta{}, errMeshVault
	}
	meta, err := p.Write(ctx, provider.Ref{Path: path}, v)
	if err != nil {
		return MeshSecretMeta{}, errMeshVault
	}
	return MeshSecretMeta{Version: meta.Version, Fingerprint: fp, Length: meta.Length}, nil
}

// PutSecret seals value as a new version of ref in workspace's namespace and
// returns the version label, the HMAC fingerprint and the length: never the
// value.
func (m *MeshVault) PutSecret(ctx context.Context, org, workspace, ref, value string) (MeshSecretMeta, error) {
	path, err := meshSecretPath(workspace, ref)
	if err != nil || value == "" {
		return MeshSecretMeta{}, ErrMeshSecretInvalid
	}
	v := secret.New([]byte(value))
	defer v.Wipe()
	p := m.local.Provider(org, "", "", "")
	fp, err := meshFingerprint(ctx, p, v)
	if err != nil {
		return MeshSecretMeta{}, errMeshVault
	}
	meta, err := p.Write(ctx, provider.Ref{Path: path}, v)
	if err != nil {
		return MeshSecretMeta{}, errMeshVault
	}
	return MeshSecretMeta{Version: meta.Version, Fingerprint: fp, Length: meta.Length}, nil
}

// ResolveSecret returns the newest enabled version of ref in workspace's
// namespace as the JSON body {"value","version"} of the resolve answer, and its
// metadata for the journal. It is the one place a value leaves the zone toward
// the API, narrowed to what a workspace wrote itself: only the prefix of the
// workspace asked for is ever read. The caller writes the body and clears it.
func (m *MeshVault) ResolveSecret(ctx context.Context, org, workspace, ref string) ([]byte, MeshSecretMeta, error) {
	path, err := meshSecretPath(workspace, ref)
	if err != nil {
		return nil, MeshSecretMeta{}, err
	}
	p := m.local.Provider(org, "", "", "")
	v, meta, err := p.Resolve(ctx, provider.Ref{Path: path})
	if errors.Is(err, provider.ErrNotFound) || errors.Is(err, provider.ErrDisabled) {
		return nil, MeshSecretMeta{}, ErrMeshSecretNotFound
	}
	if err != nil {
		return nil, MeshSecretMeta{}, errMeshVault
	}
	defer v.Wipe()
	fp, err := meshFingerprint(ctx, p, v)
	if err != nil {
		return nil, MeshSecretMeta{}, errMeshVault
	}
	// 6 bytes per input byte is the worst case (\u00XX), so dst never regrows and
	// leaves a stale copy of the value behind.
	body := make([]byte, 0, 6*v.Len()+64)
	body = append(body, `{"value":`...)
	secret.Expose(v, func(raw []byte) { body = appendJSONString(body, raw) })
	body = append(body, `,"version":`...)
	body = appendJSONString(body, []byte(meta.Version))
	body = append(body, '}')
	return body, MeshSecretMeta{Version: meta.Version, Fingerprint: fp, Length: meta.Length}, nil
}

// appendJSONString appends s as a JSON string literal. It is written out
// instead of calling json.Marshal so that no second, uncleared copy of a value
// is made: the caller owns dst and clears it.
func appendJSONString(dst, s []byte) []byte {
	const hexDigits = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c < 0x20 || c == 0x7f:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		case c < utf8.RuneSelf:
			dst = append(dst, c)
		default:
			r, size := utf8.DecodeRune(s[i:])
			if r == utf8.RuneError && size == 1 {
				dst = append(dst, `\ufffd`...)
			} else {
				dst = append(dst, s[i:i+size]...)
			}
			i += size
			continue
		}
		i++
	}
	return append(dst, '"')
}

func meshFingerprint(ctx context.Context, p *Provider, v secret.Value) (string, error) {
	k, err := p.FingerprintKey(ctx)
	if err != nil {
		return "", err
	}
	defer k.Wipe()
	return fingerprint.Compute(k, v)
}

// Generate seals a fresh random 256-bit secret as kind for workspace and
// returns it once, for the install response. It is never readable again.
func (m *MeshVault) Generate(ctx context.Context, org, workspace, kind string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", errMeshVault
	}
	out := hex.EncodeToString(raw)
	clear(raw)
	if err := m.Put(ctx, org, workspace, kind, out); err != nil {
		return "", err
	}
	return out, nil
}

// VerifyEvent reports whether tag is the HMAC-SHA256 of msg under the events
// secret sealed for workspace. Only that one kind can be verified against, and
// only a bool leaves: no caller outside the zone can obtain a MAC of a message
// it chose, under any credential.
func (m *MeshVault) VerifyEvent(ctx context.Context, org, workspace string, msg, tag []byte) (bool, error) {
	path, err := meshPath(workspace, MeshEventsSecret)
	if err != nil {
		return false, err
	}
	v, _, err := m.local.Provider(org, "", "", "").Resolve(ctx, provider.Ref{Path: path})
	if err != nil {
		return false, errMeshVault
	}
	defer v.Wipe()
	return fingerprint.VerifyMAC(v, msg, tag), nil
}

// VerifyInstall reports whether tag is the HMAC-SHA256 of msg under
// signingSecret, the secret Mesh's install handshake carries in its own body.
// The candidate is not stored; only a bool leaves.
func (m *MeshVault) VerifyInstall(signingSecret string, msg, tag []byte) bool {
	if signingSecret == "" {
		return false
	}
	b := []byte(signingSecret)
	v := secret.New(b)
	clear(b)
	defer v.Wipe()
	return fingerprint.VerifyMAC(v, msg, tag)
}

// MatchInstallSecret reports whether want is the SHA-256 of signingSecret,
// the digest an org admin gave when opening the install window. The digest
// of the candidate is computed and compared in pkg/fingerprint; only a bool
// leaves.
func (m *MeshVault) MatchInstallSecret(signingSecret string, want [32]byte) bool {
	b := []byte(signingSecret)
	v := secret.New(b)
	clear(b)
	defer v.Wipe()
	return fingerprint.MatchSHA256(v, want)
}

// SameEventsSecret reports, in constant time, whether candidate is the events
// secret sealed for workspace: a repeated install handshake is accepted only
// with the secret that is already bound.
func (m *MeshVault) SameEventsSecret(ctx context.Context, org, workspace, candidate string) (bool, error) {
	path, err := meshPath(workspace, MeshEventsSecret)
	if err != nil {
		return false, err
	}
	v, _, err := m.local.Provider(org, "", "", "").Resolve(ctx, provider.Ref{Path: path})
	if err != nil {
		return false, errMeshVault
	}
	defer v.Wipe()
	c := []byte(candidate)
	defer clear(c)
	same := false
	secret.Expose(v, func(b []byte) { same = subtle.ConstantTimeCompare(b, c) == 1 })
	return same, nil
}

// MeshCheckpoint holds the credentials a workspace had before an install
// attempt, so a failed attempt can put them back. The values stay inside the
// zone and are wiped by Wipe.
type MeshCheckpoint struct {
	m     *MeshVault
	org   string
	ws    string
	prior map[string]secret.Value
}

// Checkpoint captures the sealed credentials currently held for workspace.
// A kind that was never stored is simply absent from the checkpoint.
func (m *MeshVault) Checkpoint(ctx context.Context, org, workspace string) (*MeshCheckpoint, error) {
	cp := &MeshCheckpoint{m: m, org: org, ws: workspace, prior: map[string]secret.Value{}}
	for _, kind := range []string{MeshExtensionToken, MeshEventsSecret, MeshKeepSecret} {
		path, err := meshPath(workspace, kind)
		if err != nil {
			cp.Wipe()
			return nil, err
		}
		v, _, err := m.local.Provider(org, "", "", "").Resolve(ctx, provider.Ref{Path: path})
		// A credential that cannot be read back (never stored, disabled, or
		// sealed under a key that no longer opens) has nothing to restore, and
		// must not make the workspace impossible to reinstall.
		if errors.Is(err, provider.ErrNotFound) || errors.Is(err, provider.ErrDisabled) || errors.Is(err, provider.ErrUnavailable) {
			continue
		}
		if err != nil {
			cp.Wipe()
			return nil, errMeshVault
		}
		cp.prior[kind] = v
	}
	return cp, nil
}

// Restore writes the captured credentials back as the newest versions, so the
// previous secrets authenticate again after a failed reinstall. It runs on a
// context detached from the request: the request may be the reason it is needed.
func (c *MeshCheckpoint) Restore(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	var failed bool
	for kind, v := range c.prior {
		path, err := meshPath(c.ws, kind)
		if err != nil {
			failed = true
			continue
		}
		if _, err := c.m.local.Provider(c.org, "", "", "").Write(ctx, provider.Ref{Path: path}, v); err != nil {
			failed = true
		}
	}
	if failed {
		return errMeshVault
	}
	return nil
}

// Wipe zeroes the captured values.
func (c *MeshCheckpoint) Wipe() {
	for _, v := range c.prior {
		v.Wipe()
	}
	clear(c.prior)
}

// MeshFetched is the answer of FetchHierarchy.
type MeshFetched struct {
	NotModified bool
	ETag        string
	Body        []byte
}

// MeshFetchError names a failed fetch by a closed class and nothing else: not
// the URL, the status text, the response body or the token.
type MeshFetchError struct{ class string }

func (e *MeshFetchError) Error() string { return "builtin: mesh fetch failed: " + e.class }

// Class is one of unauthorized, not_found, server, network, too_large,
// unavailable, bad_status.
func (e *MeshFetchError) Class() string { return e.class }

const meshFetchLimit = 16 << 20

// meshFetchClient builds the client for one fetch. The token goes in the
// Authorization header: a redirect would carry it to whatever host answers, so
// none is followed, and no proxy from the environment is used. For https the
// dialer refuses every address that is not public (checked after name
// resolution, so a rebinding name cannot reach an internal host); plain http,
// for local development, dials loopback addresses only, whatever the name
// resolves to.
func meshFetchClient(scheme string) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	allowed := loopbackDialAddress
	if scheme == "https" {
		allowed = publicDialAddress
	}
	d.Control = func(_, address string, _ syscall.RawConn) error {
		if !allowed(address) {
			return errMeshAddress
		}
		return nil
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DialContext: d.DialContext, TLSHandshakeTimeout: 10 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// notPublic lists the ranges that IsGlobalUnicast, IsPrivate and IsLoopback do
// not cover but that still reach internal hosts or are reserved: shared space
// (RFC 6598), benchmarking, IETF protocol and documentation blocks, reserved
// 240/4, and the IPv6 forms that embed an IPv4 address (NAT64, 6to4, Teredo,
// IPv4-compatible).
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func dialIP(address string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// loopbackDialAddress reports whether a host:port about to be dialled is loopback.
func loopbackDialAddress(address string) bool {
	ip, ok := dialIP(address)
	return ok && ip.IsLoopback()
}

// publicDialAddress reports whether a host:port that is about to be dialled is
// a public unicast address.
func publicDialAddress(address string) bool {
	ip, ok := dialIP(address)
	if !ok || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

var errMeshAddress = errors.New("builtin: mesh address not public")

// ExtensionToken returns the sealed Mesh actor token of workspace as text for
// one request header, unsealed anew on every call so that a token a later
// install or rotation sealed is the one used next. The caller must not keep,
// log or format it. Every failure is the same opaque error: it names neither
// the value nor the vault path.
func (m *MeshVault) ExtensionToken(ctx context.Context, org, workspace string) (string, error) {
	path, err := meshPath(workspace, MeshExtensionToken)
	if err != nil {
		return "", errMeshVault
	}
	v, _, err := m.local.Provider(org, "", "", "").Resolve(ctx, provider.Ref{Path: path})
	if err != nil {
		return "", errMeshVault
	}
	defer v.Wipe()
	var tok string
	secret.Expose(v, func(b []byte) { tok = string(b) })
	if tok == "" {
		return "", errMeshVault
	}
	return tok, nil
}

// FetchHierarchy reads the workspace hierarchy from Mesh at meshURL with the
// sealed actor token of workspace. The token is unsealed here, sent as a
// Bearer and wiped; only the response (hierarchy metadata, no values) leaves.
// etag, when set, is sent as If-None-Match.
func (m *MeshVault) FetchHierarchy(ctx context.Context, org, workspace, meshURL, etag string) (MeshFetched, error) {
	path, err := meshPath(workspace, MeshExtensionToken)
	if err != nil {
		return MeshFetched{}, err
	}
	u, err := url.Parse(strings.TrimRight(meshURL, "/") + "/api/v1/workspaces/" + workspace + "/export/hierarchy")
	if err != nil || u.Host == "" {
		return MeshFetched{}, &MeshFetchError{class: "unavailable"}
	}
	v, _, err := m.local.Provider(org, "", "", "").Resolve(ctx, provider.Ref{Path: path})
	if err != nil {
		return MeshFetched{}, &MeshFetchError{class: "unavailable"}
	}
	defer v.Wipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return MeshFetched{}, &MeshFetchError{class: "unavailable"}
	}
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", `"`+etag+`"`)
	}
	secret.Expose(v, func(b []byte) { req.Header.Set("Authorization", "Bearer "+string(b)) })
	client := meshFetchClient(u.Scheme)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	req.Header.Del("Authorization")
	if err != nil {
		// A transport error names the URL; keep only the class.
		return MeshFetched{}, &MeshFetchError{class: "network"}
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return MeshFetched{NotModified: true, ETag: etag}, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return MeshFetched{}, &MeshFetchError{class: "unauthorized"}
	case resp.StatusCode == http.StatusNotFound:
		return MeshFetched{}, &MeshFetchError{class: "not_found"}
	case resp.StatusCode >= 500:
		return MeshFetched{}, &MeshFetchError{class: "server"}
	case resp.StatusCode != http.StatusOK:
		return MeshFetched{}, &MeshFetchError{class: "bad_status"}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, meshFetchLimit+1))
	if err != nil {
		return MeshFetched{}, &MeshFetchError{class: "network"}
	}
	if len(body) > meshFetchLimit {
		return MeshFetched{}, &MeshFetchError{class: "too_large"}
	}
	return MeshFetched{ETag: resp.Header.Get("ETag"), Body: body}, nil
}
