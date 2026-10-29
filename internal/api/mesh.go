package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/google/uuid"
)

// MeshVault seals the credentials of the Mesh extension; the concrete type
// lives in the plaintext zone (internal/builtin) and is wired in
// cmd/keep-server. Values go in as strings and come out only as a verdict,
// except the one secret Generate returns at install.
type MeshVault interface {
	Put(ctx context.Context, org, workspace, kind, value string) error
	Generate(ctx context.Context, org, workspace, kind string) (string, error)
	VerifyEvent(ctx context.Context, org, workspace string, msg, tag []byte) (bool, error)
	// VerifyInstall checks Mesh's install handshake against the signing
	// secret the handshake itself carries; SameEventsSecret compares a
	// candidate with the bound events secret in constant time. Both answer
	// only a verdict.
	VerifyInstall(signingSecret string, msg, tag []byte) bool
	SameEventsSecret(ctx context.Context, org, workspace, candidate string) (bool, error)
	// MatchInstallSecret compares the SHA-256 of the handshake's signing
	// secret with the one the admin gave for the window, in the zone.
	MatchInstallSecret(signingSecret string, want [32]byte) bool
	Checkpoint(ctx context.Context, org, workspace string) (MeshCheckpoint, error)
	// PutSecret seals value as a new version of ref in the workspace's own
	// namespace; only metadata comes back.
	PutSecret(ctx context.Context, org, workspace, ref, value string) (MeshSecretMeta, error)
	// PutToken seals the Mesh actor token of the workspace as a new version
	// (POST /mesh/token); only metadata comes back.
	PutToken(ctx context.Context, org, workspace, token string) (MeshSecretMeta, error)
	// ResolveSecret returns the JSON body of the resolve answer (the one place
	// a value goes toward the API; the caller writes it and clears it) and the
	// metadata for the journal. A ref the workspace never wrote is
	// ErrMeshSecretNotFound, a malformed one ErrMeshSecretInvalid.
	ResolveSecret(ctx context.Context, org, workspace, ref string) ([]byte, MeshSecretMeta, error)
}

// MeshSecretMeta describes a stored version without revealing it.
type MeshSecretMeta struct {
	Version     string
	Fingerprint string
	Length      int
}

// Errors a MeshVault returns for the two refusals the API answers by name;
// anything else is "storage unavailable".
var (
	ErrMeshSecretInvalid  = errors.New("api: invalid mesh secret request")
	ErrMeshSecretNotFound = errors.New("api: mesh secret not found")
)

// MeshCheckpoint is the set of credentials a workspace held before an install
// attempt. Restore puts them back; Wipe releases them.
type MeshCheckpoint interface {
	Restore(ctx context.Context) error
	Wipe()
}

// Credential kinds, mirrored from internal/builtin (api must not import it).
const (
	meshKindToken      = "extension_token"
	meshKindEvents     = "events_secret"
	meshKindKeepSecret = "keep_secret" // #nosec G101 -- vault slot name, not a value
)

// MeshDeps wires the optional Mesh extension. A nil *MeshDeps in [Deps] means
// the extension is off: its routes are not registered at all, and the rest of
// Keep behaves identically.
type MeshDeps struct {
	Vault MeshVault
	Repo  *meshext.Repo
	// Federation turns a Mesh context token into a console session; nil
	// leaves POST /mesh/session unregistered.
	Federation *meshext.Federation
	// KeyLevels backs the key-level page of the Mesh screen; nil hides it. When
	// it also implements KeyLevelChanger an organization admin can change the level.
	KeyLevels KeyLevelService
	// Gates applies task.gate.decided answers of confirmation cards. Nil: the
	// event is recorded and acknowledged like any other, and decides nothing.
	Gates MeshGates
	// ResolveLimit bounds POST .../resolve per workspace; the zero value is
	// 600 a minute with a burst of 100.
	ResolveLimit CatalogLimit
	// PreauthLimit bounds, per client address, the Mesh calls that are not
	// yet authenticated (events, signed secrets calls, the install handshake,
	// the session sign-in); a call that authenticates gets its token back.
	// The zero value is 120 a minute with a burst of 30.
	PreauthLimit CatalogLimit
	// TrustedProxies are the reverse proxies whose X-Forwarded-For names the
	// client (KEEP_TRUSTED_PROXIES). Empty: the peer is the client, so behind
	// a proxy every caller shares one budget.
	TrustedProxies []netip.Prefix
}

// MeshGates is the confirmation backend (internal/meshgate) as the events
// route sees it.
type MeshGates interface {
	Handle(ctx context.Context, org, workspace uuid.UUID, d meshgate.Decided, eventID string) (meshgate.Outcome, error)
}

// meshHeaderDelivery names one send of an event; its retries repeat it.
const meshHeaderDelivery = "X-Mesh-Delivery"

const (
	meshBodyLimit   = 64 << 10
	meshMaxSkew     = 5 * time.Minute
	meshSigPrefix   = "v1="
	meshHeaderWS    = "X-Mesh-Workspace"
	meshHeaderEvent = "X-Mesh-Event"
	meshHeaderTS    = "X-Mesh-Timestamp"
	meshHeaderSig   = "X-Mesh-Signature"
	meshHeaderNonce = "X-Mesh-Nonce"
	meshMinSecret   = 16
	// meshMinSigningSecret is the shortest signing secret a Mesh install
	// handshake may carry; Mesh generates 64 hex characters.
	meshMinSigningSecret = 32
	meshMaxSecret        = 512
	meshMaxTokenLen      = 4096
	meshGateDecided      = "task.gate.decided"
	// meshMaxSecretValue is the longest value a workspace may store.
	meshMaxSecretValue = 32 << 10
	// meshSecretSigTag separates the signed message of the secrets API from
	// an event's "<timestamp>.<body>", so one signature cannot serve both.
	meshSecretSigTag = "keep-mesh-secret-v1"
)

// Default budget of resolve per workspace: Mesh resolves synchronously on use.
const (
	defaultResolvePerMinute = 600
	defaultResolveBurst     = 100
	defaultPreauthPerMinute = 120
	defaultPreauthBurst     = 30
)

// MeshInstallResult is the response of POST /mesh/install. KeepSecret is
// Keep's own secret for this workspace, shown exactly once here — the same
// one-time disclosure rule as an issued token — and never readable again.
type MeshInstallResult struct {
	OK         bool   `json:"ok"`
	RequestID  string `json:"request_id"`
	KeepSecret string `json:"keep_secret"`
}

type meshInstallRequest struct {
	MeshURL              string   `json:"mesh_url"`
	WorkspaceID          string   `json:"workspace_id"`
	ExtensionToken       meshCred `json:"extension_token"`
	EventsEndpointSecret meshCred `json:"events_endpoint_secret"`
}

// meshCred is a credential received in the install body. Every formatter,
// logger and encoder prints a placeholder, so logging the request by mistake
// cannot expose it; only an explicit string conversion reads it.
type meshCred string

const meshCredMask = "[REDACTED]"

func (meshCred) String() string               { return meshCredMask }
func (meshCred) GoString() string             { return meshCredMask }
func (meshCred) LogValue() slog.Value         { return slog.StringValue(meshCredMask) }
func (meshCred) MarshalJSON() ([]byte, error) { return []byte(`"` + meshCredMask + `"`), nil }
func (meshCred) MarshalText() ([]byte, error) { return []byte(meshCredMask), nil }
func (c meshCred) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, meshCredMask) }

type meshRoutes struct {
	ir      *identity.Repo
	aud     audit.Journaler
	deps    MeshDeps
	now     func() time.Time
	resolve *limiter
	// install bounds the Mesh install handshake per workspace, with the
	// budget of resolve; it is spent only once the handshake authenticated.
	install *limiter
	// preauth bounds unauthenticated Mesh calls per client address.
	preauth      *limiter
	logger       *slog.Logger
	warnLoopOnce sync.Once
}

// preauthTake spends a token of the caller's address before any database,
// vault or Mesh work. A workspace never selects the bucket: whoever knows a
// workspace id cannot spend its budget. Exhausted: 429 and false. The returned
// refund is called once the caller authenticated, so legitimate traffic
// spends nothing; taking first keeps a parallel burst of bad calls from all
// passing a check before the first one is charged.
func (m *meshRoutes) preauthTake(w http.ResponseWriter, r *http.Request, requestID string) (refund func(), ok bool) {
	if len(m.deps.TrustedProxies) == 0 {
		if p := peerAddr(r.RemoteAddr); p.IsLoopback() {
			m.warnLoopOnce.Do(func() {
				// A loopback peer is a local reverse proxy: without
				// KEEP_TRUSTED_PROXIES every client shares its one budget.
				m.logger.Warn("mesh pre-authentication limit keyed on a loopback peer; set KEEP_TRUSTED_PROXIES")
			})
		}
	}
	k := addrKey(clientAddr(r, m.deps.TrustedProxies))
	allowed, wait := m.preauth.take(k)
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, http.StatusTooManyRequests, apperr.ClassRateLimited, "too many requests; retry later", requestID)
		return nil, false
	}
	return func() { m.preauth.refund(k) }, true
}

func (m *meshRoutes) audit(r *http.Request, p identity.Principal, requestID string, status audit.ResultStatus, class audit.ErrorClass) {
	m.auditAction(r, p, requestID, audit.ActionMeshInstall, status, class)
}

func (m *meshRoutes) auditAction(r *http.Request, p identity.Principal, requestID string, action audit.Action, status audit.ResultStatus, class audit.ErrorClass) {
	if m.aud == nil {
		return
	}
	_, _ = m.aud.Append(r.Context(), audit.Record{
		RequestID: requestID,
		OrgID:     p.OrgID.String(),
		Scope:     p.Scope,
		Actor:     audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI},
		Action:    action,
		Result:    audit.Result{Status: status, ErrorClass: class},
	})
}

// handleInstall serves POST /mesh/install: an org admin connects a Mesh
// workspace. The Mesh actor token and Mesh's events secret are sealed; Keep's
// own secret is generated, sealed and returned once.
func (m *meshRoutes) handleInstall(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())

	admin, err := requireOrgAdmin(m.ir, r, p)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	if !admin {
		m.audit(r, p, requestID, audit.StatusFailed, audit.ErrClassPermissionDenied)
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
		return
	}

	var req meshInstallRequest
	r.Body = http.MaxBytesReader(w, r.Body, meshBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid request body", requestID)
		return
	}
	ws, wsErr := uuid.Parse(req.WorkspaceID)
	if wsErr != nil || !meshext.ValidMeshURL(req.MeshURL) ||
		req.ExtensionToken == "" || len(req.ExtensionToken) > meshMaxTokenLen ||
		len(req.EventsEndpointSecret) < meshMinSecret || len(req.EventsEndpointSecret) > meshMaxSecret {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid mesh install fields", requestID)
		return
	}

	org := p.OrgID.String()
	wss := ws.String()

	// One install per workspace at a time: the checkpoint, the credential
	// writes, the generated secret and the row form one sequence, and an
	// interleaving would return a secret that is no longer the stored one.
	unlock, err := m.deps.Repo.LockWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	}
	defer unlock()

	if owner, found, err := m.deps.Repo.Owner(r.Context(), ws); err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	} else if found && owner != p.OrgID {
		m.audit(r, p, requestID, audit.StatusFailed, audit.ErrClassPermissionDenied)
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, "workspace already connected", requestID)
		return
	}

	// A reinstall replaces live credentials before the installation row is
	// written. On any failure the previous ones are put back, so a 500 never
	// leaves Mesh's old secret rejected and an undisclosed new one active.
	cp, err := m.deps.Vault.Checkpoint(r.Context(), org, wss)
	if err != nil {
		m.audit(r, p, requestID, audit.StatusFailed, audit.ErrClassInternal)
		writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
		return
	}
	defer cp.Wipe()

	generated := ""
	err = m.deps.Vault.Put(r.Context(), org, wss, meshKindToken, string(req.ExtensionToken))
	if err == nil {
		err = m.deps.Vault.Put(r.Context(), org, wss, meshKindEvents, string(req.EventsEndpointSecret))
	}
	if err == nil {
		generated, err = m.deps.Vault.Generate(r.Context(), org, wss, meshKindKeepSecret)
	}
	if err == nil {
		err = m.deps.Repo.Upsert(r.Context(), p.OrgID, ws, p.ID, req.MeshURL)
	}
	if err != nil {
		_ = cp.Restore(r.Context())
		if errors.Is(err, meshext.ErrWorkspaceTaken) {
			m.audit(r, p, requestID, audit.StatusFailed, audit.ErrClassPermissionDenied)
			writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, "workspace already connected", requestID)
			return
		}
		m.audit(r, p, requestID, audit.StatusFailed, audit.ErrClassInternal)
		writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
		return
	}
	keepSecret := generated
	m.audit(r, p, requestID, audit.StatusOK, audit.ErrClassNone)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, MeshInstallResult{OK: true, RequestID: requestID, KeepSecret: keepSecret})
}

// handleEvents serves POST /mesh/events. There is no bearer token: the
// request is authenticated only by an HMAC-SHA256 over "<timestamp>.<body>"
// keyed with the events secret Mesh gave at install. Every failure to
// authenticate (unknown workspace, stale timestamp, bad or missing signature)
// answers the same 401, so the response is no oracle on which workspaces are
// connected. An event id is recorded once; a repeat is acknowledged and has
// no further effect. A new event is applied to Keep's mirror of the Mesh
// hierarchy in the same transaction that records it.
func (m *meshRoutes) handleEvents(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	deny := func() {
		writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, meshBodyLimit))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid request body", requestID)
		return
	}
	// Mesh names the workspace only in the body; the header is Keep's own
	// form. Either selects the secret, and the signature covers the body, so
	// a workspace taken from it is checked before anything is trusted.
	wsRaw := r.Header.Get(meshHeaderWS)
	if wsRaw == "" {
		var peek struct {
			WorkspaceID string `json:"workspace_id"`
		}
		_ = json.Unmarshal(body, &peek)
		wsRaw = peek.WorkspaceID
	}
	ws, err := uuid.Parse(wsRaw)
	if err != nil {
		deny()
		return
	}
	tsRaw := r.Header.Get(meshHeaderTS)
	secs, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		deny()
		return
	}
	if d := m.now().Sub(time.Unix(secs, 0)); d > meshMaxSkew || d < -meshMaxSkew {
		deny()
		return
	}
	got, ok := meshEventSig(r.Header.Get(meshHeaderSig))
	if !ok {
		deny()
		return
	}
	refund, ok := m.preauthTake(w, r, requestID)
	if !ok {
		return
	}
	org, found, err := m.deps.Repo.Owner(r.Context(), ws)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	}
	if !found {
		deny()
		return
	}
	valid, err := m.deps.Vault.VerifyEvent(r.Context(), org.String(), ws.String(), append([]byte(tsRaw+"."), body...), got)
	if err != nil {
		// Indistinguishable from a bad signature: a vault failure must not
		// reveal that the workspace is connected.
		deny()
		return
	}
	if !valid {
		deny()
		return
	}
	refund()

	ev, err := meshext.ParseEvent(body, ws, m.now(), r.Header.Get(meshHeaderEvent), r.Header.Get(meshHeaderDelivery))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid event", requestID)
		return
	}
	inserted, err := m.deps.Repo.Accept(r.Context(), ws, ev)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	}
	if inserted && ev.Type == meshGateDecided && m.deps.Gates != nil {
		// Every well-formed signed answer is acknowledged, a refused one too:
		// a refusal never improves on retry, and a non-2xx would make Mesh
		// mark this connection degraded. Only "could not apply" is retried,
		// and then the event is forgotten so the retry is not dropped as a repeat.
		if _, herr := m.deps.Gates.Handle(r.Context(), org, ws, meshgate.Decided{TaskID: ev.TaskID, Decision: ev.Decision,
			DecidedBy: ev.DecidedBy, DecidedByType: ev.DecidedByType, ExternalHash: ev.ExternalHash}, ev.ID); herr != nil {
			// The request context may be the very reason the apply failed
			// (timeout, disconnect): forgetting on it would fail silently and
			// the retry would be dropped as a repeat.
			fctx, stop := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			_ = m.deps.Repo.Forget(fctx, ws, ev.ID)
			stop()
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
			return
		}
	}
	writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})
}

// meshEventSig reads the X-Mesh-Signature of an event: the lowercase hex of
// the MAC, bare as Mesh sends it to extensions or after one "v1=" as Keep first
// documented it. Both carry the same MAC over "<timestamp>.<body>", so the
// prefix is only a label and accepting either downgrades nothing. Anything
// else (another length, upper case, a second prefix, spaces) is refused.
func meshEventSig(h string) ([]byte, bool) {
	h = strings.TrimPrefix(h, meshSigPrefix)
	if len(h) != 2*meshSigSize {
		return nil, false
	}
	for i := 0; i < len(h); i++ {
		if c := h[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, false
		}
	}
	// Cannot fail: 64 lowercase hex characters were checked above.
	got, _ := hex.DecodeString(h)
	return got, true
}

// MeshSessionResult is the response of POST /mesh/session. The session itself
// travels only as an HttpOnly cookie.
type MeshSessionResult struct {
	OK        bool   `json:"ok"`
	RequestID string `json:"request_id"`
}

// handleSession serves POST /mesh/session: the Keep screen inside Mesh's
// iframe posts the short-lived context token it was opened with and gets a
// console session. Mesh vouches for the person; every refusal is the same 401.
func (m *meshRoutes) handleSession(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	// A session cookie is set here, so a foreign page must not be able to log
	// a visitor in as someone else (login CSRF): the Keep screen in Mesh's
	// iframe posts to its own origin, as JSON, which a cross-site form cannot.
	if !sameOrigin(r) || !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "request refused", requestID)
		return
	}
	var req struct {
		Ctx meshCred `json:"ctx"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Ctx == "" {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid request body", requestID)
		return
	}
	refund, ok := m.preauthTake(w, r, requestID)
	if !ok {
		return
	}
	handle, _, err := m.deps.Federation.SignIn(r.Context(), meshext.NewContextToken(string(req.Ctx)))
	if err == nil {
		refund()
	}
	switch {
	case errors.Is(err, meshext.ErrInvalidContext):
		writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "service temporarily unavailable", requestID)
		return
	}
	// SameSite=None: the screen runs in a cross-site iframe, where Strict or
	// Lax cookies are not sent. The route is served over TLS only.
	//nolint:gosec // G124: HttpOnly and Secure are set; None is required for the Mesh iframe
	http.SetCookie(w, &http.Cookie{Name: consoleCookie, Value: handle, Path: consolePath, HttpOnly: true, Secure: true,
		SameSite: http.SameSiteNoneMode, MaxAge: int(identity.SessionTTL / time.Second)})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, MeshSessionResult{OK: true, RequestID: requestID})
}

// MeshSecretPutResult is the response of PUT /orgs/{org}/mesh/secrets/{ref}:
// the version just written and its fingerprint, never the value.
type MeshSecretPutResult struct {
	Ref         string `json:"ref"`
	Version     string `json:"version"`
	Fingerprint string `json:"fingerprint"`
}

type meshSecretRequest struct {
	Value meshCred `json:"value"`
}

// meshRefValid mirrors the closed alphabet the vault enforces, so a bad ref is
// refused before any storage call and never reaches a journal field.
func meshRefValid(ref string) bool {
	if ref == "" || len(ref) > 128 || strings.Contains(ref, "..") {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// meshNonceValid accepts 16 to 64 characters of base64url or hex without
// padding; anything else is refused before a signature is looked at.
func meshNonceValid(n string) bool {
	if len(n) < 16 || len(n) > 64 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// secretActor authenticates the Mesh side of the secrets API. There is no
// bearer: the request is signed with the events secret Mesh gave at install,
// HMAC-SHA256 over the tag, the timestamp, a single-use nonce, the method, the request path and the
// sha256 of the body, so a signature binds one request and cannot be turned
// into an event. A user token is not read at all. Every failure to
// authenticate is the same 401. On success it returns the workspace and the
// organisation that owns its installation; the organisation in the path must
// be that one (403 otherwise). Only a call whose signature holds has an actor
// to record, so it is journaled and answered once its record is written; an
// unauthenticated call (the 401s) is not journaled: there is no verified
// workspace to attribute it to, and an open write path would let anyone fill
// the journal.
func (m *meshRoutes) secretActor(w http.ResponseWriter, r *http.Request, requestID string, action audit.Action, body []byte) (ws, org uuid.UUID, ok bool) {
	deny := func() (uuid.UUID, uuid.UUID, bool) {
		writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
		return uuid.Nil, uuid.Nil, false
	}
	ws, err := uuid.Parse(r.Header.Get(meshHeaderWS))
	if err != nil {
		return deny()
	}
	tsRaw := r.Header.Get(meshHeaderTS)
	secs, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return deny()
	}
	if d := m.now().Sub(time.Unix(secs, 0)); d > meshMaxSkew || d < -meshMaxSkew {
		return deny()
	}
	nonce := r.Header.Get(meshHeaderNonce)
	if !meshNonceValid(nonce) {
		return deny()
	}
	sig, hasPrefix := strings.CutPrefix(r.Header.Get(meshHeaderSig), meshSigPrefix)
	got, derr := hex.DecodeString(sig)
	if !hasPrefix || derr != nil {
		return deny()
	}
	refund, ok := m.preauthTake(w, r, requestID)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	owner, found, err := m.deps.Repo.Owner(r.Context(), ws)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return uuid.Nil, uuid.Nil, false
	}
	if !found {
		return deny()
	}
	path, _, _ := strings.Cut(r.RequestURI, "?")
	msg := []byte(meshSecretSigTag + "\n" + tsRaw + "\n" + nonce + "\n" + r.Method + "\n" + path + "\n" + meshBodyDigest(body))
	valid, err := m.deps.Vault.VerifyEvent(r.Context(), owner.String(), ws.String(), msg, got)
	if err != nil || !valid {
		return deny()
	}
	// The nonce is spent only after the signature holds, so unsigned traffic
	// never writes. A repeat is refused exactly like a bad signature; a store
	// failure refuses the request too and nothing is served.
	// The signature held, so the caller is a known workspace: a store failure
	// or a replay is an authenticated refusal and is journaled, nameless. The
	// replay still answers exactly like a bad signature.
	fresh, err := m.deps.Repo.UseNonce(r.Context(), ws, nonce)
	if err != nil {
		_ = m.auditSecret(r, owner, ws, action, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassInternal)
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return uuid.Nil, uuid.Nil, false
	}
	if !fresh {
		if err := m.auditSecret(r, owner, ws, action, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPermissionDenied); err != nil {
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
			return uuid.Nil, uuid.Nil, false
		}
		return deny()
	}
	// Only a fresh nonce gets the token back: a replayed signed call stays
	// on the caller's budget.
	refund()
	if pathOrg, perr := uuid.Parse(r.PathValue("org_id")); perr != nil || pathOrg != owner {
		if err := m.auditSecret(r, owner, ws, action, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPermissionDenied); err != nil {
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
			return uuid.Nil, uuid.Nil, false
		}
		writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "request refused", requestID)
		return uuid.Nil, uuid.Nil, false
	}
	return ws, owner, true
}

// auditSecret journals one Mesh secrets call: the workspace as a service actor
// reaching Keep through the plugin, the ref, the version, the fingerprint and
// the length; never the value. The error is returned so a success path can
// refuse to answer without its record.
func (m *meshRoutes) auditSecret(r *http.Request, org, ws uuid.UUID, action audit.Action, ref string, meta MeshSecretMeta, status audit.ResultStatus, class audit.ErrorClass) error {
	if m.aud == nil {
		return nil
	}
	_, err := m.aud.Append(r.Context(), audit.Record{
		RequestID: reqid.FromContext(r.Context()),
		OrgID:     org.String(),
		Scope:     "org:" + org.String(),
		Actor:     audit.Actor{Type: audit.ActorService, ID: ws.String(), Via: audit.ViaMeshPlugin},
		Action:    action,
		Secret:    audit.SecretRef{Name: ref, Version: meta.Version},
		Result:    audit.Result{Status: status, Fingerprint: meta.Fingerprint, Length: meta.Length, ErrorClass: class},
	})
	return err
}

// secretFailure answers and journals a refusal or failure of a secrets call.
// The refusal is answered only once its record is written: a call the journal
// does not hold gets a 503, never an acknowledgement.
func (m *meshRoutes) secretFailure(w http.ResponseWriter, r *http.Request, org, ws uuid.UUID, action audit.Action, ref string, err error) {
	requestID := reqid.FromContext(r.Context())
	var (
		status int
		class  apperr.Class
		msg    string
		name   = ref
		ec     audit.ErrorClass
	)
	switch {
	case errors.Is(err, ErrMeshSecretInvalid):
		status, class, msg, name, ec = http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid secret request", "", audit.ErrClassInvalidArgument
	case errors.Is(err, ErrMeshSecretNotFound):
		status, class, msg, ec = http.StatusNotFound, apperr.ClassNotFound, "not found", audit.ErrClassNotFound
	default:
		status, class, msg, ec = http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", audit.ErrClassInternal
	}
	if aerr := m.auditSecret(r, org, ws, action, name, MeshSecretMeta{}, audit.StatusFailed, ec); aerr != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
		return
	}
	writeError(w, status, class, msg, requestID)
}

// handlePutSecret serves PUT /orgs/{org_id}/mesh/secrets/{ref}: a Mesh
// workspace stores the value of one of its own settings as a new version. The
// value is never returned, logged or journaled.
func (m *meshRoutes) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, meshBodyLimit))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid request body", requestID)
		return
	}
	defer clear(body)
	ws, org, ok := m.secretActor(w, r, requestID, audit.ActionMeshSecretPut, body)
	if !ok {
		return
	}
	ref := r.PathValue("ref")
	var req meshSecretRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF || req.Value == "" || len(req.Value) > meshMaxSecretValue || !meshRefValid(ref) {
		m.secretFailure(w, r, org, ws, audit.ActionMeshSecretPut, "", ErrMeshSecretInvalid)
		return
	}
	// The attempt is journaled before anything is stored, so a version never
	// exists without a record: if the final record cannot be written, the
	// pending one remains and shows a write whose outcome was not recorded.
	if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretPut, ref, MeshSecretMeta{}, audit.StatusPending, audit.ErrClassNone); err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
		return
	}
	meta, err := m.deps.Vault.PutSecret(r.Context(), org.String(), ws.String(), ref, string(req.Value))
	if err != nil {
		m.secretFailure(w, r, org, ws, audit.ActionMeshSecretPut, ref, err)
		return
	}
	if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretPut, ref, meta, audit.StatusOK, audit.ErrClassNone); err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, MeshSecretPutResult{Ref: ref, Version: meta.Version, Fingerprint: meta.Fingerprint})
}

// handleResolveSecret serves POST /orgs/{org_id}/mesh/secrets/{ref}/resolve:
// a Mesh workspace reads back a value of its own namespace. It is the one
// deliberate exception to "a value goes only to a runner" (threat model §4),
// narrowed to the prefix the workspace wrote itself. POST and no-store so a
// cache never holds it; the call is journaled before the value is released, and
// there is no answer without the record.
func (m *meshRoutes) handleResolveSecret(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid request body", requestID)
		return
	}
	ws, org, ok := m.secretActor(w, r, requestID, audit.ActionMeshSecretResolve, body)
	if !ok {
		return
	}
	// The body was part of the signature; resolve takes none, so a signed one
	// is still not a valid request.
	if len(body) != 0 {
		m.secretFailure(w, r, org, ws, audit.ActionMeshSecretResolve, "", ErrMeshSecretInvalid)
		return
	}
	if allowed, wait := m.resolve.take(bucketKey{org: org, id: ws}); !allowed {
		// An authenticated call is journaled even when it is throttled; the
		// ref is not yet validated, so the record carries no name.
		if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretResolve, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassPolicyDenied); err != nil {
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
			return
		}
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, http.StatusTooManyRequests, apperr.ClassRateLimited, "too many requests; retry later", requestID)
		return
	}
	ref := r.PathValue("ref")
	if !meshRefValid(ref) {
		m.secretFailure(w, r, org, ws, audit.ActionMeshSecretResolve, "", ErrMeshSecretInvalid)
		return
	}
	out, meta, err := m.deps.Vault.ResolveSecret(r.Context(), org.String(), ws.String(), ref)
	defer clear(out)
	if err != nil {
		m.secretFailure(w, r, org, ws, audit.ActionMeshSecretResolve, ref, err)
		return
	}
	if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretResolve, ref, meta, audit.StatusOK, audit.ErrClassNone); err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}
