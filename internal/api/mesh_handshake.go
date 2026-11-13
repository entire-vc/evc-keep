package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/google/uuid"
)

// MeshPendingResult is the response of POST /orgs/{org_id}/mesh/pending-installs.
type MeshPendingResult struct {
	WorkspaceID string `json:"workspace_id"`
	ExpiresAt   string `json:"expires_at"`
	RequestID   string `json:"request_id"`
}

type meshPendingRequest struct {
	WorkspaceID         string `json:"workspace_id"`
	MeshURL             string `json:"mesh_url"`
	SigningSecretSHA256 string `json:"signing_secret_sha256"`
	// ExtensionID names the extension the window is for. Empty is keep, as
	// before the rotator existed; keep-rotator opens the window of its own.
	ExtensionID string `json:"extension_id"`
}

// handlePendingInstall serves POST /orgs/{org_id}/mesh/pending-installs: an
// org admin opens the window in which Mesh's own install handshake may bind
// the workspace to this organisation. The admin names the secret only by its
// full SHA-256; the secret itself never passes here.
func (m *meshRoutes) handlePendingInstall(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())

	admin, err := requireOrgAdmin(m.ir, r, p)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	if !admin {
		m.auditAction(r, p, requestID, audit.ActionMeshInstallPending, audit.StatusFailed, audit.ErrClassPermissionDenied)
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
		return
	}
	var req meshPendingRequest
	r.Body = http.MaxBytesReader(w, r.Body, meshBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid request body", requestID)
		return
	}
	ws, wsErr := uuid.Parse(req.WorkspaceID)
	rotator := req.ExtensionID == meshext.RotatorExtensionID
	if wsErr != nil || !meshext.ValidMeshURL(req.MeshURL) || !meshSHA256Valid(req.SigningSecretSHA256) ||
		(req.ExtensionID != "" && req.ExtensionID != meshext.ExtensionID && !rotator) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid mesh install window fields", requestID)
		return
	}
	pend := meshext.Pending{Org: p.OrgID, OpenedBy: p.ID, MeshURL: req.MeshURL, SecretSHA256: req.SigningSecretSHA256}
	var expires time.Time
	if rotator {
		expires, err = m.deps.Repo.OpenRotatorPending(r.Context(), ws, pend)
	} else {
		expires, err = m.deps.Repo.OpenPending(r.Context(), ws, pend)
	}
	switch {
	case errors.Is(err, meshext.ErrNoKeepBinding):
		m.auditAction(r, p, requestID, audit.ActionMeshInstallPending, audit.StatusFailed, audit.ErrClassPermissionDenied)
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
		return
	case errors.Is(err, meshext.ErrWorkspaceTaken), errors.Is(err, meshext.ErrWindowTaken):
		m.auditAction(r, p, requestID, audit.ActionMeshInstallPending, audit.StatusFailed, audit.ErrClassPermissionDenied)
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, "workspace already connected", requestID)
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	}
	m.auditAction(r, p, requestID, audit.ActionMeshInstallPending, audit.StatusOK, audit.ErrClassNone)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, MeshPendingResult{WorkspaceID: ws.String(), ExpiresAt: expires.UTC().Format(time.RFC3339), RequestID: requestID})
}

// meshSigSize is the length of an HMAC-SHA256 tag and of a SHA-256 digest.
const meshSigSize = 32

// meshSHA256Valid accepts a full SHA-256 in lowercase hex: 64 characters.
// The 8-hex label Mesh lists for a secret is not accepted.
func meshSHA256Valid(h string) bool {
	if len(h) != 2*meshSigSize {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// meshSecretMatch reports whether signingSecret has the SHA-256 the window
// was opened with. The digest of the secret is computed and compared in the
// zone; a malformed stored digest matches nothing.
func (m *meshRoutes) meshSecretMatch(want, signingSecret string) bool {
	var d [meshSigSize]byte
	if !meshSHA256Valid(want) {
		return false
	}
	// 64 lowercase hex characters always decode into exactly 32 bytes.
	_, _ = hex.Decode(d[:], []byte(want))
	return m.deps.Vault.MatchInstallSecret(signingSecret, d)
}

// takeInstall spends the authenticated handshake budget of ws; exhausted, it
// answers 429.
func (m *meshRoutes) takeInstall(w http.ResponseWriter, ws uuid.UUID, requestID string) bool {
	return m.takeInstallKind(w, ws, requestID, "")
}

// takeInstallKind is takeInstall in the bucket of kind ("" is the shared one).
func (m *meshRoutes) takeInstallKind(w http.ResponseWriter, ws uuid.UUID, requestID string, kind identity.Kind) bool {
	if allowed, wait := m.install.take(bucketKey{id: ws, kind: kind}); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, http.StatusTooManyRequests, apperr.ClassRateLimited, "too many requests; retry later", requestID)
		return false
	}
	return true
}

// handleMeshInstall serves POST /mesh/install. With an Authorization header
// it is the admin's own install (handleInstall, behind authentication);
// without one it is Mesh's install handshake (handleHandshake).
func (m *meshRoutes) handleMeshInstall(bearer, handshake http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header[http.CanonicalHeaderKey("Authorization")]; ok {
			bearer.ServeHTTP(w, r)
			return
		}
		handshake.ServeHTTP(w, r)
	})
}

type meshHandshakeRequest struct {
	ExtensionID   string   `json:"extension_id"`
	WorkspaceID   string   `json:"workspace_id"`
	SigningSecret meshCred `json:"signing_secret"`
}

// handleHandshake is Mesh's install handshake: no bearer, X-Mesh-Timestamp
// and X-Mesh-Signature = hex HMAC-SHA256 of "<timestamp>.<body>" keyed with
// the signing_secret of the body. A workspace already bound answers 200 only
// to the secret it is bound with, and writes nothing. An unbound one is bound
// only inside a live window an org admin opened for this workspace and this
// secret's SHA-256: the secret becomes the events secret, the window is
// spent, and the admin who opened it is the installer. Every other request
// gets the same 401 and writes nothing. Unknown body fields are ignored:
// Mesh is the counterparty and may add one.
func (m *meshRoutes) handleHandshake(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	deny := func() {
		writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, meshBodyLimit))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid request body", requestID)
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
	got, err := hex.DecodeString(r.Header.Get(meshHeaderSig))
	if err != nil || len(got) != meshSigSize {
		deny()
		return
	}
	var req meshHandshakeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		deny()
		return
	}
	rotator := req.ExtensionID == meshext.RotatorExtensionID
	ws, err := uuid.Parse(req.WorkspaceID)
	if err != nil || (req.ExtensionID != meshext.ExtensionID && !rotator) ||
		len(req.SigningSecret) < meshMinSigningSecret || len(req.SigningSecret) > meshMaxSecret {
		deny()
		return
	}
	// The signature is keyed with the secret of the body, so anyone can sign
	// for any workspace: the workspace's own budget is spent only below, once
	// the secret is the bound one or matches an open window.
	kind := identity.Kind("")
	if rotator {
		kind = meshRotatorBucket
	}
	refund, ok := m.preauthTakeKind(w, r, requestID, kind)
	if !ok {
		return
	}
	signingSecret := string(req.SigningSecret)
	if !m.deps.Vault.VerifyInstall(signingSecret, append([]byte(tsRaw+"."), body...), got) {
		deny()
		return
	}

	unlock, err := m.deps.Repo.LockWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	}
	defer unlock()

	org, found, err := m.deps.Repo.Owner(r.Context(), ws)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	}
	if rotator {
		m.handleRotatorHandshake(w, r, ws, org, found, signingSecret, refund, requestID)
		return
	}
	if found {
		spent := false // refund and takeInstall done: the repeat rules must not charge again
		// A store-only binding of the same organisation becomes the
		// extension when that organisation's admin opened a live window for
		// this very secret: the same proof an unbound workspace needs. A
		// window of another organisation, an expired one or a digest that
		// does not match leaves the repeat rules below untouched. The window
		// must name the Mesh the store binding was made for: the token sealed at
		// the store install is then sent only there.
		if pend, live, err := m.deps.Repo.LivePending(r.Context(), ws); err != nil {
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
			return
		} else if live && pend.Org == org && m.meshSecretMatch(pend.SecretSHA256, signingSecret) {
			installer := identity.Principal{OrgID: pend.Org, ID: pend.OpenedBy, Kind: identity.KindUser, Scope: "org:" + pend.Org.String()}
			// The budget is spent before the write, as on the unbound path:
			// a committed upgrade is never answered 429 and left unjournaled.
			refund()
			if !m.takeInstall(w, ws, requestID) {
				return
			}
			spent = true
			err := m.deps.Repo.UpgradeStore(r.Context(), ws, pend, func(ctx context.Context) error {
				// The store keeps signing with its events secret: the extension's is
				// sealed beside it, never over it.
				return m.deps.Vault.Put(ctx, pend.Org.String(), ws.String(), meshKindExtSigning, signingSecret)
			})
			switch {
			case err == nil:
				m.audit(r, installer, requestID, audit.StatusOK, audit.ErrClassNone)
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})
				return
			case errors.Is(err, meshext.ErrNoWindow), errors.Is(err, meshext.ErrNotStore):
				// fall through to the repeat rules
			default:
				m.audit(r, installer, requestID, audit.StatusFailed, audit.ErrClassInternal)
				writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
				return
			}
		}
		// Mesh repeats the handshake on every health check and after a
		// restart, always with the same secret.
		same, err := m.deps.Vault.SameEventsSecret(r.Context(), org.String(), ws.String(), signingSecret)
		if err != nil || !same {
			deny()
			return
		}
		if !spent {
			refund()
			if !m.takeInstall(w, ws, requestID) {
				return
			}
		}
		writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})
		return
	}
	pend, live, err := m.deps.Repo.LivePending(r.Context(), ws)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	}
	if !live || !m.meshSecretMatch(pend.SecretSHA256, signingSecret) {
		deny()
		return
	}
	refund()
	if !m.takeInstall(w, ws, requestID) {
		return
	}
	// The admin who opened the window is the installer of record. The
	// secret is sealed after the transaction that spends the window has
	// deleted it, and before that transaction commits: a window that
	// expired or was replaced since the lookup above gets no write, and a
	// failed write rolls the window and the installation back. A commit that
	// fails after the write leaves a sealed events secret with no
	// installation; nothing reads it, since every reader looks the
	// installation up first, and the next binding replaces it.
	installer := identity.Principal{OrgID: pend.Org, ID: pend.OpenedBy, Kind: identity.KindUser, Scope: "org:" + pend.Org.String()}
	if err := m.deps.Repo.BindPending(r.Context(), ws, pend, meshext.ModeExtension, func(ctx context.Context) error {
		return m.deps.Vault.Put(ctx, pend.Org.String(), ws.String(), meshKindEvents, signingSecret)
	}); err != nil {
		if errors.Is(err, meshext.ErrNoWindow) {
			deny()
			return
		}
		m.audit(r, installer, requestID, audit.StatusFailed, audit.ErrClassInternal)
		writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
		return
	}
	m.audit(r, installer, requestID, audit.StatusOK, audit.ErrClassNone)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})
}

// handleRotatorHandshake serves the install handshake of keep-rotator, after
// the signature checked out and the workspace lock is held. The rotator
// attaches to the keep installation of the workspace: without one, and for a
// window of another organisation, a digest that does not match or an expired
// window, the answer is the uniform 401 and nothing is written. The first
// connect is authorized only by the rotator's own admin window; a repeat only
// by the secret already bound. The keep secrets are never consulted.
func (m *meshRoutes) handleRotatorHandshake(w http.ResponseWriter, r *http.Request, ws, org uuid.UUID, found bool,
	signingSecret string, refund func(), requestID string) {
	deny := func() {
		writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
	}
	if !found {
		deny()
		return
	}
	pend, live, err := m.deps.Repo.LiveRotatorPending(r.Context(), ws)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	}
	spent := false
	if live && pend.Org == org && m.meshSecretMatch(pend.SecretSHA256, signingSecret) {
		installer := identity.Principal{OrgID: pend.Org, ID: pend.OpenedBy, Kind: identity.KindUser, Scope: "org:" + pend.Org.String()}
		refund()
		if !m.takeInstallKind(w, ws, requestID, meshRotatorBucket) {
			return
		}
		spent = true
		err := m.deps.Repo.BindRotator(r.Context(), ws, pend, func(ctx context.Context) error {
			return m.deps.Vault.Put(ctx, pend.Org.String(), ws.String(), meshKindRotator, signingSecret)
		})
		switch {
		case err == nil:
			m.audit(r, installer, requestID, audit.StatusOK, audit.ErrClassNone)
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})
			return
		case errors.Is(err, meshext.ErrNoWindow), errors.Is(err, meshext.ErrNoKeepBinding):
			// fall through to the repeat rule
		default:
			m.audit(r, installer, requestID, audit.StatusFailed, audit.ErrClassInternal)
			writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
			return
		}
	}
	// The binding follows the installation (same row key, cascade), so a
	// bound rotator is always of the installation's organisation.
	_, ok, err := m.deps.Repo.RotatorOwner(r.Context(), ws)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
		return
	}
	if !ok {
		deny()
		return
	}
	same, err := m.deps.Vault.SameRotatorSecret(r.Context(), org.String(), ws.String(), signingSecret)
	if err != nil || !same {
		deny()
		return
	}
	if !spent {
		refund()
		if !m.takeInstallKind(w, ws, requestID, meshRotatorBucket) {
			return
		}
	}
	writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})
}
