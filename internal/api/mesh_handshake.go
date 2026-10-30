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
	if wsErr != nil || !meshext.ValidMeshURL(req.MeshURL) || !meshSHA256Valid(req.SigningSecretSHA256) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid mesh install window fields", requestID)
		return
	}
	expires, err := m.deps.Repo.OpenPending(r.Context(), ws, meshext.Pending{
		Org: p.OrgID, OpenedBy: p.ID, MeshURL: req.MeshURL, SecretSHA256: req.SigningSecretSHA256})
	switch {
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
	if allowed, wait := m.install.take(bucketKey{id: ws}); !allowed {
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
	ws, err := uuid.Parse(req.WorkspaceID)
	if err != nil || req.ExtensionID != meshext.ExtensionID ||
		len(req.SigningSecret) < meshMinSigningSecret || len(req.SigningSecret) > meshMaxSecret {
		deny()
		return
	}
	// The signature is keyed with the secret of the body, so anyone can sign
	// for any workspace: the workspace's own budget is spent only below, once
	// the secret is the bound one or matches an open window.
	refund, ok := m.preauthTake(w, r, requestID)
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
	if found {
		// Mesh repeats the handshake on every health check and after a
		// restart, always with the same secret.
		same, err := m.deps.Vault.SameEventsSecret(r.Context(), org.String(), ws.String(), signingSecret)
		if err != nil || !same {
			deny()
			return
		}
		refund()
		if !m.takeInstall(w, ws, requestID) {
			return
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
