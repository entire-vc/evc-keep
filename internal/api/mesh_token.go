package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/google/uuid"
)

type meshTokenRequest struct {
	ExtensionID    string   `json:"extension_id"`
	WorkspaceID    string   `json:"workspace_id"`
	ExtensionToken meshCred `json:"extension_token"`
}

// handleToken serves POST /mesh/token: Mesh hands Keep the extension actor
// token of a connected workspace, after the install handshake and on every
// rotation, so the token never passes through a person. No bearer:
// X-Mesh-Timestamp and X-Mesh-Signature = hex HMAC-SHA256 of
// "<timestamp>.<body>" keyed with the events secret already bound to the
// workspace, never with anything the body carries. The token is sealed as a
// new version of the workspace's extension_token, which the gate and the
// hierarchy mirror read on their next call. A delivery signed no later than
// the last accepted one is refused, so a replay cannot put back a token Mesh
// rotated away. Every refusal, an oversized body and a throttled delivery
// included, is the same 401 and writes no token. The one other answer is the
// pre-authentication limit's 429: its bucket is keyed on the client address
// alone and spent before the body is read, so it says nothing of the
// workspace or the signature; a signed delivery gets its token back. The workspace's budget is
// spent only once the signature holds, and a throttled delivery is not
// journaled. The fields are checked only once the signature holds, so every
// other signed refusal is journaled, and one the journal does not hold gets
// 503. Unknown body fields are ignored: Mesh is the
// counterparty and may add one.
func (m *meshRoutes) handleToken(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	refund, ok := m.preauthTake(w, r, requestID)
	if !ok {
		return
	}
	deny := func() {
		writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, meshBodyLimit))
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
	var req meshTokenRequest
	if err := json.Unmarshal(body, &req); err != nil {
		deny()
		return
	}
	ws, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		deny()
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
	if err != nil || !valid {
		// A vault failure answers like a bad signature: it must not reveal
		// that the workspace is connected.
		deny()
		return
	}
	refund()
	// The workspace's budget is spent only by a signed delivery: a caller
	// who knows the workspace id but not its key cannot hold off Mesh's
	// token rotation by burning the budget with bad signatures.
	if allowed, _ := m.install.take(bucketKey{id: ws}); !allowed {
		deny()
		return
	}
	// Signed by the workspace's key from here on: a refusal is journaled, and
	// one the journal does not hold is not answered.
	refuse := func(class audit.ErrorClass) {
		if err := m.auditSecret(r, org, ws, audit.ActionMeshToken, "", MeshSecretMeta{}, audit.StatusFailed, class); err != nil {
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
			return
		}
		deny()
	}
	if req.ExtensionID != meshext.ExtensionID || len(req.ExtensionToken) == 0 || len(req.ExtensionToken) > meshMaxTokenLen {
		refuse(audit.ErrClassInvalidArgument)
		return
	}

	var meta MeshSecretMeta
	err = m.deps.Repo.AcceptToken(r.Context(), ws, org, secs, func(ctx context.Context) error {
		var perr error
		meta, perr = m.deps.Vault.PutToken(ctx, org.String(), ws.String(), string(req.ExtensionToken))
		return perr
	})
	switch {
	case errors.Is(err, meshext.ErrStaleToken):
		refuse(audit.ErrClassPermissionDenied)
		return
	case err != nil:
		_ = m.auditSecret(r, org, ws, audit.ActionMeshToken, "", MeshSecretMeta{}, audit.StatusFailed, audit.ErrClassInternal)
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
		return
	}
	// The token is sealed; a delivery the journal does not hold is still not
	// acknowledged, so Mesh delivers again with a new timestamp.
	if err := m.auditSecret(r, org, ws, audit.ActionMeshToken, "", meta, audit.StatusOK, audit.ErrClassNone); err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "secret storage not reachable", requestID)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})
}
