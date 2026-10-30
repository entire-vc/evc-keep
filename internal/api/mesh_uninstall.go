package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MeshUninstallResult is the response of
// DELETE /orgs/{org_id}/mesh/installations/{workspace_id}: the workspace
// removed and how many sealed versions were erased with it.
type MeshUninstallResult struct {
	WorkspaceID string `json:"workspace_id"`
	Erased      int    `json:"erased"`
	RequestID   string `json:"request_id"`
}

// handleUninstall serves DELETE /orgs/{org_id}/mesh/installations/{workspace_id}:
// an org admin removes a Mesh installation. Every sealed version under the
// workspace (its credentials and its secrets) is crypto-erased and the
// installation, with everything keyed by it, deleted, in one transaction; a
// failure changes nothing. A workspace of another organisation answers
// exactly like one never installed. The attempt is journaled before anything
// changes and every answer waits for its record: a removal or refusal the
// journal does not hold is a 503, never an acknowledgement.
func (m *meshRoutes) handleUninstall(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())

	admin, err := requireOrgAdmin(m.ir, r, p)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	if !admin {
		if m.auditUninstall(r, p, requestID, "", audit.StatusFailed, audit.ErrClassPermissionDenied) != nil {
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "audit journal not reachable", requestID)
			return
		}
		writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "organization admin required", requestID)
		return
	}
	ws, err := uuid.Parse(r.PathValue("workspace_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
		return
	}
	// The pending record names no workspace: the id may be another
	// organisation's, and that must not enter this organisation's journal.
	if m.auditUninstall(r, p, requestID, "", audit.StatusPending, audit.ErrClassNone) != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "audit journal not reachable", requestID)
		return
	}
	erased, err := m.deps.Repo.Uninstall(r.Context(), ws, p.OrgID, func(ctx context.Context, tx pgx.Tx) (int, error) {
		return m.deps.Vault.EraseWorkspace(ctx, tx, p.OrgID.String(), ws.String())
	})
	var (
		status = http.StatusOK
		class  apperr.Class
		msg    string
		reason string
		result = audit.StatusFailed
		ec     audit.ErrorClass
	)
	switch {
	case errors.Is(err, meshext.ErrNotInstalled):
		status, class, msg, ec = http.StatusNotFound, apperr.ClassNotFound, "not found", audit.ErrClassNotFound
	case err != nil:
		status, class, msg, ec = http.StatusInternalServerError, apperr.ClassInternal, "internal error", audit.ErrClassInternal
	default:
		reason, result, ec = "workspace="+ws.String()+" erased="+strconv.Itoa(erased), audit.StatusOK, audit.ErrClassNone
	}
	if m.auditUninstall(r, p, requestID, reason, result, ec) != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "audit journal not reachable", requestID)
		return
	}
	if status != http.StatusOK {
		writeError(w, status, class, msg, requestID)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, MeshUninstallResult{WorkspaceID: ws.String(), Erased: erased, RequestID: requestID})
}

// auditUninstall journals one removal attempt. reason names the workspace and
// the erased count of a removal that happened; a refusal, a failure or the
// pending record names nothing, so a probe of another organisation's
// workspace id is not written into this organisation's journal.
func (m *meshRoutes) auditUninstall(r *http.Request, p identity.Principal, requestID, reason string, status audit.ResultStatus, class audit.ErrorClass) error {
	if m.aud == nil {
		return nil
	}
	_, err := m.aud.Append(r.Context(), audit.Record{
		RequestID: requestID,
		OrgID:     p.OrgID.String(),
		Scope:     p.Scope,
		Actor:     audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI},
		Action:    audit.ActionMeshUninstall,
		Intent:    audit.Intent{Reason: audit.NewReason(reason)},
		Result:    audit.Result{Status: status, ErrorClass: class},
	})
	return err
}
