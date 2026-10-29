package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// Rotation modes of POST .../rotate. The body carries the mode and nothing
// else: a value never travels to the server through an agent (invariant I5).
const (
	rotateGenerate   = "generate"
	rotateHumanInput = "human_input"
)

// RotationService is the durable rotation boundary: it starts a run and
// reports on it, and no value, key or ciphertext crosses it.
// *rotation.Service implements it.
type RotationService interface {
	Start(context.Context, rotation.Ref, rotation.Origin) (rotation.Started, error)
	Report(context.Context, rotation.Ref, uuid.UUID) (rotation.RunReport, error)
}

// RotateCarrier is one carrier's row of a rotation status.
type RotateCarrier struct {
	CarrierID string `json:"carrier_id"`
	Phase     string `json:"phase"`
	State     string `json:"state"`
}

// RotateApproval is the approval a prod rotation waits for: the id and status
// of the approval request and the console link a human decides it at.
type RotateApproval struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	URL    string `json:"url"`
}

// RotateResult is the §4.3 rotate result row with the per-carrier progress of
// the two-phase run. A run in progress is ok=false with neither error_class
// nor a version; a failed run names its class and never a version: the new
// version is not active.
type RotateResult struct {
	OK          bool            `json:"ok"`
	RequestID   string          `json:"request_id"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Version     string          `json:"version,omitempty"`
	ErrorClass  string          `json:"error_class,omitempty"`
	Carriers    []RotateCarrier `json:"carriers,omitempty"`
	Approval    *RotateApproval `json:"approval,omitempty"`
}

type rotateRoutes struct {
	sec       *secretRoutes
	svc       RotationService
	input     InputService
	publicURL string
}

func (ro *rotateRoutes) approval(a *rotation.ApprovalRef) *RotateApproval {
	if a == nil {
		return nil
	}
	return &RotateApproval{ID: a.ID.String(), Status: a.Status, URL: ro.publicURL + "/console/approvals/" + a.ID.String()}
}

func rotateMessage(reason string) string { return "rotation " + reason }

// authorize resolves the secret of the path and the caller's rotate right on
// it. A secret the caller cannot rotate is not found.
func (ro *rotateRoutes) authorize(w http.ResponseWriter, r *http.Request) (rotation.Ref, tenancy.SecretRef, bool) {
	rid := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())
	id, err := uuid.Parse(r.PathValue("secret_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "secret_id is not a valid id", rid)
		return rotation.Ref{}, tenancy.SecretRef{}, false
	}
	tc := contextFromRequest(r, p)
	found, err := ro.sec.cat.Meta(r.Context(), p.OrgID, id, reachableScopes(tc))
	if err != nil {
		writeAppError(w, err, rid)
		return rotation.Ref{}, tenancy.SecretRef{}, false
	}
	perms, err := catalog.PermissionsAt(r.Context(), ro.sec.ir, tc, found.Scope)
	if err != nil {
		writeAppError(w, err, rid)
		return rotation.Ref{}, tenancy.SecretRef{}, false
	}
	if !perms[identity.PermRotate] || (p.Scope != "" && p.Scope != found.Scope.String()) {
		writeAppError(w, catalog.NotFoundByID(id), rid)
		return rotation.Ref{}, tenancy.SecretRef{}, false
	}
	return rotation.Ref{OrgID: p.OrgID, SecretID: id}, found, true
}

func (ro *rotateRoutes) start(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	var body struct {
		Mode string `json:"mode"`
	}
	if decodeInput(w, r, 1024, &body) != nil || (body.Mode != rotateGenerate && body.Mode != rotateHumanInput) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, rotateMessage("request invalid"), rid)
		return
	}
	ref, found, ok := ro.authorize(w, r)
	if !ok {
		return
	}
	if body.Mode == rotateHumanInput {
		// The intake link ends in a new version of the same secret, so for a
		// prod secret it would be a rotation that skips the approval gate.
		if found.Class == rotation.ClassProd {
			writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, rotateMessage("a prod secret rotates through an approval; human_input is not available"), rid)
			return
		}
		ro.issueInput(w, r, ref)
		return
	}
	if ro.svc == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, rotateMessage("service unavailable"), rid)
		return
	}
	p, _ := identity.FromContext(r.Context())
	actor := audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI}
	if p.SponsorUserID != nil {
		actor.SponsorID = p.SponsorUserID.String()
	}
	started, err := ro.svc.Start(r.Context(), ref, rotation.Origin{Actor: actor, Scope: found.Scope.String(), Name: found.Name, Class: found.Class})
	switch {
	case errors.Is(err, rotation.ErrConflict):
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, rotateMessage("already running for this secret"), rid)
		return
	case errors.Is(err, rotation.ErrRevokePending):
		writeAppError(w, rotationAppError(err), rid)
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, rotateMessage("service unavailable"), rid)
		return
	}
	writeJSON(w, http.StatusAccepted, RotateResult{RequestID: started.RunID.String(), Approval: ro.approval(started.Approval)})
}

// issueInput answers mode human_input: the same one-time link request_secret_input
// issues, for a human to enter the new value in a browser.
func (ro *rotateRoutes) issueInput(w http.ResponseWriter, r *http.Request, ref rotation.Ref) {
	rid := reqid.FromContext(r.Context())
	if ro.input == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, rotateMessage("input service unavailable"), rid)
		return
	}
	p, _ := identity.FromContext(r.Context())
	tc := contextFromRequest(r, p)
	secret, err := ro.sec.cat.Meta(r.Context(), ref.OrgID, ref.SecretID, reachableScopes(tc))
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	st, err := ro.sec.cat.GetStore(r.Context(), ref.OrgID, secret.StoreID)
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	actor := audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI}
	if p.SponsorUserID != nil {
		actor.SponsorID = p.SponsorUserID.String()
	}
	link, err := ro.input.IssueRotation(r.Context(), secret, st, actor, 0)
	if err != nil {
		inputError(w, r, err)
		return
	}
	inputHeaders(w)
	writeJSON(w, http.StatusAccepted, link)
}

func (ro *rotateRoutes) status(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	ref, _, ok := ro.authorize(w, r)
	if !ok {
		return
	}
	run, err := uuid.Parse(r.PathValue("request_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, rotateMessage("request unavailable"), rid)
		return
	}
	if ro.svc == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, rotateMessage("service unavailable"), rid)
		return
	}
	rep, err := ro.svc.Report(r.Context(), ref, run)
	switch {
	case errors.Is(err, rotation.ErrNotFound):
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, rotateMessage("request unavailable"), rid)
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, rotateMessage("service unavailable"), rid)
		return
	}
	out := RotateResult{OK: rep.Done, RequestID: run.String(), Approval: ro.approval(rep.Approval)}
	if rep.Done {
		out.Version, out.Fingerprint = rep.Version, rep.Fingerprint
	}
	if rep.Failed {
		out.ErrorClass = rotateClass(rep.Class)
	}
	for _, c := range rep.Carriers {
		out.Carriers = append(out.Carriers, RotateCarrier{CarrierID: c.CarrierID, Phase: c.Phase, State: c.State})
	}
	code := http.StatusAccepted
	if rep.Done || rep.Failed {
		code = http.StatusOK
	}
	writeJSON(w, code, out)
}

// rotateClass keeps a failure class only if the engine's closed list has it.
func rotateClass(c rotation.Class) string {
	for _, k := range []rotation.Class{rotation.ClassNoCarriers, rotation.ClassDeployFailed, rotation.ClassFingerprintMismatch,
		rotation.ClassUnhealthy, rotation.ClassVerifyFailed, rotation.ClassRevokeFailed, rotation.ClassPrepareFailed, rotation.ClassInternalError, rotation.ClassPolicyDenied, rotation.ClassSuperseded} {
		if k == c {
			return string(c)
		}
	}
	return string(apperr.ClassInternal)
}
