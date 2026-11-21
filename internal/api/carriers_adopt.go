package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

type CarrierAdoptionService interface {
	SubmitAdopt(context.Context, deployment.AdoptRequest) (deployment.Outcome, error)
	AdoptionReport(context.Context, uuid.UUID, string) (deployment.Report, error)
}

// CarrierAdoptionResult contains references and closed states only. An
// attestation is not a deployment and never reports consumer health or an
// observed fingerprint, including when a scalar does not match.
type CarrierAdoptionResult struct {
	OK         bool            `json:"ok"`
	RequestID  string          `json:"request_id"`
	Status     string          `json:"status"`
	VersionID  string          `json:"version_id"`
	JobID      string          `json:"job_id,omitempty"`
	ErrorClass string          `json:"error_class,omitempty"`
	Approval   *DeployApproval `json:"approval,omitempty"`
}

type carrierAdoptBody struct {
	RequestID string        `json:"request_id"`
	RunnerID  string        `json:"runner_id"`
	Target    CarrierTarget `json:"target"`
}

type carrierAdoptRoutes struct {
	sec *secretRoutes
	svc CarrierAdoptionService
	dr  *deploymentRoutes
}

func (c *carrierAdoptRoutes) submit(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	id, scope, p, ok := secretByID(w, r, c.sec, identity.PermAdoptCarrier)
	if !ok {
		return
	}
	var body carrierAdoptBody
	if decodeInput(w, r, 8192, &body) != nil || (body.RequestID != "" && !reqid.Valid(body.RequestID)) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid carrier adoption request", rid)
		return
	}
	runner, err := uuid.Parse(body.RunnerID)
	target := runnerproto.Target{Kind: runnerproto.TargetKind(body.Target.Kind), Path: body.Target.Path, Field: body.Target.Field, Mode: 0o600}
	if err != nil || runner == uuid.Nil || target.Kind != runnerproto.TargetYAMLScalar || target.Validate() != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid carrier adoption request", rid)
		return
	}
	if c.svc == nil {
		c.unavailable(w, rid)
		return
	}
	requestID := body.RequestID
	if requestID == "" {
		requestID = rid
	}
	actor := c.dr.deployActor(p)
	out, err := c.svc.SubmitAdopt(r.Context(), deployment.AdoptRequest{OrgID: p.OrgID, Scope: scope, SecretID: id, RunnerID: runner, RequestID: requestID, Target: target, Actor: actor})
	if c.writeError(w, err, rid) {
		return
	}
	// The existing notifier carries a generic approval link; the approval
	// itself renders the distinct, bound read-only operation.
	if out.ApprovalID != uuid.Nil && out.Created {
		meta, merr := c.sec.cat.Meta(r.Context(), p.OrgID, id, reachableScopes(contextFromRequest(r, p)))
		if merr == nil {
			c.dr.notifyApproval(out, tenancy.SecretRef{ID: id, Scope: scope, Name: meta.Name, Class: meta.Class}, actor, body.Target.Kind)
		}
	}
	rep, err := c.svc.AdoptionReport(r.Context(), p.OrgID, requestID)
	if c.writeError(w, err, rid) {
		return
	}
	c.write(w, rid, requestID, rep)
}

func (c *carrierAdoptRoutes) status(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	id, scope, p, ok := secretByID(w, r, c.sec, identity.PermAdoptCarrier)
	if !ok {
		return
	}
	if c.svc == nil {
		c.unavailable(w, rid)
		return
	}
	rep, err := c.svc.AdoptionReport(r.Context(), p.OrgID, r.PathValue("request_id"))
	if err == nil && (rep.SecretID != id || rep.Scope != scope) {
		err = deployment.ErrNotFound
	}
	if c.writeError(w, err, rid) {
		return
	}
	c.write(w, rid, r.PathValue("request_id"), rep)
}

func (c *carrierAdoptRoutes) unavailable(w http.ResponseWriter, rid string) {
	writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "carrier adoption unavailable", rid)
}

func (c *carrierAdoptRoutes) writeError(w http.ResponseWriter, err error, rid string) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, deployment.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid carrier adoption request", rid)
	case errors.Is(err, deployment.ErrNotFound):
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "carrier adoption unavailable", rid)
	case errors.Is(err, deployment.ErrConflict):
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, "carrier adoption request id already used", rid)
	default:
		c.unavailable(w, rid)
	}
	return true
}

func (c *carrierAdoptRoutes) write(w http.ResponseWriter, rid, requestID string, rep deployment.Report) {
	out := CarrierAdoptionResult{RequestID: requestID, VersionID: rep.VersionID.String(), Status: "pending"}
	if rep.JobID != uuid.Nil {
		out.JobID = rep.JobID.String()
	}
	switch rep.Status {
	case deployment.Denied:
		writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "carrier adoption denied by policy", rid)
		return
	case deployment.RateLimited:
		writeError(w, http.StatusTooManyRequests, apperr.ClassRateLimited, "carrier adoption rate limit reached", rid)
		return
	case deployment.UnsupportedProvider:
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "carrier adoption provider unsupported", rid)
		return
	case deployment.NeedsApproval:
		out.Approval = &DeployApproval{ID: rep.ApprovalID.String(), Status: rep.ApprovalStatus, URL: c.dr.publicURL + "/console/approvals/" + rep.ApprovalID.String()}
		if rep.ApprovalStatus == "rejected" || rep.ApprovalStatus == "expired" {
			writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "carrier adoption approval refused", rid)
			return
		}
		if rep.ApprovalStatus != "approved" {
			out.Status = "approval_required"
		}
	case deployment.Queued:
	default:
		c.unavailable(w, rid)
		return
	}
	status := http.StatusAccepted
	if rep.Done {
		status, out.OK, out.ErrorClass, out.Status = http.StatusOK, rep.Result.OK, string(rep.Result.ErrorClass), "failed"
		if rep.Result.OK {
			out.Status = "registered"
		}
	}
	writeJSON(w, status, out)
}
