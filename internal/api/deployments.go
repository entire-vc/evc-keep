package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/notify"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// DeploymentService is the durable deployment boundary. It takes
// authenticated references and metadata and returns decisions; no value, key
// or ciphertext crosses it. *deployment.Repo implements it.
type DeploymentService interface {
	Submit(context.Context, deployment.Request) (deployment.Outcome, error)
	Report(context.Context, uuid.UUID, string) (deployment.Report, error)
}

// DeployResult is the threat model's §4.3 deploy result row: the only shape
// POST and GET /v1/deployments answer with besides the error body. A pending
// request is ok=false with neither error_class nor approval (HTTP 202).
type DeployResult struct {
	OK          bool            `json:"ok"`
	RequestID   string          `json:"request_id"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Version     string          `json:"version,omitempty"`
	Healthcheck *DeployHealth   `json:"healthcheck,omitempty"`
	ErrorClass  string          `json:"error_class,omitempty"`
	Approval    *DeployApproval `json:"approval,omitempty"`
}

// DeployHealth is the consumer state after the job.
type DeployHealth struct {
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checked_at"`
}

// DeployApproval references the approval request a prod or unlisted target
// needs: id, status and where a human decides it.
type DeployApproval struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	URL    string `json:"url"`
}

// ApprovalNotifier tells a human that an approval is waiting. It receives the
// closed notice only and is called at most once per approval; a failure never
// changes the answer to the caller. *notify.Telegram implements it.
type ApprovalNotifier interface {
	ApprovalRequested(context.Context, notify.ApprovalNotice) error
}

type deploymentRoutes struct {
	sec       *secretRoutes
	svc       DeploymentService
	aud       audit.Journaler
	publicURL string
	notifier  ApprovalNotifier
	logger    *slog.Logger
}

// notifyApproval sends the notification off the request path: a slow chat
// service must not hold a deploy call, and its error carries nothing to log
// beyond the fact.
func (d *deploymentRoutes) notifyApproval(out deployment.Outcome, ref tenancy.SecretRef, actor audit.Actor, kind string) {
	if d.notifier == nil || out.ApprovalID == uuid.Nil || !out.Created {
		return
	}
	n := notify.ApprovalNotice{ApprovalID: out.ApprovalID, SecretName: ref.Name, SecretClass: ref.Class, RequesterKind: string(actor.Type), TargetKind: knownKind(kind)}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.notifier.ApprovalRequested(ctx, n); err != nil && d.logger != nil {
			d.logger.Warn("approval notification failed", "error_class", "notify_failed")
		}
	}()
}

type deployTargetBody struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Field    string `json:"field"`
	Unit     string `json:"unit"`
	Consumer string `json:"consumer"`
	Mode     string `json:"mode"`
	UID      *int64 `json:"uid"`
	GID      *int64 `json:"gid"`
}

type deployBody struct {
	Secret    string           `json:"secret"`
	RunnerID  string           `json:"runner_id"`
	RequestID string           `json:"request_id"`
	Workspace string           `json:"workspace_id"`
	Project   string           `json:"project_id"`
	Target    deployTargetBody `json:"target"`
}

func deployHeaders(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// knownKind returns the closed kind name, or "unknown": a caller-supplied
// kind never reaches an error message or the journal unless it is on the list.
func knownKind(k string) string {
	for _, known := range runnerproto.TargetKinds {
		if string(known) == k {
			return k
		}
	}
	return "unknown"
}

// deployMessage is the only error template of this surface: secret name,
// closed target kind and a closed reason. The target path, field and unit are
// never part of it, so a refusal caused by a newline and one caused by a quote
// in the same position answer with the same bytes.
func deployMessage(reason, name, kind string) string {
	if name == "" {
		return "deployment " + reason
	}
	return fmt.Sprintf("deployment %s: secret %q, target kind %s", reason, name, knownKind(kind))
}

func (d *deploymentRoutes) deployActor(p identity.Principal) audit.Actor {
	actor := audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI}
	if p.SponsorUserID != nil {
		actor.SponsorID = p.SponsorUserID.String()
	}
	return actor
}

// authorize resolves a deploy right at scope for the caller.
func (d *deploymentRoutes) canDeploy(ctx context.Context, p identity.Principal, tc tenancy.Context, scope tenancy.Scope) (bool, error) {
	perms, err := catalog.PermissionsAt(ctx, d.sec.ir, tc, scope)
	if err != nil {
		return false, err
	}
	return perms[identity.PermDeploy] && (p.Scope == "" || p.Scope == scope.String()), nil
}

func (d *deploymentRoutes) submit(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	var body deployBody
	if decodeInput(w, r, 8192, &body) != nil || body.Secret == "" {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid deployment request", rid)
		return
	}
	runner, err := uuid.Parse(body.RunnerID)
	if err != nil || (body.RequestID != "" && !reqid.Valid(body.RequestID)) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid deployment request", rid)
		return
	}
	requestID := body.RequestID
	if requestID == "" {
		requestID = rid
	}
	p, _ := identity.FromContext(r.Context())
	tc := contextFromRequest(r, p)
	for _, item := range []struct {
		raw string
		dst *uuid.UUID
	}{{body.Workspace, &tc.Workspace}, {body.Project, &tc.Project}} {
		if item.raw != "" {
			if *item.dst, err = uuid.Parse(item.raw); err != nil {
				writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid deployment request", rid)
				return
			}
		}
	}
	ref, err := catalog.ResolveAuthorized(r.Context(), d.sec.tr, d.sec.ir, tc, body.Secret)
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	ok, err := d.canDeploy(r.Context(), p, tc, ref.Scope)
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	if !ok {
		writeAppError(w, tenancy.NotFoundError(body.Secret, tenancy.CheckedLevels(tc)), rid)
		return
	}
	if d.svc == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)
		return
	}
	versions, err := d.sec.cat.ListVersions(r.Context(), p.OrgID, ref.ID)
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	var version *catalog.SecretVersion
	// A retry of a request id replays against the version it was first pinned
	// to, even when a newer version has appeared or the pinned one was disabled
	// since: the stored outcome, not a fresh pick, answers it.
	// The key counts whether it came in the body or in the request-id header.
	prior, perr := d.svc.Report(r.Context(), p.OrgID, requestID)
	if perr == nil && prior.SecretID == ref.ID {
		for i := range versions {
			if versions[i].ID == prior.VersionID {
				version = &versions[i]
			}
		}
	}
	for i := range versions {
		if version == nil && !versions[i].Disabled {
			version = &versions[i]
		}
	}
	if version == nil {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, deployMessage("has no deployable version", ref.Name, body.Target.Kind), rid)
		return
	}
	target, ok := body.Target.parse()
	actor := d.deployActor(p)
	if !ok || target.Validate() != nil {
		d.reject(w, r, ref.Name, ref.ID.String(), version.ProviderVersion, ref.Scope.String(), runner, body.Target.Kind, p.OrgID, requestID, actor)
		return
	}
	out, err := d.svc.Submit(r.Context(), deployment.Request{OrgID: p.OrgID, Scope: ref.Scope, SecretID: ref.ID, VersionID: version.ID,
		RunnerID: runner, RequestID: requestID, Target: target, Actor: actor})
	switch {
	case errors.Is(err, deployment.ErrInvalidArgument):
		d.reject(w, r, ref.Name, ref.ID.String(), version.ProviderVersion, ref.Scope.String(), runner, body.Target.Kind, p.OrgID, requestID, actor)
		return
	case errors.Is(err, deployment.ErrConflict):
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, deployMessage("request id already used", ref.Name, body.Target.Kind), rid)
		return
	case errors.Is(err, deployment.ErrNotFound):
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, deployMessage("runner or secret unavailable", ref.Name, body.Target.Kind), rid)
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)
		return
	}
	d.notifyApproval(out, ref, actor, body.Target.Kind)
	rep, err := d.svc.Report(r.Context(), p.OrgID, requestID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)
		return
	}
	d.write(w, rid, requestID, ref.Name, body.Target.Kind, rep)
}

func (b deployTargetBody) parse() (runnerproto.Target, bool) {
	mode := uint64(0o600)
	if b.Mode != "" {
		m, err := strconv.ParseUint(b.Mode, 8, 32)
		if err != nil {
			return runnerproto.Target{}, false
		}
		mode = m
	}
	if b.UID == nil || b.GID == nil {
		return runnerproto.Target{}, false
	}
	return runnerproto.Target{Kind: runnerproto.TargetKind(b.Kind), Path: b.Path, Field: b.Field, Unit: b.Unit,
		Consumer: b.Consumer, Mode: uint32(mode), UID: *b.UID, GID: *b.GID}, true //nolint:gosec // mode is at most 32 bits by ParseUint
}

// reject answers a malformed or network-shaped target. The audit record holds
// the closed error class and the closed kind only.
func (d *deploymentRoutes) reject(w http.ResponseWriter, r *http.Request, name, secretID, version, scope string, runner uuid.UUID, kind string, org uuid.UUID, requestID string, actor audit.Actor) {
	rid := reqid.FromContext(r.Context())
	switch _, err := d.svc.Report(r.Context(), org, requestID); {
	case err == nil:
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, deployMessage("request id already used", name, kind), rid)
		return
	case !errors.Is(err, deployment.ErrNotFound):
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)
		return
	}
	if d.aud != nil {
		if _, err := d.aud.Append(r.Context(), audit.Record{OrgID: org.String(), RequestID: requestID, Scope: scope, Actor: actor,
			Action: audit.ActionDeployRequested, Secret: audit.SecretRef{ID: secretID, Name: name, Version: version},
			Target: audit.Target{RunnerID: runner.String(), Kind: knownKind(kind)},
			Result: audit.Result{Status: audit.StatusFailed, ErrorClass: audit.ErrClassInvalidArgument}}); err != nil {
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)
			return
		}
	}
	writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, deployMessage("rejected", name, kind), rid)
}

func (d *deploymentRoutes) status(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())
	requestID := r.PathValue("request_id")
	if d.svc == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)
		return
	}
	rep, err := d.svc.Report(r.Context(), p.OrgID, requestID)
	if err == nil {
		var ok bool
		if ok, err = d.canDeploy(r.Context(), p, contextFromRequest(r, p), rep.Scope); err == nil && !ok {
			err = deployment.ErrNotFound
		}
	}
	switch {
	case errors.Is(err, deployment.ErrNotFound):
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "deployment request unavailable", rid)
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)
		return
	}
	d.write(w, rid, requestID, "", "", rep)
}

// write maps a durable report onto the closed wire shapes. name and kind feed
// the error template only when the deployment was refused.
func (d *deploymentRoutes) write(w http.ResponseWriter, rid, requestID, name, kind string, rep deployment.Report) {
	switch rep.Status {
	case deployment.Denied:
		writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, deployMessage("denied by policy", name, kind), rid)
	case deployment.RateLimited:
		writeError(w, http.StatusTooManyRequests, apperr.ClassRateLimited, deployMessage("rate limit reached", name, kind), rid)
	case deployment.UnsupportedProvider:
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, deployMessage("provider unsupported for runner delivery", name, kind), rid)
	case deployment.NeedsApproval:
		approval := &DeployApproval{ID: rep.ApprovalID.String(), Status: rep.ApprovalStatus, URL: d.publicURL + "/console/approvals/" + rep.ApprovalID.String()}
		switch rep.ApprovalStatus {
		case "rejected":
			writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, deployMessage("approval rejected", name, kind), rid)
		case "expired":
			writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, deployMessage("approval expired", name, kind), rid)
		case "approved":
			// The human said yes: from here the request behaves like a queued job.
			if !rep.Done {
				writeJSON(w, http.StatusAccepted, DeployResult{RequestID: requestID, Approval: approval})
				return
			}
			writeJSON(w, http.StatusOK, d.result(requestID, rep, approval))
		default:
			writeJSON(w, http.StatusAccepted, DeployResult{RequestID: requestID, Approval: approval})
		}
	case deployment.Queued:
		if !rep.Done {
			writeJSON(w, http.StatusAccepted, DeployResult{RequestID: requestID})
			return
		}
		writeJSON(w, http.StatusOK, d.result(requestID, rep, nil))
	default:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)
	}
}

// result is the terminal wire shape of a finished job.
func (d *deploymentRoutes) result(requestID string, rep deployment.Report, approval *DeployApproval) DeployResult {
	out := DeployResult{OK: rep.Result.OK, RequestID: requestID, Fingerprint: rep.Result.Fingerprint, Version: rep.Result.Version, ErrorClass: string(rep.Result.ErrorClass), Approval: approval}
	if h := rep.Result.Healthcheck; h != nil {
		out.Healthcheck = &DeployHealth{Status: string(h.Status), CheckedAt: h.CheckedAt}
	}
	return out
}
