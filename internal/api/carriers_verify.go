package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// CarrierVerifyService is the durable verification boundary: authenticated
// references in, states out; no value, key or ciphertext crosses it.
// *deployment.Repo implements it.
type CarrierVerifyService interface {
	SubmitVerify(context.Context, deployment.VerifyRequest) (deployment.VerifyReport, error)
	VerifyReport(context.Context, uuid.UUID, string) (deployment.VerifyReport, error)
}

// CarrierVerifyResult is the answer of POST and GET /v1/carriers/verify. The
// top-level fields are §4.3's verify result row; Carriers is a list of its
// Carrier rows. A pending verification is ok=false (HTTP 202).
type CarrierVerifyResult struct {
	OK          bool                `json:"ok"`
	RequestID   string              `json:"request_id"`
	Fingerprint string              `json:"fingerprint"`
	Version     string              `json:"version"`
	Carriers    []CarrierVerifyItem `json:"carriers"`
}

// CarrierVerifyItem is one Carrier row: status is a closed state
// (pending, match, mismatch, unreachable, failed); fingerprint_match is set
// once the runner has answered.
type CarrierVerifyItem struct {
	ID               string        `json:"id"`
	Host             string        `json:"host"`
	RunnerID         string        `json:"runner_id,omitempty"`
	Target           CarrierTarget `json:"target"`
	Status           string        `json:"status"`
	LastVerifiedAt   *time.Time    `json:"last_verified_at,omitempty"`
	FingerprintMatch *bool         `json:"fingerprint_match,omitempty"`
	ErrorClass       string        `json:"error_class,omitempty"`
}

// CarrierTarget is Carrier's target{kind,path}.
type CarrierTarget struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type carrierVerifyBody struct {
	Secret    string `json:"secret"`
	RequestID string `json:"request_id"`
	Workspace string `json:"workspace_id"`
	Project   string `json:"project_id"`
}

type carrierVerifyRoutes struct {
	sec *secretRoutes
	svc CarrierVerifyService
}

// verifyMessage is the only error template of this surface: no carrier,
// path or host text, so a refusal reads the same whatever caused it.
func verifyMessage(reason string) string { return "carrier verification " + reason }

func (c *carrierVerifyRoutes) canRead(ctx context.Context, p identity.Principal, tc tenancy.Context, scope tenancy.Scope) (bool, error) {
	perms, err := catalog.PermissionsAt(ctx, c.sec.ir, tc, scope)
	if err != nil {
		return false, err
	}
	return perms[identity.PermReadMetadata] && (p.Scope == "" || p.Scope == scope.String()), nil
}

func (c *carrierVerifyRoutes) submit(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	var body carrierVerifyBody
	if decodeInput(w, r, 4096, &body) != nil || body.Secret == "" || (body.RequestID != "" && !reqid.Valid(body.RequestID)) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, verifyMessage("request invalid"), rid)
		return
	}
	requestID := body.RequestID
	if requestID == "" {
		requestID = rid
	}
	p, _ := identity.FromContext(r.Context())
	tc := contextFromRequest(r, p)
	var err error
	for _, item := range []struct {
		raw string
		dst *uuid.UUID
	}{{body.Workspace, &tc.Workspace}, {body.Project, &tc.Project}} {
		if item.raw != "" {
			if *item.dst, err = uuid.Parse(item.raw); err != nil {
				writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, verifyMessage("request invalid"), rid)
				return
			}
		}
	}
	ref, err := catalog.ResolveAuthorized(r.Context(), c.sec.tr, c.sec.ir, tc, body.Secret)
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	ok, err := c.canRead(r.Context(), p, tc, ref.Scope)
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	if !ok {
		writeAppError(w, tenancy.NotFoundError(body.Secret, tenancy.CheckedLevels(tc)), rid)
		return
	}
	if c.svc == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, verifyMessage("unavailable"), rid)
		return
	}
	actor := audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI}
	if p.SponsorUserID != nil {
		actor.SponsorID = p.SponsorUserID.String()
	}
	rep, err := c.svc.SubmitVerify(r.Context(), deployment.VerifyRequest{OrgID: p.OrgID, Scope: ref.Scope, SecretID: ref.ID, RequestID: requestID, Actor: actor})
	if c.writeFailure(w, err, rid) {
		return
	}
	c.write(w, requestID, rep)
}

func (c *carrierVerifyRoutes) status(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	if c.svc == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, verifyMessage("unavailable"), rid)
		return
	}
	p, _ := identity.FromContext(r.Context())
	requestID := r.PathValue("request_id")
	rep, err := c.svc.VerifyReport(r.Context(), p.OrgID, requestID)
	if err == nil {
		var ok bool
		if ok, err = c.canRead(r.Context(), p, contextFromRequest(r, p), rep.Scope); err == nil && !ok {
			err = deployment.ErrNotFound
		}
	}
	if c.writeFailure(w, err, rid) {
		return
	}
	c.write(w, requestID, rep)
}

// writeFailure answers a service error and reports whether it did.
func (c *carrierVerifyRoutes) writeFailure(w http.ResponseWriter, err error, rid string) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, deployment.ErrNotFound):
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, verifyMessage("unavailable"), rid)
	case errors.Is(err, deployment.ErrConflict):
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, verifyMessage("request id already used"), rid)
	case errors.Is(err, deployment.ErrVerifyRateLimited):
		writeError(w, http.StatusTooManyRequests, apperr.ClassRateLimited, verifyMessage("rate limit reached"), rid)
	case errors.Is(err, deployment.ErrTooManyCarriers), errors.Is(err, deployment.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, verifyMessage("request invalid"), rid)
	default:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, verifyMessage("unavailable"), rid)
	}
	return true
}

// write maps a durable report onto the closed wire shape. Only match counts
// as ok; a verification with nothing to check is ok and done.
func (c *carrierVerifyRoutes) write(w http.ResponseWriter, requestID string, rep deployment.VerifyReport) {
	out := CarrierVerifyResult{OK: true, RequestID: requestID, Fingerprint: rep.Fingerprint, Version: rep.Version, Carriers: []CarrierVerifyItem{}}
	for _, it := range rep.Items {
		class := it.ErrorClass
		if class != "" && !class.Valid() {
			class = runnerproto.ErrClassInternal
		}
		row := CarrierVerifyItem{ID: it.CarrierID.String(), Host: it.Host, Target: CarrierTarget{Kind: string(it.TargetKind), Path: it.TargetPath},
			Status: string(it.State), LastVerifiedAt: it.LastVerifiedAt, ErrorClass: string(class)}
		if it.RunnerID != uuid.Nil {
			row.RunnerID = it.RunnerID.String()
		}
		switch it.State {
		case deployment.VerifyMatch, deployment.VerifyMismatch:
			match := it.State == deployment.VerifyMatch
			row.FingerprintMatch = &match
		}
		if it.State != deployment.VerifyMatch {
			out.OK = false
		}
		out.Carriers = append(out.Carriers, row)
	}
	if !rep.Done() {
		writeJSON(w, http.StatusAccepted, out)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// orgVerifyBody is the whole request of the org-scoped route: the idempotency
// key and nothing else. The secret comes from the path, the destination list
// and healthcheck from the server's own records.
type orgVerifyBody struct {
	RequestID string `json:"request_id"`
}

// submitOrg serves POST /orgs/{org_id}/secrets/{secret_id}/carriers/verify.
func (c *carrierVerifyRoutes) submitOrg(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	id, scope, p, ok := secretByID(w, r, c.sec, identity.PermReadMetadata)
	if !ok {
		return
	}
	var body orgVerifyBody
	if r.ContentLength != 0 && (decodeInput(w, r, 512, &body) != nil || (body.RequestID != "" && !reqid.Valid(body.RequestID))) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, verifyMessage("request invalid"), rid)
		return
	}
	requestID := body.RequestID
	if requestID == "" {
		requestID = rid
	}
	if c.svc == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, verifyMessage("unavailable"), rid)
		return
	}
	actor := audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI}
	if p.SponsorUserID != nil {
		actor.SponsorID = p.SponsorUserID.String()
	}
	rep, err := c.svc.SubmitVerify(r.Context(), deployment.VerifyRequest{OrgID: p.OrgID, Scope: scope, SecretID: id, RequestID: requestID, Actor: actor})
	if c.writeFailure(w, err, rid) {
		return
	}
	c.write(w, requestID, rep)
}

// statusOrg serves GET .../carriers/verify/{request_id}. A request id made for
// another secret is the same 404 as an unknown one.
func (c *carrierVerifyRoutes) statusOrg(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	id, scope, p, ok := secretByID(w, r, c.sec, identity.PermReadMetadata)
	if !ok {
		return
	}
	if c.svc == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, verifyMessage("unavailable"), rid)
		return
	}
	requestID := r.PathValue("request_id")
	rep, err := c.svc.VerifyReport(r.Context(), p.OrgID, requestID)
	if err == nil && (rep.SecretID != id || rep.Scope != scope) {
		err = deployment.ErrNotFound
	}
	if c.writeFailure(w, err, rid) {
		return
	}
	c.write(w, requestID, rep)
}
