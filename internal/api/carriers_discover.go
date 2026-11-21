package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// CarrierDiscoverService is the durable discovery boundary: authenticated
// references in, findings out; no value, key or ciphertext crosses it.
// *deployment.Repo implements it.
type CarrierDiscoverService interface {
	SubmitDiscover(context.Context, deployment.DiscoverRequest) (deployment.DiscoverReport, error)
	DiscoverReport(ctx context.Context, org uuid.UUID, requestID string, offset int) (deployment.DiscoverReport, error)
}

// CarrierDiscoverResult is one page of the answer of POST and GET
// /orgs/{org_id}/carriers/discover. A pending request is HTTP 202 with no
// findings; a completed one lists at most deployment.DiscoverPageSize of
// them from line offset of the whole report, total lines long (threat model
// 4.3.4.1). ok is the whole report's, never only this page's.
type CarrierDiscoverResult struct {
	OK         bool                   `json:"ok"`
	RequestID  string                 `json:"request_id"`
	RunnerID   string                 `json:"runner_id"`
	StoreID    string                 `json:"store_id"`
	Host       string                 `json:"host"`
	State      string                 `json:"state"`
	ErrorClass string                 `json:"error_class,omitempty"`
	Offset     int                    `json:"offset"`
	Total      int                    `json:"total"`
	Findings   []CarrierDiscoverFound `json:"findings"`
}

// CarrierDiscoverFound is one finding: a closed verdict (match, stale,
// sprawl, unknown_find), where it was seen, the variable name and the keyed
// fingerprint. Never a value and never a length, for any verdict (threat
// model 4.3.4.2). incident is true while the finding waits for a person;
// discovery never rotates anything itself.
type CarrierDiscoverFound struct {
	Verdict     string `json:"verdict"`
	CarrierID   string `json:"carrier_id,omitempty"`
	Path        string `json:"path"`
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Incident    bool   `json:"incident"`
}

type carrierDiscoverBody struct {
	RunnerID  string `json:"runner_id"`
	StoreID   string `json:"store_id"`
	RequestID string `json:"request_id"`
}

type carrierDiscoverRoutes struct {
	ir  *identity.Repo
	svc CarrierDiscoverService
}

// discoverMessage is the only error template of this surface: no path, host
// or store text, so a refusal reads the same whatever caused it.
func discoverMessage(reason string) string { return "carrier discovery " + reason }

// allowed requires manage_runners in the caller's own org: discovery makes a
// host read its files, the same right as enrolling or revoking a runner.
func (c *carrierDiscoverRoutes) allowed(w http.ResponseWriter, r *http.Request) (identity.Principal, bool) {
	rid := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())
	if c.svc == nil || c.ir == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, discoverMessage("unavailable"), rid)
		return p, false
	}
	granted, err := hasPermission(r.Context(), c.ir, p, identity.PermManageRunners)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, discoverMessage("unavailable"), rid)
		return p, false
	}
	if !granted {
		writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "permission denied", rid)
		return p, false
	}
	return p, true
}

func (c *carrierDiscoverRoutes) submit(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	p, ok := c.allowed(w, r)
	if !ok {
		return
	}
	var body carrierDiscoverBody
	if decodeInput(w, r, 1024, &body) != nil || (body.RequestID != "" && !reqid.Valid(body.RequestID)) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, discoverMessage("request invalid"), rid)
		return
	}
	runner, err1 := uuid.Parse(body.RunnerID)
	store, err2 := uuid.Parse(body.StoreID)
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, discoverMessage("request invalid"), rid)
		return
	}
	requestID := body.RequestID
	if requestID == "" {
		requestID = rid
	}
	actor := audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI}
	if p.SponsorUserID != nil {
		actor.SponsorID = p.SponsorUserID.String()
	}
	rep, err := c.svc.SubmitDiscover(r.Context(), deployment.DiscoverRequest{OrgID: p.OrgID, RunnerID: runner, StoreID: store, RequestID: requestID, Actor: actor})
	if c.writeFailure(w, err, rid) {
		return
	}
	c.write(w, requestID, rep)
}

func (c *carrierDiscoverRoutes) status(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	p, ok := c.allowed(w, r)
	if !ok {
		return
	}
	offset, valid := discoverOffset(r)
	if !valid {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, discoverMessage("request invalid"), rid)
		return
	}
	requestID := r.PathValue("request_id")
	rep, err := c.svc.DiscoverReport(r.Context(), p.OrgID, requestID, offset)
	if c.writeFailure(w, err, rid) {
		return
	}
	c.write(w, requestID, rep)
}

// discoverOffset reads the page start: no offset is 0; otherwise exactly
// one decimal number, no sign, no leading zero, at most 10 digits. Whether
// it is past the report's total is the service's to say.
func discoverOffset(r *http.Request) (int, bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, false
	}
	vals, present := q["offset"]
	if !present {
		return 0, true
	}
	if len(vals) != 1 {
		return 0, false
	}
	v := vals[0]
	if v == "" || len(v) > 10 || (len(v) > 1 && v[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(v)
	if err != nil || n > 1<<31-1 {
		return 0, false
	}
	return n, true
}

func (c *carrierDiscoverRoutes) writeFailure(w http.ResponseWriter, err error, rid string) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, deployment.ErrNotFound):
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, discoverMessage("unavailable"), rid)
	case errors.Is(err, deployment.ErrConflict):
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, discoverMessage("request id already used"), rid)
	case errors.Is(err, deployment.ErrDiscoverBusy):
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, discoverMessage("already running on this runner"), rid)
	case errors.Is(err, deployment.ErrDiscoverRateLimited):
		writeError(w, http.StatusTooManyRequests, apperr.ClassRateLimited, discoverMessage("rate limit reached"), rid)
	case errors.Is(err, deployment.ErrDiscoverTooManyCarriers):
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, discoverMessage("too many registered carriers for one discover"), rid)
	case errors.Is(err, deployment.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, discoverMessage("request invalid"), rid)
	default:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, discoverMessage("unavailable"), rid)
	}
	return true
}

// write maps one page of a durable report onto the closed wire shape. ok
// means the scan completed and every line of the whole report, on any page,
// is a match.
func (c *carrierDiscoverRoutes) write(w http.ResponseWriter, requestID string, rep deployment.DiscoverReport) {
	out := CarrierDiscoverResult{OK: rep.State == deployment.DiscoverCompleted && rep.AllMatch, RequestID: requestID, RunnerID: rep.RunnerID.String(),
		StoreID: rep.StoreID.String(), Host: rep.Host, State: string(rep.State), Offset: rep.Offset, Total: rep.Total, Findings: []CarrierDiscoverFound{}}
	if rep.State == deployment.DiscoverFailed || rep.State == deployment.DiscoverExpired {
		class := rep.ErrorClass
		if class != "" && !class.Valid() {
			class = runnerproto.ErrClassInternal
		}
		out.ErrorClass = string(class)
	}
	for _, it := range rep.Items {
		f := CarrierDiscoverFound{Verdict: string(it.Verdict), Path: it.Path, Name: it.Name, Fingerprint: it.Fingerprint, Incident: it.Incident}
		if it.CarrierID != uuid.Nil {
			f.CarrierID = it.CarrierID.String()
		}
		out.Findings = append(out.Findings, f)
	}
	if rep.State == deployment.DiscoverPending {
		writeJSON(w, http.StatusAccepted, out)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
