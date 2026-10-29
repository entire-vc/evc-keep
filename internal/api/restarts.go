package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/restart"
	"github.com/google/uuid"
)

// PollerScopePrefix starts the scope of a restart poller's token: the token is
// a service token whose scope is "restart_poll:<org id>". The role has no
// permission in the secret catalog, so such a token reaches nothing else.
const PollerScopePrefix = "restart_poll"

const maxRestartAckBytes = 1 << 10

// RestartQueue is the queue the poller routes drive; *restart.Repo implements it.
type RestartQueue interface {
	Claim(ctx context.Context, org uuid.UUID, limit int) ([]restart.Request, error)
	Ack(ctx context.Context, org, id uuid.UUID, claimToken string, res restart.Result) error
}

// RestartRequest is one claimed request: the closed list of its fields.
type RestartRequest struct {
	RequestID   string `json:"request_id"`
	Lane        string `json:"lane"`
	KeyVersion  string `json:"key_version"`
	Fingerprint string `json:"fingerprint"`
	ClaimToken  string `json:"claim_token"`
}

type restartAckRequest struct {
	Result     string `json:"result"`
	ClaimToken string `json:"claim_token"`
}

type restartRoutes struct{ q RestartQueue }

// isPoller reports whether p holds the restart:poll role.
func isPoller(p identity.Principal) bool {
	return p.Kind == identity.KindService && p.Scope == PollerScopePrefix+":"+p.OrgID.String()
}

// authenticate is identity.RequireAuth plus the poller role gate: a restart:poll
// token passes only on routes marked Poller and is refused with a bare 403
// everywhere else, before any handler parses the path, query or body, so no
// route can tell it anything. Every authenticated route goes through here.
func authenticate(ir *identity.Repo, logger *slog.Logger, allowPoller bool) func(http.Handler) http.Handler {
	auth := identity.RequireAuth(ir, logger)
	return func(next http.Handler) http.Handler {
		return auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, _ := identity.FromContext(r.Context()); !allowPoller && isPollerScope(p) {
				writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "permission denied", reqid.FromContext(r.Context()))
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// pollerGate is the outermost check: a request that carries a bearer token of
// the restart:poll role is refused with a bare 403 on every route that is not
// claim or ack, public routes and routes registered outside the route table
// included, before any handler runs. It spends one token lookup only when a
// bearer header is present; a token that does not authenticate is left to the
// route, which answers it as it always did.
func pollerGate(ir *identity.Repo, mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token, ok := identity.BearerToken(r); ok {
			if _, pattern := mux.Handler(r); !pollerPatterns[pattern] {
				if p, err := ir.Authenticate(r.Context(), token); err == nil && isPollerScope(p) {
					writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "permission denied", reqid.FromContext(r.Context()))
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// pollerPatterns are the mux patterns a restart:poll token may reach.
var pollerPatterns = map[string]bool{
	"POST /v1/restarts/claim":            true,
	"POST /v1/restarts/{request_id}/ack": true,
}

// isPollerScope reports whether p carries any restart_poll scope, including one
// bound to another organization: such a token is a poller on no route but claim/ack.
func isPollerScope(p identity.Principal) bool {
	return p.Kind == identity.KindService && (p.Scope == PollerScopePrefix || strings.HasPrefix(p.Scope, PollerScopePrefix+":"))
}

// requirePoller answers 403 when the caller lacks the role or no queue is wired.
func (s *restartRoutes) requirePoller(w http.ResponseWriter, r *http.Request) (identity.Principal, string, bool) {
	rid := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())
	if !isPoller(p) {
		writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "restart polling is not permitted for this token", rid)
		return p, rid, false
	}
	if s.q == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "restart queue unavailable", rid)
		return p, rid, false
	}
	return p, rid, true
}

// claim serves POST /v1/restarts/claim.
func (s *restartRoutes) claim(w http.ResponseWriter, r *http.Request) {
	p, rid, ok := s.requirePoller(w, r)
	if !ok {
		return
	}
	got, err := s.q.Claim(r.Context(), p.OrgID, restart.MaxClaim)
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	out := make([]RestartRequest, len(got))
	for i, x := range got {
		out[i] = RestartRequest{RequestID: x.RequestID.String(), Lane: x.Lane, KeyVersion: x.KeyVersion, Fingerprint: x.Fingerprint, ClaimToken: x.ClaimToken}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// ack serves POST /v1/restarts/{request_id}/ack.
func (s *restartRoutes) ack(w http.ResponseWriter, r *http.Request) {
	p, rid, ok := s.requirePoller(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("request_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", rid)
		return
	}
	raw, refused := readBoundedBody(w, r, maxRestartAckBytes, rid)
	if refused != nil {
		return
	}
	var req restartAckRequest
	if decodeStrict(raw, &req) != nil || !restart.Result(req.Result).Valid() {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "result must be ok, nothing_running or failed", rid)
		return
	}
	switch err := s.q.Ack(r.Context(), p.OrgID, id, req.ClaimToken, restart.Result(req.Result)); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, restart.ErrNotFound):
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", rid)
	case errors.Is(err, restart.ErrConflict):
		writeError(w, http.StatusConflict, apperr.ClassAlreadyExists, "request already finished with another result", rid)
	default:
		writeAppError(w, err, rid)
	}
}
