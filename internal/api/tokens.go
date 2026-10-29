package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// tokenRoutes bundles the dependencies handleIssueToken and
// handleRevokeToken need.
type tokenRoutes struct {
	ir  *identity.Repo
	aud audit.Journaler
	log *slog.Logger
}

// requireOrgAdmin reports whether the calling Principal may mint or revoke
// a credential in org: a human user (never an agent or a service — this
// package's own design decision, so a credential can never mint another
// one on its own) holding the admin role at the organization's own scope.
// Every denial answers the same way this route's callers already render a
// missing right — see [handleCreateSecret]'s "never 403" comment; issuing
// or revoking a token is exactly as sensitive an operation as writing a
// secret reference, and gets the same treatment.
func requireOrgAdmin(ir *identity.Repo, r *http.Request, p identity.Principal) (bool, error) {
	if p.Kind != identity.KindUser {
		return false, nil
	}
	role, ok, err := ir.UserRole(r.Context(), p.OrgID, p.ID, tenancy.Org(p.OrgID).String())
	if err != nil {
		return false, err
	}
	return ok && role == identity.RoleAdmin, nil
}

// validScope reports whether s has the "level:uuid" shape the tenancy
// model's own wire notation uses ([tenancy.Scope.String]'s format), and,
// for the org level, that it names the calling admin's own organization.
// req.Scope reached [identity.Repo.Issue] unvalidated, was stored verbatim,
// and was copied into every audit record
// this token's actions later produce (internal/audit's closed-field
// contract has no room for free text there) — this closes that specific
// injection surface. It does not yet confirm a ws/proj/user id actually
// belongs to callerOrg (that needs a repo lookup this route has no
// dependency wired for), and whether "scope" should gate an issued token's
// rights at all — it currently does not, see identity.Repo's own doc — is
// a separate, still-open design question raised on this MR, not decided
// here.
func validScope(callerOrg uuid.UUID, s string) bool {
	if len(s) > 64 {
		return false
	}
	level, id, ok := strings.Cut(s, ":")
	if !ok {
		return false
	}
	scopeID, err := uuid.Parse(id)
	if err != nil {
		return false
	}
	switch tenancy.Level(level) {
	case tenancy.LevelOrg:
		return scopeID == callerOrg
	case tenancy.LevelWorkspace, tenancy.LevelProject, tenancy.LevelUser:
		return true
	case PollerScopePrefix:
		// The restart poller's role: bound to the caller's own organization.
		return scopeID == callerOrg
	default:
		return false
	}
}

// classifyIdentityErr maps an [identity.Repo.Issue] or [identity.Repo.Revoke]
// failure to the HTTP status, apperr class, audit error class and message
// this route should render: notFoundErr is the route's own not-found
// sentinel (identity.ErrPrincipalNotFound or identity.ErrTokenUnknown), and
// notFoundMsg the message to pair with it. Anything else is a genuine
// internal failure, labeled as such — not folded into the same not_found
// bucket: this route previously logged every such failure to the audit
// journal as audit.ErrClassNotFound and rendered "not found" even when the
// actual failure was internal.
func classifyIdentityErr(err error, notFoundErr error, notFoundMsg string) (status int, class apperr.Class, auditClass audit.ErrorClass, message string) {
	if errors.Is(err, notFoundErr) {
		return http.StatusNotFound, apperr.ClassNotFound, audit.ErrClassNotFound, notFoundMsg
	}
	return http.StatusInternalServerError, apperr.ClassInternal, audit.ErrClassInternal, "internal error"
}

// rejectForeignSponsoredAgent reports whether admin (the caller, already
// confirmed an org admin by [requireOrgAdmin]) must be refused a token for
// agentID, and if so writes that refusal and its audit record itself — the
// caller only needs to check the returned bool and return.
//
// principalPermissions grants every agent token DefaultAgentGrants
// (read_metadata, deploy — see internal/catalog's own doc) at its sponsor's
// personal scope unconditionally, the same scope [PermissionsAt] otherwise
// refuses even an org admin direct access to. Minting a token for an agent
// sponsored by someone other than the caller would hand any org admin that
// same access indirectly, defeating the very isolation PermissionsAt
// enforces. Whether an org admin should be able to provision credentials on
// behalf of another member's agent at all is a real, open threat-model
// question (see this MR's own notes) — until it is decided, this fails
// closed: only an agent's own sponsor may mint its token, denied the exact
// same way a nonexistent agent would be, so this is never an oracle on who
// sponsors which agent.
func (s *tokenRoutes) rejectForeignSponsoredAgent(w http.ResponseWriter, r *http.Request, admin identity.Principal, agentID uuid.UUID, requestID string) bool {
	sponsor, err := s.ir.AgentSponsor(r.Context(), admin.OrgID, agentID)
	if err != nil {
		status, class, auditClass, message := classifyIdentityErr(err, identity.ErrPrincipalNotFound, "not found")
		writeError(w, status, class, message, requestID)
		s.appendAudit(r, admin, requestID, audit.ActionTokenIssue, audit.StatusFailed, auditClass)
		return true
	}
	if sponsor != admin.ID {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
		s.appendAudit(r, admin, requestID, audit.ActionTokenIssue, audit.StatusFailed, audit.ErrClassPermissionDenied)
		return true
	}
	return false
}

// handleIssueToken serves POST /orgs/{org_id}/tokens: mints a fresh
// agent or service token. A user token is never minted through this route
// — user authentication is separate, later work (see internal/identity's
// own package doc).
func (s *tokenRoutes) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())

	admin, err := requireOrgAdmin(s.ir, r, p)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	if !admin {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
		s.appendAudit(r, p, requestID, audit.ActionTokenIssue, audit.StatusFailed, audit.ErrClassPermissionDenied)
		return
	}

	raw, refused := readBoundedBody(w, r, maxTokenBodyBytes, requestID)
	if refused != nil {
		return
	}
	var req issueTokenRequest
	if err := decodeStrict(raw, &req); err != nil {
		logRejected(r.Context(), s.log, "token_issue_rejected", requestID)
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "request body is not valid JSON", requestID)
		return
	}
	kind := identity.Kind(req.Kind)
	if kind != identity.KindAgent && kind != identity.KindService {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "kind must be \"a\" (agent) or \"s\" (service)", requestID)
		return
	}
	principalID, err := uuid.Parse(req.PrincipalID)
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "principal_id is not a valid id", requestID)
		return
	}
	if !validScope(p.OrgID, req.Scope) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "scope must be org|ws|proj|user:<uuid>, and an org scope must be the caller's own", requestID)
		return
	}
	if strings.HasPrefix(req.Scope, PollerScopePrefix+":") && kind != identity.KindService {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "the restart poller scope is for a service token", requestID)
		return
	}
	if kind == identity.KindAgent && s.rejectForeignSponsoredAgent(w, r, p, principalID, requestID) {
		return
	}

	result, err := s.ir.Issue(r.Context(), identity.IssueParams{
		OrgID: p.OrgID, Kind: kind, PrincipalID: principalID, Scope: req.Scope, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		status, class, auditClass, message := classifyIdentityErr(err, identity.ErrPrincipalNotFound, "not found")
		writeError(w, status, class, message, requestID)
		s.appendAudit(r, p, requestID, audit.ActionTokenIssue, audit.StatusFailed, auditClass)
		return
	}
	s.appendAudit(r, p, requestID, audit.ActionTokenIssue, audit.StatusOK, audit.ErrClassNone)

	// result.Response().WireJSON() is the one place anywhere in Keep a
	// token's plaintext is meant to reach the wire — see IssueResponse's own
	// doc. json.NewEncoder/writeJSON must never be used for this value:
	// IssueResponse.MarshalJSON always fails on purpose.
	body, err := result.Response().WireJSON()
	if err != nil {
		writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // the one-time bearer must not be cached
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(body)
}

// handleRevokeToken serves POST /orgs/{org_id}/tokens/{token_id}/revoke.
func (s *tokenRoutes) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())

	admin, err := requireOrgAdmin(s.ir, r, p)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	if !admin {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
		s.appendAudit(r, p, requestID, audit.ActionTokenRevoke, audit.StatusFailed, audit.ErrClassPermissionDenied)
		return
	}
	tokenID, err := uuid.Parse(r.PathValue("token_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "token_id is not a valid id", requestID)
		return
	}

	if err := s.ir.Revoke(r.Context(), p, tokenID); err != nil {
		status, class, auditClass, message := classifyIdentityErr(err, identity.ErrTokenUnknown, "not found")
		writeError(w, status, class, message, requestID)
		s.appendAudit(r, p, requestID, audit.ActionTokenRevoke, audit.StatusFailed, auditClass)
		return
	}
	s.appendAudit(r, p, requestID, audit.ActionTokenRevoke, audit.StatusOK, audit.ErrClassNone)
	writeJSON(w, http.StatusOK, okResult{OK: true, RequestID: requestID})
}

func (s *tokenRoutes) appendAudit(r *http.Request, p identity.Principal, requestID string, action audit.Action, status audit.ResultStatus, errClass audit.ErrorClass) {
	if s.aud == nil {
		return
	}
	actor := audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI}
	if p.Kind == identity.KindAgent && p.SponsorUserID != nil {
		actor.SponsorID = p.SponsorUserID.String()
	}
	_, _ = s.aud.Append(r.Context(), audit.Record{
		RequestID: requestID,
		OrgID:     p.OrgID.String(),
		Scope:     p.Scope,
		Actor:     actor,
		Action:    action,
		Result:    audit.Result{Status: status, ErrorClass: errClass},
	})
}
