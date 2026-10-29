package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/google/uuid"
)

// secretRoutes bundles the dependencies every handler in this file needs —
// built once by [NewRouter] and closed over by each handler, never
// constructed per-request.
type secretRoutes struct {
	logger *slog.Logger
	tr     *tenancy.Repo
	ir     *identity.Repo
	cat    *catalog.Catalog
	aud    audit.Journaler
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// contextFromRequest builds the tenancy.Context a request's own scope query
// parameters (or, for handleCreateSecret, its own body) declare, seated on
// the authenticated Principal — see [principalToTenancy]'s doc for why
// org_id and the principal's identity may only come from there.
func contextFromRequest(r *http.Request, p identity.Principal) tenancy.Context {
	return tenancy.Context{Org: p.OrgID, Principal: principalToTenancy(p)}
}

// handleListSecrets serves GET /orgs/{org_id}/secrets?scope_level=&scope_id=:
// every secret defined exactly at that scope (no hierarchy walk — tenancy
// model §3's bottom-up search is Resolve's job, not this listing route's).
//
// A caller without read_metadata at that scope gets back an empty list,
// the same response an empty-but-permitted scope would produce — the same
// no-oracle reasoning [catalog.ResolveAuthorized] documents for
// secret_not_found, applied to a listing rather than a single lookup: there
// is no separate "forbidden" response for this route to leak through.
func (s *secretRoutes) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())
	scope, ok := scopeFromQuery(r)
	if !ok {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "scope_level/scope_id are required", requestID)
		return
	}
	tc := contextFromRequest(r, p)

	perms, err := catalog.PermissionsAt(r.Context(), s.ir, tc, scope)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	if !perms[identity.PermReadMetadata] {
		writeJSON(w, http.StatusOK, []Secret{})
		return
	}

	rows, err := s.cat.List(r.Context(), p.OrgID, scope)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	out := make([]Secret, 0, len(rows))
	for _, row := range rows {
		store, err := s.cat.GetStore(r.Context(), p.OrgID, row.StoreID)
		if err != nil {
			writeAppError(w, err, requestID)
			return
		}
		out = append(out, newSecret(row, store))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCreateSecret serves POST /orgs/{org_id}/secrets: a new catalog
// entry, metadata only (internal/catalog's own doc: writing the value
// itself is a provider's job). Requires create_ref at the target scope, and
// records the action in the R-AUD-1 journal (threat model §4.2) whatever
// the outcome — except a refused body (413, 400 before any rights check),
// which is not an event over a secret and is only logged, see
// [secretRoutes.logRefusedBody].
func (s *secretRoutes) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())

	// RawMessage preserves bytes that decoding into strings would replace.
	raw, refused := readBoundedBody(w, r, maxSecretBodyBytes, requestID)
	if refused != nil {
		s.logRefusedBody(r, p, requestID, refused.Status, refused.Class, refused.N)
		return
	}
	refuse := func(message string) {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, message, requestID)
		s.logRefusedBody(r, p, requestID, http.StatusBadRequest, apperr.ClassInvalidArgument, len(raw))
	}
	if !utf8.Valid(raw) {
		refuse(metadataWireField(raw, utf8.Valid) + ": must be valid UTF-8")
		return
	}
	if !validSurrogateEscapes(raw) {
		refuse(metadataWireField(raw, validSurrogateEscapes) + ": contains an unpaired Unicode surrogate")
		return
	}
	var req createSecretRequest
	if err := decodeStrict(raw, &req); err != nil {
		refuse("request body is not valid JSON")
		return
	}
	level := tenancy.Level(req.ScopeLevel)
	scopeID, idErr := uuid.Parse(req.ScopeID)
	if !level.Valid() || idErr != nil {
		refuse("scope_level/scope_id are required")
		return
	}
	if req.Name == "" || req.Class == "" || req.Type == "" {
		refuse("name, class and type are required")
		return
	}
	// provider_ref must be a locator this package's providers understand
	// (builtin://, op://, sops://, vault://), never an arbitrary string
	// (threat model §4.3).
	if !provider.ValidRef(req.ProviderRef) {
		refuse("provider_ref is not a recognized locator")
		return
	}
	scope := tenancy.Scope{Level: level, ID: scopeID}
	tc := contextFromRequest(r, p)

	perms, err := catalog.PermissionsAt(r.Context(), s.ir, tc, scope)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	if !perms[identity.PermCreateRef] {
		// Never 403 for a scope the caller cannot write to — same rule
		// identity.RequireOrgMatch documents for a mismatched org_id: the
		// response must not tell a caller whether the scope exists and they
		// lack rights, or the scope simply isn't theirs to know about.
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
		s.appendAudit(r, p, requestID, audit.ActionSecretCreateRef, audit.SecretRef{Name: req.Name}, audit.StatusFailed, audit.ErrClassPermissionDenied, "", 0)
		return
	}

	created, err := s.cat.CreateRef(r.Context(), catalog.CreateRefInput{
		Org: p.OrgID, Scope: scope, Name: req.Name, Class: req.Class, Type: req.Type,
		ProviderRef: req.ProviderRef, Description: req.Description,
	})
	if err != nil {
		writeAppError(w, err, requestID)
		s.appendAudit(r, p, requestID, audit.ActionSecretCreateRef, audit.SecretRef{Name: req.Name}, audit.StatusFailed, classifyErr(err), "", 0)
		return
	}
	s.appendAudit(r, p, requestID, audit.ActionSecretCreateRef,
		audit.SecretRef{ID: created.ID.String(), Name: created.Name}, audit.StatusOK, audit.ErrClassNone, "", 0)

	store, err := s.cat.GetStore(r.Context(), p.OrgID, created.StoreID)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	writeJSON(w, http.StatusCreated, newSecret(created, store))
}

// handleSecretMeta serves GET /orgs/{org_id}/secrets/{secret_id}. A secret
// that doesn't exist, one outside the caller's reachable scopes, and one the
// caller can reach but has no read_metadata rights over all answer the
// identical secret_not_found shape — see [catalog.ResolveAuthorized]'s doc
// for why a rights failure must never be distinguishable from a true miss.
func (s *secretRoutes) handleSecretMeta(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())
	id, err := uuid.Parse(r.PathValue("secret_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "secret_id is not a valid id", requestID)
		return
	}
	tc := contextFromRequest(r, p)

	found, err := s.cat.Meta(r.Context(), p.OrgID, id, reachableScopes(tc))
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	perms, err := catalog.PermissionsAt(r.Context(), s.ir, tc, found.Scope)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	if !perms[identity.PermReadMetadata] {
		writeAppError(w, catalog.NotFoundByID(id), requestID)
		return
	}
	store, err := s.cat.GetStore(r.Context(), p.OrgID, found.StoreID)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	writeJSON(w, http.StatusOK, newSecret(found, store))
}

// handleListVersions serves GET /orgs/{org_id}/secrets/{secret_id}/versions
// — the same rights gate as [handleSecretMeta] (a secret must be readable
// before its version history is), applied first.
func (s *secretRoutes) handleListVersions(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())
	id, err := uuid.Parse(r.PathValue("secret_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "secret_id is not a valid id", requestID)
		return
	}
	tc := contextFromRequest(r, p)

	found, err := s.cat.Meta(r.Context(), p.OrgID, id, reachableScopes(tc))
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	perms, err := catalog.PermissionsAt(r.Context(), s.ir, tc, found.Scope)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	if !perms[identity.PermReadMetadata] {
		writeAppError(w, catalog.NotFoundByID(id), requestID)
		return
	}
	rows, err := s.cat.ListVersions(r.Context(), p.OrgID, id)
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	writeJSON(w, http.StatusOK, newSecretVersions(rows))
}

// classifyErr maps an error from a catalog write into the audit journal's
// closed error-class enum (threat model §4.2) — never the error's own text.
func classifyErr(err error) audit.ErrorClass {
	var ae *apperr.Error
	if !asAppErr(err, &ae) {
		return audit.ErrClassInternal
	}
	switch ae.Class {
	case apperr.ClassInvalidArgument, apperr.ClassAmbiguousContext:
		return audit.ErrClassInvalidArgument
	case apperr.ClassNotFound, apperr.ClassSecretNotFound:
		return audit.ErrClassNotFound
	case apperr.ClassOverrideLocked, apperr.ClassNoStoreBound:
		return audit.ErrClassPolicyDenied
	default:
		return audit.ErrClassInternal
	}
}

// asAppErr uses errors.As, not a plain type assertion — [writeAppError]'s own
// classification uses errors.As, and classifyErr's journal record must never
// disagree with the response the caller actually saw about whether a
// failure was a classified apperr or a genuine internal one.
func asAppErr(err error, target **apperr.Error) bool {
	return errors.As(err, target)
}

// appendAudit writes one R-AUD-1 record for a secret-affecting action. It
// never fails the request: an audit write failure is logged by
// [audit.Journal] itself (see its WithLogger doc) and swallowed here — a
// caller must not learn from the response whether the journal is healthy,
// and the action it describes has already happened (or definitively failed)
// by the time this runs.
func (s *secretRoutes) appendAudit(r *http.Request, p identity.Principal, requestID string, action audit.Action, secretRef audit.SecretRef, status audit.ResultStatus, errClass audit.ErrorClass, fingerprint string, length int) {
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
		Secret:    secretRef,
		Result:    audit.Result{Status: status, ErrorClass: errClass, Fingerprint: fingerprint, Length: length},
	})
}

// logRefusedBody records a refused secret-create body (413, 400). Threat
// model §4.2 R-AUD-1: such a refusal is not an event over a secret — there is
// no secret, and the name in it is untrusted — so it is a log record, not an
// audit record. The record carries the closed key set only: never the body,
// the name, or any part of either; body_len is a byte count.
func (s *secretRoutes) logRefusedBody(r *http.Request, p identity.Principal, requestID string, status int, class apperr.Class, bodyLen int) {
	if s.logger == nil {
		return
	}
	s.logger.InfoContext(r.Context(), "secret_create_rejected",
		"request_id", requestID,
		"error_class", string(class),
		"org_id", p.OrgID.String(),
		"principal_id", p.ID.String(),
		"status", status,
		"body_len", bodyLen,
	)
}

func actorType(k identity.Kind) audit.ActorType {
	switch k {
	case identity.KindAgent:
		return audit.ActorAgent
	case identity.KindService:
		return audit.ActorService
	default:
		return audit.ActorUser
	}
}
