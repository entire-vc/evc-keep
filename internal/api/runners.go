package api

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"net/http"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// maxRunnerBodyBytes bounds every request body this file reads — a CSR is a
// few hundred bytes; this is generous headroom against a caller sending an
// oversized body, not a precise budget.
const maxRunnerBodyBytes = 64 * 1024

// ErrCertIssuerInvalidCSR is the sentinel a [CertIssuer] implementation must
// return for a CSR that doesn't parse, doesn't verify, or doesn't carry an
// Ed25519 key. It exists here (rather than this file checking
// internal/builtin/orgpki.ErrInvalidCSR directly) because internal/api may
// not import internal/builtin — see scripts/check-import-boundaries.sh's
// zone-internals rule; the cmd/keep-server adapter that implements
// CertIssuer over orgpki.Repo translates orgpki's own sentinel into this
// one.
var ErrCertIssuerInvalidCSR = errors.New("api: invalid certificate signing request")

// CertIssuer issues a runner's client certificate under an organization's
// CA. Implemented by an adapter over internal/builtin/orgpki.Repo, built in
// cmd/keep-server/main.go — the one place allowed to import both
// internal/builtin/orgpki and internal/api (zone-internals). RunnerCertIssued
// carries only public key material (a signed certificate, a CA certificate,
// a job-signing public key) — none of it is a secret.Value, so this file
// needs no redaction machinery for it, unlike enrolltoken.IssueResponse.
type CertIssuer interface {
	IssueRunnerCert(ctx context.Context, orgID, runnerID uuid.UUID, host string, csrDER []byte) (RunnerCertIssued, error)
}

// RunnerCertIssued is what [CertIssuer.IssueRunnerCert] returns.
type RunnerCertIssued struct {
	CertDER    []byte
	CACertDER  []byte
	SignKeyID  string
	SignPubKey []byte
	NotAfter   time.Time
}

// runnerCertResponse is the wire shape for both POST /runners/enroll and
// POST /runners/renew — a signed certificate plus the public PKI material a
// runner pins at enrollment (ADR-001 §3.2). Every field is public key
// material or an id; see TestRunnerResponseFieldsWithinAllowlist, a local
// copy of the keep-api-surface response-field guard until the shared
// reflection-based one lands.
type runnerCertResponse struct {
	RunnerID      uuid.UUID `json:"runner_id"`
	Certificate   []byte    `json:"certificate"`
	CACertificate []byte    `json:"ca_certificate"`
	SignKeyID     string    `json:"sign_key_id"`
	SignPubKey    []byte    `json:"sign_pub_key"`
	NotAfter      time.Time `json:"not_after"`
}

// revokeResult is the wire shape for POST /runners/{runner_id}/revoke — the
// threat model §4.3 "Result" shape, {ok, request_id}.
type revokeResult struct {
	OK        bool   `json:"ok"`
	RequestID string `json:"request_id"`
}

type enrollTokenIssueRequest struct {
	Host         string                 `json:"host"`
	PolicySHA256 string                 `json:"policy_sha256"`
	TTLSeconds   int64                  `json:"ttl_seconds,omitempty"`
	HostAttrs    *enrolltoken.HostAttrs `json:"host_attrs,omitempty"`
}

type runnerEnrollRequest struct {
	Token         string `json:"token"`
	Host          string `json:"host"`
	PolicySHA256  string `json:"policy_sha256"`
	CSR           []byte `json:"csr"`
	HPKEPublicKey []byte `json:"hpke_public_key,omitempty"`
}

type runnerRenewRequest struct {
	CSR []byte `json:"csr"`
}

// handleIssueEnrollToken is POST /runners/enroll-tokens, admin-only
// (requireTLS + identity.RequireAuth + requirePermission(PermManageRunners)
// wrap this in the router). The organization is always the caller's own
// principal.OrgID — never a URL or body value — the same reason
// internal/identity's own routes never take org_id from anywhere but the
// Principal (ADR-001 §6).
func handleIssueEnrollToken(tokens *enrolltoken.Repo, aud audit.Journaler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := reqid.FromContext(r.Context())
		principal, ok := identity.FromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
			return
		}

		var req enrollTokenIssueRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "malformed request body", requestID)
			return
		}

		res, err := tokens.Issue(r.Context(), enrolltoken.IssueParams{
			OrgID:        principal.OrgID,
			Host:         req.Host,
			PolicySHA256: req.PolicySHA256,
			CreatedBy:    principal.ID,
			HostAttrs:    req.HostAttrs,
			TTL:          time.Duration(req.TTLSeconds) * time.Second,
		})
		if err != nil {
			writeEnrollTokenIssueError(w, requestID, err)
			return
		}

		if _, err := aud.Append(r.Context(), audit.Record{
			RequestID: requestID, OrgID: principal.OrgID.String(), Scope: principal.Scope,
			Actor:  audit.Actor{Type: actorType(principal.Kind), ID: principal.ID.String(), Via: audit.ViaAPI},
			Action: audit.ActionRunnerEnrollTokenIssue,
			Target: audit.Target{Host: req.Host},
			Result: audit.Result{Status: audit.StatusOK},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
			return
		}
		body, err := res.Response().WireJSON()
		if err != nil {
			writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
			return
		}
		// This response body carries the one-time enrollment token itself —
		// never cacheable, by a browser, a proxy, or an admin's own client
		// (leak-review finding).
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}
}

func writeEnrollTokenIssueError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, enrolltoken.ErrInvalidHost),
		errors.Is(err, enrolltoken.ErrInvalidPolicyHash),
		errors.Is(err, enrolltoken.ErrInvalidHostAttrs),
		errors.Is(err, enrolltoken.ErrTTLTooLong):
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid enrollment token request", requestID)
	case errors.Is(err, enrolltoken.ErrOrgNotFound), errors.Is(err, enrolltoken.ErrIssuerNotFound):
		// Both collapse to the same uniform not-found response — an
		// authenticated admin's own org and own user row not resolving is
		// an internal inconsistency, not information to hand back with a
		// distinct shape.
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
	default:
		writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
	}
}

// handleEnrollRunner is POST /runners/enroll — reachable only over the TLS
// listener (requireTLS), with no prior identity of its own: the presented
// enrollment token, not a bearer token or a client certificate, is the only
// credential (a fresh runner has neither of those yet). The organization
// comes exclusively from redeeming the token; runner_id is generated fresh
// here — internal/enrolltoken.Redeemed carries only OrgID, by design (a
// token proves nothing about which runner will end up using it).
func handleEnrollRunner(tokens *enrolltoken.Repo, runners *registry.Repo, certs CertIssuer, aud audit.Journaler, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := reqid.FromContext(r.Context())

		var req runnerEnrollRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "malformed request body", requestID)
			return
		}

		// A syntactically-invalid CSR is checked before the one-time token
		// is redeemed: otherwise a typo'd CSR in an otherwise-correct
		// request would burn the operator's only enrollment token on a
		// request that could never have succeeded. The Ed25519 key-type
		// check belongs here too — CertIssuer.IssueRunnerCert rejects a
		// non-Ed25519 CSR with the same ErrInvalidCSR either way, but only
		// after the token is already spent, so checking it before Redeem
		// keeps this pre-check's promise for that case as well.
		// CertIssuer.IssueRunnerCert below still does the org-specific
		// validation (the CSR's signature verified again against the
		// stored request) that only it can do; this is a cheap pre-check,
		// not a replacement for it.
		csr, err := x509.ParseCertificateRequest(req.CSR)
		if err != nil || csr.CheckSignature() != nil {
			writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid certificate signing request", requestID)
			return
		}
		if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
			writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid certificate signing request", requestID)
			return
		}
		if req.HPKEPublicKey != nil {
			if err := registry.ValidateDeliveryPublicKey(req.HPKEPublicKey); err != nil {
				writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid delivery public key", requestID)
				return
			}
		}

		// Generated before Redeem: it depends on nothing Redeem reveals, so
		// generating it here (rather than after) is one fewer post-Redeem
		// step that could burn the token on a failure unrelated to the
		// token itself.
		runnerID, err := uuid.NewV7()
		if err != nil {
			writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
			return
		}

		redeemed, err := tokens.Redeem(r.Context(), enrolltoken.NewToken(req.Token),
			enrolltoken.RedeemParams{Host: req.Host, PolicySHA256: req.PolicySHA256})
		if err != nil {
			if !errors.Is(err, enrolltoken.ErrTokenRejected) { // enroll token backend
				writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
				return
			}
			if redeemed.OrgID != uuid.Nil {
				appendRunnerDenial(r.Context(), aud, logger, runnerTrustRecord(requestID, redeemed.OrgID, uuid.Nil, "", audit.ActionRunnerEnroll, audit.StatusFailed)) // enroll denied audit
			} else if redeemed.OrgID == uuid.Nil {
				logRunnerAuditFailure(r.Context(), logger, requestID, "unauthenticated enrollment")
			}
			// enrolltoken.ErrTokenRejected is the one error Redeem returns
			// for every caller-facing failure (reuse, expiry, wrong host,
			// wrong policy, unknown token) — see its own doc for why they
			// must stay indistinguishable (card's red-run test #1).
			writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "enrollment token rejected", requestID)
			return
		}

		// From here on, redeemed.OrgID is known and every remaining step
		// (cert issuance, then the runner row) necessarily comes after
		// Redeem — only Redeem reveals which org's CA to sign with. Any of
		// them failing releases the token (enrolltoken.Repo.Release's own
		// doc): the operator's one-time token should not be spent for an
		// infrastructure failure that had nothing to do with the token.
		issued, err := certs.IssueRunnerCert(r.Context(), redeemed.OrgID, runnerID, req.Host, req.CSR)
		if err != nil {
			if errors.Is(err, ErrCertIssuerInvalidCSR) {
				tokens.Release(r.Context(), redeemed)
				writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid certificate signing request", requestID)
				return
			}
			tokens.Release(r.Context(), redeemed)
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID) // enroll issuer
			return
		}

		serial, err := certSerial(issued.CertDER)
		if err != nil {
			tokens.Release(r.Context(), redeemed)
			writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
			return
		}
		record := runnerTrustRecord(requestID, redeemed.OrgID, runnerID, req.Host, audit.ActionRunnerEnroll, audit.StatusOK)
		journal, ok := aud.(audit.TransactionalJournaler)
		if !ok {
			tokens.Release(r.Context(), redeemed)
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "journal not reachable", requestID)
			return
		}
		var committed audit.Record
		err = runners.CreateEnrolledAudited(r.Context(), redeemed.OrgID, runnerID, req.Host, serial, issued.NotAfter,
			registry.Enrollment{HPKEPublicKey: req.HPKEPublicKey, HostAttrs: redeemed.HostAttrs}, func(tx pgx.Tx) error {
				var err error
				committed, err = journal.AppendTx(r.Context(), tx, record) // enroll ok audit
				return err
			})
		if err != nil {
			tokens.Release(r.Context(), redeemed)
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
			return
		}
		journal.LogCommitted(r.Context(), committed)
		writeRunnerCertResponse(w, runnerID, issued)
	}
}

// handleRenewRunner is POST /runners/renew — reachable only with a
// currently valid mTLS client certificate (requireTLS + RequireMTLS wrap
// this in the router). org_id, runner_id and host all come from the
// mtls.Principal the middleware already verified; nothing here reads
// them from the request again.
func handleRenewRunner(runners *registry.Repo, certs CertIssuer, aud audit.Journaler, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := reqid.FromContext(r.Context())
		principal, ok := mtls.FromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
			return
		}

		var req runnerRenewRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "malformed request body", requestID)
			return
		}

		issued, err := certs.IssueRunnerCert(r.Context(), principal.OrgID, principal.RunnerID, principal.Host, req.CSR)
		if err != nil {
			if errors.Is(err, ErrCertIssuerInvalidCSR) {
				writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid certificate signing request", requestID)
				return
			}
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID) // renew issuer
			return
		}

		serial, err := certSerial(issued.CertDER)
		if err != nil {
			writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
			return
		}
		record := runnerTrustRecord(requestID, principal.OrgID, principal.RunnerID, principal.Host, audit.ActionRunnerRenew, audit.StatusOK)
		journal, ok := aud.(audit.TransactionalJournaler)
		if !ok {
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "journal not reachable", requestID)
			return
		}
		var committed audit.Record
		err = runners.UpdateCertAudited(r.Context(), principal.OrgID, principal.RunnerID, principal.Serial, serial, issued.NotAfter, func(tx pgx.Tx) error {
			var err error
			committed, err = journal.AppendTx(r.Context(), tx, record) // renew ok audit
			return err
		})
		if err != nil {
			if errors.Is(err, registry.ErrRunnerUnknown) { // renew registry
				appendRunnerRenewDenial(r.Context(), aud, logger, principal, requestID)
				writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
			} else {
				writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
			}
			return
		}
		journal.LogCommitted(r.Context(), committed)
		writeRunnerCertResponse(w, principal.RunnerID, issued)
	}
}

func writeRunnerCertResponse(w http.ResponseWriter, runnerID uuid.UUID, issued RunnerCertIssued) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(runnerCertResponse{
		RunnerID:      runnerID,
		Certificate:   issued.CertDER,
		CACertificate: issued.CACertDER,
		SignKeyID:     issued.SignKeyID,
		SignPubKey:    issued.SignPubKey,
		NotAfter:      issued.NotAfter,
	})
}

// handleRevokeRunner is POST /runners/{runner_id}/revoke, admin-only
// (requireTLS + identity.RequireAuth + requirePermission(PermManageRunners)
// wrap this in the router). Like enroll-token issuance, the organization is
// always the caller's own principal.OrgID — an admin can only ever revoke a
// runner in their own organization; a runner_id from another organization
// is indistinguishable from one that never existed (mirrors
// internal/registry.Repo.Revoke's own contract, which mirrors
// internal/identity.Repo.Revoke).
func handleRevokeRunner(runners *registry.Repo, aud audit.Journaler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := reqid.FromContext(r.Context())
		principal, ok := identity.FromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
			return
		}
		runnerID, err := uuid.Parse(r.PathValue("runner_id"))
		if err != nil {
			writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
			return
		}

		if err := runners.Revoke(r.Context(), principal.OrgID, runnerID); err != nil {
			if errors.Is(err, registry.ErrRunnerUnknown) { // revoke registry
				writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", requestID)
			} else {
				writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
			}
			return
		}

		if err := appendRunnerRevokeAudit(r.Context(), aud, principal, runnerID, requestID); err != nil {
			// Revocation remains effective, but an unaudited action must not
			// be reported as successful. Never expose the journal's error text.
			writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(revokeResult{OK: true, RequestID: requestID})
	}
}

func appendRunnerRevokeAudit(ctx context.Context, aud audit.Journaler, principal identity.Principal, runnerID uuid.UUID, requestID string) error {
	_, err := aud.Append(ctx, audit.Record{
		RequestID: requestID, OrgID: principal.OrgID.String(), Scope: principal.Scope,
		Actor:  audit.Actor{Type: actorType(principal.Kind), ID: principal.ID.String(), Via: audit.ViaAPI},
		Action: audit.ActionRunnerRevoke,
		Target: audit.Target{RunnerID: runnerID.String()},
		Policy: audit.Policy{Decision: audit.DecisionAllow},
		Result: audit.Result{Status: audit.StatusOK},
	})
	return err
}

// requirePermission builds middleware for an admin-only route: the
// authenticated principal (identity.RequireAuth must run first) needs perm
// in its own org's scope. A user's permissions come from their membership
// role there directly; an agent's come from its sponsor's role intersected
// with the agent's own grants ([identity.Repo.EffectiveAgentPermissions]) —
// PermManageRunners is not in identity.DefaultAgentGrants, so an agent needs
// an explicit grant even when its sponsor is an org admin. A principal with
// no membership row in this scope at all (including every service
// principal, which never has one) is denied, not merely ungranted.
func requirePermission(repo *identity.Repo, perm identity.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := reqid.FromContext(r.Context())
			principal, ok := identity.FromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
				return
			}

			granted, err := hasPermission(r.Context(), repo, principal, perm)
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "database not reachable", requestID)
				return
			}
			if !granted {
				writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "permission denied", requestID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hasPermission(ctx context.Context, repo *identity.Repo, p identity.Principal, perm identity.Permission) (bool, error) {
	scope := tenancy.Org(p.OrgID).String()
	var perms map[identity.Permission]bool
	var err error
	if p.Kind == identity.KindAgent {
		perms, err = repo.EffectiveAgentPermissions(ctx, p, scope)
	} else {
		perms, err = repo.UserPermissions(ctx, p.OrgID, p.ID, scope)
	}
	if err != nil {
		return false, err
	}
	return perms[perm], nil
}

// requireTLS builds middleware refusing any request that did not arrive
// over the TLS listener (cmd/keep-server runs two: a plain one for
// /healthz and /readyz, and a TLS one — see its own doc — carrying every
// credential-bearing route). r.TLS is nil on the plain listener and always
// non-nil on the TLS one (Go's net/http sets it for every TLS connection,
// whether or not a client certificate was actually presented), so this
// check fails closed by construction if a route were ever mistakenly
// registered only on the plain listener's mux.
func requireTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", reqid.FromContext(r.Context()))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// decodeJSON reads and decodes r's body under [maxRunnerBodyBytes], with
// DisallowUnknownFields so a caller cannot silently pass an extra field this
// handler never validated.
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRunnerBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// certSerial returns a signed certificate's serial number in the same
// decimal-string form internal/registry.Repo stores and
// internal/mtls reads back off a live TLS connection's certificate —
// the two must agree, or a freshly issued certificate could never pass its
// own registry check.
func certSerial(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	return cert.SerialNumber.String(), nil
}

// runnerTrustRecord contains identifiers and closed result/policy classes,
// never token text, certificate serials or an underlying error string.
func runnerTrustRecord(requestID string, org, runner uuid.UUID, host string, action audit.Action, status audit.ResultStatus) audit.Record {
	actor := audit.Actor{Type: audit.ActorRunner, Via: audit.ViaAPI}
	target := audit.Target{Host: host}
	if runner != uuid.Nil {
		actor.ID = runner.String()
		target.RunnerID = runner.String()
	}
	record := audit.Record{RequestID: requestID, OrgID: org.String(), Scope: "org:" + org.String(), Actor: actor, Action: action, Target: target, Policy: audit.Policy{Decision: audit.DecisionAllow}, Result: audit.Result{Status: status}}
	if status == audit.StatusFailed {
		record.Policy.Decision = audit.DecisionDeny
		record.Result.ErrorClass = audit.ErrClassPermissionDenied
	}
	return record
}

func appendRunnerRenewDenial(ctx context.Context, aud audit.Journaler, logger *slog.Logger, principal mtls.Principal, requestID string) {
	appendRunnerDenial(ctx, aud, logger, runnerTrustRecord(requestID, principal.OrgID, principal.RunnerID, principal.Host, audit.ActionRunnerRenew, audit.StatusFailed)) // renew denied audit
}

func appendRunnerDenial(ctx context.Context, aud audit.Journaler, logger *slog.Logger, record audit.Record) {
	if _, err := aud.Append(ctx, record); err != nil {
		logRunnerAuditFailure(ctx, logger, record.RequestID, "runner denial journal unavailable")
	}
}

func logRunnerAuditFailure(ctx context.Context, logger *slog.Logger, requestID, message string) {
	if logger != nil {
		logger.WarnContext(ctx, message, slog.String("request_id", requestID), slog.String("error_class", "permission_denied"))
	}
}
