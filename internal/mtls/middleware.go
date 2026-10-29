// Package mtls authenticates HTTP requests from an enrolled runner by
// its mTLS client certificate — org_id, runner_id and host come from the
// certificate alone, never from the request body or a header (ADR-001 §3.2,
// threat model §2.3: tenant, runner and host are read only from the
// certificate, never from the request body or headers).
//
// This package is deliberately a sibling of internal/runner and
// internal/builtin, not a subpackage of either — internal/api, which wires
// this middleware into the server's routes, cannot import internal/runner or
// internal/builtin (scripts/check-import-boundaries.sh's zone-internals
// rule), and this middleware carries nothing that rule protects: it holds no
// private key material, only the verification logic and the two small
// interfaces ([CAResolver], [RunnerChecker]) that hide where the CA
// certificate and the runner registry actually live.
package mtls

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/google/uuid"
)

// Principal is what a verified runner mTLS client certificate proves about
// the request that carries it. It is attached to the request context only
// by [RequireMTLS] — the sole source of these facts for the rest of the
// request, mirroring internal/identity.Principal's own contract.
type Principal struct {
	OrgID    uuid.UUID
	RunnerID uuid.UUID
	Host     string
	// Serial is the certificate's serial number in decimal-string form —
	// the same form internal/registry.Repo stores as runners.cert_serial —
	// needed by the renewal handler to know which serial it is replacing.
	Serial string
}

type contextKey struct{}

func withContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

// FromContext returns the Principal [RequireMTLS] attached, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(contextKey{}).(Principal)
	return p, ok
}

// CAResolver looks up an organization's CA certificate. Implemented by an
// adapter over internal/builtin/orgpki.Repo.Lookup, built in
// cmd/keep-server/main.go — the one place allowed to import both
// internal/builtin/orgpki and this package. Lookup must never generate a CA
// for an org that doesn't have one yet; see orgpki.Repo.Lookup's own doc for
// why (verifying a certificate must not have the side effect of minting a
// CA for an org an attacker merely claims to belong to).
type CAResolver interface {
	CACert(ctx context.Context, orgID uuid.UUID) (caCertDER []byte, ok bool, err error)
}

// RunnerChecker checks whether a runner is still active. Satisfied directly
// by *internal/registry.Repo — internal/registry is outside the
// zone-internals boundary, so internal/api and this package may depend on
// it concretely; this interface exists for unit-testing this package's
// certificate-parsing and chain-verification logic without a database, not
// because the boundary requires it.
type RunnerChecker interface {
	CheckActive(ctx context.Context, orgID, runnerID uuid.UUID, certSerial string) error
}

var (
	errNoCertificate     = errors.New("mtls: no client certificate presented")
	errMalformedSubject  = errors.New("mtls: certificate subject does not carry org_id, runner_id and host")
	errChainVerification = errors.New("mtls: certificate chain verification failed")
)

// RequireMTLS builds middleware for routes only a registered, non-revoked
// runner may call. The TLS listener it runs behind is configured with
// tls.RequestClientCert, not a static ClientCAs pool (see
// cmd/keep-server/main.go's doc): each organization has its own CA, so which
// CA a presented certificate must chain to is not knowable until the
// certificate's own claimed org_id is read — chain verification therefore
// happens here, at the application layer, not at the TLS handshake.
//
// A request bearing a valid certificate for organization A and organization
// B's id anywhere else in the request (body, header, path) still operates
// as A — nothing but the certificate is ever consulted for identity (card's
// red-run test #2). A revoked runner, or one presenting a certificate serial
// that predates its last renewal, is refused on this same path (test #3).
//
// Every failure — missing certificate, unparseable subject, chain
// verification failure, unknown/revoked/stale runner — writes the identical
// apperr.ClassUnauthenticated body and logs only a closed-set auth_reason,
// mirroring internal/identity.RequireAuth exactly and for the same reason:
// the specific cause is a local debug concern, never the caller's business.
// Backend failures return a static not-ready response instead of reporting
// the runner's otherwise valid credentials as rejected.
func RequireMTLS(ca CAResolver, runners RunnerChecker, logger *slog.Logger) func(http.Handler) http.Handler {
	return RequireMTLSWithRejection(ca, runners, logger, nil)
}

// RequireMTLSWithRejection reports a registry denial only after the client
// certificate has verified against its organization's CA. Unauthenticated
// claims never reach the callback. The callback cannot change the response.
func RequireMTLSWithRejection(ca CAResolver, runners RunnerChecker, logger *slog.Logger, rejected func(context.Context, Principal, string)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := reqid.FromContext(r.Context())

			p, reason, err := verify(r, ca, runners)
			if err != nil {
				logAuthFailure(r.Context(), logger, reason, requestID)
				if reason == "runner_rejected" && rejected != nil {
					rejected(r.Context(), p, requestID)
				}
				if reason == "backend" {
					writeNotReady(w, requestID)
					return
				}
				writeUnauthenticated(w, requestID)
				return
			}
			next.ServeHTTP(w, r.WithContext(withContext(r.Context(), p)))
		})
	}
}

func verify(r *http.Request, ca CAResolver, runners RunnerChecker) (Principal, string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return Principal{}, "no_certificate", errNoCertificate
	}
	leaf := r.TLS.PeerCertificates[0]

	if len(leaf.Subject.Organization) != 1 {
		return Principal{}, "malformed_subject", errMalformedSubject
	}
	orgID, err := uuid.Parse(leaf.Subject.Organization[0])
	if err != nil {
		return Principal{}, "malformed_subject", errMalformedSubject
	}
	runnerID, err := uuid.Parse(leaf.Subject.CommonName)
	if err != nil {
		return Principal{}, "malformed_subject", errMalformedSubject
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] == "" {
		return Principal{}, "malformed_subject", errMalformedSubject
	}
	host := leaf.DNSNames[0]

	caCertDER, ok, err := ca.CACert(r.Context(), orgID)
	if err != nil {
		return Principal{}, "backend", err // CA lookup
	}
	if !ok {
		// Do not distinguish a missing organization from an invalid chain,
		// including in structured authentication diagnostics.
		return Principal{}, "chain_verification_failed", errChainVerification
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return Principal{}, "backend", err // CA DER
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return Principal{}, "chain_verification_failed", errChainVerification
	}

	serial := leaf.SerialNumber.String()
	authenticated := Principal{OrgID: orgID, RunnerID: runnerID, Host: host, Serial: serial}
	if err := runners.CheckActive(r.Context(), orgID, runnerID, serial); err != nil {
		if errors.Is(err, registry.ErrRunnerRejected) {
			return authenticated, "runner_rejected", err
		}
		return Principal{}, "backend", err
	}

	return Principal{OrgID: orgID, RunnerID: runnerID, Host: host, Serial: serial}, "", nil
}

// logAuthFailure writes exactly one debug log line for a failed mTLS check
// — a fixed message template plus the closed auth_reason enum and
// request_id, never the certificate or any underlying error's own text.
// Mirrors internal/identity's logAuthFailure exactly.
func logAuthFailure(ctx context.Context, logger *slog.Logger, reason, requestID string) {
	if logger == nil {
		return
	}
	logger.DebugContext(ctx, "mtls: mTLS authentication failed", "auth_reason", reason, "request_id", requestID)
}

func writeUnauthenticated(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(apperr.Body{
		ErrorClass: string(apperr.ClassUnauthenticated),
		Message:    "authentication failed",
		RequestID:  requestID,
	})
}

// writeNotReady answers a backend failure encountered while resolving an
// org's CA or checking the registry — never the error's own text (see
// internal/identity's own writeNotReady for the same rule).
func writeNotReady(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(apperr.Body{
		ErrorClass: string(apperr.ClassNotReady),
		Message:    "database not reachable",
		RequestID:  requestID,
	})
}
