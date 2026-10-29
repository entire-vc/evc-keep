package identity

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/google/uuid"
)

// RequireAuth builds middleware that authenticates every request via its
// bearer token and, on success, attaches the resulting [Principal] to the
// request's context — the only place org_id (or any other identity fact)
// comes from for the rest of that request (ADR-001 §6, this package's own
// acceptance requirement). Every client-facing failure — missing header,
// malformed token, unknown token, expired, revoked — writes back the
// identical apperr.ClassUnauthenticated body; [Repo.Authenticate]'s more
// specific error is never read for that decision, so there is no path by
// which it could leak into the response. A database failure inside
// Authenticate is a different case entirely and answers 503, never 401 —
// see [authReason]'s doc.
//
// logger must be built from internal/obs (see internal/api.NewRouter's own
// doc) — every log line this middleware writes goes through its allow-list,
// not around it. It may be nil, in which case authentication still works
// but nothing is logged (used by tests that don't care about the log leg).
func RequireAuth(repo *Repo, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := reqid.FromContext(r.Context())

			token, ok := bearerToken(r)
			if !ok {
				logAuthFailure(r.Context(), logger, "malformed", requestID)
				writeUnauthenticated(w, requestID)
				return
			}
			p, err := repo.Authenticate(r.Context(), token)
			if err != nil {
				reason := authReason(err)
				logAuthFailure(r.Context(), logger, reason, requestID)
				if !errors.Is(err, ErrUnauthenticated) {
					// A database failure, not an authentication verdict —
					// answering 401 here would make a down dependency look
					// like every caller's token is wrong.
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

// authReason maps an [Repo.Authenticate] error to the closed set of
// reasons this package's own design decision allows into the debug log —
// never the error's own text (which could itself be a database error
// carrying connection details) and never the token. "backend" covers any
// error that doesn't wrap [ErrUnauthenticated] at all.
func authReason(err error) string {
	switch {
	case errors.Is(err, ErrTokenMalformed):
		return "malformed"
	case errors.Is(err, ErrTokenExpired):
		return "expired"
	case errors.Is(err, ErrTokenRevoked):
		return "revoked"
	case errors.Is(err, ErrUnauthenticated):
		return "unknown"
	default:
		return "backend"
	}
}

// logAuthFailure writes exactly one debug log line for an authentication
// failure — a fixed message template plus the closed auth_reason enum and
// request_id, never the token or the underlying error's own text (this
// package's own design decision; internal/obs's own allow-list also
// filters any other key, but the message and the values passed here must
// not depend on that filter to stay safe).
func logAuthFailure(ctx context.Context, logger *slog.Logger, reason, requestID string) {
	if logger == nil {
		return
	}
	logger.DebugContext(ctx, "identity: authentication failed", "auth_reason", reason, "request_id", requestID)
}

// bearerToken extracts the token from "Authorization: Bearer <token>". It
// never returns the header's raw value on a mismatch — only ok=false —
// since a malformed Authorization header could itself carry something
// that looks like a credential.
// BearerToken extracts the bearer token of r, if it carries one.
func BearerToken(r *http.Request) (Token, bool) { return bearerToken(r) }

func bearerToken(r *http.Request) (Token, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return Token{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if token == "" {
		return Token{}, false
	}
	return NewToken(token), true
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

// writeNotReady answers a database failure encountered while
// authenticating — never the error's own text (see internal/api's own
// handleReadyz for the same rule: a connection failure's message can carry
// details pulled from KEEP_DATABASE_URL).
func writeNotReady(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(apperr.Body{
		ErrorClass: string(apperr.ClassNotReady),
		Message:    "database not reachable",
		RequestID:  requestID,
	})
}

// RequireOrgMatch builds middleware for a route whose path carries an
// org_id segment (e.g. "GET /orgs/{org_id}/..."): it compares that segment
// against the Principal's own OrgID (put in context by [RequireAuth],
// which must run first) and responds 404 — never 403 — on a mismatch, so a
// caller cannot use the response to probe whether a resource exists in an
// organization that isn't theirs (this package's own acceptance
// requirement: a foreign org_id in the URL must answer 404, not 403, so it
// can never be used as an oracle). pathParam is the http.ServeMux wildcard
// name, e.g. "org_id" for "/orgs/{org_id}/...".
func RequireOrgMatch(pathParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := reqid.FromContext(r.Context())
			p, ok := FromContext(r.Context())
			if !ok {
				// No Principal means RequireAuth didn't run first — that is
				// a wiring bug, not a client error, but the safe response
				// is still the uniform not-found shape, never a 500 that
				// might describe what went wrong.
				writeNotFound(w, requestID)
				return
			}
			urlOrgID, err := uuid.Parse(r.PathValue(pathParam))
			if err != nil || urlOrgID != p.OrgID {
				writeNotFound(w, requestID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeNotFound(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(apperr.Body{
		ErrorClass: string(apperr.ClassNotFound),
		Message:    "not found",
		RequestID:  requestID,
	})
}
