// Package reqid carries the per-request correlation id through a request's
// context: parsed from the client's X-Request-Id header when it looks safe
// to reuse, generated fresh otherwise.
package reqid

import (
	"context"
	"regexp"

	"github.com/google/uuid"
)

// HeaderName is the header a caller may set to propagate its own request id,
// and the header the response always carries back.
const HeaderName = "X-Request-Id"

// valid bounds an incoming request id to something safe to echo into a log
// line and a response header: short, and free of anything that could be
// mistaken for a format directive or a header-injection attempt.
//
// The length cap is the size of a UUID, and it is also what keeps a Keep
// token out: a token's random part is 52 characters, so no value this
// short can hold all of it, split or not — the echo of a client-supplied id
// into a response header and every log line of the request would otherwise
// carry a credential the scanner rule (which wants the "keep_<kind>_"
// prefix) does not see.
var valid = regexp.MustCompile(`^[A-Za-z0-9-]{1,36}$`)

// Valid reports whether v has the shape of a request id: what a caller that
// stores or logs one it did not generate itself must check first.
func Valid(v string) bool { return valid.MatchString(v) }

// FromHeader returns v if it is a valid request id, otherwise a fresh one.
func FromHeader(v string) string {
	if valid.MatchString(v) {
		return v
	}
	return New()
}

// New generates a fresh request id. Keep uses UUIDv7 for every entity id it
// issues, including this one, for the same reason: sortable by creation
// time without leaking a sequential counter.
func New() string {
	id, err := uuid.NewV7()
	if err != nil {
		// NewV7 only fails if the system's time/random source is broken.
		// Fall back to a still-unique, still-safe-to-log random id rather
		// than propagating the error into every request path.
		return uuid.NewString()
	}
	return id.String()
}

type ctxKey struct{}

// WithContext attaches a request id to ctx.
func WithContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the request id attached to ctx, or "" if none was set.
func FromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}
