package api

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/reqid"
)

// withRequestID resolves the request id for r (from X-Request-Id if valid,
// generated otherwise — see internal/reqid), echoes it in the response
// header, and attaches it to the request's context for every handler and
// every log line downstream.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := reqid.FromHeader(r.Header.Get(reqid.HeaderName))
		w.Header().Set(reqid.HeaderName, id)
		next.ServeHTTP(w, r.WithContext(reqid.WithContext(r.Context(), id)))
	})
}

// statusRecorder captures the status code a handler wrote, defaulting to
// 200 to match http.ResponseWriter's own implicit behavior when a handler
// never calls WriteHeader itself.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// Unwrap lets ResponseController reach deadline controls on the real writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// logged wraps a single registered route: it times the call, recovers a
// panic if the handler has one, and emits exactly one structured log line
// per request through internal/obs.
//
// Recovery lives here rather than in an outer middleware so the log line
// still knows which route panicked. On a panic:
//   - the response is a plain 500 with error_class=internal — never the
//     panic value itself, since a handler could panic with anything,
//     including a value that came from the request;
//   - the log line's "stack" field is a Go call stack (debug.Stack()). The
//     raw text isn't safe on its own — see internal/obs's doc for why
//     "stack" is the one exception to its allow-list, and how obs itself
//     (not this call site) strips argument values before the line is
//     written.
func logged(route string, logger *slog.Logger, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		requestID := reqid.FromContext(r.Context())

		defer func() {
			if rv := recover(); rv != nil {
				logger.Error("panic recovered",
					"method", r.Method,
					"route", route,
					"status", http.StatusInternalServerError,
					"request_id", requestID,
					"error_class", string(apperr.ClassInternal),
					"duration_ms", time.Since(start).Milliseconds(),
					"stack", string(debug.Stack()),
				)
				writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
				return
			}
			logger.Info("http_request",
				"method", r.Method,
				"route", route,
				"status", rec.status,
				"request_id", requestID,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		}()

		h(rec, r)
	}
}
