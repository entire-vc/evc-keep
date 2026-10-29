package obs

import (
	"io"
	"log"
	"log/slog"
	"strings"
)

// ServerErrorLog returns the *log.Logger for http.Server.ErrorLog. Without
// one, net/http writes its own diagnostics — TLS handshake failures, recovered
// handler panics, accept errors — through the standard library's global
// logger straight to stderr, outside this package's allow-list.
//
// What net/http hands over is free text built from the peer's address and
// from error strings that can echo what the peer sent, so none of it is
// forwarded: each line becomes one record with a fixed message and an
// error_class chosen from a closed set by the line's own prefix. The detail
// is deliberately lost. A handler panic inside internal/api's logged()
// wrapper is additionally logged, with a sanitized stack, by its recovery
// middleware; one raised outside it (the auth and request-id layers) leaves
// only the handler_panic class here.
//
// Every http.Server Keep starts (the API listener and the runner mTLS
// listener alike) must set ErrorLog to this.
func ServerErrorLog(logger *slog.Logger) *log.Logger {
	return log.New(serverErrorWriter{logger}, "", 0)
}

type serverErrorWriter struct{ l *slog.Logger }

func (w serverErrorWriter) Write(p []byte) (int, error) {
	w.l.Error("http server error", "error_class", classifyServerError(string(p)))
	return len(p), nil
}

var _ io.Writer = serverErrorWriter{}

func classifyServerError(line string) string {
	switch {
	case strings.HasPrefix(line, "http: TLS handshake error"):
		return "tls_handshake"
	case strings.HasPrefix(line, "http: panic serving"), strings.HasPrefix(line, "http2: panic serving"):
		return "handler_panic"
	default:
		return "http_server"
	}
}
