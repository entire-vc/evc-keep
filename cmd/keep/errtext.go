package main

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/reqid"
)

const (
	maxErrTextRunes = 512
	// maxRequestIDLen is not the request id policy (internal/reqid.Valid is);
	// it stays because the pinned runner.go that scripts/ci-runner-response-proof.py
	// overlays onto this tree still sizes a text cut with it.
	maxRequestIDLen = 64
	unexpectedValue = "(unexpected value)"
)

// sanitizeText makes server-supplied text safe to print on a terminal: every
// control (Cc: C0, DEL, C1 — ESC among them) and format (Cf: bidi overrides,
// zero-width) rune is dropped, line breaks become a space, invalid UTF-8 is
// dropped, and the result is cut to max runes with a trailing ellipsis.
func sanitizeText(s string, max int) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size <= 1:
			continue
		case isLineBreak(r):
			r = ' '
		case unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r):
			continue
		}
		if n == max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// isLineBreak: LF, CR and the Unicode line/paragraph separators (U+2028/9).
func isLineBreak(r rune) bool {
	return r == '\n' || r == '\r' || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}

// safeClass echoes a server-supplied error_class only when it is one of
// apperr's closed set; anything else is not printed.
func safeClass(c string) string {
	for _, k := range apperr.Classes() {
		if string(k) == c {
			return c
		}
	}
	return unexpectedValue
}

// safeRequestID passes a request id through only if it has the shape
// internal/reqid accepts (1–36 of [A-Za-z0-9-], or empty); otherwise it is
// not printed. The server's cap keeps a 52-character token random part out
// of the echo, so the CLI must not accept anything the server would not.
func safeRequestID(id string) string {
	if id != "" && !reqid.Valid(id) {
		return unexpectedValue
	}
	return id
}

// classMessages is the closed set of texts the CLI prints for a server error.
// The wire message is untrusted even under a known class (it can carry any
// printable text, a secret value included), so it never reaches the terminal:
// the class alone selects a static local text (threat model §4.3).
var classMessages = map[string]string{
	"internal":                 "internal server error",
	"invalid_argument":         "invalid argument",
	"not_ready":                "server not ready",
	"unauthenticated":          "authentication required",
	"not_found":                "not found",
	"secret_not_found":         "secret not found",
	"override_locked":          "override locked",
	"no_store_bound":           "no store bound",
	"ambiguous_context":        "ambiguous context",
	"already_exists":           "already exists",
	"permission_denied":        "permission denied",
	"rate_limited":             "rate limited",
	"payload_too_large":        "payload too large",
	"metadata_not_approved":    "metadata not approved",
	"deployment_not_confirmed": "deployment not confirmed",
	"revoke_pending":           "revoke pending",
}

// staticMessage returns the local text for a server error class; a class
// outside the closed set gets the generic one.
func staticMessage(class string) string {
	if m, ok := classMessages[class]; ok {
		return m
	}
	return "request failed"
}

// errBadResponse replaces a decoder error for a 2xx body: time.ParseError and
// json.SyntaxError quote the body, so the cause is never wrapped.
var errBadResponse = errors.New("parse server response: invalid body")

// decodeBody is the one place a 2xx body is decoded into a result: a failure
// is errBadResponse, never the decoder's own error.
func decodeBody(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return errBadResponse
	}
	return nil
}
