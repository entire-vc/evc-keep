// Package obs is Keep's only sanctioned way to write a log line. It wraps
// log/slog with a JSON handler that passes through a closed set of
// attribute keys and silently drops everything else — "silently" for the
// caller, not for the log: each drop also emits its own warning record
// naming the rejected key (never its value), so a call site that tries to
// log something new gets caught instead of quietly losing data forever.
//
// This exists because a request/response body, a raw error string from
// outside the process, or any other free-form value must never reach a log
// line — see CONTRIBUTING.md and the threat model's §4.4 (logs and errors).
// The allow-list is the enforcement point for that rule, not a convention
// contributors are trusted to remember.
package obs

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/tokenshape"
)

// allowed is the closed set of attribute keys this package will forward to
// the underlying JSON handler as-is. It mirrors the threat model's list:
// method, route, status, request_id, duration_ms, error_class.
//
// "stack" is one addition beyond that list, and only the panic-recovery
// path in internal/api uses it. A raw Go call-stack (runtime/debug.Stack)
// is NOT safe as-is: alongside function names and file:line pairs, each
// frame's call-site line prints its argument words verbatim — e.g.
// `pkg.f(0xc000123456, 0x1a)` — and those can be real values, not just
// pointers. [sanitizeStack] strips that argument list (and each frame's
// "+0xNN" program-counter offset) before a "stack" value is ever forwarded,
// so what survives really is only function names and file:line pairs — see
// the threat model's §4.4 rule that a logged panic stack must carry no
// argument values, only frame identity.
//
// "auth_reason" is the other addition, added together with internal/identity
// (see this file's own note below about revisiting the suffix rule
// alongside the authentication work): a closed enum
// (malformed/unknown/expired/revoked/backend — internal/identity.authReason
// is the only writer), never a token, a token id, or any other
// credential-shaped value.
//
// "action" is a further addition: the threat model's §4.2 states the
// journal's own append log line carries the record id, action, and
// request_id — the audited action's name (e.g. "secret.create_ref"), never any other
// R-AUD-1 record field. internal/audit.Action is a closed registry of
// constants that Append checks before anything is stored or logged, which is
// what makes it the same kind of value as "route" or "error_class" for logging
// purposes, and why it belongs on this fixed list rather than under the
// "_id"/"_name" suffix rule below, which is for entity identifiers.
//
// "body_len" is the byte count of a refused request body — a number, never
// the body — added for the secret-create refusal record (threat model §4.2).
//
// "count" is a number of records not delivered (the key-level outcomes left
// unjournaled when keep-server stops) — an integer, never a record. Because
// the name is generic, [isAllowedAttr] drops any "count" or "body_len" whose
// value is not an integer, so a string cannot ride under either.
//
// "kind" is added for the deploy.healthcheck event: a closed enum,
// runnerproto.HealthKind's own list
// (unit-active/http), same category as "status" and "error_class" above —
// never the healthcheck's own response body, which internal/runner/health
// never keeps past the pass/fail comparison in the first place.
var allowed = map[string]bool{
	"method":      true,
	"route":       true,
	"status":      true,
	"request_id":  true,
	"duration_ms": true,
	"error_class": true,
	"stack":       true,
	"auth_reason": true,
	"action":      true,
	"kind":        true,
	"body_len":    true,
	"count":       true,
}

// isAllowed reports whether k may pass through unfiltered. Beyond the fixed
// set above, an entity id or name is allowed under any key that says so by
// its shape — "secret_id", "owner_name", the bare "id" or "name" — because
// Keep's components (catalog, carriers, audit, …) each name their own
// entities and a fixed list of every such key would need editing for every
// new component. The values behind these keys must themselves already be
// safe to log (ids and names, never a secret's value) — that invariant is
// enforced by callers and by pkg/secret's own String()/LogValue() behavior,
// not by this filter.
//
// That suffix rule is wider than the fixed list above, and it stays that
// way deliberately — but it is not a blank check for any identifier a
// future component invents. It must NOT be used for a session id, a bearer
// token itself, or any other credential-shaped value: unlike a token_id
// (a row identifier — not replayable on its own, same category as
// "secret_id" or "owner_name") or "auth_reason" (a closed enum, added
// alongside the fixed list above), a live session id or the token string
// itself can be replayed as an access credential, and logging it is
// functionally the same mistake as logging the secret value this whole
// package exists to keep out of a log line. internal/identity is the case
// this was written for; revisit this suffix rule again for any future
// component that names something replayable.
//
// A value shaped like a Keep token's random part is blanked from the
// rendered line whatever key, message or nesting carried it (see
// [NewHandler]) — a second layer behind the types' own redaction, not a
// licence to pass tokens to the logger.
func isAllowed(k string) bool {
	if allowed[k] {
		return true
	}
	if k == "id" || k == "name" {
		return true
	}
	return strings.HasSuffix(k, "_id") || strings.HasSuffix(k, "_name")
}

// isAllowedAttr is [isAllowed] plus the value kind for the numeric keys: a
// "count" or "body_len" carries an integer or nothing.
func isAllowedAttr(a slog.Attr) bool {
	if !isAllowed(a.Key) {
		return false
	}
	if a.Key == "count" || a.Key == "body_len" {
		switch a.Value.Resolve().Kind() {
		case slog.KindInt64, slog.KindUint64:
			return true
		default:
			return false
		}
	}
	return true
}

// stackArgsPattern matches a call-site line's trailing argument list, e.g.
// the "(0xc000123456, 0x1a)" in "pkg.f(0xc000123456, 0x1a)" — always the
// last parenthesized group on the line, since a receiver type earlier in
// the same name (as in "main.(*Foo).Bar(...)") is never at the end.
var stackArgsPattern = regexp.MustCompile(`\([^()]*\)\s*$`)

// stackOffsetPattern matches a "file:line" row's trailing program-counter
// offset, e.g. the " +0x64" in "\t/path/file.go:26 +0x64".
var stackOffsetPattern = regexp.MustCompile(`\s+\+0x[0-9a-fA-F]+\s*$`)

// sanitizeStack strips a Go call-stack (runtime/debug.Stack output) down to
// function names and file:line pairs — see the "stack" entry in [allowed]'s
// doc for why the raw text isn't safe to log as-is. It is applied
// unconditionally to any value logged under the "stack" key, not just by
// convention at the one call site that currently uses it: the allow-list
// exists so a call site doesn't have to be trusted to remember a rule.
func sanitizeStack(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		line = stackOffsetPattern.ReplaceAllString(line, "")
		line = stackArgsPattern.ReplaceAllString(line, "(...)")
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

// Handler is a slog.Handler that enforces the allow-list above. Attrs
// nested inside a group (slog.Group(...)) are checked as a single top-level
// key and dropped as a unit when disallowed, never recursed into — letting
// an arbitrary key through one level down would defeat the point of a
// closed list.
type Handler struct {
	next slog.Handler
}

// NewHandler wraps a plain JSON handler writing to w with the allow-list
// filter. level sets the minimum level the underlying handler emits.
//
// Everything the handler writes also passes through [scrubWriter]: the
// allow-list filters keys, and the "*_id" suffix rule lets any value
// through under a key such as "principal_id", so a token's random part is
// blanked on the rendered line — in a value at any depth, in the message,
// under any allowed key — after slog has marshaled whatever it was given.
// It recognizes the canonical text form only (one unbroken run); a token
// re-encoded (base64 of a byte slice, hex) or split by other characters is
// not caught here, which is why the types carrying tokens redact
// themselves and this is only the layer behind them.
func NewHandler(w io.Writer, level slog.Level) *Handler {
	return &Handler{next: slog.NewJSONHandler(scrubWriter{w}, &slog.HandlerOptions{Level: level})}
}

// scrubWriter blanks anything shaped like the random part of a Keep
// identity token in each write. slog's JSON handler emits one whole record
// per Write, so a token is never split across two calls.
type scrubWriter struct{ w io.Writer }

func (s scrubWriter) Write(p []byte) (int, error) {
	if _, err := s.w.Write(tokenshape.Redact(p, []byte("[REDACTED]"))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// New returns a ready-to-use logger writing filtered JSON lines to w.
func New(w io.Writer) *slog.Logger {
	return slog.New(NewHandler(w, slog.LevelInfo))
}

func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	filtered := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	var dropped []string
	r.Attrs(func(a slog.Attr) bool {
		a.Value = a.Value.Resolve() // once: slog would call LogValue again on the original
		if !isAllowedAttr(a) {
			dropped = append(dropped, a.Key)
			return true
		}
		if a.Key == "stack" {
			a = slog.String("stack", sanitizeStack(a.Value.String()))
		}
		filtered.AddAttrs(a)
		return true
	})
	if err := h.next.Handle(ctx, filtered); err != nil {
		return err
	}
	for _, k := range dropped {
		if err := h.warnDropped(ctx, r.Time, k); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var kept []slog.Attr
	var dropped []string
	for _, a := range attrs {
		a.Value = a.Value.Resolve() // once: slog would call LogValue again on the original
		if !isAllowedAttr(a) {
			dropped = append(dropped, a.Key)
			continue
		}
		if a.Key == "stack" {
			a = slog.String("stack", sanitizeStack(a.Value.String()))
		}
		kept = append(kept, a)
	}
	for _, k := range dropped {
		_ = h.warnDropped(context.Background(), time.Now(), k)
	}
	return &Handler{next: h.next.WithAttrs(kept)}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{next: h.next.WithGroup(name)}
}

// warnDropped writes straight to the wrapped handler, bypassing this
// handler's own Handle (and so its filter): the warning's only attribute is
// the disallowed key's *name*, which is always safe to show, but "key" is
// itself not on the allow-list and would otherwise be dropped recursively.
func (h *Handler) warnDropped(ctx context.Context, t time.Time, k string) error {
	r := slog.NewRecord(t, slog.LevelWarn, "dropped disallowed log attribute", 0)
	r.AddAttrs(slog.String("key", k))
	return h.next.Handle(ctx, r)
}
