// Attacks against the Keep Server skeleton (MR !5): request_id handling,
// and the panic-recovery path exercised through the REAL router assembly
// (api.NewRouter), rather than a hand-built mux — internal/api/api_test.go
// already covers panic recovery through a purpose-built /panics route; this
// file's independent contribution is proving the same property holds for
// the actual registered routes, end to end, which a same-package test that
// builds its own mux never demonstrates.
package security

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// TestServer_ReadyzPanicsSafelyThroughRealRouter: a nil pool makes
// pool.Ping panic inside the ACTUAL /readyz handler wired up by
// api.NewRouter — no hand-rolled route, no white-box access to `logged`.
// The response must still be a clean 500/error_class=internal, and the
// logged stack must carry no raw argument/PC values (0x…), matching the
// contract's stricter rule, not just "no canary".
func TestServer_ReadyzPanicsSafelyThroughRealRouter(t *testing.T) {
	var buf bytes.Buffer
	logger := obs.New(&buf)
	handler := api.NewRouter(logger, nil, api.Deps{}) // nil pool: pool.Ping panics

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"error_class":"internal"`)) {
		t.Errorf("response body missing error_class=internal: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "nil pointer") || strings.Contains(rec.Body.String(), "panic") {
		t.Errorf("response body leaked panic detail: %s", rec.Body.String())
	}
	if strings.Contains(buf.String(), "0x") {
		t.Errorf("logged stack retains a raw argument/PC value: %s", buf.String())
	}
}

// TestServer_RequestIDHeaderInjection: the end-to-end request_id property
// (§4.3), attacked from the header-injection angle — malformed
// X-Request-Id values that a naive implementation might echo verbatim into
// a header (CRLF injection, oversized input, control bytes, unicode) must
// never reach the response header unmodified; reqid.valid requires
// [A-Za-z0-9-]{1,36}, so all of these must fall back to a fresh generated
// id instead.
func TestServer_RequestIDHeaderInjection(t *testing.T) {
	var buf bytes.Buffer
	handler := api.NewRouter(obs.New(&buf), nil, api.Deps{})

	attacks := []string{
		"x\r\nSet-Cookie: evil=1",
		"x\nX-Injected: true",
		strings.Repeat("a", 10000),
		"id\x00withnull",
		"日本語-id",
		"",
		"../../../etc/passwd",
		"<script>alert(1)</script>",
	}
	for _, id := range attacks {
		t.Run(id[:min(len(id), 30)], func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Header.Set("X-Request-Id", id)
			handler.ServeHTTP(rec, req)

			got := rec.Header().Get("X-Request-Id")
			if got == id {
				t.Errorf("malformed X-Request-Id %q was echoed back verbatim instead of being replaced", id)
			}
			if strings.ContainsAny(got, "\r\n\x00") {
				t.Errorf("response X-Request-Id header itself contains control characters: %q", got)
			}
			// The header must be a single value, not split by the injected CRLF.
			if len(rec.Header().Values("X-Request-Id")) != 1 {
				t.Errorf("X-Request-Id split into %d header values, want 1", len(rec.Header().Values("X-Request-Id")))
			}
		})
	}
}

// TestServer_DuplicateRequestIDHeaders pins down a fact about net/http
// itself, not a defense the application implements: Header.Get always
// returns the FIRST value of a repeated header, so a second, attacker-
// controlled X-Request-Id (e.g. appended by a misconfigured proxy that
// adds rather than replaces) can never surface through the handler's own
// Get("X-Request-Id") calls. This is stdlib behavior this file happens to
// rely on for request_id handling — worth pinning here so a future
// standard-library change or a switch away from Header.Get would be
// caught, not proof that the server defends against duplicate headers on
// its own.
func TestServer_DuplicateRequestIDHeaders(t *testing.T) {
	c := canary.New()
	handler := api.NewRouter(obs.New(&bytes.Buffer{}), nil, api.Deps{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Add("X-Request-Id", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	req.Header.Add("X-Request-Id", c.Value(1)) // second value, shaped like a canary
	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("X-Request-Id")
	if c.In(got) {
		t.Errorf("second X-Request-Id header value leaked into the response: %q", got)
	}
}

// TestServer_ValidRequestIDIsEchoedAndCorrelates is the positive control:
// a well-formed id really is reused verbatim (compliance, not a leak — see
// api_test.go's comment on this distinction) and really does show up in
// the log line, so the two tests above are shown to distinguish something
// real rather than always failing shut.
func TestServer_ValidRequestIDIsEchoedAndCorrelates(t *testing.T) {
	var buf bytes.Buffer
	handler := api.NewRouter(obs.New(&buf), nil, api.Deps{})
	const id = "req-abc123-XYZ"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", id)
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-Id"); got != id {
		t.Fatalf("valid id was not echoed verbatim: got %q, want %q", got, id)
	}
	if !strings.Contains(buf.String(), id) {
		t.Fatalf("valid id never appears in the log line:\n%s", buf.String())
	}
}
