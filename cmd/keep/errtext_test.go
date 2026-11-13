package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// hostileBodies are error bodies a malicious or compromised server could
// send: every control character the terminal acts on (C0 incl. ESC, DEL,
// C1, bidi overrides) sits in each of the three echoed fields.
func hostileBodies(c canary.Canary) map[string]apiError {
	evil := "\x1b[2J\x1b]0;pwned\x07\u202e\u2066\x7f\u009b\u0085\u2028\u2029\r\n" + c.Value(0)
	return map[string]apiError{
		"class":      {ErrorClass: "internal" + evil, Message: "boom", RequestID: "r1"},
		"message":    {ErrorClass: "internal", Message: "boom" + evil, RequestID: "r1"},
		"request_id": {ErrorClass: "internal", Message: "boom", RequestID: "r1" + evil},
		"unknown":    {ErrorClass: "totally_made_up", Message: "boom", RequestID: "r1"},
	}
}

func hasTerminalControl(s string) bool {
	for _, r := range s {
		if r == '\n' {
			continue
		}
		if r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

func stubErr(t *testing.T, body apiError) (*client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(body)
	}))
	return newClient(srv.URL, "org-1", "tok", false, &bytes.Buffer{}), srv.Close
}

// TestReportErrStripsControlCharsFromServerBody: a server-supplied
// error_class/message must never put raw control sequences on the terminal.
func TestReportErrStripsControlCharsFromServerBody(t *testing.T) {
	c := canary.New()
	for name, body := range hostileBodies(c) {
		t.Run(name, func(t *testing.T) {
			cl, closeSrv := stubErr(t, body)
			defer closeSrv()
			_, err := cl.do("GET", "/secrets", nil, nil)
			var stderr bytes.Buffer
			if code := reportErr(&stderr, err); code != 1 {
				t.Fatalf("exit %d, want 1", code)
			}
			out := strings.TrimSuffix(stderr.String(), "\n")
			if hasTerminalControl(out) || strings.Contains(out, "\n") {
				t.Fatalf("stderr carries a control character: %q", out)
			}
			if name == "unknown" || name == "class" {
				if !strings.Contains(out, "(unexpected value)") {
					t.Fatalf("class outside the closed set not replaced: %q", out)
				}
			}
			if name == "unknown" && strings.Contains(out, "totally_made_up") {
				t.Fatalf("unknown class echoed: %q", out)
			}
		})
	}
}

// TestPrintAPIErrorStripsControlChars: same for `keep runner` commands.
func TestPrintAPIErrorStripsControlChars(t *testing.T) {
	c := canary.New()
	for name, body := range hostileBodies(c) {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(body)
			var stderr bytes.Buffer
			printAPIError(&stderr, bytes.NewReader(raw))
			out := strings.TrimSuffix(stderr.String(), "\n")
			if hasTerminalControl(out) || strings.Contains(out, "\n") {
				t.Fatalf("stderr carries a control character: %q", out)
			}
		})
	}
}

// TestSanitizeControlHasPositiveControl: the detector above must see what it
// is meant to catch, and a well-formed body must pass through untouched.
func TestSanitizeControlHasPositiveControl(t *testing.T) {
	for _, bad := range []string{"a\x1bb", "a\x7fb", "a\u009bb", "a\u202eb", "a\u2066b", "a\x00b"} {
		if !hasTerminalControl(bad) {
			t.Fatalf("hasTerminalControl misses %q", bad)
		}
		if got := sanitizeText(bad, 512); hasTerminalControl(got) {
			t.Fatalf("sanitizeText(%q) = %q", bad, got)
		}
	}
	if got := sanitizeText("secret \"x\" not found", 512); got != "secret \"x\" not found" {
		t.Fatalf("clean text altered: %q", got)
	}
	if got := sanitizeText("a\nb", 512); got != "a b" {
		t.Fatalf("newline not turned into a space: %q", got)
	}
	long := strings.Repeat("\u00e9", 600)
	if got := sanitizeText(long, 512); len([]rune(got)) != 513 || !strings.HasSuffix(got, "…") {
		t.Fatalf("long text not cut to 512 runes + ellipsis: %d runes", len([]rune(got)))
	}
	if got := sanitizeText("a\xffb", 512); got != "a�b" && got != "ab" {
		t.Fatalf("invalid UTF-8 not neutralised: %q", got)
	}
}

// TestSafeRequestIDRejectsEachBadShape: every guard in safeRequestID alone.
func TestSafeRequestIDRejectsEachBadShape(t *testing.T) {
	for name, id := range map[string]string{
		"too long":   strings.Repeat("a", 65),
		"cap 37":     strings.Repeat("a", 37),
		"cap 52":     strings.Repeat("a", 52),
		"cap 64":     strings.Repeat("a", 64),
		"underscore": "req_1",
		"dot":        "req.1",
		"bare esc":   "\x1b",
		"bare bell":  "\x07",
		"space":      "a b",
		"newline":    "a\n",
		"non-ascii":  "é",
	} {
		if got := safeRequestID(id); got != unexpectedValue {
			t.Fatalf("%s: safeRequestID(%q) = %q", name, id, got)
		}
	}
	for _, ok := range []string{"", "req-1", "Req-1-B", strings.Repeat("a", 36)} {
		if got := safeRequestID(ok); got != ok {
			t.Fatalf("safeRequestID(%q) = %q, want unchanged", ok, got)
		}
	}
}

// TestAPIErrorErrorIsTerminalSafe: any caller printing the error with %v.
func TestAPIErrorErrorIsTerminalSafe(t *testing.T) {
	c := canary.New()
	for name, body := range hostileBodies(c) {
		b := body
		if out := (&b).Error(); hasTerminalControl(out) || strings.Contains(out, "\n") {
			t.Fatalf("%s: Error() carries a control character: %q", name, out)
		}
	}
}

// TestOutputWritersStripStoredControlChars: the server stores name,
// description etc. as given, so the table writers must filter them too.
func TestOutputWritersStripStoredControlChars(t *testing.T) {
	evil := "x\x1b]0;pwned\x07\x1b[2J\u202e\u2028"
	s := secret{Name: "db" + evil, Scope: evil, Class: evil, Type: evil, Description: evil, ProviderRef: evil}
	s.Store.Name, s.Store.Provider = evil, evil
	var b bytes.Buffer
	_ = writeSecretTable(&b, []secret{s})
	_ = writeSecretDetail(&b, s)
	_ = writeVersionTable(&b, []secretVersion{{Version: evil, Status: evil, Fingerprint: evil}})
	_ = writeAuditVerifyDetail(&b, auditVerifyResult{BrokenID: evil, BreakKind: evil})
	if out := b.String(); hasTerminalControl(out) {
		t.Fatalf("output carries a control character: %q", out)
	}
}

// TestRedactedHeaderDumpStripsControlChars: --debug prints response header
// names; a server-chosen name must not carry terminal controls.
func TestRedactedHeaderDumpStripsControlChars(t *testing.T) {
	h := http.Header{"X-Evil\u009b2J\u202e": {"a\u009b2J\u202e"}}
	if out := redactedHeaderDump(h); hasTerminalControl(out) {
		t.Fatalf("header dump carries a control character: %q", out)
	}
}

// TestPrintAPIErrorNeverPrintsMessage: the server's message does not reach
// stderr for any class; the class (closed set) and request id still do.
func TestPrintAPIErrorNeverPrintsMessage(t *testing.T) {
	c := canary.New()
	for _, class := range []string{"internal", "totally_made_up", ""} {
		raw, _ := json.Marshal(apiError{ErrorClass: class, Message: "m " + c.Value(0), RequestID: "r1"})
		var stderr bytes.Buffer
		printAPIError(&stderr, bytes.NewReader(raw))
		if c.In(stderr.String()) || strings.Contains(stderr.String(), "m kc") || !strings.Contains(stderr.String(), "request_id=r1") {
			t.Errorf("class %q: %q", class, stderr.String())
		}
	}
	raw, _ := json.Marshal(apiError{ErrorClass: "internal", Message: "boom", RequestID: "r1"})
	var stderr bytes.Buffer
	printAPIError(&stderr, bytes.NewReader(raw))
	if !strings.Contains(stderr.String(), "keep: internal (request_id=r1)") || strings.Contains(stderr.String(), "boom") {
		t.Errorf("positive control: %q", stderr.String())
	}
}
