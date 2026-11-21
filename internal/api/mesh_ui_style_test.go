package api

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The command in an empty state is one unit a person copies: on a narrow
// screen it moves to its own line whole and never breaks between words
// (`keep` on one line, `input-link NAME` on the next). A command longer than
// the line (a long secret name) scrolls inside its own box instead of
// widening the page. The rule is read from the stylesheet the screen serves.
func TestMeshUIEmptyStateCommandKeepsOneLine(t *testing.T) {
	mux := http.NewServeMux()
	(&meshUI{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).register(mux)
	req := httptest.NewRequest(http.MethodGet, "/mesh/ui/app.css", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("app.css: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rules := regexp.MustCompile(`(?m)(?:^|\})\.empty code\{([^}]*)\}`).FindAllStringSubmatch(rec.Body.String(), -1)
	if len(rules) != 1 {
		t.Fatalf("%d rules for .empty code in app.css, want 1", len(rules))
	}
	decl := map[string]string{}
	for _, d := range strings.Split(rules[0][1], ";") {
		if k, v, ok := strings.Cut(d, ":"); ok {
			decl[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	want := map[string]string{
		"white-space": "nowrap",       // the command never breaks between words
		"display":     "inline-block", // it moves to the next line as a whole
		"max-width":   "100%",         // and never sticks out of its line
		"overflow-x":  "auto",         // a longer one scrolls inside its box
	}
	for k, w := range want {
		if got := decl[k]; got != w {
			t.Errorf(".empty code %s = %q, want %q", k, got, w)
		}
	}
	// No other rule that reaches a code element (another selector, a media
	// query, !important) may set these properties and undo the rule above.
	css := strings.ToLower(regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(rec.Body.String(), ""))
	undoes := map[string]bool{"overflow": true, "all": true, "text-wrap": true, "text-wrap-mode": true, "width": true, "min-width": true}
	ours := 0
	for _, m := range regexp.MustCompile(`([^{};]+)\{([^{}]*)\}`).FindAllStringSubmatch(css, -1) {
		sel := strings.TrimSpace(m[1])
		if sel == ".empty code" {
			if ours++; ours > 1 {
				t.Errorf("a second .empty code rule (in a media query?): %q", m[2])
			}
			continue
		}
		if !regexp.MustCompile(`(^|[^a-z-])code([^a-z-]|$)`).MatchString(sel) {
			continue
		}
		for _, d := range strings.Split(m[2], ";") {
			k, _, _ := strings.Cut(d, ":")
			k = strings.TrimSpace(k)
			if _, set := want[k]; set || undoes[k] {
				t.Errorf("rule %q sets %s on a code element", sel, k)
			}
		}
	}
}
