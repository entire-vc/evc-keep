package api

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The origin that may frame the screen is taken from an install record and
// goes into a header: nothing in it may open a second directive or widen the
// source list.
func TestMeshUIFrameOriginRefusesWhatCouldWidenThePolicy(t *testing.T) {
	good := map[string]string{
		"https://mesh.example.test":          "https://mesh.example.test",
		"https://mesh.example.test/":         "https://mesh.example.test",
		"https://mesh.example.test:8443/app": "https://mesh.example.test:8443",
		"http://127.0.0.1:5000":              "http://127.0.0.1:5000",
	}
	for in, want := range good {
		if got, ok := frameOrigin(in); !ok || got != want {
			t.Errorf("frameOrigin(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	bad := []string{
		"", "mesh.example.test", "javascript:alert(1)", "ftp://mesh.example.test", "https://",
		"https://mesh.example.test; script-src *", "https://mesh.example.test, https://evil.example.test",
		"https://mesh.example.test\r\nX-Evil: 1", "https://*.example.test", "https://a b.example.test",
		"https://mesh.example.test'", "data:text/html,x",
	}
	for _, in := range bad {
		if got, ok := frameOrigin(in); ok {
			t.Errorf("frameOrigin(%q) accepted as %q", in, got)
		}
	}
}

func TestMeshUICSPShape(t *testing.T) {
	csp := meshUICSP(frameOrigins([]string{"https://a.example.test/x", "https://a.example.test", "https://b.example.test", "bogus"}))
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "font-src 'self'", "connect-src 'self'", "base-uri 'none'", "form-action 'self'",
		"frame-ancestors https://a.example.test https://b.example.test"} {
		if !strings.Contains(csp, want) {
			t.Errorf("csp lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe") || strings.Contains(csp, "data:") || strings.Contains(csp, "*") {
		t.Errorf("csp is loose: %s", csp)
	}
	// Fonts come from this origin only: no wildcard, no scheme, no other host.
	if fs := directiveSources(csp, "font-src"); len(fs) != 1 || fs[0] != "'self'" {
		t.Errorf("font-src = %v, want only 'self'", fs)
	}
	// No install record means nothing may frame the page.
	if !strings.HasSuffix(meshUICSP(nil), "frame-ancestors 'none'") || !strings.HasSuffix(meshUICSP(frameOrigins([]string{"bogus"})), "frame-ancestors 'none'") {
		t.Error("an empty origin list must yield frame-ancestors 'none'")
	}
}

// directiveSources returns the source list of one directive of a policy.
func directiveSources(csp, name string) []string {
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) > 0 && f[0] == name {
			return f[1:]
		}
	}
	return nil
}

// The fonts route serves the built-in files and nothing else, with the font
// type, only over TLS, without a session.
func TestMeshUIFontsRoute(t *testing.T) {
	mux := http.NewServeMux()
	(&meshUI{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).register(mux)
	get := func(p string, tlsOn bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		if tlsOn {
			req.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	want := []string{"jetbrains-mono-latin-400-normal.woff2", "jetbrains-mono-latin-ext-400-normal.woff2", "jetbrains-mono-cyrillic-400-normal.woff2"}
	for _, w := range []string{"400", "500", "600", "700"} {
		for _, sub := range []string{"latin", "latin-ext", "cyrillic"} {
			want = append(want, "inter-"+sub+"-"+w+"-normal.woff2")
		}
	}
	if len(meshUIFonts) != len(want) {
		t.Errorf("%d embedded fonts, want %d", len(meshUIFonts), len(want))
	}
	for _, name := range want {
		rec := get("/mesh/ui/fonts/"+name, true)
		body := rec.Body.Bytes()
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "font/woff2" || len(body) < 1024 || string(body[:4]) != "wOF2" {
			t.Errorf("%s: %d %q %d bytes", name, rec.Code, rec.Header().Get("Content-Type"), len(body))
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", name)
		}
		// Only the screen's own pages may load the file, and a cached font is
		// public data: nothing private is ever stored next to it.
		if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
			t.Errorf("%s: Cross-Origin-Resource-Policy = %q, want same-origin", name, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=604800" {
			t.Errorf("%s: Cache-Control = %q, want public, max-age=604800", name, got)
		}
		// Every served file is named by the style, and every name the style uses is served.
		if !strings.Contains(meshUIStyle, "url(/mesh/ui/fonts/"+name+")") {
			t.Errorf("%s is not used by the style", name)
		}
	}
	if n := strings.Count(meshUIStyle, "url(/mesh/ui/fonts/"); n != len(want) {
		t.Errorf("style names %d font files, want %d", n, len(want))
	}
	for _, p := range []string{"/mesh/ui/fonts/unknown.woff2", "/mesh/ui/fonts/inter-latin-400-normal.woff", "/mesh/ui/fonts/..%2fmesh_ui.go",
		"/mesh/ui/fonts/LICENSE-Inter.txt", "/mesh/ui/fonts/", "/mesh/ui/fonts/INTER-LATIN-400-NORMAL.WOFF2"} {
		if rec := get(p, true); rec.Code != http.StatusNotFound || rec.Header().Get("Content-Type") == "font/woff2" {
			t.Errorf("%s: %d %q, want 404", p, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	if rec := get("/mesh/ui/fonts/"+want[0], false); rec.Code != http.StatusNotFound {
		t.Errorf("plain HTTP served a font: %d", rec.Code)
	}
}
