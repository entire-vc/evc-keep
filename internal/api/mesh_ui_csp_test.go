package api

import (
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
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "base-uri 'none'", "form-action 'self'",
		"frame-ancestors https://a.example.test https://b.example.test"} {
		if !strings.Contains(csp, want) {
			t.Errorf("csp lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe") || strings.Contains(csp, "data:") || strings.Contains(csp, "*") {
		t.Errorf("csp is loose: %s", csp)
	}
	// No install record means nothing may frame the page.
	if !strings.HasSuffix(meshUICSP(nil), "frame-ancestors 'none'") || !strings.HasSuffix(meshUICSP(frameOrigins([]string{"bogus"})), "frame-ancestors 'none'") {
		t.Error("an empty origin list must yield frame-ancestors 'none'")
	}
}
