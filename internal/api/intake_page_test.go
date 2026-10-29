package api

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

type pageInputService struct {
	InputService
	view intake.View
	err  error
}

func (s pageInputService) Read(context.Context, string) (intake.View, error) { return s.view, s.err }

func TestInputPageClosedSurfaces(t *testing.T) {
	wantCSP := inputPageExpectedCSP(t)
	token := canary.New().Value(1)
	probe := canary.Of(token)
	if !probe.In(base64.StdEncoding.EncodeToString([]byte("xx" + token))) {
		t.Fatal("token detector missed planted leak")
	}
	for _, serviceErr := range []error{nil, intake.ErrGone, intake.ErrUnavailable, errors.New(token)} {
		var logs bytes.Buffer
		view := intake.View{RequestID: "019a0000-0000-7000-8000-000000000001", SecretName: "sample", Scope: "org:sample", StoreName: "Primary", Class: "dev", RequestedBy: "agent sample", Sponsor: "sample sponsor", PublicKey: make([]byte, 32), SigningKey: make([]byte, 32), Signature: make([]byte, 64)}
		h := NewRouter(obs.New(&logs), nil, Deps{Input: pageInputService{view: view, err: serviceErr}})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/input/"+token, nil))
		want := http.StatusOK
		if serviceErr == intake.ErrGone {
			want = http.StatusGone
		} else if serviceErr != nil {
			want = http.StatusServiceUnavailable
		}
		if w.Code != want {
			t.Fatalf("page status: got %d, want %d", w.Code, want)
		}
		if logs.Len() == 0 {
			t.Fatal("page log capture not exercised")
		}
		if probe.In(w.Body.String()) || probe.In(logs.String()) {
			t.Fatal("page capability escaped into response or log")
		}
		for _, values := range w.Header() {
			for _, value := range values {
				if probe.In(value) {
					t.Fatal("page capability escaped into header")
				}
			}
		}
		for name, want := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"} {
			if w.Header().Get(name) != want {
				t.Fatalf("missing page header %s", name)
			}
		}
		if w.Header().Get("Content-Security-Policy") != wantCSP {
			t.Fatal("CSP does not match exact policy for delivered assets")
		}
		if serviceErr == nil {
			textarea := regexp.MustCompile(`<textarea\b[^>]*>`).FindString(w.Body.String())
			for _, attr := range []string{`autocomplete="off"`, `autocapitalize="off"`, `spellcheck="false"`, `autocorrect="off"`} {
				name := strings.SplitN(attr, "=", 2)[0]
				count := len(regexp.MustCompile(`(?i)\s`+name+`(?:\s*=|\s|/?>)`).FindAllString(textarea, -1))
				if count > 1 {
					t.Fatalf("duplicate textarea privacy attribute %s", name)
				}
				if !strings.Contains(textarea, " "+attr) {
					t.Fatalf("missing textarea privacy attribute %s", attr)
				}
			}
			for _, text := range []string{"sample", "org:sample", "Primary", "dev", "agent sample", "sample sponsor", "data-public=", "data-signing=", "data-signature=", "disabled"} {
				if !strings.Contains(w.Body.String(), text) {
					t.Fatalf("missing page metadata %s", text)
				}
			}
		}
	}
}

func TestInputPageEscapesMetadata(t *testing.T) {
	planted := `<script src="https://outside.example.invalid/injected.js"></script>`
	view := intake.View{SecretName: planted, Scope: planted, StoreName: planted, Class: planted, RequestedBy: planted, Sponsor: planted}
	w := httptest.NewRecorder()
	NewRouter(obs.New(&bytes.Buffer{}), nil, Deps{Input: pageInputService{view: view}}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/input/synthetic", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("page status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), planted) || !strings.Contains(w.Body.String(), "&lt;script") {
		t.Fatal("metadata escaped its HTML text boundary")
	}
}

func TestInputPageScriptIntegrity(t *testing.T) {
	inputPageExpectedCSP(t)
}

// Derive hashes from HTTP-delivered bytes, independently of the asset package.
// Exact equality rejects extra sources, duplicate directives and overrides.
func inputPageExpectedCSP(t *testing.T) string {
	t.Helper()
	h := NewRouter(obs.New(&bytes.Buffer{}), nil, Deps{Input: pageInputService{}})
	page := httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/input/synthetic", nil))
	script := httptest.NewRecorder()
	h.ServeHTTP(script, httptest.NewRequest(http.MethodGet, "/input/assets.js", nil))
	if script.Code != http.StatusOK || script.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Fatal("script route unavailable")
	}
	sum := sha512.Sum384(script.Body.Bytes())
	integrity := "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
	if !strings.Contains(html.UnescapeString(page.Body.String()), `integrity="`+integrity+`"`) {
		t.Fatal("script integrity does not match delivered bytes")
	}
	style := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(page.Body.String())
	if len(style) != 2 {
		t.Fatal("embedded style missing")
	}
	styleSum := sha512.Sum384([]byte(style[1]))
	styleIntegrity := "sha384-" + base64.StdEncoding.EncodeToString(styleSum[:])
	want := "default-src 'none'; script-src '" + integrity + "'; style-src '" + styleIntegrity + "'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
	for _, response := range []*httptest.ResponseRecorder{page, script} {
		if response.Header().Get("Content-Security-Policy") != want {
			t.Fatal("CSP does not match exact policy for delivered assets")
		}
	}
	return want
}
