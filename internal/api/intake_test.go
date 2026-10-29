package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInputLinkIssueRequiresAuthentication(t *testing.T) {
	h := NewRouter(nil, nil, Deps{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/input-links", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("issuance without identity: status %d", w.Code)
	}
}

type tokenInputService struct {
	InputService
	err error
}

func (s tokenInputService) Complete(context.Context, string, intake.Envelope) (intake.Result, error) {
	return intake.Result{Version: "1", Fingerprint: "kfp1:test:abcdefghijklmnop"}, s.err
}

func TestInputLinkTokenClosedSurfaces(t *testing.T) {
	token := canary.New().Value(1) + "AAAAAAA"
	probe := canary.Of(token)
	var logs bytes.Buffer
	control := slog.New(slog.NewJSONHandler(&logs, nil))
	control.Info(base64.StdEncoding.EncodeToString([]byte("x" + token)))
	if !probe.In(logs.String()) {
		t.Fatal("token detector missed planted log")
	}
	logs.Reset()
	for _, err := range []error{nil, intake.ErrInvalid, intake.ErrGone, intake.ErrUnavailable} {
		h := NewRouter(obs.New(&logs), nil, Deps{Input: tokenInputService{err: err}})
		for _, body := range []string{`{"enc":"","ciphertext":""}`, `{`} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/input/"+token, strings.NewReader(body)))
			if w.Code != http.StatusOK && w.Code != http.StatusBadRequest && w.Code != http.StatusGone && w.Code != http.StatusServiceUnavailable {
				t.Fatal("input route not exercised")
			}
			if probe.In(w.Body.String()) || probe.In(logs.String()) {
				t.Fatal("input token escaped to HTTP or log")
			}
			for _, values := range w.Header() {
				for _, value := range values {
					if probe.In(value) {
						t.Fatal("input token escaped to header")
					}
				}
			}
		}
	}
	if logs.Len() == 0 {
		t.Fatal("token log capture not exercised")
	}
}

func TestInputLinkCacheHeaders(t *testing.T) {
	for _, err := range []error{nil, intake.ErrInvalid, intake.ErrGone, intake.ErrUnavailable} {
		h := NewRouter(obs.New(io.Discard), nil, Deps{Input: tokenInputService{err: err}})
		for _, body := range []string{`{"enc":"","ciphertext":""}`, `{`} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/input/synthetic-token", strings.NewReader(body)))
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("input response allows caching")
			}
		}
	}
}
