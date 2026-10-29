package mtls

import (
	"bytes"
	"context"
	"fmt"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type failedCA struct {
	der []byte
	err error
}

func (f failedCA) CACert(context.Context, uuid.UUID) ([]byte, bool, error) { return f.der, true, f.err }
func TestRequireMTLS_CAFailureClassification(t *testing.T) {
	org, runner := uuid.New(), uuid.New()
	ca := newTestCA(t, org)
	leaf := ca.issueLeaf(t, org, runner, "h", 1)
	c := canary.New()
	diagnostic := c.Value(1)
	if !c.In(diagnostic) {
		t.Fatal("canary positive control failed")
	}
	for name, resolver := range map[string]CAResolver{"backend": failedCA{err: fmt.Errorf("CA: %s", diagnostic)}, "bad-der": failedCA{der: []byte(diagnostic)}, "valid": fakeCA{org: ca.certDER}} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			called := false
			handler := RequireMTLS(resolver, fakeRunners{}, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, withPeerCert(httptest.NewRequest(http.MethodPost, "/runners/renew", nil), leaf))
			if c.In(rec.Body.String()) || c.In(logs.String()) {
				t.Error("CA error text escaped into response or logs")
			}
			if name == "valid" {
				if !called {
					t.Fatal("valid CA positive control rejected")
				}
				return
			}
			if called || rec.Code != 503 || !strings.Contains(logs.String(), `"auth_reason":"backend"`) {
				t.Fatalf("CA failure classified incorrectly: status %d, handler %v", rec.Code, called)
			}
		})
	}
}
