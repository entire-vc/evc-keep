package api

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/google/uuid"
)

// The metadata route answers with a server-generated request id: the one a
// caller sends in X-Request-Id is neither echoed in the header nor in the
// body. Other routes keep their propagate-if-valid behavior.
func TestMetadataRequestIDIsServerGenerated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewRouter(logger, nil, Deps{Audit: audit.NewJournal(nil), Mesh: &MeshDeps{Vault: touchVault{}, Repo: meshext.NewRepo(nil)}})
	const injected = "caller-chosen-id-123"
	do := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.TLS = &tls.ConnectionState{}
		r.Header.Set(reqid.HeaderName, injected)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	rec := do("/orgs/" + uuid.NewString() + "/mesh/secrets/k/metadata")
	got := rec.Header().Get(reqid.HeaderName)
	if got == injected || strings.Contains(rec.Body.String(), injected) || !reqid.Valid(got) || !strings.Contains(rec.Body.String(), got) {
		t.Fatalf("metadata route: header %q body %s", got, rec.Body.String())
	}
	if other := do("/healthz").Header().Get(reqid.HeaderName); other != injected {
		t.Fatalf("shared request-id semantics changed: %q", other)
	}
}
