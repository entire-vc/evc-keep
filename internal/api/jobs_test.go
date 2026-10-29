package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

type fakeJobs struct {
	err   error
	calls int
	peer  mtls.Principal
}

func (f *fakeJobs) Poll(_ context.Context, p mtls.Principal) (runnerproto.SignedJob, bool, error) {
	f.calls++
	f.peer = p
	return runnerproto.SignedJob{}, false, f.err
}
func (f *fakeJobs) Material(_ context.Context, p mtls.Principal, id string) (runnerproto.ValueEnvelope, error) {
	f.calls++
	f.peer = p
	return runnerproto.ValueEnvelope{JobID: id, Sealed: []byte("ciphertext"), SealedFingerprintKey: []byte("key-ciphertext")}, f.err
}
func (f *fakeJobs) Result(_ context.Context, p mtls.Principal, _ string, _ runnerproto.Result) error {
	f.calls++
	f.peer = p
	return f.err
}

func jobRouter(t *testing.T, f *fakeJobs) (http.Handler, *x509.Certificate, *bytes.Buffer) {
	t.Helper()
	base, db, pki, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	cred := enrollForTest(t, base, db, org, admin, "jobs.example.test")
	var logs bytes.Buffer
	h := NewRouter(obs.New(&logs), db, Deps{Identity: identity.NewRepo(db), Tokens: enrolltoken.NewRepo(db), Runners: registry.NewRepo(db), Certs: pki, CA: pki, Jobs: f})
	return h, parseCert(t, cred.Certificate), &logs
}

func TestRunnerJobHTTPRejectsUntrustedPeer(t *testing.T) {
	f := &fakeJobs{}
	h, _, _ := jobRouter(t, f)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/runners/jobs/next"}, {"POST", "/runners/jobs/value"}, {"POST", "/runners/jobs/01900000-0000-7000-8000-000000000000/result"},
	} {
		for _, tls := range []bool{false, true} {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(`{}`))
			if tls {
				req = tlsRequest(req, nil)
			}
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			want := http.StatusNotFound
			if tls {
				want = http.StatusUnauthorized
			}
			if res.Code != want {
				t.Fatal("runner job route bypassed required TLS identity")
			}
		}
	}
	if f.calls != 0 {
		t.Fatal("untrusted peer reached job service")
	}
}

func TestRunnerJobHTTPClosedRequestsAndErrorLeak(t *testing.T) {
	f := &fakeJobs{}
	h, cert, logs := jobRouter(t, f)
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal("job id")
	}
	for _, tc := range []struct{ path, body string }{
		{"/runners/jobs/value", `{"job_id":"` + id.String() + `","recipient":"override"}`},
		{"/runners/jobs/value", `{"job_id":"` + id.String() + `","job_id":"` + id.String() + `"}`},
		{"/runners/jobs/" + id.String() + "/result", `{"ok":true,"stdout":"hidden"}`},
		{"/runners/jobs/" + id.String() + "/result", `{"ok":false,"error_class":"raw-provider-error"}`},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tlsRequest(httptest.NewRequest("POST", tc.path, bytes.NewBufferString(tc.body)), cert))
		if rec.Code != http.StatusBadRequest {
			t.Fatal("request outside closed schema accepted")
		}
	}
	if f.calls != 0 {
		t.Fatal("invalid body reached job service")
	}
	c := canary.New()
	f.err = errors.New(c.Value(1))
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/runners/jobs/next", nil},
		{"POST", "/runners/jobs/value", runnerproto.ValueRequest{JobID: id.String()}},
		{"POST", "/runners/jobs/" + id.String() + "/result", runnerproto.Result{ErrorClass: runnerproto.ErrClassInternal}},
	} {
		rec := doJSON(t, h, tc.method, tc.path, tc.body, "", cert)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatal("unexpected backend error response")
		}
		if c.In(rec.Body.String()) || c.In(logs.String()) {
			t.Fatal("backend error leaked into runner HTTP or log")
		}
	}
	if f.calls != 3 || f.peer.Serial != cert.SerialNumber.String() {
		t.Fatal("verified certificate identity was not used")
	}
	f.err = nil
	rec := doJSON(t, h, "POST", "/runners/jobs/value", runnerproto.ValueRequest{JobID: id.String()}, "", cert)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("ciphertext response or cache policy incorrect")
	}
}
