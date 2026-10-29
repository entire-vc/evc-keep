package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

type fakeVerify struct {
	*fakeDeployments
	report    deployment.VerifyReport
	submitErr error
	reportErr error
	requests  []deployment.VerifyRequest
}

func (s *fakeVerify) SubmitVerify(_ context.Context, in deployment.VerifyRequest) (deployment.VerifyReport, error) {
	s.requests = append(s.requests, in)
	r := s.report
	r.SecretID, r.Scope = in.SecretID, in.Scope
	return r, s.submitErr
}

func (s *fakeVerify) VerifyReport(_ context.Context, _ uuid.UUID, _ string) (deployment.VerifyReport, error) {
	r := s.report
	if len(s.requests) > 0 {
		r.Scope = s.requests[0].Scope
	}
	return r, s.reportErr
}

func verifyFixture(t *testing.T, rep deployment.VerifyReport) (*deployFixture, *fakeVerify) {
	t.Helper()
	svc := &fakeVerify{fakeDeployments: &fakeDeployments{}, report: rep}
	return newDeployFixture(t, svc), svc
}

func decodeVerify(t *testing.T, body []byte) CarrierVerifyResult {
	t.Helper()
	var out CarrierVerifyResult
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal("verify answer is not JSON")
	}
	return out
}

func TestCarrierVerify_PendingThenDone(t *testing.T) {
	id := uuid.New()
	at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	rep := deployment.VerifyReport{Version: "7", Fingerprint: "kfp1:k1:abcdefghijklmnop", Items: []deployment.VerifyItem{
		{CarrierID: id, Host: "h1", TargetKind: runnerproto.TargetFile, TargetPath: "/srv/a", State: deployment.VerifyPending},
		{CarrierID: uuid.New(), Host: "h2", TargetKind: runnerproto.TargetFile, TargetPath: "/srv/b", State: deployment.VerifyMatch, LastVerifiedAt: &at},
	}}
	f, svc := verifyFixture(t, rep)
	rec := f.do(http.MethodPost, "/v1/carriers/verify", f.bearer, map[string]any{"secret": "db-password", "request_id": "vr-1"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pending verification = %d, want 202", rec.Code)
	}
	out := decodeVerify(t, rec.Body.Bytes())
	if out.OK || out.RequestID != "vr-1" || out.Version != "7" || len(out.Carriers) != 2 || out.Carriers[0].Status != "pending" || out.Carriers[0].FingerprintMatch != nil {
		t.Fatal("pending shape wrong")
	}
	if out.Carriers[1].FingerprintMatch == nil || !*out.Carriers[1].FingerprintMatch {
		t.Fatal("answered carrier must carry fingerprint_match")
	}
	if len(svc.requests) != 1 || svc.requests[0].SecretID != f.secret.ID || svc.requests[0].RequestID != "vr-1" {
		t.Fatal("service did not receive the resolved secret and request id")
	}
	svc.report.Items[0].State = deployment.VerifyMatch
	rec = f.do(http.MethodGet, "/v1/carriers/verify/vr-1", f.bearer, nil)
	if rec.Code != http.StatusOK || !decodeVerify(t, rec.Body.Bytes()).OK {
		t.Fatal("finished all-match verification must be 200 ok")
	}
	svc.report.Items[0].State = deployment.VerifyMismatch
	rec = f.do(http.MethodGet, "/v1/carriers/verify/vr-1", f.bearer, nil)
	if out = decodeVerify(t, rec.Body.Bytes()); rec.Code != http.StatusOK || out.OK || *out.Carriers[0].FingerprintMatch {
		t.Fatal("a mismatch is a finished, not-ok verification")
	}
}

func TestCarrierVerify_DefaultRequestIDAndEmptyList(t *testing.T) {
	f, _ := verifyFixture(t, deployment.VerifyReport{Version: "7", Fingerprint: "kfp1:k1:abcdefghijklmnop"})
	rec := f.do(http.MethodPost, "/v1/carriers/verify", f.bearer, map[string]any{"secret": "db-password"})
	out := decodeVerify(t, rec.Body.Bytes())
	if rec.Code != http.StatusOK || !out.OK || out.RequestID == "" || out.Carriers == nil || !strings.Contains(rec.Body.String(), `"carriers":[]`) {
		t.Fatal("nothing to verify is ok, done, with an empty list and a generated request id")
	}
}

func TestCarrierVerify_Refusals(t *testing.T) {
	for name, tc := range map[string]struct {
		body map[string]any
		err  error
		code int
	}{
		"no secret":         {map[string]any{}, nil, http.StatusBadRequest},
		"bad request id":    {map[string]any{"secret": "db-password", "request_id": "a b"}, nil, http.StatusBadRequest},
		"unknown secret":    {map[string]any{"secret": "nope"}, nil, http.StatusNotFound},
		"not found":         {map[string]any{"secret": "db-password"}, deployment.ErrNotFound, http.StatusNotFound},
		"conflict":          {map[string]any{"secret": "db-password"}, deployment.ErrConflict, http.StatusConflict},
		"rate limited":      {map[string]any{"secret": "db-password"}, deployment.ErrVerifyRateLimited, http.StatusTooManyRequests},
		"too many carriers": {map[string]any{"secret": "db-password"}, deployment.ErrTooManyCarriers, http.StatusBadRequest},
		"backend down":      {map[string]any{"secret": "db-password"}, deployment.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			f, svc := verifyFixture(t, deployment.VerifyReport{})
			if tc.err != nil {
				svc.submitErr = fmt.Errorf("%w: LEAKMARK /srv/secret-path", tc.err)
			}
			rec := f.do(http.MethodPost, "/v1/carriers/verify", f.bearer, tc.body)
			if rec.Code != tc.code {
				t.Fatalf("status = %d, want %d", rec.Code, tc.code)
			}
			if strings.Contains(rec.Body.String(), "LEAKMARK") || strings.Contains(rec.Body.String(), "/srv/") || strings.Contains(rec.Body.String(), "host") {
				t.Fatal("an error named a carrier detail")
			}
		})
	}
}

func TestCarrierVerify_RequiresAuthenticationAndMetadataRead(t *testing.T) {
	f, svc := verifyFixture(t, deployment.VerifyReport{})
	if rec := f.do(http.MethodPost, "/v1/carriers/verify", "", map[string]any{"secret": "db-password"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous POST = %d, want 401", rec.Code)
	}
	if rec := f.do(http.MethodGet, "/v1/carriers/verify/vr-1", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET = %d, want 401", rec.Code)
	}
	outsider := f.mustToken(identity.KindUser, f.mustAdmin("other-admin").ID, "ws:"+uuid.NewString())
	if rec := f.do(http.MethodPost, "/v1/carriers/verify", outsider, map[string]any{"secret": "db-password"}); rec.Code == http.StatusAccepted || rec.Code == http.StatusOK || len(svc.requests) != 0 {
		t.Fatal("a token scoped elsewhere reached the verification")
	}
	// Reading a verification needs metadata rights at the secret's scope,
	// not only knowledge of the request id.
	if rec := f.do(http.MethodPost, "/v1/carriers/verify", f.bearer, map[string]any{"secret": "db-password", "request_id": "vr-2"}); rec.Code != http.StatusOK {
		t.Fatal("owner could not start a verification")
	}
	if rec := f.do(http.MethodGet, "/v1/carriers/verify/vr-2", f.bearer, nil); rec.Code != http.StatusOK {
		t.Fatal("owner could not read a verification")
	}
	stranger := f.mustToken(identity.KindUser, f.mustUser("stranger").ID, "org:"+f.org.ID.String())
	if rec := f.do(http.MethodGet, "/v1/carriers/verify/vr-2", stranger, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("user without rights read a verification: %d", rec.Code)
	}
	if rec := f.do(http.MethodGet, "/v1/carriers/verify/vr-2", outsider, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("token scoped elsewhere read a verification: %d", rec.Code)
	}
	svc.reportErr = deployment.ErrNotFound
	if rec := f.do(http.MethodGet, "/v1/carriers/verify/missing", f.bearer, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown request id = %d, want 404", rec.Code)
	}
}

func TestCarrierVerify_NoStoreAndBodyCap(t *testing.T) {
	f, _ := verifyFixture(t, deployment.VerifyReport{Version: "7", Fingerprint: "kfp1:k1:abcdefghijklmnop"})
	rec := f.do(http.MethodPost, "/v1/carriers/verify", f.bearer, map[string]any{"secret": "db-password"})
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("a verification answer must not be cached")
	}
	rec = f.do(http.MethodGet, "/v1/carriers/verify/vr-1", f.bearer, nil)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("a verification status must not be cached")
	}
	big := map[string]any{"secret": strings.Repeat("a", 5000)}
	if rec = f.do(http.MethodPost, "/v1/carriers/verify", f.bearer, big); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body = %d, want 400", rec.Code)
	}
}

// TestCarrierVerify_ErrorClassIsClosed: whatever class the report holds, the
// answer carries only a member of the runner's closed set; text, a path or
// anything else a class column could ever hold becomes "internal".
func TestCarrierVerify_ErrorClassIsClosed(t *testing.T) {
	const loose = "open /etc/shadow: permission denied"
	rep := deployment.VerifyReport{Version: "7", Fingerprint: "kfp1:k1:abcdefghijklmnop", Items: []deployment.VerifyItem{
		{CarrierID: uuid.New(), Host: "h1", TargetKind: runnerproto.TargetFile, TargetPath: "/srv/a", State: deployment.VerifyFailed, ErrorClass: runnerproto.ErrClassTargetWrite},
		{CarrierID: uuid.New(), Host: "h2", TargetKind: runnerproto.TargetFile, TargetPath: "/srv/b", State: deployment.VerifyFailed, ErrorClass: runnerproto.ErrorClass(loose)},
		{CarrierID: uuid.New(), Host: "h3", TargetKind: runnerproto.TargetFile, TargetPath: "/srv/c", State: deployment.VerifyPending},
	}}
	f, _ := verifyFixture(t, rep)
	rec := f.do(http.MethodPost, "/v1/carriers/verify", f.bearer, map[string]any{"secret": "db-password", "request_id": "vr-1"})
	if strings.Contains(rec.Body.String(), "shadow") {
		t.Fatal("free text of a class reached the answer")
	}
	out := decodeVerify(t, rec.Body.Bytes())
	if len(out.Carriers) != 3 {
		t.Fatalf("answer = %d with %d carriers", rec.Code, len(out.Carriers))
	}
	if out.Carriers[0].ErrorClass != "target_write_failed" || out.Carriers[1].ErrorClass != "internal" || out.Carriers[2].ErrorClass != "" {
		t.Fatalf("classes = %q %q %q", out.Carriers[0].ErrorClass, out.Carriers[1].ErrorClass, out.Carriers[2].ErrorClass)
	}
}

// TestCarrierVerifyWrite_ClassNeverCarriesText needs no database: write maps
// whatever class a report holds onto the closed set, and a canary placed in the
// class reaches the answer in no encoding.
func TestCarrierVerifyWrite_ClassNeverCarriesText(t *testing.T) {
	c := canary.New()
	for _, class := range []string{c.Value(0), "x_" + c.Value(0), "internal_"} {
		rep := deployment.VerifyReport{Version: "7", Items: []deployment.VerifyItem{
			{CarrierID: uuid.New(), Host: "h1", TargetKind: runnerproto.TargetFile, TargetPath: "/srv/a", State: deployment.VerifyFailed, ErrorClass: runnerproto.ErrorClass(class)}}}
		rec := httptest.NewRecorder()
		(&carrierVerifyRoutes{}).write(rec, "vr-1", rep)
		if c.In(rec.Body.String()) {
			t.Fatalf("canary reached the answer through class %q", class)
		}
		if out := decodeVerify(t, rec.Body.Bytes()); out.Carriers[0].ErrorClass != "internal" {
			t.Fatalf("class %q = %q, want internal", class, out.Carriers[0].ErrorClass)
		}
	}
}
