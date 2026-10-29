package api

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

type orgVerifyFixture struct {
	*deployFixture
	svc  *fakeVerify
	post string
}

func newOrgVerifyFixture(t *testing.T, rep deployment.VerifyReport) *orgVerifyFixture {
	t.Helper()
	f, svc := verifyFixture(t, rep)
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Deployments: svc, Carriers: &fakeCarriers{}})
	return &orgVerifyFixture{deployFixture: f, svc: svc, post: fmt.Sprintf("/orgs/%s/secrets/%s/carriers/verify", f.org.ID, f.secret.ID)}
}

func (f *orgVerifyFixture) statusPath(request string) string { return f.post + "/" + request }

func pendingReport() deployment.VerifyReport {
	return deployment.VerifyReport{Version: "7", Fingerprint: "kfp1:k1:abcdefghijklmnop", Items: []deployment.VerifyItem{
		{CarrierID: uuid.New(), Host: "host-a", TargetKind: runnerproto.TargetFile, TargetPath: "/srv/app/.env", State: deployment.VerifyPending}}}
}

func TestOrgCarrierVerify_AcceptsThenReportsOnTheSecretOfThePath(t *testing.T) {
	f := newOrgVerifyFixture(t, pendingReport())
	rec := f.do(http.MethodPost, f.post, f.bearer, map[string]any{"request_id": "vr-1"})
	if rec.Code != http.StatusAccepted || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body)
	}
	out := decodeVerify(t, rec.Body.Bytes())
	if out.OK || out.RequestID != "vr-1" || len(out.Carriers) != 1 || out.Carriers[0].Status != "pending" {
		t.Fatalf("pending answer is wrong: %s", rec.Body)
	}
	if len(f.svc.requests) != 1 || f.svc.requests[0].SecretID != f.secret.ID || f.svc.requests[0].OrgID != f.org.ID || f.svc.requests[0].Scope != tenancy.Org(f.org.ID) {
		t.Fatalf("service got %+v", f.svc.requests)
	}
	if rec = f.do(http.MethodPost, f.post, f.bearer, nil); rec.Code != http.StatusAccepted || decodeVerify(t, rec.Body.Bytes()).RequestID == "" {
		t.Fatalf("empty body = %d, want 202 with a generated request id", rec.Code)
	}
	f.svc.report.Items[0].State = deployment.VerifyMatch
	f.svc.report.SecretID = f.secret.ID
	rec = f.do(http.MethodGet, f.statusPath("vr-1"), f.bearer, nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || !decodeVerify(t, rec.Body.Bytes()).OK {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body)
	}
}

// The request id is only reachable through the secret it was made for.
func TestOrgCarrierVerify_StatusOfAnotherSecretIsNotFound(t *testing.T) {
	f := newOrgVerifyFixture(t, pendingReport())
	f.svc.report.Scope = tenancy.Org(f.org.ID)
	f.svc.report.SecretID = uuid.New()
	if rec := f.do(http.MethodGet, f.statusPath("vr-1"), f.bearer, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("report of another secret = %d %s", rec.Code, rec.Body)
	}
	f.svc.report.SecretID = f.secret.ID
	if rec := f.do(http.MethodGet, f.statusPath("vr-1"), f.bearer, nil); rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("report of the path's secret = %d (positive control)", rec.Code)
	}
}

func TestOrgCarrierVerify_StatusOfAnotherScopeIsNotFound(t *testing.T) {
	f := newOrgVerifyFixture(t, pendingReport())
	f.svc.report.SecretID = f.secret.ID
	f.svc.report.Scope = tenancy.Org(uuid.New())
	if rec := f.do(http.MethodGet, f.statusPath("vr-1"), f.bearer, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("report at another scope = %d %s", rec.Code, rec.Body)
	}
	f.svc.report.Scope = tenancy.Org(f.org.ID)
	if rec := f.do(http.MethodGet, f.statusPath("vr-1"), f.bearer, nil); rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("report at the secret's scope = %d (positive control)", rec.Code)
	}
}

func TestOrgCarrierVerify_ForeignUnauthorizedAndUnknownAnswerLikeMissing(t *testing.T) {
	f := newOrgVerifyFixture(t, pendingReport())
	f.svc.report.SecretID = f.secret.ID
	missing := f.do(http.MethodPost, fmt.Sprintf("/orgs/%s/secrets/%s/carriers/verify", f.org.ID, uuid.New()), f.bearer, map[string]any{})
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown secret = %d", missing.Code)
	}
	foreign := fmt.Sprintf("/orgs/%s/secrets/%s/carriers/verify", uuid.New(), f.secret.ID)
	stranger := f.mustToken(identity.KindUser, f.mustUser("stranger").ID, "org:"+f.org.ID.String())
	narrow := f.mustToken(identity.KindUser, f.mustAdmin("narrow").ID, "ws:"+uuid.NewString())
	for name, tc := range map[string]struct{ method, path, bearer string }{
		"foreign org POST": {http.MethodPost, foreign, f.bearer}, "foreign org GET": {http.MethodGet, foreign + "/vr-1", f.bearer},
		"no rights POST": {http.MethodPost, f.post, stranger}, "no rights GET": {http.MethodGet, f.statusPath("vr-1"), stranger},
		"other scope POST": {http.MethodPost, f.post, narrow}, "other scope GET": {http.MethodGet, f.statusPath("vr-1"), narrow},
	} {
		var body any
		if tc.method == http.MethodPost {
			body = map[string]any{}
		}
		if rec := f.do(tc.method, tc.path, tc.bearer, body); rec.Code != http.StatusNotFound {
			t.Fatalf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	for method, path := range map[string]string{http.MethodPost: f.post, http.MethodGet: f.statusPath("vr-1")} {
		if rec := f.do(method, path, "", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s = %d", method, rec.Code)
		}
	}
	if len(f.svc.requests) != 0 {
		t.Fatal("the service was reached by a refused caller")
	}
}

// healthcheck_ref is server-side, from the deployment record: no client field
// besides the idempotency key is accepted, and a refused body reaches nothing.
func TestOrgCarrierVerify_RefusesAnythingButTheRequestID(t *testing.T) {
	c := canary.New()
	f := newOrgVerifyFixture(t, pendingReport())
	for name, body := range map[string]map[string]any{
		"healthcheck_ref": {"healthcheck_ref": "unit-active"}, "value": {"value": c.Value(0)}, "fingerprint": {"fingerprint": "kfp1:k1:abcdefghijklmnop"},
		"secret": {"secret": "db-password"}, "bad request id": {"request_id": "a b"},
	} {
		rec := f.do(http.MethodPost, f.post, f.bearer, body)
		if rec.Code != http.StatusBadRequest || c.In(rec.Body.String()) || c.In(f.logbuf.String()) {
			t.Fatalf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	if len(f.svc.requests) != 0 {
		t.Fatal("a refused body reached the service")
	}
}

func TestOrgCarrierVerify_ServiceRefusalsAreClosedAndQuoteNothing(t *testing.T) {
	c := canary.New()
	for err, code := range map[error]int{deployment.ErrNotFound: 404, deployment.ErrConflict: 409, deployment.ErrVerifyRateLimited: 429,
		deployment.ErrTooManyCarriers: 400, deployment.ErrUnavailable: 503, io.ErrUnexpectedEOF: 503} {
		f := newOrgVerifyFixture(t, pendingReport())
		f.svc.submitErr = fmt.Errorf("%w: %s host-a /srv/app/.env", err, c.Value(0))
		rec := f.do(http.MethodPost, f.post, f.bearer, map[string]any{})
		body := rec.Body.String() + fmt.Sprint(rec.Header())
		if rec.Code != code || c.In(body) || c.In(f.logbuf.String()) || strings.Contains(body, "host-a") || strings.Contains(body, "/srv/") {
			t.Fatalf("%v: %d %s", err, rec.Code, rec.Body)
		}
	}
}

func TestOrgCarrierVerify_NoCanaryInAnswerHeadersOrLog(t *testing.T) {
	c := canary.New()
	rep := pendingReport()
	rep.Items = append(rep.Items, deployment.VerifyItem{CarrierID: uuid.New(), Host: "host-b", TargetKind: runnerproto.TargetFile, TargetPath: "/srv/b",
		State: deployment.VerifyFailed, ErrorClass: runnerproto.ErrorClass(c.Value(0))})
	f := newOrgVerifyFixture(t, rep)
	f.svc.report.SecretID = f.secret.ID
	requireDetector(t, c)
	for _, rec := range []string{"POST", "GET"} {
		var got string
		if rec == "POST" {
			r := f.do(http.MethodPost, f.post, f.bearer, map[string]any{"request_id": "vr-1"})
			got = r.Body.String() + fmt.Sprint(r.Header())
		} else {
			r := f.do(http.MethodGet, f.statusPath("vr-1"), f.bearer, nil)
			got = r.Body.String() + fmt.Sprint(r.Header())
		}
		if c.In(got) || !strings.Contains(got, `"internal"`) {
			t.Fatalf("%s: canary reached the answer or the class was not closed: %s", rec, got)
		}
	}
	if f.logbuf.Len() == 0 || c.In(f.logbuf.String()) {
		t.Fatalf("log empty (%d bytes) or holds the canary", f.logbuf.Len())
	}
}

func requireDetector(t *testing.T, c canary.Canary) {
	t.Helper()
	if !c.In("prefix "+c.Value(0)) || c.In("nothing here") {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
}

// Read-only rights are enough, and the idempotency key and the caller reach
// the service as sent.
func TestOrgCarrierVerify_ViewerMaySubmitAndTheServiceGetsKeyAndActor(t *testing.T) {
	f := newOrgVerifyFixture(t, pendingReport())
	f.svc.report.SecretID = f.secret.ID
	viewer := f.mustUser("viewer")
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, viewer.ID, tenancy.Org(f.org.ID), string(identity.RoleViewer)); err != nil {
		t.Fatalf("grant viewer: %v", err)
	}
	vt := f.mustToken(identity.KindUser, viewer.ID, "org:"+f.org.ID.String())
	if rec := f.do(http.MethodPost, f.post, vt, map[string]any{"request_id": "vr-7"}); rec.Code != http.StatusAccepted {
		t.Fatalf("viewer POST = %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(http.MethodGet, f.statusPath("vr-7"), vt, nil); rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
		t.Fatalf("viewer GET = %d %s", rec.Code, rec.Body)
	}
	agent := f.mustAgent(viewer, "bot")
	at := f.mustToken(identity.KindAgent, agent.ID, "org:"+f.org.ID.String())
	if rec := f.do(http.MethodPost, f.post, at, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("agent POST = %d %s", rec.Code, rec.Body)
	}
	if len(f.svc.requests) != 2 {
		t.Fatalf("service calls = %d", len(f.svc.requests))
	}
	u, a := f.svc.requests[0], f.svc.requests[1]
	if u.RequestID != "vr-7" || u.OrgID != f.org.ID || u.Actor.ID != viewer.ID.String() || u.Actor.Type != "user" {
		t.Fatalf("user request reached the service as %+v", u)
	}
	if a.RequestID == "" || a.RequestID == "vr-7" || a.Actor.Type != "agent" || a.Actor.ID != agent.ID.String() || a.Actor.SponsorID != viewer.ID.String() {
		t.Fatalf("agent request reached the service as %+v", a)
	}
}

func TestOrgCarrierVerify_BodyIsCapped(t *testing.T) {
	f := newOrgVerifyFixture(t, pendingReport())
	// valid JSON, only padded: the size alone is what is refused
	body := `{"request_id":"vr-1"}` + strings.Repeat(" ", 600)
	req := httptest.NewRequest(http.MethodPost, f.post, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.bearer)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || len(f.svc.requests) != 0 {
		t.Fatalf("oversized body = %d, service calls %d", rec.Code, len(f.svc.requests))
	}
}

func TestOrgCarrierVerify_WithoutAServiceAnswersNotReady(t *testing.T) {
	f := newCarrierFixture(t) // router built without a deployment service
	for method, path := range map[string]string{http.MethodPost: f.path + "/verify", http.MethodGet: f.path + "/verify/vr-1"} {
		rec := f.do(method, path, f.bearer, nil)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "not_ready") {
			t.Fatalf("%s without a service = %d %s", method, rec.Code, rec.Body)
		}
	}
}
