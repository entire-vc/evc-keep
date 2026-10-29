package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/notify"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// fakeDeployments stands in for the durable service where a test decides what
// the runner reported. Validation of the request shape is the real
// deployment.Repo's, used in the refusal tests below.
type fakeDeployments struct {
	submitted []deployment.Request
	report    deployment.Report
	err       error
	// limit, when set, answers RateLimited from the (limit+1)-th request on.
	limit int
	// reportErr, when set, is what Report answers before anything else.
	reportErr error
	// outcome, when its ID is set, is what Submit answers (an approval, say).
	outcome deployment.Outcome
}

func (s *fakeDeployments) Submit(_ context.Context, in deployment.Request) (deployment.Outcome, error) {
	s.submitted = append(s.submitted, in)
	if s.outcome.ID != uuid.Nil {
		return s.outcome, s.err
	}
	return deployment.Outcome{ID: uuid.New()}, s.err
}

func (s *fakeDeployments) Report(_ context.Context, _ uuid.UUID, requestID string) (deployment.Report, error) {
	if s.reportErr != nil {
		return deployment.Report{}, s.reportErr
	}
	r := s.report
	if s.limit > 0 && len(s.submitted) > s.limit {
		r.Status = deployment.RateLimited
	}
	r.Scope = s.submittedScope()
	for _, in := range s.submitted {
		if in.RequestID == requestID {
			r.SecretID, r.VersionID = in.SecretID, in.VersionID
		}
	}
	if len(s.submitted) == 0 {
		return deployment.Report{}, deployment.ErrNotFound
	}
	return r, s.err
}

func (s *fakeDeployments) submittedScope() tenancy.Scope {
	if len(s.submitted) == 0 {
		return tenancy.Scope{}
	}
	return s.submitted[0].Scope
}

type deployFixture struct {
	*routeFixture
	bearer string
	secret tenancy.SecretRef
	body   map[string]any
}

// newDeployFixture builds a real catalog secret with one version and a router
// whose deployment service is svc (nil: the real repo over the same pool).
func newDeployFixture(t *testing.T, svc DeploymentService) *deployFixture {
	t.Helper()
	f := newRouteFixture(t)
	if svc == nil {
		svc = deployment.NewRepo(f.pool, audit.NewJournal(f.pool))
	}
	f.router = NewRouter(obs.New(io.Discard), f.pool, Deps{Deployments: svc, PublicURL: "https://keep.example.test"})
	admin := f.mustAdmin("admin")
	store := f.mustStore("default", tenancy.Org(f.org.ID))
	ref, err := f.cat.CreateRef(f.ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: tenancy.Org(f.org.ID), Name: "db-password", Class: "credential", Type: "generic", ProviderRef: "builtin://default/db-password", StoreID: store.ID})
	if err != nil {
		t.Fatalf("create ref: %v", err)
	}
	if _, err = f.cat.AddVersion(f.ctx, f.org.ID, ref.ID, "7", "kfp1:k1:abcdefghijklmnop", 12); err != nil {
		t.Fatalf("add version: %v", err)
	}
	return &deployFixture{routeFixture: f, bearer: f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String()), secret: ref,
		body: map[string]any{"secret": "db-password", "runner_id": uuid.NewString(),
			"target": map[string]any{"kind": "env-file", "path": "/srv/app/.env", "field": "DB_PASSWORD", "uid": 1001, "gid": 1001}}}
}

func (d *deployFixture) post(mutate func(map[string]any)) (*bytes.Buffer, int) {
	d.t.Helper()
	body := map[string]any{}
	for k, v := range d.body {
		body[k] = v
	}
	target := map[string]any{}
	for k, v := range d.body["target"].(map[string]any) {
		target[k] = v
	}
	body["target"] = target
	if mutate != nil {
		mutate(target)
	}
	rec := d.do(http.MethodPost, "/v1/deployments", d.bearer, body)
	return bytes.NewBuffer(rec.Body.Bytes()), rec.Code
}

var requestIDField = regexp.MustCompile(`"request_id":"[^"]*"`)

func normalized(b *bytes.Buffer) string {
	return requestIDField.ReplaceAllString(b.String(), `"request_id":"-"`)
}

func TestDeployments_ResultShapes(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	approval := uuid.New()
	for name, tc := range map[string]struct {
		report deployment.Report
		code   int
		want   DeployResult
	}{
		"pending": {deployment.Report{Status: deployment.Queued}, 202, DeployResult{}},
		"ok": {deployment.Report{Status: deployment.Queued, Done: true, Result: runnerproto.Result{OK: true, Fingerprint: "kfp1:k1:abcdefghijklmnop", Version: "7",
			Healthcheck: &runnerproto.Healthcheck{Status: runnerproto.HealthOK, Kind: runnerproto.HealthKindUnitActive, DurationMs: 40, CheckedAt: now}}}, 200,
			DeployResult{OK: true, Fingerprint: "kfp1:k1:abcdefghijklmnop", Version: "7", Healthcheck: &DeployHealth{Status: "ok", CheckedAt: now}}},
		"runner-failed": {deployment.Report{Status: deployment.Queued, Done: true, Result: runnerproto.Result{ErrorClass: runnerproto.ErrClassTargetWrite}}, 200, DeployResult{ErrorClass: "target_write_failed"}},
		"approval": {deployment.Report{Status: deployment.NeedsApproval, ApprovalID: approval, ApprovalStatus: "requested"}, 202,
			DeployResult{Approval: &DeployApproval{ID: approval.String(), Status: "requested", URL: "https://keep.example.test/console/approvals/" + approval.String()}}},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &fakeDeployments{report: tc.report}
			f := newDeployFixture(t, svc)
			out, code := f.post(nil)
			if code != tc.code {
				t.Fatalf("status %d, body %s", code, out)
			}
			var got DeployResult
			dec := json.NewDecoder(out)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&got); err != nil || got.RequestID == "" {
				t.Fatalf("response is not the closed shape: %v", err)
			}
			got.RequestID = ""
			if a, b := mustJSON(t, got), mustJSON(t, tc.want); a != b {
				t.Fatalf("got %s want %s", a, b)
			}
			if len(svc.submitted) != 1 {
				t.Fatal("service not asked exactly once")
			}
			in := svc.submitted[0]
			if in.SecretID != f.secret.ID || in.Target.Path != "/srv/app/.env" || in.Target.Mode != 0o600 || in.Actor.Via != audit.ViaAPI {
				t.Fatalf("request not built from the catalog and the token: %+v", in)
			}
		})
	}
}

// threat model 4.3: healthcheck is {status, checked_at} and nothing else, on
// the wire, whatever the runner reported.
func TestDeployments_HealthcheckHasOnlyStatusAndCheckedAt(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	svc := &fakeDeployments{report: deployment.Report{Status: deployment.Queued, Done: true, Result: runnerproto.Result{OK: true,
		Fingerprint: "kfp1:k1:abcdefghijklmnop", Version: "7",
		Healthcheck: &runnerproto.Healthcheck{Status: runnerproto.HealthOK, Kind: runnerproto.HealthKindUnitActive, DurationMs: 40, CheckedAt: now}}}}
	f := newDeployFixture(t, svc)
	out, code := f.post(nil)
	var got struct {
		Healthcheck map[string]any `json:"healthcheck"`
	}
	if code != 200 || json.Unmarshal(out.Bytes(), &got) != nil || got.Healthcheck == nil {
		t.Fatalf("status %d, body %s", code, out)
	}
	if len(got.Healthcheck) != 2 || got.Healthcheck["status"] != "ok" || got.Healthcheck["checked_at"] == nil {
		t.Fatalf("healthcheck is not exactly {status, checked_at}: %v", got.Healthcheck)
	}
	if n := reflect.TypeOf(DeployHealth{}).NumField(); n != 2 {
		t.Fatalf("DeployHealth has %d fields, want 2", n)
	}
}

// With max_deploys_per_hour = 10 the first ten deployments succeed and the
// eleventh is refused with its own closed class, not permission_denied.
func TestDeployments_EleventhDeployIsRateLimited(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	svc := &fakeDeployments{limit: 10, report: deployment.Report{Status: deployment.Queued, Done: true, Result: runnerproto.Result{OK: true,
		Fingerprint: "kfp1:k1:abcdefghijklmnop", Version: "7", Healthcheck: &runnerproto.Healthcheck{Status: runnerproto.HealthOK, CheckedAt: now}}}}
	f := newDeployFixture(t, svc)
	for i := 1; i <= 10; i++ {
		if out, code := f.post(nil); code != 200 {
			t.Fatalf("deploy %d: status %d, body %s", i, code, out)
		}
	}
	out, code := f.post(nil)
	var e struct {
		ErrorClass string `json:"error_class"`
	}
	if code != 429 || json.Unmarshal(out.Bytes(), &e) != nil || e.ErrorClass != "rate_limited" {
		t.Fatalf("eleventh deploy: status %d, body %s", code, out)
	}
}

// A refused target looks up the request id first. Only "not found" lets the
// refusal go on; a database error is 503, not a refusal that hides it.
func TestDeployments_RejectDistinguishesStorageErrorFromNotFound(t *testing.T) {
	bad := func(m map[string]any) { m["path"] = "https://example.test/x" }
	f := newDeployFixture(t, &fakeDeployments{reportErr: errors.New("storage down")})
	out, code := f.post(bad)
	body := out.String()
	var e struct {
		ErrorClass string `json:"error_class"`
	}
	// Decode reads the first object only, so the audit count below is what
	// separates "answered 503 and stopped" from "answered 503 and went on".
	if code != 503 || json.NewDecoder(out).Decode(&e) != nil || e.ErrorClass != "not_ready" {
		t.Fatalf("storage error: status %d, body %s", code, body)
	}
	if n := deployAuditRows(t, f); n != 0 {
		t.Fatalf("storage error left %d audit rows", n)
	}
	f = newDeployFixture(t, &fakeDeployments{})
	out, code = f.post(bad)
	if code != 400 || json.Unmarshal(out.Bytes(), &e) != nil || e.ErrorClass != "invalid_argument" {
		t.Fatalf("control: status %d, body %s", code, out)
	}
	if n := deployAuditRows(t, f); n != 1 {
		t.Fatalf("control: %d audit rows, want 1", n)
	}
}

func deployAuditRows(t *testing.T, f *deployFixture) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='deploy.requested'`, f.org.ID.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDeployments_PolicyRefusalsAreClosedErrors(t *testing.T) {
	for status, want := range map[deployment.Status]int{deployment.Denied: 403, deployment.RateLimited: 429, deployment.UnsupportedProvider: 400} {
		f := newDeployFixture(t, &fakeDeployments{report: deployment.Report{Status: status}})
		out, code := f.post(nil)
		var e struct {
			ErrorClass string `json:"error_class"`
			Message    string `json:"message"`
			RequestID  string `json:"request_id"`
		}
		wantClass := map[deployment.Status]string{deployment.Denied: "permission_denied", deployment.RateLimited: "rate_limited", deployment.UnsupportedProvider: "invalid_argument"}[status]
		if code != want || json.Unmarshal(out.Bytes(), &e) != nil || e.ErrorClass != wantClass || e.RequestID == "" {
			t.Fatalf("%s: status %d body %s", status, code, out)
		}
		if strings.Contains(e.Message, "/srv/app") || strings.Contains(e.Message, "DB_PASSWORD") {
			t.Fatalf("%s: message echoes the target: %s", status, e.Message)
		}
	}
}

// Newline, quote and network-shaped targets are refused before any job exists,
// and every refusal answers with the same bytes except request_id, and leaves
// the same audit shape. The refused text never reaches either.
func TestDeployments_FormatRefusalsAreByteIdentical(t *testing.T) {
	f := newDeployFixture(t, nil)
	secretText := canary.New().Value(1)
	probe := canary.Of(secretText)
	cases := map[string]func(map[string]any){
		"path-newline":  func(m map[string]any) { m["path"] = "/srv/app/" + secretText + "\n.env" },
		"field-newline": func(m map[string]any) { m["field"] = "A\n" + secretText },
		"field-quote":   func(m map[string]any) { m["field"] = "A\"" + secretText },
		"network-url":   func(m map[string]any) { m["path"] = "https://" + secretText + ".example/x" },
		"network-port":  func(m map[string]any) { m["path"] = "/srv/app/" + secretText + ":8080" },
		"network-ipv6":  func(m map[string]any) { m["path"] = "/srv/[::1]/" + secretText },
	}
	var first string
	for name, mutate := range cases {
		out, code := f.post(mutate)
		if code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, body %s", name, code, out)
		}
		if probe.In(out.String()) {
			t.Fatalf("%s: refused text reached the response", name)
		}
		got := normalized(out)
		if first == "" {
			first = got
		} else if got != first {
			t.Fatalf("%s: response differs from the first refusal:\n%s\n%s", name, got, first)
		}
	}
	if !strings.Contains(first, `"error_class":"invalid_argument"`) || !strings.Contains(first, `secret \"db-password\"`) || !strings.Contains(first, "target kind env-file") {
		t.Fatalf("template lost its closed parts: %s", first)
	}
	rows, err := f.pool.Query(f.ctx, `SELECT action,secret_name,target_kind,target_path,result_status,result_error_class FROM audit_records WHERE org_id=$1 AND action='deploy.requested'`, f.org.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var a, name, kind, path, status, class string
		if err := rows.Scan(&a, &name, &kind, &path, &status, &class); err != nil {
			t.Fatal(err)
		}
		if name != "db-password" || kind != "env-file" || path != "" || status != "failed" || class != "invalid_argument" {
			t.Fatalf("refusal audit row: %q %q %q %q %q", name, kind, path, status, class)
		}
		n++
	}
	if n != len(cases) {
		t.Fatalf("%d refusal audit rows for %d refusals", n, len(cases))
	}
	// Positive control: the detector sees the text when it is present.
	if !probe.In(`x` + secretText) {
		t.Fatal("canary detector is blind")
	}
}

func TestDeployments_RightsAndShape(t *testing.T) {
	f := newDeployFixture(t, &fakeDeployments{report: deployment.Report{Status: deployment.Queued}})
	viewer := f.mustUser("viewer")
	viewerToken := f.mustToken(identity.KindUser, viewer.ID, "org:"+f.org.ID.String())
	// A reader who may see the secret's metadata but holds no deploy right.
	reader := f.mustUser("reader")
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, reader.ID, tenancy.Org(f.org.ID), string(identity.RoleViewer)); err != nil {
		t.Fatalf("grant viewer: %v", err)
	}
	readerToken := f.mustToken(identity.KindUser, reader.ID, "org:"+f.org.ID.String())
	b, _ := json.Marshal(f.body)
	for name, tc := range map[string]struct {
		token string
		body  string
		want  int
	}{
		"no-token":      {"", string(b), 401},
		"no-rights":     {viewerToken, string(b), 404},
		"read-only":     {readerToken, string(b), 404},
		"unknown-field": {f.bearer, `{"secret":"db-password","value":"x"}`, 400},
		"bad-runner":    {f.bearer, `{"secret":"db-password","runner_id":"nope","target":{}}`, 400},
		"no-uid":        {f.bearer, `{"secret":"db-password","runner_id":"` + uuid.NewString() + `","target":{"kind":"env-file","path":"/srv/a"}}`, 400},
	} {
		r, _ := http.NewRequest(http.MethodPost, "/v1/deployments", strings.NewReader(tc.body))
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, r)
		if rec.Code != tc.want {
			t.Fatalf("%s: status %d body %s", name, rec.Code, rec.Body)
		}
	}
	if rec := f.do(http.MethodGet, "/v1/deployments/"+uuid.NewString(), viewerToken, nil); rec.Code != 404 && rec.Code != 503 {
		t.Fatalf("status of a stranger's request: %d", rec.Code)
	}
}

// A caller-chosen kind never reaches an answer or the journal, a disabled
// version is never deployed, and no answer is cacheable.
func TestDeployments_ClosedKindVersionAndHeaders(t *testing.T) {
	svc := &fakeDeployments{report: deployment.Report{Status: deployment.Queued}}
	f := newDeployFixture(t, svc)
	odd := canary.New().Value(1)
	probe := canary.Of(odd)
	out, code := f.post(func(m map[string]any) { m["kind"] = "kind-" + odd })
	if code != http.StatusBadRequest || probe.In(out.String()) || !strings.Contains(out.String(), "target kind unknown") {
		t.Fatalf("unknown kind: %d %s", code, out)
	}
	var kind string
	if err := f.pool.QueryRow(f.ctx, `SELECT target_kind FROM audit_records WHERE org_id=$1 AND action='deploy.requested'`, f.org.ID.String()).Scan(&kind); err != nil || kind != "unknown" {
		t.Fatalf("audit kind %q (%v)", kind, err)
	}
	if !probe.In("x" + odd) {
		t.Fatal("canary detector is blind")
	}

	// The newest version is disabled: the request must pin the older one.
	newer, err := f.cat.AddVersion(f.ctx, f.org.ID, f.secret.ID, "8", "kfp1:k1:bbbbbbbbbbbbbbbb", 12)
	if err != nil {
		t.Fatalf("add version: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE secret_versions SET disabled=true WHERE id=$1`, newer.ID); err != nil {
		t.Fatalf("disable version: %v", err)
	}
	rec := f.do(http.MethodPost, "/v1/deployments", f.bearer, f.body)
	if rec.Code != http.StatusAccepted || len(svc.submitted) != 1 || svc.submitted[0].VersionID == newer.ID {
		t.Fatalf("disabled version was deployed: %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("POST Cache-Control %q", got)
	}
	var res DeployResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || res.RequestID == "" {
		t.Fatal("no request id")
	}
	if got := f.do(http.MethodGet, "/v1/deployments/"+res.RequestID, f.bearer, nil).Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("GET Cache-Control %q", got)
	}
}

// The status read needs the deploy right at the secret's scope, and a retry of
// a request id replays against the version it was first pinned to.
func TestDeployments_StatusRightsAndReplayPin(t *testing.T) {
	svc := &fakeDeployments{report: deployment.Report{Status: deployment.Queued}}
	f := newDeployFixture(t, svc)
	reader := f.mustUser("reader")
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, reader.ID, tenancy.Org(f.org.ID), string(identity.RoleViewer)); err != nil {
		t.Fatalf("grant viewer: %v", err)
	}
	readerToken := f.mustToken(identity.KindUser, reader.ID, "org:"+f.org.ID.String())
	f.body["request_id"] = "pin-" + uuid.NewString()[:8]
	rec := f.do(http.MethodPost, "/v1/deployments", f.bearer, f.body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first post: %d %s", rec.Code, rec.Body)
	}
	url := "/v1/deployments/" + f.body["request_id"].(string)
	if rec := f.do(http.MethodGet, url, f.bearer, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("owner status: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(http.MethodGet, url, readerToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("reader without deploy right got %d", rec.Code)
	}
	if rec := f.do(http.MethodGet, url, "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status: %d", rec.Code)
	}
	if _, err := f.cat.AddVersion(f.ctx, f.org.ID, f.secret.ID, "9", "kfp1:k1:cccccccccccccccc", 12); err != nil {
		t.Fatalf("add version: %v", err)
	}
	if rec := f.do(http.MethodPost, "/v1/deployments", f.bearer, f.body); rec.Code != http.StatusAccepted || len(svc.submitted) != 2 {
		t.Fatalf("retry: %d", rec.Code)
	}
	if svc.submitted[0].VersionID != svc.submitted[1].VersionID {
		t.Fatal("a retry was pinned to a newer version than the original request")
	}
}

// A caller with metadata rights but no deploy right gets the very bytes a name
// that does not exist gets, apart from the name the caller itself typed.
func TestDeployments_NoDeployRightAnswersLikeMissing(t *testing.T) {
	f := newDeployFixture(t, &fakeDeployments{report: deployment.Report{Status: deployment.Queued}})
	reader := f.mustUser("reader")
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, reader.ID, tenancy.Org(f.org.ID), string(identity.RoleViewer)); err != nil {
		t.Fatalf("grant viewer: %v", err)
	}
	readerToken := f.mustToken(identity.KindUser, reader.ID, "org:"+f.org.ID.String())
	answer := func(name string) string {
		body := map[string]any{}
		for k, v := range f.body {
			body[k] = v
		}
		body["secret"] = name
		rec := f.do(http.MethodPost, "/v1/deployments", readerToken, body)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d", name, rec.Code)
		}
		out := requestIDField.ReplaceAllString(rec.Body.String(), `"request_id":"-"`)
		return strings.ReplaceAll(out, name, "NAME")
	}
	if got, want := answer("db-password"), answer("no-such-secret"); got != want {
		t.Fatalf("existing secret without deploy right is distinguishable:\n%s\n%s", got, want)
	}
}

// The idempotency key counts whether it arrives in the body or only in the
// X-Request-Id header, and a rejected request never writes under a key that
// already belongs to a deployment.
func TestDeployments_HeaderKeyPinsAndRejectKeepsForeignKey(t *testing.T) {
	svc := &fakeDeployments{report: deployment.Report{Status: deployment.Queued}}
	f := newDeployFixture(t, svc)
	post := func(key string, body map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, "/v1/deployments", bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+f.bearer)
		r.Header.Set(reqid.HeaderName, key)
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, r)
		return rec
	}
	key := "hdr-" + uuid.NewString()[:8]
	if rec := post(key, f.body); rec.Code != http.StatusAccepted {
		t.Fatalf("first post: %d %s", rec.Code, rec.Body)
	}
	if _, err := f.cat.AddVersion(f.ctx, f.org.ID, f.secret.ID, "9", "kfp1:k1:cccccccccccccccc", 12); err != nil {
		t.Fatalf("add version: %v", err)
	}
	if rec := post(key, f.body); rec.Code != http.StatusAccepted || len(svc.submitted) != 2 {
		t.Fatalf("retry: %d", rec.Code)
	}
	if svc.submitted[0].VersionID != svc.submitted[1].VersionID {
		t.Fatal("a retry keyed by the header was pinned to a newer version")
	}
	bad := map[string]any{"secret": "db-password", "runner_id": uuid.NewString(), "target": map[string]any{"kind": "env-file", "path": "relative", "uid": 1, "gid": 1}}
	if rec := post(key, bad); rec.Code != http.StatusConflict {
		t.Fatalf("rejected request under a used key: %d %s", rec.Code, rec.Body)
	}
}

type fakeNotifier struct {
	got chan notify.ApprovalNotice
	err error
}

func (n *fakeNotifier) ApprovalRequested(_ context.Context, in notify.ApprovalNotice) error {
	n.got <- in
	return n.err
}

func notifyFixture(t *testing.T, created bool, nerr error) (*fakeNotifier, uuid.UUID, int) {
	t.Helper()
	approval := uuid.New()
	svc := &fakeDeployments{report: deployment.Report{Status: deployment.NeedsApproval, ApprovalID: approval, ApprovalStatus: "requested"},
		outcome: deployment.Outcome{ID: uuid.New(), Status: deployment.NeedsApproval, ApprovalID: approval, Created: created}}
	f := newDeployFixture(t, svc)
	n := &fakeNotifier{got: make(chan notify.ApprovalNotice, 4), err: nerr}
	f.router = NewRouter(obs.New(io.Discard), f.pool, Deps{Deployments: svc, PublicURL: "https://keep.example.test", Notifier: n})
	_, code := f.post(nil)
	return n, approval, code
}

func TestDeployments_NewApprovalNotifiesOnceWithClosedFields(t *testing.T) {
	n, approval, code := notifyFixture(t, true, nil)
	if code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	select {
	case got := <-n.got:
		want := notify.ApprovalNotice{ApprovalID: approval, SecretName: "db-password", SecretClass: "credential", RequesterKind: "user", TargetKind: "env-file"}
		if got != want {
			t.Fatalf("notice %+v, want %+v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no notification")
	}
}

func TestDeployments_ReplayAndNotifierFailureDoNotChangeTheAnswer(t *testing.T) {
	n, _, code := notifyFixture(t, false, nil) // a replay: Created is false
	if code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	select {
	case got := <-n.got:
		t.Fatalf("a replay notified again: %+v", got)
	case <-time.After(200 * time.Millisecond):
	}
	if _, _, code = notifyFixture(t, true, errors.New("chat down")); code != http.StatusAccepted {
		t.Fatalf("a failing notifier changed the answer to %d", code)
	}
}

func TestDeployments_DecidedApprovalShapes(t *testing.T) {
	approval := uuid.New()
	ref := &DeployApproval{ID: approval.String(), Status: "approved", URL: "https://keep.example.test/console/approvals/" + approval.String()}
	for name, tc := range map[string]struct {
		report deployment.Report
		code   int
		class  string
		want   *DeployResult
	}{
		"approved-pending": {deployment.Report{Status: deployment.NeedsApproval, ApprovalID: approval, ApprovalStatus: "approved"}, 202, "", &DeployResult{Approval: ref}},
		"approved-done": {deployment.Report{Status: deployment.NeedsApproval, ApprovalID: approval, ApprovalStatus: "approved", Done: true, Result: runnerproto.Result{OK: true, Fingerprint: "kfp1:k1:abcdefghijklmnop", Version: "7"}}, 200, "",
			&DeployResult{OK: true, Fingerprint: "kfp1:k1:abcdefghijklmnop", Version: "7", Approval: ref}},
		"rejected": {deployment.Report{Status: deployment.NeedsApproval, ApprovalID: approval, ApprovalStatus: "rejected"}, 403, "permission_denied", nil},
		"expired":  {deployment.Report{Status: deployment.NeedsApproval, ApprovalID: approval, ApprovalStatus: "expired"}, 403, "permission_denied", nil},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDeployFixture(t, &fakeDeployments{report: tc.report})
			out, code := f.post(nil)
			if code != tc.code {
				t.Fatalf("status %d body %s", code, out)
			}
			if tc.want == nil {
				if !strings.Contains(out.String(), `"error_class":"`+tc.class+`"`) || strings.Contains(out.String(), "console/approvals") {
					t.Fatalf("not a plain closed error: %s", out)
				}
				return
			}
			var got DeployResult
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			got.RequestID = ""
			if a, b := mustJSON(t, got), mustJSON(t, *tc.want); a != b {
				t.Fatalf("got %s want %s", a, b)
			}
		})
	}
}
