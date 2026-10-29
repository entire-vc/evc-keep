package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

const rotFP = "kfp1:k1:abcdefghijklmnop"

// fakeRotations stands in for the durable service where a test decides what
// the run reported.
type fakeRotations struct {
	mu      sync.Mutex
	started []rotation.Ref
	origins []rotation.Origin
	// approval, when set, is what Start answers for a secret that needs one.
	approval *rotation.ApprovalRef
	asked    []rotation.Ref
	ids      map[uuid.UUID]rotation.Ref
	report   rotation.RunReport
	err      error
	// anyRun answers a report for a run id nobody started.
	anyRun bool
}

func (s *fakeRotations) Start(_ context.Context, ref rotation.Ref, o rotation.Origin) (rotation.Started, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return rotation.Started{}, s.err
	}
	s.started = append(s.started, ref)
	s.origins = append(s.origins, o)
	id := uuid.New()
	if s.ids == nil {
		s.ids = map[uuid.UUID]rotation.Ref{}
	}
	s.ids[id] = ref
	return rotation.Started{RunID: id, Approval: s.approval}, nil
}

func (s *fakeRotations) Report(_ context.Context, ref rotation.Ref, id uuid.UUID) (rotation.RunReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, ref)
	if owner, ok := s.ids[id]; !s.anyRun && (!ok || owner != ref) {
		return rotation.RunReport{}, rotation.ErrNotFound
	}
	r := s.report
	r.RunID = id
	return r, nil
}

type rotateFixture struct {
	*routeFixture
	bearer string
	secret tenancy.SecretRef
	path   string
}

func newRotateFixture(t *testing.T, rot RotationService, input InputService) *rotateFixture {
	t.Helper()
	f := newRouteFixture(t)
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Rotations: rot, Input: input, Catalog: unlimitedCatalog})
	admin := f.mustAdmin("admin")
	store := f.mustStore("default", tenancy.Org(f.org.ID))
	ref, err := f.cat.CreateRef(f.ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: tenancy.Org(f.org.ID), Name: "db-password", Class: "credential", Type: "generic", ProviderRef: "builtin://default/db-password", StoreID: store.ID})
	if err != nil {
		t.Fatalf("create ref: %v", err)
	}
	return &rotateFixture{routeFixture: f, bearer: f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String()), secret: ref,
		path: "/orgs/" + f.org.ID.String() + "/secrets/" + ref.ID.String() + "/rotate"}
}

// dump is everything an outside observer sees of one call: body, headers and
// the server log.
func (f *rotateFixture) dump(rec interface {
	Header() http.Header
}, body string) string {
	var b strings.Builder
	b.WriteString(body)
	for k, vs := range rec.Header() {
		b.WriteString(k + strings.Join(vs, ","))
	}
	b.WriteString(f.logbuf.String())
	return b.String()
}

// The body is the mode and nothing else: a value, or any other field, is
// refused and never echoed, and the service is not asked.
func TestRotate_BodyIsModeOnlyAndNeverEchoed(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind")
	}
	svc := &fakeRotations{}
	f := newRotateFixture(t, svc, nil)
	for name, body := range map[string]any{
		"value":        map[string]any{"mode": "generate", "value": v},
		"secret_value": map[string]any{"mode": "generate", "secret_value": v},
		"plaintext":    map[string]any{"mode": "human_input", "plaintext": v},
		"mode is text": map[string]any{"mode": v},
		"no mode":      map[string]any{},
		"nested":       map[string]any{"mode": "generate", "x": map[string]any{"value": v}},
		"other mode":   map[string]any{"mode": "set"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.do(http.MethodPost, f.path, f.bearer, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			if rec.Body.Len() == 0 || f.logbuf.Len() == 0 {
				t.Fatal("interception saw nothing; the test proves nothing")
			}
			if d := f.dump(rec, rec.Body.String()); c.In(d) {
				t.Fatalf("canary reached the response, a header or the log (%d bytes inspected)", len(d))
			}
		})
	}
	if len(svc.started) != 0 {
		t.Fatal("a refused request started a run")
	}
}

func TestRotate_StartAnswers202WithOnlyTheRequestID(t *testing.T) {
	svc := &fakeRotations{}
	f := newRotateFixture(t, svc, nil)
	rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "generate"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var got RotateResult
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("not the closed shape: %v", err)
	}
	if _, err := uuid.Parse(got.RequestID); err != nil || got.OK || got.Version != "" || got.Fingerprint != "" || got.ErrorClass != "" || got.Carriers != nil {
		t.Fatalf("a started run answers only its request id: %+v", got)
	}
	if len(svc.started) != 1 || svc.started[0].SecretID != f.secret.ID || svc.started[0].OrgID != f.org.ID {
		t.Fatalf("run not started for the secret of the path: %+v", svc.started)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", rec.Header().Get("Cache-Control"))
	}
	// The run is readable under the secret that started it and nowhere else.
	rec = f.do(http.MethodGet, f.path+"/"+got.RequestID, f.bearer, nil)
	if rec.Code != http.StatusAccepted || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status of the started run: %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if len(svc.asked) != 1 || svc.asked[0] != svc.started[0] {
		t.Fatalf("report asked for another ref than the run's: %+v", svc.asked)
	}
	other := "/orgs/" + f.org.ID.String() + "/secrets/" + uuid.NewString() + "/rotate/" + got.RequestID
	if rec := f.do(http.MethodGet, other, f.bearer, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("a run is not readable under another secret: %d", rec.Code)
	}
}

// A service that sets a version on a run that is not done is not believed:
// only a done run reports a version and a fingerprint.
func TestRotate_StatusNeverReportsAVersionBeforeDone(t *testing.T) {
	for name, rep := range map[string]rotation.RunReport{
		"failed":  {State: rotation.StateFailed, Failed: true, Class: rotation.ClassDeployFailed, Version: "2", Fingerprint: rotFP},
		"running": {State: rotation.StateDeploying, Version: "2", Fingerprint: rotFP},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRotateFixture(t, &fakeRotations{report: rep, anyRun: true}, nil)
			rec := f.do(http.MethodGet, f.path+"/"+uuid.NewString(), f.bearer, nil)
			var got RotateResult
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.OK || got.Version != "" || got.Fingerprint != "" {
				t.Fatalf("a version was reported: %s", rec.Body.String())
			}
		})
	}
}

func TestRotate_StatusShapes(t *testing.T) {
	c1, c2 := uuid.NewString(), uuid.NewString()
	for name, tc := range map[string]struct {
		rep  rotation.RunReport
		code int
		want RotateResult
	}{
		"running": {rotation.RunReport{State: rotation.StateDeploying, Carriers: []rotation.CarrierStatus{{CarrierID: c1, Phase: "deploy", State: "pending"}}}, 202,
			RotateResult{Carriers: []RotateCarrier{{CarrierID: c1, Phase: "deploy", State: "pending"}}}},
		"done": {rotation.RunReport{State: rotation.StateDone, Done: true, Version: "2", Fingerprint: rotFP, Carriers: []rotation.CarrierStatus{{CarrierID: c1, Phase: "verify", State: "ok"}}}, 200,
			RotateResult{OK: true, Version: "2", Fingerprint: rotFP, Carriers: []RotateCarrier{{CarrierID: c1, Phase: "verify", State: "ok"}}}},
		"failed": {rotation.RunReport{State: rotation.StateFailed, Failed: true, Class: rotation.ClassDeployFailed, Carriers: []rotation.CarrierStatus{
			{CarrierID: c1, Phase: "verify", State: "ok"}, {CarrierID: c2, Phase: "deploy", State: "stale"}}}, 200,
			RotateResult{ErrorClass: "deploy_failed", Carriers: []RotateCarrier{{CarrierID: c1, Phase: "verify", State: "ok"}, {CarrierID: c2, Phase: "deploy", State: "stale"}}}},
		"class outside the list": {rotation.RunReport{State: rotation.StateFailed, Failed: true, Class: "boom: free text"}, 200, RotateResult{ErrorClass: "internal"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRotateFixture(t, &fakeRotations{report: tc.rep, anyRun: true}, nil)
			id := uuid.NewString()
			rec := f.do(http.MethodGet, f.path+"/"+id, f.bearer, nil)
			if rec.Code != tc.code {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			var got RotateResult
			dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&got); err != nil || got.RequestID != id {
				t.Fatalf("not the closed shape: %v", err)
			}
			tc.want.RequestID = id
			if a, b := mustJSON(t, got), mustJSON(t, tc.want); a != b {
				t.Fatalf("got %s want %s", a, b)
			}
		})
	}
}

func TestRotate_RefusalsAndRights(t *testing.T) {
	svc := &fakeRotations{}
	f := newRotateFixture(t, svc, nil)
	body := map[string]any{"mode": "generate"}
	reader := f.mustUser("reader")
	// A viewer sees the secret's metadata and still has no rotate right.
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, reader.ID, tenancy.Org(f.org.ID), string(identity.RoleViewer)); err != nil {
		t.Fatalf("grant viewer: %v", err)
	}
	other := f.mustAdmin("other")
	// Control for the scope case below: the same owner with the secret's own
	// scope is let in, so the 404 of the narrowed token is the scope alone.
	if rec := f.do(http.MethodPost, f.path, f.mustToken(identity.KindUser, other.ID, "org:"+f.org.ID.String()), body); rec.Code != http.StatusAccepted {
		t.Fatalf("control: owner with the secret's scope: %d %s", rec.Code, rec.Body.String())
	}
	started := len(svc.started)
	otherOrg, err := f.tr.CreateOrganization(f.ctx, "other-org", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path, bearer string
		code         int
	}{
		"no token":           {f.path, "", 401},
		"no rotate right":    {f.path, f.mustToken(identity.KindUser, reader.ID, "org:"+f.org.ID.String()), 404},
		"unknown secret":     {"/orgs/" + f.org.ID.String() + "/secrets/" + uuid.NewString() + "/rotate", f.bearer, 404},
		"bad secret id":      {"/orgs/" + f.org.ID.String() + "/secrets/nope/rotate", f.bearer, 400},
		"foreign org":        {"/orgs/" + otherOrg.ID.String() + "/secrets/" + f.secret.ID.String() + "/rotate", f.bearer, 403},
		"narrow token scope": {f.path, f.mustToken(identity.KindUser, other.ID, "user:"+other.ID.String()), 404},
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.do(http.MethodPost, tc.path, tc.bearer, body)
			if rec.Code != tc.code && (tc.code != 403 || rec.Code != 404) {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
		})
	}
	if len(svc.started) != started {
		t.Fatal("a refused request started a run")
	}
	if rec := f.do(http.MethodGet, f.path+"/"+uuid.NewString(), f.mustToken(identity.KindUser, reader.ID, "org:"+f.org.ID.String()), nil); rec.Code != 404 {
		t.Fatalf("status of a run without the right: %d", rec.Code)
	}
}

func TestRotate_ConflictAndUnavailable(t *testing.T) {
	f := newRotateFixture(t, &fakeRotations{err: rotation.ErrConflict}, nil)
	if rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "generate"}); rec.Code != 409 {
		t.Fatalf("conflict: %d %s", rec.Code, rec.Body.String())
	}
	f = newRotateFixture(t, &fakeRotations{err: errors.New("db down")}, nil)
	rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "generate"})
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "db down") {
		t.Fatalf("unavailable: %d %s", rec.Code, rec.Body.String())
	}
	f = newRotateFixture(t, nil, nil)
	if rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "generate"}); rec.Code != 503 {
		t.Fatalf("no service: %d", rec.Code)
	}
}

// Without a wired rotation service the answer is an honest 503 with the closed
// not_ready class and a fixed message that names no internals.
func TestRotate_NoServiceIsNotReady(t *testing.T) {
	f := newRotateFixture(t, nil, nil)
	rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "generate"})
	var out struct {
		ErrorClass string `json:"error_class"`
		Message    string `json:"message"`
	}
	if rec.Code != 503 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.ErrorClass != string(apperr.ClassNotReady) || out.Message != "rotation service unavailable" {
		t.Fatalf("no service: %d %s", rec.Code, rec.Body.String())
	}
}

type fakeInputs struct{ issued []tenancy.SecretRef }

func (s *fakeInputs) Issue(_ context.Context, ref tenancy.SecretRef, _ catalog.Store, _ audit.Actor, _ time.Duration) (intake.Issued, error) {
	s.issued = append(s.issued, ref)
	return intake.Issued{URL: "https://keep.example.test/input/tok", ExpiresAt: time.Now().Add(time.Hour), RequestID: uuid.NewString()}, nil
}
func (s *fakeInputs) IssueRotation(ctx context.Context, ref tenancy.SecretRef, st catalog.Store, a audit.Actor, ttl time.Duration) (intake.Issued, error) {
	return s.Issue(ctx, ref, st, a, ttl)
}
func (s *fakeInputs) Read(context.Context, string) (intake.View, error) {
	return intake.View{}, intake.ErrGone
}
func (s *fakeInputs) Complete(context.Context, string, intake.Envelope) (intake.Result, error) {
	return intake.Result{}, intake.ErrGone
}
func (s *fakeInputs) Status(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (intake.Result, error) {
	return intake.Result{}, intake.ErrGone
}

// human_input answers the one-time link a human enters the value through; no
// run starts here and nothing but url, expires_at and request_id comes back.
func TestRotate_HumanInputIssuesTheLink(t *testing.T) {
	in := &fakeInputs{}
	svc := &fakeRotations{}
	f := newRotateFixture(t, svc, in)
	rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "human_input"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var got intake.Issued
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil || got.URL == "" || got.RequestID == "" {
		t.Fatalf("not the input link shape: %v", err)
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the link answer lacks the input headers: %v", rec.Header())
	}
	if len(in.issued) != 1 || in.issued[0].ID != f.secret.ID || len(svc.started) != 0 {
		t.Fatalf("issued=%d started=%d", len(in.issued), len(svc.started))
	}
	f = newRotateFixture(t, svc, nil)
	if rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "human_input"}); rec.Code != 503 {
		t.Fatalf("no input service: %d", rec.Code)
	}
}
