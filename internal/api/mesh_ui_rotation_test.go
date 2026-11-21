package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// uiEngine is the provider side of a real rotation engine for the rotation
// screens: the canary is what it would hand out as a value, and every text it
// fails with carries it. gate, when set, holds every layout until closed.
type uiEngine struct {
	mu         sync.Mutex
	v          string // the canary value
	failDeploy bool   // carrier 2 fails its layout with the canary in the error
	badOld     bool   // Prepare names the canary as the old version label
	gate       chan struct{}
}

func (e *uiEngine) Prepare(context.Context, rotation.Ref, uuid.UUID) (rotation.Version, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.badOld {
		return rotation.Version{Old: e.v, New: "3", Fingerprint: rotFP, Length: len(e.v)}, nil
	}
	return rotation.Version{Old: "1", New: "2", Fingerprint: rotFP, Length: len(e.v)}, nil
}
func (e *uiEngine) List(context.Context, rotation.Ref) ([]rotation.Carrier, error) {
	return []rotation.Carrier{{ID: engineCarrier(1)}, {ID: engineCarrier(2)}, {ID: engineCarrier(3)}}, nil
}
func (e *uiEngine) Deploy(ctx context.Context, _ rotation.Ref, _ uuid.UUID, c rotation.Carrier, _ string) error {
	e.mu.Lock()
	gate, fail := e.gate, e.failDeploy
	e.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail && c.ID == engineCarrier(2) {
		return errors.New("deploy refused, value " + e.v)
	}
	return nil
}
func (e *uiEngine) Verify(context.Context, rotation.Ref, rotation.Carrier, string) (rotation.Report, error) {
	return rotation.Report{Fingerprint: rotFP, Healthy: true}, nil
}
func (e *uiEngine) Revoke(context.Context, rotation.Ref, uuid.UUID, string) error { return nil }
func (e *uiEngine) Open(context.Context, rotation.IncidentRecord) error {
	return errors.New("incident sink down, value " + e.v)
}
func (e *uiEngine) Resolve(context.Context, rotation.IncidentRecord) error { return nil }

func (e *uiEngine) set(fn func(*uiEngine)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	fn(e)
}

// uiRotFixture is a signed-in Mesh screen over a real router and database:
// an org admin's session cookie, the rotation service and run history wired
// as the server wires them.
type uiRotFixture struct {
	*rotateFixture
	cookie string
}

func newUIRotFixture(t *testing.T, reports RotationService, runs MeshUIRotations) *uiRotFixture {
	t.Helper()
	f := newRotateFixture(t, reports, nil)
	repo := meshext.NewRepo(f.pool)
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Rotations: reports, Catalog: unlimitedCatalog, Mesh: &MeshDeps{Repo: repo,
		Federation: meshext.NewFederation(f.pool, repo, f.ir, meshext.NewVerifier(meshext.ExtensionID, nil)), Rotations: runs}})
	handle, _, err := f.ir.OpenSession(f.ctx, identity.NewToken(f.bearer))
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	return &uiRotFixture{rotateFixture: f, cookie: handle}
}

// page GETs a screen as the browser does inside the Mesh iframe; live marks
// the request the live script sends.
func (f *uiRotFixture) page(path string, live bool) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.TLS = &tls.ConnectionState{}
	r.AddCookie(&http.Cookie{Name: meshUICookie, Value: f.cookie}) //nolint:gosec // G124: test client cookie, attributes are the server's concern
	if live {
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Sec-Fetch-Mode", "cors")
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec
}

func (f *uiRotFixture) runsPath() string {
	return "/mesh/ui/secrets/" + f.secret.ID.String() + "/rotations"
}

// startAndWait starts a run over the rotate API and waits until it ends.
func (f *uiRotFixture) startAndWait(svc *rotation.Service) string {
	f.t.Helper()
	id := startRun(f.t, f.rotateFixture)
	svc.Wait()
	return id
}

// Leak, end to end: a real engine over the database runs four rotations of
// one secret whose provider side holds the canary (as the value it hands
// out, in every error, as a forged old-version label). Every rotation screen
// (the list with each filter, every run page, the answers the live script
// fetches while a run is active and after it ends, the not-found page) and
// the server log must be free of the canary in all six encodings.
func TestMeshUIRotationLeak_RealRunsAndLiveRefresh(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	eng := &uiEngine{v: v}
	pool := testPool(t)
	svc := rotation.NewService(rotation.New(pool, rotation.Deps{Versions: eng, Carriers: eng, Deployer: eng, Verifier: eng, Revoker: eng, Incident: eng})).
		WithJournal(audit.NewJournal(pool))
	f := newUIRotFixture(t, svc, NewMeshUIRotations(rotation.NewRuns(pool)))

	var dump strings.Builder
	keep := func(rec *httptest.ResponseRecorder) string {
		body := rec.Body.String()
		dump.WriteString(f.dump(rec, body))
		return body
	}

	eng.set(func(e *uiEngine) { e.failDeploy = true })
	failed := f.startAndWait(svc)
	eng.set(func(e *uiEngine) { e.failDeploy, e.badOld = false, true })
	forged := f.startAndWait(svc)
	eng.set(func(e *uiEngine) { e.badOld = false })
	done := f.startAndWait(svc)

	gate := make(chan struct{})
	eng.set(func(e *uiEngine) { e.gate = gate })
	active := startRun(t, f.rotateFixture)
	livePath := f.runsPath() + "/" + active
	var first string
	for i := 0; i < 200; i++ { // until the run has laid out its steps and waits on the gate
		first = keep(f.page(livePath, false))
		if strings.Contains(first, "data-live-active") && strings.Contains(first, "Pending") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(first, "data-live-active") {
		t.Fatalf("an active run's page must ask for live updates: %s", first)
	}
	if refetch := keep(f.page(livePath, true)); !strings.Contains(refetch, "data-live-active") {
		t.Fatal("the live answer of an active run must keep the live marker")
	}
	close(gate)
	svc.Wait()
	if after := keep(f.page(livePath, true)); strings.Contains(after, "data-live-active") || !strings.Contains(after, "Rotation done") {
		t.Fatalf("the live answer after the run ended must stop the updates: %s", after)
	}

	list := keep(f.page(f.runsPath(), false))
	keep(f.page(f.runsPath()+"?result=failed", false))
	keep(f.page(f.runsPath()+"?page=2", false))
	failedPage := keep(f.page(f.runsPath()+"/"+failed, false))
	keep(f.page(f.runsPath()+"/"+forged, false))
	donePage := keep(f.page(f.runsPath()+"/"+done, false))
	keep(f.page(f.runsPath()+"/"+uuid.NewString(), false))

	// The screens really rendered what they must, or the scan proves nothing.
	for name, want := range map[string][]string{
		"list":   {"db-password", failed, forged, done, active, "deploy_failed", "prepare_failed"},
		"failed": {"Rotation failed", "deploy_failed", engineCarrier(2), "Stale"},
		"done":   {"Rotation v1 → v2", "Rotation done", "Confirmed"},
	} {
		body := map[string]string{"list": list, "failed": failedPage, "done": donePage}[name]
		for _, w := range want {
			if !strings.Contains(body, w) {
				t.Fatalf("the %s screen lacks %q", name, w)
			}
		}
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("interception saw no log; the test proves nothing")
	}
	if c.In(dump.String()) {
		t.Fatalf("canary reached a rotation screen, a header or the log (%d bytes inspected)", dump.Len())
	}
}

// fakeReports is a RotationService that answers Report from a table; a run id
// it does not have is ErrNotFound, as the real service answers a run of
// another secret or organization.
type fakeReports struct {
	reports map[uuid.UUID]rotation.RunReport
}

func (f *fakeReports) Start(context.Context, rotation.Ref, rotation.Origin) (rotation.Started, error) {
	return rotation.Started{}, errors.New("not used")
}
func (f *fakeReports) Report(_ context.Context, _ rotation.Ref, id uuid.UUID) (rotation.RunReport, error) {
	if r, ok := f.reports[id]; ok {
		return r, nil
	}
	return rotation.RunReport{}, rotation.ErrNotFound
}

// fakeRuns is a MeshUIRotations and MeshUIRunDetail over a fixed list.
type fakeRuns struct {
	runs []RunSummary // newest first
}

// Latest answers the newest run of the list for every asked secret.
func (f *fakeRuns) Latest(_ context.Context, _ uuid.UUID, secrets []uuid.UUID) (map[uuid.UUID]RunSummary, error) {
	out := map[uuid.UUID]RunSummary{}
	if len(f.runs) > 0 {
		for _, id := range secrets {
			out[id] = f.runs[0]
		}
	}
	return out, nil
}
func (f *fakeRuns) page(in []RunSummary, limit, offset int) ([]RunSummary, int, error) {
	if offset >= len(in) {
		return nil, len(in), nil
	}
	end := min(offset+limit, len(in))
	return in[offset:end], len(in), nil
}
func (f *fakeRuns) List(_ context.Context, _, _ uuid.UUID, limit, offset int) ([]RunSummary, int, error) {
	return f.page(f.runs, limit, offset)
}
func (f *fakeRuns) ListFailed(_ context.Context, _, _ uuid.UUID, limit, offset int) ([]RunSummary, int, error) {
	var out []RunSummary
	for _, r := range f.runs {
		if r.State == "failed" {
			out = append(out, r)
		}
	}
	return f.page(out, limit, offset)
}
func (f *fakeRuns) Run(_ context.Context, _, _, id uuid.UUID) (RunSummary, bool, error) {
	for _, r := range f.runs {
		if r.ID == id {
			return r, true, nil
		}
	}
	return RunSummary{}, false, nil
}

// Leak through hostile sources: a run history and a report service that put
// the canary in every field the screens read (state, class, versions, the
// starter's name,
// carrier ids, the approval status). The screens must keep only the closed
// vocabularies and drop the rest. The list of secrets and the page of one
// secret read the same history (their Rotations blocks) and are scanned too.
func TestMeshUIRotationLeak_HostileSources(t *testing.T) {
	c := canary.New()
	v := c.Value(2)
	run := uuid.New()
	reports := &fakeReports{reports: map[uuid.UUID]rotation.RunReport{run: {
		RunID: run, State: rotation.State(v), Class: rotation.Class(v), Version: v, Fingerprint: v,
		Carriers: []rotation.CarrierStatus{{CarrierID: v, Phase: v, State: v, Class: rotation.Class(v)}},
		Approval: &rotation.ApprovalRef{ID: uuid.New(), Status: v},
	}}}
	runs := &fakeRuns{runs: []RunSummary{{ID: run, State: v, ErrorClass: v, OldVersion: v, NewVersion: v, StartedBy: v, CreatedAt: time.Now()}}}
	f := newUIRotFixture(t, reports, runs)
	var dump strings.Builder
	secretPage := "/mesh/ui/secrets/" + f.secret.ID.String()
	for _, p := range []string{f.runsPath(), f.runsPath() + "?result=failed", f.runsPath() + "/" + run.String(), "/mesh/ui/secrets", secretPage} {
		rec := f.page(p, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, rec.Code)
		}
		dump.WriteString(f.dump(rec, rec.Body.String()))
	}
	if !strings.Contains(dump.String(), run.String()) || !strings.Contains(dump.String(), "internal_error") {
		t.Fatal("the screens did not render the run; the scan proves nothing")
	}
	if c.In(dump.String()) {
		t.Fatalf("canary from a hostile source reached a rotation screen (%d bytes inspected)", dump.Len())
	}
	if body := f.page(secretPage, false).Body.String(); !strings.Contains(body, "/rotations/"+run.String()) || !strings.Contains(body, "The last rotation failed: internal_error.") {
		t.Fatal("the page of the secret did not render the hostile run; the scan proves nothing")
	}
}

// The run page: an active run asks for live updates and a finished one does
// not; a failed run with an incident says so; a run the service does not
// know for this secret, a run id that is not one, a secret of another
// organization and an unknown secret all get the same 404, byte for byte.
func TestMeshUIRotationRunPageStatesAndNotFound(t *testing.T) {
	active, done, incident, safe, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	c1, c2 := engineCarrier(1), engineCarrier(2)
	reports := &fakeReports{reports: map[uuid.UUID]rotation.RunReport{
		active: {RunID: active, State: rotation.StateVerifying, Carriers: []rotation.CarrierStatus{
			{CarrierID: c1, Phase: "verify", State: "ok"}, {CarrierID: c2, Phase: "verify", State: "pending"}}},
		done: {RunID: done, State: rotation.StateDone, Done: true, Version: "12", Fingerprint: rotFP, Carriers: []rotation.CarrierStatus{
			{CarrierID: c1, Phase: "verify", State: "ok"}}},
		incident: {RunID: incident, State: rotation.StateFailed, Failed: true, Class: rotation.ClassUnhealthy, IncidentOpened: true, Carriers: []rotation.CarrierStatus{
			{CarrierID: c1, Phase: "verify", State: "ok"}, {CarrierID: c2, Phase: "verify", State: "stale", Class: rotation.ClassUnhealthy}}},
		safe: {RunID: safe, State: rotation.StateFailed, Failed: true, Class: rotation.ClassDeployFailed, Carriers: []rotation.CarrierStatus{
			{CarrierID: c1, Phase: "deploy", State: "stale", Class: rotation.ClassDeployFailed}}},
	}}
	now := time.Date(2026, 11, 13, 22, 5, 0, 0, time.UTC)
	runs := &fakeRuns{runs: []RunSummary{
		{ID: active, State: "verifying", OldVersion: "11", NewVersion: "12", CreatedAt: now},
		{ID: done, State: "done", OldVersion: "11", NewVersion: "12", CreatedAt: now},
		{ID: incident, State: "failed", ErrorClass: "unhealthy", IncidentOpened: true, OldVersion: "11", NewVersion: "12", CreatedAt: now},
		{ID: safe, State: "failed", ErrorClass: "deploy_failed", OldVersion: "11", NewVersion: "12", CreatedAt: now},
	}}
	f := newUIRotFixture(t, reports, runs)
	get := func(p string, want int) string {
		t.Helper()
		rec := f.page(p, false)
		if rec.Code != want {
			t.Fatalf("%s: status %d, want %d", p, rec.Code, want)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Fatalf("%s: policy %q", p, csp)
		}
		return rec.Body.String()
	}

	a := get(f.runsPath()+"/"+active.String(), http.StatusOK)
	for _, w := range []string{"data-live-active", `src="/mesh/ui/live.js"`, "Rotation v11 → v12", "Rotation in progress", `class="now"`, "1 / 2 verified", "Updates every 3 s"} {
		if !strings.Contains(a, w) {
			t.Fatalf("active run page lacks %q:\n%s", w, a)
		}
	}
	d := get(f.runsPath()+"/"+done.String(), http.StatusOK)
	if strings.Contains(d, "data-live-active") || !strings.Contains(d, "data-live") || !strings.Contains(d, "Rotation done: v12 is active on every carrier and v11 was revoked.") {
		t.Fatalf("a finished run must render the live node without the active marker:\n%s", d)
	}
	in := get(f.runsPath()+"/"+incident.String(), http.StatusOK)
	for _, w := range []string{"banner-danger", "an incident is open", "1 unhealthy", `class="fail"`, "skipped: v11 stays"} {
		if !strings.Contains(in, w) {
			t.Fatalf("failed run with an incident lacks %q:\n%s", w, in)
		}
	}
	if strings.Contains(in, "data-live-active") {
		t.Fatal("a failed run must not ask for live updates")
	}
	sf := get(f.runsPath()+"/"+safe.String(), http.StatusOK)
	if !strings.Contains(sf, "Rotation failed safely: v11 is active on every carrier, nothing was revoked.") || strings.Contains(sf, "incident is open") {
		t.Fatalf("a failed run without an incident is a safe failure:\n%s", sf)
	}

	js := f.page("/mesh/ui/live.js", false)
	if js.Code != http.StatusOK || !strings.HasPrefix(js.Header().Get("Content-Type"), "text/javascript") ||
		js.Header().Get("X-Content-Type-Options") != "nosniff" || js.Body.String() != meshUILiveScript {
		t.Fatalf("live script: %d %q", js.Code, js.Header().Get("Content-Type"))
	}

	// One 404 for every way of naming a run or secret the caller cannot see.
	other, err := f.tr.CreateOrganization(f.ctx, t.Name()+"-other", "")
	if err != nil {
		t.Fatal(err)
	}
	ost, err := f.cat.CreateStore(f.ctx, other.ID, "builtin", "default", tenancy.Org(other.ID))
	if err != nil {
		t.Fatal(err)
	}
	oref, err := f.cat.CreateRef(f.ctx, catalog.CreateRefInput{Org: other.ID, Scope: tenancy.Org(other.ID), Name: "db-password", Class: "credential", Type: "generic",
		ProviderRef: "builtin://default/db-password", StoreID: ost.ID})
	if err != nil {
		t.Fatal(err)
	}
	ref404 := get(f.runsPath()+"/"+foreign.String(), http.StatusNotFound)
	for _, p := range []string{
		f.runsPath() + "/not-a-run",
		"/mesh/ui/secrets/" + uuid.NewString() + "/rotations/" + done.String(),
		"/mesh/ui/secrets/" + oref.ID.String() + "/rotations/" + done.String(),
		"/mesh/ui/secrets/" + oref.ID.String() + "/rotations",
		"/mesh/ui/secrets/not-a-secret/rotations",
	} {
		if got := get(p, http.StatusNotFound); got != ref404 {
			t.Fatalf("%s: the 404 differs from the foreign run's 404", p)
		}
	}
	if strings.Contains(ref404, foreign.String()) || strings.Contains(ref404, f.secret.ID.String()) {
		t.Fatal("the 404 names an id")
	}
}

// The Rotations page: newest first, 50 a page with a counter and links, the
// Failed filter leaves only failed runs, and each row opens its run.
func TestMeshUIRotationListPagesAndFilter(t *testing.T) {
	var all []RunSummary
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 120; i++ {
		st, cl := "done", ""
		if i%10 == 0 {
			st, cl = "failed", "verify_failed"
		}
		all = append(all, RunSummary{ID: uuid.New(), State: st, ErrorClass: cl, OldVersion: strconv.Itoa(i + 1), NewVersion: strconv.Itoa(i + 2), CreatedAt: t0.Add(-time.Duration(i) * time.Hour)})
	}
	f := newUIRotFixture(t, &fakeReports{}, &fakeRuns{runs: all})
	body := func(p string) string {
		t.Helper()
		rec := f.page(p, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, rec.Code)
		}
		return rec.Body.String()
	}
	p1 := body(f.runsPath())
	if !strings.Contains(p1, "1–50 of 120") || !strings.Contains(p1, f.runsPath()+"/"+all[0].ID.String()) || strings.Contains(p1, all[50].ID.String()) ||
		!strings.Contains(p1, "page=2") || strings.Contains(p1, ">Previous<") || strings.Contains(p1, "data-live") {
		t.Fatalf("first page:\n%s", p1)
	}
	p3 := body(f.runsPath() + "?page=3")
	if !strings.Contains(p3, "101–120 of 120") || !strings.Contains(p3, all[119].ID.String()) || strings.Contains(p3, all[99].ID.String()) || strings.Contains(p3, ">Next<") {
		t.Fatalf("last page:\n%s", p3)
	}
	fl := body(f.runsPath() + "?result=failed")
	if !strings.Contains(fl, "1–12 of 12") || strings.Contains(fl, all[1].ID.String()) || !strings.Contains(fl, all[10].ID.String()) ||
		!strings.Contains(fl, "Rolled back · verify_failed") || !strings.Contains(fl, `aria-current="true">Failed`) {
		t.Fatalf("failed filter:\n%s", fl)
	}
	empty := newUIRotFixture(t, &fakeReports{}, &fakeRuns{})
	rec := empty.page(empty.runsPath(), false)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "No rotations yet") {
		t.Fatalf("empty history: %d %s", rec.Code, rec.Body.String())
	}
}

// A banner sentence that opens with a version name starts with a capital
// letter, and a version label keeps its own form.
func TestMeshUIRotationBannerSentenceCase(t *testing.T) {
	for in, want := range map[string]string{"the previous version": "The previous version", "v11": "v11", "": "", "Done": "Done"} {
		if got := capital(in); got != want {
			t.Errorf("capital(%q) = %q, want %q", in, got, want)
		}
	}
}

// Run history does not record a starter, so an arbitrary implementation
// cannot introduce unvalidated free text through that unused field.
func TestMeshUIRotationSummaryDropsStarter(t *testing.T) {
	c := canary.New()
	in := RunSummary{ID: uuid.New(), State: "done", OldVersion: "1", NewVersion: "2", StartedBy: c.Value(1)}
	out := uiRun(in)
	if out.StartedBy != "" {
		t.Fatal("unrecorded starter survived the summary boundary")
	}
	if out.ID != in.ID || out.State != in.State || out.OldVersion != in.OldVersion || out.NewVersion != in.NewVersion {
		t.Fatal("control: valid run metadata was lost")
	}
}

func TestMeshUIRotationRequiresReadMetadata(t *testing.T) {
	run := uuid.New()
	f := newUIRotFixture(t, &fakeReports{reports: map[uuid.UUID]rotation.RunReport{
		run: {RunID: run, State: rotation.StateDone, Done: true},
	}}, &fakeRuns{runs: []RunSummary{{ID: run, State: "done"}}})
	paths := []string{f.runsPath(), f.runsPath() + "?result=failed", f.runsPath() + "/" + run.String()}
	for _, path := range paths {
		if rec := f.page(path, true); rec.Code != http.StatusOK {
			t.Fatalf("control: metadata reader rejected: %d", rec.Code)
		}
	}
	user := f.mustUser("no-roles")
	token := f.mustToken(identity.KindUser, user.ID, "org:"+f.org.ID.String())
	handle, _, err := f.ir.OpenSession(f.ctx, identity.NewToken(token))
	if err != nil {
		t.Fatalf("open unprivileged session: %v", err)
	}
	f.cookie = handle
	ref404 := f.page("/mesh/ui/secrets/"+uuid.NewString()+"/rotations", true)
	if ref404.Code != http.StatusNotFound {
		t.Fatalf("unknown secret: %d", ref404.Code)
	}
	for _, path := range paths {
		rec := f.page(path, true)
		if rec.Code != http.StatusNotFound || rec.Body.String() != ref404.Body.String() {
			t.Fatalf("member without read_metadata: %s: status %d; expected the common 404", path, rec.Code)
		}
	}
}
