package api

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// The rotation screens of the Mesh iframe: every run of a secret, and one run
// with its carriers. Both read only run metadata (RunSummary, RunReport) and
// the §4.3 Carrier row; a free-text error never reaches them, a class is
// shown only if the closed list of rotation.Class has it. While a run is
// active its page carries data-live-active and the screen script refetches
// the page itself: there is no JSON API behind it.

// meshUIRunsPerPage is one page of the Rotations screen.
const meshUIRunsPerPage = 50

// MeshUIRunDetail is the optional half of a MeshUIRotations: one run for the
// run page's header, and the Failed filter of the Rotations page. Without it
// the header names no versions and the filter is hidden.
type MeshUIRunDetail interface {
	// Run returns one run of the secret; found is false for a run of another
	// secret or organization, exactly as for an unknown id.
	Run(ctx context.Context, org, secret, run uuid.UUID) (RunSummary, bool, error)
	// ListFailed is List narrowed to failed runs.
	ListFailed(ctx context.Context, org, secret uuid.UUID, limit, offset int) ([]RunSummary, int, error)
}

// RotationRuns is the run history internal/rotation keeps (*rotation.Runs).
type RotationRuns interface {
	Latest(ctx context.Context, org uuid.UUID, secrets []uuid.UUID) (map[uuid.UUID]rotation.RunSummary, error)
	List(ctx context.Context, org, secret uuid.UUID, limit, offset int) ([]rotation.RunSummary, int, error)
	ListFailed(ctx context.Context, org, secret uuid.UUID, limit, offset int) ([]rotation.RunSummary, int, error)
	Get(ctx context.Context, org, secret, run uuid.UUID) (rotation.RunSummary, bool, error)
}

// NewMeshUIRotations is the MeshUIRotations (and MeshUIRunDetail) of the run
// history; nil hides every rotation block.
func NewMeshUIRotations(r RotationRuns) MeshUIRotations {
	if r == nil {
		return nil
	}
	return meshUIRuns{r: r}
}

type meshUIRuns struct{ r RotationRuns }

func (m meshUIRuns) Latest(ctx context.Context, org uuid.UUID, secrets []uuid.UUID) (map[uuid.UUID]RunSummary, error) {
	in, err := m.r.Latest(ctx, org, secrets)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]RunSummary, len(in))
	for id, s := range in {
		out[id] = runSummaryOf(s)
	}
	return out, nil
}

func (m meshUIRuns) List(ctx context.Context, org, secret uuid.UUID, limit, offset int) ([]RunSummary, int, error) {
	return summaries(m.r.List(ctx, org, secret, limit, offset))
}

func (m meshUIRuns) ListFailed(ctx context.Context, org, secret uuid.UUID, limit, offset int) ([]RunSummary, int, error) {
	return summaries(m.r.ListFailed(ctx, org, secret, limit, offset))
}

func (m meshUIRuns) Run(ctx context.Context, org, secret, run uuid.UUID) (RunSummary, bool, error) {
	s, ok, err := m.r.Get(ctx, org, secret, run)
	if err != nil || !ok {
		return RunSummary{}, false, err
	}
	return runSummaryOf(s), true, nil
}

func summaries(in []rotation.RunSummary, total int, err error) ([]RunSummary, int, error) {
	if err != nil {
		return nil, 0, err
	}
	out := make([]RunSummary, 0, len(in))
	for _, s := range in {
		out = append(out, runSummaryOf(s))
	}
	return out, total, nil
}

// runSummaryOf keeps only what the closed vocabularies allow: a state of
// the engine, a class of rotation.Class, a version label of the engine's
// grammar. Anything else is dropped, never shown.
func runSummaryOf(s rotation.RunSummary) RunSummary {
	return RunSummary{ID: s.ID, State: uiRunState(string(s.State)), ErrorClass: uiRunClass(string(s.Class)),
		OldVersion: uiVersion(s.OldVersion), NewVersion: uiVersion(s.NewVersion), IncidentOpened: s.IncidentOpened,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}
}

// uiRun re-reads a summary from any MeshUIRotations implementation through
// the same closed vocabularies, so a source that is not this package's
// adapter cannot put free text in a state, a class or a version either.
func uiRun(s RunSummary) RunSummary {
	s.State, s.ErrorClass = uiRunState(s.State), uiRunClass(s.ErrorClass)
	s.OldVersion, s.NewVersion = uiVersion(s.OldVersion), uiVersion(s.NewVersion)
	// The engine does not record a starter; do not render free text supplied
	// by another implementation through the reserved contract field.
	s.StartedBy = ""
	return s
}

// meshUIClosedRuns hands the other screens (the list and the page of a
// secret) the runs through uiRun as well; nil stays nil, so they hide their
// rotation blocks.
func meshUIClosedRuns(r MeshUIRotations) MeshUIRotations {
	if r == nil {
		return nil
	}
	return closedRuns{r: r}
}

type closedRuns struct{ r MeshUIRotations }

func (c closedRuns) Latest(ctx context.Context, org uuid.UUID, secrets []uuid.UUID) (map[uuid.UUID]RunSummary, error) {
	in, err := c.r.Latest(ctx, org, secrets)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]RunSummary, len(in))
	for id, s := range in {
		out[id] = uiRun(s)
	}
	return out, nil
}

func (c closedRuns) List(ctx context.Context, org, secret uuid.UUID, limit, offset int) ([]RunSummary, int, error) {
	runs, total, err := c.r.List(ctx, org, secret, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	out := make([]RunSummary, len(runs))
	for i, s := range runs {
		out[i] = uiRun(s)
	}
	return out, total, nil
}

// uiVersionRe is the engine's version grammar (internal/rotation/labels.go).
var uiVersionRe = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)

func uiVersion(v string) string {
	if uiVersionRe.MatchString(v) {
		return v
	}
	return ""
}

var uiRunStates = map[string]bool{
	string(rotation.StateNewVersion): true, string(rotation.StateDeploying): true, string(rotation.StateVerifying): true,
	string(rotation.StateRevokingOld): true, string(rotation.StateRollingBack): true, string(rotation.StateDone): true,
	string(rotation.StateFailed): true,
}

// uiRunState: an unknown state reads as failed, the state that claims nothing.
func uiRunState(s string) string {
	if uiRunStates[s] {
		return s
	}
	return string(rotation.StateFailed)
}

var uiRunClasses = map[rotation.Class]bool{
	rotation.ClassNoCarriers: true, rotation.ClassDeployFailed: true, rotation.ClassFingerprintMismatch: true,
	rotation.ClassUnhealthy: true, rotation.ClassVerifyFailed: true, rotation.ClassRevokeFailed: true,
	rotation.ClassPrepareFailed: true, rotation.ClassSuperseded: true, rotation.ClassInternalError: true,
	rotation.ClassOriginalKeyUnknown: true, rotation.ClassRollbackUnconfirmed: true, rotation.ClassPolicyDenied: true,
}

// uiRunClass keeps a class only if rotation.Class has it; "" stays "".
func uiRunClass(c string) string {
	if c == "" || uiRunClasses[rotation.Class(c)] {
		return c
	}
	return string(rotation.ClassInternalError)
}

// meshUIRotationDeps is what the two screens read.
type meshUIRotationDeps struct {
	Runs     MeshUIRotations
	Reports  RotationService
	Carriers CarrierService
}

type meshUIRotationPages struct {
	*meshUI
	d meshUIRotationDeps
}

func registerMeshUIRotations(mux *http.ServeMux, logger *slog.Logger, u *meshUI, d meshUIRotationDeps) {
	p := &meshUIRotationPages{meshUI: u, d: d}
	for _, e := range []struct {
		pattern string
		h       http.HandlerFunc
	}{
		{"/mesh/ui/secrets/{id}/rotations", p.rotations},
		{"/mesh/ui/secrets/{id}/rotations/{run}", p.run},
	} {
		mux.Handle("GET "+e.pattern, logged(e.pattern, logger, requireTLS(e.h).ServeHTTP))
	}
	mux.Handle("GET /mesh/ui/live.js", logged("/mesh/ui/live.js", logger, requireTLS(http.HandlerFunc(liveScript)).ServeHTTP))
}

func liveScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(meshUILiveScript))
}

var meshUIRotationTemplates = template.Must(template.Must(meshUITemplates.Clone()).Parse(meshUIRotationHTML))

func (p *meshUIRotationPages) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = meshUIRotationTemplates.ExecuteTemplate(w, name, data)
}

// open resolves the session and the secret of the path. A secret that does
// not exist, belongs to another organization or is outside the caller's
// read_metadata gets the one not-found page, byte for byte the same.
func (p *meshUIRotationPages) open(w http.ResponseWriter, r *http.Request) (identity.Session, []string, tenancy.SecretRef, bool) {
	s, origins, ok, err := p.sessionOf(r)
	if err != nil {
		meshUIHeaders(w, nil)
		p.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{})
		return s, nil, tenancy.SecretRef{}, false
	}
	if !ok {
		p.signedOut(w, r, "")
		return s, nil, tenancy.SecretRef{}, false
	}
	meshUIHeaders(w, origins)
	sec, found, err := p.uiSecret(r.Context(), s.Principal, r.PathValue("id"))
	switch {
	case err != nil:
		p.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{Origins: origins})
		return s, nil, tenancy.SecretRef{}, false
	case !found || p.d.Runs == nil:
		p.notFound(w, s, origins)
		return s, nil, tenancy.SecretRef{}, false
	}
	return s, origins, sec, true
}

func (p *meshUIRotationPages) notFound(w http.ResponseWriter, s identity.Session, origins []string) {
	p.render(w, http.StatusNotFound, "rotation-notfound", uiBase{Origins: origins, Active: "secrets", CSRF: s.CSRF})
}

// uiSecret finds a secret of the organization or of the caller's own user
// scope that the caller may read the metadata of: the same check as the page
// of the secret (meshUISource.Readable).
func (p *meshUIRotationPages) uiSecret(ctx context.Context, pr identity.Principal, raw string) (tenancy.SecretRef, bool, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return tenancy.SecretRef{}, false, nil
	}
	sec, err := p.src.Readable(ctx, pr, id)
	if errors.Is(err, errMeshUINotFound) {
		return tenancy.SecretRef{}, false, nil
	}
	if err != nil {
		return tenancy.SecretRef{}, false, err
	}
	return sec, true, nil
}

// --- Rotations -------------------------------------------------------------

type rotationsView struct {
	uiBase
	SecretID, SecretName string
	Failed               bool // the Failed filter is on
	CanFilter            bool
	Rows                 []runRowView
	From, To, Total      int
	PrevHref, NextHref   string
}

type runRowView struct {
	ID, Started, By, Versions string
	Result, Tone, Class       string
}

func (p *meshUIRotationPages) rotations(w http.ResponseWriter, r *http.Request) {
	s, origins, sec, ok := p.open(w, r)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 || page > 100000 {
		page = 1
	}
	detail, canFilter := p.d.Runs.(MeshUIRunDetail)
	failed := canFilter && r.URL.Query().Get("result") == "failed"
	offset := (page - 1) * meshUIRunsPerPage
	var runs []RunSummary
	var total int
	var err error
	if failed {
		runs, total, err = detail.ListFailed(r.Context(), s.Principal.OrgID, sec.ID, meshUIRunsPerPage, offset)
	} else {
		runs, total, err = p.d.Runs.List(r.Context(), s.Principal.OrgID, sec.ID, meshUIRunsPerPage, offset)
	}
	if err != nil {
		p.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{Origins: origins})
		return
	}
	v := rotationsView{uiBase: uiBase{Origins: origins, Active: "secrets", CSRF: s.CSRF}, SecretID: sec.ID.String(), SecretName: sec.Name,
		Failed: failed, CanFilter: canFilter, Total: total}
	for _, run := range runs {
		run = uiRun(run)
		res, tone := runResult(run.State, run.ErrorClass, run.IncidentOpened)
		v.Rows = append(v.Rows, runRowView{ID: run.ID.String(), Started: when(run.CreatedAt), By: run.StartedBy,
			Versions: versionsText(run.OldVersion, run.NewVersion), Result: res, Tone: tone, Class: uiRunClass(run.ErrorClass)})
	}
	if len(v.Rows) > 0 {
		v.From, v.To = offset+1, offset+len(v.Rows)
	}
	base := "/mesh/ui/secrets/" + v.SecretID + "/rotations?"
	if failed {
		base += "result=failed&"
	}
	if page > 1 {
		v.PrevHref = base + "page=" + strconv.Itoa(page-1)
	}
	if offset+len(v.Rows) < total {
		v.NextHref = base + "page=" + strconv.Itoa(page+1)
	}
	p.render(w, http.StatusOK, "rotations", v)
}

// runResult is the result badge of a run: label and tone.
func runResult(state, class string, incident bool) (string, string) {
	switch rotation.State(state) {
	case rotation.StateDone:
		if rotation.Class(class) == rotation.ClassOriginalKeyUnknown {
			return "Done · old key kept", "warn"
		}
		return "Done", "ok"
	case rotation.StateFailed:
		label := "Rolled back"
		if incident {
			label = "Failed · incident open"
		}
		if class != "" {
			label += " · " + uiRunClass(class)
		}
		return label, "danger"
	case rotation.StateRollingBack:
		return "Rolling back", "run"
	default:
		return "Rotating", "run"
	}
}

func versionsText(oldV, newV string) string {
	switch {
	case oldV != "" && newV != "":
		return "v" + oldV + " → v" + newV
	case newV != "":
		return "→ v" + newV
	default:
		return "—"
	}
}

// --- Rotation run ----------------------------------------------------------

type runView struct {
	uiBase
	SecretID, SecretName string
	RunID, Title         string
	Status, StatusTone   string
	Started, By          string
	Approval             string
	Live                 bool
	Banner               runBanner
	Steps                []runStep
	Carriers             []runCarrierView
}

type runBanner struct{ Tone, Head, Body, Class string }

type runStep struct{ Name, Note, State string }

type runCarrierView struct {
	Host, Target       string
	Phase, State, Tone string
	Class              string
}

var uiApprovalStatuses = map[string]bool{"pending": true, "approved": true, "rejected": true, "expired": true}

func (p *meshUIRotationPages) run(w http.ResponseWriter, r *http.Request) {
	s, origins, sec, ok := p.open(w, r)
	if !ok {
		return
	}
	runID, err := uuid.Parse(r.PathValue("run"))
	if err != nil || p.d.Reports == nil {
		p.notFound(w, s, origins)
		return
	}
	org := s.Principal.OrgID
	rep, err := p.d.Reports.Report(r.Context(), rotation.Ref{OrgID: org, SecretID: sec.ID}, runID)
	switch {
	case errors.Is(err, rotation.ErrNotFound):
		p.notFound(w, s, origins)
		return
	case err != nil:
		p.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{Origins: origins})
		return
	}
	var sum RunSummary
	if detail, ok := p.d.Runs.(MeshUIRunDetail); ok {
		if sum, _, err = detail.Run(r.Context(), org, sec.ID, runID); err != nil {
			p.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{Origins: origins})
			return
		}
	}
	labels, err := p.carrierLabels(r.Context(), org, sec.ID)
	if err != nil {
		p.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{Origins: origins})
		return
	}
	v := buildRunView(rep, uiRun(sum), labels)
	v.uiBase = uiBase{Origins: origins, Active: "secrets", CSRF: s.CSRF}
	v.SecretID, v.SecretName, v.RunID = sec.ID.String(), sec.Name, runID.String()
	p.render(w, http.StatusOK, "rotation-run", v)
}

type carrierLabel struct{ Host, Target string }

// carrierLabels names the secret's carriers by host and target, the §4.3
// Carrier fields; no carrier service means none is named.
func (p *meshUIRotationPages) carrierLabels(ctx context.Context, org, secret uuid.UUID) (map[string]carrierLabel, error) {
	out := map[string]carrierLabel{}
	if p.d.Carriers == nil {
		return out, nil
	}
	cs, err := p.d.Carriers.List(ctx, org, secret)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		t := c.TargetPath
		if t == "" {
			t = string(c.TargetKind)
		}
		out[c.ID.String()] = carrierLabel{Host: c.Host, Target: t}
	}
	return out, nil
}

// buildRunView turns a report and the run's summary into the page. It reads
// states and classes only through the closed vocabularies.
func buildRunView(rep rotation.RunReport, sum RunSummary, labels map[string]carrierLabel) runView {
	state := uiRunState(string(rep.State))
	class := uiRunClass(string(rep.Class))
	oldV, newV := uiVersion(sum.OldVersion), uiVersion(sum.NewVersion)
	if rep.Done && uiVersion(rep.Version) != "" {
		newV = uiVersion(rep.Version)
	}
	// A failed run still recording its incident stays live: the page refreshes
	// into the incident instead of stopping on a failure without one.
	v := runView{Started: when(sum.CreatedAt), By: sum.StartedBy, Live: !rep.Done && (!rep.Failed || rep.Settling)}
	switch {
	case oldV != "" && newV != "":
		v.Title = "Rotation v" + oldV + " → v" + newV
	case newV != "":
		v.Title = "Rotation to v" + newV
	default:
		v.Title = "Rotation"
	}
	waiting := rep.Approval != nil && rep.Approval.Status == "pending" && !rep.Failed
	if rep.Approval != nil && uiApprovalStatuses[rep.Approval.Status] {
		v.Approval = rep.Approval.Status
	}
	v.Status, v.StatusTone = runResult(state, class, rep.IncidentOpened)
	if rep.Done {
		v.Status, v.StatusTone = runResult(string(rotation.StateDone), class, false)
	}
	if waiting {
		v.Status, v.StatusTone = "Waiting for approval", "run"
	}
	old, nu := "the previous version", "the new version"
	if oldV != "" {
		old = "v" + oldV
	}
	if newV != "" {
		nu = "v" + newV
	}
	v.Banner = runBannerOf(rep, state, class, old, nu, waiting)

	var verifyFailed int
	for _, c := range rep.Carriers {
		cv := runCarrierView{Host: "Carrier", Target: c.CarrierID, Class: uiStepClass(string(c.Class))}
		if l, ok := labels[c.CarrierID]; ok {
			cv.Host, cv.Target = l.Host, l.Target
		}
		if _, err := uuid.Parse(c.CarrierID); err != nil {
			cv.Target = ""
		}
		cv.Phase = "Lay out"
		if c.Phase == rotation.PhaseVerify {
			cv.Phase = "Verify"
			if cv.Class != "" {
				verifyFailed++
			}
		}
		cv.State, cv.Tone = carrierStateLabel(c.State)
		v.Carriers = append(v.Carriers, cv)
	}
	v.Steps = runSteps(rep, state, class, oldV, newV, verifyFailed)
	return v
}

// capital starts a sentence that opens with a version name ("v11", or "the
// previous version" when the label is unknown).
func capital(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' || s[0] == 'v' && len(s) > 1 && s[1] >= '0' && s[1] <= '9' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

// uiStepClass is the class a carrier's step may record (the rotation_steps
// list); anything else is dropped.
func uiStepClass(c string) string {
	switch rotation.Class(c) {
	case rotation.ClassDeployFailed, rotation.ClassFingerprintMismatch, rotation.ClassUnhealthy, rotation.ClassVerifyFailed:
		return c
	}
	return ""
}

func carrierStateLabel(s string) (string, string) {
	switch s {
	case rotation.CarrierPending:
		return "Pending", "outline"
	case rotation.CarrierOK:
		return "Confirmed", "ok"
	case rotation.CarrierFailed:
		return "Failed", "danger"
	case rotation.CarrierStale:
		return "Stale", "warn"
	}
	return "Unknown", "muted"
}

func runBannerOf(rep rotation.RunReport, state, class, old, nu string, waiting bool) runBanner {
	switch {
	case rep.Failed && rotation.Class(class) == rotation.ClassPolicyDenied:
		return runBanner{Tone: "warn", Head: "Approval refused: nothing was changed.",
			Body: "The approval this rotation waited for was rejected or expired, so no run started. " + old + " stays active."}
	case rep.Failed && rep.IncidentOpened:
		return runBanner{Tone: "danger", Head: "Rotation failed: an incident is open.",
			Body: capital(old) + " was not revoked. Carriers marked stale did not confirm " + nu + "; lay them out again before the next rotation.", Class: class}
	case rep.Failed:
		return runBanner{Tone: "warn", Head: "Rotation failed safely: " + old + " is active on every carrier, nothing was revoked.", Class: class}
	case rep.Done && rotation.Class(class) == rotation.ClassOriginalKeyUnknown:
		return runBanner{Tone: "warn", Head: "Rotation done: " + nu + " is active on every carrier.",
			Body: "The provider key behind " + old + " was not known, so it was not revoked."}
	case rep.Done:
		return runBanner{Tone: "ok", Head: "Rotation done: " + nu + " is active on every carrier and " + old + " was revoked."}
	case waiting:
		return runBanner{Head: "Waiting for approval: nothing has changed yet.", Body: "The run starts once the approval is given."}
	case rotation.State(state) == rotation.StateRollingBack:
		return runBanner{Tone: "warn", Head: "Rolling back: carriers that took " + nu + " are being put back on " + old + ".", Class: class}
	case rotation.State(state) == rotation.StateRevokingOld && rotation.Class(class) == rotation.ClassRevokeFailed:
		return runBanner{Tone: "warn", Head: "Revoke pending: every carrier holds " + nu + ", " + old + " is still alive.",
			Body: "An incident is open; the revoke is retried.", Class: class}
	}
	return runBanner{Head: "Rotation in progress: " + old + " stays active until every carrier confirms " + nu + "."}
}

const (
	stepNewVersion = iota
	stepLayOut
	stepVerify
	stepRevoke
)

// failStep is the step a failure class belongs to; a class that names no step
// is placed by how far the carriers got.
func failStep(class string, rep rotation.RunReport) int {
	switch rotation.Class(class) {
	case rotation.ClassPrepareFailed, rotation.ClassPolicyDenied:
		return stepNewVersion
	case rotation.ClassNoCarriers, rotation.ClassDeployFailed, rotation.ClassSuperseded:
		return stepLayOut
	case rotation.ClassFingerprintMismatch, rotation.ClassUnhealthy, rotation.ClassVerifyFailed, rotation.ClassRollbackUnconfirmed:
		return stepVerify
	case rotation.ClassRevokeFailed:
		return stepRevoke
	}
	at := stepNewVersion
	for _, c := range rep.Carriers {
		if c.Phase == rotation.PhaseVerify {
			return stepVerify
		}
		at = stepLayOut
	}
	return at
}

func runSteps(rep rotation.RunReport, state, class, oldV, newV string, verifyFailed int) []runStep {
	n, laid, verified := len(rep.Carriers), 0, 0
	for _, c := range rep.Carriers {
		if c.Phase == rotation.PhaseVerify {
			laid++
			if c.State == rotation.CarrierOK {
				verified++
			}
		}
	}
	steps := []runStep{{Name: "New version"}, {Name: "Lay out"}, {Name: "Verify"}, {Name: "Revoke old"}}
	mark := func(at int, how string) { // steps before at are done, at is how, after it skipped
		for i := range steps {
			switch {
			case i < at:
				steps[i].State = "done"
			case i == at:
				steps[i].State = how
			default:
				steps[i].State = "skip"
			}
		}
	}
	switch {
	case rep.Done:
		mark(len(steps), "")
		if rotation.Class(class) == rotation.ClassOriginalKeyUnknown {
			steps[stepRevoke].State = "skip"
		}
	case rep.Failed || rotation.State(state) == rotation.StateRollingBack:
		mark(failStep(class, rep), "fail")
	default:
		at := map[rotation.State]int{rotation.StateNewVersion: stepNewVersion, rotation.StateDeploying: stepLayOut,
			rotation.StateVerifying: stepVerify, rotation.StateRevokingOld: stepRevoke}[rotation.State(state)]
		mark(at, "now")
		for i := at + 1; i < len(steps); i++ {
			steps[i].State = "" // not reached yet, not skipped
		}
	}
	nv := "v" + newV
	if newV == "" {
		nv = "new version"
	}
	ov := "v" + oldV
	if oldV == "" {
		ov = "old version"
	}
	switch steps[stepNewVersion].State {
	case "done":
		steps[stepNewVersion].Note = nv + " created"
	case "now":
		steps[stepNewVersion].Note = "creating"
	case "fail":
		steps[stepNewVersion].Note = class
	}
	switch {
	case steps[stepLayOut].State == "skip":
		steps[stepLayOut].Note = "not started"
	case n == 0 && steps[stepLayOut].State != "":
		steps[stepLayOut].Note = "no carriers"
	case steps[stepLayOut].State != "":
		steps[stepLayOut].Note = strconv.Itoa(laid) + " / " + strconv.Itoa(n) + " carriers"
	}
	switch steps[stepVerify].State {
	case "done", "now":
		steps[stepVerify].Note = strconv.Itoa(verified) + " / " + strconv.Itoa(n) + " verified"
	case "fail":
		steps[stepVerify].Note = class
		if verifyFailed > 0 && class != "" {
			steps[stepVerify].Note = strconv.Itoa(verifyFailed) + " " + class
		}
	case "skip":
		steps[stepVerify].Note = "not started"
	}
	switch steps[stepRevoke].State {
	case "done":
		steps[stepRevoke].Note = ov + " revoked"
	case "now":
		steps[stepRevoke].Note = "revoking " + ov
	case "skip":
		steps[stepRevoke].Note = "skipped: " + ov + " stays"
	}
	return steps
}
