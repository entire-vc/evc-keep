package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// fakeDiscover pages report the way deployment.Repo does: pageSize lines
// (default deployment.DiscoverPageSize) from offset, Total and AllMatch of
// the whole report, an offset past it refused.
type fakeDiscover struct {
	*fakeDeployments
	report    deployment.DiscoverReport
	pageSize  int
	submitErr error
	requests  []deployment.DiscoverRequest
	readOrgs  []uuid.UUID
	offsets   []int
}

func (s *fakeDiscover) page(offset int) (deployment.DiscoverReport, error) {
	rep := s.report
	if rep.State != deployment.DiscoverCompleted {
		if offset != 0 {
			return deployment.DiscoverReport{}, deployment.ErrInvalidArgument
		}
		rep.Items = nil
		return rep, nil
	}
	size := s.pageSize
	if size == 0 {
		size = deployment.DiscoverPageSize
	}
	rep.Total, rep.Offset, rep.AllMatch = len(s.report.Items), offset, true
	for _, it := range s.report.Items {
		rep.AllMatch = rep.AllMatch && it.Verdict == deployment.VerdictMatch
	}
	if offset < 0 || offset > rep.Total {
		return deployment.DiscoverReport{}, deployment.ErrInvalidArgument
	}
	rep.Items = s.report.Items[offset:min(offset+size, rep.Total)]
	return rep, nil
}

func (s *fakeDiscover) SubmitDiscover(_ context.Context, in deployment.DiscoverRequest) (deployment.DiscoverReport, error) {
	s.requests = append(s.requests, in)
	if s.submitErr != nil {
		return deployment.DiscoverReport{}, s.submitErr
	}
	return s.page(0)
}

func (s *fakeDiscover) DiscoverReport(_ context.Context, org uuid.UUID, _ string, offset int) (deployment.DiscoverReport, error) {
	s.readOrgs = append(s.readOrgs, org)
	s.offsets = append(s.offsets, offset)
	if s.submitErr != nil {
		return deployment.DiscoverReport{}, s.submitErr
	}
	return s.page(offset)
}

func newDiscoverFixture(t *testing.T, rep deployment.DiscoverReport) (*deployFixture, *fakeDiscover, string) {
	t.Helper()
	svc := &fakeDiscover{fakeDeployments: &fakeDeployments{}, report: rep}
	f := newDeployFixture(t, svc)
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Deployments: svc})
	return f, svc, fmt.Sprintf("/orgs/%s/carriers/discover", f.org.ID)
}

func sampleDiscover() deployment.DiscoverReport {
	return deployment.DiscoverReport{RunnerID: uuid.New(), StoreID: uuid.New(), Host: "host-a", State: deployment.DiscoverCompleted,
		Items: []deployment.DiscoverItem{
			{Verdict: deployment.VerdictMatch, CarrierID: uuid.New(), Path: "/srv/a/.env", Name: "DB_PASSWORD", Fingerprint: "kfp1:k1:abcdefghijklmnop", Len: leakLen},
			{Verdict: deployment.VerdictSprawl, Path: "/tmp/x/.env", Name: "DB_PASSWORD", Fingerprint: "kfp1:k1:abcdefghijklmnop", Len: leakLen, Incident: true},
		}}
}

func TestCarrierDiscover_ReportsFindingsAndOpenIncident(t *testing.T) {
	f, svc, path := newDiscoverFixture(t, sampleDiscover())
	rec := f.do(http.MethodPost, path, f.bearer, map[string]any{"runner_id": uuid.NewString(), "store_id": uuid.NewString(), "request_id": "dr-1"})
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body)
	}
	var out CarrierDiscoverResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.OK || out.State != "completed" || out.RequestID != "dr-1" || len(out.Findings) != 2 || out.Findings[1].Verdict != "sprawl" || !out.Findings[1].Incident || out.Findings[0].Incident {
		t.Fatalf("answer is wrong: %s", rec.Body)
	}
	if len(svc.requests) != 1 || svc.requests[0].OrgID != f.org.ID {
		t.Fatalf("service got %+v", svc.requests)
	}
	if rec = f.do(http.MethodGet, path+"/dr-1", f.bearer, nil); rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	if len(svc.readOrgs) != 1 || svc.readOrgs[0] != f.org.ID {
		t.Fatalf("status read for orgs %v, want only the caller's %s", svc.readOrgs, f.org.ID)
	}
	svc.report.State, svc.report.Items = deployment.DiscoverPending, nil
	if rec = f.do(http.MethodGet, path+"/dr-1", f.bearer, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("pending = %d, want 202", rec.Code)
	}
}

// Discovery makes a host read its files: a member who may only deploy, and a
// caller of another organization, never reach the service.
func TestCarrierDiscover_NeedsManageRunners(t *testing.T) {
	f, svc, path := newDiscoverFixture(t, sampleDiscover())
	member := f.mustUser("member")
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, member.ID, tenancy.Org(f.org.ID), string(identity.RoleMember)); err != nil {
		t.Fatal(err)
	}
	bearer := f.mustToken(identity.KindUser, member.ID, "org:"+f.org.ID.String())
	body := map[string]any{"runner_id": uuid.NewString(), "store_id": uuid.NewString()}
	if rec := f.do(http.MethodPost, path, bearer, body); rec.Code != http.StatusForbidden {
		t.Fatalf("member POST = %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(http.MethodGet, path+"/dr-1", bearer, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("member GET = %d", rec.Code)
	}
	if rec := f.do(http.MethodPost, path, "", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous POST = %d", rec.Code)
	}
	if len(svc.requests) != 0 {
		t.Fatal("a refused caller reached the service")
	}
	if rec := f.do(http.MethodPost, path, f.bearer, body); rec.Code != http.StatusOK {
		t.Fatalf("admin POST = %d (positive control)", rec.Code)
	}
}

func TestCarrierDiscover_RefusesWhatIsNotRunnerAndStore(t *testing.T) {
	c := canary.New()
	f, svc, path := newDiscoverFixture(t, sampleDiscover())
	ok := uuid.NewString()
	for name, body := range map[string]map[string]any{
		"no runner": {"store_id": ok}, "no store": {"runner_id": ok}, "path": {"runner_id": ok, "store_id": ok, "path": "/etc"},
		"value": {"runner_id": ok, "store_id": ok, "value": c.Value(0)}, "bad id": {"runner_id": "x", "store_id": ok},
		"bad request id": {"runner_id": ok, "store_id": ok, "request_id": "a b"},
	} {
		rec := f.do(http.MethodPost, path, f.bearer, body)
		if rec.Code != http.StatusBadRequest || c.In(rec.Body.String()) || c.In(f.logbuf.String()) {
			t.Fatalf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	if len(svc.requests) != 0 {
		t.Fatal("a refused body reached the service")
	}
}

func TestCarrierDiscover_ServiceRefusalsAreClosedAndQuoteNothing(t *testing.T) {
	c := canary.New()
	for err, code := range map[error]int{deployment.ErrNotFound: 404, deployment.ErrConflict: 409, deployment.ErrDiscoverBusy: 409,
		deployment.ErrDiscoverRateLimited: 429, deployment.ErrDiscoverTooManyCarriers: 400, deployment.ErrInvalidArgument: 400, deployment.ErrUnavailable: 503} {
		f, svc, path := newDiscoverFixture(t, sampleDiscover())
		svc.submitErr = fmt.Errorf("%w: %s host-a /srv/app/.env", err, c.Value(0))
		rec := f.do(http.MethodPost, path, f.bearer, map[string]any{"runner_id": uuid.NewString(), "store_id": uuid.NewString()})
		body := rec.Body.String() + fmt.Sprint(rec.Header())
		if rec.Code != code || c.In(body) || c.In(f.logbuf.String()) || strings.Contains(body, "host-a") || strings.Contains(body, "/srv/") {
			t.Fatalf("%v: %d %s", err, rec.Code, rec.Body)
		}
	}
}

// The refusal mapping itself, without a database: whatever a service error
// wraps (a value, the host, a path, the registry count) never reaches the
// answer, and every class keeps its fixed status.
func TestCarrierDiscover_WriteFailureQuotesNothingWithoutADatabase(t *testing.T) {
	c := canary.New()
	requireDetector(t, c)
	routes := &carrierDiscoverRoutes{}
	for err, code := range map[error]int{deployment.ErrNotFound: 404, deployment.ErrConflict: 409, deployment.ErrDiscoverBusy: 409,
		deployment.ErrDiscoverRateLimited: 429, deployment.ErrDiscoverTooManyCarriers: 400, deployment.ErrInvalidArgument: 400,
		deployment.ErrUnavailable: 503, errors.New("anything else"): 503} {
		rec := httptest.NewRecorder()
		wrapped := fmt.Errorf("%w: %s host-a /srv/app/.env 4097", err, c.Value(0))
		if !routes.writeFailure(rec, wrapped, "rid-1") {
			t.Fatalf("%v: not written", err)
		}
		body := rec.Body.String() + fmt.Sprint(rec.Header())
		for _, leak := range []string{"host-a", "/srv/", "4097"} {
			if strings.Contains(body, leak) {
				t.Fatalf("%v: answer quotes %q: %s", err, leak, body)
			}
		}
		if rec.Code != code || c.In(body) || !strings.Contains(body, `"carrier discovery `) {
			t.Fatalf("%v: %d %s", err, rec.Code, body)
		}
	}
	if (&carrierDiscoverRoutes{}).writeFailure(httptest.NewRecorder(), nil, "rid-1") {
		t.Fatal("no error was written as a failure")
	}
}

func TestCarrierDiscover_NoCanaryInAnswerHeadersOrLog(t *testing.T) {
	c := canary.New()
	rep := sampleDiscover()
	rep.State, rep.ErrorClass = deployment.DiscoverFailed, runnerproto.ErrorClass(c.Value(0))
	f, _, path := newDiscoverFixture(t, rep)
	requireDetector(t, c)
	r := f.do(http.MethodGet, path+"/dr-1", f.bearer, nil)
	got := r.Body.String() + fmt.Sprint(r.Header())
	if c.In(got) || c.In(f.logbuf.String()) || !strings.Contains(got, `"internal"`) {
		t.Fatalf("canary reached the answer or the class was not closed: %s", got)
	}
}

// A token of another organization is refused by the org match before the
// service: the path's org is never the one the service reads.
func TestCarrierDiscover_ForeignOrgNeverReachesTheService(t *testing.T) {
	f, svc, _ := newDiscoverFixture(t, sampleDiscover())
	other := fmt.Sprintf("/orgs/%s/carriers/discover", uuid.New())
	body := map[string]any{"runner_id": uuid.NewString(), "store_id": uuid.NewString()}
	if rec := f.do(http.MethodPost, other, f.bearer, body); rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("foreign org POST = %d", rec.Code)
	}
	if rec := f.do(http.MethodGet, other+"/dr-1", f.bearer, nil); rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("foreign org GET = %d", rec.Code)
	}
	if len(svc.requests) != 0 || len(svc.readOrgs) != 0 {
		t.Fatal("a foreign org reached the service")
	}
}

// leakLen is a finding's length no answer may carry: the length of a value
// Keep does not know is the one hint about it before any guess (threat model
// 4.3.4.2), so it is planted where a leak would show it.
const leakLen = 987654321

// allVerdicts is a completed report with one line of every verdict.
func allVerdicts() deployment.DiscoverReport {
	fp := "kfp1:k1:abcdefghijklmnop"
	return deployment.DiscoverReport{RunnerID: uuid.New(), StoreID: uuid.New(), Host: "host-a", State: deployment.DiscoverCompleted,
		Items: []deployment.DiscoverItem{
			{Verdict: deployment.VerdictMatch, CarrierID: uuid.New(), Path: "/srv/a/.env", Name: "A", Fingerprint: fp, Len: leakLen},
			{Verdict: deployment.VerdictStale, CarrierID: uuid.New(), Path: "/srv/b/.env", Name: "B", Fingerprint: fp, Len: leakLen},
			{Verdict: deployment.VerdictSprawl, Path: "/srv/c/.env", Name: "C", Fingerprint: fp, Len: leakLen, Incident: true},
			{Verdict: deployment.VerdictUnknownFind, CarrierID: uuid.New(), Path: "/srv/d/.env", Name: "D", Incident: true},
		}}
}

// Every page of the answer, POST and GET, carries neither the canary nor a
// length: no "length" key and no planted length value, for every verdict.
// The canary rides where a service could hand text out: the class of a
// failed report and the error of a refused page.
func TestCarrierDiscover_NoCanaryAndNoLengthOnAnyPage(t *testing.T) {
	c := canary.New()
	requireDetector(t, c)
	f, svc, path := newDiscoverFixture(t, allVerdicts())
	svc.pageSize = 3
	var bodies []string
	rec := f.do(http.MethodPost, path, f.bearer, map[string]any{"runner_id": uuid.NewString(), "store_id": uuid.NewString(), "request_id": "dr-1"})
	bodies = append(bodies, rec.Body.String()+fmt.Sprint(rec.Header()))
	var first CarrierDiscoverResult
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &first) != nil || first.Total != 4 {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body)
	}
	for offset := 0; offset <= first.Total; offset += 3 {
		rec = f.do(http.MethodGet, fmt.Sprintf("%s/dr-1?offset=%d", path, offset), f.bearer, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET offset %d = %d %s", offset, rec.Code, rec.Body)
		}
		bodies = append(bodies, rec.Body.String()+fmt.Sprint(rec.Header()))
	}
	all := strings.Join(bodies, "\n")
	for _, v := range []string{`"match"`, `"stale"`, `"sprawl"`, `"unknown_find"`} {
		if !strings.Contains(all, v) {
			t.Fatalf("no page carries verdict %s, the check proves nothing: %s", v, all)
		}
	}
	svc.report.State, svc.report.ErrorClass = deployment.DiscoverFailed, runnerproto.ErrorClass(c.Value(0))
	rec = f.do(http.MethodGet, path+"/dr-1", f.bearer, nil)
	bodies = append(bodies, rec.Body.String()+fmt.Sprint(rec.Header()))
	svc.submitErr = fmt.Errorf("%w: %s", deployment.ErrInvalidArgument, c.Value(1))
	rec = f.do(http.MethodGet, path+"/dr-1?offset=9", f.bearer, nil)
	bodies = append(bodies, rec.Body.String()+fmt.Sprint(rec.Header()))
	for i, body := range bodies {
		if c.In(body) || c.In(f.logbuf.String()) {
			t.Fatalf("answer %d carries the canary: %s", i, body)
		}
		if strings.Contains(body, `"length"`) || strings.Contains(body, fmt.Sprint(leakLen)) {
			t.Fatalf("answer %d carries a finding length: %s", i, body)
		}
	}
}

// The page start is one decimal number from 0 to the report's total: no
// sign, no leading zero, no second value, nothing past the total. Every
// refusal is the one closed 400 and never reaches past the parse, except the
// past-total one the service decides.
func TestCarrierDiscover_OffsetIsParsedStrictly(t *testing.T) {
	c := canary.New()
	f, svc, path := newDiscoverFixture(t, allVerdicts())
	svc.pageSize = 2
	for _, ok := range []string{"", "?offset=0", "?offset=2", "?offset=4"} {
		if rec := f.do(http.MethodGet, path+"/dr-1"+ok, f.bearer, nil); rec.Code != http.StatusOK {
			t.Fatalf("%q = %d %s (positive control)", ok, rec.Code, rec.Body)
		}
	}
	if fmt.Sprint(svc.offsets) != "[0 0 2 4]" {
		t.Fatalf("service got offsets %v", svc.offsets)
	}
	svc.offsets = nil
	for _, bad := range []string{"?offset=", "?offset=-1", "?offset=+1", "?offset=01", "?offset=00", "?offset=1.0", "?offset=1e3", "?offset=0x1",
		"?offset=%201", "?offset=1&offset=1", "?offset=99999999999", "?offset=2147483648", "?offset=%zz", "?offset=" + c.Value(0)} {
		rec := f.do(http.MethodGet, path+"/dr-1"+bad, f.bearer, nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"carrier discovery request invalid"`) || c.In(rec.Body.String()) || c.In(f.logbuf.String()) {
			t.Fatalf("%q = %d %s", bad, rec.Code, rec.Body)
		}
	}
	if len(svc.offsets) != 0 {
		t.Fatalf("a refused offset reached the service: %v", svc.offsets)
	}
	// Past the total: the service refuses, the answer is the same 400.
	rec := f.do(http.MethodGet, path+"/dr-1?offset=5", f.bearer, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"carrier discovery request invalid"`) {
		t.Fatalf("offset past total = %d %s", rec.Code, rec.Body)
	}
}

// Pages carry where they start and how long the whole report is; ok is the
// whole report's, so a first page of matches is not ok when a later page
// holds anything else.
func TestCarrierDiscover_PagesCarryOffsetTotalAndTheWholeReportsOK(t *testing.T) {
	rep := allVerdicts()
	f, svc, path := newDiscoverFixture(t, rep)
	svc.pageSize = 1
	read := func(q string) CarrierDiscoverResult {
		t.Helper()
		rec := f.do(http.MethodGet, path+"/dr-1"+q, f.bearer, nil)
		var out CarrierDiscoverResult
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("%s = %d %s", q, rec.Code, rec.Body)
		}
		return out
	}
	first := read("")
	if first.Offset != 0 || first.Total != 4 || len(first.Findings) != 1 || first.Findings[0].Verdict != "match" || first.OK {
		t.Fatalf("first page of matches must say the report is not clean: %+v", first)
	}
	last := read("?offset=3")
	if last.Offset != 3 || last.Total != 4 || len(last.Findings) != 1 || last.Findings[0].Verdict != "unknown_find" || last.OK {
		t.Fatalf("last page: %+v", last)
	}
	if end := read("?offset=4"); end.Offset != 4 || end.Total != 4 || len(end.Findings) != 0 || end.Findings == nil {
		t.Fatalf("page at total: %+v", end)
	}
	// Positive control: a report of matches only is ok on every page.
	svc.report.Items = rep.Items[:1]
	if clean := read(""); !clean.OK || clean.Total != 1 {
		t.Fatalf("clean report: %+v", clean)
	}
	rec := f.do(http.MethodPost, path, f.bearer, map[string]any{"runner_id": uuid.NewString(), "store_id": uuid.NewString()})
	var posted CarrierDiscoverResult
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &posted) != nil || posted.Offset != 0 || !posted.OK || posted.Total != 1 {
		t.Fatalf("POST answers the first page: %d %s", rec.Code, rec.Body)
	}
}
