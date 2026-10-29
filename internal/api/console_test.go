package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// fakeApprovals is the durable service's stand-in: it records every decision
// that reaches it, which is exactly what the refusal tests assert never happens.
type fakeApprovals struct {
	items   map[uuid.UUID]deployment.Approval
	decided []deployment.DecideInput
	err     error
}

func (s *fakeApprovals) ListApprovals(_ context.Context, org uuid.UUID, _ int) ([]deployment.Approval, error) {
	var out []deployment.Approval
	for _, a := range s.items {
		out = append(out, a)
	}
	return out, nil
}

func (s *fakeApprovals) GetApproval(_ context.Context, _ uuid.UUID, id uuid.UUID) (deployment.Approval, error) {
	if a, ok := s.items[id]; ok {
		return a, nil
	}
	return deployment.Approval{}, deployment.ErrNotFound
}

func (s *fakeApprovals) Decide(_ context.Context, in deployment.DecideInput) (deployment.DecideResult, error) {
	s.decided = append(s.decided, in)
	if s.err != nil {
		return deployment.DecideResult{}, s.err
	}
	if in.Approve {
		return deployment.DecideResult{Status: "approved", JobID: uuid.New()}, nil
	}
	return deployment.DecideResult{Status: "rejected"}, nil
}

type consoleFixture struct {
	*routeFixture
	svc      *fakeApprovals
	approval deployment.Approval
	admin    tenancy.User
	adminTok string
}

func newConsoleFixture(t *testing.T) *consoleFixture {
	t.Helper()
	f := newRouteFixture(t)
	c := &consoleFixture{routeFixture: f, svc: &fakeApprovals{items: map[uuid.UUID]deployment.Approval{}}}
	f.router = NewRouter(obs.New(io.Discard), f.pool, Deps{Approvals: c.svc, PublicURL: "https://keep.example.test"})
	requester := f.mustUser("requester")
	c.admin = f.mustAdmin("boss")
	c.adminTok = f.mustToken(identity.KindUser, c.admin.ID, "org:"+f.org.ID.String())
	c.approval = deployment.Approval{ID: uuid.New(), Status: "requested", RequestedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		BindingHash: strings.Repeat("ab", 32), RequestID: "req-1",
		Requester: audit.Actor{Type: audit.ActorAgent, ID: uuid.NewString(), SponsorID: requester.ID.String(), Via: audit.ViaAPI},
		SecretID:  uuid.New(), SecretName: "db-password", SecretClass: "prod", Scope: tenancy.Org(f.org.ID), RunnerID: uuid.New(),
		Target: runnerproto.Target{Kind: runnerproto.TargetFile, Path: "/srv/app/key", Mode: 0o600, UID: 1001, GID: 1001}}
	c.svc.items[c.approval.ID] = c.approval
	return c
}

type consoleSession struct {
	cookie *http.Cookie
	csrf   string
}

var csrfField = regexp.MustCompile(`name="csrf" value="([a-z2-7]+)"`)

func (c *consoleFixture) req(method, path string, s *consoleSession, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	c.t.Helper()
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Host = "keep.example.test"
	if s != nil && s.cookie != nil {
		r.AddCookie(s.cookie)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	c.router.ServeHTTP(rec, r)
	return rec
}

// login signs in with a token and returns the session plus the CSRF token the card page embeds.
func (c *consoleFixture) login(token string) *consoleSession {
	c.t.Helper()
	rec := c.req(http.MethodPost, "/console/login", nil, url.Values{"token": {token}}, map[string]string{"Origin": "https://keep.example.test"})
	if rec.Code != http.StatusSeeOther {
		c.t.Fatalf("login: status %d: %s", rec.Code, rec.Body.String())
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "keep_console" {
			s := &consoleSession{cookie: &http.Cookie{Name: ck.Name, Value: ck.Value}} //nolint:gosec // G124: a request cookie in a test, never sent by a server
			page := c.req(http.MethodGet, "/console/approvals/"+c.approval.ID.String(), s, nil, nil)
			if m := csrfField.FindStringSubmatch(page.Body.String()); m != nil {
				s.csrf = m[1]
			}
			return s
		}
	}
	c.t.Fatal("login set no console cookie")
	return nil
}

func (c *consoleFixture) decide(s *consoleSession, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	if hdr == nil {
		hdr = map[string]string{"Origin": "https://keep.example.test"}
	}
	return c.req(http.MethodPost, "/console/approvals/"+c.approval.ID.String()+"/decision", s, form, hdr)
}

func (c *consoleFixture) goodForm(s *consoleSession, decision string) url.Values {
	return url.Values{"csrf": {s.csrf}, "binding": {c.approval.BindingHash}, "decision": {decision}, "reason": {"checked with the owner"}}
}

func TestConsoleLoginCookieFlagsAndBadToken(t *testing.T) {
	c := newConsoleFixture(t)
	rec := c.req(http.MethodPost, "/console/login", nil, url.Values{"token": {c.adminTok}}, map[string]string{"Origin": "https://keep.example.test"})
	var ck *http.Cookie
	for _, x := range rec.Result().Cookies() {
		if x.Name == "keep_console" {
			ck = x
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/console" || strings.Contains(ck.Value, c.adminTok) {
		t.Fatalf("session cookie flags wrong: %+v", ck)
	}
	bad := c.req(http.MethodPost, "/console/login", nil, url.Values{"token": {"keep_u_" + strings.Repeat("a", 52)}}, map[string]string{"Origin": "https://keep.example.test"})
	if bad.Code != http.StatusUnauthorized || len(bad.Result().Cookies()) != 0 || strings.Contains(bad.Body.String(), "keep_u_") {
		t.Fatal("a bad token must answer 401 without a cookie and without echoing the token")
	}
	cross := c.req(http.MethodPost, "/console/login", nil, url.Values{"token": {c.adminTok}}, map[string]string{"Origin": "https://evil.example"})
	if cross.Code != http.StatusForbidden || len(cross.Result().Cookies()) != 0 {
		t.Fatal("cross-origin login accepted")
	}
}

func TestConsoleNeedsSession(t *testing.T) {
	c := newConsoleFixture(t)
	for _, p := range []string{"/console/approvals", "/console/approvals/" + c.approval.ID.String()} {
		rec := c.req(http.MethodGet, p, nil, nil, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/console/login" || strings.Contains(rec.Body.String(), "db-password") {
			t.Fatalf("%s without a session: %d", p, rec.Code)
		}
	}
	rec := c.decide(&consoleSession{}, url.Values{"decision": {"approve"}}, nil)
	if rec.Code == http.StatusSeeOther && rec.Header().Get("Location") != "/console/login" || len(c.svc.decided) != 0 {
		t.Fatal("decision without a session reached the service")
	}
}

func TestConsoleCardShowsRequestWithStrictHeadersAndNoScripts(t *testing.T) {
	c := newConsoleFixture(t)
	s := c.login(c.adminTok)
	rec := c.req(http.MethodGet, "/console/approvals/"+c.approval.ID.String(), s, nil, nil)
	body := rec.Body.String()
	for _, want := range []string{"db-password", "prod", "/srv/app/key", c.approval.BindingHash, c.approval.Requester.SponsorID, "agent", c.approval.RunnerID.String(), "1001", `name="csrf"`} {
		if !strings.Contains(body, want) {
			t.Errorf("card misses %q", want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "style-src 'self'", "form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe") || strings.Contains(csp, "script-src") && !strings.Contains(csp, "script-src 'none'") {
		t.Errorf("CSP allows scripts: %s", csp)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("missing no-store / nosniff / no-referrer")
	}
	lower := strings.ToLower(body)
	for _, bad := range []string{"<script", "javascript:", " onclick", " onload", " onsubmit", "style=", "<style", "http://", "https://"} {
		if strings.Contains(lower, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	if !strings.Contains(lower, `href="/console/console.css"`) {
		t.Error("stylesheet must be the same-origin file")
	}
}

func TestConsoleEscapesNames(t *testing.T) {
	c := newConsoleFixture(t)
	c.approval.SecretName = `<img src=x onerror=alert(1)>"`
	c.svc.items[c.approval.ID] = c.approval
	s := c.login(c.adminTok)
	body := c.req(http.MethodGet, "/console/approvals/"+c.approval.ID.String(), s, nil, nil).Body.String()
	if strings.Contains(body, "<img") || !strings.Contains(body, "&lt;img") {
		t.Fatal("secret name is not escaped")
	}
}

func TestConsoleListShowsOnlyApprovableScopes(t *testing.T) {
	c := newConsoleFixture(t)
	member := c.mustUser("plain")
	if _, err := c.tr.CreateMembership(c.ctx, c.org.ID, member.ID, tenancy.Org(c.org.ID), string(identity.RoleMember)); err != nil {
		t.Fatal("membership")
	}
	ms := c.login(c.mustToken(identity.KindUser, member.ID, "org:"+c.org.ID.String()))
	list := c.req(http.MethodGet, "/console/approvals", ms, nil, nil).Body.String()
	if strings.Contains(list, "db-password") {
		t.Fatal("a member without approve right sees the request")
	}
	if rec := c.req(http.MethodGet, "/console/approvals/"+c.approval.ID.String(), ms, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("card for a non-approver: %d, want 404", rec.Code)
	}
	as := c.login(c.adminTok)
	if list = c.req(http.MethodGet, "/console/approvals", as, nil, nil).Body.String(); !strings.Contains(list, "db-password") || !strings.Contains(list, c.approval.ID.String()) {
		t.Fatal("admin does not see the request")
	}
}

// A token narrowed to another scope does not reach the request even for an admin.
func TestConsoleNarrowTokenDoesNotReachOtherScope(t *testing.T) {
	c := newConsoleFixture(t)
	narrow := c.login(c.mustToken(identity.KindUser, c.admin.ID, "org:"+uuid.NewString()))
	if rec := c.req(http.MethodGet, "/console/approvals/"+c.approval.ID.String(), narrow, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("card through a narrow token: %d, want 404", rec.Code)
	}
	if strings.Contains(c.req(http.MethodGet, "/console/approvals", narrow, nil, nil).Body.String(), "db-password") {
		t.Fatal("list through a narrow token shows the request")
	}
}

// Test 4: a decision POST without a valid CSRF token is refused.
func TestConsoleDecisionNeedsCSRFAndSameOrigin(t *testing.T) {
	c := newConsoleFixture(t)
	s := c.login(c.adminTok)
	if s.csrf == "" {
		t.Fatal("card carries no csrf token")
	}
	noToken := c.goodForm(s, "approve")
	noToken.Del("csrf")
	wrong := c.goodForm(s, "approve")
	wrong.Set("csrf", strings.Repeat("a", len(s.csrf)))
	for name, tc := range map[string]struct {
		form url.Values
		hdr  map[string]string
	}{
		"no csrf":            {noToken, nil},
		"wrong csrf":         {wrong, nil},
		"foreign origin":     {c.goodForm(s, "approve"), map[string]string{"Origin": "https://evil.example"}},
		"cross-site":         {c.goodForm(s, "approve"), map[string]string{"Origin": "https://keep.example.test", "Sec-Fetch-Site": "cross-site"}},
		"no origin, no site": {c.goodForm(s, "approve"), map[string]string{"X-None": "1"}},
		"null origin alone":  {c.goodForm(s, "approve"), map[string]string{"Origin": "null"}},
	} {
		rec := c.decide(s, tc.form, tc.hdr)
		if rec.Code != http.StatusForbidden || len(c.svc.decided) != 0 {
			t.Fatalf("%s: status %d, decisions reaching the service: %d", name, rec.Code, len(c.svc.decided))
		}
	}
	// Positive control: the same request with everything right goes through.
	if rec := c.decide(s, c.goodForm(s, "approve"), nil); rec.Code != http.StatusSeeOther || len(c.svc.decided) != 1 {
		t.Fatalf("control approval failed: %d", rec.Code)
	}
	// The page sends Referrer-Policy: no-referrer, and browsers then send
	// "Origin: null" on a same-origin form POST; Sec-Fetch-Site vouches for it.
	// Found in a real browser run, not by the httptest-only tests.
	hdr := map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}
	if rec := c.decide(s, c.goodForm(s, "approve"), hdr); rec.Code != http.StatusSeeOther || len(c.svc.decided) != 2 {
		t.Fatalf("a browser form post with a null origin was refused: %d", rec.Code)
	}
}

// Test 2: an agent never approves; nobody approves their own request.
func TestConsoleAgentAndSelfApprovalAre403(t *testing.T) {
	c := newConsoleFixture(t)
	agent := c.mustAgent(c.admin, "robot")
	agentSess := c.login(c.mustToken(identity.KindAgent, agent.ID, "org:"+c.org.ID.String()))
	// The agent's pages are 403, so read its session's own csrf from storage:
	// the refusals below must come from the kind check, not from a missing token.
	if err := c.pool.QueryRow(c.ctx, `SELECT csrf FROM console_sessions WHERE principal_id=$1`, agent.ID).Scan(&agentSess.csrf); err != nil || agentSess.csrf == "" {
		t.Fatal("agent session csrf not found")
	}
	rec := c.req(http.MethodGet, "/console/approvals/"+c.approval.ID.String(), agentSess, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("agent card: %d, want 403", rec.Code)
	}
	for _, d := range []string{"approve", "reject"} {
		rec = c.decide(agentSess, url.Values{"csrf": {agentSess.csrf}, "binding": {c.approval.BindingHash}, "decision": {d}, "reason": {"r"}}, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("agent %s: %d, want 403", d, rec.Code)
		}
	}
	// the requester themself (a human who is also an admin)
	self := c.mustAdmin("selfish")
	c.approval.Requester = audit.Actor{Type: audit.ActorUser, ID: self.ID.String(), Via: audit.ViaAPI}
	c.svc.items[c.approval.ID] = c.approval
	ss := c.login(c.mustToken(identity.KindUser, self.ID, "org:"+c.org.ID.String()))
	if rec = c.decide(ss, c.goodForm(ss, "approve"), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("own request: %d, want 403", rec.Code)
	}
	if len(c.svc.decided) != 0 {
		t.Fatal("a refused decision reached the service")
	}
}

func TestConsoleSponsorMayApproveAgentRequest(t *testing.T) {
	c := newConsoleFixture(t)
	c.approval.Requester = audit.Actor{Type: audit.ActorAgent, ID: uuid.NewString(), SponsorID: c.admin.ID.String(), Via: audit.ViaAPI}
	c.svc.items[c.approval.ID] = c.approval
	s := c.login(c.adminTok)
	if rec := c.decide(s, c.goodForm(s, "approve"), nil); rec.Code != http.StatusSeeOther || len(c.svc.decided) != 1 {
		t.Fatalf("sponsor approval: %d", rec.Code)
	}
}

func TestConsoleDecisionPassesWhatWasShown(t *testing.T) {
	c := newConsoleFixture(t)
	s := c.login(c.adminTok)
	if rec := c.decide(s, c.goodForm(s, "approve"), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("approve: %d", rec.Code)
	}
	got := c.svc.decided[0]
	if got.ApprovalID != c.approval.ID || got.ApproverID != c.admin.ID || !got.ApproverIsUser || !got.Approve || got.BindingHash != c.approval.BindingHash || got.Reason != "checked with the owner" || got.OrgID != c.org.ID {
		t.Fatalf("decision lost what the human saw: %+v", got)
	}
	// "Reject" needs a reason.
	form := c.goodForm(s, "reject")
	form.Set("reason", " ")
	if rec := c.decide(s, form, nil); rec.Code != http.StatusBadRequest || len(c.svc.decided) != 1 {
		t.Fatalf("reject without a reason: %d", rec.Code)
	}
	if rec := c.decide(s, c.goodForm(s, "maybe"), nil); rec.Code != http.StatusBadRequest || len(c.svc.decided) != 1 {
		t.Fatalf("unknown decision: %d", rec.Code)
	}
}

func TestConsoleServiceRefusalsAreShownNotHidden(t *testing.T) {
	c := newConsoleFixture(t)
	s := c.login(c.adminTok)
	for err, want := range map[error]int{deployment.ErrExpired: http.StatusConflict, deployment.ErrAlreadyDecided: http.StatusConflict,
		deployment.ErrBindingMismatch: http.StatusConflict, deployment.ErrSelfApproval: http.StatusForbidden, deployment.ErrNotHuman: http.StatusForbidden,
		deployment.ErrRefused: http.StatusConflict, deployment.ErrUnavailable: http.StatusServiceUnavailable} {
		c.svc.err = err
		rec := c.decide(s, c.goodForm(s, "approve"), nil)
		if rec.Code != want || strings.Contains(rec.Body.String(), "deployment:") {
			t.Errorf("%v: status %d (want %d), body must hold a template, never the raw error", err, rec.Code, want)
		}
	}
}

func TestConsoleExpiredCardOffersNoButtons(t *testing.T) {
	c := newConsoleFixture(t)
	c.approval.Status = "expired"
	c.svc.items[c.approval.ID] = c.approval
	s := c.login(c.adminTok)
	body := c.req(http.MethodGet, "/console/approvals/"+c.approval.ID.String(), s, nil, nil).Body.String()
	if strings.Contains(body, `name="decision"`) || !strings.Contains(body, "expired") {
		t.Fatal("expired request still offers a decision")
	}
}

func TestConsoleNetworkTemplateShowsDestinationsAndPinningWarning(t *testing.T) {
	c := newConsoleFixture(t)
	c.approval.NetAllowlist = []string{"api.example.test:443", "gist.example.test:443"}
	c.svc.items[c.approval.ID] = c.approval
	s := c.login(c.adminTok)
	body := c.req(http.MethodGet, "/console/approvals/"+c.approval.ID.String(), s, nil, nil).Body.String()
	for _, want := range []string{"api.example.test:443", "gist.example.test:443",
		"Pinning restricts where the value can go, not what is done with it. If the token can write to an approved API (a gist, an issue), that is a channel too"} {
		if !strings.Contains(body, want) {
			t.Errorf("network request card misses %q", want)
		}
	}
}

func TestConsoleExecCardShowsTemplateModeAndParameterNames(t *testing.T) {
	c := newConsoleFixture(t)
	c.approval.Target = runnerproto.Target{}
	c.approval.NetAllowlist = []string{"api.example.test:443"}
	c.approval.Exec = &deployment.ApprovalExec{TemplateID: "gh-issues", Digest: strings.Repeat("ab", 32), Mode: "allowlist", ParamNames: []string{"path"}}
	c.svc.items[c.approval.ID] = c.approval
	s := c.login(c.adminTok)
	body := c.req(http.MethodGet, "/console/approvals/"+c.approval.ID.String(), s, nil, nil).Body.String()
	for _, want := range []string{"gh-issues", "allowlist", "abababababababab", "path", "api.example.test:443"} {
		if !strings.Contains(body, want) {
			t.Errorf("exec card misses %q", want)
		}
	}
	if strings.Contains(body, "0000") || strings.Contains(body, "uid / gid") {
		t.Error("exec card renders deployment target rows")
	}
}

func TestConsoleLogoutEndsSession(t *testing.T) {
	c := newConsoleFixture(t)
	s := c.login(c.adminTok)
	out := c.req(http.MethodPost, "/console/logout", s, url.Values{"csrf": {s.csrf}}, map[string]string{"Origin": "https://keep.example.test"})
	if out.Code != http.StatusSeeOther {
		t.Fatalf("logout: %d", out.Code)
	}
	if rec := c.req(http.MethodGet, "/console/approvals", s, nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatal("session survived logout")
	}
}

// The console renders metadata only. A canary sits in a field the service holds
// but no page shows (Requester.Via); a second request carries it in a rendered
// field as a positive control, so a silent interception cannot pass.
func TestConsoleNeverRendersACanary(t *testing.T) {
	c := newConsoleFixture(t)
	can := canary.New()
	if !can.In("x"+can.Value(1)) || !can.In(strings.ToLower(can.Value(1))) {
		t.Fatal("canary detector is blind")
	}
	hidden := c.approval
	hidden.ID = uuid.New()
	hidden.Requester.Via = audit.ActorVia(can.Value(1))
	hidden.Exec = &deployment.ApprovalExec{TemplateID: "gh-issues", Digest: "d", Mode: "allowlist", ParamNames: []string{"path"}}
	c.svc.items[hidden.ID] = hidden
	shown := c.approval
	shown.ID = uuid.New()
	shown.SecretName = can.Value(2)
	c.svc.items[shown.ID] = shown

	s := c.login(c.adminTok)
	page := func(p string) string {
		rec := c.req(http.MethodGet, p, s, nil, nil)
		if rec.Body.Len() == 0 {
			t.Fatalf("%s: empty page", p)
		}
		all := rec.Body.String()
		for k, v := range rec.Header() {
			all += k + strings.Join(v, ",")
		}
		return all
	}
	if !can.In(page("/console/approvals/" + shown.ID.String())) {
		t.Fatal("positive control: a canary in a rendered field was not seen; the test proves nothing")
	}
	for _, p := range []string{"/console/login", "/console/approvals", "/console/approvals/" + hidden.ID.String(), "/console/console.css"} {
		if got := page(p); can.In(strings.ReplaceAll(got, can.Value(2), "")) {
			t.Fatalf("%s leaks a canary", p)
		}
	}
}

func TestConsoleUnavailableWithoutApprovalService(t *testing.T) {
	f := newRouteFixture(t)
	rec := f.do(http.MethodGet, "/console/login", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login page must still render: %d", rec.Code)
	}
}
