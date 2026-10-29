package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// ApprovalService is the durable approval boundary the console reads and
// decides through. It carries references and metadata only; *deployment.Repo
// implements it.
type ApprovalService interface {
	ListApprovals(ctx context.Context, org uuid.UUID, limit int) ([]deployment.Approval, error)
	GetApproval(ctx context.Context, org, id uuid.UUID) (deployment.Approval, error)
	Decide(ctx context.Context, in deployment.DecideInput) (deployment.DecideResult, error)
}

const (
	consoleCookie = "keep_console"
	consolePath   = "/console"
	// consoleCSP forbids every script, inline or not, every foreign origin and
	// every embedding. Styles come from one same-origin file.
	consoleCSP = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	// networkWarning is shown verbatim whenever a request carries network destinations.
	networkWarning = "Pinning restricts where the value can go, not what is done with it. If the token can write to an approved API (a gist, an issue), that is a channel too."
)

// consoleRoutes is the minimal approval console: HTML for humans, no script,
// no value anywhere by construction (its view types hold names and ids only).
type consoleRoutes struct {
	ir     *identity.Repo
	svc    ApprovalService
	secure bool
}

func registerConsole(mux *http.ServeMux, logger *slog.Logger, ir *identity.Repo, svc ApprovalService, publicURL string) {
	c := &consoleRoutes{ir: ir, svc: svc, secure: strings.HasPrefix(publicURL, "https://")}
	for _, e := range []struct {
		method, pattern string
		h               http.HandlerFunc
	}{
		{"GET", "/console", c.root},
		{"GET", "/console/login", c.loginPage},
		{"POST", "/console/login", c.login},
		{"POST", "/console/logout", c.logout},
		{"GET", "/console/approvals", c.list},
		{"GET", "/console/approvals/{id}", c.card},
		{"POST", "/console/approvals/{id}/decision", c.decide},
		{"GET", "/console/console.css", c.css},
	} {
		mux.Handle(e.method+" "+e.pattern, logged(e.pattern, logger, e.h))
	}
}

func consoleHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", consoleCSP)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}

// sameOrigin is the first CSRF barrier: a state-changing request must come
// from this very origin. With neither header present the client is unknown
// and is refused. The pages send Referrer-Policy: no-referrer, under which a
// browser writes "Origin: null" even on a same-origin form post; that one
// spelling is accepted only when Sec-Fetch-Site vouches for it.
func sameOrigin(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	if site != "" && site != "same-origin" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return site == "same-origin"
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host != "" && u.Host == r.Host
}

func (c *consoleRoutes) session(r *http.Request) (identity.Session, bool, error) {
	ck, err := r.Cookie(consoleCookie)
	if err != nil || ck.Value == "" {
		return identity.Session{}, false, nil
	}
	s, err := c.ir.LookupSession(r.Context(), ck.Value)
	if err != nil {
		if errors.Is(err, identity.ErrUnauthenticated) {
			return identity.Session{}, false, nil
		}
		return identity.Session{}, false, err
	}
	return s, true, nil
}

// authed resolves the session or answers the request itself (redirect to the
// login page, or 503 when the backend is down) and reports false.
func (c *consoleRoutes) authed(w http.ResponseWriter, r *http.Request) (identity.Session, bool) {
	consoleHeaders(w)
	s, ok, err := c.session(r)
	if err != nil {
		c.fail(w, r, http.StatusServiceUnavailable, "Service temporarily unavailable.")
		return identity.Session{}, false
	}
	if !ok {
		http.Redirect(w, r, "/console/login", http.StatusSeeOther)
		return identity.Session{}, false
	}
	return s, true
}

func (c *consoleRoutes) canApprove(ctx context.Context, p identity.Principal, scope tenancy.Scope) (bool, error) {
	if p.Kind != identity.KindUser {
		return false, nil
	}
	// A token narrower than the secret's scope does not reach it.
	if p.Scope != "" && p.Scope != scope.String() && p.Scope != tenancy.Org(p.OrgID).String() {
		return false, nil
	}
	perms, err := catalog.PermissionsAt(ctx, c.ir, tenancy.Context{Org: p.OrgID, Principal: principalToTenancy(p)}, scope)
	if err != nil {
		return false, err
	}
	return perms[identity.PermApprove], nil
}

func isRequester(a deployment.Approval, p identity.Principal) bool {
	return a.Requester.Type == "user" && a.Requester.ID == p.ID.String()
}

// --- views: the only data the templates see; names, ids and closed enums.

type targetRow struct{ Name, Value string }

type cardView struct {
	CSRF         string
	ID           string
	Status       string
	StatusText   string
	Requested    string
	Expires      string
	Decided      string
	Reason       string
	Hash         string
	Requester    string
	Sponsor      string
	RequestID    string
	Secret       string
	Class        string
	Scope        string
	Runner       string
	Target       []targetRow
	NetAllowlist []string
	NetWarning   string
	CanDecide    bool
	Note         string
}

type listRow struct {
	ID, Secret, Class, Target, Requester, Status, StatusText, Expires string
}

var statusText = map[string]string{"requested": "awaiting decision", "approved": "approved", "rejected": "rejected", "expired": "expired"}

func when(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}

func rows(t runnerproto.Target) []targetRow {
	out := []targetRow{{"Type", string(t.Kind)}, {"Path", t.Path}}
	add := func(name, v string) {
		if v != "" {
			out = append(out, targetRow{name, v})
		}
	}
	add("Field", t.Field)
	add("Unit", t.Unit)
	add("Consumer", t.Consumer)
	return append(out, targetRow{"Mode", fmt.Sprintf("%04o", t.Mode)}, targetRow{"uid / gid", fmt.Sprintf("%d / %d", t.UID, t.GID)})
}

func toCard(a deployment.Approval, csrf string) cardView {
	v := cardView{CSRF: csrf, ID: a.ID.String(), Status: a.Status, StatusText: statusText[a.Status], Requested: when(a.RequestedAt), Expires: when(a.ExpiresAt),
		Decided: when(a.DecidedAt), Reason: a.Reason, Hash: a.BindingHash, Requester: string(a.Requester.Type) + " " + a.Requester.ID, Sponsor: a.Requester.SponsorID,
		RequestID: a.RequestID, Secret: a.SecretName, Class: a.SecretClass, Scope: a.Scope.String(), Runner: a.RunnerID.String(), NetAllowlist: a.NetAllowlist}
	v.Target = rows(a.Target)
	if e := a.Exec; e != nil {
		d := e.Digest
		if len(d) > 16 {
			d = d[:16]
		}
		v.Target = []targetRow{{"Type", "exec"}, {"Template", e.TemplateID}, {"Template digest", d}, {"Network", e.Mode}, {"Parameters", strings.Join(e.ParamNames, ", ")}}
	}
	if len(a.NetAllowlist) > 0 {
		v.NetWarning = networkWarning
	}
	if a.Rotate {
		v.Runner = "every registered carrier of the secret"
		v.Target = []targetRow{{"Action", "rotate"}, {"Plan", "new version on every carrier, old version revoked only after all confirm it"}}
	}
	return v
}

// --- handlers

func (c *consoleRoutes) root(w http.ResponseWriter, r *http.Request) {
	consoleHeaders(w)
	http.Redirect(w, r, "/console/approvals", http.StatusSeeOther)
}

func (c *consoleRoutes) css(w http.ResponseWriter, _ *http.Request) {
	consoleHeaders(w)
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write([]byte(consoleStyle))
}

func (c *consoleRoutes) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = consoleTemplates.ExecuteTemplate(w, name, data)
}

func (c *consoleRoutes) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	consoleHeaders(w)
	c.render(w, status, "error", map[string]any{"Message": msg, "RequestID": reqid.FromContext(r.Context())})
}

func (c *consoleRoutes) loginPage(w http.ResponseWriter, _ *http.Request) {
	consoleHeaders(w)
	c.render(w, http.StatusOK, "login", map[string]any{})
}

func (c *consoleRoutes) login(w http.ResponseWriter, r *http.Request) {
	consoleHeaders(w)
	if !sameOrigin(r) {
		c.fail(w, r, http.StatusForbidden, "Request refused: foreign origin.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		c.fail(w, r, http.StatusBadRequest, "Malformed request.")
		return
	}
	handle, _, err := c.ir.OpenSession(r.Context(), identity.NewToken(strings.TrimSpace(r.PostForm.Get("token"))))
	switch {
	case errors.Is(err, identity.ErrUnauthenticated):
		c.render(w, http.StatusUnauthorized, "login", map[string]any{"Error": "Sign-in failed. Check the token."})
		return
	case err != nil:
		c.fail(w, r, http.StatusServiceUnavailable, "Service temporarily unavailable.")
		return
	}
	//nolint:gosec // G124: HttpOnly and SameSite=Strict are set; Secure follows the https public URL, which a plain-http dev server cannot have
	http.SetCookie(w, &http.Cookie{Name: consoleCookie, Value: handle, Path: consolePath, HttpOnly: true, Secure: c.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(identity.SessionTTL / time.Second)})
	http.Redirect(w, r, "/console/approvals", http.StatusSeeOther)
}

func (c *consoleRoutes) logout(w http.ResponseWriter, r *http.Request) {
	s, ok := c.authed(w, r)
	if !ok {
		return
	}
	if !sameOrigin(r) || !csrfOK(r, s) {
		c.fail(w, r, http.StatusForbidden, "Request refused.")
		return
	}
	if ck, err := r.Cookie(consoleCookie); err == nil {
		_ = c.ir.CloseSession(r.Context(), ck.Value)
	}
	//nolint:gosec // G124: expiring cookie; same attributes as the one it replaces
	http.SetCookie(w, &http.Cookie{Name: consoleCookie, Value: "", Path: consolePath, HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.Redirect(w, r, "/console/login", http.StatusSeeOther)
}

func csrfOK(r *http.Request, s identity.Session) bool {
	r.Body = http.MaxBytesReader(nil, r.Body, 16384)
	if r.ParseForm() != nil {
		return false
	}
	got := r.PostForm.Get("csrf")
	return got != "" && len(got) == len(s.CSRF) && subtle.ConstantTimeCompare([]byte(got), []byte(s.CSRF)) == 1
}

func (c *consoleRoutes) humanOnly(w http.ResponseWriter, r *http.Request, s identity.Session) bool {
	if s.Principal.Kind != identity.KindUser {
		c.fail(w, r, http.StatusForbidden, "Only a human approves. An agent never approves a request.")
		return false
	}
	return true
}

func (c *consoleRoutes) list(w http.ResponseWriter, r *http.Request) {
	s, ok := c.authed(w, r)
	if !ok || !c.humanOnly(w, r, s) {
		return
	}
	if c.svc == nil {
		c.fail(w, r, http.StatusServiceUnavailable, "Approval service unavailable.")
		return
	}
	all, err := c.svc.ListApprovals(r.Context(), s.Principal.OrgID, 100)
	if err != nil {
		c.fail(w, r, http.StatusServiceUnavailable, "Service temporarily unavailable.")
		return
	}
	var out []listRow
	allowed := map[string]bool{}
	for _, a := range all {
		key := a.Scope.String()
		yes, seen := allowed[key]
		if !seen {
			if yes, err = c.canApprove(r.Context(), s.Principal, a.Scope); err != nil {
				c.fail(w, r, http.StatusServiceUnavailable, "Service temporarily unavailable.")
				return
			}
			allowed[key] = yes
		}
		if yes {
			out = append(out, listRow{ID: a.ID.String(), Secret: a.SecretName, Class: a.SecretClass, Target: listTarget(a),
				Requester: string(a.Requester.Type), Status: a.Status, StatusText: statusText[a.Status], Expires: when(a.ExpiresAt)})
		}
	}
	c.render(w, http.StatusOK, "list", map[string]any{"Rows": out, "CSRF": s.CSRF})
}

// load fetches the card an approver may see; anything else is a plain 404, so
// the page is not an oracle for ids of other scopes or organizations.
func (c *consoleRoutes) load(w http.ResponseWriter, r *http.Request, s identity.Session) (deployment.Approval, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || c.svc == nil {
		c.fail(w, r, http.StatusNotFound, "Request not found.")
		return deployment.Approval{}, false
	}
	a, err := c.svc.GetApproval(r.Context(), s.Principal.OrgID, id)
	switch {
	case errors.Is(err, deployment.ErrNotFound):
		c.fail(w, r, http.StatusNotFound, "Request not found.")
		return deployment.Approval{}, false
	case err != nil:
		c.fail(w, r, http.StatusServiceUnavailable, "Service temporarily unavailable.")
		return deployment.Approval{}, false
	}
	yes, err := c.canApprove(r.Context(), s.Principal, a.Scope)
	if err != nil {
		c.fail(w, r, http.StatusServiceUnavailable, "Service temporarily unavailable.")
		return deployment.Approval{}, false
	}
	if !yes {
		c.fail(w, r, http.StatusNotFound, "Request not found.")
		return deployment.Approval{}, false
	}
	return a, true
}

func (c *consoleRoutes) card(w http.ResponseWriter, r *http.Request) {
	s, ok := c.authed(w, r)
	if !ok || !c.humanOnly(w, r, s) {
		return
	}
	a, ok := c.load(w, r, s)
	if !ok {
		return
	}
	v := toCard(a, s.CSRF)
	switch {
	case isRequester(a, s.Principal):
		v.Note = "This is your own request: another person must decide it."
	case a.Status == "requested":
		v.CanDecide = true
	}
	c.render(w, http.StatusOK, "card", v)
}

func (c *consoleRoutes) decide(w http.ResponseWriter, r *http.Request) {
	s, ok := c.authed(w, r)
	if !ok || !c.humanOnly(w, r, s) {
		return
	}
	if !sameOrigin(r) || !csrfOK(r, s) {
		c.fail(w, r, http.StatusForbidden, "Request refused: invalid form token. Reopen the card.")
		return
	}
	a, ok := c.load(w, r, s)
	if !ok {
		return
	}
	if isRequester(a, s.Principal) {
		c.fail(w, r, http.StatusForbidden, "You cannot approve your own request.")
		return
	}
	decision := r.PostForm.Get("decision")
	reason := strings.TrimSpace(r.PostForm.Get("reason"))
	if (decision != "approve" && decision != "reject") || utf8.RuneCountInString(reason) > 200 || (decision == "reject" && reason == "") || !utf8.ValidString(reason) {
		c.fail(w, r, http.StatusBadRequest, "Choose a decision and a reason (a reason is required to reject, up to 200 characters).")
		return
	}
	_, err := c.svc.Decide(r.Context(), deployment.DecideInput{OrgID: s.Principal.OrgID, ApprovalID: a.ID, ApproverID: s.Principal.ID, ApproverIsUser: true,
		Approve: decision == "approve", Reason: reason, BindingHash: r.PostForm.Get("binding")})
	status, msg := http.StatusSeeOther, ""
	switch {
	case err == nil:
	case errors.Is(err, deployment.ErrExpired):
		status, msg = http.StatusConflict, "The request has expired and can no longer be approved."
	case errors.Is(err, deployment.ErrAlreadyDecided):
		status, msg = http.StatusConflict, "This request has already been decided."
	case errors.Is(err, deployment.ErrBindingMismatch):
		status, msg = http.StatusConflict, "The request content differs from what was shown. Reopen the card."
	case errors.Is(err, deployment.ErrSelfApproval), errors.Is(err, deployment.ErrNotHuman):
		status, msg = http.StatusForbidden, "You may not make this decision."
	case errors.Is(err, deployment.ErrRefused):
		status, msg = http.StatusConflict, "The request can no longer be executed (policy, host, provider or limit). Nothing was created."
	case errors.Is(err, deployment.ErrNotFound):
		status, msg = http.StatusNotFound, "Request not found."
	default:
		status, msg = http.StatusServiceUnavailable, "Service temporarily unavailable."
	}
	if status != http.StatusSeeOther {
		c.fail(w, r, status, msg)
		return
	}
	http.Redirect(w, r, "/console/approvals/"+a.ID.String(), http.StatusSeeOther)
}

func listTarget(a deployment.Approval) string {
	if a.Rotate {
		return "rotate"
	}
	return string(a.Target.Kind) + " " + a.Target.Path
}
