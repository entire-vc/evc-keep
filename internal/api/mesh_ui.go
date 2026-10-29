package api

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// The Keep screen inside Mesh's iframe. Mesh opens /mesh/ui/secrets?token=<JWT>
// (docs/extensions/ui-iframe.md on the Mesh side); the token is exchanged for
// a session without a second login. Pages carry only the closed field lists of
// the threat model §4.3: names, versions, fingerprints, lengths, key level.

const (
	meshUICookie = "keep_mesh_ui"
	meshUIPath   = "/mesh/ui"
	// meshUIListLimit bounds one page of the secrets table.
	meshUIListLimit = 200
)

// Key level names, as the sealer spells them. The set is closed.
var keyLevelNames = []string{"user", "project", "workspace", "organization"}

// ErrKeyLevelWeakening is returned by a KeyLevelChanger that refused a change
// to a coarser level the caller did not confirm.
var ErrKeyLevelWeakening = errors.New("api: key level weakening not confirmed")

// ErrKeyLevelInvalid is returned for a level name outside the closed set.
var ErrKeyLevelInvalid = errors.New("api: invalid key level")

// KeyLevelState is the threat model's §4.3 key-level object, read side.
type KeyLevelState struct {
	Level     string
	ChangedAt time.Time // zero: never changed, the default is in force
	ChangedBy string    // the actor that made the last change, empty when never changed
}

// KeyLevelChange is the §4.3 outcome of a change: counts only.
type KeyLevelChange struct {
	Level                         string
	Rewrapped, Unchanged, Retired int
}

// KeyLevelService reads an organization's key level.
type KeyLevelService interface {
	Get(ctx context.Context, org uuid.UUID) (KeyLevelState, error)
}

// KeyLevelChanger is the optional write side. A KeyLevelService that does not
// implement it makes the settings page read-only.
type KeyLevelChanger interface {
	Change(ctx context.Context, org, actor uuid.UUID, to string, confirmWeakening bool) (KeyLevelChange, error)
}

type meshUI struct {
	m      *meshRoutes
	logger *slog.Logger
	cat    *catalog.Catalog
}

func registerMeshUI(mux *http.ServeMux, logger *slog.Logger, m *meshRoutes, cat *catalog.Catalog) {
	u := &meshUI{m: m, logger: logger, cat: cat}
	for _, e := range []struct {
		method, pattern string
		h               http.HandlerFunc
	}{
		{"GET", "/mesh/ui/secrets", u.secrets},
		{"GET", "/mesh/ui/settings", u.settings},
		{"POST", "/mesh/ui/settings/key-level", u.changeKeyLevel},
		{"POST", "/mesh/ui/session", u.session},
		{"GET", "/mesh/ui/app.js", u.script},
		{"GET", "/mesh/ui/app.css", u.style},
	} {
		mux.Handle(e.method+" "+e.pattern, logged(e.pattern, logger, requireTLS(e.h).ServeHTTP))
	}
}

// frameOrigin reduces an install-record address to the origin a CSP source
// list takes. It refuses anything that could carry a second directive.
func frameOrigin(meshURL string) (string, bool) {
	u, err := url.Parse(meshURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", false
	}
	o := u.Scheme + "://" + u.Host
	if strings.ContainsAny(o, " ;,'\"\r\n\t*") {
		return "", false
	}
	return o, true
}

// frameOrigins lists the origins of meshURLs; none valid means none allowed.
func frameOrigins(meshURLs []string) []string {
	var out []string
	for _, s := range meshURLs {
		if o, ok := frameOrigin(s); ok {
			dup := false
			for _, e := range out {
				dup = dup || e == o
			}
			if !dup {
				out = append(out, o)
			}
		}
	}
	return out
}

// meshUICSP is the policy of every screen: one same-origin script and style
// file, no inline code, no foreign origin, and embedding only by the Mesh
// instances recorded at install.
func meshUICSP(origins []string) string {
	anc := "'none'"
	if len(origins) > 0 {
		anc = strings.Join(origins, " ")
	}
	return "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors " + anc
}

func meshUIHeaders(w http.ResponseWriter, origins []string) {
	h := w.Header()
	h.Set("Content-Security-Policy", meshUICSP(origins))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	// No X-Frame-Options: it cannot name an origin, and frame-ancestors above
	// supersedes it in every browser that can run this screen.
}

type uiBase struct {
	Origins   []string // allowed Mesh origins, for the script's origin check
	NeedLogin bool     // the page has no session; the script exchanges mesh.context
	Toast     string
	ToastLvl  string
	Active    string
	CSRF      string
}

func (b uiBase) OriginList() string { return strings.Join(b.Origins, " ") }

func (u *meshUI) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = meshUITemplates.ExecuteTemplate(w, name, data)
}

// sessionOf resolves the cookie to a user session and the origins allowed to
// frame the page. ok false means the request has no session.
func (u *meshUI) sessionOf(r *http.Request) (s identity.Session, origins []string, ok bool, err error) {
	ck, cerr := r.Cookie(meshUICookie)
	if cerr != nil || ck.Value == "" {
		return identity.Session{}, nil, false, nil
	}
	s, err = u.m.ir.LookupSession(r.Context(), ck.Value)
	if err != nil {
		if errors.Is(err, identity.ErrUnauthenticated) || errors.Is(err, identity.ErrNoSession) {
			return identity.Session{}, nil, false, nil
		}
		return identity.Session{}, nil, false, err
	}
	urls, err := u.m.deps.Repo.MeshURLs(r.Context(), s.Principal.OrgID)
	if err != nil {
		return identity.Session{}, nil, false, err
	}
	return s, frameOrigins(urls), true, nil
}

// signedOut answers a request without a valid session. The page can still be
// framed by the Mesh that issued token, so that its script can ask Mesh for a
// fresh context; without a token nothing may frame it.
func (u *meshUI) signedOut(w http.ResponseWriter, r *http.Request, tok string) {
	var origins []string
	if tok != "" {
		if ws, ok := meshext.PeekWorkspace(meshext.NewContextToken(tok)); ok {
			if _, meshURL, found, err := u.m.deps.Repo.Installation(r.Context(), ws); err == nil && found {
				origins = frameOrigins([]string{meshURL})
			}
		}
	}
	meshUIHeaders(w, origins)
	u.render(w, http.StatusUnauthorized, "signedout", uiBase{Origins: origins, NeedLogin: len(origins) > 0})
}

func (u *meshUI) setCookie(w http.ResponseWriter, handle string) {
	// SameSite=None and Partitioned: the screen runs in a cross-site iframe,
	// where Lax and Strict cookies are not sent. TLS only (requireTLS).
	//nolint:gosec // G124: HttpOnly and Secure are set; None is required for the Mesh iframe
	http.SetCookie(w, &http.Cookie{Name: meshUICookie, Value: handle, Path: meshUIPath, HttpOnly: true, Secure: true,
		SameSite: http.SameSiteNoneMode, Partitioned: true, MaxAge: int(identity.SessionTTL / time.Second)})
}

func (u *meshUI) secrets(w http.ResponseWriter, r *http.Request) {
	if tok := r.URL.Query().Get("token"); tok != "" {
		// Exchange the one-minute token for a session and drop it from the URL.
		handle, _, err := u.m.deps.Federation.SignIn(r.Context(), meshext.NewContextToken(tok))
		switch {
		case errors.Is(err, meshext.ErrInvalidContext):
			u.signedOut(w, r, tok)
			return
		case err != nil:
			meshUIHeaders(w, nil)
			u.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{})
			return
		}
		u.setCookie(w, handle)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/mesh/ui/secrets", http.StatusSeeOther)
		return
	}
	s, origins, ok, err := u.sessionOf(r)
	if err != nil {
		meshUIHeaders(w, nil)
		u.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{})
		return
	}
	if !ok {
		u.signedOut(w, r, "")
		return
	}
	meshUIHeaders(w, origins)
	rows, truncated, err := u.secretRows(r.Context(), s.Principal, r.URL.Query().Get("q"), r.URL.Query().Get("class"))
	if err != nil {
		u.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{Origins: origins})
		return
	}
	u.render(w, http.StatusOK, "secrets", secretsView{uiBase: uiBase{Origins: origins, Active: "secrets", CSRF: s.CSRF},
		Rows: rows, Truncated: truncated, Q: r.URL.Query().Get("q"), Class: r.URL.Query().Get("class")})
}

type secretsView struct {
	uiBase
	Rows      []secretRow
	Truncated bool
	Q, Class  string
}

// secretRow is the screen's whole view of a secret: the §4.3 fields only.
type secretRow struct {
	Name, Scope, Class, Version, Fingerprint, Status string
	Length                                           int
	HasVersion                                       bool
}

func (u *meshUI) secretRows(ctx context.Context, p identity.Principal, q, class string) ([]secretRow, bool, error) {
	q = strings.ToLower(strings.TrimSpace(q))
	scopes := []tenancy.Scope{tenancy.Org(p.OrgID), {Level: tenancy.LevelUser, ID: p.ID}}
	var out []secretRow
	truncated := false
	for _, sc := range scopes {
		perms, err := catalog.PermissionsAt(ctx, u.m.ir, tenancy.Context{Org: p.OrgID, Principal: principalToTenancy(p)}, sc)
		if err != nil {
			return nil, false, err
		}
		if !perms[identity.PermReadMetadata] {
			continue
		}
		refs, err := u.cat.List(ctx, p.OrgID, sc)
		if err != nil {
			return nil, false, err
		}
		for _, ref := range refs {
			if (q != "" && !strings.Contains(strings.ToLower(ref.Name), q)) || (class != "" && ref.Class != class) {
				continue
			}
			if len(out) >= meshUIListLimit {
				truncated = true
				break
			}
			row := secretRow{Name: ref.Name, Scope: sc.String(), Class: ref.Class}
			vs, err := u.cat.ListVersions(ctx, p.OrgID, ref.ID)
			if err != nil {
				return nil, false, err
			}
			if cur := newSecretVersions(vs); len(cur) > 0 {
				row.HasVersion, row.Version, row.Fingerprint, row.Length, row.Status = true, cur[0].Version, cur[0].Fingerprint, cur[0].Length, cur[0].Status
			}
			out = append(out, row)
		}
	}
	return out, truncated, nil
}

// session serves POST /mesh/ui/session: the script posts the context token
// Mesh sent it and gets the screen's session cookie.
func (u *meshUI) session(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	if !sameOrigin(r) || !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeError(w, http.StatusForbidden, apperr.ClassPermissionDenied, "request refused", requestID)
		return
	}
	tok, ok := readContextBody(w, r)
	if !ok {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid request body", requestID)
		return
	}
	handle, _, err := u.m.deps.Federation.SignIn(r.Context(), meshext.NewContextToken(tok))
	switch {
	case errors.Is(err, meshext.ErrInvalidContext):
		writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication failed", requestID)
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "service temporarily unavailable", requestID)
		return
	}
	u.setCookie(w, handle)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, MeshSessionResult{OK: true, RequestID: requestID})
}

// isOrgAdmin: manage_runners is held by the admin role alone.
func (u *meshUI) isOrgAdmin(ctx context.Context, p identity.Principal) (bool, error) {
	perms, err := catalog.PermissionsAt(ctx, u.m.ir, tenancy.Context{Org: p.OrgID, Principal: principalToTenancy(p)}, tenancy.Org(p.OrgID))
	if err != nil {
		return false, err
	}
	return perms[identity.PermManageRunners], nil
}

type settingsView struct {
	uiBase
	Level     string
	ChangedAt string
	ChangedBy string
	Levels    []string
	CanChange bool
	IsAdmin   bool
	Available bool
	Result    *KeyLevelChange
	Error     string
}

func (u *meshUI) settingsView(w http.ResponseWriter, r *http.Request, s identity.Session, origins []string) (settingsView, bool) {
	v := settingsView{uiBase: uiBase{Origins: origins, Active: "settings", CSRF: s.CSRF}, Levels: keyLevelNames}
	admin, err := u.isOrgAdmin(r.Context(), s.Principal)
	if err != nil {
		u.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{Origins: origins})
		return v, false
	}
	v.IsAdmin = admin
	if kl := u.m.deps.KeyLevels; kl != nil {
		v.Available = true
		st, err := kl.Get(r.Context(), s.Principal.OrgID)
		if err != nil {
			u.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{Origins: origins})
			return v, false
		}
		v.Level = st.Level
		if !st.ChangedAt.IsZero() {
			v.ChangedAt, v.ChangedBy = when(st.ChangedAt), st.ChangedBy
		}
		_, can := kl.(KeyLevelChanger)
		v.CanChange = can && admin
	}
	return v, true
}

func (u *meshUI) settings(w http.ResponseWriter, r *http.Request) {
	s, origins, ok, err := u.sessionOf(r)
	if err != nil {
		meshUIHeaders(w, nil)
		u.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{})
		return
	}
	if !ok {
		u.signedOut(w, r, "")
		return
	}
	meshUIHeaders(w, origins)
	v, ok := u.settingsView(w, r, s, origins)
	if !ok {
		return
	}
	if r.URL.Query().Get("changed") == "1" {
		v.Toast, v.ToastLvl = "Key level changed", "success"
	}
	u.render(w, http.StatusOK, "settings", v)
}

func (u *meshUI) changeKeyLevel(w http.ResponseWriter, r *http.Request) {
	s, origins, ok, err := u.sessionOf(r)
	if err != nil {
		meshUIHeaders(w, nil)
		u.render(w, http.StatusServiceUnavailable, "unavailable", uiBase{})
		return
	}
	if !ok {
		u.signedOut(w, r, "")
		return
	}
	meshUIHeaders(w, origins)
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !sameOrigin(r) || r.ParseForm() != nil || !csrfValue(r.PostForm.Get("csrf"), s) {
		u.render(w, http.StatusForbidden, "unavailable", uiBase{Origins: origins})
		return
	}
	v, ok := u.settingsView(w, r, s, origins)
	if !ok {
		return
	}
	if !v.IsAdmin {
		v.Error, v.Toast, v.ToastLvl = "Only an organization admin can change the key level.", "Not allowed", "error"
		u.render(w, http.StatusForbidden, "settings", v)
		return
	}
	ch, can := u.m.deps.KeyLevels.(KeyLevelChanger)
	if !can {
		v.Error = "Changing the key level is not available on this server."
		u.render(w, http.StatusNotImplemented, "settings", v)
		return
	}
	res, err := ch.Change(r.Context(), s.Principal.OrgID, s.Principal.ID, r.PostForm.Get("level"), r.PostForm.Get("confirm_weakening") == "yes")
	switch {
	case errors.Is(err, ErrKeyLevelWeakening):
		v.Error, v.Toast, v.ToastLvl = "A coarser level lets more stores share a key. Tick the confirmation to proceed.", "Confirmation needed", "warning"
		u.render(w, http.StatusConflict, "settings", v)
		return
	case errors.Is(err, ErrKeyLevelInvalid):
		v.Error = "Unknown key level."
		u.render(w, http.StatusBadRequest, "settings", v)
		return
	case err != nil:
		v.Error, v.Toast, v.ToastLvl = "The key level could not be changed. Nothing was lost; run the change again.", "Change failed", "error"
		u.render(w, http.StatusServiceUnavailable, "settings", v)
		return
	}
	v.Level, v.Result, v.Toast, v.ToastLvl = res.Level, &res, "Key level changed to "+res.Level, "success"
	// The view was read before the change: refresh who changed it and when,
	// or show neither rather than the previous change.
	v.ChangedAt, v.ChangedBy = "", ""
	if st, err := u.m.deps.KeyLevels.Get(r.Context(), s.Principal.OrgID); err == nil && !st.ChangedAt.IsZero() {
		v.ChangedAt, v.ChangedBy = when(st.ChangedAt), st.ChangedBy
	}
	u.render(w, http.StatusOK, "settings", v)
}

func (u *meshUI) script(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(meshUIScript))
}

func (u *meshUI) style(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(meshUIStyle))
}

var meshUITemplates = template.Must(template.New("meshui").Parse(meshUIHTML))

// readContextBody reads {"token": "..."}: unknown fields and oversize bodies refused.
func readContextBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Token == "" {
		return "", false
	}
	return req.Token, true
}
