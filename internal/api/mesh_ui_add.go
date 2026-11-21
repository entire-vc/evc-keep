package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/metatext"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/google/uuid"
)

// "Add secret" of the Secrets screen: a person names a secret, Keep creates
// its record and a one-time input link, the same link `keep input-link NAME`
// issues. The value never passes through this screen: the form has no field
// for it, and the link opens Keep's own input page.
//
// The link is a capability. It is drawn only in the body of the POST answer
// (no-store, no redirect): never in a URL, a header, a log line or a message
// to Mesh.

// meshUIAddInput is the closed field list of the Add secret form.
type meshUIAddInput struct {
	Scope       tenancy.Scope
	Name, Class string
}

// meshUIIssued is a link for a record that has no value yet.
type meshUIIssued struct {
	SecretID uuid.UUID
	Name     string
	Scope    tenancy.Level
	Link     intake.Issued
}

// meshUIAdder is the record and link side of Add secret (catalogAdder on the
// server). A scope or a secret outside the session's rights is
// errMeshUINotFound, the same answer as a missing one.
type meshUIAdder interface {
	// Targets lists the scopes (p's own, then the organization's) where p
	// holds create_ref and rotate and the store is the active built-in one.
	// Empty: reason says why, in a sentence for the person.
	Targets(ctx context.Context, p identity.Principal) ([]tenancy.Scope, string, error)
	// Add creates the record in.Name at in.Scope and issues its link; a
	// record of that name without a value gets a new link instead.
	Add(ctx context.Context, p identity.Principal, in meshUIAddInput) (meshUIIssued, error)
	// Link issues a link for the existing secret id, which has no value yet.
	Link(ctx context.Context, p identity.Principal, id uuid.UUID) (meshUIIssued, error)
}

var (
	errMeshUINotBuiltin = errors.New("api: input links need the built-in store")
	errMeshUIInputOff   = errors.New("api: input links are not set up")
	errMeshUILocked     = errors.New("api: a policy refuses this name or class here")
)

// errMeshUIExists: the name is taken in the scope by a secret with a value (or
// one that is not active); a new value is a rotation, not a new record.
type errMeshUIExists struct{ ID uuid.UUID }

func (e *errMeshUIExists) Error() string { return "api: secret exists" }

const (
	meshUIDefaultClass = "dev"
	meshUIAddFormLimit = 4096
	reasonInputOff     = "Input links are not set up on this server."
	reasonNoRights     = "Your role cannot add secrets here. Ask an organization admin."
	reasonNotBuiltin   = "Input links work only with the built-in store, and no active built-in store is bound here."
)

// shellSafe are the bytes a POSIX shell takes literally in a word.
var shellSafe = regexp.MustCompile(`^[A-Za-z0-9._/@:+=,-]+$`)

// shellQuote makes name one shell word: as it is when every byte is literal,
// else in single quotes.
func shellQuote(name string) string {
	if shellSafe.MatchString(name) {
		return name
	}
	return "'" + strings.ReplaceAll(name, "'", `'\''`) + "'"
}

// inputCommand is the terminal alternative of a link for name.
func inputCommand(name string) string { return "keep input-link " + shellQuote(name) }

// addControl is the Add secret button or form of a page: the scopes to offer,
// or the reason the button is disabled.
type addControl struct {
	Scopes []uiOption
	Reason string
	Name   string
	Class  string
	Error  string
}

func (a addControl) Enabled() bool { return len(a.Scopes) > 0 }

func scopeOption(level tenancy.Level) string {
	if level == tenancy.LevelUser {
		return "Only me"
	}
	return "Organization"
}

// addControlFor reads the scopes the session may add into. An error of the
// adder disables the button rather than the page.
func (u *meshUI) addControlFor(ctx context.Context, p identity.Principal) addControl {
	c := addControl{Class: meshUIDefaultClass}
	if u.add == nil {
		c.Reason = reasonInputOff
		return c
	}
	scopes, reason, err := u.add.Targets(ctx, p)
	if err != nil {
		c.Reason = "Adding a secret is unavailable right now. Reload the page to try again."
		return c
	}
	for i, sc := range scopes {
		c.Scopes = append(c.Scopes, uiOption{Value: string(sc.Level), Label: scopeOption(sc.Level), Selected: i == 0})
	}
	if len(c.Scopes) == 0 {
		c.Reason = reason
		if c.Reason == "" {
			c.Reason = reasonNoRights
		}
	}
	return c
}

type addView struct {
	uiBase
	Add addControl
	// Exists links the secret that already holds the name.
	Exists string
}

type issuedView struct {
	uiBase
	Heading               wrapText
	Name, Scope           string
	SecretHref            string
	URL, Command          string
	Expires, ExpiresIn    string
	NewRecord             bool
	LinkCopy, CommandCopy copyField
}

// copyField is a read-only field with a Copy button (template "copy-row").
// Kind names what is copied for the fixed feedback text; the copied text
// itself never leaves the page.
type copyField struct {
	ID, Value, Label, Button, Kind string
}

func commandCopy(id, name string) copyField {
	return copyField{ID: id, Value: inputCommand(name), Label: "Command for a terminal", Button: "Copy", Kind: "command"}
}

// addPage serves GET /mesh/ui/secrets/new.
func (u *meshUI) addPage(w http.ResponseWriter, r *http.Request) {
	s, origins, ok := u.uiSession(w, r)
	if !ok {
		return
	}
	v := addView{uiBase: uiBase{Origins: origins, Active: "secrets", CSRF: s.CSRF}, Add: u.addControlFor(r.Context(), s.Principal)}
	u.render(w, http.StatusOK, "secret-new", v)
}

// uiSession resolves the session of a screen request and sets the headers of
// the screen; false: the answer is already written.
func (u *meshUI) uiSession(w http.ResponseWriter, r *http.Request) (identity.Session, []string, bool) {
	s, origins, ok, err := u.sessions(r)
	if err != nil {
		meshUIHeaders(w, nil)
		u.unavailable(w, http.StatusServiceUnavailable, nil)
		return s, nil, false
	}
	if !ok {
		u.signedOut(w, r, "")
		return s, nil, false
	}
	meshUIHeaders(w, origins)
	return s, origins, true
}

// postForm checks a screen POST: same origin, a small url-encoded body, the
// session's CSRF token and no field outside allowed. false: refused, written.
func (u *meshUI) postForm(w http.ResponseWriter, r *http.Request, s identity.Session, origins []string, allowed ...string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, meshUIAddFormLimit)
	if !sameOrigin(r) || r.ParseForm() != nil || !csrfValue(r.PostForm.Get("csrf"), s) {
		u.unavailable(w, http.StatusForbidden, origins)
		return false
	}
	for k, vs := range r.PostForm {
		known := k == "csrf"
		for _, a := range allowed {
			known = known || k == a
		}
		if !known || len(vs) != 1 {
			u.unavailable(w, http.StatusBadRequest, origins)
			return false
		}
	}
	return true
}

// addSecret serves POST /mesh/ui/secrets/new.
func (u *meshUI) addSecret(w http.ResponseWriter, r *http.Request) {
	s, origins, ok := u.uiSession(w, r)
	if !ok || !u.postForm(w, r, s, origins, "name", "scope", "class") {
		return
	}
	ctx := r.Context()
	base := uiBase{Origins: origins, Active: "secrets", CSRF: s.CSRF}
	v := addView{uiBase: base, Add: u.addControlFor(ctx, s.Principal)}
	name, class := r.PostForm.Get("name"), strings.TrimSpace(r.PostForm.Get("class"))
	if class == "" {
		class = meshUIDefaultClass
	}
	v.Add.Name, v.Add.Class = name, class
	var scope tenancy.Scope
	switch r.PostForm.Get("scope") {
	case "", string(tenancy.LevelUser):
		scope = tenancy.Scope{Level: tenancy.LevelUser, ID: s.Principal.ID}
	case string(tenancy.LevelOrg):
		scope = tenancy.Org(s.Principal.OrgID)
	default:
		u.secretMissing(w, base)
		return
	}
	for i := range v.Add.Scopes {
		v.Add.Scopes[i].Selected = v.Add.Scopes[i].Value == string(scope.Level)
	}
	if msg := checkAddName(name, class); msg != "" {
		v.Add.Error = msg
		u.render(w, http.StatusBadRequest, "secret-new", v)
		return
	}
	if u.add == nil {
		v.Add.Error = reasonInputOff
		u.render(w, http.StatusServiceUnavailable, "secret-new", v)
		return
	}
	res, err := u.add.Add(ctx, s.Principal, meshUIAddInput{Scope: scope, Name: name, Class: class})
	if err != nil {
		u.addRefused(w, base, v, err)
		return
	}
	u.issuedPage(w, base, res, true)
}

// secretInputLink serves POST /mesh/ui/secrets/{id}/input-link.
func (u *meshUI) secretInputLink(w http.ResponseWriter, r *http.Request) {
	s, origins, ok := u.uiSession(w, r)
	if !ok || !u.postForm(w, r, s, origins) {
		return
	}
	base := uiBase{Origins: origins, Active: "secrets", CSRF: s.CSRF}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || u.add == nil {
		u.secretMissing(w, base)
		return
	}
	res, err := u.add.Link(r.Context(), s.Principal, id)
	if err != nil {
		u.addRefused(w, base, addView{uiBase: base, Add: u.addControlFor(r.Context(), s.Principal)}, err)
		return
	}
	u.issuedPage(w, base, res, false)
}

// checkAddName applies Keep's metadata rules to the name and class, plus one
// of the form: a name does not start or end with a space.
func checkAddName(name, class string) string {
	switch {
	case strings.TrimSpace(name) == "":
		return "Enter a name."
	case strings.TrimSpace(name) != name:
		return "A name cannot start or end with a space."
	case metatext.Validate("name", name, metatext.NameLimit) != nil:
		return "A name has at most 128 characters and no tabs, line breaks or control characters."
	case metatext.Validate("class", class, metatext.LabelLimit) != nil:
		return "A class has at most 64 characters and no tabs, line breaks or control characters."
	}
	return ""
}

func (u *meshUI) addRefused(w http.ResponseWriter, base uiBase, v addView, err error) {
	var exists *errMeshUIExists
	switch {
	case errors.Is(err, errMeshUINotFound):
		u.secretMissing(w, base)
		return
	case errors.As(err, &exists):
		v.Add.Error, v.Exists = "A secret with this name already has a value here. Rotate it from its page.", "/mesh/ui/secrets/"+exists.ID.String()
		v.Toast, v.ToastLvl = "Secret already exists", "warning"
		u.render(w, http.StatusConflict, "secret-new", v)
	case errors.Is(err, errMeshUINotBuiltin):
		v.Add.Error = "Input links work only with the built-in store. Nothing was created."
		u.render(w, http.StatusConflict, "secret-new", v)
	case errors.Is(err, errMeshUILocked):
		v.Add.Error = "An organization policy does not allow this name or class here. Nothing was created."
		u.render(w, http.StatusConflict, "secret-new", v)
	case errors.Is(err, errMeshUIInputOff):
		v.Add.Error = reasonInputOff
		u.render(w, http.StatusServiceUnavailable, "secret-new", v)
	default:
		v.Add.Error = "The link could not be created. Nothing was stored; try again."
		v.Toast, v.ToastLvl = "Input link failed", "error"
		u.render(w, http.StatusServiceUnavailable, "secret-new", v)
	}
}

func (u *meshUI) issuedPage(w http.ResponseWriter, base uiBase, res meshUIIssued, fromForm bool) {
	base.Toast, base.ToastLvl = "Input link created", "success"
	v := issuedView{uiBase: base, Heading: wrapText(res.Name), Name: res.Name, Scope: scopeOption(res.Scope),
		SecretHref: "/mesh/ui/secrets/" + res.SecretID.String(), URL: res.Link.URL, Command: inputCommand(res.Name),
		NewRecord:   fromForm,
		LinkCopy:    copyField{ID: "input-link", Value: res.Link.URL, Label: "One-time input link", Button: "Copy link", Kind: "link"},
		CommandCopy: commandCopy("input-command", res.Name)}
	if !res.Link.ExpiresAt.IsZero() {
		v.Expires = res.Link.ExpiresAt.UTC().Format("15:04 UTC")
		v.ExpiresIn = expiresIn(time.Until(res.Link.ExpiresAt))
	}
	u.render(w, http.StatusOK, "secret-issued", v)
}

// expiresIn is a lifetime a person reads: "30 min", "2 h".
func expiresIn(d time.Duration) string {
	m := int(d.Round(time.Minute) / time.Minute)
	switch {
	case m < 1:
		return "less than a minute"
	case m < 120:
		return itoa(m) + " min"
	}
	return itoa(m/60) + " h"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// catalogAdder is the server's meshUIAdder: the catalog behind the rights of
// identity, and the input service the API issues links with.
type catalogAdder struct {
	ir    *identity.Repo
	cat   *catalog.Catalog
	input InputService
	aud   audit.Journaler
}

func (a catalogAdder) tc(p identity.Principal) tenancy.Context {
	return tenancy.Context{Org: p.OrgID, Principal: principalToTenancy(p)}
}

// may reports whether p holds every one of perms at scope.
func (a catalogAdder) may(ctx context.Context, p identity.Principal, scope tenancy.Scope, perms ...identity.Permission) (bool, error) {
	got, err := catalog.PermissionsAt(ctx, a.ir, a.tc(p), scope)
	if err != nil {
		return false, err
	}
	for _, pm := range perms {
		if !got[pm] {
			return false, nil
		}
	}
	return true, nil
}

// builtinStore resolves the store a new record at scope gets (its binding,
// walked upward) and requires it to be the active built-in store.
func (a catalogAdder) builtinStore(ctx context.Context, org uuid.UUID, scope tenancy.Scope) (catalog.Store, error) {
	chain, err := a.cat.AncestorChain(ctx, org, scope)
	if err != nil {
		return catalog.Store{}, err
	}
	id, err := a.cat.ResolveStore(ctx, org, chain)
	var ae *apperr.Error
	if errors.As(err, &ae) && ae.Class == apperr.ClassNoStoreBound {
		return catalog.Store{}, errMeshUINotBuiltin
	}
	if err != nil {
		return catalog.Store{}, err
	}
	st, err := a.cat.GetStore(ctx, org, id)
	if err != nil {
		return catalog.Store{}, err
	}
	if st.Provider != "builtin" || st.Status != "active" {
		return catalog.Store{}, errMeshUINotBuiltin
	}
	return st, nil
}

func (a catalogAdder) scopes(p identity.Principal) []tenancy.Scope {
	return []tenancy.Scope{{Level: tenancy.LevelUser, ID: p.ID}, tenancy.Org(p.OrgID)}
}

func (a catalogAdder) Targets(ctx context.Context, p identity.Principal) ([]tenancy.Scope, string, error) {
	if a.input == nil {
		return nil, reasonInputOff, nil
	}
	var out []tenancy.Scope
	reason := reasonNoRights
	for _, sc := range a.scopes(p) {
		ok, err := a.may(ctx, p, sc, identity.PermCreateRef, identity.PermRotate)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			continue
		}
		if _, err := a.builtinStore(ctx, p.OrgID, sc); errors.Is(err, errMeshUINotBuiltin) {
			reason = reasonNotBuiltin
			continue
		} else if err != nil {
			return nil, "", err
		}
		out = append(out, sc)
	}
	if len(out) > 0 {
		reason = ""
	}
	return out, reason, nil
}

func (a catalogAdder) actor(p identity.Principal) audit.Actor {
	return audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaMeshPlugin}
}

func (a catalogAdder) journal(ctx context.Context, p identity.Principal, ref audit.SecretRef, status audit.ResultStatus, class audit.ErrorClass) {
	if a.aud == nil {
		return
	}
	_, _ = a.aud.Append(ctx, audit.Record{RequestID: reqid.FromContext(ctx), OrgID: p.OrgID.String(), Scope: p.Scope, Actor: a.actor(p),
		Action: audit.ActionSecretCreateRef, Secret: ref, Result: audit.Result{Status: status, ErrorClass: class}})
}

func (a catalogAdder) Add(ctx context.Context, p identity.Principal, in meshUIAddInput) (meshUIIssued, error) {
	if a.input == nil {
		return meshUIIssued{}, errMeshUIInputOff
	}
	if (in.Scope != tenancy.Scope{Level: tenancy.LevelUser, ID: p.ID}) && in.Scope != tenancy.Org(p.OrgID) {
		return meshUIIssued{}, errMeshUINotFound
	}
	ok, err := a.may(ctx, p, in.Scope, identity.PermCreateRef, identity.PermRotate)
	if err != nil {
		return meshUIIssued{}, err
	}
	if !ok {
		a.journal(ctx, p, audit.SecretRef{Name: in.Name}, audit.StatusFailed, audit.ErrClassPermissionDenied)
		return meshUIIssued{}, errMeshUINotFound
	}
	// The store first: a scope whose store cannot take an input link gets no
	// record either.
	st, err := a.builtinStore(ctx, p.OrgID, in.Scope)
	if err != nil {
		return meshUIIssued{}, err
	}
	if ref, found, err := a.named(ctx, p.OrgID, in.Scope, in.Name); err != nil || found {
		if err != nil {
			return meshUIIssued{}, err
		}
		return a.reissue(ctx, p, ref)
	}
	// A random locator, never one made of the name: a name is guessable and
	// the same name in two scopes would address one value.
	loc, err := uuid.NewV7()
	if err != nil {
		return meshUIIssued{}, err
	}
	path := "builtin://" + st.Name + "/" + loc.String()
	if !provider.ValidRef(path) {
		return meshUIIssued{}, errMeshUINotBuiltin
	}
	created, err := a.cat.CreateRef(ctx, catalog.CreateRefInput{Org: p.OrgID, Scope: in.Scope, Name: in.Name, Class: in.Class, Type: "generic",
		ProviderRef: path, StoreID: st.ID})
	if err != nil {
		a.journal(ctx, p, audit.SecretRef{Name: in.Name}, audit.StatusFailed, classifyErr(err))
		var ae *apperr.Error
		if errors.As(err, &ae) {
			switch ae.Class {
			case apperr.ClassOverrideLocked:
				return meshUIIssued{}, errMeshUILocked
			case apperr.ClassInvalidArgument, apperr.ClassNoStoreBound:
				// The name and class were checked above: what is left is
				// the store, disabled or unbound since it was resolved.
				return meshUIIssued{}, errMeshUINotBuiltin
			}
		}
		// Created by a request that raced this one: answer as a retry would.
		if ref, found, lerr := a.named(ctx, p.OrgID, in.Scope, in.Name); lerr == nil && found {
			return a.reissue(ctx, p, ref)
		}
		return meshUIIssued{}, err
	}
	a.journal(ctx, p, audit.SecretRef{ID: created.ID.String(), Name: created.Name}, audit.StatusOK, audit.ErrClassNone)
	return a.issue(ctx, p, created, st)
}

// named finds the record name at scope.
func (a catalogAdder) named(ctx context.Context, org uuid.UUID, scope tenancy.Scope, name string) (tenancy.SecretRef, bool, error) {
	refs, err := a.cat.List(ctx, org, scope)
	if err != nil {
		return tenancy.SecretRef{}, false, err
	}
	for _, r := range refs {
		if r.Name == name {
			return r, true, nil
		}
	}
	return tenancy.SecretRef{}, false, nil
}

// reissue gives a record that has no value yet a new link (a retry after a
// failure); a record with a value, or not active, is errMeshUIExists.
func (a catalogAdder) reissue(ctx context.Context, p identity.Principal, ref tenancy.SecretRef) (meshUIIssued, error) {
	if ref.Status != "active" {
		return meshUIIssued{}, &errMeshUIExists{ID: ref.ID}
	}
	vs, err := a.cat.ListVersions(ctx, p.OrgID, ref.ID)
	if err != nil {
		return meshUIIssued{}, err
	}
	if len(vs) > 0 {
		return meshUIIssued{}, &errMeshUIExists{ID: ref.ID}
	}
	st, err := a.cat.GetStore(ctx, p.OrgID, ref.StoreID)
	if err != nil {
		return meshUIIssued{}, err
	}
	if st.Provider != "builtin" || st.Status != "active" || !strings.HasPrefix(ref.ProviderRef, "builtin://") {
		return meshUIIssued{}, errMeshUINotBuiltin
	}
	return a.issue(ctx, p, ref, st)
}

func (a catalogAdder) issue(ctx context.Context, p identity.Principal, ref tenancy.SecretRef, st catalog.Store) (meshUIIssued, error) {
	link, err := a.input.Issue(ctx, ref, st, a.actor(p), 0)
	switch {
	case errors.Is(err, intake.ErrInvalid):
		return meshUIIssued{}, errMeshUINotBuiltin
	case err != nil:
		return meshUIIssued{}, err
	}
	return meshUIIssued{SecretID: ref.ID, Name: ref.Name, Scope: ref.Scope.Level, Link: link}, nil
}

func (a catalogAdder) Link(ctx context.Context, p identity.Principal, id uuid.UUID) (meshUIIssued, error) {
	if a.input == nil {
		return meshUIIssued{}, errMeshUIInputOff
	}
	ref, err := a.cat.Meta(ctx, p.OrgID, id, a.scopes(p))
	var ae *apperr.Error
	if errors.As(err, &ae) && ae.Class == apperr.ClassSecretNotFound {
		return meshUIIssued{}, errMeshUINotFound
	}
	if err != nil {
		return meshUIIssued{}, err
	}
	ok, err := a.may(ctx, p, ref.Scope, identity.PermReadMetadata, identity.PermRotate)
	if err != nil {
		return meshUIIssued{}, err
	}
	if !ok {
		return meshUIIssued{}, errMeshUINotFound
	}
	return a.reissue(ctx, p, ref)
}
