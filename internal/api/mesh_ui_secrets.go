package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// The Secrets list and the page of one secret. Both carry only the closed
// field lists of the threat model §4.3 (Secret, Version, Carrier) and the
// RunSummary of mesh_ui_rotations.go; nothing on them derives from a value
// except the fingerprint and the length.

const (
	// meshUIPageSize is one page of the Secrets list.
	meshUIPageSize = 50
	// meshUIListLimit bounds the secrets one list request reads: states and
	// sorting need every row before a page is cut.
	meshUIListLimit = 1000
	// meshUIRecentRuns is how many runs the page of a secret lists.
	meshUIRecentRuns = 5
)

// errMeshUINotFound is the one answer for a secret the session may not read,
// whether it is missing, another organization's or out of the caller's rights.
var errMeshUINotFound = errors.New("api: secret not found")

// meshUISource is what the Secrets screens read from the catalog. The
// organization always comes from the session.
type meshUISource interface {
	// Visible lists the secrets p may read the metadata of: the organization
	// scope and p's own user scope, each only where p holds read_metadata.
	Visible(ctx context.Context, p identity.Principal) ([]tenancy.SecretRef, error)
	// Readable returns one of the secrets Visible would list; any other id
	// is errMeshUINotFound.
	Readable(ctx context.Context, p identity.Principal, id uuid.UUID) (tenancy.SecretRef, error)
	// Versions lists the versions of a secret, newest first.
	Versions(ctx context.Context, org, id uuid.UUID) ([]catalog.SecretVersion, error)
	Store(ctx context.Context, org, id uuid.UUID) (catalog.Store, error)
}

// meshUICarriers is the carrier side of the screens (*carriers.Service).
type meshUICarriers interface {
	List(ctx context.Context, org, secret uuid.UUID) ([]carriers.Carrier, error)
	Summary(ctx context.Context, org uuid.UUID) (map[uuid.UUID]carriers.Summary, error)
}

// meshUIDeps are the optional readers of the screens. A nil Carriers hides
// carrier counts and states; a nil Rotations hides every rotation block; a nil
// Input disables Add secret, with its reason on the page.
type meshUIDeps struct {
	Carriers  meshUICarriers
	Rotations MeshUIRotations
	Input     InputService
}

// meshUICarriersOf returns the carrier reader of the server's carrier
// service, or nil when it cannot summarize.
func meshUICarriersOf(svc CarrierService) meshUICarriers {
	c, _ := svc.(meshUICarriers)
	return c
}

// catalogSource is the server's meshUISource: the catalog behind the rights
// of identity.
type catalogSource struct {
	ir  *identity.Repo
	cat *catalog.Catalog
}

// scopes are the scopes of the screen p may read the metadata of.
func (s catalogSource) scopes(ctx context.Context, p identity.Principal) ([]tenancy.Scope, error) {
	var out []tenancy.Scope
	for _, sc := range []tenancy.Scope{tenancy.Org(p.OrgID), {Level: tenancy.LevelUser, ID: p.ID}} {
		perms, err := catalog.PermissionsAt(ctx, s.ir, tenancy.Context{Org: p.OrgID, Principal: principalToTenancy(p)}, sc)
		if err != nil {
			return nil, err
		}
		if perms[identity.PermReadMetadata] {
			out = append(out, sc)
		}
	}
	return out, nil
}

func (s catalogSource) Visible(ctx context.Context, p identity.Principal) ([]tenancy.SecretRef, error) {
	scopes, err := s.scopes(ctx, p)
	if err != nil {
		return nil, err
	}
	var out []tenancy.SecretRef
	for _, sc := range scopes {
		refs, err := s.cat.List(ctx, p.OrgID, sc)
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
	}
	return out, nil
}

func (s catalogSource) Readable(ctx context.Context, p identity.Principal, id uuid.UUID) (tenancy.SecretRef, error) {
	scopes, err := s.scopes(ctx, p)
	if err != nil {
		return tenancy.SecretRef{}, err
	}
	if len(scopes) == 0 {
		return tenancy.SecretRef{}, errMeshUINotFound
	}
	ref, err := s.cat.Meta(ctx, p.OrgID, id, scopes)
	var ae *apperr.Error
	if errors.As(err, &ae) && ae.Class == apperr.ClassSecretNotFound {
		return tenancy.SecretRef{}, errMeshUINotFound
	}
	return ref, err
}

func (s catalogSource) Versions(ctx context.Context, org, id uuid.UUID) ([]catalog.SecretVersion, error) {
	return s.cat.ListVersions(ctx, org, id)
}

func (s catalogSource) Store(ctx context.Context, org, id uuid.UUID) (catalog.Store, error) {
	return s.cat.GetStore(ctx, org, id)
}

// uiState is the one state a row, a carrier or a run shows, with its badge.
type uiState struct {
	Label, Badge string
	rank         int
	attention    bool
	rotating     bool
}

// The list states in the order the brief ranks them (§3.1).
func stateFailed() uiState {
	return uiState{Label: "Rotation failed", Badge: "danger", rank: 0, attention: true}
}
func stateRotating() uiState {
	return uiState{Label: "Rotating", Badge: "run", rank: 1, rotating: true}
}
func stateStale(n int) uiState {
	return uiState{Label: strconv.Itoa(n) + " stale", Badge: "warn", rank: 2, attention: true}
}
func stateUnverified(n int) uiState {
	return uiState{Label: strconv.Itoa(n) + " not verified", Badge: "outline", rank: 3, attention: true}
}
func stateNoCarriers() uiState { return uiState{Label: "No carriers", Badge: "muted", rank: 5} }
func stateNoValue() uiState    { return uiState{Label: "No value", Badge: "muted", rank: 4} }
func stateInSync() uiState     { return uiState{Label: "In sync", Badge: "ok", rank: 6} }
func stateStored() uiState     { return uiState{Label: "Stored", Badge: "ok", rank: 6} }

// runActive reports whether a run has not reached an end state.
func runActive(state string) bool { return state != "done" && state != "failed" }

// rowState picks the one state of a secret by the priority of §3.1.
func rowState(hasVersion bool, sum carriers.Summary, carriersKnown bool, run *RunSummary) uiState {
	switch {
	case run != nil && run.State == "failed":
		return stateFailed()
	case run != nil && runActive(run.State):
		return stateRotating()
	case carriersKnown && sum.Stale > 0:
		return stateStale(sum.Stale)
	case carriersKnown && sum.Unknown > 0:
		return stateUnverified(sum.Unknown)
	case !hasVersion:
		// Before "no carriers": nothing can be laid out without a value, so
		// the brief's order would never show this state.
		return stateNoValue()
	case carriersKnown && sum.Total == 0:
		return stateNoCarriers()
	case !carriersKnown:
		return stateStored()
	}
	return stateInSync()
}

type secretListRow struct {
	ID, Href, Name, Description, Class, Scope string
	HasVersion                                bool
	Version, Fingerprint, Rotated, Carriers   string
	State                                     uiState
	rotatedAt                                 time.Time
}

type uiOption struct {
	Value, Label string
	Selected     bool
}

type uiStateLink struct {
	Label, Href string
	Count       int
	Current     bool
}

type secretsView struct {
	uiBase
	Rows                       []secretListRow
	Total, Matched             int
	CarrierTotal, Attention    int
	Rotating                   int
	ShowRotating, ShowCarriers bool
	Truncated                  bool
	Q, Class, Scope, Sort      string
	StateQ                     string
	Classes, Scopes, Sorts     []uiOption
	States                     []uiStateLink
	AllHref, AttentionHref     string
	RotatingHref               string
	From, To                   int
	PrevHref, NextHref         string
	Add                        addControl
}

// listQuery is the list's query string, cleaned: unknown values fall back
// to the default, so a hand-edited URL cannot reach an odd state.
type listQuery struct {
	q, class, scope, state, sort string
	page                         int
}

func parseListQuery(v url.Values) listQuery {
	q := listQuery{q: strings.TrimSpace(v.Get("q")), class: v.Get("class"), scope: v.Get("scope"), state: v.Get("state"), sort: v.Get("sort")}
	if len(q.q) > 128 {
		q.q = q.q[:128]
	}
	if q.scope != string(tenancy.LevelOrg) && q.scope != string(tenancy.LevelUser) {
		q.scope = ""
	}
	if q.state != "attention" && q.state != "rotating" {
		q.state = ""
	}
	if q.sort != "rotated" && q.sort != "state" {
		q.sort = "name"
	}
	q.page, _ = strconv.Atoi(v.Get("page"))
	if q.page < 1 {
		q.page = 1
	}
	return q
}

// href is the list URL with q's filters, overridden by kv pairs; the page is
// dropped unless named.
func (q listQuery) href(kv ...string) string {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		} else {
			v.Del(k)
		}
	}
	set("q", q.q)
	set("class", q.class)
	set("scope", q.scope)
	set("state", q.state)
	if q.sort != "name" {
		set("sort", q.sort)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		set(kv[i], kv[i+1])
	}
	if len(v) == 0 {
		return "/mesh/ui/secrets"
	}
	return "/mesh/ui/secrets?" + v.Encode()
}

func shortDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("Jan 2, 2006")
}

// secretsPage builds and writes the Secrets list for a signed-in session.
func (u *meshUI) secretsPage(w http.ResponseWriter, r *http.Request, s identity.Session, origins []string) {
	ctx := r.Context()
	org := s.Principal.OrgID
	base := uiBase{Origins: origins, Active: "secrets", CSRF: s.CSRF}
	q := parseListQuery(r.URL.Query())
	refs, err := u.src.Visible(ctx, s.Principal)
	if err != nil {
		u.unavailable(w, http.StatusServiceUnavailable, base.Origins)
		return
	}
	truncated := len(refs) > meshUIListLimit
	if truncated {
		refs = refs[:meshUIListLimit]
	}
	var sums map[uuid.UUID]carriers.Summary
	if u.deps.Carriers != nil {
		if sums, err = u.deps.Carriers.Summary(ctx, org); err != nil {
			u.unavailable(w, http.StatusServiceUnavailable, base.Origins)
			return
		}
	}
	var runs map[uuid.UUID]RunSummary
	if u.deps.Rotations != nil && len(refs) > 0 {
		ids := make([]uuid.UUID, len(refs))
		for i, ref := range refs {
			ids[i] = ref.ID
		}
		if runs, err = u.deps.Rotations.Latest(ctx, org, ids); err != nil {
			u.unavailable(w, http.StatusServiceUnavailable, base.Origins)
			return
		}
	}
	v := secretsView{uiBase: base, Total: len(refs), Truncated: truncated, ShowRotating: u.deps.Rotations != nil,
		ShowCarriers: u.deps.Carriers != nil, Q: q.q, Class: q.class, Scope: q.scope, Sort: q.sort, StateQ: q.state,
		Add: u.addControlFor(ctx, s.Principal)}
	classes := map[string]bool{}
	needle := strings.ToLower(q.q)
	var rows []secretListRow
	for _, ref := range refs {
		classes[ref.Class] = true
		vs, err := u.src.Versions(ctx, org, ref.ID)
		if err != nil {
			u.unavailable(w, http.StatusServiceUnavailable, base.Origins)
			return
		}
		row := secretListRow{ID: ref.ID.String(), Href: "/mesh/ui/secrets/" + ref.ID.String(), Name: ref.Name, Class: ref.Class,
			Scope: string(ref.Scope.Level), Rotated: "—", Carriers: "—"}
		if ref.Description != nil {
			row.Description = *ref.Description
		}
		if cur := newSecretVersions(vs); len(cur) > 0 && cur[0].Status == versionStatusCurrent {
			row.HasVersion, row.Version, row.Fingerprint = true, versionLabel(cur[0].Version), cur[0].Fingerprint
			row.rotatedAt, row.Rotated = cur[0].CreatedAt, shortDate(cur[0].CreatedAt)
		}
		sum := sums[ref.ID]
		if v.ShowCarriers {
			v.CarrierTotal += sum.Total
			if sum.Total > 0 {
				row.Carriers = strconv.Itoa(sum.InSync) + " / " + strconv.Itoa(sum.Total)
			}
		}
		var run *RunSummary
		if rs, ok := runs[ref.ID]; ok {
			run = &rs
		}
		row.State = rowState(row.HasVersion, sum, v.ShowCarriers, run)
		if row.State.attention {
			v.Attention++
		}
		if row.State.rotating {
			v.Rotating++
		}
		if (needle != "" && !strings.Contains(strings.ToLower(ref.Name), needle)) || (q.class != "" && ref.Class != q.class) ||
			(q.scope != "" && string(ref.Scope.Level) != q.scope) || (q.state == "attention" && !row.State.attention) ||
			(q.state == "rotating" && !row.State.rotating) {
			continue
		}
		rows = append(rows, row)
	}
	sortRows(rows, q.sort)
	v.Matched = len(rows)
	pages := (len(rows) + meshUIPageSize - 1) / meshUIPageSize
	if q.page > pages && pages > 0 {
		q.page = pages
	}
	if len(rows) > 0 {
		from := (q.page - 1) * meshUIPageSize
		to := min(from+meshUIPageSize, len(rows))
		v.Rows, v.From, v.To = rows[from:to], from+1, to
		if q.page > 1 {
			v.PrevHref = q.href("page", strconv.Itoa(q.page-1))
		}
		if q.page < pages {
			v.NextHref = q.href("page", strconv.Itoa(q.page+1))
		}
	}
	if q.class != "" {
		classes[q.class] = true
	}
	v.Classes = []uiOption{{Value: "", Label: "All classes", Selected: q.class == ""}}
	names := make([]string, 0, len(classes))
	for c := range classes {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		v.Classes = append(v.Classes, uiOption{Value: c, Label: c, Selected: c == q.class})
	}
	v.Scopes = []uiOption{{"", "All scopes", q.scope == ""}, {"org", "Organization", q.scope == "org"}, {"user", "Personal", q.scope == "user"}}
	v.Sorts = []uiOption{{"name", "Sort: name", q.sort == "name"}, {"rotated", "Sort: last rotated", q.sort == "rotated"}, {"state", "Sort: state", q.sort == "state"}}
	v.States = []uiStateLink{{Label: "All", Href: q.href("state", ""), Current: q.state == ""},
		{Label: "Needs attention", Href: q.href("state", "attention"), Count: v.Attention, Current: q.state == "attention"}}
	if v.ShowRotating {
		v.States = append(v.States, uiStateLink{Label: "Rotating", Href: q.href("state", "rotating"), Count: v.Rotating, Current: q.state == "rotating"})
	}
	v.AllHref, v.AttentionHref, v.RotatingHref = "/mesh/ui/secrets", "/mesh/ui/secrets?state=attention", "/mesh/ui/secrets?state=rotating"
	u.render(w, http.StatusOK, "secrets", v)
}

func sortRows(rows []secretListRow, by string) {
	byName := func(a, b secretListRow) bool {
		if la, lb := strings.ToLower(a.Name), strings.ToLower(b.Name); la != lb {
			return la < lb
		}
		return a.ID < b.ID
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch by {
		case "rotated":
			if !a.rotatedAt.Equal(b.rotatedAt) {
				return a.rotatedAt.After(b.rotatedAt) // never rotated (zero) sorts last
			}
		case "state":
			if a.State.rank != b.State.rank {
				return a.State.rank < b.State.rank
			}
		}
		return byName(a, b)
	})
}

// uiBanner: Where names the carrier in question (host and path), drawn
// breakable; Text follows it.
type uiBanner struct {
	Level, Title string
	Where        wrapText
	Text         string
	Command      string
}

type carrierRow struct {
	Host, Path                              wrapText
	Kind, Field, Consumer, Health, Verified string
	State                                   uiState
	// finding is what the banner says about this carrier when it is off the
	// current version: the old version it holds, or that it matches none.
	finding string
}

// versionLabel draws a bare version number (the builtin provider counts 1, 2,
// 3) as v1, v2, v3, as the screen brief names a version; any other
// provider version is drawn as it is.
func versionLabel(v string) string {
	if v == "" || strings.Trim(v, "0123456789") != "" {
		return v
	}
	return "v" + v
}

// wrapText is a name, host or path drawn with a line break opportunity after
// each separator and inside every long run, so it fits a narrow frame whatever
// the stylesheet says (template "wrap").
type wrapText string

const wrapRun = 16

// Parts splits the text after each of / . - _ : @ and every wrapRun runes of a
// run without one; joined back they are the text itself.
func (w wrapText) Parts() []string {
	var parts []string
	var cur []rune
	n := 0
	for _, r := range string(w) {
		cur = append(cur, r)
		n++
		if strings.ContainsRune("/.-_:@ ", r) || n >= wrapRun {
			parts = append(parts, string(cur))
			cur, n = cur[:0:0], 0
		}
	}
	if len(cur) > 0 {
		parts = append(parts, string(cur))
	}
	return parts
}

type versionRow struct {
	Version, Fingerprint, Created string
	Length                        int
	State                         uiState
}

type runRow struct {
	Href, Started, By, Versions string
	State                       uiState
}

type secretView struct {
	uiBase
	ID, Name, Class, Scope, Description string
	Heading                             wrapText
	StoreName, StoreProvider, Created   string
	Banner                              *uiBanner
	ShowCarriers                        bool
	Carriers                            []carrierRow
	InSync                              int
	Versions                            []versionRow
	ShowRotations                       bool
	Runs                                []runRow
	RunsTotal                           int
	RunsHref                            string
	DeployCommand, InputCommand         string
	// CanLink: the session may issue an input link for this secret (it has
	// no value yet); LinkReason says why not when it may not.
	CanLink    bool
	LinkReason string
	InputCopy  copyField
}

// secretMissing is the one answer for a secret the session cannot open: the
// same bytes whether it does not exist, is another organization's or is out
// of the caller's rights.
func (u *meshUI) secretMissing(w http.ResponseWriter, base uiBase) {
	u.render(w, http.StatusNotFound, "secret-missing", base)
}

func versionState(status string) uiState {
	switch status {
	case versionStatusCurrent:
		return uiState{Label: "Current", Badge: "ok"}
	case versionStatusPrevious:
		return uiState{Label: "Previous", Badge: "outline"}
	}
	return uiState{Label: "Disabled", Badge: "muted"}
}

func runState(rs RunSummary) uiState {
	switch rs.State {
	case "done":
		return uiState{Label: "Done", Badge: "ok"}
	case "failed":
		l := "Failed"
		if rs.ErrorClass != "" {
			l += " · " + rs.ErrorClass
		}
		return uiState{Label: l, Badge: "danger"}
	case "rolling_back":
		return uiState{Label: "Rolling back", Badge: "run"}
	}
	return uiState{Label: "In progress", Badge: "run"}
}

// secretPage serves GET /mesh/ui/secrets/{id}.
func (u *meshUI) secretPage(w http.ResponseWriter, r *http.Request) {
	s, origins, ok, err := u.sessions(r)
	if err != nil {
		meshUIHeaders(w, nil)
		u.unavailable(w, http.StatusServiceUnavailable, nil)
		return
	}
	if !ok {
		u.signedOut(w, r, "")
		return
	}
	meshUIHeaders(w, origins)
	ctx := r.Context()
	org := s.Principal.OrgID
	base := uiBase{Origins: origins, Active: "secrets", CSRF: s.CSRF}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		u.secretMissing(w, base)
		return
	}
	ref, err := u.src.Readable(ctx, s.Principal, id)
	if errors.Is(err, errMeshUINotFound) {
		u.secretMissing(w, base)
		return
	}
	if err != nil {
		u.unavailable(w, http.StatusServiceUnavailable, base.Origins)
		return
	}
	vs, err := u.src.Versions(ctx, org, id)
	if err != nil {
		u.unavailable(w, http.StatusServiceUnavailable, base.Origins)
		return
	}
	st, err := u.src.Store(ctx, org, ref.StoreID)
	if err != nil {
		u.unavailable(w, http.StatusServiceUnavailable, base.Origins)
		return
	}
	v := secretView{uiBase: base, ID: id.String(), Name: ref.Name, Heading: wrapText(ref.Name), Class: ref.Class, Scope: string(ref.Scope.Level),
		StoreName: st.Name, StoreProvider: st.Provider, Created: shortDate(ref.CreatedAt),
		ShowCarriers: u.deps.Carriers != nil, ShowRotations: u.deps.Rotations != nil,
		RunsHref:      "/mesh/ui/secrets/" + id.String() + "/rotations",
		DeployCommand: "keep deploy " + shellQuote(ref.Name), InputCommand: inputCommand(ref.Name),
		InputCopy: commandCopy("input-command", ref.Name)}
	if ref.Description != nil {
		v.Description = *ref.Description
	}
	current := ""
	// byFP names the version a carrier's last observed fingerprint belongs
	// to: a plain comparison of the stored fingerprint strings.
	byFP := map[string]string{}
	for _, sv := range newSecretVersions(vs) {
		if sv.Status == versionStatusCurrent {
			current = sv.Version
		}
		if sv.Fingerprint != "" {
			byFP[sv.Fingerprint] = sv.Version
		}
		v.Versions = append(v.Versions, versionRow{Version: versionLabel(sv.Version), Fingerprint: sv.Fingerprint, Length: sv.Length,
			Created: when(sv.CreatedAt), State: versionState(sv.Status)})
	}
	var stale []carrierRow
	if v.ShowCarriers {
		list, err := u.deps.Carriers.List(ctx, org, id)
		if errors.Is(err, carriers.ErrNotFound) {
			u.secretMissing(w, base)
			return
		}
		if err != nil {
			u.unavailable(w, http.StatusServiceUnavailable, base.Origins)
			return
		}
		for _, c := range list {
			row := carrierRow{Host: wrapText(c.Host), Kind: string(c.TargetKind), Path: wrapText(c.TargetPath), Field: c.TargetField,
				Consumer: c.Consumer, Health: c.HealthcheckRef, Verified: "never"}
			if c.LastVerifiedAt != nil {
				row.Verified = when(*c.LastVerifiedAt)
			}
			switch {
			case c.State == carriers.Unknown:
				row.State = uiState{Label: "Not verified", Badge: "outline"}
			case c.Version != current:
				row.State = uiState{Label: "Stale · holds " + versionLabel(c.Version), Badge: "warn"}
				row.finding = "holds " + versionLabel(c.Version) + "."
				stale = append(stale, row)
			case c.State == carriers.Stale:
				// Registered at the current version, but the last check saw
				// another fingerprint. The row's version did not change, so
				// it says nothing of what the carrier holds: name an older
				// version only when its fingerprint is the one observed.
				if held, ok := byFP[c.LastFP]; ok && c.LastFP != "" && held != current {
					row.State = uiState{Label: "Stale · holds " + versionLabel(held), Badge: "warn"}
					row.finding = "holds " + versionLabel(held) + "."
				} else {
					row.State = uiState{Label: "Drift · not " + versionLabel(current), Badge: "warn"}
					row.finding = "no longer matches " + versionLabel(current) + " by fingerprint."
				}
				stale = append(stale, row)
			default:
				row.State = uiState{Label: "In sync", Badge: "ok"}
				v.InSync++
			}
			v.Carriers = append(v.Carriers, row)
		}
	}
	var last *RunSummary
	if v.ShowRotations {
		runs, total, err := u.deps.Rotations.List(ctx, org, id, meshUIRecentRuns, 0)
		if err != nil {
			u.unavailable(w, http.StatusServiceUnavailable, base.Origins)
			return
		}
		v.RunsTotal = total
		if len(runs) > 0 {
			last = &runs[0]
		}
		for _, rs := range runs {
			by := rs.StartedBy
			if by == "" {
				by = "—"
			}
			v.Runs = append(v.Runs, runRow{Href: "/mesh/ui/secrets/" + id.String() + "/rotations/" + rs.ID.String(),
				Started: when(rs.CreatedAt), By: by, Versions: versionLabel(rs.OldVersion) + " → " + versionLabel(rs.NewVersion), State: runState(rs)})
		}
	}
	v.Banner = secretBanner(v, current, stale, last)
	if len(v.Versions) == 0 {
		add := u.addControlFor(ctx, s.Principal)
		v.LinkReason = add.Reason
		for _, o := range add.Scopes {
			v.CanLink = v.CanLink || o.Value == string(ref.Scope.Level)
		}
		if !v.CanLink && v.LinkReason == "" {
			v.LinkReason = reasonNoRights
		}
	}
	u.render(w, http.StatusOK, "secret", v)
}

// secretBanner names the one problem of the page and its next step: a failed
// last rotation, then carriers off the current version, then nowhere laid out.
func secretBanner(v secretView, current string, stale []carrierRow, last *RunSummary) *uiBanner {
	switch {
	case last != nil && last.State == "failed":
		b := &uiBanner{Level: "danger", Title: "The last rotation failed.",
			Text: "Open the run to see which carriers it reached and which version is active."}
		if last.ErrorClass != "" {
			b.Title = "The last rotation failed: " + last.ErrorClass + "."
		}
		if last.IncidentOpened {
			b.Text = "An incident is open. " + b.Text
		}
		return b
	case len(stale) > 0:
		title := strconv.Itoa(len(stale)) + " of " + strconv.Itoa(len(v.Carriers)) + " carriers are not on the current version"
		if current != "" {
			title += " (" + versionLabel(current) + ")"
		}
		b := &uiBanner{Level: "warn", Title: title + ".", Where: stale[0].Host + " " + stale[0].Path, Text: stale[0].finding, Command: v.DeployCommand}
		if current != "" {
			b.Text += " Lay out " + versionLabel(current) + " to it again or rotate the secret:"
		}
		return b
	case v.ShowCarriers && len(v.Carriers) == 0 && current != "":
		return &uiBanner{Level: "warn", Title: "Not laid out anywhere yet.", Text: "Lay the current version out to a runner:", Command: v.DeployCommand}
	}
	return nil
}
