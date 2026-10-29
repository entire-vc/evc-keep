package api

import (
	"net/http"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// principalToTenancy converts an authenticated [identity.Principal] (from
// [identity.FromContext], put there by [identity.RequireAuth]) into the
// [tenancy.Principal] shape internal/tenancy and internal/catalog's rights
// checks expect — the one and only place that conversion happens for this
// package's new routes, so org_id and the principal's own identity always
// come from the authenticated Principal, never from a URL or request body
// (ADR-001 §6).
func principalToTenancy(p identity.Principal) tenancy.Principal {
	tp := tenancy.Principal{ID: p.ID}
	switch p.Kind {
	case identity.KindUser:
		tp.Kind = tenancy.PrincipalUser
	case identity.KindAgent:
		tp.Kind = tenancy.PrincipalAgent
		if p.SponsorUserID != nil {
			tp.SponsorUserID = *p.SponsorUserID
		}
	case identity.KindService:
		tp.Kind = tenancy.PrincipalService
	}
	return tp
}

// reachableScopes is the []tenancy.Scope shape [catalog.Catalog.Meta]'s own
// reachable parameter expects: tc's declared context chain (org, and
// workspace/project when tc sets them) plus tc.Principal's own effective
// user scope, if it has one. It trusts tc's own fields and does no
// existence validation against the database — an invented ancestor id here
// grants nothing, since Meta only ever matches a scope a secret's row
// actually carries (see orgfilter_test.go's own reachable-set construction,
// which this mirrors).
func reachableScopes(tc tenancy.Context) []tenancy.Scope {
	out := []tenancy.Scope{tenancy.Org(tc.Org)}
	if tc.Workspace != uuid.Nil {
		out = append(out, tenancy.Scope{Level: tenancy.LevelWorkspace, ID: tc.Workspace})
	}
	if tc.Project != uuid.Nil {
		out = append(out, tenancy.Scope{Level: tenancy.LevelProject, ID: tc.Project})
	}
	switch tc.Principal.Kind {
	case tenancy.PrincipalUser:
		out = append(out, tenancy.Scope{Level: tenancy.LevelUser, ID: tc.Principal.ID})
	case tenancy.PrincipalAgent:
		out = append(out, tenancy.Scope{Level: tenancy.LevelUser, ID: tc.Principal.SponsorUserID})
	}
	return out
}

// scopeFromQuery parses the "scope_level" and "scope_id" query parameters
// shared by every route in this file that names an exact scope directly
// (rather than resolving one by name) — never trusting org_id from
// anywhere but the already-authenticated Principal (see
// [principalToTenancy]'s doc), only the level/id pair within it.
func scopeFromQuery(r *http.Request) (tenancy.Scope, bool) {
	level := tenancy.Level(r.URL.Query().Get("scope_level"))
	if !level.Valid() {
		return tenancy.Scope{}, false
	}
	id, err := uuid.Parse(r.URL.Query().Get("scope_id"))
	if err != nil {
		return tenancy.Scope{}, false
	}
	return tenancy.Scope{Level: level, ID: id}, true
}
