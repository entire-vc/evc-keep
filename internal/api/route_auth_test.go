package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
)

// Every route requires identity authentication except probes and the
// intake endpoint, whose one-time capability is checked by the service.
// Without this guard, dropping Auth: true from one routeTable entry stays
// green unless that route's own tests happen to probe an unauthenticated
// call. Default-deny: a new route without {org_id} in its path is covered too.

// publicRoutes is the closed list of routes allowed to have Auth false.
var publicRoutes = map[string]bool{
	"GET /healthz":         true,
	"GET /readyz":          true,
	"GET /version":         true,
	"POST /input/{token}":  true,
	"GET /input/{token}":   true,
	"GET /input/assets.js": true,
}

// unauthenticatedRoutes lists the entries in table that have Auth false and
// are not in publicRoutes.
func unauthenticatedRoutes(table []routeEntry) []string {
	var bad []string
	for _, e := range table {
		key := e.Method + " " + e.Pattern
		if !e.Auth && !publicRoutes[key] {
			bad = append(bad, key)
		}
	}
	return bad
}

func TestEveryOrgRouteRequiresAuth(t *testing.T) {
	table := routeTable(identity.NewRepo(nil), nil, nil, nil, nil, nil, "", nil, nil, nil)
	orgRoutes := 0
	for _, e := range table {
		if strings.Contains(e.Pattern, "{org_id}") {
			orgRoutes++
		}
	}
	if orgRoutes == 0 {
		t.Fatal("no {org_id} routes found in routeTable — the matcher or the table is broken, this test proves nothing")
	}
	for _, r := range unauthenticatedRoutes(table) {
		t.Errorf("%s has Auth false and is not a listed public route", r)
	}
}

func TestEveryOrgRouteRequiresAuth_RedRun(t *testing.T) {
	table := []routeEntry{
		{Method: "GET", Pattern: "/healthz", Auth: false},
		{Method: "POST", Pattern: "/input/{token}", Auth: false},
		{Method: "GET", Pattern: "/orgs/{org_id}/secrets", Auth: true},
		{Method: "GET", Pattern: "/orgs/{org_id}/audit/verify", Auth: false},
		{Method: "GET", Pattern: "/links/{id}", Auth: false},
	}
	bad := unauthenticatedRoutes(table)
	if len(bad) != 2 || bad[0] != "GET /orgs/{org_id}/audit/verify" || bad[1] != "GET /links/{id}" {
		t.Fatalf("guard must flag exactly the unauthenticated non-public routes, got %v", bad)
	}
}

// TestOrgRoutesRejectMissingToken goes through NewRouter, so it also catches a
// router that stops honouring Auth when it builds the mux.
func TestOrgRoutesRejectMissingToken(t *testing.T) {
	h := NewRouter(obs.New(io.Discard), nil, Deps{})
	checked := 0
	for _, e := range routeTable(identity.NewRepo(nil), nil, nil, nil, nil, nil, "", nil, nil, nil) {
		if publicRoutes[e.Method+" "+e.Pattern] {
			continue
		}
		path := strings.NewReplacer(
			"{org_id}", "00000000-0000-0000-0000-000000000001",
			"{secret_id}", "00000000-0000-0000-0000-000000000002",
			"{token_id}", "00000000-0000-0000-0000-000000000003",
		).Replace(e.Pattern)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(e.Method, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: got %d, want 401", e.Method, e.Pattern, rec.Code)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no authenticated routes exercised")
	}
}
