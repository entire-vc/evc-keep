package api

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/identity"
)

// This file cross-checks api/openapi.yaml against [routeTable] — the single
// place this package's routes are declared (router.go's own doc). No YAML
// library is added for this: Go's enhanced http.ServeMux wildcard syntax
// ("{org_id}") and OpenAPI 3.1's path-templating syntax are textually
// identical, so a path key straight out of the YAML is exactly a mux
// pattern, string for string, with no translation step to get wrong.

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "patch": true,
	"options": true, "head": true,
}

var pathKeyRe = regexp.MustCompile(`^  (/\S*):\s*$`)
var methodKeyRe = regexp.MustCompile(`^    (\S+):\s*$`)

// parseOpenAPIPaths extracts the {"METHOD /pattern": true} set the
// document's own "paths:" block declares, trusting only indentation and the
// closed list of HTTP method keys — enough structure for this one
// cross-check, not a general YAML parser.
func parseOpenAPIPaths(path string) (map[string]bool, error) {
	f, err := os.Open(path) // #nosec G304 -- test-only, path is this file's own literal, never external input
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := map[string]bool{}
	inPaths := false
	currentPath := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "paths:" {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") {
			// Back to column 0 — "paths:" block is over (e.g. "components:").
			break
		}
		if m := pathKeyRe.FindStringSubmatch(line); m != nil {
			currentPath = m[1]
			continue
		}
		if currentPath == "" {
			continue
		}
		if m := methodKeyRe.FindStringSubmatch(line); m != nil {
			method := strings.ToLower(m[1])
			if httpMethods[method] {
				out[strings.ToUpper(method)+" "+currentPath] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// actualRoutes is [routeTable]'s own set, in the same "METHOD /pattern" shape
// parseOpenAPIPaths produces — enumeration only, never serves a request, so
// nil dependencies are safe (see routeTable's own doc).
func actualRoutes() map[string]bool {
	out := map[string]bool{}
	for _, e := range routeTable(identity.NewRepo(nil), nil, nil, nil, nil, nil, "", nil, nil, nil) {
		out[e.Method+" "+e.Pattern] = true
	}
	return out
}

// diffRouteSets reports every route in actual missing from doc, and every
// route in doc missing from actual — the two are meant to be identical.
func diffRouteSets(actual, doc map[string]bool) []string {
	var problems []string
	for r := range actual {
		if !doc[r] {
			problems = append(problems, fmt.Sprintf("router declares %q but api/openapi.yaml does not", r))
		}
	}
	for r := range doc {
		if !actual[r] {
			problems = append(problems, fmt.Sprintf("api/openapi.yaml declares %q but the router does not", r))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestOpenAPIMatchesRouteTable(t *testing.T) {
	doc, err := parseOpenAPIPaths("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("parse api/openapi.yaml: %v", err)
	}
	if len(doc) == 0 {
		t.Fatal("parsed zero paths from api/openapi.yaml — the parser or the fixture is broken, this test proves nothing")
	}
	for _, problem := range diffRouteSets(actualRoutes(), doc) {
		t.Error(problem)
	}
}

// TestOpenAPIMatchesRouteTable_RedRun is this guard's own proof that it can
// fail: a route present on only one side must surface as a problem.
func TestOpenAPIMatchesRouteTable_RedRun(t *testing.T) {
	actual := map[string]bool{"GET /orgs/{org_id}/secrets": true, "GET /healthz": true}
	doc := map[string]bool{"GET /orgs/{org_id}/secrets": true, "GET /healthz": true, "DELETE /orgs/{org_id}/secrets/{secret_id}": true}

	problems := diffRouteSets(actual, doc)
	if len(problems) == 0 {
		t.Fatal("diffRouteSets missed a route present in only one set; this guard cannot fail")
	}
	found := false
	for _, p := range problems {
		if strings.Contains(p, "DELETE /orgs/{org_id}/secrets/{secret_id}") {
			found = true
		}
	}
	if !found {
		t.Fatalf("diffRouteSets did not name the mismatched route, got: %v", problems)
	}
}
