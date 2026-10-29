package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/version"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

// setBuild injects build-time values the way -ldflags would and restores them.
func setBuild(t *testing.T, commit, buildDate, ver string) {
	t.Helper()
	oc, od, ov := version.Commit, version.BuildDate, version.Version
	version.Commit, version.BuildDate, version.Version = commit, buildDate, ver
	t.Cleanup(func() { version.Commit, version.BuildDate, version.Version = oc, od, ov })
}

func getVersion(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	h := NewRouter(obs.New(io.Discard), nil, Deps{})
	rec := httptest.NewRecorder()
	// No Authorization header: the route is public like the probes.
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))
	return rec
}

func TestVersionJSONShape(t *testing.T) {
	setBuild(t, testCommit, "2026-10-26T01:02:03Z", "1.2.3")
	rec := getVersion(t)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 without credentials; body %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not JSON: %v: %q", err, rec.Body.String())
	}
	want := map[string]any{"commit": testCommit, "build_time": "2026-10-26T01:02:03Z"}
	if len(got) != len(want) || got["commit"] != want["commit"] || got["build_time"] != want["build_time"] {
		t.Fatalf("body = %v, want exactly %v", got, want)
	}
}

func TestVersionWithoutInjectedValues(t *testing.T) {
	setBuild(t, "unknown", "unknown", "0.0.0-dev")
	rec := getVersion(t)
	var got VersionResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	// A test binary built in a checkout may carry vcs.revision; either way the
	// commit is 40-hex or the literal "unknown", and a missing time is empty.
	if got.Commit != "unknown" && len(got.Commit) != 40 {
		t.Fatalf("commit = %q, want 40-hex or unknown", got.Commit)
	}
}

func TestVersionRejectsNonGET(t *testing.T) {
	h := NewRouter(obs.New(io.Discard), nil, Deps{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/version", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /version = %d, want 405", rec.Code)
	}
}

// versionLeaks returns every forbidden marker that appears in body.
func versionLeaks(body string, forbidden map[string]string) []string {
	var out []string
	for name, marker := range forbidden {
		if marker != "" && strings.Contains(body, marker) {
			out = append(out, name)
		}
	}
	return out
}

// TestVersionExposesNoOtherBuildOrEnvData: the body holds only commit and
// build_time. Other build metadata the binary knows (version string, Go
// toolchain, module path, hostname) and a process environment value must not
// reach it.
func TestVersionExposesNoOtherBuildOrEnvData(t *testing.T) {
	const envCanary = "KEEP_VERSION_ENV_CANARY_5f3a9c"
	t.Setenv("KEEP_VERSION_TEST_ENV", envCanary)
	const verCanary = "9.9.9-version-canary-71be"
	setBuild(t, testCommit, "2026-10-26T01:02:03Z", verCanary)
	host, _ := os.Hostname()

	forbidden := map[string]string{
		"version string": verCanary,
		"env value":      envCanary,
		"go version":     runtime.Version(),
		"module path":    "github.com/entire-vc/evc-keep",
		"hostname":       host,
		"goos/goarch":    runtime.GOOS + "/" + runtime.GOARCH,
	}
	rec := getVersion(t)
	body := rec.Body.String()
	if leaks := versionLeaks(body, forbidden); len(leaks) > 0 {
		t.Fatalf("/version body leaks %v: %q", leaks, body)
	}
	for k, vs := range rec.Header() {
		for _, v := range vs {
			if leaks := versionLeaks(v, forbidden); len(leaks) > 0 {
				t.Fatalf("/version header %s leaks %v: %q", k, leaks, v)
			}
		}
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	for k := range keys {
		if k != "commit" && k != "build_time" {
			t.Fatalf("unexpected field %q in /version body", k)
		}
	}
}

// Red run: the leak check must fire on a body that does leak, otherwise the
// test above proves nothing.
func TestVersionLeakCheckRedRun(t *testing.T) {
	forbidden := map[string]string{"version string": "9.9.9-x", "env value": "SECRET_ENV"}
	bad := `{"commit":"` + testCommit + `","build_time":"","version":"9.9.9-x","env":"SECRET_ENV"}`
	if leaks := versionLeaks(bad, forbidden); len(leaks) != 2 {
		t.Fatalf("leak check missed a leaking body, found %v", leaks)
	}
	if leaks := versionLeaks(`{"commit":"`+testCommit+`","build_time":""}`, forbidden); len(leaks) != 0 {
		t.Fatalf("leak check flagged a clean body: %v", leaks)
	}
}
