package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// keepBinPath is set by TestMain to the built binary, once, so every test in
// this file execs the real thing rather than calling run() in-process — the
// point of this file is proving what an actual subprocess prints to actual
// stdout/stderr, which an in-process call can't observe (os.Stdout is fixed
// at process start).
var keepBinPath string

// TestMain always builds the binary and runs the suite, even without
// KEEP_DATABASE_URL set: this package also holds token_test.go's DB-free
// unit tests (including the card AC red-run guards for the token-file
// permission check), and an earlier version of this function called
// os.Exit(0) before m.Run() when the database was missing — which skipped
// those DB-free tests too, silently, with `go test ./...` still printing a
// plain `ok` and no `--- SKIP` line for any of them. Each DB-dependent test
// now skips for itself, visibly, via testPool.
func TestMain(m *testing.M) {
	// os.Exit skips deferred calls, so the work, and its cleanup, live in a
	// helper that returns the exit code (testmain_cleanup_test.go guards it).
	os.Exit(runTestMain(m))
}

func runTestMain(m *testing.M) int {
	dir, err := os.MkdirTemp("", "keep-cli-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkdir temp dir:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	keepBinPath = filepath.Join(dir, "keep")
	pkg := "."
	if os.Getenv("KEEP_E2E_PROBE_BUILD_FAIL") == "1" {
		pkg = "./no-such-package" // testmain_cleanup_test.go: exercise the build-failure exit
	}
	build := exec.Command("go", "build", "-o", keepBinPath, pkg) //nolint:gosec // G204: keepBinPath is our own mkdtemp path, not attacker input
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build keep binary:", err)
		return 1
	}
	return m.Run()
}

// testEnv wires a real server (internal/api.NewRouter against a real
// PostgreSQL pool) behind an httptest.Server, so the built binary talks over
// a real TCP loopback connection exactly as it would to a deployed Keep
// Server — this is deliberately heavier than internal/api's own in-process
// httptest.NewRecorder fixture, because the point here is exercising the
// CLI's own HTTP client, not the router.
type testEnv struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	tr       *tenancy.Repo
	cat      *catalog.Catalog
	ir       *identity.Repo
	server   *httptest.Server
	org      tenancy.Organization
	requests *atomic.Int64
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open test pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	pool := testPool(t)
	logger := obs.New(&bytes.Buffer{})
	router := api.NewRouter(logger, pool, api.Deps{})
	var requests atomic.Int64
	// Counts every request that actually reaches the router, so a test can
	// assert the CLI refused to make a call at all (not just that it
	// reported an error) — see TestCLI_RefusesWideOpenTokenFileAndNeverCallsTheServer.
	counting := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		router.ServeHTTP(w, r)
	})
	server := httptest.NewServer(counting)
	t.Cleanup(server.Close)

	e := &testEnv{
		t: t, ctx: context.Background(), pool: pool,
		tr: tenancy.New(pool), cat: catalog.New(pool), ir: identity.NewRepo(pool),
		server: server, requests: &requests,
	}
	org, err := e.tr.CreateOrganization(e.ctx, t.Name(), "")
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	e.org = org
	return e
}

func (e *testEnv) mustAdmin(name string) tenancy.User {
	e.t.Helper()
	u, err := e.tr.CreateUser(e.ctx, e.org.ID, name+"@example.test")
	if err != nil {
		e.t.Fatalf("create user %s: %v", name, err)
	}
	if _, err := e.tr.CreateMembership(e.ctx, e.org.ID, u.ID, tenancy.Org(e.org.ID), string(identity.RoleAdmin)); err != nil {
		e.t.Fatalf("grant org admin to %s: %v", name, err)
	}
	return u
}

func (e *testEnv) mustStore(name string, owner tenancy.Scope) catalog.Store {
	e.t.Helper()
	s, err := e.cat.CreateStore(e.ctx, e.org.ID, "builtin", name, owner)
	if err != nil {
		e.t.Fatalf("create store %s: %v", name, err)
	}
	if _, err := e.cat.CreateStoreBinding(e.ctx, e.org.ID, owner, s.ID); err != nil {
		e.t.Fatalf("bind store %s at %v: %v", name, owner, err)
	}
	return s
}

// mustToken mints a real bearer token and returns its plaintext. Reveal is
// permitted only in a _test.go file (.golangci.yml's token-reveal
// exclusion) — this is the one place in this whole test file a real token
// value is allowed to exist as a Go string, precisely so the canary tests
// below can prove it never appears anywhere else.
func (e *testEnv) mustToken(principalID uuid.UUID, scope tenancy.Scope) string {
	e.t.Helper()
	res, err := e.ir.Issue(e.ctx, identity.IssueParams{OrgID: e.org.ID, Kind: identity.KindUser, PrincipalID: principalID, Scope: scope.String()})
	if err != nil {
		e.t.Fatalf("issue token: %v", err)
	}
	return identity.Reveal(res.Token)
}

// runResult is one subprocess invocation's outcome.
type runResult struct {
	stdout   string
	stderr   string
	exitCode int
}

// runKeep execs the built binary with a hermetic environment: only PATH,
// KEEP_SERVER and KEEP_ORG are ever set from the parent process, plus
// whatever extraEnv the caller adds (typically KEEP_TOKEN) — so a leak into
// an *inherited* environment variable the test didn't intend can never hide
// behind the real one.
func (e *testEnv) runKeep(extraEnv []string, args ...string) runResult {
	e.t.Helper()
	return e.runKeepAt(e.server.URL, extraEnv, args...)
}

// runKeepAt is runKeep against an arbitrary server URL, for tests that stand
// in a stub for the real router.
func (e *testEnv) runKeepAt(serverURL string, extraEnv []string, args ...string) runResult {
	e.t.Helper()
	cmd := exec.Command(keepBinPath, args...) //nolint:gosec // G204: keepBinPath is the binary TestMain just built, args come from this test file's own calls
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"KEEP_SERVER=" + serverURL,
		"KEEP_ORG=" + e.org.ID.String(),
	}, extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		// args isn't printed: a positional `login <token>` call passes the
		// real token as an arg, and this failure path (the process itself
		// couldn't start or be waited on) has nothing to do with which args
		// were given.
		e.t.Fatalf("run keep (%d args): %v", len(args), err)
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

// runKeepStdin is runKeep with stdin wired to a fixed string, for
// `keep login`'s stdin-token form.
func (e *testEnv) runKeepStdin(extraEnv []string, stdin string, args ...string) runResult {
	e.t.Helper()
	cmd := exec.Command(keepBinPath, args...) //nolint:gosec // G204: keepBinPath is the binary TestMain just built, args come from this test file's own calls
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"KEEP_SERVER=" + e.server.URL,
		"KEEP_ORG=" + e.org.ID.String(),
	}, extraEnv...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		// args isn't printed: a positional `login <token>` call passes the
		// real token as an arg, and this failure path (the process itself
		// couldn't start or be waited on) has nothing to do with which args
		// were given.
		e.t.Fatalf("run keep (%d args): %v", len(args), err)
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

func withToken(token string) []string { return []string{"KEEP_TOKEN=" + token} }

// --- happy path ---

func TestCLI_CreateListMetaVersionRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	token := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	e.mustStore("default", tenancy.Org(e.org.ID))
	env := withToken(token)
	scope := []string{"--scope-level", "org", "--scope-id", e.org.ID.String()}

	create := e.runKeep(env, append([]string{"create-ref", "db-password",
		"--class", "credential", "--type", "generic",
		"--provider-ref", "builtin://default/db-password", "--json"}, scope...)...)
	if create.exitCode != 0 {
		t.Fatalf("create-ref: exit %d, stderr=%s", create.exitCode, create.stderr)
	}
	var created struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		ProviderRef string `json:"provider_ref"`
	}
	if err := json.Unmarshal([]byte(create.stdout), &created); err != nil {
		t.Fatalf("parse create-ref --json output: %v\noutput: %s", err, create.stdout)
	}
	if created.Name != "db-password" || created.ProviderRef != "builtin://default/db-password" {
		t.Fatalf("created secret fields wrong: %+v", created)
	}

	list := e.runKeep(env, append([]string{"list", "--json"}, scope...)...)
	if list.exitCode != 0 {
		t.Fatalf("list: exit %d, stderr=%s", list.exitCode, list.stderr)
	}
	var listed []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(list.stdout), &listed); err != nil {
		t.Fatalf("parse list --json output: %v\noutput: %s", err, list.stdout)
	}
	if len(listed) != 1 || listed[0].Name != "db-password" {
		t.Fatalf("list --json = %+v, want exactly [db-password]", listed)
	}

	meta := e.runKeep(env, append([]string{"meta", "db-password", "--json"}, scope...)...)
	if meta.exitCode != 0 {
		t.Fatalf("meta: exit %d, stderr=%s", meta.exitCode, meta.stderr)
	}
	var gotMeta struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(meta.stdout), &gotMeta); err != nil || gotMeta.Name != "db-password" {
		t.Fatalf("meta --json = %q, err=%v", meta.stdout, err)
	}

	version := e.runKeep(env, append([]string{"version", "db-password", "--json"}, scope...)...)
	if version.exitCode != 0 {
		t.Fatalf("version: exit %d, stderr=%s", version.exitCode, version.stderr)
	}
	var versions []map[string]any
	if err := json.Unmarshal([]byte(version.stdout), &versions); err != nil {
		t.Fatalf("parse version --json output: %v\noutput: %s", err, version.stdout)
	}
	if versions == nil {
		t.Fatal("keep version --json must print an empty array, not null, when no version exists yet")
	}
}

// TestCLI_UnknownNameAnswersSecretNotFound covers the plain "genuine miss"
// half of the no-oracle guarantee that TestCLI_CrossOrgAndGenuineMissAnswerIdenticalNotFound
// exercises against a real cross-org miss.
func TestCLI_UnknownNameAnswersSecretNotFound(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	token := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	env := withToken(token)
	scope := []string{"--scope-level", "org", "--scope-id", e.org.ID.String()}

	res := e.runKeep(env, append([]string{"meta", "does-not-exist", "--json"}, scope...)...)
	if res.exitCode == 0 {
		t.Fatalf("meta of an unknown name must fail, got exit 0: %s", res.stdout)
	}
	if !strings.Contains(res.stderr, "secret_not_found") {
		t.Fatalf("stderr = %q, want it to mention secret_not_found", res.stderr)
	}
}

// TestCLI_CrossOrgAndGenuineMissAnswerIdenticalNotFound: org1's token asking
// org2 for a name that exists there must fail byte-for-byte like asking org2
// for a name that exists nowhere, and like asking for an org that does not
// exist — internal/api's no-oracle guarantee only holds end to end if the
// CLI's own client-side name resolution (there is no by-name lookup route)
// adds no distinguishing signal. The whole stderr is compared, not just the
// error class. Note the class the server gives for an org the caller cannot
// read is not_found (not secret_not_found, which is what a miss inside the
// caller's own org says): that difference only separates "your org" from
// "not your org" and says nothing about whether org2 holds the name.
func TestCLI_CrossOrgAndGenuineMissAnswerIdenticalNotFound(t *testing.T) {
	const sharedName = "shared-name"
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	token := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	env := withToken(token)

	org2, err := e.tr.CreateOrganization(e.ctx, t.Name()+"-other", "")
	if err != nil {
		t.Fatalf("create second organization: %v", err)
	}
	store2, err := e.cat.CreateStore(e.ctx, org2.ID, "builtin", "default", tenancy.Org(org2.ID))
	if err != nil {
		t.Fatalf("create store in org 2: %v", err)
	}
	if _, err := e.cat.CreateStoreBinding(e.ctx, org2.ID, tenancy.Org(org2.ID), store2.ID); err != nil {
		t.Fatalf("bind store in org 2: %v", err)
	}
	if _, err := e.cat.CreateRef(e.ctx, catalog.CreateRefInput{
		Org: org2.ID, Scope: tenancy.Org(org2.ID), Name: sharedName,
		Class: "credential", Type: "generic", ProviderRef: "builtin://default/" + sharedName,
	}); err != nil {
		t.Fatalf("create ref in org 2: %v", err)
	}

	ask := func(org uuid.UUID, name string) runResult {
		return e.runKeep(env, "meta", name, "--org", org.String(),
			"--scope-level", "org", "--scope-id", org.String(), "--json")
	}
	existing := ask(org2.ID, sharedName)
	missing := ask(org2.ID, "no-such-name")
	noOrg := ask(uuid.New(), sharedName)

	for label, r := range map[string]runResult{"existing": existing, "missing": missing, "no-org": noOrg} {
		if r.exitCode == 0 {
			t.Fatalf("%s: a foreign org must not be readable, got exit 0: %s", label, r.stdout)
		}
		if r.stdout != "" {
			t.Fatalf("%s: stdout must stay empty on failure, got %d bytes", label, len(r.stdout))
		}
		if _, ok := errorClassOf(r.stderr); !ok {
			t.Fatalf("%s: could not extract an error class from stderr %q (the probe may not have reached the server)", label, r.stderr)
		}
	}
	if existing.stderr != missing.stderr || existing.stderr != noOrg.stderr || existing.exitCode != missing.exitCode {
		t.Fatalf("a foreign org answers differently depending on what it holds:\nexisting name: %q\nmissing name:  %q\nunknown org:   %q",
			existing.stderr, missing.stderr, noOrg.stderr)
	}
}

// errorClassOf extracts the error_class token from reportErr's
// "keep: <error_class>: <message>" stderr format.
func errorClassOf(stderr string) (string, bool) {
	const prefix = "keep: "
	if !strings.HasPrefix(stderr, prefix) {
		return "", false
	}
	rest := stderr[len(prefix):]
	i := strings.Index(rest, ":")
	if i < 0 {
		return "", false
	}
	return rest[:i], true
}

// --- leak tests (card AC red run 1) ---

// TestCLI_TokenNeverLeaksToStdoutStderrOrDebug is red run (1) from the
// card's AC: --debug printing the Authorization header must fail this test.
// scripts/check-keep-cli-mutations.sh removes client.go's redaction and
// requires it to go red.
func TestCLI_TokenNeverLeaksToStdoutStderrOrDebug(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	realToken := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	c := canary.Of(realToken)
	env := withToken(realToken)
	scope := []string{"--scope-level", "org", "--scope-id", e.org.ID.String()}

	runs := []runResult{
		e.runKeep(env, append([]string{"list", "--json", "--debug"}, scope...)...),
		e.runKeep(env, append([]string{"create-ref", "leaky-check",
			"--class", "credential", "--type", "generic",
			"--provider-ref", "builtin://default/leaky-check", "--debug"}, scope...)...),
	}
	e.mustStore("default", tenancy.Org(e.org.ID))
	runs = append(runs,
		e.runKeep(env, append([]string{"meta", "leaky-check", "--debug"}, scope...)...),
		e.runKeep(env, append([]string{"version", "leaky-check", "--debug"}, scope...)...),
		// error path: a bad scope forces the server to answer with an error body
		e.runKeep(env, []string{"meta", "no-such-name", "--scope-level", "org", "--scope-id", uuid.NewString(), "--debug"}...),
	)

	sawDebugOutput := false
	for i, r := range runs {
		// The failure message below deliberately never prints stdout/stderr:
		// this test is the one place in the suite that runs with --debug
		// against a real token, so a naive t.Fatalf including the stream
		// would put that token straight into the test/CI log it's trying to
		// prove never happens.
		if c.In(r.stdout) {
			t.Fatalf("run %d: the real token appears in stdout (%d bytes)", i, len(r.stdout))
		}
		if c.In(r.stderr) {
			t.Fatalf("run %d: the real token appears in stderr (%d bytes)", i, len(r.stderr))
		}
		if strings.Contains(r.stderr, "[debug]") {
			sawDebugOutput = true
			// Positive control: --debug must still print something for the
			// Authorization header, just never the token itself — otherwise
			// an empty debug trace would trivially "pass" this test for the
			// wrong reason.
			if !strings.Contains(r.stderr, "[REDACTED]") {
				t.Fatalf("run %d: --debug output has no [REDACTED] marker at all — the debug trace isn't exercising header redaction (%d bytes)", i, len(r.stderr))
			}
		}
	}
	if !sawDebugOutput {
		t.Fatal("no run produced any [debug] output — --debug appears to be a no-op, so this test never actually exercised the redaction path")
	}
}

// TestCLI_MetadataCanaryStaysOutOfDebugTrace: a canary placed in the one
// free-text metadata field (description) legitimately reaches stdout of
// meta --json — that is the positive control proving the detector can see
// it — but the --debug trace must carry only method, URL and redacted
// headers, never a response body. A debug trace that dumped bodies would
// copy whatever the server returned (and, for a future route that carried a
// value, the value itself) into stderr and CI logs.
func TestCLI_MetadataCanaryStaysOutOfDebugTrace(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	token := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	e.mustStore("default", tenancy.Org(e.org.ID))
	content := canary.New()
	env := withToken(token)
	scope := []string{"--scope-level", "org", "--scope-id", e.org.ID.String()}

	create := e.runKeep(env, append([]string{"create-ref", "canary-meta",
		"--class", "credential", "--type", "generic",
		"--provider-ref", "builtin://default/canary-meta",
		"--description", content.Value(0)}, scope...)...)
	if create.exitCode != 0 {
		t.Fatalf("create-ref: exit %d (stderr %d bytes)", create.exitCode, len(create.stderr))
	}

	for _, args := range [][]string{
		{"meta", "canary-meta", "--json", "--debug"},
		{"list", "--json", "--debug"},
		{"version", "canary-meta", "--json", "--debug"},
	} {
		r := e.runKeep(env, append(args, scope...)...)
		if r.exitCode != 0 {
			t.Fatalf("%s: exit %d (stderr %d bytes)", args[0], r.exitCode, len(r.stderr))
		}
		if !strings.Contains(r.stderr, "[debug]") {
			t.Fatalf("%s: no [debug] output — the trace was not exercised", args[0])
		}
		if content.In(r.stderr) {
			t.Fatalf("%s: the metadata canary appears in the --debug trace (%d bytes): response bodies must never be traced", args[0], len(r.stderr))
		}
		if args[0] != "version" && !content.In(r.stdout) {
			t.Fatalf("%s: the canary is missing from stdout, where the description legitimately appears — the detector is blind, this test proves nothing", args[0])
		}
	}
}

// TestCLI_LoginTokenNeverLeaks: the token given to `keep login` must not
// appear on stdout/stderr either (only get written, at the caller's
// request, into the token file).
func TestCLI_LoginTokenNeverLeaks(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	realToken := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	c := canary.Of(realToken)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")

	res := e.runKeep(nil, "login", realToken, "--token-file", tokenFile)
	if res.exitCode != 0 {
		t.Fatalf("login: exit %d (stderr %d bytes)", res.exitCode, len(res.stderr))
	}
	if c.In(res.stdout) || c.In(res.stderr) {
		t.Fatalf("login printed the token: stdout leak=%v (%d bytes) stderr leak=%v (%d bytes)",
			c.In(res.stdout), len(res.stdout), c.In(res.stderr), len(res.stderr))
	}
	got, err := os.ReadFile(tokenFile) //nolint:gosec // G304: tokenFile is this test's own t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != realToken {
		t.Fatalf("token file content length = %d, want it to equal the token (length %d)", len(got), len(realToken))
	}
}

// TestCLI_LoginReadsTokenFromStdin: the preferred form — no token on argv at
// all, so it never reaches `ps` or shell history.
func TestCLI_LoginReadsTokenFromStdin(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	realToken := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	c := canary.Of(realToken)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")

	res := e.runKeepStdin(nil, realToken+"\n", "login", "--token-file", tokenFile)
	if res.exitCode != 0 {
		t.Fatalf("login: exit %d (stderr %d bytes)", res.exitCode, len(res.stderr))
	}
	if c.In(res.stdout) || c.In(res.stderr) {
		t.Fatal("login (stdin form) printed the token")
	}
	got, err := os.ReadFile(tokenFile) //nolint:gosec // G304: tokenFile is this test's own t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != realToken {
		t.Fatalf("token file content length = %d, want it to equal the token (length %d)", len(got), len(realToken))
	}
}

// TestCLI_LoginWithPositionalTokenWarns: the positional form still works
// (backward compatibility), but must warn every time, since the token is
// visible to other local users via `ps` for as long as the process runs and
// lands in shell history the moment the command is typed.
func TestCLI_LoginWithPositionalTokenWarns(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	realToken := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")

	res := e.runKeep(nil, "login", realToken, "--token-file", tokenFile)
	if res.exitCode != 0 {
		t.Fatalf("login: exit %d (stderr %d bytes)", res.exitCode, len(res.stderr))
	}
	if !strings.Contains(strings.ToLower(res.stderr), "ps") && !strings.Contains(strings.ToLower(res.stderr), "history") {
		t.Fatalf("stderr (%d bytes) has no warning about ps/shell history visibility", len(res.stderr))
	}
}

// --- token-file permission guard (card AC red run 2) ---

// TestCLI_RefusesWideOpenTokenFileAndNeverCallsTheServer is the CLI-level
// companion to token_test.go's TestResolveToken_RefusesWidePermissions: a
// 0644 token file must be refused before any network call is attempted, so
// even a server that would happily answer never sees the (already
// compromised) token leave the machine.
func TestCLI_RefusesWideOpenTokenFileAndNeverCallsTheServer(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	realToken := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(realToken), 0o644); err != nil { //nolint:gosec // G306: the wide-open mode is the point of this test — it must be refused
		t.Fatal(err)
	}

	res := e.runKeep(nil, "list", "--scope-level", "org", "--scope-id", e.org.ID.String(), "--token-file", tokenFile)
	if res.exitCode == 0 {
		t.Fatalf("list with a 0644 token file must fail, got exit 0 (stdout %d bytes)", len(res.stdout))
	}
	if !strings.Contains(res.stderr, "0644") && !strings.Contains(strings.ToLower(res.stderr), "refus") {
		t.Fatalf("stderr (%d bytes) has no refusal mentioning the loose permission", len(res.stderr))
	}
	if n := e.requests.Load(); n != 0 {
		t.Fatalf("the server received %d request(s); a refused token file must fail before any network call", n)
	}
}
