package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/entire-vc/evc-keep/internal/testutil/fdredirect"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func neverCalledHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler downstream of RequireAuth was called despite authentication failing")
	}
}

func newAuthRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// testLogger returns a logger at Debug level whose records go to two
// places, both written to the returned buffer: the same obs allow-list
// [RequireAuth] uses in production (so the buffer shows what production
// would print), and a bare slog JSON handler (so it also shows what the
// code under test HANDED the logger, before obs filtered or scrubbed it).
// A leak assertion on this buffer therefore fails when the code logs a
// token, not only when the last layer happens to let it through.
func testLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return slog.New(teeHandler{
		obs.NewHandler(&buf, slog.LevelDebug),
		slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}),
	}), &buf
}

// teeHandler hands every record to each of its handlers.
type teeHandler []slog.Handler

func (t teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range t {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (t teeHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range t {
		if err := h.Handle(ctx, r.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (t teeHandler) WithAttrs(a []slog.Attr) slog.Handler {
	out := make(teeHandler, len(t))
	for i, h := range t {
		out[i] = h.WithAttrs(a)
	}
	return out
}

func (t teeHandler) WithGroup(name string) slog.Handler {
	out := make(teeHandler, len(t))
	for i, h := range t {
		out[i] = h.WithGroup(name)
	}
	return out
}

// captureOutput redirects the process's real stdout AND stderr FILE
// DESCRIPTORS (fd 1 and 2, via dup2) for the duration of fn and
// returns everything written to either. This has to work at the file
// descriptor level, not by swapping the os.Stdout/os.Stderr *os.File
// variables: the builtin println/print write straight to fd 2 through a
// runtime syscall and never go through those variables at all, so a
// leak test built on reassigning them would stay green against exactly
// the probe (println(token)) this exists to catch — measured directly:
// see check-identity-mutations.sh's auth-success-logs-token and
// backend-error-logs-token mutations.
//
// All cleanup (restoring fd 1/2, closing every pipe end, reading what was
// captured into the named return) happens in ONE deferred closure, not as
// plain statements after fn() returns — fn() can end via t.Fatal, which is
// runtime.Goexit under the hood and skips everything after the call site
// that triggered it, deferred calls excepted. Measured live, 24.09: an
// unrelated mutation (no-revoke-check) made a neverCalledHandler passed to
// one of these tests actually get called, which called t.Fatal from
// inside fn() — with the restore as plain post-fn() statements, fd 1/2
// were left pointed at this function's pipe forever, and the next write
// to stdout or stderr ANYWHERE in the process (including go test's own)
// died with SIGPIPE, taking down every other mutation queued after it in
// the same run.
//
// Not safe to run in parallel with another test doing the same, or with
// anything else in this process that writes to stdout/stderr while fn
// runs — this package has no t.Parallel calls.
func captureOutput(t *testing.T, fn func()) (output string) {
	t.Helper()
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("captureOutput: pipe stdout: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("captureOutput: pipe stderr: %v", err)
	}
	savedOut, err := unix.Dup(1)
	if err != nil {
		t.Fatalf("captureOutput: save fd 1: %v", err)
	}
	savedErr, err := unix.Dup(2)
	if err != nil {
		t.Fatalf("captureOutput: save fd 2: %v", err)
	}

	defer func() {
		// Restoring fd 1/2 to the saved originals closes the redirected
		// duplicate sitting in that slot, as part of dup2's own
		// semantics — this has to happen before closing wOut/wErr, or the
		// pipe would still have an open writer (fd 1/2 itself) and the
		// read below would block forever waiting for an EOF that never
		// comes.
		_ = fdredirect.Dup2(savedOut, 1)
		_ = fdredirect.Dup2(savedErr, 2)
		_ = unix.Close(savedOut)
		_ = unix.Close(savedErr)
		_ = wOut.Close()
		_ = wErr.Close()

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		_, _ = io.Copy(&buf, rErr)
		_ = rOut.Close()
		_ = rErr.Close()
		output = buf.String()
	}()

	if err := fdredirect.Dup2(int(wOut.Fd()), 1); err != nil {
		t.Fatalf("captureOutput: redirect fd 1: %v", err)
	}
	if err := fdredirect.Dup2(int(wErr.Fd()), 2); err != nil {
		t.Fatalf("captureOutput: redirect fd 2: %v", err)
	}

	fn()
	return
}

// stripRequestID replaces the response's per-request request_id with a
// fixed placeholder, so two otherwise-identical unauthenticated responses
// (each carrying its own freshly generated request_id) compare equal.
var requestIDField = regexp.MustCompile(`"request_id":"[^"]*"`)

func stripRequestID(t *testing.T, body string) string {
	t.Helper()
	return requestIDField.ReplaceAllString(body, `"request_id":"X"`)
}

func TestRequireAuthAttachesPrincipalOnSuccess(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)
	agent := seedAgent(t, db, org, sponsor)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindAgent, PrincipalID: agent, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatal(err)
	}

	var gotPrincipal Principal
	var ok bool
	handler := RequireAuth(repo, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrincipal, ok = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := serve(handler, newAuthRequest(Reveal(res.Token)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !ok {
		t.Fatal("downstream handler found no Principal in context")
	}
	if gotPrincipal.ID != agent || gotPrincipal.OrgID != org {
		t.Errorf("Principal = %+v, want ID=%s OrgID=%s", gotPrincipal, agent, org)
	}
}

func TestRequireAuthRejectsMissingHeader(t *testing.T) {
	handler := RequireAuth(NewRepo(nil), nil)(neverCalledHandler(t))
	rec := serve(handler, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var body apperr.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the closed error shape: %v (%s)", err, rec.Body.String())
	}
	if body.ErrorClass != string(apperr.ClassUnauthenticated) {
		t.Errorf("error_class = %q, want %q", body.ErrorClass, apperr.ClassUnauthenticated)
	}
}

// TestRequireAuthReturnsNotReadyOnBackendError is red run for the
// distinction [RequireAuth] must make between "this token is wrong" and
// "the database is unreachable": the latter must answer 503/not_ready,
// never 401 — a down dependency must not look like every caller suddenly
// has an invalid token.
func TestRequireAuthReturnsNotReadyOnBackendError(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	token := mustToken(t, KindService)
	db.Close() // the database becomes unreachable mid-request

	logger, buf := testLogger(t)
	handler := RequireAuth(repo, logger)(neverCalledHandler(t))
	rec := serve(handler, newAuthRequest(Reveal(token)))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — body=%s", rec.Code, rec.Body.String())
	}
	var body apperr.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the closed error shape: %v (%s)", err, rec.Body.String())
	}
	if body.ErrorClass != string(apperr.ClassNotReady) {
		t.Errorf("error_class = %q, want %q", body.ErrorClass, apperr.ClassNotReady)
	}
	if strings.Contains(strings.ToLower(body.Message), "pool") || strings.Contains(strings.ToLower(body.Message), "closed") {
		t.Errorf("message leaks the backend error's own text: %q", body.Message)
	}
	if !strings.Contains(buf.String(), `"auth_reason":"backend"`) {
		t.Errorf("debug log does not carry auth_reason=backend: %s", buf.String())
	}
}

// TestRequireOrgMatchRejectsMismatchedOrgIDWith404 is red run (2) from
// this package's own acceptance requirement: a request whose URL org_id
// doesn't match the authenticated Principal's own org_id must get 404,
// never 403 — so the response can't be used as an oracle for "does this
// org exist".
func TestRequireOrgMatchRejectsMismatchedOrgIDWith404(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	sponsor := seedUser(t, db, orgA)
	agent := seedAgent(t, db, orgA, sponsor)
	res, err := repo.Issue(ctx, IssueParams{OrgID: orgA, Kind: KindAgent, PrincipalID: agent, Scope: "org:" + orgA.String()})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /orgs/{org_id}/whoami", RequireOrgMatch("org_id")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	handler := RequireAuth(repo, nil)(mux)

	reqOwn := newAuthRequest(Reveal(res.Token))
	reqOwn.URL.Path = "/orgs/" + orgA.String() + "/whoami"
	recOwn := serve(handler, reqOwn)
	if recOwn.Code != http.StatusOK {
		t.Fatalf("own org: status = %d, want 200 — body=%s", recOwn.Code, recOwn.Body.String())
	}

	reqOther := newAuthRequest(Reveal(res.Token))
	reqOther.URL.Path = "/orgs/" + orgB.String() + "/whoami"
	recOther := serve(handler, reqOther)
	if recOther.Code != http.StatusNotFound {
		t.Fatalf("other org: status = %d, want 404 (never 403 — that would be an oracle) — body=%s", recOther.Code, recOther.Body.String())
	}
	var body apperr.Body
	if err := json.Unmarshal(recOther.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the closed error shape: %v", err)
	}
	if body.ErrorClass != string(apperr.ClassNotFound) {
		t.Errorf("error_class = %q, want %q", body.ErrorClass, apperr.ClassNotFound)
	}

	// The 404 for "wrong org" and a 404 for "route doesn't exist at all"
	// must be indistinguishable — same handler, same body shape.
	reqNoRoute := newAuthRequest(Reveal(res.Token))
	reqNoRoute.URL.Path = "/does-not-exist"
	recNoRoute := serve(handler, reqNoRoute)
	if recNoRoute.Code != http.StatusNotFound {
		t.Fatalf("no such route: status = %d, want 404", recNoRoute.Code)
	}
}

// TestAuthFailuresNeverLeakTokenToLog is the log leg of the leak test this
// package's own acceptance requirement calls for: a debug log line is
// written for every authentication failure ([RequireAuth]'s auth_reason
// log), and none of those lines may contain a real token in any of the six
// encodings [leaksIn] checks for — obs's own allow-list filters attribute
// KEYS, not the values behind an allowed key, and it does nothing at all
// for the free-text message, so this has to be proven directly against the
// rendered log line, not assumed from the allow-list's existence.
func TestAuthFailuresNeverLeakTokenToLog(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	svc := seedService(t, db, org, "proj:test")

	past := time.Now().Add(-time.Hour)
	expired, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindService, PrincipalID: svc, Scope: "proj:test", ExpiresAt: &past})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindService, PrincipalID: svc, Scope: "proj:test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, Principal{OrgID: org}, revoked.TokenID); err != nil {
		t.Fatal(err)
	}
	garbage, err := GenerateToken(KindService) // well-formed, never issued
	if err != nil {
		t.Fatal(err)
	}

	logger, buf := testLogger(t)
	handler := RequireAuth(repo, logger)(neverCalledHandler(t))

	cases := map[string]string{
		"malformed-header": "not-a-keep-token-at-all",
		"unknown":          Reveal(garbage),
		"expired":          Reveal(expired.Token),
		"revoked":          Reveal(revoked.Token),
	}
	for name, token := range cases {
		buf.Reset()
		captured := captureOutput(t, func() {
			serve(handler, newAuthRequest(token))
		})
		out := buf.String()
		if out == "" {
			t.Fatalf("%s: nothing was logged — the logger isn't wired, this test proves nothing", name)
		}
		if !strings.Contains(out, `"auth_reason"`) {
			t.Errorf("%s: log line carries no auth_reason: %s", name, out)
		}
		for _, real := range []string{Reveal(expired.Token), Reveal(revoked.Token), Reveal(garbage)} {
			if leaksIn(out, real) {
				t.Errorf("%s: auth-failure log leaks a token: %s", name, out)
			}
			if leaksIn(captured, real) {
				t.Errorf("%s: auth-failure writes a token to stdout/stderr: %q", name, captured)
			}
		}
	}

	buf.Reset()
	serve(handler, httptest.NewRequest(http.MethodGet, "/", nil)) // no Authorization header at all
	if buf.String() == "" {
		t.Fatal("missing-header case: nothing was logged")
	}

	// Positive control: leaksIn actually can find a token when it's really
	// there, at more than one of the offsets base64 needs — a detector
	// that can't see a planted leak proves nothing above.
	planted := Reveal(expired.Token)
	if !leaksIn("prefix "+planted, planted) {
		t.Fatal("leaksIn detector is blind to a token appended after other text")
	}
	if !leaksIn(hex.EncodeToString([]byte(planted)), planted) {
		t.Fatal("leaksIn detector is blind to a hex-encoded token")
	}
	// Same positive control, but at a base64 offset the token doesn't start
	// at byte 0 of — this is exactly the case a private six-encoding
	// reimplementation (checking only base64.StdEncoding.EncodeToString(needle)
	// on its own) is blind to, and why leaksIn is now backed by
	// internal/testutil/canary's Of/In instead of its own copy.
	if !leaksIn("Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte("user:"+planted)), planted) {
		t.Fatal("leaksIn detector is blind to a token at a shifted base64 offset")
	}
}

// TestRequireAuthSuccessNeverLeaksTokenToLog is the success-path leg of the
// leak test — the prior review round's TestRequireAuthAttachesPrincipalOnSuccess
// passes a nil logger, so it exercises no logging at all and would stay
// green even if the success path started logging the token. This test uses
// a real logger and captures stdout/stderr too, so a println(token) planted
// anywhere on the success path (check-identity-mutations.sh's
// auth-success-logs-token mutation) is caught.
func TestRequireAuthSuccessNeverLeaksTokenToLog(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)
	agent := seedAgent(t, db, org, sponsor)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindAgent, PrincipalID: agent, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatal(err)
	}

	logger, buf := testLogger(t)
	handler := RequireAuth(repo, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var rec *httptest.ResponseRecorder
	captured := captureOutput(t, func() {
		rec = serve(handler, newAuthRequest(Reveal(res.Token)))
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if leaksIn(buf.String(), Reveal(res.Token)) {
		t.Errorf("success path logged the token: %s", buf.String())
	}
	if leaksIn(captured, Reveal(res.Token)) {
		t.Errorf("success path wrote the token to stdout/stderr: %q", captured)
	}
}

// TestRequireAuthNotReadyNeverLeaksTokenToLog is the 503 leg of the leak
// test: a backend failure logs auth_reason=backend
// (TestRequireAuthReturnsNotReadyOnBackendError already checks that), but
// neither that log line nor stdout/stderr may carry the token that
// triggered it (check-identity-mutations.sh's backend-error-logs-token
// mutation).
func TestRequireAuthNotReadyNeverLeaksTokenToLog(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	token := mustToken(t, KindService)
	db.Close() // the database becomes unreachable mid-request

	logger, buf := testLogger(t)
	handler := RequireAuth(repo, logger)(neverCalledHandler(t))

	var rec *httptest.ResponseRecorder
	captured := captureOutput(t, func() {
		rec = serve(handler, newAuthRequest(Reveal(token)))
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if leaksIn(buf.String(), Reveal(token)) {
		t.Errorf("503 path logged the token: %s", buf.String())
	}
	if leaksIn(captured, Reveal(token)) {
		t.Errorf("503 path wrote the token to stdout/stderr: %q", captured)
	}
}

// nonResponseTypes lists this package's own exported struct types that
// TestTokenFieldAppearsOnlyOnIssueResponse's completeness scan (below)
// deliberately excludes from the token-field walk, with the reason each
// one is safe to skip. A struct that is neither here nor in that test's
// own responseTypes fails the scan — so a new exported struct is always
// forced into one list or the other, never silently skipped.
var nonResponseTypes = map[string]string{
	"Repo":        "internal storage handle carrying a *pgxpool.Pool; never constructed as a response and never serialized",
	"Token":       "holds a token's text behind an unexported pointer and renders [REDACTED] under every fmt verb, text/JSON encoding and slog value — see TestTokenValueNeverRendersAsItself",
	"IssueResult": "this package's own internal bookkeeping shape (see its own doc) — refuses to serialize at all, see TestIssueResultNeverLeaksThroughJSONLogOrFormat",
}

// TestTokenFieldAppearsOnlyOnIssueResponse is test (checked at the level of
// each type's own JSON shape, recursively through any nested struct) for
// this package's own design decision: a token's plaintext appears in
// exactly one response shape, [IssueResponse], and nowhere else — matched
// by JSON field name, since that's what actually reaches a caller, not by
// Go's own field name.
//
// responseTypes below is still a literal list, but it no longer has to be
// remembered: exportedStructTypeNames finds every exported struct this
// package declares via go/parser, independent of this list, and the test
// fails loudly if one isn't accounted for here or in [nonResponseTypes] —
// so a new `type X struct{ Token string \`json:"token"\` }` added anywhere
// in the package cannot go unscanned the way a purely hand-kept list would
// let it.
func TestTokenFieldAppearsOnlyOnIssueResponse(t *testing.T) {
	responseTypes := []any{
		apperr.Body{},
		IssueResponse{},
		Principal{},
		IssueParams{},
		Session{},
	}
	scanned := map[string]bool{}
	for _, v := range responseTypes {
		scanned[reflect.TypeOf(v).Name()] = true
	}

	for _, name := range exportedStructTypeNames(t) {
		if scanned[name] || nonResponseTypes[name] != "" {
			continue
		}
		t.Errorf("type %s is an exported struct declared in this package but is not in responseTypes or nonResponseTypes above — go/parser found it independently of that list, so add it to one or the other", name)
	}

	found := 0
	for _, v := range responseTypes {
		rt := reflect.TypeOf(v)
		walkJSONFields(t, rt, rt.Name(), &found)
	}
	if found == 0 {
		t.Fatal("no scanned type carries a token field at all — this test would pass vacuously, something is wrong with it")
	}
}

// exportedStructTypeNames returns the name of every exported struct type
// declared directly in this package's own non-test Go source, via
// go/parser over each of the package's own .go files — not a hand-kept
// list, so a type added anywhere in the package is found the moment this
// test next runs, before anyone thinks to update a list. This parses each
// file with [parser.ParseFile] rather than the package-directory form
// ([parser.ParseDir]): the latter is deprecated (it ignores build tags
// when grouping files into packages), and this package has exactly one
// file set to worry about anyway — its own directory, non-test files.
func exportedStructTypeNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("exportedStructTypeNames: read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("exportedStructTypeNames: parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if _, ok := ts.Type.(*ast.StructType); !ok {
					continue
				}
				if ast.IsExported(ts.Name.Name) {
					names = append(names, ts.Name.Name)
				}
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("exportedStructTypeNames found no exported struct at all — this scan is broken, the test above would pass vacuously")
	}
	return names
}

// walkJSONFields recursively visits every field of rt (following nested
// structs, through a pointer, a slice/array element or a map's value type)
// and fails t if a field whose JSON name is "token" is found under a type
// other than IssueResponse. rootName is the top-level type being scanned —
// the one [TestTokenFieldAppearsOnlyOnIssueResponse] actually cares about,
// since a nested field's own Go type name isn't what a caller of the API
// sees. An interface-typed field is skipped: its dynamic type isn't known
// statically, so there is nothing here to walk into.
func walkJSONFields(t *testing.T, rt reflect.Type, rootName string, found *int) {
	t.Helper()
	for rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		return
	}
	if rt == reflect.TypeOf(time.Time{}) || rt == reflect.TypeOf(uuid.UUID{}) {
		return
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		name := jsonFieldName(f)
		if name == "" {
			continue
		}
		if strings.EqualFold(name, "token") {
			*found++
			if rootName != "IssueResponse" {
				t.Errorf("type %s has a JSON field named %q — only IssueResponse may carry a token's plaintext", rootName, name)
			}
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array || ft.Kind() == reflect.Map {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			walkJSONFields(t, ft, rootName, found)
		}
	}
}

// jsonFieldName returns the name f would serialize under via
// encoding/json: the tag's own name if present (honoring "-" and an empty
// name-with-options like ",omitempty"), otherwise the Go field name.
func jsonFieldName(f reflect.StructField) string {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	if name == "" {
		return f.Name
	}
	return name
}
