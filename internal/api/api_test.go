package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool opens a pool against a real PostgreSQL instance — see
// CONTRIBUTING.md / the testing-conventions skill: the database layer is
// never mocked. CI provides one via the "postgres" service (.gitlab-ci.yml);
// locally, point KEEP_DATABASE_URL at any throwaway instance.
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

// scratchPool is a pool on a freshly migrated throwaway database, for tests
// that alter the schema (see [pgscratch.New]); the shared KEEP_DATABASE_URL
// database is never touched.
func scratchPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	ctx := context.Background()
	mdb, err := store.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatalf("open migration db: %v", err)
	}
	defer func() { _ = mdb.Close() }()
	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatalf("new migration provider: %v", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open scratch pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// capturingRouter builds the real router against a logger that writes into
// buf instead of stdout, so tests can inspect exactly what would have been
// logged.
func capturingRouter(t *testing.T) (http.Handler, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := obs.New(&buf)
	return NewRouter(logger, testPool(t), Deps{}), &buf
}

// Test 1 (CONTRIBUTING.md leak test): a canary placed in a
// request's body, headers, query string, and path must never come back in
// a response — status, headers, or body — nor appear in anything logged
// for that request, in any of the encodings canary.In checks.
//
// X-Request-Id is deliberately not one of these probes: the
// request_id contract requires a valid incoming X-Request-Id to be
// echoed into the response header and the log's request_id field — that is
// compliance, not a leak, since the caller already had the value it sent.
// TestRequestIDCanaryStaysInItsOwnChannel below covers that surface with
// the narrower, still-meaningful property: the echo happens only through
// its one designated channel, never anywhere else.
func TestNoCanaryInResponseOrLog(t *testing.T) {
	c := canary.New()
	handler, logbuf := capturingRouter(t)

	type probe struct {
		name string
		req  func() *http.Request
	}
	probes := []probe{
		{"in body", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/healthz", bytes.NewBufferString(c.Value(1)))
			return req
		}},
		{"in header", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Header.Set("X-Canary-Probe", c.Value(2))
			return req
		}},
		{"in query", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/healthz?q="+c.Value(3), nil)
		}},
		{"in path", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/"+c.Value(5), nil)
		}},
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, p.req())

			if c.In(rec.Body.String()) {
				t.Errorf("canary leaked into response body: %q", rec.Body.String())
			}
			for k, vs := range rec.Header() {
				for _, v := range vs {
					if c.In(v) {
						t.Errorf("canary leaked into response header %s: %q", k, v)
					}
				}
			}
		})
	}

	if c.In(logbuf.String()) {
		t.Errorf("canary leaked into log output:\n%s", logbuf.String())
	}
}

// TestRequestIDCanaryStaysInItsOwnChannel: a canary sent as X-Request-Id is
// expected to come back — in the X-Request-Id response header, and in the
// log's request_id field, exactly as sent. What it must never do is leak
// anywhere else: the response body, any other response header, or via a
// different encoding than the one literally sent (which would indicate a
// second, unintended path handling it).
func TestRequestIDCanaryStaysInItsOwnChannel(t *testing.T) {
	c := canary.New()
	id := c.Value(4)
	handler, logbuf := capturingRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", id)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-Id"); got != id {
		t.Fatalf("X-Request-Id echo = %q, want %q (a valid incoming id must be reused verbatim)", got, id)
	}
	if c.In(rec.Body.String()) {
		t.Errorf("canary leaked into response body: %q", rec.Body.String())
	}
	for k, vs := range rec.Header() {
		if k == "X-Request-Id" {
			continue
		}
		for _, v := range vs {
			if c.In(v) {
				t.Errorf("canary leaked into unrelated response header %s: %q", k, v)
			}
		}
	}

	// The log is expected to contain the literal id, once, as request_id.
	log := logbuf.String()
	if !bytes.Contains([]byte(log), []byte(id)) {
		t.Errorf("expected request_id %q in log output, got:\n%s", id, log)
	}
}

// Test 2: a handler that panics with a canary value in its
// argument must produce a 500 with error_class=internal, and the canary
// must not appear anywhere in the log — including the recovered panic
// value itself, which this test never lets the logger see. It also checks
// the lead's stricter rule for the logged stack itself (no argument values
// at all, not just "no canary in the stack"): runtime/debug.Stack
// prints each call-site's argument words as raw hex, e.g.
// "pkg.f(0xc000123456, 0x1a)", and those can be real values, not just
// pointers — a canary embedded in a string argument would already be
// caught above, but an int or pointer-shaped argument value would not be.
// "0x" is the fixed signature every one of those raw words shares (and
// also the PC offset on each frame's file:line row), so its absence from
// the logged "stack" field is the general-case check.
func TestPanicRecoveryDoesNotLeakCanary(t *testing.T) {
	c := canary.New()
	var buf bytes.Buffer
	logger := obs.New(&buf)

	mux := http.NewServeMux()
	mux.Handle("GET /panics", logged("/panics", logger, func(w http.ResponseWriter, r *http.Request) {
		panic(fmt.Sprintf("boom: %s", c.Value(1)))
	}))
	handler := withRequestID(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/panics", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"error_class":"internal"`)) {
		t.Errorf("response body missing error_class=internal: %s", rec.Body.String())
	}
	if c.In(rec.Body.String()) {
		t.Errorf("canary leaked into panic response body: %q", rec.Body.String())
	}
	if c.In(buf.String()) {
		t.Errorf("canary leaked into panic log output:\n%s", buf.String())
	}

	var logLine struct {
		Stack string `json:"stack"`
	}
	if err := json.Unmarshal(buf.Bytes(), &logLine); err != nil {
		t.Fatalf("parse panic log line as JSON: %v\nline: %s", err, buf.String())
	}
	if logLine.Stack == "" {
		t.Fatal("panic log line is missing its \"stack\" field")
	}
	if strings.Contains(logLine.Stack, "0x") {
		t.Errorf("logged stack retains a raw argument/PC value (contains %q): %s", "0x", logLine.Stack)
	}
}

// Test 3: a disallowed log key must never appear in the
// output — this exercises internal/obs directly rather than going through
// HTTP, since it is obs's contract being tested, not api's.
func TestObsDropsDisallowedKeys(t *testing.T) {
	var buf bytes.Buffer
	logger := obs.New(&buf)

	logger.Info("test event",
		"method", "GET", // allowed
		"value", "should-never-appear",
		"token", "should-never-appear-either",
		"body", "nor-this",
	)

	out := buf.String()
	for _, forbidden := range []string{"should-never-appear", "should-never-appear-either", "nor-this"} {
		if bytes.Contains([]byte(out), []byte(forbidden)) {
			t.Errorf("disallowed value leaked into log output: %q\nfull output:\n%s", forbidden, out)
		}
	}
	if !bytes.Contains([]byte(out), []byte(`"method":"GET"`)) {
		t.Errorf("allowed key was dropped too: %s", out)
	}
	// Each disallowed key must also produce its own warning, naming the key.
	for _, key := range []string{"value", "token", "body"} {
		if !bytes.Contains([]byte(out), []byte(`"key":"`+key+`"`)) {
			t.Errorf("expected a dropped-attribute warning naming key %q, got:\n%s", key, out)
		}
	}
}
