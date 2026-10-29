package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDatabaseDeadlineDiagnosticsAreClassifiedAndSanitized(t *testing.T) {
	c := canary.New()
	err := fmt.Errorf("connection detail %s: %w", c.Value(1), context.DeadlineExceeded)
	if !c.In(err.Error()) {
		t.Fatal("canary positive control failed")
	}
	for _, out := range []string{sqlStateOf(err), connErr("test database", err).Error()} {
		if c.In(out) {
			t.Error("database deadline diagnostic exposed connection details")
		}
		if !strings.Contains(out, "database operation deadline exceeded") {
			t.Error("database deadline diagnostic lost the infrastructure marker")
		}
	}
}

func TestDatabaseQueryDeadlineKeepsInfrastructureMarker(t *testing.T) {
	pool := testPool(t)
	if err := pool.Ping(pgscratch.Context(t)); err != nil {
		t.Fatal("database positive control failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := pool.Exec(ctx, "SELECT pg_sleep(1)")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("database wait did not reach its context deadline")
	}
	if sqlStateOf(err) != "database operation deadline exceeded" {
		t.Fatal("query deadline lost the infrastructure marker")
	}
	// Exercise the production guard's sanitized return path as well.
	_, err = readLogSetting(ctx, pool, "log_statement")
	if err == nil || !strings.Contains(err.Error(), "database operation deadline exceeded") {
		t.Fatal("setting read lost the infrastructure marker")
	}
}

// testPool opens a pool against a real PostgreSQL instance — see
// CONTRIBUTING.md: the database layer is never mocked. CI provides one via
// the "postgres" service (.gitlab-ci.yml); locally, point
// KEEP_DATABASE_URL at any throwaway instance.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	pool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
	if err != nil {
		t.Fatalf("open test pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Test 4: a KEEP_DATABASE_URL carrying a canary password
// must never surface that canary in the returned error's text, on any
// connection failure — auth failure, unreachable host, or a DSN that
// doesn't even parse. See Open's doc for why this checks more than just
// "is the password redacted".
func TestOpenNeverLeaksDSNOnFailure(t *testing.T) {
	c := canary.New()
	pw := c.Value(1)

	cases := []struct {
		name string
		dsn  string
	}{
		{"wrong password", "postgres://postgres:" + pw + "@127.0.0.1:1/keep?sslmode=disable"},
		{"unreachable port", "postgres://postgres:" + pw + "@127.0.0.1:1/keep?sslmode=disable"},
		{"malformed dsn", "not a valid dsn with " + pw + " inside ::: bad"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(pgscratch.Context(t), tc.dsn)
			if err == nil {
				t.Fatal("expected Open to fail against an unreachable/invalid DSN")
			}
			if c.In(err.Error()) {
				t.Errorf("canary leaked into Open's error text: %q", err.Error())
			}
		})
	}
}

// TestOpenSucceedsAgainstRealDatabase is the positive counterpart: Open
// must actually work against a real, reachable PostgreSQL instance — see
// CONTRIBUTING.md, the database layer is never mocked.
func TestOpenSucceedsAgainstRealDatabase(t *testing.T) {
	pool := testPool(t)
	if err := pool.Ping(pgscratch.Context(t)); err != nil {
		t.Fatalf("ping failed (%s)", sqlStateOf(err))
	}
}

// Leak test first: with default_query_exec_mode=simple_protocol, pgx
// interpolates parameter values into the SQL text it sends, so
// log_statement (or log_min_duration_statement) writes them into the
// server log outside anything CheckLogSettings governs — see
// checkQueryExecMode's doc. Red without the guard: connecting directly via
// pgx (bypassing Open, which already carries the fix) with
// QueryExecModeSimpleProtocol and running a parameterized query carrying a
// canary against a real, log_statement=all database puts the canary in the
// server log verbatim — recorded manually for this task's MR (not
// automated here: reading a PostgreSQL service's own server log isn't
// something this suite can do portably against CI's postgres service).
// This test is the unit-level guard that actually ships: it stops Open
// before it ever dials, on a DSN that doesn't even need a reachable host —
// with the canary as the DSN password, so a future change that echoes the
// DSN into this error path is itself caught.
func TestOpenRefusesUnsafeQueryExecMode(t *testing.T) {
	c := canary.New()
	pw := c.Value(1)
	cases := []struct {
		name string
		mode string
	}{
		{"simple_protocol", "simple_protocol"},
		{"exec", "exec"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dsn := "postgres://postgres:" + pw + "@127.0.0.1:1/keep?sslmode=disable&default_query_exec_mode=" + tc.mode
			_, err := Open(pgscratch.Context(t), dsn)
			if err == nil {
				t.Fatalf("Open with default_query_exec_mode=%s: want a refusal, got nil error", tc.mode)
			}
			if !strings.Contains(err.Error(), tc.mode) {
				t.Errorf("Open error = %q, want it to name %q", err.Error(), tc.mode)
			}
			if c.In(err.Error()) {
				t.Errorf("canary leaked into Open's error text: %q", err.Error())
			}
		})
	}
}

// The default exec mode (unset, and the extended-protocol modes Open
// leaves alone) must not be refused — otherwise every DSN would fail.
func TestOpenAcceptsDefaultQueryExecMode(t *testing.T) {
	if err := checkQueryExecMode(pgx.QueryExecModeCacheStatement); err != nil {
		t.Errorf("checkQueryExecMode(default) = %v, want nil", err)
	}
}
