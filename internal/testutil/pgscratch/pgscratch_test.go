package pgscratch

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestContextBoundsDatabaseWait(t *testing.T) {
	// The bound is a property of the context, not of how long a loaded
	// server takes to answer: check the deadline itself, then that a wait
	// under a (shortened) deadline really stops there.
	deadline, ok := Context(t).Deadline()
	if remaining := time.Until(deadline); !ok || remaining <= 0 || remaining > 10*time.Second {
		t.Fatal("database operation lacks a ten-second bound")
	}

	dsn := New(t, nil)
	pool, err := pgxpool.New(Context(t), dsn)
	if err != nil {
		t.Fatal("open scratch pool failed")
	}
	t.Cleanup(pool.Close)
	// A working connection is the positive control, before making it wait.
	if err := pool.Ping(Context(t)); err != nil {
		t.Fatal("scratch pool ping failed")
	}
	// The server would sleep a minute; the deadline is one second, so the
	// call returning long before the sleep ends is the stop, whatever the
	// runner's speed.
	short, cancel := context.WithTimeout(Context(t), time.Second)
	defer cancel()
	start := time.Now()
	_, err = pool.Exec(short, "SELECT pg_sleep(60)")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("database operation did not stop at its context deadline")
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("database operation outlived its context deadline")
	}
	// Cleanup and subsequent operations need a fresh, uncanceled context.
	if err := pool.Ping(Context(t)); err != nil {
		t.Fatal("fresh operation after deadline failed")
	}
}

func TestDSNCapsConnectionTimeout(t *testing.T) {
	// Synthetic connection metadata only. Never print DSNs or parsing errors.
	for _, query := range []string{"", "&connect_timeout=120"} {
		cfg, err := pgxpool.ParseConfig(DSN(t, "postgres://test@localhost/test?sslmode=disable"+query))
		if err != nil {
			t.Fatal("parse bounded DSN failed")
		}
		if cfg.ConnConfig.ConnectTimeout <= 0 || cfg.ConnConfig.ConnectTimeout > 5*time.Second {
			t.Fatal("connection establishment has no effective five-second bound")
		}
	}
}

// A leaked scratch database retains cluster-role grants and makes later
// migration tests fail when dropping keep_app. Check cleanup after the child
// has finished, rather than trusting a successful CREATE DATABASE alone.
func TestNewDropsDatabase(t *testing.T) {
	var name string
	var adminDSN string
	t.Run("create", func(t *testing.T) {
		dsn := New(t, map[string]string{"log_error_verbosity": "terse"})
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("parse scratch DSN failed")
		}
		name = u.Path[1:]
		u.Path = "/postgres"
		// Bounded like every other connection here, and warmed: the first
		// connection to the maintenance database on a loaded runner is the
		// slow one and used to eat the whole ten-second query budget.
		adminDSN = DSN(t, u.String())
		warmUp(t, adminDSN)
		pool, err := pgxpool.New(Context(t), adminDSN)
		if err != nil {
			t.Fatal("open admin pool failed")
		}
		t.Cleanup(pool.Close)
		if exists, why := databaseExists(Context(t), pool, name); why != "" {
			t.Fatal("inspect scratch database failed (" + why + ")")
		} else if !exists {
			t.Fatal("scratch database was not created")
		}
	})
	if t.Failed() {
		t.FailNow()
	}
	if name == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	pool, err := pgxpool.New(Context(t), adminDSN)
	if err != nil {
		t.Fatal("open admin pool after cleanup failed")
	}
	t.Cleanup(pool.Close)
	// Also remove a deliberately leaked negative-control database.
	t.Cleanup(func() {
		if _, err := pool.Exec(databaseContext(t), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error("fallback scratch cleanup failed")
		}
	})
	exists, why := databaseExists(Context(t), pool, name)
	if why != "" {
		t.Fatal("inspect scratch cleanup failed (" + why + ")")
	}
	if exists {
		t.Fatal("scratch database survived test cleanup")
	}
}

// databaseExists keeps a failed query apart from an absent database, so a
// red run says which of the two it was. why is empty when the query worked.
func databaseExists(ctx context.Context, pool *pgxpool.Pool, name string) (exists bool, why string) {
	if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
		return false, reason(err)
	}
	return exists, ""
}

func TestDatabaseExistsSeparatesQueryFailureFromAbsence(t *testing.T) {
	// Absence is an answer; an unreachable server is not.
	dead, err := pgxpool.New(context.Background(), "postgres://u@127.0.0.1:1/x?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal("open pool failed")
	}
	defer dead.Close()
	if exists, why := databaseExists(Context(t), dead, "x"); exists || why == "" {
		t.Fatal("a failed query was reported as an answer")
	}
	if os.Getenv("KEEP_DATABASE_URL") == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	WaitReady(t)
	live, err := pgxpool.New(Context(t), DSN(t, os.Getenv("KEEP_DATABASE_URL")))
	if err != nil {
		t.Fatal("open admin pool failed")
	}
	defer live.Close()
	if exists, why := databaseExists(Context(t), live, "keep_scratch_no_such_database"); exists || why != "" {
		t.Fatal("an absent database was not reported as a clean absence")
	}
}

func TestDatabaseContextBoundsFileOperations(t *testing.T) {
	ctx := databaseContext(t)
	deadline, ok := ctx.Deadline()
	if remaining := time.Until(deadline); !ok || remaining <= 0 || remaining > 30*time.Second {
		t.Fatal("database file operation lacks a thirty-second bound")
	}
}

func TestMigrateContextIsFreshAndBounded(t *testing.T) {
	// Spent first context: the migration context must not inherit it.
	spent, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-spent.Done()
	ctx := MigrateContext(t)
	if ctx.Err() != nil {
		t.Fatal("migration context inherited an expired deadline")
	}
	deadline, ok := ctx.Deadline()
	if remaining := time.Until(deadline); !ok || remaining < 11*time.Second || remaining > 30*time.Second {
		t.Fatal("migration context is not its own thirty-second bound")
	}
}

type recorder struct{ failures []string }

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// A closed pool fails every statement the way an unreachable server would.
// Each cleanup step must report that, so a leaked scratch database or role
// turns the test red instead of surfacing in a later, unrelated one.
func TestCleanupReportsFailedDrop(t *testing.T) {
	ctx := context.Background()
	dead, err := pgxpool.New(ctx, "postgres://u@127.0.0.1:1/x?sslmode=disable")
	if err != nil {
		t.Fatal("open pool failed")
	}
	dead.Close()
	for name, drop := range map[string]func(*recorder){
		"database": func(r *recorder) { dropDatabase(r, ctx, dead, `"x"`) },
		"owned":    func(r *recorder) { dropOwned(r, ctx, dead, `"x"`) },
		"role":     func(r *recorder) { dropRole(r, ctx, dead, `"x"`) },
	} {
		var r recorder
		drop(&r)
		if len(r.failures) != 1 {
			t.Fatalf("%s: a failed drop was not reported exactly once", name)
		}
	}
}

// NewRole's cleanup must run, not just exist: the throwaway role is a
// cluster-level object that outlives its database if its DROP never happens.
func TestNewRoleCleanupDropsRole(t *testing.T) {
	var role string
	t.Run("create", func(t *testing.T) {
		dsn := NewRole(t, New(t, nil))
		u, err := url.Parse(dsn)
		if err != nil || u.User == nil {
			t.Fatal("parse scratch role DSN failed")
		}
		role = u.User.Username()
	})
	if t.Failed() {
		t.FailNow()
	}
	if role == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	base := os.Getenv("KEEP_DATABASE_URL")
	pool, err := pgxpool.New(Context(t), DSN(t, base))
	if err != nil {
		t.Fatal("open admin pool failed")
	}
	t.Cleanup(pool.Close)
	var exists bool
	if err := pool.QueryRow(Context(t), "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname = $1)", role).Scan(&exists); err != nil {
		t.Fatal("inspect scratch role cleanup failed")
	}
	if exists {
		t.Cleanup(func() { dropRole(t, Context(t), pool, pgx.Identifier{role}.Sanitize()) })
		t.Fatal("scratch role survived test cleanup")
	}
}
