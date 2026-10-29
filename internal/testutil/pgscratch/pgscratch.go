// Package pgscratch creates throwaway PostgreSQL databases for tests that
// need database-level settings (ALTER DATABASE ... SET) without touching
// the shared database KEEP_DATABASE_URL names, which other packages' tests
// use in parallel.
package pgscratch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// New creates an empty database on the server KEEP_DATABASE_URL points at,
// applies settings to it with ALTER DATABASE, and returns a DSN for it.
// The database is dropped when the test ends. The test is skipped if
// KEEP_DATABASE_URL is unset. Needs CREATEDB and, for superuser-level
// settings, superuser on that role — the CI postgres service has both.
//
// Setting names and values are written into SQL as given: pass only
// literals from the test itself.
func New(t *testing.T, settings map[string]string) string {
	t.Helper()
	base := os.Getenv("KEEP_DATABASE_URL")
	if base == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	WaitReady(t)
	ctx := Context(t)
	// Error texts from parsing or dialing a DSN can repeat the DSN,
	// password included, so they are never printed here.
	admin, err := pgxpool.New(ctx, DSN(t, base))
	if err != nil {
		t.Fatal("open admin pool on KEEP_DATABASE_URL failed")
	}
	t.Cleanup(admin.Close)

	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	name := "keep_scratch_" + hex.EncodeToString(b)
	ident := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(databaseContext(t), "CREATE DATABASE "+ident); err != nil {
		t.Fatalf("create scratch database failed (%s)", sqlState(err))
	}
	t.Cleanup(func() { dropDatabase(t, databaseContext(t), admin, ident) })
	for k, v := range settings {
		if _, err := admin.Exec(Context(t), "ALTER DATABASE "+ident+" SET "+pgx.Identifier{k}.Sanitize()+" = "+v); err != nil {
			t.Fatalf("set %s on scratch database failed (%s)", k, sqlState(err))
		}
	}

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal("KEEP_DATABASE_URL is not a URL")
	}
	u.Path = "/" + name
	dsn := DSN(t, u.String())
	// The first connection to a database that was just created is the slow
	// one on a loaded server. Make it here, with a wait, so the caller's own
	// bounded open does not carry that cost.
	warmUp(t, dsn)
	return dsn
}

// warmUp makes the first connection to dsn, waiting up to warmBudget for it.
func warmUp(t testing.TB, dsn string) {
	t.Helper()
	if err := warm(dsn, warmBudget, readyInterval); err != nil {
		t.Fatal(err)
	}
}

// NewRole creates a throwaway, non-superuser LOGIN role, grants it full
// read/write on dbDSN's public schema (present tables and anything a future
// migration adds), and returns dbDSN (as [New] returns it) with its user
// replaced by the new role. This is the shape [store.CheckNotSuperuser]
// expects a real deployment's application role to have: no superuser, no
// DDL rights of its own, but able to run keep-server's schema check and its
// own reads and writes. The role is dropped when the test ends. Needs
// CREATEROLE on the admin connection — the CI postgres superuser has it.
// memberships optionally grants application roles needed by the tested path.
func NewRole(t *testing.T, dbDSN string, memberships ...string) string {
	t.Helper()
	base := os.Getenv("KEEP_DATABASE_URL")
	if base == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	WaitReady(t)
	ctx := Context(t)
	admin, err := pgxpool.New(ctx, DSN(t, base))
	if err != nil {
		t.Fatal("open admin pool on KEEP_DATABASE_URL failed")
	}
	t.Cleanup(admin.Close)

	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	name := "keep_scratch_role_" + hex.EncodeToString(b)
	ident := pgx.Identifier{name}.Sanitize()

	// CREATE ROLE's PASSWORD clause only accepts a string literal, not a
	// query parameter — password is hex output from crypto/rand, so its
	// alphabet is fixed to [0-9a-f] and quoting it by hand is safe.
	pwBytes := make([]byte, 18)
	if _, err := rand.Read(pwBytes); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(pwBytes)

	if _, err := admin.Exec(Context(t), "CREATE ROLE "+ident+" LOGIN NOSUPERUSER PASSWORD '"+password+"'"); err != nil {
		t.Fatalf("create scratch role failed (%s)", sqlState(err))
	}
	t.Cleanup(func() {
		// t.Cleanup runs LIFO: this runs before [New]'s own DROP
		// DATABASE cleanup, while the GRANTs below still stand inside
		// dbDSN's database — DROP ROLE fails while the role owns
		// privileges anywhere, so strip them there first.
		if dbCleanup, err := pgxpool.New(Context(t), DSN(t, dbDSN)); err == nil {
			// Not fatal here: surfaced again, more usefully, by the
			// DROP ROLE below if it still holds privileges.
			dropOwned(t, Context(t), dbCleanup, ident)
			dbCleanup.Close()
		}
		dropRole(t, Context(t), admin, ident)
	})

	// GRANT ... ON ALL TABLES/SEQUENCES IN SCHEMA and ALTER DEFAULT
	// PRIVILEGES are both database-scoped, so this needs its own
	// connection into the scratch database dbDSN names, not the base
	// admin connection above (which may be pointed at an unrelated
	// database).
	dbAdmin, err := pgxpool.New(ctx, DSN(t, dbDSN))
	if err != nil {
		t.Fatal("open admin pool on scratch database failed")
	}
	defer dbAdmin.Close()
	grants := []string{
		"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO " + ident,
		"GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO " + ident,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO " + ident,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO " + ident,
	}
	for _, role := range memberships {
		grants = append(grants, "GRANT "+pgx.Identifier{role}.Sanitize()+" TO "+ident)
	}
	for _, g := range grants {
		if _, err := dbAdmin.Exec(Context(t), g); err != nil {
			t.Fatalf("grant privileges to scratch role failed (%s)", sqlState(err))
		}
	}

	u, err := url.Parse(dbDSN)
	if err != nil {
		t.Fatal("scratch database DSN is not a URL")
	}
	u.User = url.UserPassword(name, password)
	return DSN(t, u.String())
}

// reporter is the part of testing.TB the cleanup helpers use, so a test can
// record what they report. A cleanup that fails must be visible: a leaked
// scratch database keeps cluster-role grants and breaks later tests.
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func dropDatabase(t reporter, ctx context.Context, admin execer, ident string) {
	t.Helper()
	if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)"); err != nil {
		t.Errorf("drop scratch database failed (%s)", sqlState(err))
	}
}

func dropOwned(t reporter, ctx context.Context, db execer, ident string) {
	t.Helper()
	if _, err := db.Exec(ctx, "DROP OWNED BY "+ident); err != nil {
		t.Errorf("drop owned by scratch role failed (%s)", sqlState(err))
	}
}

func dropRole(t reporter, ctx context.Context, admin execer, ident string) {
	t.Helper()
	if _, err := admin.Exec(ctx, "DROP ROLE IF EXISTS "+ident); err != nil {
		t.Errorf("drop scratch role failed (%s)", sqlState(err))
	}
}

// sqlState returns the SQLSTATE of a server-side error, or a fixed marker.
// pgx's error text for a failed (re)connect names the host, user and
// database, so it is never printed.
func sqlState(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "database operation deadline exceeded"
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return "SQLSTATE " + pgErr.Code
	}
	return "unclassified"
}

// ErrClass names the class of a database error for test failure messages:
// a deadline, a SQLSTATE, or a fixed marker. It never includes error text.
func ErrClass(err error) string { return sqlState(err) }

// Context bounds a test database operation, including pool acquisition and
// cleanup. Each operation gets a fresh deadline so cleanup still works after
// a preceding operation timed out. It must not inherit a canceled test context.
func Context(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// DSN caps connection establishment independently of the query deadline.
// Parse errors never include the input, which may contain credentials.
func DSN(t testing.TB, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("test database DSN is not a PostgreSQL URL")
	}
	q := u.Query()
	q.Set("connect_timeout", "5")
	u.RawQuery = q.Encode()
	return u.String()
}

// Creating or dropping a database copies/removes files and can take longer
// than a query on a busy test server. Keep each operation below one minute,
// with its own budget independent of preceding settings or role grants.
func databaseContext(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// MigrateContext bounds one schema migration of a scratch database. A
// migration runs many statements under an advisory lock, so it gets the same
// budget as CREATE/DROP DATABASE rather than a single query's, and always its
// own: sharing the open or pool context with it let a slow open starve the
// migration of its deadline.
func MigrateContext(t testing.TB) context.Context {
	t.Helper()
	return databaseContext(t)
}
