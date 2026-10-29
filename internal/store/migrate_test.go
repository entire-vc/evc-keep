package store

import (
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func testMigrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	db, err := OpenMigrationDB(pgscratch.Context(t), pgscratch.DSN(t, dsn))
	if err != nil {
		t.Fatalf("open migration db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Unit-level counterpart to TestOpenNeverLeaksDSNOnFailure (store_test.go),
// for the migration path specifically: before this task's return round,
// OpenMigrationDB itself never failed on a bad dsn (database/sql's "pgx"
// driver parses and dials lazily), so the first failure came from inside
// goose (provider.GetVersions/Up), whose wrapped error text carried the raw
// pgx error — including, on a dsn that doesn't even parse, the password.
// See migrate.go's doc for why OpenMigrationDB now parses and pings eagerly.
func TestOpenMigrationDBNeverLeaksDSNOnFailure(t *testing.T) {
	c := canary.New()
	pw := c.Value(1)

	cases := []struct {
		name string
		dsn  string
	}{
		{"unreachable port", "postgres://postgres:" + pw + "@127.0.0.1:1/keep?sslmode=disable"},
		{"malformed dsn", "not a valid dsn with " + pw + " inside ::: bad"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := OpenMigrationDB(pgscratch.Context(t), tc.dsn)
			if err == nil {
				t.Fatal("expected OpenMigrationDB to fail against an unreachable/invalid dsn")
			}
			if c.In(err.Error()) {
				t.Errorf("canary leaked into OpenMigrationDB's error text: %q", err.Error())
			}
		})
	}
}

// OpenMigrationDB shares checkQueryExecMode with Open (see migrate.go's
// doc) — this is the migration-path counterpart of
// TestOpenRefusesUnsafeQueryExecMode in store_test.go.
func TestOpenMigrationDBRefusesUnsafeQueryExecMode(t *testing.T) {
	c := canary.New()
	pw := c.Value(1)
	for _, mode := range []string{"simple_protocol", "exec"} {
		t.Run(mode, func(t *testing.T) {
			dsn := "postgres://postgres:" + pw + "@127.0.0.1:1/keep?sslmode=disable&default_query_exec_mode=" + mode
			_, err := OpenMigrationDB(pgscratch.Context(t), pgscratch.DSN(t, dsn))
			if err == nil {
				t.Fatalf("OpenMigrationDB with default_query_exec_mode=%s: want a refusal, got nil error", mode)
			}
			if !strings.Contains(err.Error(), mode) {
				t.Errorf("OpenMigrationDB error = %q, want it to name %q", err.Error(), mode)
			}
			if c.In(err.Error()) {
				t.Errorf("canary leaked into OpenMigrationDB's error text: %q", err.Error())
			}
		})
	}
}

// Empty database, no migrations applied: CheckSchema must report the schema
// behind — this is the state cmd/keep-server refuses to start against.
func TestCheckSchema_BehindOnEmptyDatabase(t *testing.T) {
	db := testMigrationDB(t)

	provider, err := NewProvider(db)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	status, err := CheckSchema(pgscratch.Context(t), provider)
	if err != nil {
		t.Fatalf("check schema: %v", err)
	}
	if !status.Behind() {
		t.Fatalf("status = %+v, want Behind() = true on an empty database", status)
	}
	if status.Current != 0 {
		t.Errorf("current = %d, want 0", status.Current)
	}
}

// After "migrate up", CheckSchema must report the schema caught up, and a
// pool opened against the same database must work end to end.
func TestCheckSchema_UpToDateAfterMigrateUp(t *testing.T) {
	db := testMigrationDB(t)

	provider, err := NewProvider(db)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	status, err := CheckSchema(pgscratch.Context(t), provider)
	if err != nil {
		t.Fatalf("check schema: %v", err)
	}
	if status.Behind() {
		t.Fatalf("status = %+v, want Behind() = false after migrate up", status)
	}

	pool := testPool(t)
	if err := pool.Ping(pgscratch.Context(t)); err != nil {
		t.Fatalf("ping after migrate up: %v", err)
	}
}

// TestMigrations_DownThenUpAgain proves every migration's Down script undoes
// exactly what its Up script did: after migrating up, down to zero, and up
// again, the second Up succeeds (a Down that left an object behind fails it
// with "already exists") and the schema is at the latest version.
func TestMigrations_DownThenUpAgain(t *testing.T) {
	db := testMigrationDB(t)

	// PostgreSQL roles span databases. Exercise the unchanged migration SQL
	// with a per-test role name so Down can really drop it without revoking
	// keep_app from other tests or failing on their schema grants.
	var database string
	if err := db.QueryRowContext(pgscratch.Context(t), "SELECT current_database()").Scan(&database); err != nil {
		t.Fatal("read scratch database name failed")
	}
	role := strings.Replace(database, "keep_scratch_", "keep_scratch_role_", 1)
	ident := pgx.Identifier{role}.Sanitize()
	t.Cleanup(func() {
		var exists bool
		if err := db.QueryRowContext(pgscratch.Context(t), "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname = $1)", role).Scan(&exists); err != nil {
			t.Error("inspect migration role cleanup failed")
			return
		}
		if exists {
			for _, stmt := range []string{"DROP OWNED BY " + ident, "DROP ROLE " + ident} {
				if _, err := db.ExecContext(pgscratch.Context(t), stmt); err != nil {
					t.Error("migration role cleanup failed")
				}
			}
		}
	})
	files := fstest.MapFS{}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal("read embedded migrations failed")
	}
	for _, entry := range entries {
		content, err := fs.ReadFile(migrationFiles, "migrations/"+entry.Name())
		if err != nil {
			t.Fatal("read embedded migration failed")
		}
		files[entry.Name()] = &fstest.MapFile{Data: []byte(strings.ReplaceAll(string(content), "keep_app", role))}
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatalf("first migrate up: %v", err)
	}
	if _, err := provider.DownTo(pgscratch.Context(t), 0); err != nil {
		t.Fatalf("migrate down to 0: %v", err)
	}
	if _, err := provider.Up(pgscratch.Context(t)); err != nil {
		t.Fatalf("second migrate up after a full down: %v", err)
	}
	status, err := CheckSchema(pgscratch.Context(t), provider)
	if err != nil {
		t.Fatalf("check schema: %v", err)
	}
	if status.Behind() {
		t.Fatalf("status = %+v, want Behind() = false after down and up again", status)
	}
}
