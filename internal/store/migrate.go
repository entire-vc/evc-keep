package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
	"github.com/pressly/goose/v3/lock"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver, used only here
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// OpenMigrationDB opens a plain database/sql handle for running migrations.
// goose operates on *sql.DB, not pgxpool.Pool, so this is separate from
// [Open]'s pool and is meant to be short-lived: open it, migrate or check,
// close it. Same DSN-handling rule as [Open] — see that function's doc.
//
// database/sql's own "pgx" driver (registered by the stdlib import above)
// parses dsn and dials lazily, on the first query — never inside sql.Open
// itself. Left alone, that means the first place a bad dsn would fail is
// deep inside goose (provider.GetVersions/Up), whose wrapped error text is
// exactly the unsanitized pgx text [Open] already treats as unsafe. This
// function parses and pings up front instead, specifically so a bad dsn
// fails right here, where it can be sanitized the same way [Open] sanitizes
// it — never inside goose. It also refuses the same query exec modes as
// [Open] — see [checkQueryExecMode].
func OpenMigrationDB(ctx context.Context, dsn string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		// Same reasoning as pgxpool.New in Open: a parse error's text
		// echoes the offending dsn verbatim, including any password.
		return nil, dsnParseErr("open migration database handle")
	}
	if err := checkQueryExecMode(cfg.DefaultQueryExecMode); err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, dsnParseErr("open migration database handle")
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, connErr("open migration database handle", err)
	}
	return db, nil
}

// NewProvider builds a goose migration provider bound to db and to this
// package's embedded migration files.
//
// It uses a Postgres session-level advisory lock (goose's own recommended
// mechanism for this) so that two processes calling Up concurrently
// against the same database serialize instead of racing on the same
// CREATE TABLE — goose has no locking by default (see [goose.WithSessionLocker]'s
// doc: "If WithSessionLocker is not called, locking is disabled"), and this
// codebase's own tests exercise exactly that scenario: `go test ./...`
// parallelizes across packages, and internal/store's, cmd/keep-server's,
// and internal/identity's tests all call this function against the one
// shared CI Postgres service. Without the lock, that surfaced as
// "relation already exists" (42P07) — not a bug in any one migration, but
// in every migration after the first non-idempotent one, applied
// concurrently with no serialization at all.
func NewProvider(db *sql.DB) (*goose.Provider, error) {
	migrationsDir, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("load embedded migrations: %w", err)
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, fmt.Errorf("create migration lock: %w", err)
	}
	provider, err := goose.NewProvider(database.DialectPostgres, db, migrationsDir, goose.WithSessionLocker(locker))
	if err != nil {
		return nil, fmt.Errorf("create migration provider: %w", err)
	}
	return provider, nil
}

// SchemaStatus is the result of comparing the database's applied migration
// version against the version this binary was built with.
type SchemaStatus struct {
	Current  int64
	Required int64
}

// Behind reports whether the database schema has not caught up to what this
// binary expects.
func (s SchemaStatus) Behind() bool { return s.Current < s.Required }

// CheckSchema reports the database's current migration version against the
// highest version embedded in this binary, without applying anything. The
// server calls this at startup and refuses to serve traffic if the schema
// is behind — see cmd/keep-server. It never migrates on its own.
func CheckSchema(ctx context.Context, provider *goose.Provider) (SchemaStatus, error) {
	current, required, err := provider.GetVersions(ctx)
	if err != nil {
		return SchemaStatus{}, fmt.Errorf("read schema version: %w", err)
	}
	return SchemaStatus{Current: current, Required: required}, nil
}
