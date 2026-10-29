// Package store owns Keep Server's PostgreSQL connection pool and its
// schema migrations. It never keeps a secret's plaintext value — see
// pkg/secret and CONTRIBUTING.md — but it does hold KEEP_DATABASE_URL,
// which carries its own credential and gets the same treatment: never
// logged, never returned in an error, whole or in part.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a connection pool from dsn (KEEP_DATABASE_URL) and verifies
// it with a ping before returning.
//
// Every error path below builds its own message instead of propagating
// anything pgx derived from dsn. That is deliberately stricter than "redact
// the password": pgx's own error text also reformats the host, user, and
// database name from the DSN it was given, and those count as "part of the
// connection string" for this rule even though none of them is the secret
// itself — see CONTRIBUTING.md's rule that a secret's value, in full or in
// part, must never appear in logs or error text.
// The one thing pulled out of a pgx error is its SQLSTATE code (via
// [sqlStateOf]), a fixed five-character taxonomy value like "28P01" that
// carries no connection info at all.
//
// It also refuses a dsn that requests [pgx.QueryExecModeSimpleProtocol] or
// [pgx.QueryExecModeExec] — see [checkQueryExecMode] — before it dials.
//
// [OpenMigrationDB] connects to the same database over a second, separate
// path (database/sql + goose, not pgxpool) and must sanitize its own errors
// the same way — see [dsnParseErr] and [connErr], which both functions
// share so the rule can't drift between the two call sites — and must
// reject the same query exec modes; see its own doc.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// pgxpool.ParseConfig's error text echoes the offending DSN
		// verbatim (including any password), so it is never used here,
		// not even redacted.
		return nil, dsnParseErr("open database pool")
	}
	if err := checkQueryExecMode(cfg.ConnConfig.DefaultQueryExecMode); err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, dsnParseErr("open database pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, connErr("ping database", err)
	}
	return pool, nil
}

// checkQueryExecMode refuses [pgx.QueryExecModeSimpleProtocol] and
// [pgx.QueryExecModeExec]. Both encode query parameters as text and hand
// them to the server inside the statement text or bind message instead of
// the extended protocol's typed wire format, so log_statement and
// log_min_duration_statement can echo them into the server log — a path
// [RequiredLogSettings] cannot close, because it is not one of the settings
// PostgreSQL itself logs against. A dsn that sets
// default_query_exec_mode=simple_protocol or =exec is refused here, before
// any connection is attempted.
func checkQueryExecMode(mode pgx.QueryExecMode) error {
	switch mode {
	case pgx.QueryExecModeSimpleProtocol, pgx.QueryExecModeExec:
		return fmt.Errorf("default_query_exec_mode=%s would write parameter values into the server log — see \"Database requirements\" in README.md", queryExecModeName(mode))
	default:
		return nil
	}
}

// queryExecModeName returns the connection-string spelling of mode, for use
// only in [checkQueryExecMode]'s error — never a value derived from the dsn
// itself.
func queryExecModeName(mode pgx.QueryExecMode) string {
	if mode == pgx.QueryExecModeSimpleProtocol {
		return "simple_protocol"
	}
	return "exec"
}

// dsnParseErr is the fixed, dsn-independent error returned whenever a DSN
// fails to parse — pgx's own parse-error text echoes the offending DSN
// verbatim, including any password, so that text is never used here, not
// even redacted. prefix names the caller's operation (e.g. "open database
// pool") for a reader distinguishing pool errors from migration errors.
func dsnParseErr(prefix string) error {
	return fmt.Errorf("%s: invalid KEEP_DATABASE_URL", prefix)
}

// connErr is the sanitized error returned whenever a DSN parses but the
// connection attempt itself fails (wrong password, unreachable host, …).
// The only thing pulled out of the underlying pgx/database-sql error is its
// SQLSTATE code via [sqlStateOf] — never its message, which pgx reformats
// from the host, user, and database name it was given.
func connErr(prefix string, err error) error {
	return fmt.Errorf("%s: connection failed (%s)", prefix, sqlStateOf(err))
}

// sqlStateOf extracts a Postgres SQLSTATE code from err if pgx classified it
// as a server-side error, or a fixed marker otherwise (e.g. the server was
// never reached at all, so there is no server-issued code). Only .Code is
// read from the underlying *pgconn.PgError — never .Message, .Detail, or
// .Hint, which can echo back connection details such as the username.
func sqlStateOf(err error) string {
	// Preserve deadline classification without retaining driver text, which
	// can contain connection credentials. Mutation checks must distinguish
	// a stalled database from a deliberately broken security property.
	if errors.Is(err, context.DeadlineExceeded) {
		return "database operation deadline exceeded"
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return "unclassified"
}
