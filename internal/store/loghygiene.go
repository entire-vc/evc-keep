package store

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RequiredLogSettings are the PostgreSQL server settings Keep requires
// before it serves traffic, each checked for exact equality — see
// [AllowedLogStatement] for the one setting checked against a small set
// instead. With the server defaults, a statement that violates a
// constraint, or one that simply runs, makes PostgreSQL write parameter
// values into its own server log, outside anything this process controls:
//
//   - log_error_verbosity=default adds "DETAIL: Failing row contains (...)"
//     with every column of the rejected row, and a CONTEXT line with bound
//     parameter values when log_parameter_max_length_on_error is raised
//     (any session may raise it). terse drops DETAIL, HINT, QUERY and
//     CONTEXT.
//   - log_min_error_statement=error adds "STATEMENT: <sql>" to every failed
//     statement, which carries any literal values in the SQL text. terse
//     does not remove it; only raising the threshold to panic does.
//   - log_min_duration_statement and log_min_duration_sample, above -1
//     (disabled), log every statement (or a sample of them) that runs
//     longer than the threshold — success or failure — with its bound
//     parameter values, regardless of log_error_verbosity.
//   - log_transaction_sample_rate, above 0, does the same per transaction.
//
// Together with [AllowedLogStatement] and [AllowedLogMinMessages] they keep
// DETAIL, CONTEXT and STATEMENT lines, and any duration- or
// sample-triggered logging, out of the server log — with log_min_messages
// raised to fatal or panic (see [AllowedLogMinMessages]), the primary error
// message itself (a value PostgreSQL fails to parse: invalid input syntax
// for type uuid: "...", ERROR severity) is suppressed too, as a side effect
// of suppressing debug_print_*'s LOG-severity output; code should still not
// pass unchecked strings into typed parameters, since that suppression is
// an operational cost of this setting, not something to rely on. Nor do
// they touch [checkQueryExecMode]'s concern (the wire protocol) or an
// application role with superuser rights — see [CheckNotSuperuser] — and
// the check runs once at startup: an ALTER DATABASE ... RESET afterwards
// reaches new pool connections unnoticed.
//
// debug_print_plan, debug_print_parse and debug_print_rewritten are a
// separate gap none of the above closes: each has PostgreSQL's "user"
// context, so any role may turn one on for its own session — or persist
// it for every future one with a plain ALTER ROLE/DATABASE ... SET, no
// GRANT needed — and each then writes the query's parsed or planned tree
// straight to the server log at LOG severity, bound parameter values
// included, in a form none of the settings above suppress. Because
// they're user-context, checking they're off at startup only catches
// what's already set database-wide; nothing stops a session from
// switching one on afterwards. See [AllowedLogMinMessages] instead:
// raising log_min_messages high enough suppresses LOG-severity output
// regardless of who turns debug_print_* on or when.
//
// All are superuser-level settings, so Keep can only check them, not set
// them. The operator sets them once per database:
//
//	ALTER DATABASE keep SET log_error_verbosity = terse;
//	ALTER DATABASE keep SET log_min_error_statement = panic;
//	ALTER DATABASE keep SET log_statement = 'none';   -- or 'ddl'
//	ALTER DATABASE keep SET log_min_duration_statement = -1;
//	ALTER DATABASE keep SET log_min_duration_sample = -1;
//	ALTER DATABASE keep SET log_transaction_sample_rate = 0;
//	ALTER DATABASE keep SET log_min_messages = 'panic';   -- or 'fatal'
var RequiredLogSettings = map[string]string{
	"log_error_verbosity":         "terse",
	"log_min_error_statement":     "panic",
	"log_min_duration_statement":  "-1",
	"log_min_duration_sample":     "-1",
	"log_transaction_sample_rate": "0",
}

// autoExplainLogMinDurationSetting is checked separately from
// [RequiredLogSettings]: unlike every setting above, auto_explain (a
// standard, commonly preloaded extension for diagnosing slow queries) is
// optional, so "not loaded" — current_setting's missing_ok argument
// returns NULL — is itself a passing value here, alongside the disabled
// value it takes when loaded (-1, also its own default). Any other value
// is a mismatch.
//
// auto_explain writes a statement's execution plan to the server log once
// its own log_min_duration threshold is crossed, independent of every
// statement-logging [RequiredLogSettings] value above (log_statement,
// log_min_duration_statement, ...): it hooks the planner/executor
// directly, not PostgreSQL's own statement-logging path. The plan
// includes each bound parameter's value, inlined as a literal by the
// planner itself before auto_explain ever prints it —
// auto_explain.log_parameter_max_length does not close this: measured
// directly (ALTER DATABASE keep SET auto_explain.log_parameter_max_length
// = 0 together with log_min_duration = 0), a canary value still reached
// the server log in the plan's own Filter line; log_parameter_max_length
// only truncates the separate "Query Parameters:" line auto_explain also
// prints.
//
// auto_explain's own log_level GUC (unchecked here) still gates this
// through PostgreSQL's ordinary message-severity filter, so
// log_min_messages at 'fatal'/'panic' — which [RequiredLogSettings]
// already requires — is the first barrier that already suppresses it
// (measured: a canary reached the log at log_min_messages='warning', not
// at 'fatal'). This check is the second barrier: it holds even if
// log_min_messages is ever loosened without this one being noticed, and
// disabling auto_explain.log_min_duration outright is the only setting
// that closes the gap on its own.
//
//	ALTER DATABASE keep SET auto_explain.log_min_duration = -1;
const autoExplainLogMinDurationSetting = "auto_explain.log_min_duration"

// logStatementSetting is the one setting [CheckLogSettings] checks against
// [AllowedLogStatement] instead of a single required value in
// [RequiredLogSettings].
const logStatementSetting = "log_statement"

// AllowedLogStatement lists the log_statement values Keep accepts. mod and
// all log every statement's bound parameter values; ddl logs only
// schema-changing statement text, which never carries a secret's value.
var AllowedLogStatement = []string{"none", "ddl"}

// logMinMessagesSetting is the other setting [CheckLogSettings] checks
// against a small set of allowed values instead of a single required
// value — see [AllowedLogMinMessages] and the debug_print_* paragraph on
// [RequiredLogSettings] for why a value set, not one exact value, is
// required here.
const logMinMessagesSetting = "log_min_messages"

// AllowedLogMinMessages lists the log_min_messages values Keep accepts.
// log_min_messages is superuser-only (context=superuser, unlike
// debug_print_*) and gates every message below its threshold: raised to
// fatal, PostgreSQL writes nothing to the server log below FATAL
// severity, so LOG-severity output — debug_print_*'s included — never
// reaches it no matter which session turns debug_print_* on. panic goes
// one step further and also silences FATAL; either is accepted.
var AllowedLogMinMessages = []string{"fatal", "panic"}

// LogSettingsError lists the settings that differ from [RequiredLogSettings],
// [AllowedLogStatement] or [AllowedLogMinMessages]. Its text holds only
// setting names and PostgreSQL's own setting values.
type LogSettingsError struct {
	// Mismatches maps a setting name to the value the database reported.
	Mismatches map[string]string
}

func (e *LogSettingsError) Error() string {
	parts := make([]string, 0, len(e.Mismatches))
	for _, name := range slices.Sorted(maps.Keys(e.Mismatches)) {
		parts = append(parts, fmt.Sprintf("%s=%s (want %s)", name, e.Mismatches[name], wantText(name)))
	}
	return "postgres server log would echo rejected rows: " + strings.Join(parts, ", ")
}

// wantText names the value or values [CheckLogSettings] requires for name,
// for use only in [LogSettingsError.Error] — never a value read from the
// database.
func wantText(name string) string {
	switch name {
	case logStatementSetting:
		return strings.Join(AllowedLogStatement, " or ")
	case logMinMessagesSetting:
		return strings.Join(AllowedLogMinMessages, " or ")
	case autoExplainLogMinDurationSetting:
		return "-1 or unset (auto_explain not loaded)"
	default:
		return RequiredLogSettings[name]
	}
}

// CheckLogSettings reads the settings in [RequiredLogSettings],
// [logStatementSetting] and [logMinMessagesSetting] as a new session of
// pool sees them and returns a *LogSettingsError if any differ from what's
// required or allowed. The server calls this at startup and refuses to
// serve if it fails.
func CheckLogSettings(ctx context.Context, pool *pgxpool.Pool) error {
	mismatches := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(RequiredLogSettings)) {
		got, err := readLogSetting(ctx, pool, name)
		if err != nil {
			return err
		}
		if got != RequiredLogSettings[name] {
			mismatches[name] = got
		}
	}
	got, err := readLogSetting(ctx, pool, logStatementSetting)
	if err != nil {
		return err
	}
	if !slices.Contains(AllowedLogStatement, got) {
		mismatches[logStatementSetting] = got
	}
	got, err = readLogSetting(ctx, pool, logMinMessagesSetting)
	if err != nil {
		return err
	}
	if !slices.Contains(AllowedLogMinMessages, got) {
		mismatches[logMinMessagesSetting] = got
	}
	aeGot, aeLoaded, err := readNullableLogSetting(ctx, pool, autoExplainLogMinDurationSetting)
	if err != nil {
		return err
	}
	if aeLoaded && aeGot != "-1" {
		mismatches[autoExplainLogMinDurationSetting] = aeGot
	}
	if len(mismatches) > 0 {
		return &LogSettingsError{Mismatches: mismatches}
	}
	return nil
}

// readLogSetting reads name as the current session of pool sees it.
func readLogSetting(ctx context.Context, pool *pgxpool.Pool, name string) (string, error) {
	var got string
	if err := pool.QueryRow(ctx, "SELECT current_setting($1)", name).Scan(&got); err != nil {
		// pgx's text for a failed (re)connect names the host, user
		// and database; report only the SQLSTATE.
		return "", fmt.Errorf("read setting %s failed (%s)", name, sqlStateOf(err))
	}
	return got, nil
}

// readNullableLogSetting reads name as the current session of pool sees
// it, using current_setting's own missing_ok argument: a name unknown to
// this backend (an optional extension's GUC, not loaded) comes back NULL
// instead of erroring, reported here as ok=false rather than a value.
func readNullableLogSetting(ctx context.Context, pool *pgxpool.Pool, name string) (value string, ok bool, err error) {
	var got *string
	if err := pool.QueryRow(ctx, "SELECT current_setting($1, true)", name).Scan(&got); err != nil {
		return "", false, fmt.Errorf("read setting %s failed (%s)", name, sqlStateOf(err))
	}
	if got == nil {
		return "", false, nil
	}
	return *got, true, nil
}

// SuperuserError is returned when the role Keep connects as — or a role
// reachable from it, see [CheckNotSuperuser] — has PostgreSQL superuser
// rights, or the equivalent of them. Its text names no role.
type SuperuserError struct{}

func (e *SuperuserError) Error() string {
	return "postgres role has superuser rights and could reset every setting CheckLogSettings just verified"
}

// AdminEquivalentRoleError is returned when the role Keep connects as — or
// a role reachable from it, see [CheckNotSuperuser] — is a member of
// pg_execute_server_program or pg_write_server_files, holds EXECUTE on
// lo_export or either lo_import overload, or holds USAGE on any foreign
// server, without holding PostgreSQL superuser rights itself. Its text
// names no role.
type AdminEquivalentRoleError struct{}

func (e *AdminEquivalentRoleError) Error() string {
	return "postgres role can reach an admin-equivalent connection outside CheckLogSettings' reach — running a server-side program, reading or writing a file as the server's own OS user, or using a foreign server's user mapping — without holding superuser rights itself"
}

// ParameterPrivilegeError is returned when the role Keep connects as — or a
// role reachable from it — has been granted the right to change one of the
// settings [CheckLogSettings] verifies. Its text names the setting, never
// the role.
type ParameterPrivilegeError struct {
	// Setting is the configuration parameter name the role may change.
	Setting string
}

func (e *ParameterPrivilegeError) Error() string {
	return fmt.Sprintf("postgres role has been granted the right to change %s and could reset it after CheckLogSettings just verified it", e.Setting)
}

// reachableRolesCTE names every role session_user can eventually exercise
// the privileges of — not just the roles usable right now via SET ROLE
// (which needs the SET option) or automatic inheritance (which needs
// INHERIT), but every role reachable through any chain of membership at
// all, following plain rows of pg_auth_members regardless of their
// set_option, inherit_option or admin_option. That is deliberately wider
// than "SET ROLE works today": a membership granted WITH ADMIN TRUE,
// INHERIT FALSE, SET FALSE looks, from SET ROLE's perspective, like no
// access at all — but ADMIN OPTION lets session_user re-run that same
// GRANT itself, adding WITH SET TRUE, and then SET ROLE straight through.
// So every role reachable by *some* grant — direct or via a role it can in
// turn re-grant itself into — is a role whose privileges session_user can
// end up exercising, one extra GRANT away at worst. It is a superset of
// what a snapshot of today's SET ROLE targets would find, and this check's
// job is exactly to have no gap, not to describe the tightest possible
// session.
const reachableRolesCTE = `WITH RECURSIVE reachable(rid) AS (
	SELECT oid FROM pg_roles WHERE rolname = session_user
	UNION
	SELECT m.roleid FROM pg_auth_members m JOIN reachable r ON m.member = r.rid
)
`

// CheckNotSuperuser refuses a role that can undo what [CheckLogSettings]
// just verified from inside its own session — checked not just for
// session_user itself but for every role in [reachableRolesCTE] — three
// ways:
//
//   - PostgreSQL superuser rights, on session_user or a reachable role.
//     Checked against session_user, not current_user: a superuser can
//     connect with a "role" parameter in the DSN, or run SET ROLE
//     directly, to make current_user report a different, unprivileged
//     role for the rest of the session — but session_user stays fixed for
//     the life of the connection, and RESET ROLE (or SET ROLE back to
//     session_user) always restores the superuser's own privileges.
//
//   - Membership in pg_execute_server_program or pg_write_server_files,
//     PostgreSQL's built-in roles for running an arbitrary program, or
//     writing an arbitrary file, as the OS user the server process itself
//     runs as. Either lets that role open its own admin connection to
//     Postgres entirely outside SQL (a plain psql, run as the server's own
//     OS user) and reset every setting CheckLogSettings verified from
//     there — the same effect as holding superuser rights, without
//     rolsuper ever being set on any reachable role. Returned as
//     [AdminEquivalentRoleError], not [SuperuserError], so an operator
//     reading the error knows whether to strip SUPERUSER or revoke a
//     built-in role membership.
//
//     pg_read_server_files is deliberately not checked here: it can read
//     any file the server's OS user can, including postgresql.auto.conf,
//     pg_hba.conf and the server log itself — a real information
//     disclosure risk, but not a way to reset a setting CheckLogSettings
//     verified, which is this check's own job, not [CheckLogSettings]'.
//
//   - EXECUTE on lo_export or either lo_import overload, granted directly
//     to session_user or a reachable role rather than reached through the
//     two built-in roles above. PostgreSQL revokes EXECUTE on all three
//     from PUBLIC by default, but that default is an ACL like any other:
//     an operator, or any role holding GRANT privilege on the function,
//     can hand it to an application role with a plain GRANT EXECUTE,
//     bypassing pg_execute_server_program/pg_write_server_files
//     membership entirely while reaching the identical OS-level admin
//     connection — lo_export writes an arbitrary file as the server's own
//     OS user just as directly as pg_write_server_files does, only
//     through a different grant. Also [AdminEquivalentRoleError].
//
//   - USAGE on any foreign server (postgres_fdw, dblink_fdw, or any other
//     foreign-data wrapper) held by session_user or a reachable role. A
//     foreign table, or dblink_exec, over that server runs as whichever
//     role its user mapping names — a role this check has no way to
//     inspect, since it may live on a different server entirely — up to
//     and including a mapping that names this database's own superuser,
//     from which resetting every setting CheckLogSettings verified is a
//     plain ALTER DATABASE ... SET away. Keep's own role has no
//     legitimate need for a foreign server, so any USAGE grant at all is
//     refused here rather than attempting to classify a user mapping as
//     safe or not. Also [AdminEquivalentRoleError].
//
//   - GRANT SET ON PARAMETER or GRANT ALTER SYSTEM ON PARAMETER (both
//     PostgreSQL 15+), against every setting in [RequiredLogSettings] plus
//     [logStatementSetting] and [logMinMessagesSetting], on session_user or
//     a reachable role. A role can be granted the right to change an
//     individual GUC without ever
//     holding superuser rights at all — same effect as a superuser session
//     running a plain SET or ALTER SYSTEM, and not a superuser check's job
//     to catch. ALTER SYSTEM only matters for an operator who sets these
//     in postgresql.conf instead of ALTER DATABASE, and only after the
//     next reload — but the grant works the same way SET does, so it gets
//     the same check.
//
// A superuser is also exempt from every GRANT/REVOKE in Keep's schema.
// Migrations and test/admin tooling (e.g. internal/testutil/pgscratch,
// which needs CREATEDB and ALTER DATABASE) keep superuser; only the role
// keep-server itself connects as — and every role reachable from it — must
// not be superuser, hold the two built-in roles above, or hold SET/ALTER
// SYSTEM on any of these parameters. The server calls this at startup,
// alongside [CheckLogSettings], and refuses to serve if it fails.
func CheckNotSuperuser(ctx context.Context, pool *pgxpool.Pool) error {
	var rolsuper bool
	if err := pool.QueryRow(ctx,
		reachableRolesCTE+"SELECT bool_or(r.rolsuper) FROM pg_roles r JOIN reachable ON r.oid = reachable.rid",
	).Scan(&rolsuper); err != nil {
		return fmt.Errorf("read role privileges failed (%s)", sqlStateOf(err))
	}
	if rolsuper {
		return &SuperuserError{}
	}

	for _, builtin := range []string{"pg_execute_server_program", "pg_write_server_files"} {
		var member bool
		if err := pool.QueryRow(ctx,
			reachableRolesCTE+"SELECT bool_or(r.rolname = $1) FROM pg_roles r JOIN reachable ON r.oid = reachable.rid",
			builtin,
		).Scan(&member); err != nil {
			return fmt.Errorf("read role privileges failed (%s)", sqlStateOf(err))
		}
		if member {
			return &AdminEquivalentRoleError{}
		}
	}

	for _, fn := range []string{"lo_export(oid,text)", "lo_import(text)", "lo_import(text,oid)"} {
		var canExec bool
		if err := pool.QueryRow(ctx,
			reachableRolesCTE+`SELECT bool_or(has_function_privilege(r.oid, $1, 'EXECUTE'))
			FROM pg_roles r JOIN reachable ON r.oid = reachable.rid`,
			fn,
		).Scan(&canExec); err != nil {
			return fmt.Errorf("read function privilege for %s failed (%s)", fn, sqlStateOf(err))
		}
		if canExec {
			return &AdminEquivalentRoleError{}
		}
	}

	var canUseForeignServer bool
	if err := pool.QueryRow(ctx,
		reachableRolesCTE+`SELECT coalesce(bool_or(has_server_privilege(r.oid, fs.oid, 'USAGE')), false)
		FROM pg_roles r JOIN reachable ON r.oid = reachable.rid, pg_foreign_server fs`,
	).Scan(&canUseForeignServer); err != nil {
		return fmt.Errorf("read foreign server privilege failed (%s)", sqlStateOf(err))
	}
	if canUseForeignServer {
		return &AdminEquivalentRoleError{}
	}

	names := make([]string, 0, len(RequiredLogSettings)+2)
	names = append(names, logStatementSetting, logMinMessagesSetting)
	for name := range RequiredLogSettings {
		names = append(names, name)
	}
	// names must end up holding every setting CheckLogSettings checks —
	// logStatementSetting and logMinMessagesSetting appended above by name,
	// plus every RequiredLogSettings key by this loop — or a setting this
	// check silently stops covering could be reset by GRANT SET ON
	// PARAMETER without CheckLogSettings ever failing to catch it at the
	// next restart.
	for _, name := range slices.Sorted(slices.Values(names)) {
		var canSet bool
		if err := pool.QueryRow(ctx,
			reachableRolesCTE+`SELECT bool_or(has_parameter_privilege(r.oid, $1, 'SET') OR has_parameter_privilege(r.oid, $1, 'ALTER SYSTEM'))
			FROM pg_roles r JOIN reachable ON r.oid = reachable.rid`,
			name,
		).Scan(&canSet); err != nil {
			return fmt.Errorf("read parameter privilege for %s failed (%s)", name, sqlStateOf(err))
		}
		if canSet {
			return &ParameterPrivilegeError{Setting: name}
		}
	}
	return nil
}
