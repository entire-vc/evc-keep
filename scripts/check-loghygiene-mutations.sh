#!/bin/sh
# Proves the PostgreSQL log-hygiene guard can fail: in a scratch copy of the
# tree, switch off one part at a time — store.CheckLogSettings,
# store.CheckNotSuperuser, store.checkQueryExecMode, or keep-server's use of
# any of the three — and require the named tests to go red. Exits 0 only if
# every mutation is caught and the real code is green.
#
# Needs KEEP_DATABASE_URL pointing at a server where its role may CREATE
# DATABASE and ALTER DATABASE ... SET superuser-level settings; without it
# the tests would skip, which this script must never report as red.
set -eu

if [ "${MUTATION_APPLY_ONLY:-}" != 1 ] && [ -z "${KEEP_DATABASE_URL:-}" ]; then
	echo "FAIL check-loghygiene-mutations: KEEP_DATABASE_URL is not set — the tests would skip, not fail"
	exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
mutation_shard_init

# Private per-run build cache: on a shared host running several
# clones' go test/build concurrently, a shared $GOCACHE can serve one
# process a build-cache entry another process is evicting mid-write,
# producing a spurious build failure unrelated to any code change
# (seen as "could not import internal/chacha8rand ... no such file").
# Scoping the cache to each run removes the sharing, not just the
# symptom. Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
pkgs="./internal/store/ ./cmd/keep-server/app/"
run='TestCheckLogSettings|TestReadNullableLogSetting|TestServeRefusesVerbosePostgresLog|TestCheckNotSuperuser|TestServeRefusesSuperuserRole|TestOpenRefusesUnsafeQueryExecMode|TestServeRefusesUnsafeQueryExecMode|TestOpenMigrationDBRefusesUnsafeQueryExecMode|TestDatabase(Deadline|QueryDeadline)|TestCheckReservedRefs|TestServeRefusesReservedRef'

fail=0
# Some mutants here break connecting on purpose (exec-mode-unchecked), so a
# refused connection cannot be told from an outage by its text. Every shard
# therefore proves the database first.
mutation_connect_faults_are_mutants=1
mutation_db_witness -run '^TestCheckNotSuperuser$' ./internal/store/
# Shards jointly form one suite. Run the full baseline once, on shard 1,
# so splitting the inventory does not multiply expensive unmutated attacks.
if [ "$mutation_index" -eq 1 ] && ! mutation_apply_only; then
# The deadline guards below mutate pgscratch itself, so its tests need their
# own green baseline; dependency tests do not run with the store test suite.
if (cd "$root" && go test -timeout 600s -count=1 -p 1 -v ./internal/testutil/pgscratch/ >"$work/out" 2>&1) && ! grep -q -- '--- SKIP' "$work/out"; then
	echo "ok   database harness baseline: tests green on the real code"
else
	echo "FAIL database harness baseline: tests are red or skipped on the real code"
	# Result lines plus the tests' own fixed messages (they never carry a DSN),
	# so a timing failure on a loaded runner names what failed.
	grep -E -- '^(--- |FAIL|ok )|^ +[a-z_]+\.go:[0-9]+: ' "$work/out" || true
	exit 1
fi
# shellcheck disable=SC2086
if (cd "$root" && go test -timeout 600s -count=1 -p 1 -v -run "$run" $pkgs >"$work/out" 2>&1) && ! grep -q -- '--- SKIP' "$work/out"; then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red or skipped on the real code"
	# Only the result lines: a full dump could carry connection details.
	grep -E -- '^(--- |FAIL|ok )' "$work/out" || true
	fail=1
fi

# The selection guard of check-no-silent-skip.sh can fail: a regex that
# matches no test must not read as a pass.
if (cd "$root" && KEEP_TEST_RUN='^NoSuchTestAnywhere$' ./scripts/check-no-silent-skip.sh ./internal/testutil/pgscratch/ >"$work/out" 2>&1); then
	echo "FAIL selection guard: an empty test selection passed"
	fail=1
else
	echo "ok   selection guard: an empty test selection fails"
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
fi

# mutate NAME FILE FROM TO [AFTER]: replace the first literal occurrence of
# FROM with TO; with AFTER, the first one on a line after a line holding AFTER.
mutate() {
	mutation_selected || return 0
	name=$1 src=$2 from=$3 to=$4 after=${5:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" -v after="$after" '
		BEGIN { armed = (after == "") }
		armed && !done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		!armed && index($0, after) { armed = 1 }
		{ print }
		END { exit !done }' "$root/$src" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	# Run the family that owns the mutated guard. The full baseline above
	# still exercises every family, once; each mutant avoids repeating the
	# unrelated database/role inventory and competing package binaries.
	mutant_pkgs=$pkgs
	mutant_run=$run
	case "$src" in
		internal/store/loghygiene.go)
			mutant_pkgs="./internal/store/"
			case "$name" in
				no-*|verbose-accepted|statement-logged|mismatch-ignored|log-statement-*|log-min-messages-unchecked|log-min-messages-allows-*|log-min-messages-wanttext-*) mutant_run='^TestCheckLogSettings$' ;;
				ae-mismatch-ignored) mutant_run='^TestCheckLogSettings_AutoExplain$' ;;
				ae-missing-ok-dropped|ae-nil-check-forced) mutant_run='^Test(CheckLogSettings_AutoExplain|ReadNullableLogSetting_UnknownSettingIsNotAnError)$' ;;
				*) mutant_run='^TestCheckNotSuperuser$' ;;
			esac ;;
		internal/store/store.go)
			mutant_pkgs="./internal/store/"
			case "$name" in
				exec-mode-unchecked) mutant_run='^TestOpen(MigrationDB)?RefusesUnsafeQueryExecMode$' ;;
				*) mutant_run='^TestDatabase(Deadline|QueryDeadline)' ;;
			esac ;;
		internal/store/reservedref.go)
			mutant_pkgs="./internal/store/"
			mutant_run='^TestCheckReservedRefs(QueryFailure)?$' ;;
		cmd/keep-server/app/main.go)
			mutant_pkgs="./cmd/keep-server/app/"
			case "$name" in
				reserved-*) mutant_run='^TestServeRefusesReservedRef$' ;;
				server-unchecked|refusal-exits-zero) mutant_run='^TestServeRefusesVerbosePostgresLog$' ;;
				*) mutant_run='^TestServeRefusesSuperuserRole$' ;;
			esac ;;
	esac
	# shellcheck disable=SC2086 # fixed package paths
	if (cd "$work/tree" && go test -timeout 600s -count=1 -p 1 -v -run "$mutant_run" $mutant_pkgs >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		# Only test names and result lines; never dump connection errors.
		grep -E -- '^(=== RUN|--- FAIL|[[:space:]]+--- FAIL|FAIL[[:space:]])' "$work/out" || true
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

hyg=internal/store/loghygiene.go
str=internal/store/store.go
main=cmd/keep-server/app/main.go
# each required setting is actually required
mutate no-verbosity      $hyg '"log_error_verbosity":         "terse",' ''
mutate no-statement      $hyg '"log_min_error_statement":     "panic",' ''
mutate verbose-accepted  $hyg '"log_error_verbosity":         "terse",' '"log_error_verbosity":         "default",'
mutate statement-logged  $hyg '"log_min_error_statement":     "panic",' '"log_min_error_statement":     "error",'
# a mismatch is reported, not ignored
mutate mismatch-ignored  $hyg 'if got != RequiredLogSettings[name] {' 'if false {'
# keep-server calls the check before it listens
mutate server-unchecked  $main 'if err := store.CheckLogSettings(ctx, pool); err != nil {' 'if err := error(nil); err != nil {'
# the refusal is a failure exit, so a supervisor sees it
mutate refusal-exits-zero $main 'return 1' 'return 0' 'store.CheckLogSettings(ctx, pool)'

# point 2: duration/sample settings that bypass log_error_verbosity/
# log_min_error_statement entirely are each actually required
mutate no-duration-statement-required $hyg '"log_min_duration_statement":  "-1",' ''
mutate no-duration-sample-required    $hyg '"log_min_duration_sample":     "-1",' ''
mutate no-txn-sample-required         $hyg '"log_transaction_sample_rate": "0",' ''
# log_statement is checked against AllowedLogStatement, not ignored
mutate log-statement-unchecked $hyg 'if !slices.Contains(AllowedLogStatement, got) {' 'if false {'
# fourth review round: debug_print_plan and its siblings bypass every
# setting above (they're user-context, not superuser-context), so
# log_min_messages raised high enough is the setting that actually
# suppresses them — checked against AllowedLogMinMessages, not ignored
mutate log-min-messages-unchecked $hyg 'if !slices.Contains(AllowedLogMinMessages, got) {' 'if false {'
# fifth review round: AllowedLogMinMessages must actually be narrow — error
# is the value closest to accepted (is_log_level_output still emits LOG
# severity, debug_print_*'s included, at every threshold up to and
# including error) and widening the allowed set to admit it must be caught
mutate log-min-messages-allows-error $hyg '"fatal", "panic"' '"fatal", "panic", "error"'
# sixth review round: log leaks exactly like error (is_log_level_output
# prints LOG severity, debug_print_*'s included, at any threshold up to and
# including log) and stayed uncaught by the mutant above alone, since only
# error was ever added as an explicit bad-value case — caught now by the
# enumvals-driven test iterating PostgreSQL's own enum instead
mutate log-min-messages-allows-log $hyg '"fatal", "panic"' '"fatal", "panic", "log"'
# fifth review round: LogSettingsError.Error() must actually name the
# allowed log_min_messages values, not fall through to the empty
# RequiredLogSettings[name] default
mutate log-min-messages-wanttext-unchecked $hyg 'case logMinMessagesSetting:' 'case "__disabled__":'

# auto_explain (hooks the planner/executor, independent of every
# RequiredLogSettings/log_statement/log_min_messages check above): an
# enabled log_min_duration is refused, not silently accepted
mutate ae-mismatch-ignored $hyg 'aeGot != "-1"' 'false'
# readNullableLogSetting must actually use current_setting's missing_ok
# argument — without it, an unloaded extension's GUC name raises an error
# instead of reading as "not loaded", which TestReadNullableLogSetting_
# UnknownSettingIsNotAnError pins directly
mutate ae-missing-ok-dropped $hyg 'SELECT current_setting($1, true)' 'SELECT current_setting($1)'
# the nil check itself, not just the aeLoaded wiring above it, must
# actually gate ok — forcing it to always report "not loaded" is a second,
# independent way to make the guard never fire
mutate ae-nil-check-forced $hyg 'if got == nil {' 'if true {'

# point 1: default_query_exec_mode=simple_protocol/exec is refused before
# Open (and OpenMigrationDB, which shares checkQueryExecMode) ever dials
mutate exec-mode-unchecked $str 'case pgx.QueryExecModeSimpleProtocol, pgx.QueryExecModeExec:' 'case pgx.QueryExecMode(-1):'
mutate query-deadline-unclassified $str 'return "database operation deadline exceeded"' 'return "unclassified"'
mutate query-deadline-leaks-details $str 'return "database operation deadline exceeded"' 'return err.Error()'

# reserved service-token ref: a secrets row under it is counted, a query
# failure is a refusal, and keep-server calls the check before it listens
# and exits non-zero on it
rsv=internal/store/reservedref.go
mutate reserved-count-nothing   $rsv 'WHERE starts_with(provider_ref, $1)' 'WHERE false AND starts_with(provider_ref, $1)'
mutate reserved-count-loose     $rsv 'WHERE starts_with(provider_ref, $1)' "WHERE position(\$1::text in provider_ref) > 0"
mutate reserved-query-fails-open $rsv 'return 0, apperr.New(apperr.ClassInternal, "reserved provider reference check failed")' 'return 0, nil'
mutate reserved-count-ignored   $rsv 'if n > 0 {' 'if false {'
mutate reserved-unchecked       $main 'if n, err := store.CheckReservedRefs(ctx, pool, keepprovider.ReservedRefPrefix); err != nil {' 'if n, err := len(keepprovider.ReservedRefPrefix)*0, error(nil); err != nil {'
mutate reserved-refusal-exits-zero $main 'return 1' 'return 0' 'store.CheckReservedRefs(ctx, pool, keepprovider.ReservedRefPrefix)'

# point 3: a superuser role is refused, and keep-server actually calls the
# check before it listens
mutate superuser-accepted        $hyg 'if rolsuper {' 'if false {'
mutate superuser-check-unchecked $main 'if err := store.CheckNotSuperuser(ctx, pool); err != nil {' 'if err := error(nil); err != nil {'

# point 3, review round: the rolsuper check reads session_user, not
# current_user — a superuser connecting with a "role" DSN parameter (or
# SET ROLE) narrows current_user but leaves session_user, and RESET ROLE,
# untouched; a check against current_user alone would pass it through
mutate session-user-bypass $hyg \
	'SELECT oid FROM pg_roles WHERE rolname = session_user' \
	'SELECT oid FROM pg_roles WHERE rolname = current_user'
# point 3, review round: a role granted SET on one of the required GUCs
# (PostgreSQL 15+ GRANT SET ON PARAMETER) is refused even without rolsuper
mutate parameter-privilege-unchecked $hyg 'if canSet {' 'if false {'
# fifth review round: logMinMessagesSetting must actually be one of the
# names the parameter-privilege loop checks, not silently dropped from the
# two constants appended directly
mutate log-min-messages-privilege-unchecked $hyg \
	'names = append(names, logStatementSetting, logMinMessagesSetting)' \
	'names = append(names, logStatementSetting)'
# fifth review round: the loop that adds every RequiredLogSettings key to
# the parameter-privilege check must actually run — removing it silently
# drops log_error_verbosity, log_min_error_statement and the three
# duration/sample settings from that check while leaving log_statement and
# log_min_messages covered
mutate required-settings-privilege-loop-removed $hyg \
	'for name := range RequiredLogSettings {' \
	'for name := range map[string]string{} {'
# point 3, third review round: reachableRolesCTE walks every row of
# pg_auth_members transitively from session_user, not just roles usable
# right now via SET ROLE or INHERIT — without the recursive branch, a role
# reached only through membership (SET-option, NOINHERIT, or ADMIN-only)
# is invisible to both the rolsuper and the parameter-privilege check
mutate reachable-roles-recursion-removed $hyg \
	'SELECT m.roleid FROM pg_auth_members m JOIN reachable r ON m.member = r.rid' \
	'SELECT m.roleid FROM pg_auth_members m JOIN reachable r ON m.member = r.rid WHERE false'
# fourth review round: the recursive term must actually chain past one
# hop — restricting it to combine only with session_user's own base row
# still finds every direct member, but never a member of a member, which
# every mutant and test above this round used only one-hop chains to
# catch. Caught only by a chain two hops deep (superuser_reachable_
# through_two-hop_role_chain_refused).
mutate reachable-roles-one-hop-only $hyg \
	'SELECT m.roleid FROM pg_auth_members m JOIN reachable r ON m.member = r.rid' \
	'SELECT m.roleid FROM pg_auth_members m JOIN reachable r ON m.member = r.rid AND r.rid = (SELECT oid FROM pg_roles WHERE rolname = session_user)'
# point 3, third review round: pg_execute_server_program/pg_write_server_files
# let a reachable role run an OS program (or write a file) as the server's
# own process user — an admin connection outside SQL entirely, without
# rolsuper ever being set on any role in reach
mutate os-program-check-unchecked $hyg 'if member {' 'if false {'
# fourth review round: both built-in roles are checked, not just the
# first one in the list — dropping only pg_write_server_files stayed
# green until a test exercised it on its own
mutate write-server-files-unchecked $hyg \
	'[]string{"pg_execute_server_program", "pg_write_server_files"}' \
	'[]string{"pg_execute_server_program"}'
# lo_export/lo_import EXECUTE, granted directly rather than through the
# two built-in roles above, is refused; and dropping the lo_import(text,oid)
# overload from the checked list alone is caught
mutate lo-export-lo-import-unchecked $hyg 'if canExec {' 'if false {'
mutate lo-import-oid-overload-dropped $hyg \
	'[]string{"lo_export(oid,text)", "lo_import(text)", "lo_import(text,oid)"}' \
	'[]string{"lo_export(oid,text)", "lo_import(text)"}'
# same round: USAGE on any foreign server is refused outright
mutate foreign-server-usage-unchecked $hyg 'if canUseForeignServer {' 'if false {'
# point 3, third review round: ALTER SYSTEM ON PARAMETER (PostgreSQL 15+)
# is a separate grant from SET ON PARAMETER — checking only SET would miss
# a role that can rewrite postgresql.conf directly
mutate alter-system-privilege-unchecked $hyg \
	"has_parameter_privilege(r.oid, \$1, 'SET') OR has_parameter_privilege(r.oid, \$1, 'ALTER SYSTEM')" \
	"has_parameter_privilege(r.oid, \$1, 'SET')"


# The harness must bound database waits too. These are infrastructure guards,
# tested in isolation so each negative control has an unambiguous assertion.
pkgs="./internal/testutil/pgscratch/"
run='^TestContextBoundsDatabaseWait$'
mutate database-deadline internal/testutil/pgscratch/pgscratch.go '10*time.Second' '30*time.Second'
run='^TestDSNCapsConnectionTimeout$'
mutate connection-deadline internal/testutil/pgscratch/pgscratch.go 'q.Set("connect_timeout", "5")' 'q.Set("connect_timeout", "120")'

run='^TestNewDropsDatabase$'
mutate database-cleanup internal/testutil/pgscratch/pgscratch.go '"DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)"' '"SELECT 1"'
# A failed cleanup must be reported, not swallowed: each DROP in the scratch
# helpers is switched to ignore its error, one at a time.
run='^TestCleanupReportsFailedDrop$'
mutate cleanup-drop-database-ignored internal/testutil/pgscratch/pgscratch.go 't.Errorf("drop scratch database failed (%s)", sqlState(err))' '_ = err'
mutate cleanup-drop-owned-ignored    internal/testutil/pgscratch/pgscratch.go 't.Errorf("drop owned by scratch role failed (%s)", sqlState(err))' '_ = err'
mutate cleanup-drop-role-ignored     internal/testutil/pgscratch/pgscratch.go 't.Errorf("drop scratch role failed (%s)", sqlState(err))' '_ = err'
run='^TestNewRoleCleanupDropsRole$'
mutate cleanup-role-never-dropped    internal/testutil/pgscratch/pgscratch.go '		dropRole(t, Context(t), admin, ident)' '		_ = admin'
mutate cleanup-owned-never-dropped   internal/testutil/pgscratch/pgscratch.go '			dropOwned(t, Context(t), dbCleanup, ident)' '			_ = dbCleanup'
run='^TestDatabaseContextBoundsFileOperations$'
mutate database-file-deadline internal/testutil/pgscratch/pgscratch.go '30*time.Second' '120*time.Second'

mutation_shard_finish
exit $fail
