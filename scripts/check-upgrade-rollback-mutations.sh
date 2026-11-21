#!/usr/bin/env bash
# Red runs for scripts/check-upgrade-rollback.sh: each mutant breaks one thing
# in a copy (of the document or of the script) and the check must fail, with
# the designated message. The unmutated check must pass first, so a red is
# never an artefact of the environment. Needs the same environment as the
# check (KEEP_ADMIN_URL and its tools). A red run is reported by the fixed
# messages of scripts/upgrade-rollback-report.sh, never by the raw output.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh" # apply-only mode (MUTATION_APPLY_ONLY=1) on merge requests
temp_workspace
fail=0

run() { # label doc script -> output in $work/out, status returned
	KEEP_DEPLOY_DOC=$2 KEEP_UPGRADE_ROOT=$root bash "$3" >"$work/out" 2>&1
}

# A mutant that prints a value puts this mark on the same line. The check prints
# its job output only after scanning it, so a red run must not carry the mark:
# with the mark in the output the value reached the CI log before the detector
# turned the job red.
mark=UPGLEAKMARK

# REDRUN_ONLY=name[,name] runs only those mutants (and skips the baseline), for development.
only=${REDRUN_ONLY:-} # one mutant name or a comma list
if [ -n "$only" ] || mutation_apply_only; then
	:
elif run baseline "$root/docs/deploy.md" "$root/scripts/check-upgrade-rollback.sh"; then
	echo "ok   baseline: the unmutated check passes"
else
	"$root/scripts/upgrade-rollback-report.sh" "$work/out" || true; echo "FAIL baseline: the unmutated check is red"; exit 1
fi

# drop_line NAME PATTERN MESSAGE: the document copy without the lines matching PATTERN.
drop_line() {
	local name=$1 pat=$2 msg=$3 line
	if ! grep -q -E -- "$pat" docs/deploy.md; then echo "FAIL $name: pattern not in the document, update this script"; fail=1; return; fi
	line=$(grep -E -- "$pat" docs/deploy.md)
	if ! mutation_edit docs/deploy.md "$line" '' >"$work/doc.md"; then fail=1; return; fi
	expect_red "$name" "$work/doc.md" "$root/scripts/check-upgrade-rollback.sh" "$msg"
}
# sub_doc NAME FROM TO MESSAGE: the document copy with FROM replaced by TO.
sub_doc() {
	mutation_take_occurrences
	local name=$1 from=$2 to=$3 msg=$4
	if ! mutation_edit docs/deploy.md "$from" "$to" "${mutation_occurrence:-}" >"$work/doc.md"; then fail=1; return; fi
	expect_red "$name" "$work/doc.md" "$root/scripts/check-upgrade-rollback.sh" "$msg"
}
# edit_script NAME FROM TO MESSAGE: the script copy with FROM replaced by TO.
edit_script() {
	mutation_take_occurrences
	local name=$1 from=$2 to=$3 msg=$4
	if ! mutation_edit scripts/check-upgrade-rollback.sh "$from" "$to" "${mutation_occurrence:-}" >"$work/check.sh"; then fail=1; return; fi
	expect_red "$name" "$root/docs/deploy.md" "$work/check.sh" "$msg"
}
expect_red() {
	local name=$1 doc=$2 script=$3 msg=$4
	case ",$only," in ,,|*",$name,"*) ;; *) return ;; esac
	mutation_applied "$name" && return
	if run "$name" "$doc" "$script"; then
		echo "FAIL $name: the check stayed green"; fail=1
	elif grep -a -q -F -- "$mark" "$work/out"; then
		echo "FAIL $name: red, but the printed value reached the output before the scan (line(s) $(grep -a -n -F -- "$mark" "$work/out" | cut -d: -f1 | tr '\n' ' '))"; fail=1
	elif grep -q -F -- "$msg" "$work/out"; then
		echo "ok   $name: red with '$msg'"
	else
		"$root/scripts/upgrade-rollback-report.sh" "$work/out" || true; echo "FAIL $name: red, but not with '$msg'"; fail=1
	fi
}

# inner-hang: the run stops after the server is up and the canary sealed. The
# check must end it at the (shortened) limit with its own message, print the
# job output it scanned and leave no server behind.
inner_hang() {
	local name=inner-hang from='echo "ok: $from at schema $old_schema, canary sealed' msg='the run exceeded' text
	case ",$only," in ,,|*",$name,"*) ;; *) return ;; esac
	if ! grep -q -F -- "$from" scripts/check-upgrade-rollback.sh; then echo "FAIL $name: text not in the script, update this script"; fail=1; return; fi
	text=$(cat scripts/check-upgrade-rollback.sh)
	printf '%s\n' "${text/"$from"/"sleep 100000; $from"}" >"$work/check.sh"
	mutation_applied "$name" && return
	# The baseline run reaches the step in about a minute in CI; 180s leaves room.
	if KEEP_UPGRADE_INNER_TIMEOUT=180 run "$name" "$root/docs/deploy.md" "$work/check.sh"; then
		echo "FAIL $name: the check stayed green"; fail=1
	elif ! grep -q -F -- "$msg" "$work/out"; then
		"$root/scripts/upgrade-rollback-report.sh" "$work/out" || true
		echo "FAIL $name: red, but not with '$msg'"; fail=1
	elif ! grep -q -F -- "ok: built keep-server" "$work/out"; then
		echo "FAIL $name: red, but the job output it ran was not printed"; fail=1
	elif [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:18081/healthz || true)" != 000 ]; then
		echo "FAIL $name: red, but the server still answers after the run"; fail=1
	else
		echo "ok   $name: red with '$msg', the job output printed, no server left"
	fi
}

drop_line no-migrate-up '^  keep-server migrate up &&$' 'server exited'
sub_doc no-url-to-libpq 'pg_dump -Fc -d "$db"' 'pg_dump -Fc' 'the exec:upgrade block failed'
MUTATION_OCCURRENCE=1 sub_doc url-query-dropped 'db=${KEEP_DATABASE_URL:?KEEP_DATABASE_URL is not set in the env file}' 'db=${KEEP_DATABASE_URL%%\?*}' 'the exec:upgrade block failed'
sub_doc restore-continues-after-error $'keep-pre-upgrade.dump" &&\n  systemctl stop keep-server' $'keep-pre-upgrade.dump" ;\n  systemctl stop keep-server' 'the failed restore changed the database'
sub_doc no-pg-dump 'pg_dump -Fc -d "$db" -f "$BACKUP_DIR/keep-pre-upgrade.dump" &&' 'true &&' 'the upgrade block wrote no backup'
sub_doc no-goose-down 'exec goose -dir internal/store/migrations down-to "$2"' 'exec true' 'schema is'
sub_doc no-pg-restore 'pg_restore --no-owner -f "$BACKUP_DIR/restore.sql" "$BACKUP_DIR/keep-pre-upgrade.dump" &&' 'true &&' 'the failed restore changed the database'
edit_script wrong-expected-fingerprint 'want=$(cat "$work/state/before")' 'want="version=1 fingerprint=kfp1:000000000000:aaaaaaaaaaaaaaaa length=36"' 'differs from the sealed one'
edit_script canary-in-output 'audit0=$(audit_count)' 'echo "leak '$mark' $(cat "$work/state/canary.value")"; audit0=$(audit_count)' 'canary scan of the job output failed'
edit_script password-in-output 'audit0=$(audit_count)' 'echo "leak '$mark' $pw"; audit0=$(audit_count)' 'carries the database password or the root key'
edit_script password-before-seal 'start_server "$work/bin-old/keep-server"' 'echo "leak '$mark' $pw"; fail "stopped before the seal"' 'carries the database password or the root key'
# The password printed right after it is made (the next statement), then a
# failure before any psql.
edit_script password-early 'head -c 32 /dev/urandom >"$work/root.key"' 'echo "leak '$mark' $pw"; fail "stopped before psql"; head -c 32 /dev/urandom >"$work/root.key"' 'carries the database password or the root key'
inner_hang

[ "$fail" -eq 0 ] || exit 1
echo "PASS check-upgrade-rollback-mutations"
