#!/usr/bin/env bash
# Red runs for scripts/check-upgrade-rollback.sh: each mutant breaks one thing
# in a copy (of the document or of the script) and the check must fail, with
# the designated message. The unmutated check must pass first, so a red is
# never an artefact of the environment. Needs the same environment as the
# check (KEEP_ADMIN_URL and its tools).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0

run() { # label doc script -> output in $work/out, status returned
	KEEP_DEPLOY_DOC=$2 KEEP_UPGRADE_ROOT=$root bash "$3" >"$work/out" 2>&1
}

# REDRUN_ONLY=name[,name] runs only those mutants (and skips the baseline), for development.
only=${REDRUN_ONLY:-} # one mutant name or a comma list
if [ -n "$only" ]; then
	:
elif run baseline "$root/docs/deploy.md" "$root/scripts/check-upgrade-rollback.sh"; then
	echo "ok   baseline: the unmutated check passes"
else
	tail -15 "$work/out"; echo "FAIL baseline: the unmutated check is red"; exit 1
fi

# drop_line NAME PATTERN MESSAGE: the document copy without the lines matching PATTERN.
drop_line() {
	local name=$1 pat=$2 msg=$3
	if ! grep -q -E -- "$pat" docs/deploy.md; then echo "FAIL $name: pattern not in the document, update this script"; fail=1; return; fi
	grep -v -E -- "$pat" docs/deploy.md >"$work/doc.md"
	expect_red "$name" "$work/doc.md" "$root/scripts/check-upgrade-rollback.sh" "$msg"
}
# sub_doc NAME FROM TO MESSAGE: the document copy with FROM replaced by TO.
sub_doc() {
	local name=$1 from=$2 to=$3 msg=$4 text
	text=$(cat docs/deploy.md)
	case "$text" in *"$from"*) ;; *) echo "FAIL $name: text not in the document, update this script"; fail=1; return ;; esac
	printf '%s\n' "${text/"$from"/"$to"}" >"$work/doc.md"
	expect_red "$name" "$work/doc.md" "$root/scripts/check-upgrade-rollback.sh" "$msg"
}
# edit_script NAME FROM TO MESSAGE: the script copy with FROM replaced by TO.
edit_script() {
	local name=$1 from=$2 to=$3 msg=$4
	if ! grep -q -F -- "$from" scripts/check-upgrade-rollback.sh; then echo "FAIL $name: text not in the script, update this script"; fail=1; return; fi
	local text
	text=$(cat scripts/check-upgrade-rollback.sh)
	printf '%s\n' "${text/"$from"/"$to"}" >"$work/check.sh"
	expect_red "$name" "$root/docs/deploy.md" "$work/check.sh" "$msg"
}
expect_red() {
	local name=$1 doc=$2 script=$3 msg=$4
	case ",$only," in ,,|*",$name,"*) ;; *) return ;; esac
	if run "$name" "$doc" "$script"; then
		echo "FAIL $name: the check stayed green"; fail=1
	elif grep -q -F -- "$msg" "$work/out"; then
		echo "ok   $name: red with '$msg'"
	else
		tail -8 "$work/out"; echo "FAIL $name: red, but not with '$msg'"; fail=1
	fi
}

drop_line no-migrate-up '^  keep-server migrate up &&$' 'server exited'
sub_doc no-url-to-libpq 'pg_dump -Fc -d "$db"' 'pg_dump -Fc' 'the exec:upgrade block failed'
sub_doc url-query-dropped 'db=${KEEP_DATABASE_URL:?KEEP_DATABASE_URL is not set in the env file}' 'db=${KEEP_DATABASE_URL%%\?*}' 'the exec:upgrade block failed'
sub_doc restore-continues-after-error $'keep-pre-upgrade.dump" &&\n  systemctl stop keep-server' $'keep-pre-upgrade.dump" ;\n  systemctl stop keep-server' 'the failed restore changed the database'
sub_doc no-pg-dump 'pg_dump -Fc -d "$db" -f "$BACKUP_DIR/keep-pre-upgrade.dump" &&' 'true &&' 'the upgrade block wrote no backup'
sub_doc no-goose-down 'exec goose -dir internal/store/migrations down-to "$2"' 'exec true' 'schema is'
sub_doc no-pg-restore 'pg_restore --no-owner -f "$BACKUP_DIR/restore.sql" "$BACKUP_DIR/keep-pre-upgrade.dump" &&' 'true &&' 'the failed restore changed the database'
edit_script wrong-expected-fingerprint 'want=$(cat "$work/state/before")' 'want="version=1 fingerprint=kfp1:000000000000:aaaaaaaaaaaaaaaa length=36"' 'differs from the sealed one'
edit_script canary-in-output 'audit0=$(audit_count)' 'echo "leak $(cat "$work/state/canary.value")"; audit0=$(audit_count)' 'canary scan of the job output failed'
edit_script password-in-output 'audit0=$(audit_count)' 'echo "leak $pw"; audit0=$(audit_count)' 'carries the database password or the root key'

[ "$fail" -eq 0 ] || exit 1
echo "PASS check-upgrade-rollback-redrun"
