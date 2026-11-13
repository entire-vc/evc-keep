#!/usr/bin/env bash
# docs/deploy.md "Upgrade", "Rollback" and "Restore" as an executable check:
# the older release (KEEP_UPGRADE_FROM, default 0.6.5) to the current commit and
# back, against a real PostgreSQL. The fenced blocks that follow an
# `<!-- exec:NAME -->` marker in the document are extracted and run as written;
# only the operating-system edge is shimmed (systemctl starts and stops the
# server process, sudo runs its argument).
#
#   1. older binary: migrate up, bootstrap-org, start, seal a disposable canary
#      (probe: cmd/keep-server/app/upgrade_probe_test.go) and record its
#      version, fingerprint and length; the audit chain verifies;
#   2. docs exec:upgrade with the new binary: /version is the current commit,
#      the schema is at the newest migration, the canary opens with the same
#      version, fingerprint and length, the audit chain still verifies;
#   3. docs exec:rollback (goose down to the older schema, older binary): the
#      older server starts, same canary, same fingerprint, audit ok;
#   4. upgrade again, then docs exec:restore (the pre-upgrade pg_dump, older
#      binary): same canary, same fingerprint, audit ok;
#   5. nothing the job printed carries the canary in any of six encodings, the
#      database password or the root key.
#
# Needs KEEP_ADMIN_URL: a superuser URL of a scratch PostgreSQL 17; psql,
# pg_dump, pg_restore, curl, jq, git, tar and go. A missing tool, variable or
# tag is a failure, not a skip. KEEP_DEPLOY_DOC names another copy of the
# document (the red runs in check-upgrade-rollback-mutations.sh).
set -euo pipefail
root=${KEEP_UPGRADE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
cd "$root"
doc=${KEEP_DEPLOY_DOC:-$root/docs/deploy.md}
from=${KEEP_UPGRADE_FROM:-0.6.5}
pkg=./cmd/keep-server/app

fail() { echo "FAIL upgrade-rollback: $1" >&2; exit 1; }

# The outer shell runs the real script and keeps its output, so the canary
# scan at the end reads exactly what the job printed.
if [ -z "${UPG_INNER:-}" ]; then
	work=$(mktemp -d)
	export UPG_WORK=$work
	trap 'rm -rf "$work"' EXIT
	set +e
	UPG_INNER=1 bash "$0" "$@" 2>&1 | tee "$work/job.log"
	rc=${PIPESTATUS[0]}
	set -e
	if [ -f "$work/state/canary.value" ]; then
		cp "$work/job.log" "$work/scanned.log"
		if ! (cd "$root" && KEEP_PROBE_ACTION=scan KEEP_PROBE_DIR="$work/state" KEEP_PROBE_LOG="$work/scanned.log" \
			go test -tags upgradeprobe -count=1 -run '^TestUpgradeProbe$' -v "$pkg" >"$work/scan.out" 2>&1); then
			tail -8 "$work/scan.out"
			echo "FAIL upgrade-rollback: the canary scan of the job output failed" >&2
			exit 1
		fi
		grep -E 'scanned [0-9]+ bytes' "$work/scan.out" || true
		if [ -f "$work/secrets.txt" ] && grep -q -F -f "$work/secrets.txt" "$work/scanned.log"; then
			echo "FAIL upgrade-rollback: the job output carries the database password or the root key" >&2
			exit 1
		fi
	elif [ "$rc" -eq 0 ]; then
		echo "FAIL upgrade-rollback: no canary was sealed, nothing was scanned" >&2
		exit 1
	fi
	exit "$rc"
fi
work=$UPG_WORK
in_block=""
set -E
trap 'fail "a command failed (line $LINENO${in_block:+, in the exec:$in_block block of the document})"' ERR

for t in psql pg_dump pg_restore curl jq git tar go; do command -v "$t" >/dev/null 2>&1 || fail "$t is required"; done
[ -n "${KEEP_ADMIN_URL:-}" ] || fail "KEEP_ADMIN_URL is not set"
[ -f "$doc" ] || fail "$doc does not exist"
git rev-parse -q --verify "refs/tags/$from^{commit}" >/dev/null || fail "tag $from is missing: fetch tags (GIT_DEPTH: 0)"
old_sha=$(git rev-parse "$from^{commit}")
new_sha=$(git rev-parse HEAD)
admin_host=${KEEP_ADMIN_HOST:-postgres}
admin_port=${KEEP_ADMIN_PORT:-5432}

pids=""
srv=""
cleanup() { for p in $pids $srv; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

# --- both binaries, built from their own trees ------------------------------
mkdir -p "$work/old" "$work/bin-old" "$work/bin-new" "$work/state" "$work/backups" "$work/gobin"
git archive "$from" | tar -x -C "$work/old"
cp "$root/cmd/keep-server/app/upgrade_probe_test.go" "$work/old/cmd/keep-server/app/upgrade_probe_test.go"
build() { # tree commit outdir
	(cd "$1" && go build -buildvcs=false -ldflags "-X github.com/entire-vc/evc-keep/internal/version.Commit=$2" -o "$3/keep-server" ./cmd/keep-server)
}
build "$work/old" "$old_sha" "$work/bin-old" || fail "build $from"
build "$root" "$new_sha" "$work/bin-new" || fail "build HEAD"
echo "ok: built keep-server $from ($old_sha) and HEAD ($new_sha)"

# --- database and configuration, the way docs/deploy.md describes -----------
pw="upg$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
psql "$KEEP_ADMIN_URL" -v ON_ERROR_STOP=1 -q <<SQL >/dev/null
DROP DATABASE IF EXISTS keepupg;
DROP ROLE IF EXISTS keepupg;
DROP ROLE IF EXISTS keep_app;
CREATE ROLE keepupg LOGIN CREATEROLE PASSWORD '$pw';
CREATE DATABASE keepupg OWNER keepupg;
ALTER DATABASE keepupg SET log_error_verbosity = terse;
ALTER DATABASE keepupg SET log_min_error_statement = panic;
ALTER DATABASE keepupg SET log_statement = 'none';
ALTER DATABASE keepupg SET log_min_duration_statement = -1;
ALTER DATABASE keepupg SET log_min_duration_sample = -1;
ALTER DATABASE keepupg SET log_transaction_sample_rate = 0;
ALTER DATABASE keepupg SET log_min_messages = 'panic';
SQL
admin_db=$(printf '%s' "$KEEP_ADMIN_URL" | sed 's#/[^/]*$#/keepupg#')
psql "$admin_db" -v ON_ERROR_STOP=1 -q -c 'ALTER SCHEMA public OWNER TO keepupg' >/dev/null

head -c 32 /dev/urandom >"$work/root.key"
chmod 600 "$work/root.key"
# The authority names a host that does not exist; the real one is in the query,
# which pgx applies over the authority and libpq honours too. A step that parses
# the URL by hand and drops the query reaches the decoy and fails.
export KEEP_DATABASE_URL="postgres://keepupg:$pw@decoy.invalid:1/keepupg?host=$admin_host&port=$admin_port&sslmode=disable&connect_timeout=3"
export KEEP_ROOT_KEY_FILE="$work/root.key"
export KEEP_HTTP_ADDR=127.0.0.1:18081 KEEP_RUNNER_ADDR=127.0.0.1:18444
export KEEP_DEV_EPHEMERAL_TLS=1 # no real certificate in CI
export KEEP_LOCAL_URL=http://127.0.0.1:18081
export BACKUP_DIR=$work/backups
export ENV_FILE=$work/keep-server.env
( umask 077; {
	echo "KEEP_DATABASE_URL='$KEEP_DATABASE_URL'"
	echo "KEEP_ROOT_KEY_FILE='$KEEP_ROOT_KEY_FILE'"
	echo "KEEP_HTTP_ADDR='$KEEP_HTTP_ADDR'"
	echo "KEEP_RUNNER_ADDR='$KEEP_RUNNER_ADDR'"
} >"$ENV_FILE" )
# What the scan of the job output must not find.
{ printf '%s\n' "$pw"; od -An -tx1 "$work/root.key" | tr -d ' \n'; echo; base64 <"$work/root.key" | tr -d '\n'; echo; } >"$work/secrets.txt"
export GOBIN=$work/gobin
export PATH="$GOBIN:$PATH" # goose, "put it on root's PATH"

# --- helpers ------------------------------------------------------------------
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$KEEP_LOCAL_URL$1" || true; }
wait_ready() {
	local i=0
	until [ "$(code /readyz)" = 200 ]; do
		i=$((i + 1))
		[ "$i" -le 30 ] || { tail -5 "$work/server.log"; fail "server never became ready ($1)"; }
		kill -0 "$srv" 2>/dev/null || { tail -5 "$work/server.log"; fail "server exited ($1)"; }
		sleep 1
	done
}
# Like a systemd unit with EnvironmentFile=: the server gets the env file, nothing else.
start_server() { ( set -a; . "$ENV_FILE"; exec "$1" ) >>"$work/server.log" 2>&1 & srv=$!; wait_ready "$1"; }
stop_server() { if [ -n "$srv" ]; then kill "$srv" 2>/dev/null || true; wait "$srv" 2>/dev/null || true; srv=""; fi; }

# The operating-system edge of the document's blocks.
start_bin=""
systemctl() {
	case "$*" in
		"restart keep-server") stop_server; start_server "${start_bin:-$(command -v keep-server)}" ;;
		"stop keep-server") stop_server ;;
		"start keep-server") start_server "${start_bin:-$(command -v keep-server)}" ;;
		*) fail "the document runs an unexpected systemctl $*" ;;
	esac
}
sudo() { "$@"; }

# run_block NAME: the fenced block after <!-- exec:NAME -->, executed as written.
run_block() {
	awk -v m="<!-- exec:$1 -->" '
		$0 == m { armed = 1; next }
		armed && /^```sh$/ { inb = 1; next }
		inb && /^```$/ { exit }
		inb { print }
		armed && !inb && NF { armed = 0 }' "$doc" >"$work/block-$1.sh"
	[ -s "$work/block-$1.sh" ] || fail "$doc has no exec:$1 block"
	echo "--- docs exec:$1"
	# The block gets only what the document gives it: the env file. Whatever
	# connection settings this script holds are removed first and put back after.
	local saved
	saved=$(export -p | grep -E '^declare -x (KEEP_(DATABASE_URL|ROOT_KEY_FILE|HTTP_ADDR|RUNNER_ADDR)|PG[A-Z]*)=') || true
	unset PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE PGPASSFILE PGSERVICE KEEP_DATABASE_URL KEEP_ROOT_KEY_FILE KEEP_HTTP_ADDR KEEP_RUNNER_ADDR
	in_block=$1
	block_rc=0
	# A block is plain sh and stops at its first failed step by itself (steps are
	# chained with &&); its exit status is checked here whatever shell options hold.
	. "$work/block-$1.sh" || block_rc=$?
	in_block=""
	unset PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE
	eval "${saved//declare -x /declare -gx }" # -g: a function would make them local
	if [ "$block_rc" -ne 0 ] && [ -z "${block_may_fail:-}" ]; then fail "the exec:$1 block failed (exit $block_rc)"; fi
	return 0
}

probe() { # action tree outfile
	rm -f "$3"
	(cd "$2" && KEEP_PROBE_ACTION=$1 KEEP_PROBE_DIR="$work/state" KEEP_PROBE_ORG=$org KEEP_PROBE_OUT=$3 \
		go test -tags upgradeprobe -count=1 -run '^TestUpgradeProbe$' "$pkg" >"$work/probe.log" 2>&1) \
		|| { sed 's/^/probe: /' "$work/probe.log" | tail -15; fail "probe $1 in $2"; }
	[ -s "$3" ] || fail "probe $1 wrote no state"
}

audit_count() { # prints the number of verified records, fails on a broken chain
	local out
	out=$(keep-server audit verify --org "$org") || fail "audit verify: $out"
	case "$out" in "chain OK: "*) ;; *) fail "audit verify: $out" ;; esac
	printf '%s' "$out" | sed -n 's/^chain OK: \([0-9]*\) record.*/\1/p'
}

schema() { PGHOST=$admin_host PGPORT=$admin_port PGUSER=keepupg PGPASSWORD=$pw PGDATABASE=keepupg psql -Atc 'SELECT max(version_id) FROM goose_db_version WHERE is_applied'; }

check_canary() { # label tree
	probe read "$2" "$work/state/after-$1"
	if [ "$(cat "$work/state/after-$1")" != "$want" ]; then
		echo "before: $want" >&2
		echo "after:  $(cat "$work/state/after-$1")" >&2
		fail "the canary after $1 differs from the sealed one (version, fingerprint, length)"
	fi
	echo "ok: after $1 the canary opens as the same value: $want"
}

check_version() { # commit
	local got
	got=$(curl -s --max-time 3 "$KEEP_LOCAL_URL/version" | jq -r .commit)
	[ "$got" = "$1" ] || fail "/version commit is $got, want $1"
	[ "$(code /healthz)" = 200 ] || fail "/healthz is not 200"
}

# --- 1. the older release ------------------------------------------------------
export PATH="$work/bin-old:$PATH"
keep-server migrate up >"$work/migrate-old.log" 2>&1 || { tail -5 "$work/migrate-old.log"; fail "migrate up with $from"; }
old_schema=$(schema)
keep-server migrate status | grep -q "up to date at version $old_schema" || fail "$from migrate status is not up to date at $old_schema"
bootstrap=$(keep-server bootstrap-org --name "upg-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
	--admin-email admin@example.test --token-file "$work/admin.token" --ttl 1h) || fail "bootstrap-org with $from"
org=$(printf '%s\n' "$bootstrap" | sed -n 's/^org_id=//p')
[ -n "$org" ] || fail "bootstrap-org printed no org_id"
start_server "$work/bin-old/keep-server"
check_version "$old_sha"
probe seal "$work/old" "$work/state/before"
want=$(cat "$work/state/before")
case "$want" in "version="*" fingerprint=kfp1:"*" length="*) ;; *) fail "the sealed canary's state is malformed: $want" ;; esac
audit0=$(audit_count)
[ "$audit0" -ge 1 ] || fail "the audit chain is empty before the upgrade: nothing to verify"
echo "ok: $from at schema $old_schema, canary sealed ($want), audit chain of $audit0 record(s) verified"

# --- 2. upgrade: docs/deploy.md "Upgrade" --------------------------------------
export PATH="$work/bin-new:$PATH"
if keep-server migrate status >"$work/status-behind.log" 2>&1; then fail "migrate status with the new binary did not exit 1 on the older schema"; fi
grep -q "behind" "$work/status-behind.log" || fail "migrate status on the older schema does not say 'behind'"
new_schema=$(ls internal/store/migrations/*.sql | sed 's#.*/0*\([0-9]*\)_.*#\1#' | sort -n | tail -1)
[ "$new_schema" -gt "$old_schema" ] || fail "HEAD has no migration beyond $old_schema: nothing is upgraded"
start_bin=""
run_block upgrade
[ -s "$BACKUP_DIR/keep-pre-upgrade.dump" ] || fail "the upgrade block wrote no backup"
[ "$(schema)" = "$new_schema" ] || fail "schema is $(schema) after the upgrade, want $new_schema"
check_version "$new_sha"
check_canary upgrade "$root"
audit1=$(audit_count)
[ "$audit1" -ge "$audit0" ] || fail "the audit chain shrank in the upgrade: $audit0 -> $audit1"
echo "ok: upgrade $old_schema -> $new_schema, /version is HEAD, audit chain of $audit1 record(s) verified"

# --- 3. rollback, binary and schema: docs/deploy.md "Rollback" -----------------
export PATH="$work/bin-old:$PATH"
export OLDER_SCHEMA_VERSION=$old_schema
start_bin="$work/bin-old/keep-server"
run_block rollback
[ "$(schema)" = "$old_schema" ] || fail "schema is $(schema) after the rollback, want $old_schema"
keep-server migrate status | grep -q "up to date at version $old_schema" || fail "$from migrate status after the rollback"
check_version "$old_sha"
check_canary rollback "$work/old"
[ "$(audit_count)" -ge "$audit0" ] || fail "the audit chain lost records in the rollback"
echo "ok: rollback $new_schema -> $old_schema with $from, audit chain verified"

# --- 4. restore: docs/deploy.md "Restore" --------------------------------------
stop_server
PATH="$work/bin-new:$PATH" keep-server migrate up >/dev/null 2>&1 || fail "migrate up before the restore"
[ "$(schema)" = "$new_schema" ] || fail "schema is $(schema) before the restore, want $new_schema"
# First a damaged dump: the block must fail, leave the database as it was and not start a server.
cp "$BACKUP_DIR/keep-pre-upgrade.dump" "$work/good.dump"
printf 'this is not a pg_dump archive' >"$BACKUP_DIR/keep-pre-upgrade.dump"
block_may_fail=1 run_block restore
[ "$block_rc" -ne 0 ] || fail "the restore block reported success for a damaged dump"
[ "$(schema 2>/dev/null || echo none)" = "$new_schema" ] || fail "the failed restore changed the database"
[ -z "$srv" ] || fail "the restore block started a server after a failed pg_restore"
echo "ok: a damaged dump stops the restore before anything is dropped (exit $block_rc)"
cp "$work/good.dump" "$BACKUP_DIR/keep-pre-upgrade.dump"
run_block restore
[ "$(schema)" = "$old_schema" ] || fail "schema is $(schema) after the restore, want $old_schema"
check_version "$old_sha"
check_canary restore "$work/old"
[ "$(audit_count)" -ge "$audit0" ] || fail "the audit chain lost records in the restore"
echo "ok: restore of the pre-upgrade dump: schema $old_schema, same canary, audit chain verified"
stop_server

# The server's own output goes through the same scan as the script's.
sed 's/^/server: /' "$work/server.log"
echo "PASS upgrade-rollback"
