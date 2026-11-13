#!/usr/bin/env sh
# Starts a keep-server binary (taken out of a published image) against a
# scratch PostgreSQL, the way scripts/check-deploy-smoke.sh does, and writes the
# body of GET /version to OUT. It checks nothing about the body: the receipt
# builder (scripts/mesh_image_receipt.py) compares it with the source commit.
#
#   KEEP_ADMIN_URL=postgres://... scripts/run-image-version.sh BIN OUT
#
# Needs psql, curl and a superuser KEEP_ADMIN_URL of a scratch PostgreSQL.
# A missing tool or variable is a failure. Nothing the server prints is kept.
set -eu
fail() { echo "FAIL run-image-version: $1" >&2; exit 1; }
[ $# -eq 2 ] || fail "usage: run-image-version.sh BIN OUT"
bin=$1
out=$2
[ -x "$bin" ] || fail "binary is not executable"
for t in psql curl head od tr sed; do command -v "$t" >/dev/null 2>&1 || fail "$t is required"; done
[ -n "${KEEP_ADMIN_URL:-}" ] || fail "KEEP_ADMIN_URL is not set"

work=$(mktemp -d)
srv=""
cleanup() { [ -z "$srv" ] || kill "$srv" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT INT TERM

pw="ver$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
psql "$KEEP_ADMIN_URL" -v ON_ERROR_STOP=1 -q <<SQL >/dev/null
DROP DATABASE IF EXISTS keepver;
DROP ROLE IF EXISTS keepver;
CREATE ROLE keepver LOGIN CREATEROLE PASSWORD '$pw';
CREATE DATABASE keepver OWNER keepver;
ALTER DATABASE keepver SET log_error_verbosity = terse;
ALTER DATABASE keepver SET log_min_error_statement = panic;
ALTER DATABASE keepver SET log_statement = 'none';
ALTER DATABASE keepver SET log_min_duration_statement = -1;
ALTER DATABASE keepver SET log_min_duration_sample = -1;
ALTER DATABASE keepver SET log_transaction_sample_rate = 0;
ALTER DATABASE keepver SET log_min_messages = 'panic';
SQL
admin_db=$(printf '%s' "$KEEP_ADMIN_URL" | sed 's#/[^/?]*\(?.*\)\{0,1\}$#/keepver#')
psql "$admin_db" -v ON_ERROR_STOP=1 -q -c 'ALTER SCHEMA public OWNER TO keepver' >/dev/null
host=$(printf '%s' "$KEEP_ADMIN_URL" | sed 's#^[a-z]*://[^@]*@\([^/?]*\).*#\1#')

export KEEP_DATABASE_URL="postgres://keepver:$pw@$host/keepver?sslmode=disable&connect_timeout=3"
head -c 32 /dev/urandom >"$work/root.key"
chmod 600 "$work/root.key"
export KEEP_ROOT_KEY_FILE="$work/root.key"
export KEEP_HTTP_ADDR=127.0.0.1:18080 KEEP_RUNNER_ADDR=127.0.0.1:18443
export KEEP_DEV_EPHEMERAL_TLS=1

log="$work/server.log"
"$bin" migrate up >"$log" 2>&1 || fail "migrate up (server output withheld)"
"$bin" >>"$log" 2>&1 &
srv=$!
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:18080/readyz || true)" = 200 ]; do
	i=$((i + 1))
	[ "$i" -le 30 ] || fail "server never became ready (output withheld)"
	kill -0 "$srv" 2>/dev/null || fail "server exited (output withheld)"
	sleep 1
done
curl -s --fail --max-time 3 http://127.0.0.1:18080/version >"$out.tmp" || fail "GET /version failed"
mv "$out.tmp" "$out"
echo "ok: /version captured"
