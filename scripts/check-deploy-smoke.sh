#!/usr/bin/env sh
# Deployment smoke test: the keep-server binary taken out of the built image
# (KEEP_IMAGE_TAR, the Dockerfile's output), configured the way docs/deploy.md
# describes (environment only, non-superuser role, migrations applied first),
# against a real PostgreSQL. The CI runner has no container runtime, so the
# image is unpacked and its entrypoint binary is run; the image's user and
# entrypoint are asserted from its config.
#
#   - the image runs as a non-root user with the keep-server entrypoint;
#   - the downgrade in docs/deploy.md works: goose down-to the previous
#     version, `migrate status` shows it, the newer binary refuses to start on
#     the older schema with a pointer to `migrate up`, `migrate up` recovers;
#   - /healthz is 200 and /readyz is 200 while the database answers;
#   - GET /version answers with exactly commit and build_time;
#   - the database connection is cut: /readyz is no longer 200 while /healthz
#     still is (the red run for the readiness probe);
#   - nothing the server prints carries the database password.
#
# Needs KEEP_ADMIN_URL: a superuser URL of a scratch PostgreSQL 17, KEEP_IMAGE_TAR,
# plus psql, socat, curl, jq and go (goose is fetched at its pinned version). Missing tool or variable is a failure, not a skip.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

fail() { echo "FAIL deploy-smoke: $1" >&2; exit 1; }
for t in psql socat curl jq tar go; do command -v "$t" >/dev/null 2>&1 || fail "$t is required"; done
[ -n "${KEEP_ADMIN_URL:-}" ] || fail "KEEP_ADMIN_URL is not set"
[ -f "${KEEP_IMAGE_TAR:-}" ] || fail "KEEP_IMAGE_TAR must name the built image tarball"
admin_host=${KEEP_ADMIN_HOST:-postgres}
admin_port=${KEEP_ADMIN_PORT:-5432}

work=$(mktemp -d)
pids=""
cleanup() { for p in $pids; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"; }
trap cleanup EXIT INT TERM

# Synthetic password, only ever seen by this script and the database.
pw="smoke$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
psql "$KEEP_ADMIN_URL" -v ON_ERROR_STOP=1 -q <<SQL >/dev/null
DROP DATABASE IF EXISTS keepsmoke;
DROP ROLE IF EXISTS keepsmoke;
DROP ROLE IF EXISTS keep_app;
CREATE ROLE keepsmoke LOGIN CREATEROLE PASSWORD '$pw';
CREATE DATABASE keepsmoke OWNER keepsmoke;
ALTER DATABASE keepsmoke SET log_error_verbosity = terse;
ALTER DATABASE keepsmoke SET log_min_error_statement = panic;
ALTER DATABASE keepsmoke SET log_statement = 'none';
ALTER DATABASE keepsmoke SET log_min_duration_statement = -1;
ALTER DATABASE keepsmoke SET log_min_duration_sample = -1;
ALTER DATABASE keepsmoke SET log_transaction_sample_rate = 0;
ALTER DATABASE keepsmoke SET log_min_messages = 'panic';
SQL
admin_db=$(printf '%s' "$KEEP_ADMIN_URL" | sed 's#/[^/]*$#/keepsmoke#')
psql "$admin_db" -v ON_ERROR_STOP=1 -q -c 'ALTER SCHEMA public OWNER TO keepsmoke' >/dev/null

# The server reaches the database through a proxy we can cut.
socat TCP-LISTEN:55432,fork,reuseaddr TCP:"$admin_host:$admin_port" &
proxy=$!
pids="$pids $proxy"
sleep 1

export KEEP_DATABASE_URL="postgres://keepsmoke:$pw@127.0.0.1:55432/keepsmoke?sslmode=disable&connect_timeout=3"
head -c 32 /dev/urandom >"$work/root.key"
chmod 600 "$work/root.key" # the server refuses any other mode
export KEEP_ROOT_KEY_FILE="$work/root.key"
export KEEP_HTTP_ADDR=127.0.0.1:18080 KEEP_RUNNER_ADDR=127.0.0.1:18443
export KEEP_DEV_EPHEMERAL_TLS=1 # no real certificate in CI; production sets the TLS file variables

# Unpack the image: assert user and entrypoint, take the binary from its layers.
mkdir "$work/img"
tar -xf "$KEEP_IMAGE_TAR" -C "$work/img"
cfg=$(jq -r '.[0].Config' "$work/img/manifest.json")
[ "$(jq -r '.config.User' "$work/img/$cfg")" = "10001:10001" ] || fail "image does not run as 10001:10001"
[ "$(jq -r '.config.Entrypoint | join(" ")' "$work/img/$cfg")" = "/usr/local/bin/keep-server" ] || fail "image entrypoint is not keep-server"
for l in $(jq -r '.[0].Layers[]' "$work/img/manifest.json"); do
	tar -xf "$work/img/$l" -C "$work" usr/local/bin/keep-server 2>/dev/null || true
done
mv "$work/usr/local/bin/keep-server" "$work/keep-server" || fail "no keep-server binary in the image"
echo "ok: image runs as 10001:10001, entrypoint keep-server; binary taken from its layers"
out="$work/out.log"
"$work/keep-server" migrate up >"$out" 2>&1 || { tail -5 "$out" | sed "s/$pw/[pw]/g"; fail "migrate up"; }
"$work/keep-server" >>"$out" 2>&1 &
srv=$!
pids="$pids $srv"

code() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:18080$1" || true; }
i=0
until [ "$(code /readyz)" = 200 ]; do
	i=$((i + 1))
	[ "$i" -le 30 ] || { tail -5 "$out" | sed "s/$pw/[pw]/g"; fail "server never became ready"; }
	kill -0 "$srv" 2>/dev/null || { tail -5 "$out" | sed "s/$pw/[pw]/g"; fail "server exited"; }
	sleep 1
done
[ "$(code /healthz)" = 200 ] || fail "/healthz is not 200"
echo "ok: /healthz=200 /readyz=200 with the database up"

# GET /version is served by the binary taken from the image: public, exactly
# commit and build_time, and the commit is 40-hex or "unknown" (CI builds the
# image without a commit build argument, so "unknown" is expected here).
ver=$(curl -s --max-time 3 http://127.0.0.1:18080/version || true)
[ "$(printf '%s' "$ver" | jq -r 'keys | join(",")' 2>/dev/null)" = "build_time,commit" ] \
	|| fail "/version does not carry exactly commit and build_time: $ver"
printf '%s' "$ver" | jq -e '.commit | test("^([0-9a-f]{40}|unknown)$")' >/dev/null \
	|| fail "/version commit is neither 40-hex nor unknown: $ver"
echo "ok: /version serves commit and build_time"

# Downgrade exactly as docs/deploy.md describes: goose with the URL in its
# environment (never argv), one version down, then the newer binary must refuse
# the older schema, and `migrate up` must recover.
kill "$srv"; wait "$srv" 2>/dev/null || true
latest=$(ls internal/store/migrations/*.sql | sed 's#.*/0*\([0-9]*\)_.*#\1#' | sort -n | tail -1)
prev=$((latest - 1))
(cd "$work" && GOOSE_DRIVER=postgres GOOSE_DBSTRING="$KEEP_DATABASE_URL" \
	go run github.com/pressly/goose/v3/cmd/goose@v3.27.0 -dir "$root/internal/store/migrations" down-to "$prev") >"$work/down.log" 2>&1 \
	|| { sed "s/$pw/[pw]/g" "$work/down.log" | tail -5; fail "goose down-to $prev"; }
v=$(psql "$admin_db" -Atc 'SELECT max(version_id) FROM goose_db_version WHERE is_applied')
[ "$v" = "$prev" ] || fail "schema is at $v after down-to $prev"
if "$work/keep-server" >"$work/old.log" 2>&1; then fail "server started on a schema behind its binary"; fi
grep -q "migrate up" "$work/old.log" || fail "refusal carries no pointer to migrate up"
"$work/keep-server" migrate up >>"$out" 2>&1 || fail "migrate up after downgrade"
v=$(psql "$admin_db" -Atc 'SELECT max(version_id) FROM goose_db_version WHERE is_applied')
[ "$v" = "$latest" ] || fail "schema is at $v after migrate up, want $latest"
echo "ok: downgrade $latest -> $prev, older schema refused, migrate up -> $latest"
"$work/keep-server" >>"$out" 2>&1 &
srv=$!
pids="$pids $srv"
i=0
until [ "$(code /readyz)" = 200 ]; do
	i=$((i + 1)); [ "$i" -le 30 ] || fail "server never became ready after migrate up"; sleep 1
done

# Red run: cut the database. Stop the listener, then drop the connections
# already open through it.
kill "$proxy"
psql "$KEEP_ADMIN_URL" -q -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='keepsmoke'" >/dev/null
sleep 2
r=$(code /readyz)
[ "$r" != 200 ] || fail "/readyz stayed 200 with the database unreachable"
[ "$(code /healthz)" = 200 ] || fail "/healthz dropped with the database unreachable"
echo "ok: database cut -> /readyz=$r, /healthz=200"

if grep -q -- "$pw" "$out"; then fail "server output carries the database password"; fi
echo "PASS deploy-smoke"
