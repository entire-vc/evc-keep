#!/bin/sh
# Self-test of scripts/run-mutation-checks.sh without compiling Go: a stub
# script must see GOCACHE unset even when the caller set it, and a failing
# stub must fail the wrapper. An optional path tests a deliberately broken copy.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
wrapper=${1:-$root/scripts/run-mutation-checks.sh}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
printf '#!/bin/sh\n[ -z "${GOCACHE+x}" ]\n' >"$scratch/sees-no-cache.sh"
printf '#!/bin/sh\nexit 1\n' >"$scratch/fails.sh"
chmod +x "$scratch"/*.sh

GOCACHE=/nonexistent/lane-cache "$wrapper" "$scratch/sees-no-cache.sh" >/dev/null ||
    { echo "FAIL: wrapper leaked the caller's GOCACHE to the script" >&2; exit 1; }
if GOCACHE=/nonexistent/lane-cache "$wrapper" "$scratch/fails.sh" >/dev/null 2>&1; then
    echo "FAIL: wrapper hid a failing script" >&2; exit 1
fi
echo "ok   run-mutation-checks: GOCACHE dropped, failure propagated"
