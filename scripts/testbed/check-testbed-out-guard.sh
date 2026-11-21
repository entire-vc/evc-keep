#!/usr/bin/env bash
# Proves the stand refuses a foreign TESTBED_OUT before it chmods, writes or
# deletes anything, and still accepts its own directory. docker is a stub that
# fails at once, so no engine is needed; the red run is the same script against
# a copy of rotation.sh with the guard removed (see RED=1).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${RED_SCRIPT:-$HERE/rotation.sh}
W=$(mktemp -d "${TMPDIR:-/tmp}/tb-out-guard.XXXXXX"); trap 'find "$W" -delete' EXIT
mkdir "$W/bin"; printf '#!/bin/sh\nexit 1\n' >"$W/bin/docker"; chmod +x "$W/bin/docker"
run() { PATH="$W/bin:$PATH" TESTBED_OUT="$1" timeout 60 "$SCRIPT" up >"$W/log" 2>&1 || true; }

# negative: a foreign non-empty directory keeps its file and its mode
mkdir -m 755 "$W/foreign"; echo keep >"$W/foreign/mine.txt"
run "$W/foreign"
[ -f "$W/foreign/mine.txt" ] || { echo "FAIL foreign file was deleted"; exit 1; }
[ "$(ls -A "$W/foreign" | wc -l)" -eq 1 ] || { echo "FAIL foreign directory was written to"; exit 1; }
grep -q 'not a stand output directory' "$W/log" || { echo "FAIL no refusal message"; exit 1; }
# positive control: a new directory is accepted (marker written) and a rerun on it too
run "$W/fresh"; [ -f "$W/fresh/.keep-testbed-out" ] || { echo "FAIL own directory not accepted"; exit 1; }
! grep -q 'not a stand output directory' "$W/log" || { echo "FAIL own directory refused"; exit 1; }
echo x >"$W/fresh/stale"; run "$W/fresh"
[ ! -e "$W/fresh/stale" ] || { echo "FAIL own directory not cleaned"; exit 1; }
echo "PASS foreign TESTBED_OUT refused, own directory accepted and cleaned"
