#!/bin/sh
# Pending attacks activate only for their own target; real witnesses must pass.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
test -f "$root/go.mod" || { echo 'refuse: root is not the repo root' >&2; exit 2; }
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
python3 "$root/scripts/check-w3-stubs.py" "$root" "$work"
