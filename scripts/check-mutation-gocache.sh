#!/bin/sh
# Every mutation check must use a private exported cache. The shared cache
# lifecycle guard verifies the per-run default and its export to children,
# caller ownership, safe EXIT cleanup, and each script's library integration.
# Pass another checkout's scripts directory to check that tree.
set -eu

dir=${1:-$(cd "$(dirname "$0")" && pwd)}
check="$dir/check-gocache-cleanup.sh"
[ -f "$check" ] || { echo "FAIL: no cache lifecycle guard found in $dir" >&2; exit 1; }
sh "$check"
echo "ok   mutation scripts use a private exported GOCACHE with ownership cleanup"
