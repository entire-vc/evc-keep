#!/bin/sh
# Run every scripts/check-*-mutations.sh, each with a private throwaway Go
# build cache. A caller-owned GOCACHE (a lane's shared cache) is kept by
# scripts/lib/gocache.sh by design, so the mutants, which are all distinct
# sources, would pile up there: about 150-450 MiB per script, GiB per run.
# Dropping GOCACHE makes each script allocate its own and remove it on exit.
# CI wants the shared cache and calls the scripts directly, not this wrapper.
# Usage: scripts/run-mutation-checks.sh [script ...]   (default: all)
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
[ $# -gt 0 ] || set -- "$root"/scripts/check-*-mutations.sh
fail=0
for s in "$@"; do
    echo "== $s"
    env -u GOCACHE "$s" || { echo "FAIL $s"; fail=1; }
done
exit $fail
