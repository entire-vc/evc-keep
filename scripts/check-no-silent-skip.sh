#!/usr/bin/env sh
# Requires KEEP_DATABASE_URL and refuses to let its absence pass as a
# green test run.
#
# Without KEEP_DATABASE_URL, internal/store's (and a few other packages')
# DB-backed tests call t.Skip — and `go test ./...` (no -v) prints a plain
# "ok" for a package where every test skipped. A skip and a pass are then
# visually indistinguishable in the one line CI or a human actually reads.
# See CONTRIBUTING.md: the database layer is never mocked, so there is no
# substitute run that would have exercised this code instead.
#
# CI always sets KEEP_DATABASE_URL (see .gitlab-ci.yml's `test` job), so
# hitting this check there would mean the job's own config broke — this
# script is what that job runs, so CI and a local run share one
# definition of "passed" rather than CI trusting a bare `go test ./...`.
set -u

if [ -z "${KEEP_DATABASE_URL:-}" ]; then
	echo "check-no-silent-skip: KEEP_DATABASE_URL is not set." >&2
	echo "Without it, internal/store's tests SKIP instead of running, and a bare" >&2
	echo "'go test ./...' prints 'ok' for that — indistinguishable from a real pass." >&2
	echo "Set KEEP_DATABASE_URL to a throwaway Postgres (see CONTRIBUTING.md / the" >&2
	echo "keep-local-ci runbook) before running this script." >&2
	exit 1
fi

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT INT TERM

# -p 1: run package test binaries one at a time, not concurrently.
# internal/store's own migration tests reset the whole schema mid-run
# (see internal/store/migrate_test.go's resetSchema) — necessary for THEM
# to test the empty/behind states, but any other package's test querying a
# real table (internal/identity's do) would otherwise race against that
# reset if `go test`'s default per-package parallelism let both run
# against the one shared postgres service at the same time.
# Optional package arguments let CI isolate expensive targets attacks while
# the default local command still exercises the entire repository.
if [ "$#" -eq 0 ]; then set -- ./...; fi
# KEEP_TEST_RUN / KEEP_TEST_SKIP (regexes) let CI split one package's slow
# tests into their own job; the two halves are an exact partition, see the
# `test` job. A selection that matches nothing must not read as a pass.
sel=""
if [ -n "${KEEP_TEST_SKIP:-}" ]; then sel=1; set -- -skip "$KEEP_TEST_SKIP" "$@"; fi
if [ -n "${KEEP_TEST_RUN:-}" ]; then sel=1; set -- -run "$KEEP_TEST_RUN" "$@"; fi
go test -timeout 600s -race -count=1 -p 1 -v "$@" >"$LOG" 2>&1
status=$?

cat "$LOG"

if grep -q 'KEEP_DATABASE_URL not set' "$LOG"; then
	echo "" >&2
	echo "check-no-silent-skip: KEEP_DATABASE_URL is set, but a test skipped citing it anyway —" >&2
	echo "something is misconfigured (wrong var reaching the process, a stale build, etc)." >&2
	grep -B1 'KEEP_DATABASE_URL not set' "$LOG" >&2
	exit 1
fi

# Every test that skipped must be on the allowlist. Only names are printed.
allow="${KEEP_SKIP_ALLOWLIST:-$(dirname "$0")/allowed-skips.txt}"
if [ ! -r "$allow" ]; then
	echo "check-no-silent-skip: allowlist $allow is not readable" >&2
	exit 1
fi
unknown=$(awk -v allow="$allow" '
	BEGIN { while ((getline l < allow) > 0) { if (l ~ /^[ \t]*(#|$)/) continue; split(l, f, /[ \t]+/); ok[f[1]] = 1 } }
	/^[ \t]*--- SKIP: / { n = $3; top = n; sub(/\/.*/, "", top); if (!(n in ok) && !(top in ok)) print n }
' "$LOG" | sort -u)
if [ -n "$unknown" ]; then
	echo "" >&2
	echo "check-no-silent-skip: skipped tests that are not in $allow:" >&2
	echo "$unknown" >&2
	exit 1
fi

if [ "$status" -eq 0 ] && [ -n "$sel" ] && ! grep -q -- '^--- PASS' "$LOG"; then
	echo "check-no-silent-skip: the test selection ran no passing test" >&2
	exit 1
fi

exit "$status"
