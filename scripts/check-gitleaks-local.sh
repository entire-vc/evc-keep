#!/usr/bin/env bash
# Runs the same gitleaks scan CI's secret-scan job runs, for local use —
# and refuses to call a scan of zero commits / zero bytes a pass.
#
# Why this exists: colima (the docker runtime on Mac Mini lanes) only
# mounts $HOME into its VM. A clone living outside $HOME (e.g. under
# /tmp/...) is invisible inside the container: `git log` fails with "not a
# git repository", gitleaks logs "0 commits scanned" / "scanned ~0 bytes
# (0)", finds nothing, and exits 0 — the same exit code a real, clean scan
# gives. Reproduced 2026-09-24: identical exit 0 from a clone under /tmp
# (0 commits / 0 bytes) and a clone under $HOME (real commit count / real
# byte count) — the exit code alone cannot tell them apart, only the
# counters gitleaks itself prints can.
set -uo pipefail

GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-zricethezav/gitleaks:v8.30.1}"
REPO_ROOT="$(git rev-parse --show-toplevel)"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT INT TERM

docker run --rm -v "$REPO_ROOT:/repo" -w /repo --entrypoint sh "$GITLEAKS_IMAGE" -c \
	'git config --global --add safe.directory /repo; gitleaks git --redact --exit-code 1 -v .' \
	>"$LOG" 2>&1
status=$?

cat "$LOG"

commits="$(grep -oE '[0-9]+ commits scanned' "$LOG" | grep -oE '[0-9]+' | tail -1)"
bytes="$(grep -oE 'scanned ~[0-9]+ bytes' "$LOG" | grep -oE '[0-9]+' | tail -1)"

if [ -z "$commits" ] || [ -z "$bytes" ]; then
	echo "" >&2
	echo "check-gitleaks-local: couldn't find gitleaks' own \"N commits scanned\" / \"scanned ~N bytes\"" >&2
	echo "lines in its output above — treating that as a failure, not a pass, since this script's" >&2
	echo "whole job is to read those counters." >&2
	exit 1
fi

if [ "$commits" -eq 0 ] || [ "$bytes" -eq 0 ]; then
	echo "" >&2
	echo "check-gitleaks-local: gitleaks scanned $commits commits / $bytes bytes — not a real scan." >&2
	echo "Repo root is: $REPO_ROOT" >&2
	echo "Most likely cause: this clone is not under \$HOME. colima only mounts \$HOME into the" >&2
	echo "docker VM, so gitleaks sees an empty directory and 'passes' having scanned nothing." >&2
	echo "Move the clone under \$HOME and rerun." >&2
	exit 1
fi

if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
	echo "" >&2
	echo "check-gitleaks-local: gitleaks exited $status (neither 0 clean nor 1 findings) — treat as" >&2
	echo "a tool failure, not a clean scan." >&2
	exit 1
fi

echo ""
echo "check-gitleaks-local OK: $commits commits / $bytes bytes actually scanned (exit $status)."
exit "$status"
