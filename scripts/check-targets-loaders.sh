#!/bin/sh
# Runs the three internal/targets tests that skip on an ordinary host and
# fails unless each of them really ran and passed:
#
#   TestHermesConfigReadableByHermesLoader      needs KEEP_HERMES_PYTHON (a venv
#   TestHermesConfigRefusesEveryKnownKeyInValue  with python-dotenv and hermes_cli)
#   TestSystemdCredentialWithBinary             needs a trusted /usr/bin/systemd-creds
#
# `go test` prints a plain "ok" for a package whose tests all skipped, so the
# job that is meant to exercise those loaders would stay green with no loader
# in the image. Here a SKIP, a missing PASS line or a missing test is a
# failure. `--selftest` proves it: with the Hermes interpreter withheld the
# run must fail on the SKIP, and the script exits 0 only if it did.
#
# The output carries test names and verdicts only; it never prints the
# environment or a value.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root" || exit 2

tests="TestHermesConfigReadableByHermesLoader TestHermesConfigRefusesEveryKnownKeyInValue TestSystemdCredentialWithBinary TestTargetsAttack_HermesDifferentialLoader"

if [ "${1:-}" = "--selftest" ]; then
	if env -u KEEP_HERMES_PYTHON "$0" >/dev/null 2>&1; then
		echo "check-targets-loaders --selftest: the check passed with no Hermes interpreter; it cannot fail" >&2
		exit 1
	fi
	echo "check-targets-loaders --selftest: red without KEEP_HERMES_PYTHON, as required"
	exit 0
fi

if [ -z "${KEEP_HERMES_PYTHON:-}" ]; then
	echo "check-targets-loaders: KEEP_HERMES_PYTHON is not set (the Hermes loader tests would SKIP)" >&2
	exit 1
fi

log=$(mktemp)
trap 'rm -f "$log"' EXIT INT TERM

run=$(printf '^(%s)$' "$(echo "$tests" | sed 's/ /|/g')")
go test -count=1 -v -run "$run" ./internal/targets/ >"$log" 2>&1
status=$?
# Verdict lines only: -v also prints test logs, which are not needed here.
grep -E '^(--- (PASS|FAIL|SKIP)|FAIL|ok|panic)' "$log"

fail=0
if [ "$status" -ne 0 ]; then
	echo "check-targets-loaders: go test exited $status" >&2
	fail=1
fi
for t in $tests; do
	if grep -q -- "^--- SKIP: $t " "$log"; then
		echo "check-targets-loaders: $t SKIPPED" >&2
		fail=1
	elif ! grep -q -- "^--- PASS: $t " "$log"; then
		echo "check-targets-loaders: $t has no PASS line" >&2
		fail=1
	fi
done
n=$(grep -c -- '--- SKIP' "$log")
echo "check-targets-loaders: SKIP count = $n"
[ "$n" -eq 0 ] || fail=1
exit "$fail"
