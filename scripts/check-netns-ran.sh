#!/usr/bin/env sh
# Usage: check-netns-ran.sh <go test -v log> [allowlist]
# The netns tests are allowed to SKIP in the shared test job only because the
# netns-tests job runs them. This proves it: every allowlisted test named
# TestNetns* / TestRunWithRealIsolator* must show "--- PASS" in the netns log,
# and no test may show "--- SKIP" or "--- FAIL". Only test names are printed.
set -u
log="${1:?usage: check-netns-ran.sh <log> [allowlist]}"
allow="${2:-$(dirname "$0")/allowed-skips.txt}"
[ -r "$log" ] && [ -r "$allow" ] || { echo "check-netns-ran: log or allowlist unreadable" >&2; exit 1; }
names=$(awk '/^(TestNetns|TestRunWithRealIsolator)/ {print $1}' "$allow")
[ -n "$names" ] || { echo "check-netns-ran: no netns tests in the allowlist" >&2; exit 1; }
rc=0
if grep -q -e '--- SKIP' "$log"; then
	echo "check-netns-ran: skipped in the netns job:" >&2
	grep -e '--- SKIP' "$log" | awk '{print $3}' >&2
	rc=1
fi
if grep -q -e '--- FAIL' "$log"; then
	echo "check-netns-ran: failed in the netns job:" >&2
	grep -e '--- FAIL' "$log" | awk '{print $3}' >&2
	rc=1
fi
for n in $names; do
	grep -q -e "--- PASS: $n " "$log" || { echo "check-netns-ran: not passed: $n" >&2; rc=1; }
done
[ "$rc" -eq 0 ] && echo "check-netns-ran: all $(echo "$names" | wc -w | tr -d ' ') netns tests passed, 0 skipped"
exit "$rc"
