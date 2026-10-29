#!/usr/bin/env sh
# W2 acceptance on the Linux stand: input link -> browser -> keep deploy ->
# runner placement, with the CLI run as a separate user "agent" and a
# headless Chromium as the human. Every part is mandatory: a missing
# browser, Node, database or agent account fails the run, and a skipped
# subtest is a failure, not a pass.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

fail() { echo "FAIL e2e-w2: $1" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || fail "needs the Linux stand (uid/gid checks need a second account)"
[ -n "${KEEP_DATABASE_URL:-}" ] || fail "KEEP_DATABASE_URL is not set"
id agent >/dev/null 2>&1 || fail "user \"agent\" does not exist"
command -v node >/dev/null 2>&1 || fail "node is required"
if [ -z "${CHROME_BIN:-}" ]; then
	for c in /usr/bin/chromium /usr/bin/chromium-browser /usr/bin/google-chrome; do
		[ -x "$c" ] && CHROME_BIN=$c && break
	done
fi
[ -n "${CHROME_BIN:-}" ] || fail "headless Chromium is required"
export CHROME_BIN
[ "$(id -u)" -eq 0 ] && export KEEP_E2E_NO_SANDBOX=1

log=$(mktemp)
trap 'rm -f "$log"' EXIT INT TERM
set +e
go test -tags e2e -count=1 -v -timeout 10m ./test/e2e >"$log" 2>&1
status=$?
set -e
grep -E '^\s*(---|ok|FAIL|PASS)' "$log" || true
[ "$status" -eq 0 ] || { tail -40 "$log"; fail "go test exited $status"; }
if grep -q -- '--- SKIP' "$log"; then fail "a subtest was skipped; SKIP is not PASS"; fi
n=$(grep -c -- '--- PASS: TestW2InputLinkToRunnerPlacement/forbidden_targets/agent-readable_path' "$log" || true)
[ "$n" -ge 2 ] || fail "the agent-readable path cases did not both pass (passed: $n)"
echo "PASS e2e-w2"
