#!/bin/sh
# Concurrent answers to one mesh gate on a real PostgreSQL, three runs:
#  1. without the Settle slot bound the test hangs; a goroutine dump taken at
#     the process timeout names where (lock holder in pgxpool Acquire, the rest
#     in Postgres on the gate row lock);
#  2. with exactly-once switched off the test goes red in time, also under
#     -cpu 1 -count=20, never at the process timeout;
#  3. unmutated, -race -count=50 stays green with no skip.
# Prints only declared test names, outcomes, counts and code frames, never a
# line of go test output (scripts/test-result-names.sh).
# Needs a real PostgreSQL: KEEP_DATABASE_URL.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
: "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must name disposable PostgreSQL}"

pkg=./internal/deployment
test=TestGateConcurrentAnswersApplyOnce
limit=60
fail=0
echo "sha=${CI_COMMIT_SHA:-$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)} start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# patch FILE FROM TO [FILE2 FROM2 TO2]: replace one literal in the scratch tree.
patch() {
	python3 - "$work/tree" "$@" <<'PY'
import sys
tree, rest = sys.argv[1], sys.argv[2:]
for i in range(0, len(rest), 3):
    p, a, b = tree + '/' + rest[i], rest[i + 1], rest[i + 2]
    s = open(p).read()
    if s.count(a) < 1:
        sys.exit(1)
    open(p, 'w').write(s.replace(a, b, 1))
PY
}

fresh_tree() {
	mutation_snapshot "$work/tree"
}

# shown N MAX: a count taken from the log, printed no larger than MAX
# ("MAX+"), so the number of forged lines carries no more than the bound.
shown() {
	if [ "$1" -gt "$2" ]; then echo "$2+"; else echo "$1"; fi
}

# 1. Slot bound off: the waiting answers take every connection and the holder
# of the row lock waits for one. The process timeout comes before the test's
# own 20 s bound, so the runtime dumps every goroutine.
fresh_tree
if ! patch internal/meshgate/pgstore.go '	case p.settleSlots <- struct{}{}:' '	default:' \
	internal/meshgate/pgstore.go '	defer func() { <-p.settleSlots }()' ''; then
	echo "FAIL dump: mutation did not apply, update this script"
	exit 1
fi
if (cd "$work/tree" && go test -count=1 -p 1 -timeout 12s -run "^$test\$" "$pkg" >"$work/dump" 2>&1); then
	echo "FAIL dump: $test passed without the slot bound"
	fail=1
elif ! grep -q 'panic: test timed out' "$work/dump"; then
	echo "FAIL dump: no hang without the slot bound"
	"$root/scripts/test-result-names.sh" "$work/tree" <"$work/dump" ||
		echo "FAIL diagnostics: test-result-names.sh exited $?"
	fail=1
else
	holder=$(grep -c 'pgxpool.(\*Pool).Acquire' "$work/dump" || true)
	settle=$(grep -c 'meshgate.(\*PG).Settle' "$work/dump" || true)
	echo "dump: panic: test timed out; goroutines in pgxpool.(*Pool).Acquire=$(shown "$holder" 40), frames of meshgate.(*PG).Settle=$(shown "$settle" 40)"
	# Code frames only: function and file:line of this repo (under the tree)
	# and of pgx (in the module cache); no header text, no arguments.
	"$root/scripts/test-result-names.sh" --goroutines "$work/tree" <"$work/dump" ||
		echo "FAIL diagnostics: test-result-names.sh exited $?"
	if [ "$holder" -lt 1 ] || [ "$settle" -lt 1 ]; then
		echo "FAIL dump: the hang is not where the fix says (Acquire under Settle)"
		fail=1
	fi
fi

# 2. Exactly-once off: red in time, one CPU, twenty runs.
fresh_tree
if ! patch internal/meshgate/meshgate.go '		case g.Status != "pending":' '		case false:' \
	internal/deployment/approval.go '	if status != "requested" {' '	if false {'; then
	echo "FAIL exactly-once-off: mutation did not apply, update this script"
	exit 1
fi
if (cd "$work/tree" && go test -v -count=20 -cpu 1 -p 1 -timeout 240s -run "^$test\$" "$pkg" >"$work/mutant" 2>&1); then
	echo "FAIL exactly-once-off: $test stayed green"
	fail=1
fi
"$root/scripts/test-result-names.sh" "$work/tree" <"$work/mutant" ||
	echo "FAIL diagnostics: test-result-names.sh exited $?"
if mutation_infrastructure_failed "$work/mutant"; then
	fail=1
fi
reds=$(grep -c -- "^--- FAIL: $test " "$work/mutant" || true)
slow=$(sed -n "s/^--- FAIL: $test (\([0-9.]*\)s)\$/\1/p" "$work/mutant" | awk -v l="$limit" '$1 > l' | wc -l | tr -d ' ')
# The longest red run, recomputed and bounded: never a field copied from the log.
max=$(sed -n "s/^--- FAIL: $test (\([0-9.]*\)s)\$/\1/p" "$work/mutant" |
	awk 'BEGIN { m = -1 } { if ($1 + 0 > m) m = $1 + 0 } END { if (m < 0) print "none"; else if (m > 999) print ">999"; else printf "%.2f", m }')
echo "exactly-once-off -cpu 1 -count=20: red=$(shown "$reds" 20)/20 max=${max}s over_${limit}s=$(shown "$slow" 20)"
if [ "$reds" -ne 20 ] || [ "$slow" -ne 0 ]; then
	echo "FAIL exactly-once-off: want 20 red runs each within ${limit}s"
	fail=1
fi

# 3. Unmutated: fifty green runs under the race detector, no skip.
if ! (cd "$root" && go test -race -v -count=50 -p 1 -timeout 600s -run "^$test\$" "$pkg" >"$work/race" 2>&1); then
	echo "FAIL race: $test went red unmutated"
	"$root/scripts/test-result-names.sh" "$root" <"$work/race" ||
		echo "FAIL diagnostics: test-result-names.sh exited $?"
	fail=1
fi
pass=$(grep -c -- "^--- PASS: $test " "$work/race" || true)
skip=$(grep -c -- "^--- SKIP" "$work/race" || true)
"$root/scripts/test-result-names.sh" "$root" <"$work/race" ||
	echo "FAIL diagnostics: test-result-names.sh exited $?"
echo "race -count=50: pass=$(shown "$pass" 50)/50 skip=$(shown "$skip" 40)"
if [ "$pass" -ne 50 ] || [ "$skip" -ne 0 ]; then
	echo "FAIL race: want 50 passes and no skip"
	fail=1
fi

echo "end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
exit "$fail"
