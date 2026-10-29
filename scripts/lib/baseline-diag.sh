# Sourced by mutation checks. baseline_diagnose <go-test-log> <rc> prints why a
# baseline `go test -v` run was red or skipped: the class and the names of the
# tests, plus file:line of failed assertions. Message text is never printed,
# because a test message could quote a value; names and locations cannot.
#
# A test message is attacker-shaped text: it can span lines and imitate any
# line `go test -v` prints. So only lines a message cannot produce are read:
# `--- FAIL|SKIP:` at column 0 (a message line is always indented), names of
# the top-level test only (subtest names are free text: only their count is
# printed), `file.go:N:` at exactly four spaces (a continuation line of a
# message is indented deeper), and `running tests:` only after the line
# `panic: test timed out`. Every printed token is matched against a closed
# character set.
baseline_diagnose() {
	log=$1
	rc=$2
	if grep -q -- '--- FAIL' "$log"; then
		class=fail
	elif grep -q -- '--- SKIP' "$log"; then
		class=skip
	elif grep -q 'panic: test timed out' "$log"; then
		class='timeout (go test deadline)'
	elif grep -q '^panic:' "$log"; then
		class=panic
	elif grep -q '^FAIL.*\[build failed\]\|^# ' "$log"; then
		class=build-fail
	else
		class="exit $rc, no named test"
	fi
	echo "     baseline class: $class (go test exit $rc)"
	sed -n -E 's/^--- (FAIL|SKIP): ((Test|Example|Fuzz|Benchmark)[A-Za-z0-9_]*) \([0-9.]+s\)$/     --- \1: \2/p' "$log" | sort -u | head -20
	subs=$(grep -c -E '^[[:space:]]+--- (FAIL|SKIP): ' "$log" || true)
	[ "${subs:-0}" -eq 0 ] || echo "     subtests failed or skipped: $subs"
	awk '/^panic: test timed out/ {armed=1; next} armed && /^[[:space:]]*running tests:$/ {on=1; next} on && /^[[:space:]]+(Test|Fuzz|Benchmark)[A-Za-z0-9_]* \([0-9.hms]+\)$/ {print "     running " $1; next} {on=0}' "$log" | sort -u | head -5
	sed -n -E 's/^    ([A-Za-z0-9_]+\.go):([0-9]+): .*/     at \1:\2/p' "$log" | sort -u | head -12
	sed -n -E 's/^(FAIL|ok)[[:space:]]+([A-Za-z0-9_.\/-]+)[[:space:]]+([0-9.]+s|\[build failed\]|\(cached\))$/     package \2: \1/p' "$log" | head -5
	sed -n -E 's/^# ([A-Za-z0-9_.\/-]+)$/     build \1/p' "$log" | head -3
}
