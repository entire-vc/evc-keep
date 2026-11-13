#!/bin/sh
# Proves the console exec-card predicate can fail: in a scratch copy of the
# tree, break it (or the exec view it guards) one way at a time and require
# TestExecCardPredicateIgnoresUUIDWithZeros to go red, and green without it.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
test=TestExecCardPredicateIgnoresUUIDWithZeros

fail=0
mutate() {
	name=$1 file=$2 from=$3 to=$4
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$file" >"$work/tree/$file"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -count=1 -run "^$test\$" ./internal/api/ >"$work/out" 2>&1); then
		echo "FAIL $name: $test stayed green with the guard broken"
		fail=1
	elif ! grep -q -- "--- FAIL: $test " "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?)"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

# Baseline: the untouched tree must be green, or every red above is noise.
if ! mutation_apply_only; then
	if (cd "$root" && go test -count=1 -v -run "^$test\$" ./internal/api/ >"$work/base" 2>&1) && grep -q -- "^--- PASS: $test " "$work/base" && ! grep -q -- "SKIP" "$work/base"; then
		echo "ok   baseline: $test green on the real code, none skipped"
	else
		echo "FAIL baseline: $test is not green on the clean tree"
		cat "$work/base"
		fail=1
	fi
fi

test_file=internal/api/console_test.go
# the old global substring check comes back
mutate predicate-bare-0000   $test_file 'func hasDeploymentTargetRows(body string) bool { return deploymentTargetRow.MatchString(body) }' 'func hasDeploymentTargetRows(body string) bool { return strings.Contains(body, "0000") || strings.Contains(body, "uid / gid") }'
# the predicate never fires (blind to real rows)
mutate predicate-always-false $test_file 'func hasDeploymentTargetRows(body string) bool { return deploymentTargetRow.MatchString(body) }' 'func hasDeploymentTargetRows(body string) bool { return false }'
# real deployment target rows leak into the exec view
mutate exec-view-shows-rows  internal/api/console.go 'if e := a.Exec; e != nil {' 'if e := a.Exec; e != nil && false {'

exit $fail
