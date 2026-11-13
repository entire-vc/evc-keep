#!/bin/sh
# Proves TestListeningLogMeansSocketsAreBound can fail: in a scratch copy of
# the tree, log the "listening" line before the sockets are bound and require
# the test to go red. The test retries a serveBoth that exits early (a lost
# port race), so this also proves that retry does not hide the real defect.
# Exits 0 only if the mutation is caught and the real code is green.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace
pkg=cmd/keep-server/app
src=$pkg/main.go
run='TestListeningLogMeansSocketsAreBound'

fail=0
# log-before-bind: move the announcement above the first net.Listen.
name=log-before-bind
rm -rf "$work/tree"
mutation_snapshot "$work/tree"
logpat='logger\.Info\(fmt\.Sprintf\("keep-server listening on'
logline=$(grep -E "$logpat" "$root/$src" || true)
# Two passes: the log line sits after the binds, so read it first, then drop the
# original and print it once, right before the first net.Listen of serveBoth.
if [ "$(printf '%s\n' "$logline" | grep -c .)" != 1 ]; then
	echo "FAIL $name: expected exactly one listening log line in $src — the source changed, update this script"
	fail=1
elif ! awk -v held="$logline" '
	index($0, "keep-server listening on") { next }
	/^func serveBoth\(/ { infn = 1 }
	infn && !done && /net\.Listen\(/ { print held; done = 1 }
	{ print }
	END { exit !done }' "$root/$src" >"$work/tree/$src"; then
	echo "FAIL $name: mutation did not apply — the source changed, update this script"
	fail=1
elif [ "$(grep -cE "$logpat" "$work/tree/$src")" != 1 ] ||
	[ "$(grep -nE "$logpat" "$work/tree/$src" | cut -d: -f1)" -ge "$(grep -n 'net\.Listen(' "$work/tree/$src" | awk -F: -v s="$(grep -n '^func serveBoth(' "$work/tree/$src" | cut -d: -f1)" '$1>s{print $1; exit}')" ]; then
	echo "FAIL $name: mutant is malformed — the log must be kept once and sit before the first bind"
	fail=1
elif ! mutation_applied "$name"; then
	if (cd "$work/tree" && go test -timeout 120s -count=1 -run "$run" ./$pkg/ >"$work/out" 2>&1); then
		echo "FAIL $name: test stayed green with the log before the bind"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- "--- FAIL: $run" "$work/out"; then
		echo "FAIL $name: mutant did not reach the failing test (build error?)"
		fail=1
	else
		echo "ok   $name: $run went red"
	fi
fi

if mutation_apply_only; then
	:
elif ! (cd "$root" && go test -v -timeout 120s -count=1 -run "$run" ./$pkg/ >"$work/base" 2>&1); then
	echo "FAIL baseline: test is red on the real code"
	fail=1
elif ! grep -q -- "--- PASS: $run" "$work/base" || grep -q -- '--- SKIP' "$work/base"; then
	echo "FAIL baseline: test did not run to a pass (skipped or not found)"
	fail=1
else
	echo "ok   baseline: $run green on the real code, none skipped"
fi

exit $fail
