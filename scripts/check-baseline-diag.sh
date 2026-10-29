#!/bin/sh
# Proves baseline_diagnose names the failing test for each class of red
# baseline and never prints message text (a planted value must not appear).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/baseline-diag.sh"
dir=$(mktemp -d "${TMPDIR:-/tmp}/baseline-diag.XXXXXXXX")
trap 'find "$dir" -delete' EXIT INT TERM
fail=0
canary=CANARY-3f9a1c7e5b
expect() { # name log rc want...
	name=$1; log=$2; rc=$3; shift 3
	out=$(baseline_diagnose "$log" "$rc")
	for w in "$@"; do
		case $out in *"$w"*) ;; *) echo "FAIL $name: missing '$w'"; echo "$out"; fail=1; return;; esac
	done
	case $out in *"$canary"*) echo "FAIL $name: message text leaked"; fail=1; return;; esac
	echo "ok   $name"
}
printf '=== RUN   TestA\n    store_test.go:42: got %s want x\n--- FAIL: TestA (0.10s)\nFAIL\nFAIL\texample/pkg\t1.2s\n' "$canary" >"$dir/fail"
expect red "$dir/fail" 1 'class: fail' '--- FAIL: TestA' 'at store_test.go:42' 'package example/pkg: FAIL'
printf '=== RUN   TestB\n    b_test.go:7: needs db %s\n--- SKIP: TestB (0.00s)\nPASS\nok  \texample/pkg\t1.0s\n' "$canary" >"$dir/skip"
expect skip "$dir/skip" 0 'class: skip' '--- SKIP: TestB' 'at b_test.go:7'
printf 'panic: test timed out after 2m0s\n\trunning tests:\n\t\tTestC (2m0s)\nFAIL\texample/pkg\t120.0s\n' >"$dir/timeout"
expect timeout "$dir/timeout" 1 'timeout (go test deadline)' 'running TestC'
printf '# example/pkg\nx.go:3:1: undefined: %s\nFAIL\texample/pkg [build failed]\n' "$canary" >"$dir/build"
expect build "$dir/build" 1 'class: build-fail' 'build example/pkg'
printf 'ok  \texample/pkg\t1.0s\n' >"$dir/green"
out=$(baseline_diagnose "$dir/green" 0)
case $out in *'--- FAIL'*|*'--- SKIP'*) echo "FAIL green: names a test"; fail=1;; *) echo "ok   green: no test named";; esac

# The same helper on the output of a real `go test -v` over planted tests.
go_expect() { # name want... ; tests come from $dir/mod/planted_test.go
	name=$1; shift
	rc=0
	(cd "$dir/mod" && go test -v -count=1 -timeout "${GO_TIMEOUT:-60s}" ./... >"$dir/real" 2>&1) || rc=$?
	if [ "$name" = green ]; then
		[ "$rc" -eq 0 ] || { echo "FAIL real-$name: go test rc=$rc"; fail=1; return; }
	else
		[ "$rc" -ne 0 ] || [ "$name" = skip ] || { echo "FAIL real-$name: planted test did not fail"; fail=1; return; }
	fi
	expect "real-$name" "$dir/real" "$rc" "$@"
}
mkdir "$dir/mod"
printf 'module example.test/planted\n\ngo 1.21\n' >"$dir/mod/go.mod"
printf 'package planted\n\nimport "testing"\n\nfunc TestPlantedRed(t *testing.T) { t.Fatalf("value %%s", "%s") }\n' "$canary" >"$dir/mod/planted_test.go"
go_expect red 'class: fail' '--- FAIL: TestPlantedRed' 'at planted_test.go:5'
printf 'package planted\n\nimport "testing"\n\nfunc TestPlantedSkip(t *testing.T) { t.Skip("db %s") }\n' "$canary" >"$dir/mod/planted_test.go"
go_expect skip 'class: skip' '--- SKIP: TestPlantedSkip' 'at planted_test.go:5'
printf 'package planted\n\nimport (\n\t"testing"\n\t"time"\n)\n\nfunc TestPlantedSlow(t *testing.T) { time.Sleep(time.Minute) }\n' >"$dir/mod/planted_test.go"
GO_TIMEOUT=1s go_expect timeout 'timeout (go test deadline)' 'running TestPlantedSlow'
printf 'package planted\n\nimport "testing"\n\nfunc TestPlantedOK(t *testing.T) {}\n' >"$dir/mod/planted_test.go"
go_expect green 'package example.test/planted: ok'

# Message text that imitates what `go test -v` prints: a multi-line message
# faking a result line, a skip line or a location, and a subtest whose name is
# free text. The marker is in the raw output (positive control) and must not
# be in the diagnosis, while the failing top-level test is still named.
probe_expect() { # name go-test-body
	name=$1; body=$2
	m=probe7c1e5a9d3b2f4a60
	printf 'package planted\n\nimport "testing"\n\nfunc TestProbe(t *testing.T) { %s }\n' "$body" >"$dir/mod/planted_test.go"
	rc=0
	(cd "$dir/mod" && go test -v -count=1 -timeout 60s ./... >"$dir/real" 2>&1) || rc=$?
	grep -q "$m" "$dir/real" || { echo "FAIL probe-$name: positive control, go test did not print the marker"; fail=1; return; }
	out=$(baseline_diagnose "$dir/real" "$rc")
	case $out in *"$m"*) echo "FAIL probe-$name: marker leaked into the diagnosis"; echo "$out"; fail=1; return;; esac
	case $out in *TestProbe*) echo "ok   probe-$name";; *) echo "FAIL probe-$name: failing test not named"; fail=1;; esac
}
probe_expect message 't.Fatalf("value %s", "probe7c1e5a9d3b2f4a60")'
probe_expect multiline-fail 't.Fatalf("value\n--- FAIL: %s", "probe7c1e5a9d3b2f4a60")'
probe_expect multiline-skip 't.Skipf("value\n--- SKIP: %s", "probe7c1e5a9d3b2f4a60")'
probe_expect multiline-location 't.Fatalf("value\n    %s.go:42: detail", "probe7c1e5a9d3b2f4a60")'
probe_expect dynamic-subtest 't.Run("probe7c1e5a9d3b2f4a60", func(t *testing.T) { t.Fatal("failed") })'
probe_expect multiline-running 't.Fatalf("value\nrunning tests:\n\t%s (1s)", "probe7c1e5a9d3b2f4a60")'

# The builtin check must run the helper whenever its baseline is red or skipped.
if grep -q '^\. "\$root/scripts/lib/baseline-diag.sh"' "$root/scripts/check-builtin-mutations.sh" &&
	grep -q '^	baseline_diagnose "\$work/baseline" "\$baseline_rc"$' "$root/scripts/check-builtin-mutations.sh"; then
	echo "ok   check-builtin-mutations.sh runs baseline_diagnose on a red or skipped baseline"
else
	echo "FAIL check-builtin-mutations.sh does not call baseline_diagnose"; fail=1
fi
exit $fail
