#!/bin/sh
# Infrastructure timeouts must not count as caught mutants. A product-level
# context deadline can be the expected witness of a deliberately broken lock.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

expect() {
	name=$1 want=$2 text=$3
	printf '%s\n' "$text" >"$work/output"
	if mutation_infrastructure_failed "$work/output" >"$work/diagnostic"; then
		got=infrastructure
	else
		got=test
	fi
	if [ "$got" != "$want" ]; then
		echo "FAIL $name: expected $want, got $got"
		exit 1
	fi
	echo "ok   $name"
}

expect ordinary-failure test '--- FAIL: TestGuard'
expect process-timeout infrastructure '--- FAIL: TestGuard
panic: test timed out after 2m0s'
expect scratch-timeout infrastructure '--- FAIL: TestGuard
create scratch database failed (database operation deadline exceeded)'
# The stage that stalled must reach the log: a readiness failure names its
# attempts and budget, and nothing from the DSN.
printf '%s\n' '--- FAIL: TestGuard' '    x_test.go:9: test database not ready after 15 attempts in 1m30s (database operation deadline exceeded)' >"$work/output"
mutation_infrastructure_failed "$work/output" >"$work/diagnostic" || { echo "FAIL stage-line: fault not reported"; exit 1; }
grep -q 'infrastructure stage: .*not ready after 15 attempts in 1m30s' "$work/diagnostic" || { echo "FAIL stage-line: stage not printed"; exit 1; }
# A wrapper may put a DSN in front of the stage text; only the stage text
# from "test database" onward may reach the log.
printf '%s\n' '--- FAIL: TestGuard' '    x_test.go:9: open postgres://u:pwplaceholder@db.invalid:5432/keep: test database not ready after 15 attempts in 1m30s (database operation deadline exceeded)' >"$work/output"
mutation_infrastructure_failed "$work/output" >"$work/diagnostic" || { echo "FAIL stage-line-prefix: fault not reported"; exit 1; }
grep -q 'infrastructure stage: test database not ready after 15 attempts' "$work/diagnostic" || { echo "FAIL stage-line-prefix: stage not printed"; exit 1; }
! grep -q -e 'pwplaceholder' -e 'db.invalid' -e 'postgres://' "$work/diagnostic" || { echo "FAIL stage-line-prefix: prefix reached the log"; exit 1; }
echo "ok   stage-line-prefix"
# Text after the reason class (host, user) must not reach the log either.
printf '%s\n' '--- FAIL: TestGuard' '    x_test.go:9: test database not ready after 15 attempts in 1m30s (database operation deadline exceeded) host=db.invalid user=u' >"$work/output"
mutation_infrastructure_failed "$work/output" >"$work/diagnostic" || { echo "FAIL stage-line-suffix: fault not reported"; exit 1; }
! grep -q -e 'db.invalid' -e 'user=u' "$work/diagnostic" || { echo "FAIL stage-line-suffix: suffix reached the log"; exit 1; }
! grep -q 'infrastructure stage' "$work/diagnostic" || { echo "FAIL stage-line-suffix: stage line of an unknown shape was printed"; exit 1; }
echo "ok   stage-line-suffix"
printf '%s\n' '--- FAIL: TestGuard' 'create scratch database failed (database operation deadline exceeded)' >"$work/output"
mutation_infrastructure_failed "$work/output" >"$work/diagnostic" || exit 1
! grep -q 'infrastructure stage' "$work/diagnostic" || { echo "FAIL stage-line: printed for a line that is not a stage"; exit 1; }
echo "ok   stage-line"
expect database-down infrastructure '--- FAIL: TestGuard
    guard_test.go:9: open migration db: open migration database handle: connection failed (unclassified)'
expect scratch-unreachable infrastructure '--- FAIL: TestGuard
create scratch database failed (unclassified)'
mutation_connect_faults_are_mutants=1
expect connect-fault-is-a-mutant test '--- FAIL: TestOpenRefusesUnsafeQueryExecMode
    store_test.go:9: connection failed (unclassified)'
mutation_connect_faults_are_mutants=0
expect product-deadlock test '--- FAIL: TestChangeLevel
context deadline exceeded'

# CI free-text variables that quote a signature must not reach a child that
# inherits the job environment (MR !170: the MR description tripped the
# classifier). The child echoes them; a real signature line must still fail.
for ci_var in CI_MERGE_REQUEST_DESCRIPTION CI_MERGE_REQUEST_TITLE CI_COMMIT_MESSAGE CI_COMMIT_DESCRIPTION CI_COMMIT_TITLE; do
	(
		export "$ci_var=database operation deadline exceeded; panic: test timed out"
		. "$root/scripts/mutation-helpers.sh"
		sh -c 'echo "--- FAIL: TestGuard"; echo "[$1]"' sh "$(eval "printf %s \"\${$ci_var-}\"")" >"$work/output"
		if mutation_infrastructure_failed "$work/output" >"$work/diagnostic"; then
			echo "FAIL ci-env-$ci_var: classified as infrastructure"
			exit 1
		fi
	)
	echo "ok   ci-env-$ci_var ignored"
done
# The scrub must not mask a real fault: with the variables exported and the
# helpers sourced, a genuine signature line still reports infrastructure.
(
	export CI_MERGE_REQUEST_DESCRIPTION=quoted
	. "$root/scripts/mutation-helpers.sh"
	printf '%s\n' '--- FAIL: TestGuard' 'create scratch database failed (database operation deadline exceeded)' >"$work/output"
	if ! mutation_infrastructure_failed "$work/output" >"$work/diagnostic"; then
		echo "FAIL real-signature-after-scrub: fault not reported"
		exit 1
	fi
)
echo "ok   real-signature-after-scrub"

# A failing package summary is insufficient: the target needs a named test
# failure, and a compiler/setup failure in any package must reject the run.
expect_package_failure() {
	name=$1 want=$2 output=$3
	printf '%s\n' "$output" >"$work/output"
	if mutation_package_test_failed "$work/output" example.invalid/target; then
		got=caught
	else
		got=invalid
	fi
	if [ "$got" != "$want" ]; then
		echo "FAIL $name: expected $want, got $got"
		exit 1
	fi
	echo "ok   $name"
}
target_failure='{"Action":"fail","Package":"example.invalid/target","Test":"TestGuard"}'
expect_package_failure target-test caught "$target_failure"
expect_package_failure other-test invalid '{"Action":"fail","Package":"example.invalid/other","Test":"TestGuard"}'
expect_package_failure package-only invalid '{"Action":"fail","Package":"example.invalid/target"}'
expect_package_failure mixed-build invalid "$target_failure
FAIL example.invalid/other [build failed]"
expect_package_failure mixed-setup invalid "$target_failure
FAIL example.invalid/other [setup failed]"

# Every mutant belongs to exactly one shard; the unsharded run selects all.
for shard in 1 2 3 4; do
	(
		MUTATION_SHARD_INDEX=$shard MUTATION_SHARD_TOTAL=4
		mutation_shard_init
		for mutant in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do
			if mutation_selected; then printf '%s\n' "$mutant"; fi
		done
	) >>"$work/partition"
done
sort -n "$work/partition" >"$work/sorted"
seq 17 >"$work/expected"
cmp "$work/sorted" "$work/expected"
for invalid in '0 4' '5 4' '1 0' 'x 4' '1 2x' '1 2:3' '01 4'; do
	set -- $invalid
	if (MUTATION_SHARD_INDEX=$1 MUTATION_SHARD_TOTAL=$2; mutation_shard_init) >/dev/null 2>&1; then
		echo "FAIL invalid shard accepted"
		exit 1
	fi
done
if (MUTATION_SHARD_INDEX=1 MUTATION_SHARD_TOTAL=1; mutation_shard_init; mutation_shard_finish) >/dev/null 2>&1; then
	echo 'FAIL empty shard accepted'
	exit 1
fi
(MUTATION_SHARD_INDEX=1 MUTATION_SHARD_TOTAL=1; mutation_shard_init; mutation_selected; mutation_selected; mutation_shard_finish)
echo 'ok   shard partition covers every mutant exactly once and rejects invalid shards'

# Test the copier against a tiny fixture, never against machine-wide caches.
root="$work/source"
mkdir -p "$root/scripts" "$root/.git" "$root/.gocache" "$root/.gomodcache" "$root/.artifacts"
printf 'module example.invalid/test\n' >"$root/go.mod"
printf 'source\n' >"$root/scripts/probe.sh"
for dir in .git .gocache .gomodcache .artifacts; do
	printf 'cache\n' >"$root/$dir/marker"
done
mutation_snapshot "$work/copy"
cmp "$root/go.mod" "$work/copy/go.mod"
cmp "$root/scripts/probe.sh" "$work/copy/scripts/probe.sh"
for dir in .git .gocache .gomodcache .artifacts; do
	if [ -e "$work/copy/$dir" ]; then
		echo "FAIL snapshot copied $dir"
		exit 1
	fi
done
echo 'ok   snapshot preserves source and excludes caches'

# Exercise the real Go tool, including output that must stay private. Subtest
# names can contain fixture values, so diagnostics may show top-level names only.
cat >"$root/baseline_test.go" <<'EOF'
package baseline
import (
    "os"
    "testing"
)
func TestBaselinePass(t *testing.T) {}
func TestBaselineFailure(t *testing.T) {
    t.Log(`{"Action":"fail","Test":"TestForged"}`)
    t.Run("diagnostic-output-canary", func(t *testing.T) {
        t.Fatal("diagnostic-output-canary")
    })
}
func TestBaselineTimeout(t *testing.T) {
    t.Log("diagnostic-output-canary")
    select {}
}
func TestBaselineAbruptExit(t *testing.T) {
    t.Log("diagnostic-output-canary")
    os.Exit(2)
}
func TestBaselinePanic(t *testing.T) { panic("diagnostic-output-canary") }
EOF
expect_baseline() {
	name=$1 want=$2 marker=$3
	shift 3
	if mutation_baseline "$@" >"$work/diagnostic" 2>&1; then
		got=green
	else
		got=red
	fi
	if [ "$got" != "$want" ] || ! grep -Fq "$marker" "$work/diagnostic"; then
		echo "FAIL $name: expected $want with safe diagnostic"
		exit 1
	fi
	if grep -q -e 'diagnostic-output-canary' -e 'undefinedDiagnosticOutputCanary' -e 'TestForged' "$work/diagnostic"; then
		echo "FAIL $name: raw test output or subtest name escaped"
		exit 1
	fi
	echo "ok   $name"
}
expect_baseline baseline-green green 'ok   baseline: tests green on the real code' -timeout 10s -run '^TestBaselinePass$' .
expect_baseline baseline-test-failure red 'FAIL baseline test: TestBaselineFailure' -timeout 10s -run '^TestBaselineFailure$' .
grep -Fq 'FAIL baseline: go test exited 1' "$work/diagnostic"
if grep -Fq 'FAIL baseline: no named test failure recorded' "$work/diagnostic"; then
	echo 'FAIL baseline-test-failure: unexpected unnamed failure diagnostic'
	exit 1
fi
expect_baseline baseline-timeout red 'FAIL baseline: test timeout' -timeout 1s -run '^TestBaselineTimeout$' .
grep -Fq 'FAIL baseline active test: TestBaselineTimeout' "$work/diagnostic"
# An abrupt process exit has a run event but no named test failure event.
expect_baseline baseline-abrupt-exit red 'FAIL baseline: no named test failure recorded' -timeout 10s -run '^TestBaselineAbruptExit$' .
grep -Fq 'FAIL baseline active test: TestBaselineAbruptExit' "$work/diagnostic"
expect_baseline baseline-panic red 'TestBaselinePanic' -timeout 10s -run '^TestBaselinePanic$' .
printf '\nvar _ = undefinedDiagnosticOutputCanary\n' >>"$root/baseline_test.go"
expect_baseline baseline-build-failure red 'FAIL baseline: build/setup failure' -timeout 10s .
