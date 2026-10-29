#!/bin/sh
# Proves the test-database readiness wait in internal/testutil/pgscratch can
# fail: in a scratch copy of the tree, switch off one property at a time and
# require the named test to go red.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
dir=internal/testutil/pgscratch

fail=0
mutate() {
	name=$1 file=$2 test=$3 from=$4 to=$5 nth=${6:-1}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" -v nth="$nth" '
		!done && (i = index($0, from)) && ++seen == nth { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$file" >"$work/tree/$file"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -count=1 "./$(dirname "$file")/" >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the check switched off"
		fail=1
	elif ! grep -q -- "--- FAIL: $test" "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?)"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

# A server that answers late is waited for, not failed on.
mutate no-retry $dir/ready.go TestConnectWithRetryRidesOutLateServer 'if !transient(last) {' 'if true {'
# Rejected credentials are final: waiting does not heal them.
mutate retry-everything $dir/ready.go TestConnectWithRetryDoesNotRetryRejectedCredentials 'if !transient(last) {' 'if false {'
# The give-up text names what expired and never repeats the DSN.
mutate dsn-in-failure $dir/ready.go TestConnectWithRetryGivesUpWithClearReason 'attempts, budget, reason(last))' 'attempts, budget, last)'
# The scratch-database entry point waits before its first statement.
mutate new-skips-wait $dir/pgscratch.go TestNewWaitsForLateServer 'WaitReady(t)' 't.Helper()'
mutate newrole-skips-wait $dir/pgscratch.go TestNewRoleWaitsForLateServer 'WaitReady(t)' 't.Helper()' 2
# Retries are paced and bounded by the budget.
mutate no-pause $dir/ready.go TestConnectWithRetryGivesUpWithClearReason 'time.Sleep(interval)' '_ = interval'
mutate unbounded-budget $dir/ready.go TestConnectWithRetryGivesUpWithClearReason 'if time.Now().Add(interval).After(deadline) {' 'if time.Now().Add(interval).After(deadline.Add(time.Hour)) {'
# attackDB waits for the database before it opens a pool.
mutate attackdb-skips-wait test/security/identity_attack_test.go TestAttackDBWaitsForTheDatabase 'pgscratch.WaitReady(t)' '_ = pgscratch.WaitReady'
# Each new scratch database is warmed before its DSN is handed out.
mutate warm-failure-swallowed $dir/pgscratch.go TestWarmUpFailsWhenWarmFails 'if err := warm(dsn, warmBudget, readyInterval); err != nil {' 'if err := warm(dsn, warmBudget, readyInterval); false && err != nil {'
mutate warm-budget-zero $dir/ready.go TestWarmUpFailsWhenWarmFails 'warmBudget    = 30 * time.Second' 'warmBudget    = 0'
mutate warm-skipped $dir/pgscratch.go TestNewWarmsTheScratchDatabase 'if err := warm(dsn, warmBudget, readyInterval); err != nil {' 'if err := error(nil); err != nil {'
# One outcome per process, failure included, and it is raised to every caller.
mutate cache-ignored $dir/ready.go TestWaitReadyCachesItsOutcome 'if !ready.done {' 'if true {'
mutate failure-swallowed $dir/ready.go TestWaitReadyCachesItsOutcome 'if ready.err != nil {' 'if false {'
# Only dial, timeout and startup failures count as "not ready yet".
mutate startup-sqlstate-dropped $dir/ready.go TestTransientClassification 'return pgErr.Code == "57P03" || (len(pgErr.Code) == 5 && pgErr.Code[:2] == "08")' 'return false'
mutate network-dropped $dir/ready.go TestTransientClassification 'if errors.As(err, &netErr) {' 'if errors.As(err, &netErr) && false {'
# A refusal never repeats the DSN either.
mutate dsn-in-refusal $dir/ready.go TestConnectWithRetryDoesNotRetryRejectedCredentials '"test database refused the connection (%s)", reason(last))' '"test database refused the connection (%s)", last)'

if mutation_apply_only; then
	:
elif (cd "$root" && go test -count=1 ./$dir/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
