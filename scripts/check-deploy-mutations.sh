#!/bin/sh
# Proves internal/runner/deploy's guards can fail: in a scratch copy of the
# tree, switch off one step at a time and require the named test to go red.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
dir=internal/runner/deploy

fail=0
mutate() {
	name=$1 file=$dir/$2 test=$3 from=$4 to=$5
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
	if (cd "$work/tree" && go test -count=1 ./$dir/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the check switched off"
		fail=1
	elif ! grep -q -- "--- FAIL: $test" "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?)"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

# The host policy gate comes before any write or restart.
mutate policy-check-skipped deploy.go TestApplyRefusedJobTouchesNothing 'if err := runnerproto.Check(j, p); err != nil {' 'if err := error(nil); err != nil {'
# Only a deploy job is applied.
mutate action-unchecked deploy.go TestApplyRefusedJobTouchesNothing 'if j.Action != runnerproto.ActionDeploy {' 'if false {'
# A failed healthcheck is ok=false.
mutate failed-check-reported-ok deploy.go TestApplyFailedHealthcheckIsNotOK 'res.OK, res.ErrorClass = false, runnerproto.ErrClassHealthcheck' 'res.OK, res.ErrorClass = true, ""'
# A kind-less failure has no healthcheck object.
mutate kindless-failure-kept deploy.go TestApplyRestartFailedWithoutKind 'if out.Kind != "" {' 'if true {'
# No consumer: no restart, no check.
mutate consumer-less-restarted deploy.go TestApplyNoConsumerSkipsRestart 'if j.Target.Consumer == "" {' 'if false {'
# The last gate on the Result.
mutate result-gate-removed deploy.go TestApplyOutsideContractNeverLeavesApply 'if r.Validate() != nil {' 'if false {'
# The leak test must see a value in the log: plant one.
mutate value-in-log deploy.go TestApplyNeverLeaksValue 'health.EmitEvent(d.Log, out)' 'health.EmitEvent(d.Log, out); secret.Expose(v, func(b []byte) { d.Log.Info("deploy.healthcheck", "status", string(b)) })'

if mutation_apply_only; then
	:
elif (cd "$root" && go test -count=1 ./$dir/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
