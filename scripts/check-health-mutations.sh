#!/bin/sh
# Proves internal/runner/health's guards can fail: in a scratch copy of the
# tree, switch off one check at a time and require the named test to go
# red. A check whose removal leaves that test green is not tested.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
dir=internal/runner/health

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
	elif ! grep -q -- "--- FAIL: $test " "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?)"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

# http check: status and body marker must both be enforced — "200 proves
# nothing" (fleet rule); the marker requirement is what actually proves the
# consumer is healthy, not just that something answered.
mutate http-status-ignored     health.go TestRunHTTPWrongStatus   'if resp.StatusCode != int(h.ExpectStatus) {' 'if false {'
mutate http-marker-ignored     health.go TestRunHTTPRequiresMarker 'return bytes.Contains(body, []byte(marker))' 'return true'

# unit-active: is-active's/list's answer must actually gate the result, on
# both backends — a bypass here would report a crashed consumer as healthy.
mutate systemd-active-ignored  health.go TestUnitActiveDetectsCrashAfterSettle '_, err := r.Run(ctx, []string{"/usr/bin/systemctl", "is-active", name})' '_, err := r.Run(ctx, []string{"/usr/bin/systemctl", "is-active", name}); err = nil'
mutate launchd-state-ignored   health.go TestUnitActiveLaunchdNotRunning 'return bytes.Contains(out, []byte(`"PID" = `))' 'return true'

# Run: a failed restart must short-circuit to HealthFailed, never run the
# check against a consumer that was never actually restarted.
mutate restart-failure-ignored health.go TestRunFailedWhenRestartFails 'if err := restart(ctx, defaultRunner, t.Consumer, t.UID); err != nil {' 'if err := error(nil); err != nil {'

# consumer parsing: an unknown domain must be refused, not silently routed
# to one of the two known argv shapes.
mutate consumer-domain-open    health.go TestSplitConsumerRejectsMalformed 'case "launchd", "systemd":' 'case "launchd", "systemd", domain:'

# Run's own dispatch switch must actually reach the check for the
# configured kind, not just the restart short-circuit and skip paths above.
mutate run-dispatch-broken     health.go TestRunDispatchesUnitActive 'switch h.Kind {' 'switch runnerproto.HealthKind("") {'

# a redirect response must not let a loopback-restricted check follow it
# off the checked host — the client's CheckRedirect must actually refuse.
mutate http-follows-redirect   health.go TestHTTPClientForNeverFollowsRedirect 'return http.ErrUseLastResponse' 'return nil'

# restart's failure path must report only that it failed, never the
# subprocess's own error text — positive control for the leak test below.
mutate restart-error-echoed    health.go TestRestartNeverLeaksSubprocessOutput 'return failed("restart %q: command failed", consumer)' 'return failed("restart %q: %s", consumer, err)'

# isActive's failure paths must report only a bool, never the text of the
# launchctl/systemctl error — one mutation per backend.
mutate launchd-list-error-echoed  health.go TestIsActiveNeverLeaksSubprocessOutput 'return false, nil // not listed' 'return false, fmt.Errorf("list: %s", err) // not listed'
mutate systemd-isactive-error-echoed health.go TestIsActiveNeverLeaksSubprocessOutput 'return err == nil, nil' 'return err == nil, err'

# runHTTP's marker-missing path must report only a bool, never the body it
# just read to check for the marker.
mutate http-body-echoed        health.go TestRunHTTPNeverLeaksBody 'return markerInBody(resp.Body, h.BodyMarker), nil' 'body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodyBytes)); return hasMarker(body, h.BodyMarker), fmt.Errorf("no marker in body: %s", body)'

# The canary detector itself, the same way runnerproto_test.go's
# canary-detector mutation proves TestCanaryNeverInProtocol's own assertion
# actually fires: EmitEvent has no body-shaped parameter for production code
# to leak through today, so this plants a canary directly on the journal
# logger inside the test and requires TestEmitEventNeverLeaksBody's own
# c.In(buf.String()) check to catch it.
mutate emitevent-canary-detector health_test.go TestEmitEventNeverLeaksBody 'EmitEvent(log, out)' 'EmitEvent(log, out); log.Info("deploy.healthcheck", "status", leaked)'

# And the unmutated tree must be green, or every "red" above means nothing.
if mutation_apply_only; then
	:
elif (cd "$root" && go test -count=1 ./$dir/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
