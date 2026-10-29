#!/bin/sh
# Named behavioral witnesses for process-wide capture. Never print captured
# bytes: even a deliberately broken provider may put its value there.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
dir=pkg/provider/providertest
fail=0
mutate() {
	name=$1 test=$2 from=$3 to=$4
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! python3 - "$work/tree/$dir/providertest.go" "$from" "$to" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
s = p.read_text()
if s.count(sys.argv[2]) != 1:
    raise SystemExit("mutation source must match exactly once")
p.write_text(s.replace(sys.argv[2], sys.argv[3], 1))
PY
	then
		echo "FAIL $name: mutation did not apply - the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && GORACE="log_path=$work/race" go test -race -count=1 -timeout 20s -run "^$test$" ./$dir/ >"$work/out" 2>&1); then
		echo "FAIL $name: witness stayed green"
		fail=1
	elif ! grep -q -- "--- FAIL: $test " "$work/out"; then
		echo "FAIL $name: no named behavioral failure"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

mutate pipe-runs-unprotected TestRunOne_SetupFailureDoesNotRunProvider '
	r, w, err := pipe()
	if err != nil {
		return "", false
	}' '
	r, w, err := pipe()
	if err != nil {
		fn()
		return "", false
	}'
mutate fd1-runs-unprotected TestRunOne_SetupFailureDoesNotRunProvider '
	restoreOut, err := redirect(1, w)
	if err != nil {
		_ = w.Close()' '
	restoreOut, err := redirect(1, w)
	if err != nil {
		fn()
		_ = w.Close()'
mutate fd2-runs-unprotected TestRunOne_SetupFailureDoesNotRunProvider '
	restoreErr, err := redirect(2, w)
	if err != nil {
		_ = restoreOut()' '
	restoreErr, err := redirect(2, w)
	if err != nil {
		fn()
		_ = restoreOut()'
mutate capture-fails-open TestRunOne_CaptureFailureIsViolation 'if !capturedOK {' 'if false && !capturedOK {'
mutate capture-failure-skips TestRunOne_CaptureFailureOverridesSkip 'e.skipped = ""' '_ = e.skipped'
mutate capture-leak-skips TestRunOne_LeakOverridesSkip 'e.skipped = ""' '_ = e.skipped'
mutate drain-error-fails-open TestCaptureStdio_ReadFailureIsUnverified 'err == nil && restored' '(err == nil || err != nil) && restored'
mutate restore-error-fails-open TestCaptureStdio_RestoreFailureIsUnverified 'restored = errErr == nil && errOut == nil' 'restored = true
			_ = errErr
			_ = errOut'
mutate pipe-fails-open TestRunOne_SetupFailureDoesNotRunProvider '
	r, w, err := pipe()
	if err != nil {
		return "", false' '
	r, w, err := pipe()
	if err != nil {
		return "", true'
mutate fd1-fails-open TestRunOne_SetupFailureDoesNotRunProvider '
	restoreOut, err := redirect(1, w)
	if err != nil {
		_ = w.Close()
		return "", false' '
	restoreOut, err := redirect(1, w)
	if err != nil {
		_ = w.Close()
		return "", true'
mutate fd2-fails-open TestRunOne_SetupFailureDoesNotRunProvider '
	restoreErr, err := redirect(2, w)
	if err != nil {
		_ = restoreOut()
		_ = w.Close()
		return "", false' '
	restoreErr, err := redirect(2, w)
	if err != nil {
		_ = restoreOut()
		_ = w.Close()
		return "", true'
mutate partial-setup-not-restored TestRunOne_SetupFailureDoesNotRunProvider '
	restoreErr, err := redirect(2, w)
	if err != nil {
		_ = restoreOut()' '
	restoreErr, err := redirect(2, w)
	if err != nil {
		// partial setup restore omitted'
mutate partial-setup-stderr-clobbered TestRunOne_SetupFailureDoesNotRunProvider '
	restoreErr, err := redirect(2, w)
	if err != nil {
		_ = restoreOut()' '
	restoreErr, err := redirect(2, w)
	if err != nil {
		_ = syscall.Close(2)
		_ = restoreOut()'
mutate fd1-not-restored TestCaptureStdio_RestoresDescriptors '
			errOut := restoreOut()' '
			errOut := error(nil)
			_ = restoreOut'
mutate fd2-not-restored TestCaptureStdio_RestoresDescriptors '
			errErr := restoreErr()' '
			errErr := error(nil)
			_ = restoreErr'
mutate restore-dup2-omitted TestCaptureStdio_RestoresDescriptors 'err := fdredirect.Dup2(saved, fd)' 'err := error(nil)'
mutate panic-before-restore-defer TestCaptureStdio_RestoresDescriptors '
	func() {
		defer func() {' '
	func() {
		fn()
		defer func() {'
mutate capture-not-serialized TestCaptureStdio_SecondCaptureBlocks '
	stdioMu.Lock()
	defer stdioMu.Unlock()' '
	// serialization omitted'
mutate drain-not-bounded TestCaptureStdio_BoundedTimeoutOnStuckDrain 'case <-time.After(stdioDrainTimeout):' 'case <-time.After(24 * time.Hour):'
mutate stderr-not-redirected TestCaptureStdio_StderrOnly '
	restoreErr, err := redirect(2, w)' '
	restoreErr, err := func() (func() error, error) { return func() error { return nil }, nil }()'
mutate variable-swap-races TestCaptureStdio_ConcurrentCheckAndPrint '
	var buf lockedBuffer' '
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()
	var buf lockedBuffer'

mutate factory-outside-window TestRunOne_FactoryRunsInsideCaptureWindow '
	stdio, capturedOK := capture(func() {' '
	h := f(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	f = func(*slog.Logger) Harness { return h }
	stdio, capturedOK := capture(func() {'
mutate stdout-scan-disabled TestProviderConformance_StdoutLeakEscapesDetection 'else if e.canary.in(stdio) {' 'else if false && e.canary.in(stdio) {'

# The attacking test and each new witness must run, not silently skip.
if mutation_apply_only; then
	:
elif (cd "$root" && GORACE="log_path=$work/baseline-race" go test -race -count=1 -timeout 30s -v -run '^Test(CaptureStdio|RunOne|ProviderConformance_StdoutLeakEscapesDetection|ReferencePasses|SuiteFailsBrokenProviders|EveryCheckHasARedRun)' ./$dir/ >"$work/baseline" 2>&1) && ! grep -q -- '--- SKIP:' "$work/baseline"; then
	echo "ok   baseline: capture witnesses and attack green with no skips"
else
	echo "FAIL baseline: capture witnesses failed or skipped"
	fail=1
fi
exit "$fail"
