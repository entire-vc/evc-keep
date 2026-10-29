#!/bin/sh
# Proves keep-runner's execution loop (internal/runner/loop), the runner side
# of value delivery (internal/builtin OpenRunnerMaterial) and `keep-runner run`
# can fail: in a scratch copy of the tree, switch off one guard at a time and
# require the named test to go red.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace

fail=0
# mutate <name> <file> <package> <test> <from> <to> [<from2> <to2>]
# <from> must occur in <file>; the first occurrence is replaced. The optional
# second pair is applied the same way, for a mutation that needs an import.
mutate() {
	name=$1 file=$2 pkg=$3 test=$4 from=$5 to=$6 from2=${7:-} to2=${8:-}
	rm -rf "${work:?}/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$file" >"$work/tree/$file"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	if [ -n "$from2" ]; then
		if ! awk -v from="$from2" -v to="$to2" '
			!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
			{ print }
			END { exit !done }' "$work/tree/$file" >"$work/second" || ! cp "$work/second" "$work/tree/$file"; then
			echo "FAIL $name: second mutation did not apply — update this script"
			fail=1
			return
		fi
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -count=1 -run "$test" ./$pkg/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the check switched off"
		fail=1
	elif ! grep -q -- "--- FAIL: $test" "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?)"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

L=internal/runner/loop
T=internal/targets
LP=internal/runner/loop

# 1. Order: signature, policy, limit and fingerprint all come before the write.
mutate signature-unchecked $L/loop.go $LP TestBadSignatureNeverReachesFetchOrWrite \
	'j, err := runnerproto.VerifyJob(sj, r.Keys, r.Me, r.now(), bf)' 'j, err := runnerproto.DecodeJob(sj.Payload)'
mutate policy-check-skipped $L/loop.go $LP TestOutsidePolicyRejectedBeforeFetchAndWrite \
	'if err := runnerproto.Check(j, r.Policy); err != nil {' 'if err := error(nil); err != nil {'
mutate limiter-skipped $L/loop.go $LP TestRateLimitedBeforeFetch \
	'if r.Limiter == nil || r.Limiter.Allow(j, r.now()) != nil {' 'if r.Limiter == nil {'
mutate fingerprint-unchecked $L/loop.go $LP TestWrongValueNeverWritten \
	'if err != nil || got != j.ExpectedFingerprint {' 'if err != nil || got == "" {'
mutate fingerprint-unchecked-empty-substitute $L/loop.go $LP TestEmptySubstituteNeverWritten \
	'if err != nil || got != j.ExpectedFingerprint {' 'if err != nil || got == "" {'
mutate exec-deps-missing-allowed $L/loop.go $LP TestExecRefusalsAreOneClassAndBeforeFetch \
	'if r.Exec == nil {' 'if false && r.Exec == nil {' 
mutate exec-prepare-skipped $L/loop.go $LP TestExecRefusalsAreOneClassAndBeforeFetch \
	'if plan, err = execrun.Prepare(j, r.Policy); err != nil {' 'if plan, err = execrun.Prepare(j, r.Policy); false && err != nil {'
mutate exec-refusal-class-leaks $L/loop.go $LP TestExecRefusalsAreOneClassAndBeforeFetch \
	'return fail(runnerproto.ErrClassPolicyDenied)' 'return fail(runnerproto.ErrClassInvalidJob)' \
	'return fail(runnerproto.ErrClassPolicyDenied)' 'return fail(runnerproto.ErrClassInvalidJob)'
mutate exec-fingerprint-unchecked $L/loop.go $LP TestExecWrongValueNeverRuns \
	'if err != nil || got != j.ExpectedFingerprint {' 'if err != nil || got == "" {'
mutate exec-nonzero-exit-ok $L/loop.go $LP TestExecNonZeroExitIsInternalAndExitCodeStaysOnTheHost \
	'if out.ExitCode != 0 {' 'if false {'
mutate exec-sink-skipped $L/loop.go $LP TestExecJobRunsAndReportsOnlyTheClosedResult \
	'if r.ExecSink != nil {' 'if false {'
mutate exec-class-dropped $L/loop.go $LP TestExecHostWithoutIsolationRefuses \
	'if class != "" {' 'if false {'
# Identity and window come from VerifyJob; a rejected job is reported, not run.
mutate rejected-job-unreported $L/loop.go $LP TestIdentityAndWindowRejectedBeforeFetch \
	'if err := r.Outbox.CloseIfAbsent(j.JobID, runnerproto.Result{ErrorClass: class}); errors.Is(err, os.ErrExist) {' 'if err := error(nil); errors.Is(err, os.ErrExist) {'
# A late re-served job must not overwrite the Result of the run that executed it.
mutate reject-overwrites-result $L/outbox.go $LP TestLateReservedJobKeepsTheRealResult \
	'if exclusive {' 'if false {'
# A replay is only logged: it must not be reported over the real result.
mutate replay-reported $L/loop.go $LP TestReplayedJobDoesNothingTwice \
	'if errors.Is(cause, runnerproto.ErrSignature) || errors.Is(cause, runnerproto.ErrReplay) {' 'if errors.Is(cause, runnerproto.ErrSignature) {'

# 2. Outbox: started before the fetch, restart order, retry rules.
mutate started-not-recovered $L/loop.go $LP TestRestartSendsOutboxBeforePoll \
	'if p.Closed {' 'if true {'
mutate outbox-not-flushed-before-poll $L/loop.go $LP TestRestartSendsOutboxBeforePoll \
	'if err := r.flush(ctx); err != nil {' 'if err := error(nil); err != nil {'
mutate refusal-retried-forever $L/loop.go $LP TestServerRefusalDropsTheEntry \
	'case errors.Is(err, ErrRefused):' 'case false:'
mutate result-acked-unsent $L/loop.go $LP TestNetworkFailureRepeatsOnlyTheResult \
	'switch err := r.Transport.SendResult(ctx, p.JobID, p.Result); {' 'switch err := error(nil); {'
mutate no-backoff $L/loop.go $LP TestRunBacksOffOnPollFailure \
	'if d *= 2; d > maxBackoff {' 'if d *= 1; d > maxBackoff {'

# 3. Outbox files: private, regular, closed schema, safe names.
mutate outbox-job-id-unchecked $L/outbox.go $LP TestOutboxRefusesBadJobIDs \
	'if !jobIDRe.MatchString(jobID) {' 'if false {'
mutate outbox-file-mode-unchecked $L/outbox.go $LP TestOutboxRefusesDamagedEntries \
	'fi.Mode().Perm() != 0o600 || !ownedByUs(fi) {' 'false {'
mutate outbox-symlink-followed $L/outbox_unix.go $LP TestOutboxRefusesDamagedEntries \
	'const noFollow = syscall.O_NOFOLLOW' 'const noFollow = 0'
mutate outbox-unknown-fields-accepted $L/outbox.go $LP TestOutboxRefusesDamagedEntries \
	'dec.DisallowUnknownFields()' ''
mutate outbox-dir-mode-unchecked $L/outbox.go $LP TestOutboxDirectoryMustBePrivate \
	'fi.Mode().Perm() != 0o700 ||' 'false ||'
mutate outbox-result-unvalidated $L/outbox.go $LP TestOutboxRefusesResultOutsideContract \
	'if err := r.Validate(); err != nil {' 'if err := error(nil); err != nil {'

# 4. Transport: closed schema, no body echo, no redirect, https only.
mutate transport-unknown-fields-accepted $L/transport.go $LP TestHTTPTransportRefusesOpenSchema \
	'dec.DisallowUnknownFields()' ''
mutate transport-body-echoed $L/transport.go $LP TestHTTPTransportErrorsNeverEchoTheBody \
	'return nil, fmt.Errorf("%w: status %d", ErrTransport, resp.StatusCode)' 'b, _ := io.ReadAll(resp.Body); return nil, fmt.Errorf("%w: %s", ErrTransport, b)'
mutate transport-redirect-followed $L/transport.go $LP TestHTTPTransportStatusMapping \
	'CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },' ''
mutate transport-plain-http $L/transport.go $LP TestHTTPTransportNeedsClientCertificate \
	'if !strings.HasPrefix(server, "https://") {' 'if false {'
mutate transport-client-certificate-dropped $L/transport.go $LP TestHTTPTransportRoutesAndBodies \
	'Certificates: []tls.Certificate{cert}, RootCAs: serverCA,' 'Certificates: []tls.Certificate{cert}[:0], RootCAs: serverCA,'
mutate transport-size-unbounded $L/transport.go $LP TestHTTPTransportRefusesOpenSchema \
	'if err != nil || int64(len(b)) > limit {' 'if err != nil {'
mutate transport-value-body-limit-shrunk $L/transport.go $LP TestHTTPTransportValueBodyLimit \
	'maxEnvBody     = 2 << 20' 'maxEnvBody     = 64 << 10'
mutate transport-job-id-unchecked $L/transport.go $LP TestHTTPTransportRefusesOpenSchema \
	'if !jobIDRe.MatchString(jobID) {' 'if false {'

# 5. Leak test must see a value in the log: plant one.
mutate value-in-log $L/loop.go $LP TestCanaryNeverLeavesTheTargetFile \
	'defer v.Wipe()' 'defer v.Wipe(); secret.Expose(v, func(b []byte) { r.Log.Info("runner.job", "status", string(b)) })'

mutate delivery-key-in-log $L/loop.go $LP TestMismatchBranchLeaksNothing \
	'return fail(runnerproto.ErrClassFingerprintMismatch)' 'r.Log.Info("runner.job", "status", fmt.Sprintf("%v", r.Delivery.Bytes())); return fail(runnerproto.ErrClassFingerprintMismatch)'

mutate once-hides-send-failure $L/loop.go $LP TestOnceReportsAResultThatCouldNotBeSent \
	'return true, r.flush(ctx)' '_ = r.flush(ctx); return true, nil'
mutate begin-skipped-before-claim $L/loop.go $LP TestCrashBeforeTheClaimIsReportedAfterRestart \
	'if err := b.r.Outbox.Begin(jobID); err != nil {' 'if err := error(nil); err != nil {'
mutate refused-claim-keeps-entry $L/loop.go $LP TestReplayedJobDoesNothingTwice \
	'if err := b.r.Journal.Claim(jobID, notAfter, now); err != nil {' 'if err := b.r.Journal.Claim(jobID, notAfter, now); err != nil { return err'

mutate run-continues-after-outbox-failure $L/loop.go $LP TestUnrecordableOutcomeStopsTheLoop \
	'case errors.Is(err, ErrOutbox):' 'case false:'
mutate close-failure-not-propagated $L/loop.go $LP TestUnrecordableOutcomeStopsTheLoop \
	'if err := r.Outbox.Close(j.JobID, res); err != nil {' 'if err := r.Outbox.Close(j.JobID, res); err != nil { r.Log.Error("runner.job", "status", "outbox"); return nil }; if false {'

# 6. Runner side of delivery: both envelopes bound to the job and the recipient.
B=internal/builtin
mutate open-empty-value-refused $B/delivery.go $B TestOpenRunnerMaterialBoundarySizes \
	'len(sealed) <= scheme.CiphertextSize() {' 'len(sealed) <= scheme.CiphertextSize()+16 {'
mutate open-job-id-unchecked $B/delivery.go $B TestOpenRunnerMaterialRoundTripAndBindings \
	'|| env.JobID != j.JobID {' '{'
mutate open-key-info-reused $B/delivery.go $B TestOpenRunnerMaterialRoundTripAndBindings \
	'openRunnerBytes(recipient, runnerproto.FingerprintKeyInfo(j), env.SealedFingerprintKey)' 'openRunnerBytes(recipient, runnerproto.Info(j), env.SealedFingerprintKey)'
mutate open-value-info-weakened $B/delivery.go $B TestOpenRunnerMaterialRoundTripAndBindings \
	'openRunnerBytes(recipient, runnerproto.Info(j), env.Sealed)' 'openRunnerBytes(recipient, nil, env.Sealed)'

# 7. CLI: no refusal reflects an argument.
C=cmd/keep-runner
mutate cli-reflects-command $C/main.go $C TestRunCommandNeverReflectsArguments \
	'unknown command\\n", version.String())' 'unknown command %q\\n", version.String(), args[0])'
mutate cli-reflects-policy-path $C/run.go $C TestRunCommandNeverReflectsArguments \
	'fmt.Fprintf(os.Stderr, "keep-runner run: %s\\n", what)' 'fmt.Fprintf(os.Stderr, "keep-runner run: %s %s\\n", what, *policyPath)'
mutate cli-identity-unchecked $C/run.go $C TestRunOnceEndToEnd \
	'cred.SignKeyID: ed25519.PublicKey(cred.SignPubKey)' 'cred.SignKeyID: ed25519.PublicKey(make([]byte, 32))'

# The child's home must be an existing, empty, clean, real directory.
mutate exec-home-not-empty-ok $C/exec_home.go $C TestCheckExecHome \
	'len(ents) != 0' 'len(ents) < 0'
mutate exec-home-symlink-followed $C/exec_home.go $C TestCheckExecHome \
	'os.Lstat(home)' 'os.Stat(home)'
mutate exec-home-unclean-ok $C/exec_home.go $C TestCheckExecHome \
	'filepath.Clean(home) != home' 'false'

mutate exec-home-relative-ok $C/exec_home.go $C TestCheckExecHomeRefusesRelativePathToAnExistingDirectory \
	'!filepath.IsAbs(home) ||' 'false ||'
mutate exec-home-read-error-ok $C/exec_home.go $C TestCheckExecHomeRefusesAnUnreadableDirectory \
	'err != nil || len(ents) != 0' 'len(ents) != 0'

# The flags that reach the loop: the policy decides whether exec is set up at
# all, the account is never root, the home is required and is the child's cwd.
mutate exec-policy-gate-off $C/run.go $C TestRunOnceExecEndToEnd \
	'if policy.AllowExec {' 'if false {'
mutate exec-deps-not-wired $C/run.go $C TestRunOnceExecEndToEnd \
	'Exec:      execDeps,' 'Exec:      func() *execrun.Deps { _ = execDeps; return nil }(),'
mutate exec-uid-zero-ok $C/exec_deps.go $C TestRunRefusesExecPolicyWithoutChildAccount \
	'uid == 0 || gid == 0' 'false'
mutate exec-gid-zero-ok $C/exec_deps.go $C TestExecSetup \
	'uid == 0 || gid == 0' 'uid == 0'
mutate exec-home-optional $C/exec_deps.go $C TestRunRefusesExecPolicyWithoutChildAccount \
	'if home == "" {' 'if false {'
mutate exec-home-unchecked $C/exec_deps.go $C TestRunRefusesExecPolicyWithoutChildAccount \
	'if err := checkExecHome(home); err != nil {' 'if err := error(nil); err != nil {'
mutate exec-home-group-writable-ok $C/exec_home.go $C TestCheckExecHomeRefusesARootOthersCanWriteOrNotOwnedByTheRunner \
	'fi.Mode().Perm()&0o022 != 0' 'false'
mutate exec-home-foreign-owner-ok $C/exec_home.go $C TestCheckExecHomeRefusesARootOthersCanWriteOrNotOwnedByTheRunner \
	'!ok || uid != os.Geteuid()' 'uid < 0 && !ok'
mutate exec-ids-not-passed $C/exec_deps.go $C TestExecSetup \
	'&execrun.Netns{ChildUID: uid, ChildGID: gid}' '&execrun.Netns{}'
mutate exec-home-root-not-passed $C/exec_deps.go $C TestExecSetup \
	'HomeRoot: home,' 'HomeRoot: "/",'
mutate exec-deps-ids-not-passed $C/exec_deps.go $C TestExecSetup \
	', ChildUID: uid, ChildGID: gid, CorePiped' ', CorePiped'

# verify: the runner reports only a fingerprint, after the owner check
mutate verify-policy-check-skipped $L/loop.go $LP TestVerifyOutsidePolicyRefusedBeforeKey \
	'if err := runnerproto.Check(j, r.Policy); err != nil {' 'if err := runnerproto.Check(j, r.Policy); err != nil && j.Action != runnerproto.ActionVerify {'
mutate verify-writable-carrier-allowed $T/observe.go $LP TestVerifyAgentWritableCarrierRefusedBeforeKey \
	'if err := ag.refuseWritableFile("target", &st); err != nil {' 'if err := ag.refuseWritableFile("target", &st); err != nil && false {'
mutate verify-agent-owned-allowed $T/observe.go $LP TestVerifyAgentOwnedCarrierRefusedBeforeKeyAndRead \
	'if err := ag.refuseWritableFile("target", &st); err != nil {' 'if err := ag.refuseWritableFile("target", &st); err != nil && false {'
mutate verify-mismatch-hides-observed $L/loop.go $LP TestVerifyMismatchNamesTheObservedFingerprint \
	'ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: got}' 'ErrorClass: runnerproto.ErrClassFingerprintMismatch}'
mutate verify-compare-always-match $L/loop.go $LP TestVerifyMismatchNamesTheObservedFingerprint \
	'case !targets.SameFingerprint(got, j.ExpectedFingerprint):' 'case false:'
mutate verify-absent-fetches-key $L/loop.go $LP TestVerifyAbsentCarrierIsAMismatchWithoutFingerprintAndWithoutKey \
	'case !exists:' 'case !exists && false:'
mutate verify-key-opens-a-value $B/delivery.go $B TestOpenRunnerKeyRefusesAValueAndOtherJobs \
	' || len(env.Sealed) != 0 {' ' {'
mutate verify-key-not-job-bound $B/delivery.go $B TestOpenRunnerKeyRefusesAValueAndOtherJobs \
	'openRunnerBytes(recipient, runnerproto.VerifyKeyInfo(j), env.SealedFingerprintKey)' 'openRunnerBytes(recipient, runnerproto.Info(j), env.SealedFingerprintKey)'
mutate verify-key-for-any-job $B/delivery.go $B TestVerifyKeyIsSealedOnlyForVerifyJobs \
	'if j.Validate() != nil || !j.NeedsFingerprintKey() || j.NeedsValue() {' 'if j.Validate() != nil {'
mutate verify-key-sealed-under-value-info $B/delivery.go $B TestVerifyKeyEnvelopeCarriesTheKeyAndNoValue \
	'sealRunnerBytes(recipient, runnerproto.VerifyKeyInfo(j), raw)' 'sealRunnerBytes(recipient, runnerproto.Info(j), raw)'

# Host policy prefixes through a symlink: check refuses, run warns.
mutate check-prefix-unchecked $C/check.go $C TestCheckRefusesSymlinkPrefixEndToEnd \
	'runnerproto.CheckPrefixesOnHost(pol)' 'runnerproto.CheckPrefixesOnHost(runnerproto.HostPolicy{Version: pol.Version})'
mutate run-prefix-unwarned $C/run.go $C TestRunWarnsOnSymlinkPrefix \
	'runnerproto.CheckPrefixesOnHost(policy)' 'runnerproto.CheckPrefixesOnHost(runnerproto.HostPolicy{})'

if mutation_apply_only; then
	:
elif (cd "$root" && go test -count=1 ./$LP/ ./$C/ >/dev/null 2>&1 && go test -count=1 -run 'RunnerMaterial' ./$B/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
