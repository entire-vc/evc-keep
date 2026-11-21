#!/bin/sh
# Proves the rotation tests can fail: in a scratch copy of the
# tree, switch off one property at a time and require the tests of
# internal/rotation to go red. A property whose removal
# leaves the tests green is not tested.
#
# The tests need a real PostgreSQL (no mocking, CONTRIBUTING.md)
# and reset the schema themselves, so KEEP_DATABASE_URL must point at a
# database of its own; they run one package at a time (-p 1) because they
# share it.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
mutation_shard_init

# Allocate a private per-run cache unless the caller owns one, and clean
# both that cache and child scratch files through the shared lifecycle.
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace

if [ -z "${KEEP_DATABASE_URL:-}" ] && ! mutation_apply_only; then
	echo "FAIL check-rotation-mutations: KEEP_DATABASE_URL is not set — the tests would skip, not fail, which this script must never report as red"
	exit 1
fi

fail=0
# occurrences SRC FROM: print how many times the literal FROM occurs in SRC
# (every occurrence, also several on one line).
occurrences() {
	awk -v from="$2" '
		{ rest = $0; while ((i = index(rest, from)) > 0) { n++; rest = substr(rest, i + length(from)) } }
		END { print n + 0 }' "$1"
}

# edit SRC FROM TO NTH: print SRC with the NTH literal occurrence of FROM
# replaced by TO; exit 1 if FROM occurs fewer than NTH times.
edit() {
	awk -v from="$2" -v to="$3" -v nth="$4" '
		{
			out = ""; rest = $0
			while (!done && (i = index(rest, from)) > 0) {
				if (++n == nth) { out = out substr(rest, 1, i-1) to; done = 1 }
				else out = out substr(rest, 1, i-1) from
				rest = substr(rest, i + length(from))
			}
			print out rest
		}
		END { exit !done }' "$1"
}

pkgs="./internal/rotation/"

# failed_declared_tests TREE OUT: print, space-separated, each top-level
# test that OUT records as failed with a go-test result line
# ("--- FAIL: Name[/sub] (N.NNs)") AND that TREE declares as a test function
# of the package, or " none". Only identifiers from the sources are printed;
# subtest names and anything a test writes never reach the log.
failed_declared_tests() {
	{
		echo '#'
		for f in "$1"/internal/rotation/*_test.go; do
			if [ -f "$f" ]; then
				sed -n 's/^func \(Test[A-Za-z0-9_]*\)(t \*testing\.T) {$/\1/p' "$f"
			fi
		done
	} >"$work/declared"
	awk '
		NR == FNR { declared[$0] = 1; next }
		$1 == "---" && $2 == "FAIL:" && NF == 4 && $4 ~ /^\([0-9.]+s\)$/ {
			top = $3; sub(/\/.*/, "", top)
			if ((top in declared) && !(top in seen)) { seen[top] = 1; printf " %s", top; n++ }
		}
		END { if (!n) printf " none" }' "$work/declared" "$2"
}

# Setup uses sanitized store connection errors, while subsequent pgx/sql
# operations can return driver errors directly. Neither proves a rotation
# property. Keep these connection/lifecycle classes separate from ordinary
# product context deadlines and constraint violations (e.g. SQLSTATE 23503).
rotation_database_failed() {
	grep -q -E 'failed to connect to|connection failed \(|connection refused|connection reset by peer|broken pipe|unexpected EOF|i/o timeout|conn closed|sql: (database is closed|connection is already closed)|driver: bad connection|SQLSTATE (08[0-9A-Z]{3}|57P0[123]|53300)' "$1"
}

# mutate NAME FILE FROM TO [WANT] [OCCURRENCE]: FILE is relative to the repo root. WANT,
# when given, is a space-separated list of `--- FAIL: ` prefixes that MUST
# all appear in the red run — a mutant is not proven to isolate the property
# it claims to just because *some* test went red; the wrong test catching it
# (a different, unrelated check that happened to also depend on the mutated
# line) proves nothing about the property WANT names. Mirrors the
# `--- FAIL: WANT` check in check-identity-attack-mutations.sh.
#
# OCCURRENCE (6th argument) names which literal occurrence of FROM the mutant
# switches off. An anchor that occurs more than once without it is refused:
# silently taking the first occurrence once aimed a mutant at a branch its
# witness never runs. The refusal holds under MUTATION_APPLY_ONLY=1 too.
mutate() {
	mutation_selected || return 0
	name=$1 src=$2 from=$3 to=$4 want=${5:-} occurrence=${6:-}
	if [ -z "$from" ]; then
		echo "FAIL $name: mutation anchor is empty"
		fail=1
		return
	fi
	case $occurrence in
		'') ;;
		*[!0-9]* | 0*) echo "FAIL $name: occurrence must be a positive number, got '$occurrence'"; fail=1; return ;;
	esac
	mutation_snapshot "$work/tree"
	if [ "$from" = "@remove-file" ]; then
		printf '%s\n' 'package rotation' >"$work/tree/$src"
	else
		found=$(occurrences "$root/$src" "$from")
		if [ "$found" -gt 1 ] && [ -z "$occurrence" ]; then
			echo "FAIL $name: anchor occurs $found times, name the occurrence"
			fail=1
			return
		fi
		if ! edit "$root/$src" "$from" "$to" "${occurrence:-1}" >"$work/tree/$src"; then
			echo "FAIL $name: mutation did not apply — the source changed, update this script"
			fail=1
			return
		fi
	fi
	mutation_applied "$name" && return
	# shellcheck disable=SC2086
	if (cd "$work/tree" && timeout -k 10s 300s go test -timeout 200s -count=1 -p 1 -v $pkgs >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
		return
	else
		test_status=$?
	fi
	# A killed or incomplete process can emit some (even all) named failures.
	# Require the normal go-test failure status AND its final package summary;
	# infrastructure failures never prove a witness, even after a named red.
	if [ "$test_status" -ne 1 ] ||
		! awk '$1 == "FAIL" && $2 == "github.com/entire-vc/evc-keep/internal/rotation" && $3 ~ /^[0-9.]+s$/ { found=1 } END { exit !found }' "$work/out" ||
		grep -q -E '^panic:|^fatal error:|signal: killed|\[build failed\]|\[setup failed\]|--- SKIP' "$work/out" ||
		mutation_infrastructure_failed "$work/out" ||
		rotation_database_failed "$work/out"; then
		echo "FAIL $name: invalid test run (incomplete process, timeout, build/setup failure, or skip; exit $test_status)"
		fail=1
		return
	fi
	if ! grep -q -- '--- FAIL' "$work/out"; then
		# Red because the mutant does not build, or every test skipped, is
		# not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error, or a silent skip?)"
		fail=1
		return
	fi
	missing=""
	for w in $want; do
		awk -v witness="$w" '$1 == "---" && $2 == "FAIL:" && ($3 == witness || index($3, witness "/") == 1) { found=1 } END { exit !found }' "$work/out" || missing="$missing $w"
	done
	if [ -n "$missing" ]; then
		# Never echo go-test output: a message or a subtest name can carry a
		# value. Print only top-level names that are both a go-test result
		# record and a test function declared in the package's sources.
		echo "FAIL $name: red, but not on:$missing (the wrong test/subtest caught it); failed:$(failed_declared_tests "$work/tree" "$work/out")"
		fail=1
		return
	fi
	echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)${want:+, confirmed on: $want}"
}

# Each mutant switches off one guard of the two-phase rotation; the named
# test must be the one that catches it.
mutate revoke-on-partial-success internal/rotation/store.go \
 'return err == nil && total > 0 && total == ok, err' \
 'return err == nil && total > 0, err' 'TestPartialFailureNeverRevokes'
mutate revoke-gate-off internal/rotation/store.go \
 'return err == nil && total > 0 && total == good, err' \
 'return err == nil && good > 0, err' 'TestRevokeGateReadsTheDatabase'
mutate revoke-gate-no-steps-ok internal/rotation/store.go \
 'total > 0 && total == good' 'total == good' 'TestRevokeGateReadsTheDatabase'
mutate revoke-gate-empty-fp internal/rotation/store.go \
 "AND r.expected_fp <> ''" '' 'TestRevokeGateReadsTheDatabase'
mutate incident-error-forwarded internal/rotation/engine.go \
 'return ErrIncident' 'return err' 'TestValueNeverReachesStateIncidentOrErrors' 1
mutate invalid-carrier-id-left-open internal/rotation/engine.go \
 'if !validCarrierID(c.ID) {' 'if false {' 'TestInvalidCarrierIDFailsRun'
mutate carrier-id-any-label internal/rotation/labels.go \
 'return err == nil && u.String() == s' 'return err == nil && u.String() == s || s != ""' 'TestIdentifiersAcceptNoSecretShapedString'
mutate carrier-id-non-canonical-uuid internal/rotation/labels.go \
 'return err == nil && u.String() == s' 'return err == nil && (u.String() == s || len(s) > 0)' 'TestIdentifierGrammar'
mutate version-old-label-regex internal/rotation/labels.go \
 '^[1-9][0-9]{0,8}$' '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$' 'TestIdentifiersAcceptNoSecretShapedString'
mutate version-old-unchecked internal/rotation/labels.go \
 'return s == "" || validVersion(s)' 'return true' 'TestIdentifiersAcceptNoSecretShapedString'
mutate version-check-skipped internal/rotation/engine.go \
 '!validVersion(v.New) || !validOldVersion(v.Old) || ' '' 'TestIdentifiersAcceptNoSecretShapedString'
mutate fingerprint-check-skipped internal/rotation/engine.go \
 '!fingerprint.Valid(rep.Fingerprint) || rep.Fingerprint != run.ExpectedFP' \
 'false' 'TestFingerprintMismatchOnAnyCarrierFails'
mutate fingerprint-gate-skipped internal/rotation/store.go \
 'AND st.observed_fp = r.expected_fp)' \
 'AND true)' 'TestRevokeGateReadsTheDatabase'
mutate unhealthy-accepted internal/rotation/engine.go \
 'case !rep.Healthy:' 'case false:' 'TestUnhealthyCarrierFails'
mutate no-run-lock internal/store/migrations/00020_rotation.sql \
 'CREATE UNIQUE INDEX rotation_runs_one_active_idx' \
 'CREATE INDEX rotation_runs_one_active_idx' 'TestParallelRotateOfOneSecretConflicts'
mutate lease-ignored internal/rotation/store.go \
 "(lease_owner='' OR" '(true OR' 'TestSameRunIDInParallelConflicts TestLeaseOfDeadProcessExpires' 1
mutate lease-never-expires internal/rotation/store.go \
 'OR lease_until < $4' 'OR false' 'TestLeaseOfDeadProcessExpires'
mutate resume-redeploys internal/rotation/engine.go \
 'if s.Deploy != "ok" {' 'if true {' 'TestResumeAfterKillMidLayout'
mutate incident-skipped internal/rotation/engine.go \
 'if run.State == StateFailed && !run.IncidentOpened && run.Class != ClassSuperseded {' \
 'if false && run.State == StateFailed && !run.IncidentOpened && run.Class != ClassSuperseded {' 'TestPartialFailureNeverRevokes'
mutate incident-not-retried internal/rotation/store.go \
 "OR (state='failed' AND NOT incident_opened))" ')' 'TestIncidentRetriedOnResume'
mutate no-carriers-accepted internal/rotation/engine.go \
 'if len(ids) == 0 {' 'if false {' 'TestNoCarriersNeverRevokes'
mutate concurrency-unbounded internal/rotation/engine.go \
 'make(chan struct{}, limit)' 'make(chan struct{}, limit+8)' 'TestConcurrencyLimit'
mutate failure-keeps-launching internal/rotation/engine.go \
 'if failed.Load() || ctx.Err() != nil {' 'if ctx.Err() != nil {' 'TestPartialFailureNeverRevokes'
mutate lease-not-renewed internal/rotation/engine.go \
 'if err := e.store.renew(ctx, id, l, at, ttl); err != nil {' \
 'if false {' 'TestLiveRunKeepsItsLeasePastTTL'
# The heartbeat cancels the run at its first failed renewal, the lease watcher
# when the end of the lease passes, and every fenced write refuses a lost
# lease: the three overlap by design, so switching the heartbeat's cancel off
# alone is not a mutant (nothing observable changes but the time it takes);
# the watcher and the writes have their own mutants below.
mutate renew-ignores-owner internal/rotation/store.go \
 'WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3' \
 'WHERE id=$1 AND (lease_owner=$2 OR true) AND (lease_epoch=$3 OR true)' 'TestLostLeaseStopsTheRun' 1
mutate revoke-unfenced internal/rotation/engine.go \
 'sctx, stop, err := e.fence(ctx, run.ID)' \
 'sctx, stop, err := ctx, func() {}, error(nil)' 'TestRevokeIsFencedByTheLease' 1
mutate deploy-unfenced internal/rotation/engine.go \
 'sctx, stop, ferr := e.fence(ctx, run.ID)' \
 'sctx, stop, ferr := ctx, func() {}, error(nil)' 'TestDeployIsFencedByTheLease'
mutate fence-always-holds internal/rotation/store.go \
 'AND lease_owner=$2 AND lease_epoch=$3 AND lease_until >= $4' \
 'AND (lease_owner=$2 OR true) AND (lease_epoch=$3 OR true) AND lease_until >= $4' 'TestRevokeIsFencedByTheLease TestDeployIsFencedByTheLease'
# A caller that passed the ownership check and then lost its lease (the
# window between the check and the side effect).
mutate epoch-not-incremented internal/rotation/store.go \
 'DO UPDATE SET epoch = rotation_secret_epochs.epoch + 1' 'DO UPDATE SET epoch = rotation_secret_epochs.epoch + 0' 'TestEpochGrowsWithEveryClaim TestStaleOwnerCannotDeployAfterTakeover'
# The epoch is the secret's, not the run's: a second run of the same secret
# must claim above what a carrier accepted for the first.
mutate epoch-scoped-to-run internal/rotation/store.go \
 'lease_epoch=(SELECT epoch FROM e)' 'lease_epoch=r.lease_epoch+1' 'TestEpochIsMonotonicAcrossRunsOfOneSecret TestSecondRunOfTheSecretPassesAfterATakeover'
mutate epoch-counter-reset-per-claim internal/rotation/store.go \
 'DO UPDATE SET epoch = rotation_secret_epochs.epoch + 1' 'DO UPDATE SET epoch = 1' 'TestEpochGrowsWithEveryClaim TestEpochIsMonotonicAcrossRunsOfOneSecret'
# Prepare is idempotent per run: a repeat makes no second version and a run
# that is already past it never calls it.
mutate prepare-repeat-makes-a-version internal/rotation/engine.go \
 'e.versions.Prepare(ctx, run.Ref, run.ID)' 'e.versions.Prepare(ctx, run.Ref, uuid.New())' 'TestRepeatedPrepareMakesOneVersion'
mutate prepare-called-past-new-version internal/rotation/engine.go \
 'return e.deploy(ctx, run, opts)' '_, _ = e.versions.Prepare(ctx, run.Ref, run.ID); return e.deploy(ctx, run, opts)' 'TestResumePastPrepareDoesNotPrepareAgain'
mutate epoch-not-in-call-context internal/rotation/engine.go \
 'context.WithCancelCause(withEpoch(ctx, l.epoch))' 'context.WithCancelCause(ctx)' 'TestStaleOwnerCannotDeployAfterTakeover TestStaleOwnerCannotRevokeAfterTakeover'
mutate lease-end-does-not-cut-the-call internal/rotation/engine.go \
 'rem := time.Duration(l.until.Load() - e.now().UnixNano())' \
 'rem := time.Hour' 'TestSideEffectsEndWithTheLease'
mutate cut-deploy-recorded-as-failure internal/rotation/engine.go \
 'if errors.Is(context.Cause(sctx), ErrLeaseLost) { // cut by' \
 'if false { // cut by' 'TestSideEffectsEndWithTheLease' 1
mutate cut-revoke-recorded-as-failure internal/rotation/engine.go \
 'if errors.Is(context.Cause(sctx), ErrLeaseLost) { // revoke cut' \
 'if false { // revoke cut' 'TestSideEffectsEndWithTheLease'
mutate release-unfenced internal/rotation/store.go \
 'lease_until=NULL WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3' \
 'lease_until=NULL WHERE id=$1 AND $2 IS NOT NULL AND $3>=0' 'TestStaleReleaseKeepsTheNewOwnersLease'
mutate mark-incident-unfenced internal/rotation/store.go \
 'SET incident_opened=true WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3' \
 'SET incident_opened=true WHERE id=$1 AND $2 IS NOT NULL AND $3>=0' 'TestStaleOwnerCannotOpenIncidentAfterTakeover'
mutate incident-unfenced internal/rotation/engine.go \
 'ictx, istop, err := e.fence(ctx, run.ID)' \
 'ictx, istop, err := ctx, func() {}, error(nil)' 'TestStaleOwnerCannotOpenIncidentAfterTakeover' 1
mutate lease-end-not-renewed-locally internal/rotation/engine.go \
 'l.until.Store(at.Add(ttl).UnixNano())' '_ = at' 'TestLiveRunKeepsItsLeasePastTTL'
mutate write-begin-unfenced internal/rotation/store.go \
 "WHERE id=\$1 AND state='new_version' AND lease_owner=\$5 AND lease_epoch=\$6" "WHERE id=\$1 AND state='new_version' AND \$5<>'' AND \$6>=0" 'TestStaleLeaseWritesNothing'

mutate leak-test-prints-dump internal/rotation/rotation_test.go \
 'canary reached the result, an incident, an error or a row (%d bytes inspected)", dump.Len())' \
 'canary leaked: %s", dump.String())' 'TestLeakTestsDoNotPrintWhatTheyInspect'
mutate security-leak-test-prints-dump test/security/w3_rotation_attack_test.go \
 't.Fatal("canary reached rotation state, incident or error")' \
 't.Fatal("canary reached " + dump.String())' 'TestLeakTestsDoNotPrintWhatTheyInspect'

# the report: a version only once done, stale carriers, a run only under its own secret
mutate report-version-before-done internal/rotation/service.go \
 'if rep.Done {' 'if true {' 'TestServiceFailedCarrierActivatesNothing'
mutate report-no-stale-carriers internal/rotation/service.go \
 'if runFailed && cs.State != CarrierOK {' 'if false {' 'TestServiceFailedCarrierActivatesNothing'
mutate report-verify-phase-lost internal/rotation/service.go \
 'cs.Phase, cs.State = PhaseVerify, st.Verify' 'cs.State = st.Verify' 'TestServiceFailedCarrierActivatesNothing TestServiceDoneReportsVersionAndFingerprint'
mutate report-foreign-run-visible internal/rotation/service.go \
 'if run.Ref != ref {' 'if false {' 'TestServiceReportOfAnotherSecretIsUnavailable'
mutate report-unknown-run-is-internal internal/rotation/service.go \
 'if errors.Is(err, pgx.ErrNoRows) {' 'if errors.Is(err, pgx.ErrNoRows) && false {' 'TestServiceReportOfAnotherSecretIsUnavailable'
mutate report-fingerprint-before-done internal/rotation/service.go \
 'rep.Version, rep.Fingerprint = run.NewVersion, run.ExpectedFP' 'rep.Version, rep.Fingerprint = run.NewVersion, ""' 'TestServiceDoneReportsVersionAndFingerprint'

# a worker that panics ends its run as failed (fixed class), never as a pending run that blocks the secret
mutate panic-leaves-run-pending internal/rotation/service.go \
 'if recover() != nil {' 'if recover() != nil && false {' 'TestServicePanicInACollaboratorStopsOnlyTheRun'
mutate panic-fails-a-leased-run internal/rotation/store.go \
 "AND (lease_owner='' OR lease_until IS NULL OR lease_until < \$3)" "" 'TestFailAbandonedLeavesALeasedRunAlone'
mutate panic-in-worker-goroutine-kills-process internal/rotation/engine.go \
 'if recover() != nil {' 'if false {' 'TestServicePanicInACollaboratorStopsOnlyTheRunAndPrintsNothing'
mutate panic-recover-prints-value-in-service internal/rotation/service.go \
 'if recover() != nil {' 'if rv := recover(); rv != nil { println(rv.(string))' 'TestServicePanicInACollaboratorStopsOnlyTheRunAndPrintsNothing'
mutate panic-recover-prints-value-in-worker internal/rotation/engine.go \
 'if recover() != nil {' 'if rv := recover(); rv != nil { println(rv.(string))' 'TestServicePanicInACollaboratorStopsOnlyTheRunAndPrintsNothing'
mutate failabandoned-overwrites-done internal/rotation/store.go \
 "WHERE id=\$1 AND state NOT IN ('done','failed')" "WHERE id=\$1" 'TestFailAbandonedKeepsFinishedAndAppliesExpiredLease'
mutate failabandoned-ignores-expiry internal/rotation/store.go \
 "OR lease_until < \$3)" "OR false)" 'TestFailAbandonedKeepsFinishedAndAppliesExpiredLease'

# RotationProvider adapters (provider.go): each mutant switches off one
# property of the provider-driven run; the named test must catch it.
mutate provider-verify-skipped internal/rotation/engine.go \
 'StateDeploying, StateVerifying, ClassNone' 'StateDeploying, StateRevokingOld, ClassNone' 'TestProviderDualKeyOrderIsStrict'
mutate provider-old-version-not-disabled internal/rotation/provider.go \
 'dis.Version = oldVersion' 'dis.Version = "99"' 'TestProviderDualKeyOrderIsStrict'
mutate provider-forward-only-not-sealed internal/rotation/provider.go \
 'meta, err := t.Store.Write(ctx, t.Ref, iss.Value)' 'meta, err := provider.Meta{Version: "2"}, error(nil)' 'TestProviderForwardOnlySealsAtPrepareAndRetriesLayout'
mutate provider-forward-only-retry-off internal/rotation/engine.go \
 'attempts = opts.DeployAttempts' 'attempts = 1' 'TestProviderForwardOnlySealsAtPrepareAndRetriesLayout'
mutate provider-forward-only-flag-dropped internal/rotation/engine.go \
 'ForwardOnly: e.forwardOnly()}' 'ForwardOnly: false}' 'TestProviderForwardOnlyFailureIsAnIncidentWithoutRollback'
mutate provider-forward-only-inverted internal/rotation/provider.go \
 'return !v.d.Provider.Capabilities().DualKey }' 'return v.d.Provider.Capabilities().DualKey }' 'TestProviderForwardOnlySealsAtPrepareAndRetriesLayout TestProviderDualKeyDoesNotRetryLayout'
mutate provider-issue-repeated-on-resume internal/rotation/provider.go \
 '} else if ok {' '} else if false && ok {' 'TestProviderPrepareIsIdempotentPerRun'
mutate provider-run-of-other-secret internal/rotation/provider.go \
 'if got.ref != ref {' 'if false {' 'TestProviderPrepareIsIdempotentPerRun'
mutate provider-rollback-in-forward-only internal/rotation/provider.go \
 'func (v *ProviderVersions) rollback(ctx context.Context, ref Ref, runID uuid.UUID, keyID string) {' 'func (v *ProviderVersions) rollback(ctx context.Context, ref Ref, runID uuid.UUID, keyID string) { _ = v.d.Provider.Revoke(context.WithoutCancel(ctx), keyID); return' 'TestProviderSealFailureRollsBackOnlyWithDualKey'
mutate provider-revoker-version-unchecked internal/rotation/provider.go \
 'rec.ref != ref || rec.old != oldVersion ||' 'rec.ref != ref ||' 'TestProviderRevokeRefusesAForeignRunOrVersion'
mutate provider-revoker-secret-unchecked internal/rotation/provider.go \
 '!ok || rec.ref != ref ||' '!ok ||' 'TestProviderRevokeRefusesAForeignRunOrVersion'
mutate provider-forward-only-revokes-at-provider internal/rotation/provider.go \
 'if r.d.Provider.Capabilities().DualKey {' 'if true {' 'TestProviderForwardOnlyNeverCallsProviderRevoke'
mutate provider-value-not-wiped internal/rotation/provider.go \
 'defer iss.Value.Wipe()' 'defer func() {}()' 'TestProviderPrepareWipesValueAndKey'
mutate provider-fingerprint-key-not-wiped internal/rotation/provider.go \
 'defer key.Wipe()' 'defer func() { _ = key }()' 'TestProviderPrepareWipesValueAndKey'
mutate provider-issue-before-fingerprint-key internal/rotation/provider.go \
 'key, err := v.d.FingerprintKey(ctx)' 'v.d.Provider.Issue(ctx, prot.IssueRequest{}); key, err := v.d.FingerprintKey(ctx)' 'TestProviderNoIssueWhenFingerprintKeyIsUnavailable'
mutate provider-keyid-unvalidated internal/rotation/provider.go \
 'if !prot.ValidKeyID(iss.KeyID) || iss.Value.IsZero() {' 'if iss.Value.IsZero() {' 'TestProviderRefusesAMalformedIssue'
mutate provider-zero-value-accepted internal/rotation/provider.go \
 'if !prot.ValidKeyID(iss.KeyID) || iss.Value.IsZero() {' 'if !prot.ValidKeyID(iss.KeyID) {' 'TestProviderRefusesAMalformedIssue'
mutate provider-fingerprint-corrupted internal/rotation/provider.go \
 'fp, err := fingerprint.Compute(key, iss.Value)' 'fp, err := fingerprint.Compute(key, iss.Value); fp = "kfp1:k1:abcdefghijklmnop"' 'TestProviderFingerprintIsOfTheIssuedValueAndRollbackEndsThatKey'
mutate provider-rollback-wrong-key internal/rotation/provider.go \
 'if err := v.d.Provider.Revoke(rctx, keyID); err == nil {' 'if err := v.d.Provider.Revoke(rctx, keyID+"0"); err == nil {' 'TestProviderFingerprintIsOfTheIssuedValueAndRollbackEndsThatKey'
mutate provider-keyof-secret-unfiltered internal/rotation/provider.go \
 'WHERE org_id=$1 AND secret_id=$2 AND new_version=$3' 'WHERE org_id=$1 AND $2::uuid IS NOT NULL AND new_version=$3' 'TestProviderRevokerFindsOnlyThisSecretsKey'
mutate provider-keyof-org-unfiltered internal/rotation/provider.go \
 'WHERE org_id=$1 AND secret_id=$2 AND new_version=$3' 'WHERE $1::uuid IS NOT NULL AND secret_id=$2 AND new_version=$3' 'TestProviderRevokerFindsOnlyThisSecretsKey'
mutate provider-revoker-empty-old-version internal/rotation/provider.go \
 ' || oldVersion == "" {' ' {' 'TestProviderRevokerFindsOnlyThisSecretsKey'
mutate provider-version-error-forwarded internal/rotation/provider.go \
 'switch m, err := t.Store.Version(ctx, t.Ref); {' \
 'm, err := t.Store.Version(ctx, t.Ref); if err != nil && !errors.Is(err, provider.ErrNotFound) { return Version{}, errors.New(ErrPrepare.Error() + err.Error()) }; switch {' 'TestProviderAdapterErrorsHoldNoCanary'
mutate provider-fingerprint-key-error-forwarded internal/rotation/provider.go \
 'key, err := v.d.FingerprintKey(ctx)' \
 'key, err := v.d.FingerprintKey(ctx); if err != nil { return Version{}, errors.New(ErrPrepare.Error() + err.Error()) }' 'TestProviderAdapterErrorsHoldNoCanary'
mutate provider-resolve-error-forwarded internal/rotation/provider.go \
 't, err := r.d.Resolve(ctx, ref)' \
 't, err := r.d.Resolve(ctx, ref); if err != nil { return errors.New(ErrRevoke.Error() + err.Error()) }' 'TestProviderAdapterErrorsHoldNoCanary'
mutate provider-disable-error-forwarded internal/rotation/provider.go \
 'if err := t.Store.Disable(ctx, dis); err != nil && !errors.Is(err, provider.ErrNotFound) {' \
 'if err := t.Store.Disable(ctx, dis); err != nil && !errors.Is(err, provider.ErrNotFound) { return errors.New(ErrRevoke.Error() + err.Error()) }; if false {' 'TestProviderAdapterErrorsHoldNoCanary'
mutate provider-revoke-not-confirmed internal/rotation/provider.go \
 'if st, err := r.d.Provider.Check(ctx, k); err != nil || st.Active {' 'if st, err := r.d.Provider.Check(ctx, k); err != nil || (st.Active && false) {' 'TestProviderRevokeMustBeConfirmedByCheck'
mutate provider-issue-error-forwarded internal/rotation/provider.go \
 'iss, err := v.d.Provider.Issue(ctx, prot.IssueRequest{Subject: t.Subject, RunID: runID})' \
 'iss, err := v.d.Provider.Issue(ctx, prot.IssueRequest{Subject: t.Subject, RunID: runID}); if err != nil { return Version{}, errors.New(ErrPrepare.Error() + err.Error()) }' 'TestProviderAdapterErrorsHoldNoCanary'
mutate provider-revoke-error-forwarded internal/rotation/provider.go \
 'if err := r.d.Provider.Revoke(ctx, k); err != nil {' \
 'if err := r.d.Provider.Revoke(ctx, k); err != nil { return errors.New(ErrRevoke.Error() + err.Error()) }; if false {' 'TestProviderAdapterErrorsHoldNoCanary'
mutate provider-committed-row-revoked internal/rotation/provider.go \
 'case ok && got.keyID == iss.KeyID:' 'case false && ok && got.keyID == iss.KeyID:' 'TestProviderCommittedLedgerRowKeepsItsKey'
# Current and the first rotation of a DualKey secret.
mutate provider-current-ignored internal/rotation/provider.go \
 'err == nil && ok && prot.ValidKeyID(id) {' 'err == nil && ok && false && prot.ValidKeyID(id) {' 'TestProviderFirstRotationRevokesOriginalKeyAfterVerify' 1
mutate provider-original-not-persisted internal/rotation/provider.go \
 'fp: fp, orig: orig, length' 'fp: fp, orig: orig[:0], length' 'TestProviderFirstRotationRevokesOriginalKeyAfterVerify'
mutate provider-original-revoked-before-verify internal/rotation/engine.go \
 'StateDeploying, StateVerifying, ClassNone' 'StateDeploying, StateRevokingOld, ClassNone' 'TestProviderFirstRotationRevokesOriginalKeyAfterVerify'
mutate provider-new-key-revokable internal/rotation/provider.go \
 'if k != "" && k != rec.keyID && !slices.Contains(keys, k) {' 'if k != "" && !slices.Contains(keys, k) {' 'TestProviderNewKeyIsNeverRevoked'
mutate provider-current-id-unvalidated internal/rotation/provider.go \
 'err == nil && ok && prot.ValidKeyID(id) {' 'err == nil && ok {' 'TestProviderCurrentNonIDIsDropped' 1
mutate provider-incident-before-disable internal/rotation/provider.go \
 'if err := t.Store.Disable(ctx, dis); err != nil && !errors.Is(err, provider.ErrNotFound) {' \
 'if unknown { _ = r.d.Incident.Open(ctx, IncidentRecord{Ref: ref, RunID: runID, Class: ClassOriginalKeyUnknown}); unknown = false }; if err := t.Store.Disable(ctx, dis); err != nil && !errors.Is(err, provider.ErrNotFound) {' 'TestProviderUnknownKeyThenDisableFailureIsRevokeFailed'
mutate provider-no-incident-sink-check internal/rotation/provider.go \
 'DualKey && v.d.Incident == nil {' 'DualKey && v.d.Incident == nil && false {' 'TestProviderDualKeyNeedsAnIncidentSink' 1
mutate provider-unknown-masked-by-ledger-key internal/rotation/provider.go \
 'unknown = rec.orig == "" || rec.orig == rec.keyID' 'unknown = len(keys) == 0' 'TestProviderUnknownCurrentIsRecordedEvenWithALedgerKey'
mutate provider-rollback-unconfirmed internal/rotation/provider.go \
 'if st, err := v.d.Provider.Check(rctx, keyID); err == nil && !st.Active {' 'if true {' 'TestProviderRollbackIsConfirmedOrAnIncident'
mutate provider-no-intent-before-issue internal/rotation/provider.go \
 'if fresh, err := v.d.Ledger.intend(ctx, ref, runID); err != nil || !fresh {' 'if _, err := v.d.Ledger.intend(ctx, ref, runID); err != nil {' 'TestProviderReplayAfterLostLedgerRowNeverIssuesAgain'
mutate provider-intent-always-fresh internal/rotation/provider.go \
 'return err == nil && tag.RowsAffected() == 1, err' 'return err == nil && tag.RowsAffected() >= 0, err' 'TestProviderReplayAfterLostLedgerRowNeverIssuesAgain'
mutate provider-intent-call-removed internal/rotation/provider.go \
 'if fresh, err := v.d.Ledger.intend(ctx, ref, runID); err != nil || !fresh {' 'if fresh := true; !fresh {' 'TestProviderReplayAfterLostLedgerRowNeverIssuesAgain'
mutate provider-unknown-key-no-incident internal/rotation/provider.go \
 'unknown = rec.orig == "" || rec.orig == rec.keyID' 'unknown = false' 'TestProviderUnknownOriginalKeyIsNotRevoked'
mutate provider-unknown-key-disabled-without-incident internal/rotation/provider.go \
 'if err := r.d.Incident.Open(ctx, IncidentRecord{Ref: ref, RunID: runID, Class: ClassOriginalKeyUnknown}); err != nil {' \
 'if err := r.d.Incident.Open(ctx, IncidentRecord{Ref: ref, RunID: runID, Class: ClassOriginalKeyUnknown}); err != nil && false {' 'TestProviderUnknownOriginalKeyNeedsTheIncident'

mutate start-revoke-pending-reported-as-conflict internal/rotation/store.go \
 'qe == nil && pending' 'qe != nil && pending' 'TestRevokePendingBlocksNewRun'
mutate start-revoke-pending-query-matches-nothing internal/rotation/store.go \
 "state='revoking_old' AND error_class=\$3" "state='no_such_state' AND error_class=\$3" 'TestRevokePendingBlocksNewRun'

mutate binding-length-prefix-dropped internal/rotation/approval.go \
 '_, _ = h.Write(n[:])' '_ = n' 'TestRotationBinding_CoversEveryFieldAndIsUnambiguous'
mutate binding-drops-run internal/rotation/approval.go \
 'secret.String(), run.String(), string(a.Type)' 'secret.String(), string(a.Type)' 'TestRotationBinding_CoversEveryFieldAndIsUnambiguous'
mutate binding-drops-sponsor internal/rotation/approval.go \
 'a.ID, a.SponsorID, string(a.Via))' 'a.ID, string(a.Via))' 'TestRotationBinding_CoversEveryFieldAndIsUnambiguous'
mutate generator-short-entropy internal/rotation/generate.go \
 'io.ReadFull(src, raw)' 'src.Read(raw)' 'TestGeneratorIssuesFreshValidKeys'
mutate adopt-other-version internal/rotation/provider.go \
 'got.ref != ref || got.new != ver.New' 'got.ref != ref' 'TestProviderAdoptRecordsTheEnteredVersionPerRun'
mutate start-prepared-prod-allowed internal/rotation/service.go \
 'if prepared != nil {' 'if false {' 'TestStartPreparedRefusesAProdSecret' 1
mutate start-prepared-no-adopt internal/rotation/service.go \
 'if write, err = a.Adopt(ctx, ref, id, *prepared); err != nil {' 'if write, err = nil, error(nil); a == nil || err != nil {' 'TestStartPreparedRecordsTheVersionBeforeTheRun'
mutate start-prepared-slot-conflict-ignored internal/rotation/service.go \
 'if err = s.e.store.startTx(ctx, tx, ref, id); err != nil {' 'if err = s.e.store.startTx(ctx, tx, ref, id); err != nil && false {' 'TestStartPreparedThatLosesTheSlotLeavesNoLedgerRow'
mutate start-prepared-write-off-transaction internal/rotation/provider.go \
 'v.d.Ledger.putTx(ctx, tx, rec)' 'v.d.Ledger.put(ctx, rec)' 'TestStartPreparedWithoutItsRecordLeavesNoLedgerRow TestStartPreparedConcurrentStartsDoNotExhaustThePool'

# Resume of a run nothing drives: each mutant switches off one property.
mutate resume-noop internal/rotation/resume.go \
 'runs, err := s.e.store.claimResumes(ctx, cfg, s.now(), s.inflightIDs())' 'runs, err := []resumable(nil), error(nil)' 'TestResumeLaysOutARunTheHookLeftActive'
mutate resume-takes-nothing-back internal/rotation/resume.go \
 's.launch(ctx, r.ref, r.id, o, approval, nil)' '_, _, _ = r, o, approval' 'TestResumeLaysOutARunTheHookLeftActive'
mutate resume-takes-own-goroutine internal/rotation/resume.go \
 'claimResumes(ctx, cfg, s.now(), s.inflightIDs())' 'claimResumes(ctx, cfg, s.now(), []uuid.UUID{})' 'TestResumeEachLiveRunGuardHoldsAlone'
mutate resume-goroutine-untracked internal/rotation/service.go \
 's.track(id, true)' 's.track(id, false)' 'TestResumeEachLiveRunGuardHoldsAlone'
mutate resume-takes-live-lease internal/rotation/store.go \
 "AND (r.lease_owner='' OR r.lease_until IS NULL OR r.lease_until < \$1)" 'AND true' 'TestResumeEachLiveRunGuardHoldsAlone'
mutate resume-takes-young-run internal/rotation/store.go \
 'AND r.updated_at < clock_timestamp() - make_interval(secs => $2::float8)' 'AND true' 'TestResumeLeavesAYoungRunAlone'
mutate resume-ignores-backoff internal/rotation/store.go \
 'AND (r.resume_after IS NULL OR r.resume_after <= $1)' 'AND true' 'TestResumeBackoffSpacesAttempts'
mutate resume-attempts-uncounted internal/rotation/store.go \
 'resume_attempts=r.resume_attempts+1' 'resume_attempts=r.resume_attempts' 'TestResumeGivesUpAndFreesTheSecret'
mutate resume-never-gives-up internal/rotation/store.go \
 "SET state='failed', error_class=\$4," 'SET state=r.state, error_class=$4,' 'TestResumeGivesUpAndFreesTheSecret'
mutate resume-two-servers-share-a-run internal/rotation/store.go \
 'ORDER BY r.updated_at LIMIT $7 FOR UPDATE OF r SKIP LOCKED' 'ORDER BY r.updated_at LIMIT $7' 'TestResumeSkipsARunAnotherServerIsClaiming'

# Rollback of a failed DualKey run: carriers back on the old version, read back,
# and only then the new key ended. Each mutant switches off one step; the named
# test must be the one that catches it.
mutate rollback-never-entered internal/rotation/engine.go \
 '&& run.OldVersion != "" && rollsBack(c) {' '&& run.OldVersion != "" && rollsBack(c) && false {' 'TestRollbackPutsCarriersBackThenEndsTheNewKey'
mutate rollback-class-set-open internal/rotation/engine.go \
 'case ClassDeployFailed, ClassVerifyFailed, ClassUnhealthy, ClassFingerprintMismatch:' 'case ClassDeployFailed, ClassVerifyFailed, ClassUnhealthy, ClassFingerprintMismatch, ClassSuperseded:' 'TestRollbackSkipsASupersededRun'
mutate rollback-of-an-adopted-version internal/rotation/provider.go \
 'return ok && rec.ref == ref && !rec.adopted && rec.old != "", nil' 'return ok && rec.ref == ref && rec.old != "", nil' 'TestProviderCanRollbackOnlyForAnIssuedKeyOfADualKeyProvider'
mutate rollback-without-old-version internal/rotation/provider.go \
 'return ok && rec.ref == ref && !rec.adopted && rec.old != "", nil' 'return ok && rec.ref == ref && !rec.adopted, nil' 'TestProviderCanRollbackOnlyForAnIssuedKeyOfADualKeyProvider'
mutate rollback-readback-skipped internal/rotation/engine.go \
 'if verr != nil || !rep.Healthy || !fingerprint.Valid(rep.Fingerprint) || rep.Fingerprint == run.ExpectedFP {' 'if verr != nil && rep.Healthy && fingerprint.Valid(rep.Fingerprint) && rep.Fingerprint == run.ExpectedFP && false {' 'TestRollbackUnconfirmedLeavesTheNewKey'
mutate rollback-new-fingerprint-accepted internal/rotation/engine.go \
 '|| rep.Fingerprint == run.ExpectedFP {' '{' 'TestRollbackUnconfirmedLeavesTheNewKey/still_new_key'
mutate rollback-unhealthy-accepted internal/rotation/engine.go \
 'verr != nil || !rep.Healthy ||' 'verr != nil ||' 'TestRollbackUnconfirmedLeavesTheNewKey/unhealthy'
mutate rollback-key-ended-unconfirmed internal/rotation/engine.go \
 'if len(unconfirmed) > 0 {' 'if false {' 'TestRollbackUnconfirmedLeavesTheNewKey'
mutate rollback-carrier-never-put-back internal/rotation/engine.go \
 'derr := e.deployer.Deploy(sctx, run.Ref, run.ID, Carrier{ID: s.CarrierID}, run.OldVersion)' 'var derr error' 'TestRollbackPutsCarriersBackThenEndsTheNewKey'
mutate rollback-not-marked-as-rollback internal/rotation/engine.go \
 'e.fence(withRollback(ctx), run.ID)' 'e.fence(ctx, run.ID)' 'TestRollbackPutsCarriersBackThenEndsTheNewKey'
mutate rollback-read-not-marked-as-rollback internal/rotation/engine.go \
 'vctx := withRollback(ctx)' 'vctx := ctx' 'TestRollbackPutsCarriersBackThenEndsTheNewKey'
mutate rollback-reads-a-carrier-not-put-back internal/rotation/engine.go \
 'if s.Deploy == "ok" && putBack[s.CarrierID] {' 'if s.Deploy == "ok" {' 'TestRollbackUnconfirmedLeavesTheNewKey/deploy_refused'
mutate rollback-incident-not-recorded internal/rotation/engine.go \
 'if err := e.store.markIncident(ctx, run.ID); err != nil {' 'if err := error(nil); err != nil {' 'TestRollbackUnconfirmedLeavesTheNewKey'
mutate rollback-incident-class-lost internal/rotation/engine.go \
 'Class: ClassRollbackUnconfirmed, Carriers: carriers}' 'Class: run.Class, Carriers: carriers}' 'TestRollbackUnconfirmedLeavesTheNewKey'
mutate rollback-key-failure-silent internal/rotation/engine.go \
 'if rerr := rb.RollbackNew(sctx, run.Ref, run.ID); rerr != nil {' 'if rerr := rb.RollbackNew(sctx, run.Ref, run.ID); rerr != nil && false {' 'TestRollbackNewKeyNotEndedIsAnIncident'
mutate rollback-class-forgotten internal/rotation/engine.go \
 'if err := e.store.setState(ctx, run.ID, StateRollingBack, StateFailed, run.Class); err != nil {' 'if err := e.store.setState(ctx, run.ID, StateRollingBack, StateFailed, ClassNone); err != nil {' 'TestRollbackPutsCarriersBackThenEndsTheNewKey' 2
mutate rollback-refused-class-forgotten internal/rotation/engine.go \
 'if err := e.store.setState(ctx, run.ID, StateRollingBack, StateFailed, run.Class); err != nil {' 'if err := e.store.setState(ctx, run.ID, StateRollingBack, StateFailed, ClassNone); err != nil {' 'TestRollbackOnlyWhereItAppliesKeepsTheOldBehaviour/forward-only' 1
mutate rollback-key-needs-check internal/rotation/provider.go \
 'if st, err := v.d.Provider.Check(ctx, rec.keyID); err != nil || st.Active {' 'if st, err := v.d.Provider.Check(ctx, rec.keyID); false && (err != nil || st.Active) {' 'TestProviderRollbackNeedsCheckToConfirm'
mutate rollback-ends-the-key-of-the-old-version internal/rotation/provider.go \
 'kerr != nil || (oldKey != "" && oldKey == rec.keyID)' 'kerr != nil || (oldKey != "" && oldKey == rec.keyID && false)' 'TestProviderRollbackNeverEndsTheKeyOfTheOldVersion'
mutate rollback-capability-error-read-as-no internal/rotation/engine.go \
 'can, err := rb.CanRollback(ctx, run.Ref, run.ID)' 'can, err := rb.CanRollback(ctx, run.Ref, run.ID); if err != nil { can, err = false, nil }' 'TestRollbackCapabilityErrorKeepsTheRunRollingBack'
mutate rollback-give-up-without-incident internal/rotation/resume.go \
 'if r.prev == StateRollingBack {' 'if r.prev == StateRollingBack && false {' 'TestResumeGiveUpInRollingBackOpensTheIncident'
mutate rollback-give-up-incident-not-recorded internal/rotation/store.go \
 "SET incident_opened=true WHERE id=\$1 AND state='failed'" "SET incident_opened=false WHERE id=\$1 AND state='failed'" 'TestResumeGiveUpInRollingBackOpensTheIncident'
mutate rollback-unconfirmed-class-forgotten internal/rotation/engine.go \
 'final := run.Class //' 'final := ClassNone //' 'TestRollbackUnconfirmedLeavesTheNewKey'
mutate rollback-without-old-version-in-engine internal/rotation/engine.go \
 'run.OldVersion != "" && rollsBack(c)' 'rollsBack(c)' 'TestRollbackOnlyWhereItAppliesKeepsTheOldBehaviour'
mutate rollback-adopted-not-recorded internal/rotation/provider.go \
 'orig: orig, adopted: true}' 'orig: orig, adopted: false}' 'TestProviderCanRollbackOnlyForAnIssuedKeyOfADualKeyProvider'
mutate rollback-never-ends-the-original-key internal/rotation/provider.go \
 'if rec.keyID == rec.orig {' 'if false {' 'TestProviderRollbackNeverEndsTheOriginalKey'
mutate rollback-disables-the-old-version internal/rotation/provider.go \
 'dis.Version = rec.new' 'dis.Version = rec.old' 'TestProviderFailedRunEndsOnlyTheNewKey'
mutate rollback-ends-the-original-key internal/rotation/provider.go \
 'if err := v.d.Provider.Revoke(ctx, rec.keyID); err != nil {' 'if err := v.d.Provider.Revoke(ctx, rec.orig); err != nil {' 'TestProviderFailedRunEndsOnlyTheNewKey'
mutate rollback-pending-carrier-not-put-back internal/rotation/engine.go \
 'case "failed", "pending":' 'case "failed":' 'TestRollbackPutsCarriersBackThenEndsTheNewKey'
mutate rollback-unread-carriers-stop-the-read internal/rotation/engine.go \
 'return true // the others are read all the same' 'return false // the others are read all the same' 'TestRollbackIncidentNamesOnlyTheCarriersThatFailed'
mutate rollback-disable-error-swallowed internal/rotation/provider.go \
 'derr != nil && !errors.Is(derr, provider.ErrNotFound)' 'false && derr != nil' 'TestProviderRollbackNeedsCheckToConfirm'
mutate migration-down-leaves-rolling-back internal/store/migrations/00053_rotation_rolling_back.sql \
 "UPDATE rotation_runs SET state='failed' WHERE state='rolling_back';" '' 'TestRollingBackMigrationDownAndUp'
mutate migration-state-not-accepted internal/store/migrations/00053_rotation_rolling_back.sql \
 "'revoking_old','rolling_back','done','failed'));" "'revoking_old','done','failed'));" 'TestRollingBackMigrationDownAndUp'

# The unmutated tree is green: a script whose baseline is red proves nothing.
if mutation_apply_only; then
	:
else
mutation_snapshot "$work/tree"
# shellcheck disable=SC2086
if (cd "$work/tree" && timeout -k 10s 300s go test -timeout 200s -count=1 -p 1 -v $pkgs >"$work/out" 2>&1); then
	if grep -q -- '--- SKIP' "$work/out"; then
        echo "FAIL baseline: skipped tests"
        fail=1
    else
        echo "ok   baseline: tests green on the real code (0 SKIP)"
    fi
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi
fi

mutation_shard_finish
exit "$fail"
