#!/bin/sh
# Proves the rotation tests can fail: in a scratch copy of the
# tree, switch off one property at a time and require the tests of
# cmd/keep-server to go red. A property whose removal
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
	echo "FAIL check-rotation-wiring-mutations: KEEP_DATABASE_URL is not set — the tests would skip, not fail, which this script must never report as red"
	exit 1
fi

fail=0
# edit SRC FROM TO: print SRC with the first literal occurrence of FROM
# replaced by TO; exit 1 if FROM is not there.
edit() {
	awk -v from="$2" -v to="$3" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$1"
}

pkgs="-run ^TestRotateE2E ./cmd/keep-server/app/"

# Setup uses sanitized store connection errors, while subsequent pgx/sql
# operations can return driver errors directly. Neither proves a rotation
# property. Keep these connection/lifecycle classes separate from ordinary
# product context deadlines and constraint violations (e.g. SQLSTATE 23503).
rotation_database_failed() {
	grep -q -E 'failed to connect to|connection failed \(|connection refused|connection reset by peer|broken pipe|unexpected EOF|i/o timeout|conn closed|sql: (database is closed|connection is already closed)|driver: bad connection|SQLSTATE (08[0-9A-Z]{3}|57P0[123]|53300)' "$1"
}

# mutate NAME FILE FROM TO [WANT]: FILE is relative to the repo root. WANT,
# when given, is a space-separated list of `--- FAIL: ` prefixes that MUST
# all appear in the red run — a mutant is not proven to isolate the property
# it claims to just because *some* test went red; the wrong test catching it
# (a different, unrelated check that happened to also depend on the mutated
# line) proves nothing about the property WANT names. Mirrors the
# `--- FAIL: WANT` check in check-identity-attack-mutations.sh.
mutate() {
	mutation_selected || return 0
	name=$1 src=$2 from=$3 to=$4 want=${5:-} from2=${6:-} to2=${7:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if [ "$from" = "@remove-file" ]; then
		printf '%s\n' 'package main' >"$work/tree/$src"
	elif ! edit "$root/$src" "$from" "$to" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	# A second edit, for a property two code paths enforce: one alone is masked
	# by the other, so both are switched off together.
	if [ -n "$from2" ]; then
		if ! edit "$work/tree/$src" "$from2" "$to2" >"$work/tree/$src.next"; then
			echo "FAIL $name: second mutation did not apply — the source changed, update this script"
			fail=1
			return
		fi
		mv "$work/tree/$src.next" "$work/tree/$src"
	fi
	mutation_applied "$name" && return
	# shellcheck disable=SC2086
	if (cd "$work/tree" && timeout -k 10s 600s go test -timeout 480s -count=1 -p 1 -v $pkgs >"$work/out" 2>&1); then
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
		! awk '$1 == "FAIL" && $2 == "github.com/entire-vc/evc-keep/cmd/keep-server/app" && $3 ~ /^[0-9.]+s$/ { found=1 } END { exit !found }' "$work/out" ||
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
		echo "FAIL $name: red, but not on:$missing (the wrong test/subtest caught it):"
		fail=1
		return
	fi
	echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)${want:+, confirmed on: $want}"
}

# The hook itself has no mutant: it is the fast path, and the sweeper (mutants
# below) is what guarantees the layout, so removing the hook only delays it.
# Each mutant switches off one guard of keep-server's rotation wiring; the
# named end-to-end test must be the one that catches it.
mutate deploy-refusal-off internal/rotation/rotwire/rotwire.go \
 'if !res.OK || res.ErrorClass != "" || res.Version != version || !healthy {' \
 'if (!res.OK || res.ErrorClass != "" || res.Version != version || !healthy) && false {' 'TestRotateE2E_OneFailingCarrierActivatesNothing'
mutate revoke-pending-unmapped internal/api/rotate.go \
 'writeAppError(w, rotationAppError(err), rid)' 'writeAppError(w, err, rid)' 'TestRotateE2E_RevokePendingIs409'
mutate catalog-old-version-left-enabled cmd/keep-server/app/rotation.go \
 'SET disabled=true WHERE org_id=$1 AND secret_id=$2 AND provider_version=$3`, ref.OrgID, ref.SecretID, oldVersion)' 'SET disabled=false WHERE org_id=$1 AND secret_id=$2 AND provider_version=$3`, ref.OrgID, ref.SecretID, oldVersion)' 'TestRotateE2E_AllCarriersConfirmed' \
 'SET disabled=true WHERE org_id=$1 AND secret_id=$2 AND provider_version=$3`, ref.OrgID, ref.SecretID, v)' 'SET disabled=false WHERE org_id=$1 AND secret_id=$2 AND provider_version=$3`, ref.OrgID, ref.SecretID, v)'
mutate hook-panic-not-contained internal/intake/service.go \
 'defer func() { _ = recover() }()' '' 'TestRotateE2E_PanickingHookDoesNotFailTheInput'
mutate input-conflict-dropped cmd/keep-server/app/rotation.go \
 'ri.release(ctx, p, rotationRetryEvery)' 'ri.finish(ctx, p)' 'TestRotateE2E_HumanInputWaitsForTheActiveRun'
mutate pending-sweeper-not-run cmd/keep-server/app/rotation.go \
 '		sweep(ctx)' '		_ = sweep' 'TestRotateE2E_PendingLayoutSurvivesRestart TestRotateE2E_HumanInputSurvivesTransientAdoptFailure'
mutate failed-layout-never-retried cmd/keep-server/app/rotation.go \
 'claimed_until=clock_timestamp()+$3::interval' "claimed_until=clock_timestamp()+interval '1 hour'" 'TestRotateE2E_HumanInputSurvivesTransientAdoptFailure'
mutate claim-ownership-not-rechecked cmd/keep-server/app/rotation.go \
 'AND started_at IS NULL AND claim_token=$3 RETURNING true' 'AND started_at IS NULL AND $3::uuid IS NOT NULL RETURNING true' 'TestRotateE2E_ExpiredClaimDoesNotStartTheLayout'
mutate permanent-failure-retried-forever cmd/keep-server/app/rotation.go \
 'if n >= rotationMaxAttempts {' 'if n >= rotationMaxAttempts && false {' 'TestRotateE2E_PermanentFailureIsAbandoned'
mutate failed-layout-marked-done cmd/keep-server/app/rotation.go \
 'fail := func(class string, wait time.Duration) {' 'fail := func(class string, wait time.Duration) { defer ri.finish(ctx, p);' 'TestRotateE2E_HumanInputSurvivesTransientAdoptFailure'
mutate superseded-input-laid-out cmd/keep-server/app/rotation.go \
 '	if newer {' '	if false && newer {' 'TestRotateE2E_OlderInputHandledFirstGetsNoRun'
mutate newer-input-by-created-at cmd/keep-server/app/rotation.go \
 'ov.seal_seq > mv.seal_seq' '(ov.created_at, ov.id) > (mv.created_at, mv.id)' 'TestRotateE2E_NewestIsTheLastSealedNotTheLatestTimestamp'
mutate predecessor-by-created-at cmd/keep-server/app/rotation.go \
 'ORDER BY v.seal_seq DESC LIMIT 1), ' 'ORDER BY v.created_at DESC, v.id DESC LIMIT 1), ' 'TestRotateE2E_PredecessorFallbackFollowsSealOrder'
mutate deployed-pointer-not-updated internal/rotation/engine.go \
 'if m, ok := e.revoker.(DeployedMarker); ok {' 'if m, ok := e.revoker.(DeployedMarker); ok && false {' 'TestRotateE2E_DeployedVersionPointerFeedsThePredecessor'
mutate deployed-pointer-ignored-by-predecessor cmd/keep-server/app/rotation.go \
 'WHERE s.org_id=$1 AND s.id=$2 AND d.seal_seq < cur.seal_seq),' 'WHERE s.org_id=$1 AND s.id=$2 AND false),' 'TestRotateE2E_DeployedVersionPointerFeedsThePredecessor'
mutate current-version-by-created-at internal/deployment/verify.go \
 'NOT disabled ORDER BY seal_seq DESC LIMIT 1`' 'NOT disabled ORDER BY created_at DESC,id DESC LIMIT 1`' 'TestRotateE2E_NewestIsTheLastSealedNotTheLatestTimestamp'
mutate plain-input-excluded-as-predecessor cmd/keep-server/app/rotation.go \
 " JOIN intake_rotation_links rl ON rl.org_id=il.org_id AND rl.request_id=il.request_id" "" 'TestRotateE2E_PlainInputVersionIsTheRevokedPredecessor'
mutate late-plain-input-not-marked internal/intake/service.go \
 'SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM rotation_runs' 'SELECT $1,$2 WHERE false AND EXISTS(SELECT 1 FROM rotation_runs' 'TestRotateE2E_PlainInputDuringARunEndsWithOneActiveVersion'
mutate plain-input-always-marked internal/intake/service.go \
 'SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM rotation_runs' 'SELECT $1,$2 WHERE true OR EXISTS(SELECT 1 FROM rotation_runs' 'TestRotateE2E_PlainInputLinkStartsNothing'
mutate older-versions-left-active cmd/keep-server/app/rotation.go \
 'for _, v := range stale {' 'for _, v := range stale[:0] {' 'TestRotateE2E_GivenUpOlderInputIsDisabledByTheNextRun'
mutate retired-input-laid-out cmd/keep-server/app/rotation.go \
 '	if gone {' '	if gone && false {' 'TestRotateE2E_InputRetiredByAGeneratedRotationIsNotLaidOut'
mutate retire-lock-removed cmd/keep-server/app/rotation.go \
 'tx.Exec(ctx, rotationLockRow, ref.OrgID, ref.SecretID)' 'tx.Exec(ctx, `SELECT 1`)' 'TestRotateE2E_ConcurrentSealDuringRetireLeavesOneActive'
mutate seal-lock-removed internal/intake/service.go \
 'FOR UPDATE OF l FOR SHARE OF s,st' 'FOR UPDATE OF l FOR SHARE OF st' 'TestRotateE2E_SealWaitsForTheRetireLock'
mutate retire-keeps-the-oldest cmd/keep-server/app/rotation.go \
 'SELECT max(m.seal_seq) FROM secret_versions m' 'SELECT min(m.seal_seq) FROM secret_versions m' 'TestRotateE2E_ConcurrentSealDuringRetireLeavesOneActive'
mutate superseded-not-detected internal/rotation/engine.go \
 'cerr == nil && newer {' 'cerr == nil && newer && false {' 'TestRotateE2E_RunSupersededByNewerSealedVersion'
mutate superseded-opens-incident internal/rotation/engine.go \
 ' && run.Class != ClassSuperseded {' ' {' 'TestRotateE2E_RunSupersededByNewerSealedVersion'
mutate superseded-masked-as-internal internal/api/rotate.go \
 ', rotation.ClassSuperseded}' '}' 'TestRotateE2E_RunSupersededByNewerSealedVersion'
mutate resume-sweep-unwired cmd/keep-server/app/rotation.go \
 'n, err := svc.Resume(ctx)' 'n, err := 0, error(nil); _ = svc' 'TestRotateE2E_AbandonedRunIsResumed'
mutate resume-sweep-wired-without-service cmd/keep-server/app/rotation.go \
 'if !ok {' 'if false && !ok {' 'TestRotateE2E_ResumeSweepNeedsTheService'
# The baseline runs on an unmutated snapshot, not on the last mutant.
rm -rf "$work/tree"
mutation_snapshot "$work/tree"
# shellcheck disable=SC2086
if mutation_apply_only; then
	:
elif (cd "$work/tree" && timeout -k 10s 600s go test -timeout 480s -count=1 -p 1 -v $pkgs >"$work/out" 2>&1); then
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

mutation_shard_finish
exit "$fail"
