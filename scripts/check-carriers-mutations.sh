#!/bin/sh
# Proves the carrier tests can fail: in a scratch copy of the
# tree, switch off one property at a time and require the tests of
# internal/carriers to go red. A property whose removal
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

if ! mutation_apply_only && [ -z "${KEEP_DATABASE_URL:-}" ]; then
	echo "FAIL check-carriers-mutations: KEEP_DATABASE_URL is not set — the tests would skip, not fail, which this script must never report as red"
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

pkgs="./internal/carriers/"

# Setup uses sanitized store connection errors, while subsequent pgx/sql
# operations can return driver errors directly. Neither proves a carrier
# property. Keep these connection/lifecycle classes separate from ordinary
# product context deadlines and constraint violations (e.g. SQLSTATE 23503).
carrier_database_failed() {
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
	name=$1 src=$2 from=$3 to=$4 want=${5:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if [ "$from" = "@remove-file" ]; then
		printf '%s\n' 'package carriers' >"$work/tree/$src"
	elif ! edit "$root/$src" "$from" "$to" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	# shellcheck disable=SC2086
	if (cd "$work/tree" && timeout -k 10s 180s go test -timeout 90s -count=1 -p 1 -v $pkgs >"$work/out" 2>&1); then
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
		! awk '$1 == "FAIL" && $2 == "github.com/entire-vc/evc-keep/internal/carriers" && $3 ~ /^[0-9.]+s$/ { found=1 } END { exit !found }' "$work/out" ||
		grep -q -E '^panic:|^fatal error:|signal: killed|\[build failed\]|\[setup failed\]|--- SKIP' "$work/out" ||
		mutation_infrastructure_failed "$work/out" ||
		carrier_database_failed "$work/out"; then
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

# Turn off independently observable tenant guards and require the isolation
# test itself (not an unrelated schema failure) to catch each mutation.
mutate list-any-org internal/carriers/repo.go \
 'SELECT id FROM secrets WHERE org_id=$1 AND id=$2`' \
 'SELECT id FROM secrets WHERE $1::uuid IS NOT NULL AND id=$2`' 'TestTenantIsolation'
mutate remove-any-org internal/carriers/repo.go \
 'DELETE FROM carriers WHERE org_id=$1 AND id=$2' \
 'DELETE FROM carriers WHERE $1::uuid IS NOT NULL AND id=$2' 'TestTenantIsolation'
mutate unknown-any-org internal/carriers/repo.go \
 'WHERE org_id=$1 AND id=$2`, org, id)' \
 'WHERE $1::uuid IS NOT NULL AND id=$2`, org, id)' 'TestTenantIsolation'
mutate register-not-idempotent internal/carriers/repo.go \
 'DO UPDATE SET version=EXCLUDED.version, consumer=EXCLUDED.consumer,' \
 'DO UPDATE SET id=EXCLUDED.id, version=EXCLUDED.version, consumer=EXCLUDED.consumer,' 'TestIdempotentRegistration'
mutate metadata-policy-off internal/carriers/repo.go \
 'if err != nil || !allowed {' \
 'if false && (err != nil || !allowed) {' 'TestMetadataCanary'
mutate foreign-key-accepted internal/carriers/repo.go \
 'a.KeyID == b.KeyID' \
 '(a.KeyID != "" && b.KeyID != "")' 'TestFingerprintGate'
mutate malformed-fingerprint-accepted internal/carriers/repo.go \
 'return false' 'return true' 'TestFingerprintGate'
mutate stale-marked-ok internal/carriers/repo.go \
 '(state == Registered && !sameFingerprint(fp, expected))' \
 '(false && state == Registered && !sameFingerprint(fp, expected))' 'TestStatesAndDeployHook TestOldFingerprintReplay'
mutate catalog-version-race internal/carriers/repo.go \
 "AND status='active' FOR UPDATE" \
 "AND status='active'" 'TestCatalogVersionCannotRaceRegistration'
mutate failed-deploy-accepted internal/carriers/repo.go \
 'if !result.OK || result.ErrorClass != "" || result.Version != in.Version || !sameFingerprint(result.Fingerprint, in.LastFP) {' \
 'if result.Version != in.Version || !sameFingerprint(result.Fingerprint, in.LastFP) {' 'TestDeploymentFailureIsNotRegistration'
mutate database-error-echoed internal/carriers/repo.go \
 'return Carrier{}, ErrInternal // Never expose the database error.' \
 'return Carrier{}, err' 'TestDatabaseErrorsAreSanitized'
mutate schema-value-column internal/store/migrations/00015_carriers.sql \
 'host TEXT NOT NULL,' 'host TEXT NOT NULL, value TEXT,' 'TestClosedSchemaAndDowngrade'

# Each previously surviving guard has a dedicated behavioral witness.
mutate register-wrong-content internal/carriers/repo.go \
 '|| !sameFingerprint(in.LastFP, expected)' '' 'TestRegistrationRejectsDifferentHashUnderCurrentKey'
mutate rotation-fingerprint-not-updated internal/carriers/repo.go \
 'last_fp=EXCLUDED.last_fp,' '' 'TestRegistrationUpdatesAfterRotation'
mutate rotation-version-not-updated internal/carriers/repo.go \
 'version=EXCLUDED.version,' '' 'TestRegistrationUpdatesAfterRotation'
mutate begin-error-exposed internal/carriers/repo.go \
 'return nil, ErrInternal // Begin failed; never expose its error.' 'return nil, err' 'TestDatabaseBeginErrorsAreSanitized'
mutate current-secret-error-exposed internal/carriers/repo.go \
 'return "", "", ErrInternal // Secret lookup failed; never expose its error.' 'return "", "", err' 'TestDatabaseCurrentErrorsAreSanitized/secrets'
mutate current-version-error-exposed internal/carriers/repo.go \
 'return "", "", ErrInternal // Version lookup failed; never expose its error.' 'return "", "", err' 'TestDatabaseCurrentErrorsAreSanitized/secret_versions'
mutate list-lookup-error-exposed internal/carriers/repo.go \
 'return nil, ErrInternal // List lookup failed; never expose its error.' 'return nil, err' 'TestDatabaseListErrorPathsAreSanitized/lookup'
mutate list-query-error-exposed internal/carriers/repo.go \
 'return nil, ErrInternal // List query failed; never expose its error.' 'return nil, err' 'TestDatabaseListErrorPathsAreSanitized/query'
mutate list-scan-error-exposed internal/carriers/repo.go \
 'return nil, ErrInternal // List scan failed; never expose its error.' 'return nil, err' 'TestDatabaseListErrorPathsAreSanitized/scan'
mutate list-iteration-error-exposed internal/carriers/repo.go \
 'return nil, ErrInternal // List iteration failed; never expose its error.' 'return nil, rows.Err()' 'TestDatabaseListErrorPathsAreSanitized/rows'
mutate mark-lookup-error-exposed internal/carriers/repo.go \
 'return ErrInternal // Carrier lookup failed; never expose its error.' 'return err' 'TestDatabaseMarkLookupErrorsAreSanitized'
mutate register-commit-error-exposed internal/carriers/repo.go \
 'return Carrier{}, ErrInternal // Register commit failed; never expose its error.' 'return Carrier{}, err' 'TestDatabaseCommitErrorsAreSanitized/register'
mutate mark-commit-error-exposed internal/carriers/repo.go \
 'return ErrInternal // Mark commit failed; never expose its error.' 'return err' 'TestDatabaseCommitErrorsAreSanitized/mark-ok TestDatabaseCommitErrorsAreSanitized/mark-stale'
mutate disabled-secret-accepted internal/carriers/repo.go \
 "AND status='active' FOR UPDATE" 'FOR UPDATE' 'TestInactiveCatalogCannotRegister/secret-disabled-true'
mutate disabled-version-accepted internal/carriers/repo.go \
 'AND NOT disabled ORDER BY' 'ORDER BY' 'TestInactiveCatalogCannotRegister/secret-disabled-false'
mutate fingerprint-check-removed internal/store/migrations/00015_carriers.sql \
 "CHECK (last_fp ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$')" '' 'TestDirectCarrierConstraints/fingerprint'
mutate state-check-removed internal/store/migrations/00015_carriers.sql \
 "CHECK (state IN ('registered', 'stale', 'unknown'))" '' 'TestDirectCarrierConstraints/state'
mutate secret-fk-removed internal/store/migrations/00015_carriers.sql \
 'FOREIGN KEY (org_id, secret_id) REFERENCES secrets(org_id, id),' '' 'TestDirectCarrierConstraints/secret-fk'
mutate version-share-lock-removed internal/carriers/repo.go \
 'LIMIT 1 FOR SHARE' 'LIMIT 1' 'TestCatalogVersionRowCannotRaceRegistration'
mutate metadata-formatting-removed internal/carriers/format.go \
 '@remove-file' '' 'TestMetadataCanary TestMetadataSerializationRefused'
mutate metadata-gob-encode-accepted internal/carriers/format.go \
 'return nil, ErrMetadata' 'return nil, nil' 'TestMetadataSerializationRefused'
mutate metadata-gob-decode-accepted internal/carriers/format.go \
 'GobDecode([]byte) error     { return ErrMetadata }' 'GobDecode([]byte) error     { return nil }' 'TestMetadataSerializationRefused'
mutate metadata-json-decode-accepted internal/carriers/format.go \
 'UnmarshalJSON' 'decodeJSON' 'TestMetadataSerializationRefused'
mutate metadata-text-decode-accepted internal/carriers/format.go \
 'UnmarshalText([]byte) error { return ErrMetadata }' 'UnmarshalText([]byte) error { return nil }' 'TestMetadataSerializationRefused'

# Registration needs proof: an approved destination and a completed deployment
# of exactly this version there; the fingerprint comes from that deployment.
# The runner's revoked/expired state and the organization are each checked
# twice (in the runner query and again by GetDeliveryTrust), so no single
# mutation of either is red; likewise the policy check in Service.Register
# repeats the one in Repository.Register (the first is pinned by its order:
# an unapproved host is ErrMetadata before any deployment is looked up); the tests cover them with revoked-runner and
# foreign-organization cases and positive controls.
mutate svc-policy-skipped internal/carriers/deploy.go \
 'if !ok {' 'if !ok && false {' 'TestServiceRefusesAnUnapprovedHostBeforeLookingForADeployment'
mutate svc-deployment-skipped internal/carriers/deploy.go \
 'return Carrier{}, err' 'fp = md.Host' 'TestServiceRefusesWithoutAConfirmedDeployment'
mutate svc-job-version-unmatched internal/carriers/deploy.go \
 'if j.version == version && j.result.Version == version {' 'if j.result.Version == version {' 'TestServiceRefusesWithoutAConfirmedDeployment/job_of_another_version_reporting_this_one'
mutate svc-reported-version-unmatched internal/carriers/deploy.go \
 'if j.version == version && j.result.Version == version {' 'if j.version == version {' 'TestServiceRefusesWithoutAConfirmedDeployment/job_of_this_version_reporting_another_one'
mutate svc-fingerprint-not-from-record internal/carriers/deploy.go \
 'return j.result.Fingerprint, healthKind, nil' 'return "", healthKind, nil' 'TestServiceRegistersOnlyWhatWasDeployed'
mutate svc-healthcheck-from-caller internal/carriers/deploy.go \
 'md.HealthcheckRef = kind' '_ = kind' 'TestServiceTakesTheHealthcheckFromTheDeploymentRecord'
mutate svc-healthcheck-ignored internal/carriers/deploy.go \
 'return r.Healthcheck == nil || r.Healthcheck.Status == runnerproto.HealthOK || r.Healthcheck.Status == runnerproto.HealthSkipped' 'return true' 'TestServiceRefusesWithoutAConfirmedDeployment/healthcheck_failed'
mutate svc-host-unchecked internal/carriers/deploy.go \
 'AND host=$2 AND revoked_at IS NULL' 'AND $2::text IS NOT NULL AND revoked_at IS NULL' 'TestServiceRefusesAnUnapprovedDestination/host_of_no_runner'
mutate svc-policy-decision-ignored internal/carriers/deploy.go \
 'err == nil && d == deployment.Allow {' 'err == nil && d == d {' 'TestServiceRefusesAnUnapprovedDestination/no_policy_rules TestServiceRefusesAnUnapprovedDestination/path_outside_policy'
mutate svc-prod-self-approved internal/carriers/deploy.go \
 'registered = registered || (j.runner == id && j.approved)' 'registered = j.runner == id || true' 'TestServiceProductionNeedsAnApprovedDeployment'

mutate svc-approval-status-ignored internal/carriers/deploy.go \
 "AND a.status='approved')" "AND a.status IS NOT NULL)" 'TestProductionNeedsAnApprovalThatWasGranted'
mutate svc-approval-of-other-runner internal/carriers/deploy.go \
 'registered = registered || (j.runner == id && j.approved)' 'registered = registered || j.approved' 'TestProductionApprovalOfAnotherRunnerDoesNotCount'
mutate svc-evidence-of-other-secret internal/carriers/deploy.go \
 'WHERE j.org_id=$1 AND j.secret_id=$2 AND' 'WHERE j.org_id=$1 AND $2::text IS NOT NULL AND' 'TestDeploymentOfAnotherSecretIsNoEvidence'
mutate svc-disabled-secret-approved internal/carriers/deploy.go \
 "WHERE s.org_id=\$1 AND s.id=\$2 AND s.status='active'" 'WHERE s.org_id=$1 AND s.id=$2' 'TestDisabledSecretIsNotApproved'
mutate svc-failed-result-delivered internal/carriers/deploy.go \
 'if !r.OK || r.ErrorClass != "" {' 'if false {' 'TestAFailedResultIsNotADelivery'
mutate svc-database-error-read-as-refusal internal/carriers/deploy.go \
 'return Carrier{}, ErrInternal' 'return Carrier{}, ErrMetadata' 'TestDatabaseFailureIsInternalAndSilent'
mutate svc-database-error-leaks-driver-text internal/carriers/deploy.go \
 'return nil, ErrInternal // Never expose the database error.' 'return nil, err' 'TestDatabaseFailureIsInternalAndSilent'

mutate svc-target-filter-after-limit internal/carriers/deploy.go \
 'AND dr.target @> $4::jsonb' 'AND $4::jsonb IS NOT NULL' 'TestServiceFindsTheDeploymentBehindManyNewerDeploymentsToOtherTargets'
mutate svc-runner-not-named internal/carriers/deploy.go \
 'c.RunnerID = j.runner' '_ = j' 'TestServiceRegistersOnlyWhatWasDeployed'

# The unmutated tree is green: a script whose baseline is red proves nothing.
if mutation_apply_only; then
	mutation_shard_finish
	exit "$fail"
fi
rm -rf "$work/tree"
mutation_snapshot "$work/tree"
# shellcheck disable=SC2086
if (cd "$work/tree" && timeout -k 10s 180s go test -timeout 90s -count=1 -p 1 -v $pkgs >"$work/out" 2>&1); then
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
