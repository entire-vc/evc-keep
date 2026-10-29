#!/bin/sh
# Proves the rotate journal action and the rotate approval gate can fail: in a
# scratch copy of the tree, switch off one property at a time and require the
# TestRotate* tests of internal/api to go red. A property whose removal
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
	echo "FAIL check-rotate-audit-mutations: KEEP_DATABASE_URL is not set — the tests would skip, not fail, which this script must never report as red"
	exit 1
fi

# The tests need the real schema; apply it here so the script is correct on any
# database, not only one the CI job happened to migrate first.
mutation_apply_only || (cd "$root" && go run ./cmd/keep-server migrate up)

fail=0
# edit SRC FROM TO: print SRC with the first literal occurrence of FROM
# replaced by TO; exit 1 if FROM is not there.
edit() {
	awk -v from="$2" -v to="$3" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$1"
}

pkgs="./internal/api/ -run TestRotate"

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
	name=$1 src=$2 from=$3 to=$4 want=${5:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if [ "$from" = "@remove-file" ]; then
		printf '%s\n' 'package rotation' >"$work/tree/$src"
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
		! awk '$1 == "FAIL" && $2 == "github.com/entire-vc/evc-keep/internal/api" && $3 ~ /^[0-9.]+s$/ { found=1 } END { exit !found }' "$work/out" ||
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

# Each mutant switches off one guard; the named test must be the one that
# catches it. Mutations that remove a call also remove what it feeds.
mutate prod-gate-off internal/rotation/service.go \
 'if o.Class == ClassProd {' 'if false {' 'TestRotateApproval_ProdWaitsForAHuman'
mutate request-record-dropped internal/rotation/service.go \
 's.journal.AppendTx(ctx, tx, requestRecord(ref, id, o, audit.DecisionAllow, uuid.Nil))' '(audit.Record{}), error(nil)' 'TestRotateAudit_OutcomeHoldsNamesAndNoValue'
mutate nil-journal-starts-rotation internal/rotation/service.go \
 'if s.journal == nil {' 'if false {' 'TestRotateAudit_NoRecordNoRotation'
mutate journal-failure-ignored internal/rotation/service.go \
 'rec, err := s.journal.AppendTx(ctx, tx, requestRecord(ref, id, o, audit.DecisionAllow, uuid.Nil))' 'rec, err := s.journal.AppendTx(ctx, tx, requestRecord(ref, id, o, audit.DecisionAllow, uuid.Nil)); err = nil' 'TestRotateAudit_NoRecordNoRotation'
mutate run-row-outside-the-record-tx internal/rotation/service.go \
 's.e.store.startTx(ctx, tx, ref, id)' 's.e.store.start(ctx, ref, id)' 'TestRotateAudit_NoRecordNoRotation'
mutate outcome-record-dropped internal/rotation/service.go \
 '_, _ = s.journal.Append(ctx, rec)' '_ = rec' 'TestRotateAudit_OutcomeHoldsNamesAndNoValue'
mutate failed-run-names-version internal/rotation/service.go \
 'active := run.State == StateDone || c == ClassRevokeFailed' 'active := true' 'TestRotateAudit_OutcomeHoldsNamesAndNoValue'
mutate self-approval-allowed internal/rotation/approval.go \
 'if rtype == string(audit.ActorUser) && rid == in.ApproverID.String() {' 'if false {' 'TestRotateApproval_ApprovingStartsTheRunOfTheRequestID'
mutate non-human-approver-allowed internal/rotation/approval.go \
 'if !in.ApproverIsUser {' 'if false {' 'TestRotateApproval_ApprovingStartsTheRunOfTheRequestID'
mutate binding-hash-unchecked internal/rotation/approval.go \
 'subtle.ConstantTimeCompare(stored, shown) != 1 ||' 'false ||' 'TestRotateApproval_ApprovingStartsTheRunOfTheRequestID'
mutate expired-approval-decidable internal/rotation/approval.go \
 'if expired {' 'if false {' 'TestRotateApproval_ExpiredApprovalCannotBeDecided'
mutate rejection-starts-run internal/rotation/approval.go \
 'if in.Approve {' 'if true {' 'TestRotateApproval_RejectionStartsNothingAndReportsDenied'
mutate console-ignores-rotation-approvals internal/api/approvals_rotate.go \
 'if ra, ok := rotations.(RotationApprovals); ok {' 'if ra, ok := rotations.(RotationApprovals); ok && false {' 'TestRotateApproval_ConsoleServiceRoutesRotationApprovals'
mutate human-input-skips-prod-gate internal/api/rotate.go \
 'if found.Class == rotation.ClassProd {' 'if false {' 'TestRotateApproval_HumanInputOnProdIsRefused'

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
	grep -E -- '^(--- FAIL|FAIL|panic:)|_test.go:[0-9]+:' "$work/out" | head -40 | cut -c1-300
	fail=1
fi

mutation_shard_finish
exit "$fail"
