#!/bin/sh
# Sourced by mutation suites. Never copy build/module caches into each mutant.

# Apply-only mode (MUTATION_APPLY_ONLY=1, run on merge requests by
# scripts/check-mutant-anchors.sh): a suite applies every mutation and stops
# there, with no baseline, witness or test run. It proves in seconds that each
# anchor still matches the source, so a change that strands a mutation goes red
# on its merge request instead of in the mutation batch on main. A suite calls
# `mutation_applied "$name" && return` right after a mutation applied, and puts
# `mutation_apply_only ||` in front of its baseline and any other test run.
# scripts/lib/apply-only/ goes first on PATH: a `go test`, `go run` or `node`
# the suite forgot to skip fails loudly instead of silently running tests.
mutation_apply_only() {
	[ "${MUTATION_APPLY_ONLY:-}" = 1 ]
}

mutation_applied() {
	mutation_apply_only || return 1
	echo "ok   $1: applies"
}

case ${MUTATION_APPLY_ONLY:-} in
	'' | 0) ;;
	1)
		PATH="$root/scripts/lib/apply-only:$PATH"
		export PATH ;;
	*) echo 'FAIL MUTATION_APPLY_ONLY must be 1, 0 or unset'; exit 2 ;;
esac

mutation_snapshot() {
	mkdir -p "$1"
	(cd "$root" && tar --exclude=.git --exclude=.gocache --exclude=.gomodcache --exclude=.artifacts -cf - .) | tar -xf - -C "$1"
}

# Free-text CI variables (MR description, titles, commit message) can quote a
# fault signature. A mutant that inherits the job environment echoes them into
# the test output and the classifier below would take the quote for a real
# database fault. Drop them before any mutant or baseline runs.
for mutation_ci_text in CI_MERGE_REQUEST_DESCRIPTION CI_MERGE_REQUEST_TITLE CI_COMMIT_MESSAGE CI_COMMIT_DESCRIPTION CI_COMMIT_TITLE; do
	unset "$mutation_ci_text"
done

# A process or scratch-database timeout is not evidence that a guard fired.
# Product tests may intentionally use a context deadline to expose a deadlock;
# do not classify every "context deadline exceeded" as an infrastructure fault.
mutation_infrastructure_counts() {
	# Fixed signature names and matching-line counts only; never matching text.
	for mutation_fault in process_timeout database_deadline scratch_create admin_pool_open database_connect; do
		case "$mutation_fault" in
			process_timeout) mutation_signature='panic: test timed out' ;;
			database_deadline) mutation_signature='database operation deadline exceeded' ;;
			scratch_create) mutation_signature='create scratch database failed' ;;
			admin_pool_open) mutation_signature='open admin pool on scratch database failed' ;;
			database_connect) mutation_signature='connection failed (unclassified)' ;;
		esac
		mutation_matches=$(grep -F -c -- "$mutation_signature" "$1" || true)
		if [ "$mutation_matches" -gt 0 ]; then
			printf 'FAIL mutation infrastructure detail: %s count=%s\n' "$mutation_fault" "$mutation_matches"
		fi
	done
	# pgscratch's readiness and refusal lines are fixed vocabulary (attempt
	# count, budget, a reason class; never host, user or DSN), so naming the
	# stage that stalled is safe and tells a stalled server from a slow test.
	# Only the fixed shape (attempts, budget, reason class) is copied; a line
	# with anything else around it, a DSN prefix or a host after the reason,
	# does not match and prints nothing.
	sed -n -e 's/^.*\(test database not ready after [0-9][0-9]* attempts in [0-9hms.]*\) (\([a-z0-9 _-]*\))$/\1 (\2)/p' \
		-e 's/^.*\(test database refused the connection\) (\([a-z0-9 _-]*\))$/\1 (\2)/p' "$1" | head -3 |
		while IFS= read -r mutation_stage; do
			printf 'FAIL mutation infrastructure stage: %s\n' "$mutation_stage"
		done || true
}

mutation_infrastructure_failed() {
	if grep -Eq 'panic: test timed out|database operation deadline exceeded|create scratch database failed|open admin pool on scratch database failed' "$1"; then
		echo "FAIL mutation infrastructure: test database or process fault (${name:-baseline})"
		mutation_infrastructure_counts "$1"
		return 0
	fi
	# Shards other than the first run no unmutated baseline, so a down or
	# flaky database would turn every mutant red. A refused connection is an
	# infrastructure fault too, unless the suite's mutants legitimately break
	# connecting (it then sets mutation_connect_faults_are_mutants=1 and
	# proves the database with mutation_db_witness instead).
	if [ "${mutation_connect_faults_are_mutants:-0}" != 1 ] && grep -Eq 'connection failed \(unclassified\)' "$1"; then
		echo "FAIL mutation infrastructure: database connection failed (${name:-baseline})"
		mutation_infrastructure_counts "$1"
		return 0
	fi
	return 1
}

# mutation_db_witness <go test args...>: the unmutated tree must pass the
# given tests with nothing skipped. Every shard runs it, so a database that is
# down for one shard cannot make its mutants look caught.
mutation_db_witness() {
	mutation_apply_only && return 0
	if (cd "$root" && go test -timeout 600s -count=1 -p 1 -v "$@" >"$work/witness" 2>&1) && ! grep -q -- '--- SKIP' "$work/witness"; then
		echo "ok   database witness: green on the real code"
	else
		echo "FAIL database witness: not green (or skipped) on the real code"
		grep -E -- '^(--- |FAIL|ok )' "$work/witness" || true
		exit 1
	fi
}

# Structured test events tie a failure to the expected witness package.
# A build/setup failure anywhere invalidates the run, even when another
# package emitted a failing test. Test output is never printed here.
mutation_package_test_failed() {
	if grep -q -F -e '[build failed]' -e '[setup failed]' "$1"; then
		return 1
	fi
	grep -F '"Package":"'"$2"'"' "$1" | grep -F '"Action":"fail"' | grep -q -F '"Test":'
}

# Keep raw test output private: even subtest names may contain fixture values.
# Structured events identify top-level failures without printing their messages.
mutation_baseline() {
	mutation_apply_only && return 0
	if (cd "$root" && go test -json -count=1 "$@" >"$work/baseline" 2>&1); then
		echo 'ok   baseline: tests green on the real code'
		return 0
	else
		baseline_status=$?
	fi
	echo "FAIL baseline: go test exited $baseline_status"
	awk '
		/"Action":"(run|pass|skip|fail)"/ && /"Test":"[A-Za-z_][A-Za-z0-9_]*"/ {
			name = $0
			sub(/^.*"Test":"/, "", name)
			sub(/".*$/, "", name)
			if ($0 ~ /"Action":"run"/) active[name] = 1
			else delete active[name]
			if ($0 ~ /"Action":"fail"/) {
				if (!seen[name]++) print "FAIL baseline test: " name
				found = 1
			}
		}
		END {
			if (!found) {
				print "FAIL baseline: no named test failure recorded"
				for (name in active) print "FAIL baseline active test: " name
			}
		}
	' "$work/baseline"
	# Opt-in per test: only a test that holds no fixture values may have its
	# own failure message printed, so a flake in it is diagnosable from the
	# trace. Every other test stays name-only.
	for diag in ${MUTATION_BASELINE_DIAG_TESTS:-}; do
		grep -F '"Action":"output"' "$work/baseline" | grep -F '"Test":"'"$diag"'"' |
			grep -E -o '"Output":"[^"]*"' | sed -e 's/^"Output":"//' -e 's/"$//' -e 's/\\n$//' |
			grep -F -e '_test.go:' | sed "s/^/FAIL baseline $diag: /" | head -n 20
	done
	if grep -q -F 'panic: test timed out' "$work/baseline"; then
		echo 'FAIL baseline: test timeout'
	fi
	if grep -q -F -e '[build failed]' -e '[setup failed]' -e '"Action":"build-fail"' "$work/baseline"; then
		echo 'FAIL baseline: build/setup failure'
	fi
	return 1
}

# Round-robin partitioning keeps the script itself as the complete inventory.
# CI supplies explicit indexes; a local run defaults to the whole suite.
mutation_shard_init() {
	mutation_index=${MUTATION_SHARD_INDEX:-1}
	mutation_total=${MUTATION_SHARD_TOTAL:-1}
	for value in "$mutation_index" "$mutation_total"; do
		case $value in
			'' | *[!0-9]* | 0*) echo 'FAIL invalid mutation shard'; exit 1 ;;
		esac
	done
	if [ "$mutation_total" -lt 1 ] || [ "$mutation_index" -lt 1 ] || [ "$mutation_index" -gt "$mutation_total" ]; then
		echo 'FAIL invalid mutation shard'
		exit 1
	fi
	mutation_ordinal=0
	mutation_count=0
}

mutation_selected() {
	mutation_ordinal=$((mutation_ordinal + 1))
	if [ $(((mutation_ordinal - 1) % mutation_total + 1)) -ne "$mutation_index" ]; then
		return 1
	fi
	mutation_count=$((mutation_count + 1))
	return 0
}

mutation_shard_finish() {
	if [ "$mutation_count" -eq 0 ]; then
		echo 'FAIL mutation shard selected no mutants'
		exit 1
	fi
	echo "ok   shard $mutation_index/$mutation_total: $mutation_count selected mutants"
}
