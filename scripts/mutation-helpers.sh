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

# Python suites import scripts/lib/mutation_edit.py from $root: no bytecode
# cache may appear there under a run (snapshots skip __pycache__ as a cache).
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE

case ${MUTATION_APPLY_ONLY:-} in
	'' | 0) ;;
	1)
		PATH="$root/scripts/lib/apply-only:$PATH"
		export PATH ;;
	*) echo 'FAIL MUTATION_APPLY_ONLY must be 1, 0 or unset'; exit 2 ;;
esac

# mutation_edit SRC FROM TO [OCCURRENCE]: SRC with one literal occurrence of
# FROM replaced by TO, on stdout. FROM must occur exactly once, or OCCURRENCE
# (1-based) must name which one; otherwise "FAIL $name: anchor occurs N
# times in SRC, name the occurrence" on stderr and exit 1. Works the same in
# apply-only mode, so the merge-request anchor job catches an ambiguous anchor
# without a database. Arguments are literal: no awk or sed escape processing.
# Suite wrappers forward an optional ordinal, or MUTATION_OCCURRENCE for a
# single call. Compound wrappers use MUTATION_OCCURRENCE2 for their second edit.
mutation_edit() {
	python3 -I "$root/scripts/lib/mutation_edit.py" "${name:-mutation}" "$@"
}

# Apply-only batch: a suite of hundreds of mutants that starts one python3 and
# restores one tree per mutant spends minutes on a loaded runner doing nothing
# but process starts. Instead its mutate() queues the mutant here and returns:
#
#   mutation_batch FILE FROM TO OCCURRENCE [FILE2 FROM2 TO2 OCCURRENCE2]
#
# queues mutant $name (FILE relative to the base; OCCURRENCE may be empty; the
# second edit applies on top of the first). At its end the suite calls
#
#   mutation_batch_run BASE
#
# once: one python3 applies every queued mutant to its own in-memory copy of
# the files under BASE (scripts/lib/mutation_edit.py --batch), prints
# "ok   NAME: applies" or "FAIL NAME: mutation did not apply (...)" for each,
# and returns non-zero if any failed or the queue does not hold exactly the
# mutants queued. BASE is only read; no mutant sees another's edit. A suite
# that queues and never runs the batch reports no applied mutation, which the
# anchor driver fails.
mutation_batch() {
	mutation_apply_only || { echo "FAIL ${name:-mutation}: mutation_batch outside apply-only mode"; exit 2; }
	case $# in
		4 | 8) ;;
		*) echo "FAIL ${name:-mutation}: mutation_batch takes 4 or 8 arguments, got $#"; exit 2 ;;
	esac
	[ -n "${name:-}" ] || { echo 'FAIL mutation_batch: no mutant name'; exit 2; }
	mutation_batch_count=$((${mutation_batch_count:-0} + 1))
	printf '%s\000' "$name" $(($# / 4)) "$@" >>"$work/mutation-batch"
}

mutation_batch_run() {
	if [ "${mutation_batch_count:-0}" -eq 0 ]; then
		echo 'FAIL apply-only batch: no mutant queued'
		return 1
	fi
	python3 -I "$root/scripts/lib/mutation_edit.py" --batch "$1" "$work/mutation-batch" "$mutation_batch_count"
}

# A prefix assignment on a shell function can persist in POSIX sh. Consume it
# before selection so an explicit ordinal never leaks into the next mutant.
mutation_take_occurrences() {
	mutation_occurrence=${MUTATION_OCCURRENCE:-}
	mutation_occurrence2=${MUTATION_OCCURRENCE2:-}
	unset MUTATION_OCCURRENCE MUTATION_OCCURRENCE2
}

# mutation_snapshot DIR [tracked] [prepare FN]: give DIR as a clean copy of the
# source tree. A suite calls it once per mutant; only the first call copies.
#
# The first call extracts one tar of $root into DIR (.git and caches left out;
# `tracked`: only the files git tracks), runs `FN DIR` when given, and writes
# DIR.manifest next to DIR: every directory, every symlink with its target,
# every file with its owner-exec bit, SHA-256 and size. Every later call resets
# DIR to that manifest: a changed or missing file is copied back from $root
# (from DIR.pristine when FN rewrote it), a missing directory or symlink is
# recreated, and a path the manifest does not name is removed. A mutant then
# writes a handful of files instead of the whole tree; a copy per mutant made
# thousands of file events each and overflowed the host's file-event journal.
#
# scripts/lib/mutation_snapshot.py does the work: the copy and its record
# once, then one helper process per shell (fds 8 and 9, a FIFO pair beside
# DIR) answers every reset; there is no fallback without python3. Content decides; a file's lstat
# (ino, size, mtime_ns, ctime_ns, mode) only spares rereading a file whose
# stat is the one recorded with its hash, outside a 2s window before the
# stamp written with that record. No git in DIR: some CI images lack it.
# Fail closed, exit 2: the reset leaves DIR different from the manifest, or a
# source file no longer matches its manifest line (the checkout changed under
# the run). Limits: of a file's mode only the owner-exec bit is compared, and
# a write a mutant makes through a symlink out of DIR is outside the reset.
# The exit handler of temp_workspace prints the run's summary
# `ok   snapshot: snapshots=S mutants=N restored_max=K` (K: most paths one
# reset touched), checks $root against the manifest once more and, on a run
# that ended by itself, resets DIR and hashes all of it without the stat
# filter: what the filter let through fails the run there.
# The tallies live on disk, not in shell variables: a suite may make its first
# call, or all of them, in a subshell (a selftest in `( )`), and the exit
# handler of the parent still has to report and check that tree. Each tree is
# named once in the registry ($work/mutation-snapshot.registry, or
# $mutation_snapshot_registry), and DIR.log gets `copy` per copy and
# `reset K` per reset (K: paths restored).
mutation_snapshot_py=$root/scripts/lib/mutation_snapshot.py
mutation_snapshots=0
mutation_snapshot_calls=0
mutation_snapshot_restored_max=0
mutation_snapshot_nl='
'
mutation_snapshot_tab=$(printf '\t')
mutation_snapshot_server=

# mutation_snapshot_reg: the registry file of this run into mutation_snapshot_r.
mutation_snapshot_reg() {
	mutation_snapshot_r=${mutation_snapshot_registry:-}
	if [ -z "$mutation_snapshot_r" ]; then
		[ -n "${work:-}" ] || mutation_snapshot_fail 'snapshot: no $work and no $mutation_snapshot_registry for the registry'
		mutation_snapshot_r=$work/mutation-snapshot.registry
	fi
}

mutation_snapshot_fail() {
	echo "FAIL mutation $1"
	exit 2
}

# mutation_snapshot_run CMD ARGS...: the Python side; its stdout lands in
# mutation_snapshot_out. Its FAIL lines, or a FAIL of ours, then exit 2.
mutation_snapshot_run() {
	if ! mutation_snapshot_out=$(python3 -I -S "$mutation_snapshot_py" "$@"); then
		case $mutation_snapshot_out in
			*'FAIL mutation '*)
				printf '%s\n' "$mutation_snapshot_out"
				exit 2 ;;
		esac
		mutation_snapshot_fail "snapshot: $1 of $2 did not finish"
	fi
}

# mutation_snapshot_serve DIR: start the helper of this shell, FIFOs in
# DIR.serve. It reads fd 8 and answers on fd 9.
mutation_snapshot_serve() {
	mutation_snapshot_fifo=$1.serve
	rm -rf "$mutation_snapshot_fifo"
	mkdir "$mutation_snapshot_fifo" && mkfifo "$mutation_snapshot_fifo/in" "$mutation_snapshot_fifo/out" ||
		mutation_snapshot_fail "snapshot: cannot make $mutation_snapshot_fifo"
	exec 8>&- 9<&-
	python3 -I -S "$mutation_snapshot_py" serve <"$mutation_snapshot_fifo/in" >"$mutation_snapshot_fifo/out" &
	mutation_snapshot_server=$!
	exec 8>"$mutation_snapshot_fifo/in" 9<"$mutation_snapshot_fifo/out"
}

# mutation_snapshot_ask CMD DIR ARGS...: one request to the helper. Its output
# lands in mutation_snapshot_out, its answer in mutation_snapshot_rc (empty:
# no answer) and mutation_snapshot_value.
mutation_snapshot_ask() {
	[ -n "$mutation_snapshot_server" ] || mutation_snapshot_serve "$2"
	mutation_snapshot_req=$1
	shift
	for mutation_snapshot_arg do
		case $mutation_snapshot_arg in
			*"$mutation_snapshot_tab"* | *"$mutation_snapshot_nl"*) mutation_snapshot_fail "snapshot: a tab or a newline in $mutation_snapshot_arg" ;;
		esac
		mutation_snapshot_req=$mutation_snapshot_req$mutation_snapshot_tab$mutation_snapshot_arg
	done
	# A helper that is gone must not end the shell on SIGPIPE: the read below
	# then finds no answer, and the caller names it. Builtins only in between.
	trap '' PIPE
	printf '%s\n' "$mutation_snapshot_req" >&8 2>/dev/null || true
	trap - PIPE
	mutation_snapshot_out= mutation_snapshot_rc= mutation_snapshot_value=
	while IFS= read -r mutation_snapshot_line <&9; do
		case $mutation_snapshot_line in
			'= '*)
				mutation_snapshot_line=${mutation_snapshot_line#= }
				mutation_snapshot_rc=${mutation_snapshot_line%% *}
				mutation_snapshot_value=${mutation_snapshot_line#* }
				return 0 ;;
		esac
		mutation_snapshot_out=$mutation_snapshot_out$mutation_snapshot_line$mutation_snapshot_nl
	done
}

# mutation_snapshot_end: close this shell's helper and wait for it.
mutation_snapshot_end() {
	[ -n "$mutation_snapshot_server" ] || return 0
	exec 8>&- 9<&-
	wait "$mutation_snapshot_server" 2>/dev/null || true
	rm -rf "$mutation_snapshot_fifo"
	mutation_snapshot_server=
}

mutation_snapshot_create() {
	mutation_snapshot_d=$1
	case "$mutation_snapshot_d/" in
		"$root"/*) mutation_snapshot_fail "snapshot: $mutation_snapshot_d is inside $root" ;;
	esac
	rm -rf "$mutation_snapshot_d" "$mutation_snapshot_d.pristine"
	mkdir -p "$mutation_snapshot_d" "$mutation_snapshot_d.pristine"
	mutation_snapshot_want=0
	if [ "$mutation_snapshot_tracked" = 1 ]; then
		# One list, one copying process: `xargs tar` would split a long list
		# into several archives, and `tar -x` stops after the first of them.
		(cd "$root" && git ls-files -z) >"$mutation_snapshot_d.tracked" ||
			mutation_snapshot_fail "snapshot: git ls-files in $root failed"
		mutation_snapshot_want=$mutation_snapshot_d.tracked
		mutation_snapshot_run copytracked "$mutation_snapshot_d" "$root" "$mutation_snapshot_d.tracked"
	else
		(cd "$root" && tar --exclude=.git --exclude=.gocache --exclude=.gomodcache --exclude=.artifacts --exclude=.lintcache --exclude=__pycache__ -cf - .) |
			tar -xf - -C "$mutation_snapshot_d"
	fi
	mutation_snapshots=$((mutation_snapshots + 1))
	# The copy, before any prepare step, must be the source exactly.
	mutation_snapshot_run copy "$mutation_snapshot_d" "$root" "$mutation_snapshot_tracked" "$mutation_snapshot_want"
	if [ -n "$mutation_snapshot_prepare" ]; then
		"$mutation_snapshot_prepare" "$mutation_snapshot_d" || mutation_snapshot_fail "snapshot: $mutation_snapshot_prepare failed"
	fi
	printf '%s\n' "$mutation_snapshot_opts" >"$mutation_snapshot_d.opts"
	mutation_snapshot_run seal "$mutation_snapshot_d" "$mutation_snapshot_prepare"
	mutation_snapshot_reg
	printf 'copy\n' >>"$mutation_snapshot_d.log" &&
		printf '%s\n' "$mutation_snapshot_d" >>"$mutation_snapshot_r" ||
		mutation_snapshot_fail "snapshot: cannot record $mutation_snapshot_d in $mutation_snapshot_r"
}

mutation_snapshot() {
	command -v python3 >/dev/null 2>&1 || mutation_snapshot_fail 'tree reset: python3 required'
	mutation_snapshot_dir=$1
	shift
	mutation_snapshot_tracked=0
	mutation_snapshot_prepare=
	while [ $# -gt 0 ]; do
		case $1 in
			tracked) mutation_snapshot_tracked=1 ;;
			prepare)
				[ $# -ge 2 ] || mutation_snapshot_fail 'snapshot: prepare needs a function'
				mutation_snapshot_prepare=$2
				shift ;;
			*) mutation_snapshot_fail "snapshot: unknown option $1" ;;
		esac
		shift
	done
	mutation_snapshot_opts="tracked=$mutation_snapshot_tracked prepare=$mutation_snapshot_prepare"
	mutation_snapshot_calls=$((mutation_snapshot_calls + 1))
	if [ ! -f "$mutation_snapshot_dir.manifest" ]; then
		mutation_snapshot_create "$mutation_snapshot_dir"
		return 0
	fi
	IFS= read -r mutation_snapshot_had <"$mutation_snapshot_dir.opts" || mutation_snapshot_had=
	if [ "$mutation_snapshot_had" != "$mutation_snapshot_opts" ]; then
		mutation_snapshot_fail "snapshot: $mutation_snapshot_dir reused with other options"
	fi
	# A suite that removes the tree between mutants would get every path
	# copied back: the per-mutant copy this helper exists to avoid.
	if [ ! -d "$mutation_snapshot_dir" ] || [ -h "$mutation_snapshot_dir" ]; then
		mutation_snapshot_fail "snapshot: $mutation_snapshot_dir was removed between mutants; call mutation_snapshot without removing the tree"
	fi
	mutation_snapshot_ask reset "$mutation_snapshot_dir" "$root"
	case $mutation_snapshot_rc in
		0) ;;
		'') mutation_snapshot_fail "snapshot: reset of $mutation_snapshot_dir did not finish" ;;
		*)
			printf '%s' "$mutation_snapshot_out"
			exit 2 ;;
	esac
	if [ "$mutation_snapshot_value" -gt "$mutation_snapshot_restored_max" ]; then
		mutation_snapshot_restored_max=$mutation_snapshot_value
	fi
	printf 'reset %s\n' "$mutation_snapshot_value" >>"$mutation_snapshot_dir.log" ||
		mutation_snapshot_fail "snapshot: cannot record a reset of $mutation_snapshot_dir"
}

# mutation_snapshot_report [STATUS]: called once from the exit handler of
# temp_workspace with the run's exit status. Never exits itself. The final
# pass runs when the suite ended by itself (STATUS 0 or 1, the default 0).
mutation_snapshot_report() {
	mutation_snapshot_r=${mutation_snapshot_registry:-${work:+$work/mutation-snapshot.registry}}
	[ -n "$mutation_snapshot_r" ] && [ -s "$mutation_snapshot_r" ] || return 0
	mutation_snapshot_final=0
	case ${1:-0} in 0 | 1) mutation_snapshot_final=1 ;; esac
	mutation_snapshot_status=0
	while IFS= read -r mutation_snapshot_d; do
		[ -n "$mutation_snapshot_d" ] || continue
		mutation_snapshot_tracked=0
		case $(cat "$mutation_snapshot_d.opts") in tracked=1*) mutation_snapshot_tracked=1 ;; esac
		mutation_snapshot_ask report "$mutation_snapshot_d" "$root" "$mutation_snapshot_tracked" "$mutation_snapshot_final"
		case $mutation_snapshot_rc in
			0) ;;
			'')
				mutation_snapshot_status=2
				mutation_snapshot_out="${mutation_snapshot_out}FAIL mutation snapshot: report of $mutation_snapshot_d did not finish$mutation_snapshot_nl" ;;
			*) mutation_snapshot_status=2 ;;
		esac
		printf '%s' "$mutation_snapshot_out"
	done <<EOF
$(sort -u "$mutation_snapshot_r")
EOF
	mutation_snapshot_end
	# Totals of every shell that called mutation_snapshot, subshells included.
	mutation_snapshot_tally=$(sort -u "$mutation_snapshot_r" | while IFS= read -r mutation_snapshot_d; do
		cat "$mutation_snapshot_d.log" 2>/dev/null || echo 'missing'
	done | awk '
		$1 == "copy" { s++; c++; next }
		$1 == "reset" && $2 ~ /^[0-9]+$/ { c++; if ($2 + 0 > k) k = $2 + 0; next }
		{ bad = 1 }
		END { printf "snapshots=%d mutants=%d restored_max=%d%s", s, c, k, bad ? " log=unreadable" : "" }
	')
	case $mutation_snapshot_tally in *log=unreadable) mutation_snapshot_status=2 ;; esac
	if [ "$mutation_snapshot_status" -eq 0 ]; then
		echo "ok   snapshot: $mutation_snapshot_tally"
	else
		echo "FAIL snapshot: $mutation_snapshot_tally"
	fi
	return "$mutation_snapshot_status"
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
	# pgscratch's readiness and refusal lines (internal/testutil/pgscratch,
	# connectWithRetry) end in a reason from a closed set: reason() and
	# sqlState(). Each stage x reason pair is counted against its exact line
	# shape and printed as fixed words and a count. No text from the test
	# output is copied, so a test that prints such a line with anything else
	# in the parentheses, a value or a host, matches no pair and prints
	# nothing. SQLSTATE codes, attempts and budget are not printed either.
	for mutation_stage in refused not_ready; do
		case $mutation_stage in
			refused) mutation_stage_shape='test database refused the connection' ;;
			not_ready) mutation_stage_shape='test database not ready after [0-9]+ attempts in [0-9hms.]+' ;;
		esac
		for mutation_reason in network deadline sqlstate unclassified; do
			case $mutation_reason in
				network) mutation_reason_shape='network unreachable or refused' ;;
				deadline) mutation_reason_shape='database operation deadline exceeded' ;;
				sqlstate) mutation_reason_shape='SQLSTATE [0-9A-Z]{5}' ;;
				unclassified) mutation_reason_shape='unclassified' ;;
			esac
			mutation_matches=$(grep -E -c -- "$mutation_stage_shape \\($mutation_reason_shape\\)\$" "$1" || true)
			if [ "$mutation_matches" -gt 0 ]; then
				printf 'FAIL mutation infrastructure stage: %s reason=%s count=%s\n' "$mutation_stage" "$mutation_reason" "$mutation_matches"
			fi
		done
	done
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
		mutation_result_names "$work/witness" "$@"
		exit 1
	fi
}

# mutation_declared_tests <go test args...>: names of the test functions
# declared in the packages the args name. ./dir names that package alone, so
# only its own directory is read; ./dir/... names the packages below it too.
mutation_declared_tests() {
	for mutation_arg in "$@"; do
		case $mutation_arg in
			./*...) mutation_dir="$root/${mutation_arg%...}" mutation_depth= ;;
			./*) mutation_dir="$root/$mutation_arg" mutation_depth=1 ;;
			*) continue ;;
		esac
		if [ -d "$mutation_dir" ]; then
			find "$mutation_dir" ${mutation_depth:+-maxdepth "$mutation_depth"} -name '*_test.go' -exec cat {} +
		fi
	done | sed -n 's/^func \(Test[A-Za-z0-9_]*\)(.*/\1/p'
}

# mutation_result_names FILE <go test args...>: the top-level results of a go
# test -v run by name only, for a witness, a baseline or a mutant. A test can
# print a line shaped like a result record from column 0, so a test name is
# printed only when it is a test function declared in the packages the run
# named, and a package path only when it is the module or a directory under
# $root. The rest of the line is dropped.
mutation_result_names() {
	mutation_results_out=$1
	shift
	mutation_module=$(sed -n 's/^module //p' "$root/go.mod")
	mutation_declared=$(mutation_declared_tests "$@")
	awk '
		substr($0, 1, 4) == "--- " && ($2 == "FAIL:" || $2 == "SKIP:") && $3 ~ /^Test[A-Za-z0-9_]*$/ { print "test", $2, $3; next }
		/^FAIL[ \t]/ && $2 ~ /^[A-Za-z0-9._\/-]+$/ { print "package", "FAIL", $2; next }
		/^ok[ \t]/ && $2 ~ /^[A-Za-z0-9._\/-]+$/ { print "package", "ok", $2 }
	' "$mutation_results_out" | while read -r mutation_kind mutation_result mutation_item; do
		case $mutation_kind in
			test)
				if printf '%s\n' "$mutation_declared" | grep -q -x -F -- "$mutation_item"; then
					printf -- '--- %s %s\n' "$mutation_result" "$mutation_item"
				fi ;;
			package)
				case $mutation_item in
					*..* | *//*) ;;
					"$mutation_module") printf '%s\t%s\n' "$mutation_result" "$mutation_item" ;;
					"$mutation_module"/*)
						if [ -d "$root/${mutation_item#"$mutation_module"/}" ]; then
							printf '%s\t%s\n' "$mutation_result" "$mutation_item"
						fi ;;
				esac ;;
		esac
	done
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
