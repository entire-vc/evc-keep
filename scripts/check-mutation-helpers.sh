#!/bin/sh
# Infrastructure timeouts must not count as caught mutants. A product-level
# context deadline can be the expected witness of a deliberately broken lock.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

expect() {
	name=$1 want=$2 text=$3
	printf '%s\n' "$text" >"$work/output"
	if mutation_infrastructure_failed "$work/output" >"$work/diagnostic"; then
		got=infrastructure
	else
		got=test
	fi
	if [ "$got" != "$want" ]; then
		echo "FAIL $name: expected $want, got $got"
		exit 1
	fi
	echo "ok   $name"
}

expect ordinary-failure test '--- FAIL: TestGuard'
expect process-timeout infrastructure '--- FAIL: TestGuard
panic: test timed out after 2m0s'
expect scratch-timeout infrastructure '--- FAIL: TestGuard
create scratch database failed (database operation deadline exceeded)'
# The stage that stalled must reach the log as fixed words and a count: the
# stage, the reason class and how many lines; never attempts, budget or the
# text around it.
printf '%s\n' '--- FAIL: TestGuard' '    x_test.go:9: test database not ready after 15 attempts in 1m30s (database operation deadline exceeded)' >"$work/output"
mutation_infrastructure_failed "$work/output" >"$work/diagnostic" || { echo "FAIL stage-line: fault not reported"; exit 1; }
grep -q -x 'FAIL mutation infrastructure stage: not_ready reason=deadline count=1' "$work/diagnostic" || { echo "FAIL stage-line: stage not printed"; exit 1; }
! grep -q -e '15 attempts' -e '1m30s' "$work/diagnostic" || { echo "FAIL stage-line: attempts or budget printed"; exit 1; }
# A wrapper may put a DSN in front of the stage text; the stage is still
# counted and nothing of the prefix reaches the log.
printf '%s\n' '--- FAIL: TestGuard' '    x_test.go:9: open postgres://u:pwplaceholder@db.invalid:5432/keep: test database not ready after 15 attempts in 1m30s (database operation deadline exceeded)' >"$work/output"
mutation_infrastructure_failed "$work/output" >"$work/diagnostic" || { echo "FAIL stage-line-prefix: fault not reported"; exit 1; }
grep -q -x 'FAIL mutation infrastructure stage: not_ready reason=deadline count=1' "$work/diagnostic" || { echo "FAIL stage-line-prefix: stage not printed"; exit 1; }
! grep -q -e 'pwplaceholder' -e 'db.invalid' -e 'postgres://' "$work/diagnostic" || { echo "FAIL stage-line-prefix: prefix reached the log"; exit 1; }
echo "ok   stage-line-prefix"
# Text after the reason class (host, user) must not reach the log either.
printf '%s\n' '--- FAIL: TestGuard' '    x_test.go:9: test database not ready after 15 attempts in 1m30s (database operation deadline exceeded) host=db.invalid user=u' >"$work/output"
mutation_infrastructure_failed "$work/output" >"$work/diagnostic" || { echo "FAIL stage-line-suffix: fault not reported"; exit 1; }
! grep -q -e 'db.invalid' -e 'user=u' "$work/diagnostic" || { echo "FAIL stage-line-suffix: suffix reached the log"; exit 1; }
! grep -q 'infrastructure stage' "$work/diagnostic" || { echo "FAIL stage-line-suffix: stage line of an unknown shape was printed"; exit 1; }
echo "ok   stage-line-suffix"
# A reason outside the closed vocabulary (a value a test printed in the
# parentheses) counts nowhere and prints nothing; the SQLSTATE code itself
# is not printed.
printf '%s\n' '--- FAIL: TestGuard' 'database operation deadline exceeded' 'test database refused the connection (kc0123abcd-v1-secret)' 'test database refused the connection (SQLSTATE 28P01)' >"$work/output"
mutation_infrastructure_failed "$work/output" >"$work/diagnostic" || { echo "FAIL stage-reason-closed: fault not reported"; exit 1; }
! grep -q -e 'kc0123abcd' -e '28P01' "$work/diagnostic" || { echo "FAIL stage-reason-closed: test text reached the log"; exit 1; }
if [ "$(grep -c 'infrastructure stage' "$work/diagnostic")" != 1 ] || ! grep -q -x 'FAIL mutation infrastructure stage: refused reason=sqlstate count=1' "$work/diagnostic"; then
	echo "FAIL stage-reason-closed: wrong stage lines"
	exit 1
fi
echo "ok   stage-reason-closed"
printf '%s\n' '--- FAIL: TestGuard' 'create scratch database failed (database operation deadline exceeded)' >"$work/output"
mutation_infrastructure_failed "$work/output" >"$work/diagnostic" || exit 1
! grep -q 'infrastructure stage' "$work/diagnostic" || { echo "FAIL stage-line: printed for a line that is not a stage"; exit 1; }
echo "ok   stage-line"
expect database-down infrastructure '--- FAIL: TestGuard
    guard_test.go:9: open migration db: open migration database handle: connection failed (unclassified)'
expect scratch-unreachable infrastructure '--- FAIL: TestGuard
create scratch database failed (unclassified)'
mutation_connect_faults_are_mutants=1
expect connect-fault-is-a-mutant test '--- FAIL: TestOpenRefusesUnsafeQueryExecMode
    store_test.go:9: connection failed (unclassified)'
mutation_connect_faults_are_mutants=0
expect product-deadlock test '--- FAIL: TestChangeLevel
context deadline exceeded'

# CI free-text variables that quote a signature must not reach a child that
# inherits the job environment (MR !170: the MR description tripped the
# classifier). The child echoes them; a real signature line must still fail.
for ci_var in CI_MERGE_REQUEST_DESCRIPTION CI_MERGE_REQUEST_TITLE CI_COMMIT_MESSAGE CI_COMMIT_DESCRIPTION CI_COMMIT_TITLE; do
	(
		export "$ci_var=database operation deadline exceeded; panic: test timed out"
		. "$root/scripts/mutation-helpers.sh"
		sh -c 'echo "--- FAIL: TestGuard"; echo "[$1]"' sh "$(eval "printf %s \"\${$ci_var-}\"")" >"$work/output"
		if mutation_infrastructure_failed "$work/output" >"$work/diagnostic"; then
			echo "FAIL ci-env-$ci_var: classified as infrastructure"
			exit 1
		fi
	)
	echo "ok   ci-env-$ci_var ignored"
done
# The scrub must not mask a real fault: with the variables exported and the
# helpers sourced, a genuine signature line still reports infrastructure.
(
	export CI_MERGE_REQUEST_DESCRIPTION=quoted
	. "$root/scripts/mutation-helpers.sh"
	printf '%s\n' '--- FAIL: TestGuard' 'create scratch database failed (database operation deadline exceeded)' >"$work/output"
	if ! mutation_infrastructure_failed "$work/output" >"$work/diagnostic"; then
		echo "FAIL real-signature-after-scrub: fault not reported"
		exit 1
	fi
)
echo "ok   real-signature-after-scrub"

# A failing package summary is insufficient: the target needs a named test
# failure, and a compiler/setup failure in any package must reject the run.
expect_package_failure() {
	name=$1 want=$2 output=$3
	printf '%s\n' "$output" >"$work/output"
	if mutation_package_test_failed "$work/output" example.invalid/target; then
		got=caught
	else
		got=invalid
	fi
	if [ "$got" != "$want" ]; then
		echo "FAIL $name: expected $want, got $got"
		exit 1
	fi
	echo "ok   $name"
}
target_failure='{"Action":"fail","Package":"example.invalid/target","Test":"TestGuard"}'
expect_package_failure target-test caught "$target_failure"
expect_package_failure other-test invalid '{"Action":"fail","Package":"example.invalid/other","Test":"TestGuard"}'
expect_package_failure package-only invalid '{"Action":"fail","Package":"example.invalid/target"}'
expect_package_failure mixed-build invalid "$target_failure
FAIL example.invalid/other [build failed]"
expect_package_failure mixed-setup invalid "$target_failure
FAIL example.invalid/other [setup failed]"

# Every mutant belongs to exactly one shard; the unsharded run selects all.
for shard in 1 2 3 4; do
	(
		MUTATION_SHARD_INDEX=$shard MUTATION_SHARD_TOTAL=4
		mutation_shard_init
		for mutant in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do
			if mutation_selected; then printf '%s\n' "$mutant"; fi
		done
	) >>"$work/partition"
done
sort -n "$work/partition" >"$work/sorted"
seq 17 >"$work/expected"
cmp "$work/sorted" "$work/expected"
for invalid in '0 4' '5 4' '1 0' 'x 4' '1 2x' '1 2:3' '01 4'; do
	set -- $invalid
	if (MUTATION_SHARD_INDEX=$1 MUTATION_SHARD_TOTAL=$2; mutation_shard_init) >/dev/null 2>&1; then
		echo "FAIL invalid shard accepted"
		exit 1
	fi
done
if (MUTATION_SHARD_INDEX=1 MUTATION_SHARD_TOTAL=1; mutation_shard_init; mutation_shard_finish) >/dev/null 2>&1; then
	echo 'FAIL empty shard accepted'
	exit 1
fi
(MUTATION_SHARD_INDEX=1 MUTATION_SHARD_TOTAL=1; mutation_shard_init; mutation_selected; mutation_selected; mutation_shard_finish)
echo 'ok   shard partition covers every mutant exactly once and rejects invalid shards'

# Test the copier against a tiny fixture, never against machine-wide caches.
root="$work/source"
mkdir -p "$root/scripts" "$root/.git" "$root/.gocache" "$root/.gomodcache" "$root/.artifacts"
printf 'module example.invalid/test\n' >"$root/go.mod"
printf 'source\n' >"$root/scripts/probe.sh"
for dir in .git .gocache .gomodcache .artifacts; do
	printf 'cache\n' >"$root/$dir/marker"
done
mutation_snapshot "$work/copy"
cmp "$root/go.mod" "$work/copy/go.mod"
cmp "$root/scripts/probe.sh" "$work/copy/scripts/probe.sh"
for dir in .git .gocache .gomodcache .artifacts; do
	if [ -e "$work/copy/$dir" ]; then
		echo "FAIL snapshot copied $dir"
		exit 1
	fi
done
echo 'ok   snapshot preserves source and excludes caches'

# Exercise the real Go tool, including output that must stay private. Subtest
# names can contain fixture values, so diagnostics may show top-level names only.
cat >"$root/baseline_test.go" <<'EOF'
package baseline
import (
    "os"
    "testing"
)
func TestBaselinePass(t *testing.T) {}
func TestBaselineFailure(t *testing.T) {
    t.Log(`{"Action":"fail","Test":"TestForged"}`)
    t.Run("diagnostic-output-canary", func(t *testing.T) {
        t.Fatal("diagnostic-output-canary")
    })
}
func TestBaselineTimeout(t *testing.T) {
    t.Log("diagnostic-output-canary")
    select {}
}
func TestBaselineAbruptExit(t *testing.T) {
    t.Log("diagnostic-output-canary")
    os.Exit(2)
}
func TestBaselinePanic(t *testing.T) { panic("diagnostic-output-canary") }
EOF
expect_baseline() {
	name=$1 want=$2 marker=$3
	shift 3
	if mutation_baseline "$@" >"$work/diagnostic" 2>&1; then
		got=green
	else
		got=red
	fi
	if [ "$got" != "$want" ] || ! grep -Fq "$marker" "$work/diagnostic"; then
		echo "FAIL $name: expected $want with safe diagnostic"
		exit 1
	fi
	if grep -q -e 'diagnostic-output-canary' -e 'undefinedDiagnosticOutputCanary' -e 'TestForged' "$work/diagnostic"; then
		echo "FAIL $name: raw test output or subtest name escaped"
		exit 1
	fi
	echo "ok   $name"
}
expect_baseline baseline-green green 'ok   baseline: tests green on the real code' -timeout 10s -run '^TestBaselinePass$' .
expect_baseline baseline-test-failure red 'FAIL baseline test: TestBaselineFailure' -timeout 10s -run '^TestBaselineFailure$' .
grep -Fq 'FAIL baseline: go test exited 1' "$work/diagnostic"
if grep -Fq 'FAIL baseline: no named test failure recorded' "$work/diagnostic"; then
	echo 'FAIL baseline-test-failure: unexpected unnamed failure diagnostic'
	exit 1
fi
expect_baseline baseline-timeout red 'FAIL baseline: test timeout' -timeout 1s -run '^TestBaselineTimeout$' .
grep -Fq 'FAIL baseline active test: TestBaselineTimeout' "$work/diagnostic"
# An abrupt process exit has a run event but no named test failure event.
expect_baseline baseline-abrupt-exit red 'FAIL baseline: no named test failure recorded' -timeout 10s -run '^TestBaselineAbruptExit$' .
grep -Fq 'FAIL baseline active test: TestBaselineAbruptExit' "$work/diagnostic"
expect_baseline baseline-panic red 'TestBaselinePanic' -timeout 10s -run '^TestBaselinePanic$' .
printf '\nvar _ = undefinedDiagnosticOutputCanary\n' >>"$root/baseline_test.go"
expect_baseline baseline-build-failure red 'FAIL baseline: build/setup failure' -timeout 10s .

# One snapshot per suite. mutation_snapshot copies the tree once and resets it
# for every later mutant; the checks below compare the result with the source
# by their own walk, never by the helper's manifest.
snap_src="$work/snap-src"
mkdir -p "$snap_src/a/b" "$snap_src/c" "$snap_src/.git" "$snap_src/.gocache"
printf 'one\n' >"$snap_src/a/one.go"
printf 'two\n' >"$snap_src/a/b/two.go"
printf 'spaced\n' >"$snap_src/a/with space.txt"
printf '#!/bin/sh\n' >"$snap_src/run.sh"
chmod 755 "$snap_src/run.sh"
printf 'three\n' >"$snap_src/c/three.txt"
chmod 644 "$snap_src/a/one.go" "$snap_src/a/b/two.go" "$snap_src/a/with space.txt" "$snap_src/c/three.txt"
ln -s a/one.go "$snap_src/link"
printf 'cache\n' >"$snap_src/.gocache/marker"
printf 'keep\n' >"$work/outside"

snap_walk() {
	(cd "$1" && find . '(' -name .git -o -name .gocache ')' -prune -o -print | LC_ALL=C sort)
}
# snap_same A B: same paths, types, symlink targets, file bytes and exec bits.
snap_same() {
	[ "$(snap_walk "$1")" = "$(snap_walk "$2")" ] || return 1
	snap_walk "$1" >"$work/snap-paths"
	while IFS= read -r p; do
		if [ -h "$1/$p" ]; then
			[ -h "$2/$p" ] && [ "$(readlink "$1/$p")" = "$(readlink "$2/$p")" ] || return 1
		elif [ -f "$1/$p" ]; then
			[ -f "$2/$p" ] && [ ! -h "$2/$p" ] && cmp -s "$1/$p" "$2/$p" || return 1
			[ "$(find "$1/$p" -perm -100 | wc -l)" = "$(find "$2/$p" -perm -100 | wc -l)" ] || return 1
		elif [ -d "$1/$p" ]; then
			[ -d "$2/$p" ] && [ ! -h "$2/$p" ] || return 1
		fi
	done <"$work/snap-paths"
}

# (a) Every kind of damage a mutant can do comes back as the source.
snap_damage() {
	t=$1
	case $2 in
		edit) printf 'mutant\n' >>"$t/a/one.go" ;;
		replace-by-mv) printf 'mutant\n' >"$work/edited" && mv "$work/edited" "$t/run.sh" ;;
		space-path) printf 'mutant\n' >>"$t/a/with space.txt" ;;
		delete-file) rm "$t/a/b/two.go" ;;
		delete-dir) rm -r "$t/a/b" ;;
		extra-file) printf 'new\n' >"$t/c/new.txt" ;;
		extra-hidden) printf 'new\n' >"$t/.hidden" ;;
		extra-dir) mkdir -p "$t/d/e" && printf 'new\n' >"$t/d/e/f" ;;
		exec-added) chmod 755 "$t/c/three.txt" ;;
		exec-removed) chmod 644 "$t/run.sh" ;;
		file-to-dir) rm "$t/c/three.txt" && mkdir "$t/c/three.txt" ;;
		dir-to-file) rm -r "$t/a/b" && printf 'file\n' >"$t/a/b" ;;
		file-to-symlink) rm "$t/a/one.go" && ln -s ../run.sh "$t/a/one.go" ;;
		symlink-outside) rm "$t/a/one.go" && ln -s "$work/outside" "$t/a/one.go" ;;
		symlink-retarget) rm "$t/link" && ln -s c/three.txt "$t/link" ;;
		symlink-removed) rm "$t/link" ;;
		symlink-to-file) rm "$t/link" && printf 'file\n' >"$t/link" ;;
		*) echo "FAIL snapshot selftest: unknown damage $2"; exit 1 ;;
	esac
}
# Each case runs in a subshell with the counters of a fresh suite.
snap_fresh_state() {
	mutation_snapshots=0 mutation_snapshot_calls=0 mutation_snapshot_restored_max=0 mutation_snapshot_server=
	mutation_snapshot_registry=$(mktemp "$work/snap-registry.XXXXXX")
}
snap_kinds='edit replace-by-mv space-path delete-file delete-dir extra-file extra-hidden extra-dir exec-added exec-removed file-to-dir dir-to-file file-to-symlink symlink-outside symlink-retarget symlink-removed symlink-to-file'
(
	snap_fresh_state
	root=$snap_src
	mutation_snapshot "$work/snap-a" >"$work/snap-out"
	snap_same "$root" "$work/snap-a" || { echo 'FAIL snapshot: first copy differs from the source'; exit 1; }
	[ ! -e "$work/snap-a/.gocache" ] || { echo 'FAIL snapshot: copied .gocache'; exit 1; }
	# One edited file costs one restored path, not a copy of the tree.
	snap_damage "$work/snap-a" edit
	mutation_snapshot "$work/snap-a" >>"$work/snap-out"
	[ "$mutation_snapshot_restored_max" = 1 ] || { echo "FAIL snapshot: one edit restored $mutation_snapshot_restored_max paths"; exit 1; }
	calls=2
	for kind in $snap_kinds; do
		snap_damage "$work/snap-a" "$kind"
		mutation_snapshot "$work/snap-a" >>"$work/snap-out"
		calls=$((calls + 1))
		snap_same "$root" "$work/snap-a" || { echo "FAIL snapshot reset: $kind left the tree different from the source"; exit 1; }
		[ "$(cat "$work/outside")" = keep ] || { echo "FAIL snapshot reset: $kind wrote through a symlink out of the tree"; exit 1; }
	done
	# Several kinds at once, as a compound mutant leaves them.
	for kind in edit extra-dir delete-dir exec-removed symlink-retarget; do snap_damage "$work/snap-a" "$kind"; done
	mutation_snapshot "$work/snap-a" >>"$work/snap-out"
	calls=$((calls + 1))
	snap_same "$root" "$work/snap-a" || { echo 'FAIL snapshot reset: compound damage left the tree different'; exit 1; }
	if grep -q FAIL "$work/snap-out"; then cat "$work/snap-out"; exit 1; fi
	mutation_snapshot_report >"$work/snap-out"
	grep -qx "ok   snapshot: snapshots=1 mutants=$calls restored_max=[0-9]*" "$work/snap-out" || { echo 'FAIL snapshot summary:'; cat "$work/snap-out"; exit 1; }
) || { echo "FAIL snapshot reset cases: exit $?"; cat "$work/snap-out" 2>/dev/null; exit 1; }
echo 'ok   snapshot: one copy, every kind of damage reset to the source'

# A prepare step (discovery instruments its tree) is part of the clean tree:
# a reset restores its version, and it is not taken for a changed source.
(
	snap_fresh_state
	root=$snap_src
	stamp() { printf 'prepared\n' >>"$1/a/one.go"; }
	mutation_snapshot "$work/snap-p" prepare stamp >/dev/null
	cp -p "$work/snap-p/a/one.go" "$work/prepared"
	printf 'mutant\n' >>"$work/snap-p/a/one.go"
	mutation_snapshot "$work/snap-p" prepare stamp >/dev/null
	cmp -s "$work/prepared" "$work/snap-p/a/one.go" || { echo 'FAIL snapshot prepare: reset lost the prepared file'; exit 1; }
	mutation_snapshot_report >"$work/snap-out" || { echo 'FAIL snapshot prepare: prepared file taken for a changed source'; exit 1; }
	if (mutation_snapshot "$work/snap-p" >/dev/null); then echo 'FAIL snapshot: reuse with other options accepted'; exit 1; fi
) || { echo "FAIL snapshot prepare: exit $?"; cat "$work/snap-out" 2>/dev/null; exit 1; }
echo 'ok   snapshot: prepared files are restored as prepared'

# Only the tracked files, for a check that works on a git checkout.
(
	snap_fresh_state
	root="$work/snap-git"
	cp -R "$snap_src" "$root"
	rm -rf "$root/.git"
	printf 'untracked\n' >"$root/c/untracked.txt"
	(cd "$root" && git init -q && git add a c run.sh link && git reset -q c/untracked.txt) || exit 1
	# A long list must reach the copy whole: here xargs runs its command per
	# two paths, as a real one does past its size limit (a CI image cut the
	# tracked list into several archives and the copy kept only the first).
	mkdir -p "$work/xargs-shim"
	printf '#!/bin/sh\nexec %s -n 2 "$@"\n' "$(command -v xargs)" >"$work/xargs-shim/xargs"
	chmod +x "$work/xargs-shim/xargs"
	PATH="$work/xargs-shim:$PATH"
	[ "$(cd "$root" && git ls-files | wc -l)" -gt 2 ] || { echo 'FAIL snapshot tracked: fixture too small to split'; exit 1; }
	mutation_snapshot "$work/snap-t" tracked >/dev/null
	[ "$(cd "$work/snap-t" && find . ! -type d | wc -l)" -eq "$(cd "$root" && git ls-files | wc -l)" ] ||
		{ echo 'FAIL snapshot tracked: the copy lost tracked paths'; exit 1; }
	[ ! -e "$work/snap-t/c/untracked.txt" ] || { echo 'FAIL snapshot tracked: copied an untracked file'; exit 1; }
	printf 'mutant\n' >>"$work/snap-t/c/three.txt"
	printf 'mutant\n' >"$work/snap-t/c/untracked.txt"
	mutation_snapshot "$work/snap-t" tracked >/dev/null
	cmp -s "$root/c/three.txt" "$work/snap-t/c/three.txt" && [ ! -e "$work/snap-t/c/untracked.txt" ] ||
		{ echo 'FAIL snapshot tracked: reset did not restore the tracked set'; exit 1; }
	printf 'more\n' >>"$root/c/untracked.txt"
	mutation_snapshot_report >/dev/null || { echo 'FAIL snapshot tracked: an untracked file taken for the source'; exit 1; }
) || { echo "FAIL snapshot tracked: exit $?"; cat "$work/snap-out" 2>/dev/null; exit 1; }
echo 'ok   snapshot: tracked mode copies a split list whole, restores tracked files only'
python3 -I "$(dirname "$0")/test_tracked_snapshot.py" || exit 1

# (b) The reset is verified: a helper whose restore or removal is switched off
# fails closed, exit 2, instead of handing a dirty tree to the next mutant.
root_real=$(cd "$(dirname "$0")/.." && pwd)
# snap_break_py LABEL LINE [WITH]: scripts/lib/mutation_snapshot.py with the
# one line that reads LINE (indentation aside) replaced by WITH (default
# `pass`), in $work/broken-snapshot.py.
snap_break_py() {
	awk -v t="$2" -v r="${3:-pass}" '
		{ s = $0; sub(/^[ \t]+/, "", s) }
		s == t { n++; match($0, /^[ \t]*/); $0 = substr($0, 1, RLENGTH) r }
		{ print }
		END { if (n != 1) exit 1 }
	' "$root_real/scripts/lib/mutation_snapshot.py" >"$work/broken-snapshot.py" ||
		{ echo "FAIL snapshot selftest: $1: not exactly one helper line reads: $2"; exit 1; }
}
snap_broken() {
	label=$1 from=$2 damage=$3
	snap_break_py "$label" "$from"
	rm -rf "$work/snap-b" "$work/snap-b".*
	set +e
	(
		root=$snap_src
		mutation_snapshot_py=$work/broken-snapshot.py
		snap_fresh_state
		mutation_snapshot "$work/snap-b" >/dev/null
		snap_damage "$work/snap-b" "$damage"
		mutation_snapshot "$work/snap-b"
		echo 'reset returned'
	) >"$work/snap-out" 2>&1
	status=$?
	set -e
	if [ "$status" != 2 ] || ! grep -q '^FAIL mutation tree reset: [1-9][0-9]* paths differ$' "$work/snap-out"; then
		echo "FAIL snapshot $label: broken reset not refused (exit $status)"
		cat "$work/snap-out"
		exit 1
	fi
	echo "ok   snapshot $label: refused, exit 2"
}
snap_broken restore-off 'put_file(d, root, rel, value[1])' edit
snap_broken removal-off 'remove(target)' extra-file
snap_broken mkdir-off 'os.makedirs(target, exist_ok=True)' delete-dir

# snap_record DIR REL stat|hash: rewrite the stat cache of a snapshot as
# another helper would, with a new token. stat: REL's record takes REL's stat
# as it is now and the stamp lands 1s after REL's ctime. hash: REL's record
# keeps the stat as it is now with a hash that is not the manifest's, and the
# stamp moves far ahead.
snap_record() {
	python3 - "$@" <<'PY'
import os, sys
d, rel, how = sys.argv[1], sys.argv[2], sys.argv[3]
st = os.lstat(os.path.join(d, rel))
key = "%d %d %d %d %d" % (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode)
with open(d + ".stat") as f:
    lines = f.read().splitlines()
hit = [i for i, line in enumerate(lines[1:], 1) if line.split("\t")[2] == rel]
assert len(hit) == 1, "no stat cache line for " + rel
sig = lines[hit[0]].split("\t")[1]
if how == "hash":
    sig = sig.split(" ")[0] + " " + "0" * 64 + " " + sig.split(" ")[2]
lines[0] = "another-helper"
lines[hit[0]] = "\t".join([key, sig, rel])
with open(d + ".stat", "w") as f:
    f.write("\n".join(lines) + "\n")
when = st.st_ctime_ns + 10**9 if how == "stat" else 1893456000 * 10**9
os.utime(d + ".stamp", ns=(when, when))
PY
}

# (e) The stat filter. Content decides; a stat only spares a reread.
(
	snap_fresh_state
	root=$snap_src
	mutation_snapshot "$work/snap-s" >/dev/null
	mutation_snapshot "$work/snap-s" >/dev/null
	# Stamp an hour ahead: every recorded stat is out of the racy window, so
	# only the stat comparison decides. A same-size rewrite in place that puts
	# the old mtime back (touch -r) still has a new ctime.
	touch -t 203001010000 "$work/snap-s.stamp"
	cp -p "$work/snap-s/a/one.go" "$work/one-ref"
	printf 'eno\n' >"$work/snap-s/a/one.go"
	touch -r "$work/one-ref" "$work/snap-s/a/one.go"
	mutation_snapshot "$work/snap-s" >/dev/null
	cmp -s "$root/a/one.go" "$work/snap-s/a/one.go" ||
		{ echo 'FAIL snapshot stat filter: a same-size rewrite under the old mtime was taken as unchanged'; exit 1; }
	# A write in the clock tick of the record leaves the stat as recorded. Model
	# it: the record takes the rewritten file's stat, the stamp lands 1s after
	# that file's ctime. Within 2s of the stamp the file is read again.
	printf 'owt\n' >"$work/snap-s/a/b/two.go"
	snap_record "$work/snap-s" a/b/two.go stat
	mutation_snapshot "$work/snap-s" >/dev/null
	cmp -s "$root/a/b/two.go" "$work/snap-s/a/b/two.go" ||
		{ echo 'FAIL snapshot stat filter: a write inside the racy window was taken as unchanged'; exit 1; }
	# The helper of another shell (a subshell) may have written the record
	# since: a record that is not the one this helper wrote is read again.
	# Model it: a new token, the stat of a/one.go as it is, a hash that is not
	# the manifest's, the stamp far ahead. A helper that reads it puts the
	# file back (one path); one that kept its own record touches nothing.
	snap_record "$work/snap-s" a/one.go hash
	mutation_snapshot_restored_max=0
	mutation_snapshot "$work/snap-s" >/dev/null
	[ "$mutation_snapshot_restored_max" = 1 ] ||
		{ echo "FAIL snapshot stat filter: a record written by another helper was not read (restored $mutation_snapshot_restored_max)"; exit 1; }
) || exit 1
echo 'ok   snapshot stat filter: a kept mtime, a write inside the racy window and a record of another helper are all read again'

# (f) The exit handler hashes the whole tree once more without the stat
# filter: a filter that takes every recorded file as unchanged lets a mutant's
# edit through the reset, and that final pass fails the run.
for snap_case in real trusts-all; do
	if [ "$snap_case" = trusts-all ]; then
		snap_break_py "$snap_case" 'return entry[:5] == key and max(entry[2], entry[3]) < ref_ns - RACY_NS' 'return True'
	else
		cp "$root_real/scripts/lib/mutation_snapshot.py" "$work/broken-snapshot.py"
	fi
	rm -rf "$work/snap-f" "$work/snap-f".*
	set +e
	(
		snap_fresh_state
		root=$snap_src
		mutation_snapshot_py=$work/broken-snapshot.py
		mutation_snapshot "$work/snap-f" >/dev/null
		mutation_snapshot "$work/snap-f" >/dev/null
		printf 'mutant\n' >>"$work/snap-f/a/one.go"
		mutation_snapshot_report 0
	) >"$work/snap-out" 2>&1
	status=$?
	set -e
	case $snap_case:$status in
		real:0) ;;
		trusts-all:2) grep -q '^FAIL mutation tree reset: final pass: 1 paths differ from the manifest: a/one.go$' "$work/snap-out" ||
			{ echo 'FAIL snapshot final pass: no FAIL line'; cat "$work/snap-out"; exit 1; } ;;
		*) echo "FAIL snapshot final pass $snap_case: exit $status"; cat "$work/snap-out"; exit 1 ;;
	esac
done
echo 'ok   snapshot final pass: what the stat filter let through fails the run'

# (g) One helper process per shell answers the resets. A helper that is gone
# stops the suite with exit 2 and a reason; the report ends the helper.
set +e
(
	snap_fresh_state
	root=$snap_src
	mutation_snapshot "$work/snap-g" >/dev/null
	mutation_snapshot "$work/snap-g" >/dev/null
	kill "$mutation_snapshot_server"
	wait "$mutation_snapshot_server" 2>/dev/null
	mutation_snapshot "$work/snap-g"
) >"$work/snap-out" 2>&1
status=$?
set -e
if [ "$status" != 2 ] || ! grep -qx "FAIL mutation snapshot: reset of $work/snap-g did not finish" "$work/snap-out"; then
	echo "FAIL snapshot helper gone: exit $status"
	cat "$work/snap-out"
	exit 1
fi
(
	snap_fresh_state
	root=$snap_src
	mutation_snapshot "$work/snap-h" >/dev/null
	mutation_snapshot "$work/snap-h" >/dev/null
	snap_pid=$mutation_snapshot_server
	[ -n "$snap_pid" ] && kill -0 "$snap_pid" || { echo 'FAIL snapshot helper: no helper process'; exit 1; }
	mutation_snapshot_report 0 >/dev/null
	if kill -0 "$snap_pid" 2>/dev/null; then echo 'FAIL snapshot helper: still running after the report'; exit 1; fi
) || exit 1
echo 'ok   snapshot helper: a helper that is gone stops the suite, the report ends it'

# Refusals at creation and reset: each case must exit 2 with its message.
snap_refuse() {
	label=$1 want=$2 body=$3
	rm -rf "$work/snap-r" "$work/snap-r".* "$work/snap-src-r" "$work/shim"
	cp -R "$snap_src" "$work/snap-src-r"
	set +e
	(
		snap_fresh_state
		root="$work/snap-src-r"
		eval "$body"
		echo 'returned'
	) >"$work/snap-out" 2>&1
	status=$?
	set -e
	if [ "$status" != 2 ] || ! grep -qF -- "$want" "$work/snap-out"; then
		echo "FAIL snapshot refusal $label: exit $status"
		cat "$work/snap-out"
		exit 1
	fi
	echo "ok   snapshot refusal $label: exit 2"
}
snap_tar_shim() {
	# tar that drops one file on extraction: a copy that is not the source.
	mkdir -p "$work/shim"
	snap_real_tar=$(command -v tar)
	printf '#!/bin/sh\n"%s" "$@" || exit\ncase " $* " in *" -xf "*) for a; do last=$a; done; rm -f "$last/c/three.txt" ;; esac\n' "$snap_real_tar" >"$work/shim/tar"
	chmod +x "$work/shim/tar"
	PATH="$work/shim:$PATH"
}
snap_refuse tree-removed 'was removed between mutants' 'mutation_snapshot "$work/snap-r" >/dev/null; rm -rf "$work/snap-r"; mutation_snapshot "$work/snap-r"'
snap_refuse tree-inside-source 'is inside' 'mutation_snapshot "$root/tree"'
snap_refuse unknown-option 'unknown option' 'mutation_snapshot "$work/snap-r" trackd'
snap_refuse prepare-failed 'prepare_fails failed' 'prepare_fails() { return 1; }; mutation_snapshot "$work/snap-r" prepare prepare_fails'
snap_refuse tab-in-name 'tab or a newline' 'printf x >"$root/a/tab$(printf "\t")name"; mutation_snapshot "$work/snap-r"'
snap_refuse newline-in-name 'tab or a newline' 'printf x >"$root/a/nl$(printf "\nx")"; mutation_snapshot "$work/snap-r"'
snap_refuse fifo-in-source 'not a file, directory or symlink' 'mkfifo "$root/c/pipe"; mutation_snapshot "$work/snap-r"'
snap_refuse copy-differs 'the copy differs from' 'snap_tar_shim; mutation_snapshot "$work/snap-r"'
snap_refuse copy-differs-prepare 'the copy differs from' 'snap_tar_shim; noop() { :; }; mutation_snapshot "$work/snap-r" prepare noop'
snap_refuse tracked-missing 'tracked path a/b/two.go is missing' '(cd "$root" && rm -rf .git && git init -q && git add a c run.sh link) && rm "$root/a/b/two.go" && mutation_snapshot "$work/snap-r" tracked'
# A copy that comes back short (here: the symlink step switched off) is caught
# by the exact tracked path set before any mutant runs.
snap_refuse tracked-short 'tracked path set differs (copied 5 of 6 paths)' 'snap_break_py tracked-short "os.symlink(os.readlink(src), dst)"; mutation_snapshot_py=$work/broken-snapshot.py; (cd "$root" && rm -rf .git && git init -q && git add a c run.sh link) && mutation_snapshot "$work/snap-r" tracked'
snap_refuse source-became-symlink 'changed during the run' 'mutation_snapshot "$work/snap-r" >/dev/null; printf "mutant\n" >>"$work/snap-r/a/one.go"; cp "$root/a/one.go" "$work/one-copy"; rm "$root/a/one.go"; ln -s "$work/one-copy" "$root/a/one.go"; mutation_snapshot "$work/snap-r"'
snap_refuse no-python3 'python3 required' 'mkdir -p "$work/no-python"; PATH="$work/no-python"; mutation_snapshot "$work/snap-r"'
snap_refuse report-source-gone 'cannot read' 'mutation_snapshot "$work/snap-r" >/dev/null; rm -rf "$root"; mutation_snapshot_report || exit $?'
snap_refuse report-log-gone 'FAIL snapshot: snapshots=0 mutants=0 restored_max=0 log=unreadable' 'mutation_snapshot "$work/snap-r" >/dev/null; rm "$work/snap-r.log"; mutation_snapshot_report || exit $?'

# (c) The source changing under a run fails it: at the reset of a path the
# mutant touched, and at exit for any other path.
snap_source_change() {
	label=$1
	rm -rf "$work/snap-c" "$work/snap-c".* "$work/snap-src-c"
	cp -R "$snap_src" "$work/snap-src-c"
	set +e
	(
		snap_fresh_state
		root="$work/snap-src-c"
		mutation_snapshot "$work/snap-c" >/dev/null
		case $label in
			touched-path)
				printf 'mutant\n' >>"$work/snap-c/a/one.go"
				printf 'edited during the run\n' >>"$root/a/one.go"
				mutation_snapshot "$work/snap-c" ;;
			other-path)
				printf 'edited during the run\n' >>"$root/c/three.txt"
				mutation_snapshot_report || exit $? ;;
			new-path)
				printf 'new\n' >"$root/c/new.go"
				mutation_snapshot_report || exit $? ;;
		esac
		echo 'returned'
	) >"$work/snap-out" 2>&1
	status=$?
	set -e
	if [ "$status" = 0 ] || ! grep -q 'changed during the run' "$work/snap-out"; then
		echo "FAIL snapshot source-change $label: not refused (exit $status)"
		cat "$work/snap-out"
		exit 1
	fi
	echo "ok   snapshot source-change $label: refused"
}
snap_source_change touched-path
snap_source_change other-path
snap_source_change new-path
# The exit handler of temp_workspace turns such a run red even when every
# mutant was caught, and prints the summary of a clean run. A bytecode cache a
# Python suite writes next to scripts/lib/mutation_edit.py is not a change.
# A suite may make its first call, or every call, in a subshell (a selftest
# in `( )`, a `$( )`): the summary and the final pass still cover that tree,
# and a reset in a subshell still counts as a mutant.
for snap_case in clean changed cache sub-first sub-only sub-reset sub-changed; do
	rm -rf "$work/snap-src-e"
	cp -R "$snap_src" "$work/snap-src-e"
	set +e
	(
		snap_fresh_state
		root="$work/snap-src-e"
		. "$root_real/scripts/temp-workspace.sh"
		temp_workspace
		case $snap_case in
			clean | changed | cache)
				mutation_snapshot "$work/tree" >/dev/null
				mutation_snapshot "$work/tree" >/dev/null ;;
			sub-first)
				(mutation_snapshot "$work/tree" >/dev/null)
				mutation_snapshot "$work/tree" >/dev/null ;;
			sub-only)
				(mutation_snapshot "$work/tree" >/dev/null)
				(mutation_snapshot "$work/tree" >/dev/null) ;;
			sub-reset)
				mutation_snapshot "$work/tree" >/dev/null
				printf 'mutant\n' >>"$work/tree/a/one.go"
				(mutation_snapshot "$work/tree" >/dev/null) ;;
			sub-changed)
				(mutation_snapshot "$work/tree" >/dev/null) ;;
		esac
		case $snap_case in changed | sub-changed) printf 'x\n' >>"$root/c/three.txt" ;; esac
		if [ "$snap_case" = cache ]; then
			mkdir -p "$root/c/__pycache__" "$work/tree/c/__pycache__"
			printf 'x\n' >"$root/c/__pycache__/m.pyc"
			printf 'x\n' >"$work/tree/c/__pycache__/m.pyc"
			mutation_snapshot "$work/tree" >/dev/null
		fi
		exit 0
	) >"$work/snap-out" 2>&1
	status=$?
	set -e
	case $snap_case:$status in
		sub-first:0 | sub-only:0) grep -qx 'ok   snapshot: snapshots=1 mutants=2 restored_max=0' "$work/snap-out" ||
			{ echo "FAIL snapshot exit handler $snap_case: a tree made in a subshell has no summary"; cat "$work/snap-out"; exit 1; } ;;
		sub-reset:0) grep -qx 'ok   snapshot: snapshots=1 mutants=2 restored_max=1' "$work/snap-out" ||
			{ echo 'FAIL snapshot exit handler sub-reset: a reset in a subshell is not counted'; cat "$work/snap-out"; exit 1; } ;;
		sub-changed:2) grep -q 'changed during the run' "$work/snap-out" && grep -qx 'FAIL snapshot: snapshots=1 mutants=1 restored_max=0' "$work/snap-out" ||
			{ echo 'FAIL snapshot exit handler sub-changed: no final check of a tree made in a subshell'; cat "$work/snap-out"; exit 1; } ;;
		clean:0) grep -qx 'ok   snapshot: snapshots=1 mutants=2 restored_max=0' "$work/snap-out" ||
			{ echo 'FAIL snapshot exit handler: no summary line'; cat "$work/snap-out"; exit 1; } ;;
		changed:2) ;;
		cache:0) grep -qx 'ok   snapshot: snapshots=1 mutants=3 restored_max=0' "$work/snap-out" ||
			{ echo 'FAIL snapshot exit handler: a __pycache__ counted as a change'; cat "$work/snap-out"; exit 1; } ;;
		*) echo "FAIL snapshot exit handler $snap_case: exit $status"; cat "$work/snap-out"; exit 1 ;;
	esac
done
echo 'ok   snapshot exit handler: summary on a clean run, exit 2 on a changed source, subshell calls counted'

# (d) No suite copies the whole tree for each mutant: a tar or recursive copy
# of $root belongs to mutation_snapshot, and removing the tree right before
# mutation_snapshot throws the snapshot away. Allowed exceptions name why:
# this file holds the refused patterns as fixtures, and the anchor self-test
# removes a tree on purpose to prove the helper refuses it; the select redrun
# builds three scratch checkouts with untracked files, not one per mutant.
snapshot_once_allowed='check-mutation-helpers.sh check-mutant-anchors-selftest.sh check-mutation-select-redrun.sh'
snapshot_once_lint() {
	snap_lint_status=0
	for f in "$1"/check-*.sh; do
		base=$(basename "$f")
		case " $snapshot_once_allowed " in *" $base "*) continue ;; esac
		awk -v file="$base" '
			# A path argument as the shell sees it: quotes, braces and a
			# trailing slash do not make it another path.
			# ${work:?} and ${work:-x} name $work as well.
			function norm(x,   n) {
				gsub(/["\047]/, "", x)
				while (match(x, /\$\{[A-Za-z_][A-Za-z0-9_]*[:?=+-][^}]*\}/)) {
					n = substr(x, RSTART + 2, RLENGTH - 3); sub(/[:?=+-].*$/, "", n)
					x = substr(x, 1, RSTART - 1) "$" n substr(x, RSTART + RLENGTH)
				}
				gsub(/\$\{/, "$", x); gsub(/\}/, "", x); sub(/\/+$/, "", x); return x
			}
			function snapshot_arg(line, a) {
				if (line !~ /mutation_snapshot[ \t]/) return ""
				a = line; sub(/^.*mutation_snapshot[ \t]+/, "", a); sub(/[ \t;&|)].*$/, "", a); return norm(a)
			}
			{ code = $0; sub(/^[ \t]*#.*/, "", code) }
			code ~ /\$\{?root/ && code ~ /(^|[^A-Za-z_-])tar[ \t]/ && code ~ /[ \t](-[A-Za-z]*c[A-Za-z]*|c[A-Za-z]*f|--create)([ \t=]|$)/ {
				print "FAIL " file ":" NR ": copies the source tree; use mutation_snapshot"; bad = 1
			}
			code ~ /(^|[^A-Za-z_-])(cp|rsync)[ \t]+(-[A-Za-z]+[ \t]+)*-[A-Za-z]*[RrAa][A-Za-z]*[ \t]+(-[A-Za-z]+[ \t]+)*["\047]?\$\{?root\}?["\047]?(\/\.?|\/\*)?["\047]?([ \t]|$)/ {
				print "FAIL " file ":" NR ": copies the source tree; use mutation_snapshot"; bad = 1
			}
			left > 0 {
				left--
				arg = snapshot_arg(code)
				if (arg != "") {
					if (arg == pending) { print "FAIL " file ":" NR ": removes " pending " before mutation_snapshot, a full copy per mutant"; bad = 1 }
					left = 0
				}
			}
			match(code, /rm([ \t]+-[A-Za-z]+)+[ \t]+[^ \t;&|]+/) {
				removed = substr(code, RSTART, RLENGTH); flags = removed
				sub(/^rm([ \t]+-[A-Za-z]+)+[ \t]+/, "", removed)
				if (flags ~ /[ \t]-[A-Za-z]*[rR]/) {
					pending = norm(removed); left = 6
					arg = snapshot_arg(substr(code, RSTART + RLENGTH))
					if (arg != "" && arg == pending) { print "FAIL " file ":" NR ": removes " pending " before mutation_snapshot, a full copy per mutant"; bad = 1 }
				}
			}
			END { exit bad }
		' "$f" || snap_lint_status=1
	done
	return "$snap_lint_status"
}
if ! snapshot_once_lint "$root_real/scripts" >"$work/snap-out"; then
	cat "$work/snap-out"
	exit 1
fi
mkdir -p "$work/lint"
snap_lint_expect() {
	label=$1 body=$2
	rm -f "$work/lint"/*
	printf '#!/bin/sh\n%s\n' "$body" >"$work/lint/check-fixture-mutations.sh"
	if snapshot_once_lint "$work/lint" >"$work/snap-out"; then
		echo "FAIL snapshot-once lint: $label accepted"
		exit 1
	fi
	echo "ok   snapshot-once lint: $label refused"
}
snap_lint_expect tar-copy '	(cd "$root" && tar --exclude=.git -cf - .) | (cd "$work/tree" && tar -xf -)'
snap_lint_expect tar-tracked '(cd "$root" && git ls-files -z | xargs -0 tar cf -) | (cd "$work/tree" && tar xf -)'
snap_lint_expect tar-dir-flag 'tar -C "$root" -cf - . | tar -xf - -C "$work/tree"'
snap_lint_expect cp-recursive 'cp -R "$root/." "$work/tree"'
snap_lint_expect rm-before-snapshot '	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"'
snap_lint_expect rm-before-snapshot-var 'rm -rf "$tree" 2>/dev/null || true
# fresh tree
mutation_snapshot "$tree"'
snap_lint_expect rm-modifier '	rm -rf "${work:?}/tree"
	mutation_snapshot "$work/tree"'
snap_lint_expect rm-same-line 'rm -rf "$work/tree" && mutation_snapshot "$work/tree"'
snap_lint_expect rm-spelling 'rm -r -f "${work}/tree/"
	mutation_snapshot "$work/tree"'
snap_lint_expect rm-single-quotes "rm -rf '\$work/tree'; mutation_snapshot '\$work/tree'"
snap_lint_expect rm-five-lines-later 'rm -rf "$work/tree"
:
:
:
:
mutation_snapshot "$work/tree"'
snap_lint_expect tar-long-option '(cd "$root" && tar --create --file=- .) | tar -xf - -C "$work/tree"'
snap_lint_expect cp-glob 'cp -R "$root"/* "$work/tree"'
printf '#!/bin/sh\n%s\n' 'mutation_snapshot "$work/tree"' 'rm -rf "$work/tree/scratch"' 'cp -R "$root/scripts/lib/apply-only" "$work/x"' >"$work/lint/check-fixture-mutations.sh"
snapshot_once_lint "$work/lint" >"$work/snap-out" || { echo 'FAIL snapshot-once lint: refused a per-file copy'; cat "$work/snap-out"; exit 1; }
echo 'ok   snapshot-once lint: suites keep one snapshot; a per-file copy passes'
