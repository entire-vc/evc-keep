#!/bin/sh
# Red runs of scripts/check-mutant-anchors.sh and the apply-only mode of
# scripts/mutation-helpers.sh, on stub suites in a scratch repository: a
# stranded anchor, a forgotten go or node run, a silent suite, a FAIL line
# behind exit 0 and a crash after applied mutants must each fail the driver;
# a clean suite must pass. A driver stopped by a signal must name the suite it
# did not finish. Apply-only snapshots copy the tree once and must restore it
# between mutants (see the restore self-test at the end).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
# Exercise byte-sensitive anchors and all refusal modes through the Python API.
python3 -I - "$root/scripts/lib" <<'PYTHON'
import pathlib, sys, tempfile
sys.path.insert(0, sys.argv[1])
from mutation_edit import AnchorError, edit, edit_file
text = 'first\n\tanchor\\n anchor\\n\n'
assert edit(text, 'anchor\\n', 'changed', 2) == 'first\n\tanchor\\n changed\n'
assert edit('ababa', 'aba', 'X') == 'Xba'  # Non-overlapping occurrences.
assert edit('a\na', 'a\na', 'b') == 'b'
for old, occurrence, message in [
    ('missing', None, 'anchor not found'),
    ('anchor\\n', None, 'anchor occurs 2 times'),
    ('anchor\\n', 3, 'occurrence 3 named'),
    ('', None, 'empty anchor'),
    ('anchor', 0, 'positive number'),
    ('anchor', '1.5', 'positive number'),
    ('anchor', '²', 'positive number'),
    ('anchor', True, 'positive number'),
]:
    try:
        edit(text, old, 'changed', occurrence, 'fixture')
    except Exception as error:  # A crash is not the refusal this row names.
        assert isinstance(error, AnchorError) and message in str(error), (old, occurrence, repr(error))
    else:
        raise AssertionError('editor accepted an invalid anchor or occurrence')
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / 'source'
    path.write_bytes(b'one\r\none\r\n')
    edit_file(path, 'one', 'two', 2)
    assert path.read_bytes() == b'one\r\ntwo\r\n'
print('ok   editor: literal escapes, newlines, explicit occurrence, refusals, CRLF')
PYTHON
work=$(mktemp -d "${TMPDIR:-/tmp}/keep-anchors-selftest.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
repo=$work/repo
mkdir -p "$repo/scripts/lib"
cp "$root/go.mod" "$repo/"
cp "$root/scripts/check-mutant-anchors.sh" "$root/scripts/mutation-helpers.sh" "$repo/scripts/"
cp "$root/scripts/lib/mutation_edit.py" "$root/scripts/lib/mutation_snapshot.py" "$repo/scripts/lib/"
cp -R "$root/scripts/lib/apply-only" "$repo/scripts/lib/"

suite() {
	cat >"$repo/scripts/check-$1-mutations.sh" <<SUITE
#!/bin/sh
set -eu
root=\$(cd "\$(dirname "\$0")/.." && pwd)
. "\$root/scripts/mutation-helpers.sh"
fail=0
mutate() {
	if [ "\$2" != applies ]; then
		echo "FAIL \$1: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "\$1" && return
	echo "ok   \$1: tests went red"
}
$2
exit \$fail
SUITE
	chmod +x "$repo/scripts/check-$1-mutations.sh"
}

printf 'anchor anchor\n' >"$repo/anchor.txt"
suite ambiguous 'name=duplicate
mutation_edit "$root/anchor.txt" anchor changed >"$root/edited.txt"
mutate duplicate applies'
suite explicit 'name=duplicate
MUTATION_OCCURRENCE=2 mutation_take_occurrences
[ "$mutation_occurrence" = 2 ]
mutation_take_occurrences
[ -z "$mutation_occurrence" ]
mutation_edit "$root/anchor.txt" anchor changed 2 >"$root/edited.txt"
[ "$(cat "$root/edited.txt")" = "anchor changed" ]
mutate duplicate applies'

# The shell path: a refusal exits 1 with nothing on stdout (suites rely on
# set -e), and SRC bytes, CR included, reach stdout unchanged.
suite cli 'name=cli
refused() {
	rc=0
	mutation_edit "$@" >"$root/cli.out" 2>"$root/cli.err" || rc=$?
	[ "$rc" = 1 ] || { echo "FAIL cli: $2 exit $rc, want 1"; exit 1; }
	[ ! -s "$root/cli.out" ] || { echo "FAIL cli: $2 refusal wrote stdout"; exit 1; }
}
refused "$root/anchor.txt" anchor changed
grep -q "^FAIL cli: anchor occurs 2 times" "$root/cli.err" || { echo "FAIL cli: ambiguity not named"; exit 1; }
refused "$root/anchor.txt" missing changed
grep -q "^FAIL cli: anchor not found" "$root/cli.err" || { echo "FAIL cli: missing anchor not named"; exit 1; }
refused "$root/anchor.txt" anchor changed 3
grep -q "^FAIL cli: occurrence 3 named" "$root/cli.err" || { echo "FAIL cli: occurrence out of range not named"; exit 1; }
printf "a anchor\r\nb anchor\r\n" >"$root/crlf.txt"
mutation_edit "$root/crlf.txt" "$(printf "anchor\r")" "$(printf "changed\r")" 2 >"$root/crlf.out"
printf "a anchor\r\nb changed\r\n" >"$root/crlf.want"
cmp -s "$root/crlf.out" "$root/crlf.want" || { echo "FAIL cli: CRLF bytes changed"; exit 1; }
mutate cli applies'
suite clean 'mutation_apply_only || go test ./...
mutate a applies
mutate b applies'
suite stale 'mutate a applies
mutate b stale'
suite forgot-go 'go test ./... || true
mutate a applies'
suite forgot-node 'node x.js || true
mutate a applies'
suite silent 'true'
suite hidden-fail 'echo "FAIL a: mutation target is not unique or moved"
mutate b applies'
suite crash 'mutate a applies
exit 3'
suite inputs 'echo "ok   apply-only: no source anchors (fixtures only)"'
# Apply-only batch (mutation_batch, mutation_batch_run): one python3 for the
# whole suite. A compound mutant's second edit sees its first; a named
# occurrence picks the right one; no mutant sees another's edit; the base file
# is never written; a queue that does not hold the mutants queued, or a batch
# that never runs, fails the suite.
batch_suite() {
	suite "$1" "work=\$root/.work-$1
rm -rf \"\$work\"
mkdir -p \"\$work\"
printf 'one two two\\n' >\"\$root/$1.txt\"
$2"
}
batch_suite batch 'name=a; mutation_batch batch.txt one ONE ""
name=b; mutation_batch batch.txt one 1 "" batch.txt "1 two" X ""
name=c; mutation_batch batch.txt two TWO 2
mutation_batch_run "$root" || fail=1
[ "$(cat "$root/batch.txt")" = "one two two" ] || { echo "FAIL batch: the base file was written"; fail=1; }'
batch_suite batch-isolated 'name=a; mutation_batch batch-isolated.txt one ZZZ ""
name=b; mutation_batch batch-isolated.txt ZZZ one ""
mutation_batch_run "$root" || fail=1'
batch_suite batch-ambiguous 'name=a; mutation_batch batch-ambiguous.txt two TWO ""
mutation_batch_run "$root" || fail=1'
batch_suite batch-count 'name=a; mutation_batch batch-count.txt one ONE ""
python3 -I "$root/scripts/lib/mutation_edit.py" --batch "$root" "$work/mutation-batch" 2 || fail=1'
batch_suite batch-truncated 'name=a; mutation_batch batch-truncated.txt one ONE ""
printf "%s\000" b 2 batch-truncated.txt >>"$work/mutation-batch"
python3 -I "$root/scripts/lib/mutation_edit.py" --batch "$root" "$work/mutation-batch" 2 || fail=1'
batch_suite batch-unrun 'name=a; mutation_batch batch-unrun.txt one ONE ""'

expect() {
	want=$1
	shift
	if "$repo/scripts/check-mutant-anchors.sh" "$@" >"$work/out" 2>&1; then got=0; else got=1; fi
	if [ "$got" != "$want" ]; then
		echo "FAIL driver $*: exit $got, want $want"
		cat "$work/out"
		exit 1
	fi
	echo "ok   driver $*: exit $got"
}
expect 1 ambiguous
grep -q 'FAIL duplicate: anchor occurs 2 times in .*anchor.txt, name the occurrence' "$work/out" || {
 echo 'FAIL driver: ambiguous anchor was not named'; exit 1;
}
expect 0 explicit
expect 0 cli
expect 0 clean
expect 0 inputs
expect 1 stale
expect 1 forgot-go
expect 1 forgot-node
expect 1 silent
expect 1 hidden-fail
expect 1 crash
expect 1 clean stale
expect 0 batch
grep -q '^ok   batch: 3 mutations apply' "$work/out" || { echo 'FAIL driver: batch did not report 3 applied mutants'; exit 1; }
expect 1 batch-isolated
grep -q '^FAIL b: mutation did not apply (anchor not found in batch-isolated.txt)' "$work/out" ||
	{ echo "FAIL driver: a mutant's edit reached the next mutant in the batch"; exit 1; }
grep -q '^ok   a: applies' "$work/out" || { echo 'FAIL driver: batch dropped the good mutant'; exit 1; }
expect 1 batch-ambiguous
grep -q '^FAIL a: mutation did not apply (anchor occurs 2 times in batch-ambiguous.txt, name the occurrence)' "$work/out" ||
	{ echo 'FAIL driver: batch took an ambiguous anchor'; exit 1; }
expect 1 batch-count
grep -q '^FAIL apply-only batch: 1 mutants in the queue, the suite queued 2' "$work/out" ||
	{ echo 'FAIL driver: batch accepted a queue short of the queued mutants'; exit 1; }
expect 1 batch-truncated
grep -q '^FAIL apply-only batch: unreadable queue (queue ends inside mutant b)' "$work/out" ||
	{ echo 'FAIL driver: batch accepted a truncated queue'; exit 1; }
expect 1 batch-unrun
grep -q '^FAIL batch-unrun: no mutation reported as applied' "$work/out" ||
	{ echo 'FAIL driver: a batch that never ran was accepted'; exit 1; }
expect 1 no-such-suite
expect 1 'bad id'
"$repo/scripts/check-mutant-anchors.sh" forgot-go >"$work/out" 2>&1 || true
grep -q '^FAIL forgot-go: ran go test' "$work/out" || { echo 'FAIL driver: trap mark not reported'; exit 1; }
echo 'ok   driver: forgotten go test is named'

# Stopped mid-run (the CI budget's `timeout`, or any TERM): a finished suite's
# verdict is already printed, the unfinished one is named as FAIL, its process
# tree is gone and the exit is non-zero. "kill" signals only the driver, as
# busybox timeout does; "timeout" is whichever timeout(1) the host has (GNU
# signals the whole process group).
slow=slow$$
suite "$slow" "sleep 60 & echo \$! >'$work/$slow.sleep'; wait
mutate a applies"
stop_case() {
	how=$1
	rm -f "$work/$slow.sleep" "$work/stop.out"
	if [ "$how" = kill ]; then
		"$repo/scripts/check-mutant-anchors.sh" clean "$slow" >"$work/stop.out" 2>&1 &
	else
		timeout -k 5s 8s "$repo/scripts/check-mutant-anchors.sh" clean "$slow" >"$work/stop.out" 2>&1 &
	fi
	pid=$!
	if [ "$how" = kill ]; then
		n=0
		until grep -q '^ok   clean: 2 mutations apply ([0-9]*s)$' "$work/stop.out" && [ -s "$work/$slow.sleep" ]; do
			n=$((n + 1))
			if [ "$n" -gt 60 ]; then
				echo "FAIL driver stop ($how): no streamed verdict for clean within 30s"
				cat "$work/stop.out"
				kill -TERM "$pid" 2>/dev/null || true
				exit 1
			fi
			sleep 0.5
		done
		kill -TERM "$pid"
	fi
	if wait "$pid"; then rc=0; else rc=$?; fi
	if [ "$rc" = 0 ]; then
		echo "FAIL driver stop ($how): exit 0 with $slow unfinished"
		cat "$work/stop.out"
		exit 1
	fi
	for want in '^ok   clean: 2 mutations apply ([0-9]*s)$' '^FAIL stopped by SIGTERM after [0-9]*s' \
		"^FAIL $slow: unfinished, ran [0-9]*s before the stop\$"; do
		grep -q "$want" "$work/stop.out" || {
			echo "FAIL driver stop ($how): no line matching $want"
			cat "$work/stop.out"
			exit 1
		}
	done
	n=0
	while kill -0 "$(cat "$work/$slow.sleep")" 2>/dev/null; do
		n=$((n + 1))
		if [ "$n" -gt 10 ]; then
			echo "FAIL driver stop ($how): the unfinished suite's process outlived the driver"
			kill "$(cat "$work/$slow.sleep")" 2>/dev/null || true
			exit 1
		fi
		sleep 0.5
	done
	echo "ok   driver stop ($how): exit $rc, $slow named unfinished, its processes stopped"
}
stop_case kill
if command -v timeout >/dev/null; then
	stop_case timeout
fi

# The helper itself: off by default, refuses anything but 1/0/unset.
(
	. "$repo/scripts/mutation-helpers.sh"
	if mutation_applied x >/dev/null; then echo 'FAIL helper: apply-only on without the variable'; exit 1; fi
) || exit 1
echo 'ok   helper: off without MUTATION_APPLY_ONLY'
if (MUTATION_APPLY_ONLY=yes root=$repo sh -c '. "$root/scripts/mutation-helpers.sh"') >/dev/null 2>&1; then
	echo 'FAIL helper: MUTATION_APPLY_ONLY=yes accepted'
	exit 1
fi
echo 'ok   helper: refuses MUTATION_APPLY_ONLY=yes'
if (root=$repo work=$work name=x sh -c '. "$root/scripts/mutation-helpers.sh"; mutation_batch f a b ""') >"$work/batch.out" 2>&1 ||
	! grep -q -x 'FAIL x: mutation_batch outside apply-only mode' "$work/batch.out"; then
	echo 'FAIL helper: mutation_batch queued outside apply-only mode'
	exit 1
fi
if (MUTATION_APPLY_ONLY=1 root=$repo work=$work name=x sh -c '. "$root/scripts/mutation-helpers.sh"; mutation_batch f a b') >"$work/batch.out" 2>&1 ||
	! grep -q -x 'FAIL x: mutation_batch takes 4 or 8 arguments, got 3' "$work/batch.out"; then
	echo 'FAIL helper: mutation_batch took a short edit'
	exit 1
fi
echo 'ok   helper: mutation_batch only in apply-only mode, whole edits only'
# The batch's own exit status, not only its FAIL line: a suite that reads
# only the status (`mutation_batch_run BASE || fail=1`) must see the stale one.
mkdir -p "$work/batch-rc"
printf 'one\n' >"$work/batch-rc/rc.txt"
if (MUTATION_APPLY_ONLY=1 root=$repo work=$work/batch-rc sh -c '. "$root/scripts/mutation-helpers.sh"
	name=good; mutation_batch rc.txt one ONE ""
	name=stale; mutation_batch rc.txt nope X ""
	mutation_batch_run "$work"') >"$work/batch.out" 2>&1; then
	echo 'FAIL helper: mutation_batch_run returned 0 with a mutant that did not apply'
	exit 1
fi
echo 'ok   helper: mutation_batch_run returns non-zero when a mutant did not apply'
if (MUTATION_APPLY_ONLY=1 root=$repo sh -c '. "$root/scripts/mutation-helpers.sh"; go version' >/dev/null 2>&1) && command -v go >/dev/null; then
	echo 'ok   helper: go version still reaches the real toolchain'
elif command -v go >/dev/null; then
	echo 'FAIL helper: go version blocked in apply-only mode'
	exit 1
fi

# Apply-only snapshots copy the tree once (mutation_snapshot in
# mutation-helpers.sh; its reset guards are proved in check-mutation-helpers.sh).
# A mutant's leftovers (a rewritten, a created, an ignored and a deleted file)
# must not reach the next mutant, the source repository is never written, and
# a tree removed or replaced between mutants stops the suite.
helpers=$root/scripts/mutation-helpers.sh
snapshot_py=$root/scripts/lib/mutation_snapshot.py
(
	root=$work/restore-src
	work=$work/restore-work
	mkdir -p "$root/pkg" "$work"
	printf 'package pkg\n\nconst anchor = "base"\n' >"$root/pkg/a.go"
	printf 'deleted by the first mutant\n' >"$root/pkg/doomed.txt"
	printf '*.log\n' >"$root/.gitignore"
	git -C "$root" -c init.defaultBranch=main init -q
	git -C "$root" add -A
	git -C "$root" -c user.name=t -c user.email=t@example.invalid -c commit.gpgSign=false commit -q -m base
	MUTATION_APPLY_ONLY=1
	. "$helpers"
	# The scratch source has no scripts/: point the helper at the real one.
	mutation_snapshot_py=$snapshot_py
	# mutant NAME FROM TO: a suite's mutate() in miniature.
	mutant() {
		mutation_snapshot "$work/tree"
		if ! grep -q -F "$2" "$work/tree/pkg/a.go"; then
			echo "did not apply: $1"
			return 0
		fi
		sed "s/$2/$3/" "$work/tree/pkg/a.go" >"$work/tree/pkg/a.go.new"
		mv "$work/tree/pkg/a.go.new" "$work/tree/pkg/a.go"
		printf 'package pkg\n' >"$work/tree/pkg/created.go"
		printf 'ignored\n' >"$work/tree/pkg/left.log"
		rm "$work/tree/pkg/doomed.txt"
		mutation_applied "$1"
	}
	mutation_snapshot "$work/tree"
	first_inode=$(ls -i "$work/tree/.gitignore" | awk '{print $1}')
	[ "$(mutant one '"base"' '"BASE"')" = 'ok   one: applies' ] || { echo 'FAIL restore: mutant one did not apply'; exit 1; }
	# Same second, same size: the stat check alone must not hide the rewrite.
	[ "$(mutant two '"BASE"' '"base2"')" = 'did not apply: two' ] ||
		{ echo 'FAIL restore: mutant two found the anchor only mutant one wrote'; exit 1; }
	mutation_snapshot "$work/tree"
	for left in pkg/created.go pkg/left.log; do
		if [ -e "$work/tree/$left" ]; then echo "FAIL restore: $left survived into the next snapshot"; exit 1; fi
	done
	cmp -s "$root/pkg/doomed.txt" "$work/tree/pkg/doomed.txt" || { echo 'FAIL restore: deleted file not restored'; exit 1; }
	cmp -s "$root/pkg/a.go" "$work/tree/pkg/a.go" || { echo 'FAIL restore: rewritten file not restored'; exit 1; }
	[ -z "$(git -C "$root" status --porcelain --ignored --untracked-files=all)" ] || { echo 'FAIL restore: the source repository was written'; exit 1; }
	# An unchanged file keeps its inode: the reset did not copy the tree again.
	[ "$(ls -i "$work/tree/.gitignore" | awk '{print $1}')" = "$first_inode" ] ||
		{ echo 'FAIL restore: apply-only copied the whole tree again'; exit 1; }
	echo 'ok   apply-only snapshot: no leftover reaches the next mutant, the source stays clean'
	# A tree removed or replaced by a symlink between mutants is refused:
	# copying it again would be the per-mutant copy this helper replaced.
	for replace in removed symlink; do
		rm -rf "$work/tree"
		if [ "$replace" = symlink ]; then
			mkdir -p "$work/elsewhere"
			ln -s "$work/elsewhere" "$work/tree"
		fi
		if (mutation_snapshot "$work/tree") >"$work/reset.out" 2>&1; then
			echo "FAIL restore: a $replace tree was accepted"
			exit 1
		fi
		grep -q -F "FAIL mutation snapshot: $work/tree was removed between mutants" "$work/reset.out" ||
			{ echo "FAIL restore: a $replace tree gave no FAIL line"; exit 1; }
	done
	echo 'ok   apply-only snapshot: a tree removed or replaced between mutants stops the suite'
)
