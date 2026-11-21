#!/bin/sh
# Merge request gate for the mutation suites, without their tests: runs each
# mutation suite a change needs in apply-only mode (MUTATION_APPLY_ONLY=1, see
# scripts/mutation-helpers.sh). A mutation whose anchor no longer matches the
# source fails here, in minutes, instead of in the mutation batch on main
# after the merge.
#
#   scripts/check-mutant-anchors.sh            suites mutation-select.py picks
#                                              for $MUTANT_ANCHORS_BASE...HEAD
#                                              (default origin/main)
#   scripts/check-mutant-anchors.sh --all      every suite
#   scripts/check-mutant-anchors.sh ID...      the named suites
#
# Suites run $MUTANT_ANCHORS_JOBS at a time (default 4); each one passes only
# if it exits 0, reports at least one applied mutation, prints no FAIL line,
# and starts no go or node run (scripts/lib/apply-only/).
#
# Each suite's verdict line, with its duration, is printed the moment the suite
# ends; the suites' own output follows at the end. Stopped by a signal (the CI
# budget's `timeout` sends TERM), the driver prints the verdicts it has, names
# every suite that had not finished and how long it ran, stops the rest and
# exits non-zero.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }

# --one ID DIR: one suite, verdict in DIR/ID.log and DIR/ID.rc.
if [ "${1:-}" = --one ]; then
	id=$2 dir=$3
	log=$dir/$id.log trap_file=$dir/$id.trap
	# The selector's naming (mutation-select.py own_script): a map id whose
	# suite is not called check-<id>-mutations.sh.
	script=scripts/check-$id-mutations.sh
	[ -f "$root/$script" ] || script=scripts/$id-mutations.sh
	start=$(date +%s)
	echo "$start" >"$dir/$id.start"
	verdict() {
		echo "$2" >>"$log"
		echo "$2" >"$dir/$id.verdict"
		echo "$1" >"$dir/$id.rc"
		# Streamed at once: a run stopped by its budget still shows this line.
		echo "$2"
		exit 0
	}
	echo "--- $script" >"$log"
	took() { echo $(($(date +%s) - start)); }
	if (cd "$root" && MUTATION_APPLY_ONLY=1 MUTATION_APPLY_ONLY_TRAP="$trap_file" ./"$script" >"$dir/$id.out" 2>&1); then
		status=0
	else
		status=$?
	fi
	cat "$dir/$id.out" >>"$log"
	applied=$(grep -c -E '^ok +[^ ]+: applies$' "$dir/$id.out" || true)
	if [ -s "$trap_file" ]; then
		verdict 1 "FAIL $id: ran $(sort -u "$trap_file" | tr '\n' ' ')in apply-only mode; the suite must skip its tests ($(took)s)"
	elif [ "$status" -ne 0 ]; then
		verdict 1 "FAIL $id: exit $status ($(took)s)"
	elif grep -q '^FAIL' "$dir/$id.out"; then
		verdict 1 "FAIL $id: exit 0 but a FAIL line was printed ($(took)s)"
	elif [ "$applied" -eq 0 ] && grep -q -E '^ok +apply-only: no source anchors' "$dir/$id.out"; then
		# Its mutants are inputs or broken implementations, not source edits.
		verdict 0 "ok   $id: no source anchors to check ($(took)s)"
	elif [ "$applied" -eq 0 ]; then
		verdict 1 "FAIL $id: no mutation reported as applied ($(took)s)"
	fi
	verdict 0 "ok   $id: $applied mutations apply ($(took)s)"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/keep-anchors.XXXXXXXX")
trap 'rm -rf "$work"' EXIT

if [ "$#" -eq 1 ] && [ "$1" = --all ]; then
	set -- $(cd "$root/scripts" && ls *-mutations.sh | sed -e 's/^check-//' -e 's/-mutations\.sh$//')
elif [ "$#" -eq 0 ]; then
	base=${MUTANT_ANCHORS_BASE:-origin/main}
	# The selector answers "everything" on any doubt or failure of its own.
	(cd "$root" && python3 scripts/mutation-select.py --base "$base" --head HEAD --json "$work/select.json")
	set -- $(python3 -I -c 'import json, sys; print(" ".join(s["script"] for s in json.load(open(sys.argv[1]))["selected"]))' "$work/select.json")
fi
if [ "$#" -eq 0 ]; then
	echo 'ok   no mutation suite selected for this change'
	exit 0
fi

fail=0
: >"$work/ids"
for id in "$@"; do
	case $id in
		'' | *[!a-z0-9-]*) echo "FAIL $id: not a suite id"; fail=1; continue ;;
	esac
	if [ ! -f "$root/scripts/check-$id-mutations.sh" ] && [ ! -f "$root/scripts/$id-mutations.sh" ]; then
		echo "FAIL $id: no scripts/check-$id-mutations.sh or scripts/$id-mutations.sh"
		fail=1
		continue
	fi
	echo "$id" >>"$work/ids"
done
jobs=${MUTANT_ANCHORS_JOBS:-4}
case $jobs in '' | *[!0-9]* | 0) echo 'FAIL MUTANT_ANCHORS_JOBS must be a positive number'; exit 2 ;; esac

# Every descendant of $1, deepest last, then $1 itself: busybox timeout signals
# only this shell, so the running suites would outlive it otherwise.
tree() {
	for child in $(pgrep -P "$1" 2>/dev/null || true); do tree "$child"; done
	echo "$1"
}
stopped() {
	trap - HUP INT TERM
	now=$(date +%s)
	echo "FAIL stopped by SIG$1 after $((now - run_start))s; finished suites:"
	while read -r id; do
		if [ -f "$work/$id.verdict" ]; then cat "$work/$id.verdict"; fi
	done <"$work/ids"
	while read -r id; do
		if [ -f "$work/$id.verdict" ]; then continue; fi
		if [ -f "$work/$id.start" ]; then
			echo "FAIL $id: unfinished, ran $((now - $(cat "$work/$id.start")))s before the stop"
		else
			echo "FAIL $id: unfinished, not started before the stop"
		fi
	done <"$work/ids"
	if [ -n "${xpid:-}" ]; then
		# shellcheck disable=SC2046 # one pid per word
		kill -TERM $(tree "$xpid") 2>/dev/null || true
	fi
	exit "$2"
}
run_start=$(date +%s)
xpid=
trap 'stopped HUP 129' HUP
trap 'stopped INT 130' INT
trap 'stopped TERM 143' TERM
echo "--- $(wc -l <"$work/ids" | tr -d ' ') suites, $jobs at a time"
# In the background, so a trapped signal interrupts `wait` instead of waiting
# for every suite to end.
xargs -P "$jobs" -I '{}' "$root/scripts/check-mutant-anchors.sh" --one '{}' "$work" <"$work/ids" &
xpid=$!
if ! wait "$xpid"; then
	echo "FAIL the suite runner (xargs) failed"
	fail=1
fi
trap - HUP INT TERM
echo "--- suite output"
while read -r id; do
	if [ -f "$work/$id.log" ]; then cat "$work/$id.log"; fi
	if [ "$(cat "$work/$id.rc" 2>/dev/null || echo 1)" != 0 ]; then
		[ -f "$work/$id.rc" ] || echo "FAIL $id: no verdict"
		fail=1
	fi
done <"$work/ids"
echo "--- $(($(date +%s) - run_start))s in all"
exit $fail
