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
	verdict() {
		echo "$2" >>"$log"
		echo "$1" >"$dir/$id.rc"
		exit 0
	}
	echo "--- $script" >"$log"
	start=$(date +%s)
	if (cd "$root" && MUTATION_APPLY_ONLY=1 MUTATION_APPLY_ONLY_TRAP="$trap_file" ./"$script" >"$dir/$id.out" 2>&1); then
		status=0
	else
		status=$?
	fi
	cat "$dir/$id.out" >>"$log"
	applied=$(grep -c -E '^ok +[^ ]+: applies$' "$dir/$id.out" || true)
	if [ -s "$trap_file" ]; then
		verdict 1 "FAIL $id: ran $(sort -u "$trap_file" | tr '\n' ' ')in apply-only mode; the suite must skip its tests"
	elif [ "$status" -ne 0 ]; then
		verdict 1 "FAIL $id: exit $status"
	elif grep -q '^FAIL' "$dir/$id.out"; then
		verdict 1 "FAIL $id: exit 0 but a FAIL line was printed"
	elif [ "$applied" -eq 0 ] && grep -q -E '^ok +apply-only: no source anchors' "$dir/$id.out"; then
		# Its mutants are inputs or broken implementations, not source edits.
		verdict 0 "ok   $id: no source anchors to check"
	elif [ "$applied" -eq 0 ]; then
		verdict 1 "FAIL $id: no mutation reported as applied"
	fi
	verdict 0 "ok   $id: $applied mutations apply ($(($(date +%s) - start))s)"
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
xargs -P "$jobs" -I '{}' "$root/scripts/check-mutant-anchors.sh" --one '{}' "$work" <"$work/ids"
while read -r id; do
	if [ -f "$work/$id.log" ]; then cat "$work/$id.log"; fi
	if [ "$(cat "$work/$id.rc" 2>/dev/null || echo 1)" != 0 ]; then
		[ -f "$work/$id.rc" ] || echo "FAIL $id: no verdict"
		fail=1
	fi
done <"$work/ids"
exit $fail
