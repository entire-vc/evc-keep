#!/bin/sh
# Start the manual mutation jobs of an MR's latest pipeline, once, when the MR
# is ready. Merge request pipelines carry no mutation job any more (mutation
# suites run in the nightly schedule and on release tags, see .gitlab-ci.yml),
# so on a current pipeline it finds nothing to start; it stays for pipelines
# created before that change, which still have the manual, blocking
# start-mutations job and the `mutations` trigger of the selected child.
#
# A manual job only appears when its stage is reached, and a manual job in an
# early stage holds the later ones. The script therefore keeps polling and
# starts each mutation job as it turns manual, until none is left to start
# (the pipeline finished, or every remaining job is running or done).
#
# Gate: it refuses (exit 3, reasons printed) unless every non-mutation job of the
# head pipeline is success (a failed or canceled job of a later stage refuses
# too), every child pipeline (bridge) succeeded (the `mutations` trigger, not
# started yet, aside), and the latest "Verify: Charles" note on the MR names
# the current full HEAD SHA with SHIP (or "AC PASS ... awaiting mutations").
# A later note by the reviewer that withdraws or blocks the verdict (DO-NOT-SHIP,
# BLOCKED, withdrawn) also refuses. See scripts/ci-play-gate.py; the merge gate is unchanged. Helper only: to roll
# it back, revert the commit that added the gate.
#
# Usage: scripts/ci-play-mutation-jobs.sh <mr_iid> [project]   (needs an authenticated glab)
set -eu
iid=${1:?usage: ci-play-mutation-jobs.sh <mr_iid> [project]}
project=${2:-entire-vc%2Fevc-keep}
interval=${PLAY_MUTATIONS_INTERVAL:-30}
# At most this many mutation jobs of the MR are queued or running at once; the
# rest start as slots free up. Playing all ~50 at once put every other MR's
# jobs behind them in the runner queue (p90 wait 24 min, median 0.5).
max_inflight=${PLAY_MUTATIONS_MAX_INFLIGHT:-16}
case $max_inflight in ''|*[!0-9]*) echo "PLAY_MUTATIONS_MAX_INFLIGHT must be a positive integer" >&2; exit 2;; esac
# "08" is decimal 8: shell arithmetic would read a leading zero as octal ("08" fails, "00" plays nothing)
max_inflight=${max_inflight#"${max_inflight%%[!0]*}"}
[ -n "$max_inflight" ] || { echo "PLAY_MUTATIONS_MAX_INFLIGHT must be a positive integer" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
gate=$(mktemp -d "${TMPDIR:-/tmp}/play-gate.XXXXXX")
trap 'rm -rf "$gate"' EXIT
glab api "projects/$project/merge_requests/$iid" >"$gate/mr.json"
pipeline=$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])).get("head_pipeline") or {}; print(p.get("id") or "")' "$gate/mr.json")
[ -n "$pipeline" ] || { echo "MR !$iid has no head pipeline" >&2; exit 1; }
glab api "projects/$project/merge_requests/$iid/notes?per_page=100&sort=desc" >"$gate/notes.json"
glab api --paginate "projects/$project/pipelines/$pipeline/jobs?per_page=100" |
	python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read().replace("][", ",") or "[]")))' >"$gate/jobs.json"
glab api "projects/$project/pipelines/$pipeline/bridges" >"$gate/bridges.json"
# Read the MR again last: the gate refuses if HEAD or the head pipeline moved meanwhile.
glab api "projects/$project/merge_requests/$iid" >"$gate/mr_after.json"
rc=0
python3 "$here/ci-play-gate.py" "$gate/mr.json" "$gate/notes.json" "$gate/jobs.json" "$gate/bridges.json" "$gate/mr_after.json" || rc=$?
if [ "$rc" -ne 0 ]; then
	echo "mutation jobs of MR !$iid not started (pipeline $pipeline)" >&2
	exit "$rc"
fi

started=0
while :; do
	# Prints "<pending>" and "<inflight mutation jobs>" on the first two lines,
	# then "<id> <name>" per manual job.
	report=$(glab api --paginate "projects/$project/pipelines/$pipeline/jobs?per_page=100" |
		python3 -c '
import json, sys
text = sys.stdin.read().replace("][", ",")
jobs = json.loads(text or "[]")
mut = [j for j in jobs if j["name"].split(" ")[0].endswith("-mutations")]
manual = [j for j in mut if j["status"] == "manual"]
pending = [j for j in jobs if j["status"] in ("created", "pending", "running", "waiting_for_resource", "preparing")]
print(len(pending))
print(len([j for j in mut if j["status"] in ("pending", "running", "waiting_for_resource", "preparing")]))
for j in manual:
    print(j["id"], j["name"])')
	pending=$(echo "$report" | head -n 1)
	inflight=$(echo "$report" | sed -n 2p)
	manual=$(echo "$report" | tail -n +3)
	waiting=$(echo "$manual" | grep -c . || true)
	slots=$((max_inflight - inflight))
	[ "$slots" -ge 0 ] || slots=0
	# Only the head of the list fits in the free slots; the next round takes the rest.
	manual=$(echo "$manual" | awk -v n="$slots" "NR <= n")
	if [ -n "$manual" ]; then
		# Re-read the MR immediately before EVERY play POST, not once per batch: if
		# HEAD or the head pipeline moves between two POSTs, the rest of the batch
		# belongs to an old pipeline and must not start. The loop reads from a file,
		# not a pipe, so `exit` stops the whole script rather than a subshell.
		echo "$manual" >"$gate/manual.txt"
		while read -r id name; do
			glab api "projects/$project/merge_requests/$iid" >"$gate/mr_now.json"
			rc=0
			python3 "$here/ci-play-gate.py" --same "$gate/mr.json" "$gate/mr_now.json" || rc=$?
			if [ "$rc" -ne 0 ]; then
				echo "mutation jobs of MR !$iid: batch stopped before $name, MR changed (pipeline $pipeline)" >&2
				exit "$rc"
			fi
			glab api -X POST "projects/$project/jobs/$id/play" >/dev/null
			echo "started $name ($id)"
			started=1
		done <"$gate/manual.txt"
	fi
	# Stop only when nothing is in flight and no manual job is left to start;
	# "pending" was read before this round's plays, so a round that played
	# something is followed by a fresh read.
	[ "$pending" -gt 0 ] || [ "$waiting" -gt 0 ] || break
	sleep "$interval"
done
[ "$started" -eq 1 ] || echo "pipeline $pipeline: no manual mutation jobs (already started, or not an MR pipeline)"
