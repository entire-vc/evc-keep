#!/usr/bin/env python3
"""Decide whether the mutation jobs of an MR pipeline may be started.

Used by ci-play-mutation-jobs.sh. Inputs are four JSON files (the MR, its
notes, the jobs of its head pipeline, its bridges: child pipelines). Exit 0 = go; exit 3 = refused, with the
reasons on stdout (job names and statuses, author names, short SHAs: never a
note body). A mutation job costs minutes of a shared runner, so it is not
started until everything else is green and a reviewer's verdict names the
HEAD that would be tested. The merge gate is not touched by this script.
"""
from datetime import datetime
import json
import os
import re
import sys

# Fixed on purpose: an environment override would let the caller start the
# mutation jobs without the reviewer's verdict or with a shorter stage list.
STAGES = ["security", "lint", "test", "build", "post-review"]
VERDICT_AUTHOR = "charles"
# The trigger that starts the merge request's child pipeline of post-review jobs.
POST_REVIEW_TRIGGER = "mutations"
# "SHIP" as a whole word, not the tail of "DO-NOT-SHIP" or part of "SHIPPED".
SHIP = re.compile(r"(?<![A-Za-z0-9_-])SHIP(?![A-Za-z0-9_-])")
# Anything that negates or withholds a verdict, anywhere in the verdict line.
NEGATION = re.compile(r"\b(NOT|NO|NEVER|CANNOT|CAN'T|WON'T|BLOCKED|ROUTE|FAIL\w*)\b|DO-NOT-SHIP", re.I)
# "AC PASS ... awaiting mutations" as the reviewer writes it (escaped: the repo stays ASCII).
AC_PASS_AWAITING = re.compile("AC PASS[^\\n]*\u043e\u0436\u0438\u0434\u0430\u0435\u0442 \u043c\u0443\u0442\u0430\u0446\u0438\u0438")
SHA = re.compile(r"\b[0-9a-f]{40}\b")
# A note without the marker that still withdraws or blocks a verdict.
WITHDRAWS = re.compile(r"DO-NOT-SHIP|\b(BLOCKED|WITHDRAW\w*|REVOKE\w*|RETRACT\w*)\b", re.I)


def verdict_line(body):
    """The first unquoted line carrying the marker, or None."""
    for line in body.splitlines():
        if not line.lstrip().startswith(">") and "Verify: Charles" in line:
            return line
    return None


def when(note):
    return datetime.fromisoformat(note["created_at"].replace("Z", "+00:00"))


def is_mutation(job):
    return job["name"].split(" ")[0].endswith("-mutations")


def withdraws(body):
    """True if an unquoted line of a note without the marker blocks or withdraws."""
    return any(WITHDRAWS.search(l) for l in body.splitlines() if not l.lstrip().startswith(">"))


def snapshot(mr):
    """(HEAD sha, head pipeline id) of an MR response."""
    return ((mr.get("sha") or "").lower(), (mr.get("head_pipeline") or {}).get("id"))


def reasons(mr, notes, jobs, bridges, mr_after=None):
    out = []
    head = (mr.get("sha") or "").lower()
    pipe = mr.get("head_pipeline") or {}
    # The MR, notes, jobs and bridges are separate API calls. If HEAD or the head
    # pipeline moved while they were read, the pieces describe different states.
    if mr_after is not None and snapshot(mr_after) != snapshot(mr):
        return ["the MR HEAD or head pipeline changed while the state was read"]
    for what, items in (("job", jobs), ("bridge", bridges)):
        for it in items:
            if (it.get("pipeline") or {}).get("id") != pipe.get("id"):
                out.append("%s %s does not belong to head pipeline %s" % (what, it.get("name"), pipe.get("id")))
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        return ["the MR has no HEAD sha"]
    if (pipe.get("sha") or "").lower() != head:
        out.append("the head pipeline is not on the current HEAD %s" % head[:8])

    mut = [j for j in jobs if is_mutation(j)]
    mut_stage = STAGES.index(mut[0]["stage"]) if mut and mut[0]["stage"] in STAGES else len(STAGES)
    for j in jobs:
        if is_mutation(j):
            continue
        st = STAGES.index(j["stage"]) if j["stage"] in STAGES else -1
        if st > mut_stage:
            # Later stage: it cannot have run yet (created, skipped), but a
            # job that already failed or was canceled is not a green CI.
            if j["status"] in ("failed", "canceled"):
                out.append("job %s is %s, not success" % (j["name"], j["status"]))
            continue
        if j["status"] != "success":
            out.append("job %s is %s, not success" % (j["name"], j["status"]))

    # A child pipeline is part of the same CI: jobs of the parent do not count it.
    for b in bridges:
        down = b.get("downstream_pipeline") or {}
        # The trigger of the post-review child waits for start-mutations, the
        # job this gate is about to start: not started yet is its only valid
        # state here. Any other state of it, or of any other child, refuses.
        if (b.get("stage") == STAGES[-1] and b.get("name") == POST_REVIEW_TRIGGER
                and not b.get("downstream_pipeline") and b.get("status") == "created"):
            continue
        if down.get("status") != "success":
            out.append("bridge %s downstream is %s, not success" % (b.get("name"), down.get("status") or "not started"))

    mine = [n for n in notes if not n.get("system")
            and (n.get("author") or {}).get("username") == VERDICT_AUTHOR]
    verdicts = [n for n in mine if verdict_line(n.get("body", "")) is not None]
    # The latest note that either carries the marker or withdraws a verdict decides.
    deciding = [n for n in mine if n in verdicts or withdraws(n.get("body", ""))]
    if not verdicts:
        out.append("no 'Verify: Charles' note by %s on this MR" % VERDICT_AUTHOR)
    elif max(deciding, key=when) not in verdicts:
        out.append("a later note by %s withdraws or blocks the verdict" % VERDICT_AUTHOR)
    else:
        latest = max(deciding, key=when)
        line = verdict_line(latest["body"])
        shas = SHA.findall(line.lower())
        if shas != [head]:
            out.append("the latest verdict does not name exactly the current HEAD %s" % head[:8])
        elif NEGATION.search(line) or not (SHIP.search(line) or AC_PASS_AWAITING.search(line)):
            out.append("the latest verdict on this HEAD is not SHIP or AC PASS")
    return out


def main(argv):
    if argv[1] == "--same":
        # Recheck before starting jobs: the MR must still be the one that was gated.
        a, b = (json.load(open(p)) for p in argv[2:4])
        if snapshot(a) == snapshot(b):
            return 0
        print("refused: the MR HEAD or head pipeline changed since the gate")
        return 3
    mr, notes, jobs, bridges, mr_after = (json.load(open(p)) for p in argv[1:6])
    why = reasons(mr, notes, jobs, bridges, mr_after)
    for w in why:
        print("refused: " + w)
    return 3 if why else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
