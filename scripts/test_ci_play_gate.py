#!/usr/bin/env python3
"""ci-play-mutation-jobs.sh against a fake glab: it must refuse unless the rest
of CI is green and a reviewer's verdict names the current HEAD, and must say
why without printing a note body."""
import copy
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/ci-play-mutation-jobs.sh"
HEAD = "a" * 40
OLD = "b" * 40
CANARY = "canary-note-body-7c1e"
AWAITING = "AC PASS, \u043e\u0436\u0438\u0434\u0430\u0435\u0442 \u043c\u0443\u0442\u0430\u0446\u0438\u0438"

FAKE_GLAB = """#!/bin/sh
d="$FAKE_DIR"
for a in "$@"; do url=$a; done
case "$*" in
*"-X POST"*) echo "$url" >>"$d/played.log"; echo '{}';;
*/notes*) cat "$d/notes.json";;
*/bridges*) cat "$d/bridges.json";;
*/jobs*) if [ -f "$d/played.log" ]; then sed 's/"created"/"success"/g; s/"manual"/"success"/g' "$d/jobs.json"; else cat "$d/jobs.json"; fi;;
*) n=$(cat "$d/mr.count" 2>/dev/null || echo 0); n=$((n+1)); echo $n >"$d/mr.count"
   if [ -f "$d/mr$n.json" ]; then cat "$d/mr$n.json"; else cat "$d/mr.json"; fi;;
esac
"""


# Played jobs stay "running" for two job listings, then succeed; every play
# records how many played jobs were still running at that moment.
WAVE_GLAB = """#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_DIR"]
url = sys.argv[-1]
state = os.path.join(d, "state.json")
st = json.load(open(state)) if os.path.exists(state) else {}
if "-X" in sys.argv:
    running = sum(1 for v in st.values() if v < 2)
    open(os.path.join(d, "inflight.log"), "a").write("%d\\n" % running)
    open(os.path.join(d, "played.log"), "a").write(url + "\\n")
    st[url.split("/")[-2]] = 0
    json.dump(st, open(state, "w"))
    print("{}")
elif "/notes" in url:
    print(open(os.path.join(d, "notes.json")).read())
elif "/bridges" in url:
    print(open(os.path.join(d, "bridges.json")).read())
elif "/jobs" in url:
    jobs = json.load(open(os.path.join(d, "jobs.json")))
    n = os.path.join(d, "listings")
    seen = int(open(n).read()) if os.path.exists(n) else 0
    open(n, "w").write(str(seen + 1))
    for j in jobs:
        if j.get("late") and seen >= 3:
            j["status"] = "manual"
        v = st.get(str(j["id"]))
        if v is not None:
            j["status"] = "running" if v < 2 else "success"
    st = {k: v + 1 for k, v in st.items()}
    json.dump(st, open(state, "w"))
    print(json.dumps(jobs))
else:
    print(open(os.path.join(d, "mr.json")).read())
"""


def job(id_, name, status, stage="test"):
    return {"id": id_, "name": name, "status": status, "stage": stage, "pipeline": {"id": 7}}


def note(body, author="charles", at="2026-10-15T01:00:00Z", system=False):
    return {"body": body, "author": {"username": author}, "created_at": at, "system": system}


def green_jobs():
    return [job(1, "lint", "success", "lint"), job(2, "test", "success"),
            job(3, "build", "created", "build"),
            job(10, "sealer-mutations", "manual"), job(11, "carriers-mutations 1/4", "manual")]


def green_bridges():
    return [{"name": "full-tests", "status": "success", "pipeline": {"id": 7}, "downstream_pipeline": {"id": 8, "status": "success"}}]


LAST_INFLIGHT = []


def ci_config():
    spec = importlib.util.spec_from_file_location("ci_config", ROOT / "scripts/test_ci_config.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, module.yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())


def mr_pipeline(module, config):
    """The jobs a merge request pipeline of `config` creates, every one either
    green or waiting to be played, as the jobs API would list them."""
    names = sorted(module.pipeline_jobs(config, module.MR))
    return [job(100 + i, name, "manual" if name.endswith("-mutations") else "success",
                config[name].get("stage", "test"))
            for i, name in enumerate(names) if "trigger" not in config[name]]


def run(jobs, notes, head=HEAD, pipe_sha=HEAD, bridges=None, later_mr=None, extra_env=None, fake=FAKE_GLAB):
    with tempfile.TemporaryDirectory() as d:
        dd = Path(d)
        (dd / "mr.json").write_text(json.dumps({"sha": head, "head_pipeline": {"id": 7, "sha": pipe_sha}}))
        for n, body in (later_mr or {}).items():
            (dd / ("mr%d.json" % n)).write_text(json.dumps(body))
        (dd / "notes.json").write_text(json.dumps(notes))
        (dd / "jobs.json").write_text(json.dumps(jobs))
        (dd / "bridges.json").write_text(json.dumps(green_bridges() if bridges is None else bridges))
        bindir = dd / "bin"
        bindir.mkdir()
        glab = bindir / "glab"
        glab.write_text(fake)
        glab.chmod(glab.stat().st_mode | stat.S_IXUSR)
        env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"], FAKE_DIR=d,
                   PLAY_MUTATIONS_INTERVAL="0", TMPDIR=d, **(extra_env or {}))
        p = subprocess.run(["sh", str(SCRIPT), "5", "p"], env=env, capture_output=True, text=True, timeout=60)
        played = (dd / "played.log").read_text().split() if (dd / "played.log").exists() else []
        global LAST_INFLIGHT
        LAST_INFLIGHT = [int(x) for x in (dd / "inflight.log").read_text().split()] if (dd / "inflight.log").exists() else []
        return p.returncode, p.stdout + p.stderr, played


class Gate(unittest.TestCase):
    def test_refuses_without_verdict(self):
        rc, out, played = run(green_jobs(), [])
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])
        self.assertIn("no 'Verify: Charles' note", out)

    def test_plays_with_ship_on_head_and_green_jobs(self):
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP at %s %s" % (HEAD, CANARY))])
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(played), 2, played)
        self.assertNotIn(CANARY, out)

    def test_plays_with_ac_pass_awaiting_mutations(self):
        rc, out, played = run(green_jobs(), [note("Verify: Charles %s on %s" % (AWAITING, HEAD))])
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(played), 2)

    def test_refuses_when_head_moved_after_verdict(self):
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % OLD)])
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])
        self.assertIn("current HEAD", out)

    def test_refuses_when_pipeline_is_not_on_head(self):
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD)], pipe_sha=OLD)
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])

    def test_refuses_on_red_or_running_non_mutation_job(self):
        for status in ("failed", "running", "pending", "manual", "canceled"):
            jobs = green_jobs()
            jobs[1] = job(2, "test", status)
            rc, out, played = run(jobs, [note("Verify: Charles SHIP %s" % HEAD)])
            self.assertEqual(rc, 3, (status, out))
            self.assertEqual(played, [])
            self.assertIn("job test is %s" % status, out)

    def test_refuses_on_failed_or_canceled_later_stage_job(self):
        ship = [note("Verify: Charles SHIP %s" % HEAD)]
        for status in ("failed", "canceled"):
            jobs = green_jobs()
            jobs[2] = job(3, "build", status, "build")
            rc, out, played = run(jobs, ship)
            self.assertEqual((rc, played), (3, []), (status, out))
            self.assertIn("job build is %s" % status, out)
        for status in ("created", "skipped"):  # not run yet: the control
            jobs = green_jobs()
            jobs[2] = job(3, "build", status, "build")
            rc, out, played = run(jobs, ship)
            self.assertEqual(rc, 0, (status, out))

    def test_refuses_unless_every_child_pipeline_succeeded(self):
        ship = [note("Verify: Charles SHIP %s" % HEAD)]
        for status in ("failed", "running", "pending", "canceled", "created", "manual"):
            bridges = [{"name": "full-tests", "downstream_pipeline": {"id": 8, "status": status}}]
            rc, out, played = run(green_jobs(), ship, bridges=bridges)
            self.assertEqual((rc, played), (3, []), (status, out))
            self.assertIn("bridge full-tests downstream is %s" % status, out)
        rc, out, played = run(green_jobs(), ship, bridges=[{"name": "full-tests", "downstream_pipeline": None}])
        self.assertEqual((rc, played), (3, []), out)
        self.assertIn("not started", out)
        rc, out, played = run(green_jobs(), ship, bridges=[])  # no child at all: nothing to wait for
        self.assertEqual(rc, 0, out)

    def test_post_review_trigger_waits_for_the_start_job(self):
        ship = [note("Verify: Charles SHIP %s" % HEAD)]
        waiting = {"name": "mutations", "stage": "post-review", "status": "created",
                   "pipeline": {"id": 7}, "downstream_pipeline": None}
        jobs = green_jobs()[:2] + [job(3, "build", "success", "build"),
                                   job(12, "start-mutations", "manual", "post-review")]
        rc, out, played = run(jobs, ship, bridges=green_bridges() + [waiting])
        self.assertEqual((rc, played), (0, ["projects/p/jobs/12/play"]), out)
        # Controls: the same exception for another trigger, another stage, a
        # started trigger or one whose child exists refuses.
        for change in ({"name": "full-tests"}, {"stage": "test"}, {"status": "running"},
                       {"status": "manual"}, {"downstream_pipeline": {"id": 9, "status": "running"}}):
            bridge = dict(waiting, **change)
            rc, out, played = run(jobs, ship, bridges=green_bridges() + [bridge])
            self.assertEqual((rc, played), (3, []), (change, out))

    def test_a_later_note_that_withdraws_the_verdict_refuses(self):
        ship = note("Verify: Charles SHIP %s" % HEAD, at="2026-10-15T01:00:00Z")
        for body in ("DO-NOT-SHIP %s %s" % (HEAD, CANARY), "SHIP withdrawn, see findings", "BLOCKED on a finding"):
            rc, out, played = run(green_jobs(), [ship, note(body, at="2026-10-15T02:00:00Z")])
            self.assertEqual((rc, played), (3, []), (body, out))
            self.assertIn("withdraws or blocks", out)
            self.assertNotIn(CANARY, out)
        # A plain later note does not revoke; an earlier withdrawal does not either.
        rc, out, played = run(green_jobs(), [ship, note("looking at the log now", at="2026-10-15T02:00:00Z")])
        self.assertEqual(rc, 0, out)
        rc, out, played = run(green_jobs(), [note("BLOCKED on a finding", at="2026-10-15T00:30:00Z"), ship])
        self.assertEqual(rc, 0, out)

    def test_refuses_do_not_ship(self):
        rc, out, played = run(green_jobs(), [note("Verify: Charles DO-NOT-SHIP %s %s" % (HEAD, CANARY))])
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])
        self.assertNotIn(CANARY, out)

    def test_latest_verdict_wins(self):
        notes = [note("Verify: Charles SHIP %s" % HEAD, at="2026-10-15T01:00:00Z"),
                 note("Verify: Charles DO-NOT-SHIP %s" % HEAD, at="2026-10-15T02:00:00Z")]
        rc, out, played = run(green_jobs(), notes)
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])

    def test_verdict_from_anyone_else_does_not_count(self):
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD, author="bender"),
                                             note("Verify: Charles SHIP %s" % HEAD, author="charles", system=True)])
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])

    def test_negated_or_foreign_verdicts_are_refused(self):
        for body in ["Verify: Charles NOT SHIP %s" % HEAD, "Verify: Charles DO NOT SHIP %s" % HEAD,
                     "Verify: Charles cannot SHIP %s" % HEAD, "Verify: Charles SHIP_IT %s" % HEAD,
                     "Verify: Charles SHIP %s (HEAD now %s)" % (OLD, HEAD),
                     "> Verify: Charles SHIP %s\n\nnope" % HEAD,
                     "Verify: Charles AC FAIL 3; AC PASS 1, \u043e\u0436\u0438\u0434\u0430\u0435\u0442 \u043c\u0443\u0442\u0430\u0446\u0438\u0438 %s" % HEAD]:
            rc, out, played = run(green_jobs(), [note(body)])
            self.assertEqual((rc, played), (3, []), body)

    def test_latest_verdict_is_compared_as_a_time_not_a_string(self):
        notes = [note("Verify: Charles SHIP %s" % HEAD, at="2026-10-15T01:00:00Z"),
                 note("Verify: Charles DO-NOT-SHIP %s" % HEAD, at="2026-10-15T00:30:00-05:00")]
        rc, out, played = run(green_jobs(), notes)
        self.assertEqual((rc, played), (3, []), out)

    def test_short_sha_is_not_a_verdict_on_head(self):
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD[:8])])
        self.assertEqual(rc, 3, out)

    def test_later_stage_jobs_do_not_block(self):
        jobs = green_jobs()
        jobs[2] = job(3, "build", "skipped", "build")
        rc, out, _ = run(jobs, [note("Verify: Charles SHIP %s" % HEAD)])
        self.assertEqual(rc, 0, out)

    def test_refuses_when_head_and_pipeline_change_between_requests(self):
        moved = {"sha": "c" * 40, "head_pipeline": {"id": 8, "sha": "c" * 40}}
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD)], later_mr={2: moved})
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])
        self.assertIn("changed", out)

    def test_refuses_when_head_changes_after_the_gate_before_play(self):
        moved = {"sha": "c" * 40, "head_pipeline": {"id": 8, "sha": "c" * 40}}
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD)], later_mr={3: moved})
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])

    def test_stops_the_batch_when_head_changes_after_the_first_play(self):
        # MR reads: 1 gate, 2 gate re-read, 3 before the first POST, 4 before the second.
        moved = {"sha": "c" * 40, "head_pipeline": {"id": 8, "sha": "c" * 40}}
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD)], later_mr={4: moved})
        self.assertEqual(rc, 3, out)
        self.assertEqual(len(played), 1, played)
        self.assertIn("batch stopped", out)

    def test_stable_head_plays_the_whole_batch(self):
        same = {"sha": HEAD, "head_pipeline": {"id": 7, "sha": HEAD}}
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD)], later_mr={3: same, 4: same})
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(played), 2, played)

    def test_refuses_jobs_of_another_pipeline(self):
        jobs = green_jobs()
        jobs[1]["pipeline"] = {"id": 6}
        rc, out, played = run(jobs, [note("Verify: Charles SHIP %s" % HEAD)])
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])
        self.assertIn("does not belong", out)

    def test_reviewer_cannot_be_replaced_through_the_environment(self):
        env = {"PLAY_VERDICT_AUTHOR": "bender", "PLAY_STAGES": "build"}
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD, author="bender")], extra_env=env)
        self.assertEqual(rc, 3, out)
        self.assertEqual(played, [])
        rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD)], extra_env=env)
        self.assertEqual(rc, 0, out)

    def test_mutation_jobs_start_in_waves_under_the_inflight_cap(self):
        jobs = green_jobs()[:2] + [job(3, "build", "success", "build")] + [job(20 + i, "m%d-mutations" % i, "manual") for i in range(7)]
        note_ = [note("Verify: Charles SHIP %s" % HEAD)]
        rc, out, played = run(jobs, note_, extra_env={"PLAY_MUTATIONS_MAX_INFLIGHT": "3"}, fake=WAVE_GLAB)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(played), 7, played)
        # inflight is sampled before each play, so the new job makes it cap at most.
        self.assertLessEqual(max(LAST_INFLIGHT) + 1, 3, LAST_INFLIGHT)
        self.assertGreaterEqual(max(LAST_INFLIGHT) + 1, 3, "cap never reached; the test would pass with no throttle")

    def test_default_cap_is_sixteen(self):
        jobs = green_jobs()[:2] + [job(3, "build", "success", "build")] + [job(20 + i, "m%d-mutations" % i, "manual") for i in range(20)]
        rc, out, played = run(jobs, [note("Verify: Charles SHIP %s" % HEAD)], fake=WAVE_GLAB)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(played), 20)
        self.assertEqual(max(LAST_INFLIGHT) + 1, 16, LAST_INFLIGHT)

    def test_job_that_turns_manual_after_the_first_round_is_still_played(self):
        late = dict(job(40, "late-mutations", "created", "post-review"), late=True)
        jobs = green_jobs()[:2] + [job(3, "build", "success", "build"), job(20, "a-mutations", "manual"), late]
        rc, out, played = run(jobs, [note("Verify: Charles SHIP %s" % HEAD)], fake=WAVE_GLAB)
        self.assertEqual(rc, 0, out)
        self.assertIn("projects/p/jobs/40/play", played)

    def test_cap_with_a_leading_zero_is_decimal(self):
        jobs = green_jobs()[:2] + [job(3, "build", "success", "build")] + [job(20 + i, "m%d-mutations" % i, "manual") for i in range(10)]
        for cap, want in (("03", 3), ("08", 8)):
            with self.subTest(cap=cap):
                LAST_INFLIGHT.clear()
                rc, out, played = run(jobs, [note("Verify: Charles SHIP %s" % HEAD)],
                                      extra_env={"PLAY_MUTATIONS_MAX_INFLIGHT": cap}, fake=WAVE_GLAB)
                self.assertEqual(rc, 0, out)
                self.assertEqual(len(played), 10, played)
                self.assertEqual(max(LAST_INFLIGHT) + 1, want, LAST_INFLIGHT)

    def test_cap_is_validated(self):
        for bad in ("0", "00", "x", "-1"):
            rc, out, played = run(green_jobs(), [note("Verify: Charles SHIP %s" % HEAD)],
                                  extra_env={"PLAY_MUTATIONS_MAX_INFLIGHT": bad})
            self.assertEqual(rc, 2, (bad, out))
            self.assertEqual(played, [])


class CurrentConfig(unittest.TestCase):
    """Merge request pipelines carry no mutation job, so the script has nothing
    to start on one, even with a SHIP verdict on HEAD and everything green."""

    def test_nothing_to_play_on_a_merge_request_pipeline(self):
        module, config = ci_config()
        jobs = mr_pipeline(module, config)
        self.assertGreater(len(jobs), 5, jobs)
        rc, out, played = run(jobs, [note("Verify: Charles SHIP %s" % HEAD)])
        self.assertEqual(rc, 0, out)
        self.assertEqual(played, [])
        self.assertIn("no manual mutation jobs", out)

    def test_a_mutation_job_back_on_merge_requests_would_be_played(self):
        # Broken control: the same harness notices a mutation job that returns.
        module, config = ci_config()
        config = copy.deepcopy(config)
        config["sealer-mutations"]["rules"] = [{"if": module.MR_IF, "when": "manual"}]
        jobs = mr_pipeline(module, config)
        rc, out, played = run(jobs, [note("Verify: Charles SHIP %s" % HEAD)])
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(played), 1, played)


if __name__ == "__main__":
    unittest.main()
