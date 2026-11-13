#!/usr/bin/env python3
"""scripts/check-mr-mutation-gate.py: a merge request's mutation proof is the
child pipeline of `mutations-mr`; every way it can be absent, stale or partial
must refuse, and only the complete, current one passes."""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check-mr-mutation-gate.py"
spec = importlib.util.spec_from_file_location("gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

HEAD, OLD = "a" * 40, "b" * 40
MR = {"sha": HEAD}
BRIDGES = [{"name": "full-tests", "status": "success"},
           {"name": "mutations-mr", "status": "success",
            "downstream_pipeline": {"id": 9, "sha": HEAD, "status": "success"}}]
GENERATED = {"workflow": {}, "stages": ["post-review"], ".tpl": {"script": ["true"]},
             "sealer-mutations": {"stage": "post-review", "script": ["x"]},
             "tenancy-mutations": {"stage": "post-review", "script": ["x"], "parallel": 2}}
CHILD = [{"name": "sealer-mutations", "status": "success", "allow_failure": False},
         {"name": "tenancy-mutations 1/2", "status": "success", "allow_failure": False},
         {"name": "tenancy-mutations 2/2", "status": "success", "allow_failure": False}]


def run(mr=MR, bridges=BRIDGES, child=CHILD, generated=GENERATED):
    return gate.reasons(mr, copy.deepcopy(bridges), copy.deepcopy(child), copy.deepcopy(generated))


class GateTest(unittest.TestCase):
    def test_complete_current_child_passes(self):
        self.assertEqual(run(), [])

    def refused(self, needle, **kw):
        why = run(**kw)
        self.assertTrue(any(needle in w for w in why), (needle, why))

    def test_missing_bridge_is_a_failure_not_a_pass(self):
        self.refused("no mutations-mr bridge", bridges=[BRIDGES[0]])
        self.refused("no mutations-mr bridge", bridges=[])

    def test_child_of_another_commit_blocks(self):
        b = copy.deepcopy(BRIDGES)
        b[1]["downstream_pipeline"]["sha"] = OLD
        self.refused("not on the MR head", bridges=b)

    def test_missing_selected_job_blocks(self):
        self.refused("sealer-mutations is missing", child=CHILD[1:])

    def test_missing_shard_blocks(self):
        self.refused("1 of 2 shards", child=CHILD[:2])

    def test_red_or_soft_selected_job_blocks(self):
        for field, value, needle in (("status", "failed", "not success"), ("status", "manual", "not success"),
                                     ("status", "skipped", "not success"), ("allow_failure", True, "allowed to fail")):
            child = copy.deepcopy(CHILD)
            child[0][field] = value
            self.refused(needle, child=child)

    def test_bridge_never_started_blocks(self):
        """Before start-mutations is played the bridge exists but has no child: not a pass."""
        for status in ("created", "manual", "skipped"):
            b = copy.deepcopy(BRIDGES)
            b[1] = {"name": "mutations-mr", "status": status, "downstream_pipeline": None}
            self.refused("bridge mutations-mr is %s" % status, bridges=b)
            self.refused("has no child pipeline", bridges=b)

    def test_unfinished_child_or_bridge_blocks(self):
        b = copy.deepcopy(BRIDGES)
        b[1]["status"] = "running"
        b[1]["downstream_pipeline"]["status"] = "running"
        self.refused("bridge mutations-mr is running", bridges=b)
        self.refused("child pipeline 9 is running", bridges=b)

    def test_unreadable_selection_blocks(self):
        self.refused("unreadable", generated=None)
        self.refused("selects no job", generated={"workflow": {}})

    def test_placeholder_needs_its_job(self):
        gen = {"workflow": {}, "no-mutations": {"stage": "post-review"}}
        self.assertEqual(run(generated=gen, child=[{"name": "no-mutations", "status": "success"}]), [])
        self.refused("placeholder", generated=gen, child=[])

    def test_bad_mr_head_blocks(self):
        self.assertEqual(run(mr={"sha": "nope"}), ["the MR names no head commit"])
        self.assertEqual(run(mr={}), ["the MR names no head commit"])

    def test_duplicate_bridges_and_bridge_without_child_block(self):
        self.assertEqual(run(bridges=[BRIDGES[1], BRIDGES[1]]), ["2 mutations-mr bridges in the head pipeline"])
        b = copy.deepcopy(BRIDGES)
        b[1].pop("downstream_pipeline")
        self.refused("has no child pipeline", bridges=b)

    def test_non_integer_parallel_blocks(self):
        for value in ("2", {"matrix": []}, True):
            gen = copy.deepcopy(GENERATED)
            gen["tenancy-mutations"]["parallel"] = value
            self.refused("not a plain count", generated=gen)

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for name, data in (("mr", MR), ("bridges", BRIDGES), ("child", CHILD)):
                (d / f"{name}.json").write_text(json.dumps(data))
            (d / "gen.yml").write_text(yaml.dump(GENERATED))
            args = [sys.executable, str(SCRIPT), "--files", *(str(d / n) for n in ("mr.json", "bridges.json", "child.json", "gen.yml"))]
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
            (d / "child.json").write_text(json.dumps(CHILD[1:]))
            r = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(r.returncode, 3)
            self.assertIn("sealer-mutations is missing", r.stderr)
            (d / "child.json").write_text("not json")
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)

    # --ci: the same verdict from the job's own API facts, fail closed on anything unreadable.
    ENV = {"CI_API_V4_URL": "https://gl.example/api/v4", "CI_PROJECT_ID": "7", "CI_PIPELINE_ID": "5",
           "CI_JOB_TOKEN": "tok-not-printed", "CI_COMMIT_SHA": HEAD, "CI_PIPELINE_SOURCE": "merge_request_event"}

    def fake_get(self, bridges=BRIDGES, child=CHILD, fail=None, pages=1):
        seen = []

        def get(url, token):
            seen.append((url, token))
            if fail and fail in url:
                raise OSError("boom")
            data = bridges if "/bridges" in url else child
            page = int(url.rsplit("page=", 1)[1])
            part = data[page - 1::pages] if pages > 1 else data
            return json.dumps(part), (str(page + 1) if page < pages else None)
        return get, seen

    def ci(self, env=None, **kw):
        get, seen = self.fake_get(**kw)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "gen.yml").write_text(yaml.dump(GENERATED))
            facts = gate.ci_facts(env or self.ENV, str(Path(d) / "gen.yml"), get)
        return gate.reasons(*facts), seen

    def test_ci_complete_child_passes_and_reads_every_page(self):
        why, seen = self.ci(pages=2)
        self.assertEqual(why, [])
        self.assertTrue(any("page=2" in u for u, _ in seen), seen)
        self.assertTrue(all(t == "tok-not-printed" for _, t in seen))

    def test_ci_missing_job_on_second_page_blocks(self):
        why, _ = self.ci(child=CHILD[:2], pages=2)
        self.assertTrue(any("shards exist" in w for w in why), why)

    def test_ci_api_failure_or_wrong_source_is_not_a_pass(self):
        for fail in ("/bridges", "/jobs"):
            get, _ = self.fake_get(fail=fail)
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "gen.yml").write_text(yaml.dump(GENERATED))
                with self.assertRaises(OSError):
                    gate.ci_facts(self.ENV, str(Path(d) / "gen.yml"), get)
        with self.assertRaises(RuntimeError):
            self.ci(env=self.ENV | {"CI_PIPELINE_SOURCE": "push"})

    def test_ci_non_list_api_answer_is_not_a_pass(self):
        for body in ('{"message": "401 Unauthorized"}', "null", '"x"'):
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "gen.yml").write_text(yaml.dump(GENERATED))
                with self.assertRaises(ValueError):
                    gate.ci_facts(self.ENV, str(Path(d) / "gen.yml"), lambda url, token, b=body: (b, None))

    def test_ci_cli_missing_environment_exits_2_without_printing_token(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "gen.yml").write_text(yaml.dump(GENERATED))
            env = {"PATH": "/usr/bin:/bin", "CI_JOB_TOKEN": "tok-not-printed"}
            r = subprocess.run([sys.executable, str(SCRIPT), "--ci", str(Path(d) / "gen.yml")],
                               capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertNotIn("tok-not-printed", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
