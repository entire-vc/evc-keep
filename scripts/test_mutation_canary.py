#!/usr/bin/env python3
"""Binding/command tests; fixture observations are not native acceptance."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("canary", ROOT / "scripts/mutation-canary.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


# Jobs whose apk line gains nodejs relative to the base (see test_internal_api_jobs_install_node).
NODE_JOBS = {
    "runner-enroll-mutations", "mesh-ui-mutations", "public-hygiene-mutations",
    "builtin-mutations", "approvals-mutations", "deploy-api-mutations", "mesh-mutations",
    "meshgate-mutations", "mesh-hierarchy-mutations", "dispatch-mutations",
    "carrier-verify-mutations",
}


class GuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        (cls.root / "scripts").mkdir()
        for name in ("mutation-select.py", "mutation-select.map"):
            shutil.copyfile(ROOT / "scripts" / name, cls.root / "scripts" / name)
        for f in (ROOT / "scripts").glob("*mutations.sh"):
            shutil.copyfile(f, cls.root / "scripts" / f.name)
        (cls.root / "internal/carriers").mkdir(parents=True)
        leaf = cls.root / "internal/carriers/repo.go"
        leaf.write_text("package carriers\n")
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=cls.root, stderr=subprocess.DEVNULL).decode().strip()
        git("init", "-q")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "base")
        cls.base = git("rev-parse", "HEAD")
        leaf.write_text("package carriers\n// leaf change\n")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "leaf")
        cls.head = git("rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.root_patch = patch.object(c, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.artifact_patch = patch.object(c, "ARTIFACT", self.root / "mutation-canary.json")
        self.artifact_patch.start()
        self.addCleanup(self.artifact_patch.stop)
        ms = c.selector()
        mapping = ms.Map((self.root / "scripts/mutation-select.map").read_text())
        # Real map and real select(), with a deliberately small graph fixture.
        packages = {r.removesuffix("/..."): {"dir": r.removesuffix("/..."), "imports": [], "tests": []}
                    for v in mapping.scripts.values() for r in v["roots"]}
        packages["internal/carriers"] = {"dir": "internal/carriers", "imports": [], "tests": []}
        selected, skipped = ms.select(["internal/carriers/repo.go"], packages, mapping)
        p = ms.provenance(self.base, self.head, self.root / "scripts/mutation-select.map")
        source = p["working_tracked_sha256"]
        graph = {"status": "observed", "packages": packages, "sha256": c.canonical(packages),
                 "listing": {"status": "observed", "exit_code": 0, "source_binding_status": "observed-stable",
                 "source_before_sha256": source, "source_after_sha256": source,
                 "argv": ["go", "list", "-json", "./..."], "version": "go version go1.25.14 linux/amd64",
                 "binary_sha256": "a" * 64,
                 "target": {"GOOS": "linux", "GOARCH": "amd64", "GOFLAGS": "-buildvcs=false", "CGO_ENABLED": "0"}}}
        self.report = {"mode": "graph", "all": False, "changed": ["internal/carriers/repo.go"],
                       "selected": selected, "skipped": skipped, "provenance": p, "graph": graph}
        self.d = {"schema": "keep-tenancy-canary-v1", "project_id": 70, "mr_iid": 999,
                  "head": self.head, "base": self.base, "merge_base": p["merge_base"],
                  "source_tree": p["source_tree"], "working_tracked_sha256": source,
                  "map_sha256": p["map_sha256"], "selector_sha256": p["selector_sha256"],
                  "mutation_inventory_sha256": p["mutation_inventory_sha256"],
                  "graph_sha256": graph["sha256"], "go_binary_sha256": "a" * 64,
                  "go_version": graph["listing"]["version"], "omitted_jobs": ["tenancy-mutations"],
                  "full_reference": {"sha": self.head, "pipeline_id": 100, "status": "success"}}
        self.context = {"KEEP_MUTATION_CANARY": json.dumps(self.d), "CI_PIPELINE_SOURCE": "merge_request_event",
                        "CI_PROJECT_ID": "70", "CI_MERGE_REQUEST_IID": "999", "CI_PIPELINE_ID": "101",
                        "CI_MERGE_REQUEST_EVENT_TYPE": "detached", "CI_DEFAULT_BRANCH": "main",
                        "CI_COMMIT_SHA": self.head, "CI_MERGE_REQUEST_DIFF_BASE_SHA": self.base,
                        "CI_JOB_NAME": "tenancy-mutations 1/2", "CI_NODE_TOTAL": "2", "CI_NODE_INDEX": "1"}


    def eligible(self, context):
        try:
            c.validate(c.descriptor(context), self.report, context)
            return True
        except Exception:
            return False

    def shell(self, line, context=None, missing_cmp=False):
        import yaml
        block = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())["tenancy-mutations"]["script"][0]
        artifact = self.root / "mutation-canary.decision"
        if line is None:
            artifact.unlink(missing_ok=True)
        else:
            artifact.write_text(line)
        tools = self.root / "test-bin"
        tools.mkdir(exist_ok=True)
        fake = tools / "timeout"
        fake.write_text("#!/bin/sh\nprintf '%s\\n' \"$MUTATION_SHARD_INDEX/$MUTATION_SHARD_TOTAL $*\" > \"$FAKE_TRACE\"\nexit 7\n")
        fake.chmod(0o755)
        trace = self.root / "command.trace"
        trace.unlink(missing_ok=True)
        # The runner's own pipeline variables (schedule: CI_COMMIT_BRANCH=main)
        # must not decide what the shell block under test sees.
        base_env = {k: v for k, v in os.environ.items() if k not in ("KEEP_FULL_CI", "CI_COMMIT_BRANCH")}
        run_env = dict(base_env, CI_COMMIT_BRANCH="fixture-branch")
        run_env.update(context or self.context)
        run_env.update(PATH=str(tools) + ("" if missing_cmp else os.pathsep + os.environ["PATH"]), FAKE_TRACE=str(trace))
        result = subprocess.run(["/bin/sh", "-eu", "-c", block], cwd=self.root, env=run_env, capture_output=True, text=True)
        return result, trace.read_text() if trace.exists() else None

    def line(self):
        return f"KEEP_TENANCY_CANARY_V1 OMIT 101 {self.head} 999 tenancy-mutations\n"

    def test_actual_map_selector_and_shell_omit_complete_body_on_all_four_shards(self):
        self.assertTrue(self.eligible(self.context))
        for index in range(1, 3):
            context = dict(self.context, CI_NODE_INDEX=str(index), CI_JOB_NAME=f"tenancy-mutations {index}/2")
            result, trace = self.shell(self.line(), context)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(trace)
            self.assertIn("no tenancy tests executed", result.stdout)

    def test_context_negative_guards_run_original_body(self):
        cases = {"KEEP_MUTATION_CANARY": "", "CI_PROJECT_ID": "71", "CI_MERGE_REQUEST_IID": "998",
                 "CI_PIPELINE_SOURCE": "schedule", "CI_MERGE_REQUEST_EVENT_TYPE": "merged_result",
                 "CI_COMMIT_BRANCH": "main", "KEEP_FULL_CI": "1", "CI_COMMIT_SHA": "0" * 40,
                 "CI_MERGE_REQUEST_DIFF_BASE_SHA": "0" * 40, "CI_PIPELINE_ID": "100"}
        for key, value in cases.items():
            with self.subTest(key=key):
                context = dict(self.context, **{key: value})
                self.assertFalse(self.eligible(context))

    def test_wrong_descriptor_and_security_or_mixed_job_requests_fall_back(self):
        for key in ("head", "base", "merge_base", "source_tree", "working_tracked_sha256", "map_sha256",
                    "selector_sha256", "mutation_inventory_sha256", "graph_sha256", "go_binary_sha256"):
            with self.subTest(key=key):
                d = dict(self.d, **{key: "0" * len(self.d[key])})
                self.assertFalse(self.eligible(dict(self.context, KEEP_MUTATION_CANARY=json.dumps(d))))
        for jobs in (["sealer-mutations"], ["builtin-mutations"], ["intake-browser"], ["tenancy-mutations", "carriers-mutations"]):
            d = dict(self.d, omitted_jobs=jobs)
            self.assertFalse(self.eligible(dict(self.context, KEEP_MUTATION_CANARY=json.dumps(d))))

    def test_corrupt_missing_unknown_all_selected_and_shared_reports_fall_back(self):
        modifications = [lambda r: r.update(mode="all", all=True),
                         lambda r: r["graph"].update(status="unknown"),
                         lambda r: r["graph"]["listing"].update(status="error"),
                         lambda r: r["graph"]["listing"].update(source_binding_status="unknown"),
                         lambda r: r["graph"]["listing"]["target"].update(CGO_ENABLED=None),
                         lambda r: r["provenance"].update(input_mode="explicit-files"),
                         lambda r: r.update(changed=[".gitlab-ci.yml"]),
                         lambda r: r["selected"].append({"script": "tenancy", "always": False}),
                         lambda r: r["graph"]["packages"].clear()]
        original = copy.deepcopy(self.report)
        for modify in modifications:
            self.report = copy.deepcopy(original)
            modify(self.report)

            self.assertFalse(self.eligible(self.context))
    def test_source_drift_and_reference_not_exact_cannot_omit(self):
        leaf = self.root / "internal/carriers/repo.go"
        original = leaf.read_bytes()
        try:
            leaf.write_bytes(original + b"// dirty\n")
            self.assertFalse(self.eligible(self.context))
        finally:
            leaf.write_bytes(original)
        for reference in ({"sha": "0" * 40, "pipeline_id": 100, "status": "success"},
                          {"sha": self.head, "pipeline_id": 101, "status": "success"},
                          {"sha": self.head, "pipeline_id": 100, "status": "failed"}):
            d = dict(self.d, full_reference=reference)
            self.assertFalse(self.eligible(dict(self.context, KEEP_MUTATION_CANARY=json.dumps(d))))

    def test_default_prepare_does_not_invoke_go_and_writes_all(self):
        with patch.object(c.subprocess, "run") as invoked:
            c.prepare({})
            invoked.assert_not_called()
        self.assertEqual(c.ARTIFACT.read_text(), "ALL\n")

    def test_prepare_writes_exact_line_only_after_full_validation(self):
        real_run = subprocess.run
        def observed(command, **kwargs):
            if command[0] == sys.executable:
                self.assertIn(self.head, command)
                # Execute the real selector report/CLI and provenance functions;
                # only the Go listing is a documented fixture observation.
                module = c.selector()
                graph = module.Graph(self.report["graph"]["packages"])
                graph.observation = self.report["graph"]["listing"]
                with patch.object(module, "load_graph", return_value=graph):
                    module.main(command[2:])
                return subprocess.CompletedProcess(command, 0)
            return real_run(command, **kwargs)
        with patch.object(c.subprocess, "run", side_effect=observed):
            c.prepare(self.context)
        self.assertEqual(c.ARTIFACT.read_text(), self.line())
        for index in range(1, 3):
            result, trace = self.shell(c.ARTIFACT.read_text(), dict(self.context,
                CI_NODE_INDEX=str(index), CI_JOB_NAME=f"tenancy-mutations {index}/2"))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(trace)

    def test_missing_corrupt_extra_lines_and_wrong_context_run_original_command(self):
        for line in (None, "ALL\n", "", self.line() + "\n", self.line() + self.line(),
                     self.line().rstrip(), self.line().replace("101", "102"),
                     self.line().replace(self.head, "0" * 40), self.line().replace("999", "998"),
                     self.line().replace("tenancy-mutations", "sealer-mutations"),
                     "$(touch injected)\n"):
            result, trace = self.shell(line)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(trace.strip(), "1/2 -k 10s 19m ./scripts/check-tenancy-mutations.sh")
            self.assertFalse((self.root / "injected").exists())
        for key, value in {"KEEP_MUTATION_CANARY": "", "CI_PIPELINE_SOURCE": "schedule",
                           "CI_JOB_NAME": "builtin-mutations", "CI_NODE_TOTAL": "3", "CI_NODE_INDEX": "5",
                           "CI_COMMIT_BRANCH": "main", "KEEP_FULL_CI": "1"}.items():
            result, trace = self.shell(self.line(), dict(self.context, **{key: value}))
            self.assertEqual(result.returncode, 7)
            self.assertIsNotNone(trace)
        result, trace = self.shell(self.line(), missing_cmp=True)
        self.assertEqual(result.returncode, 7)
        self.assertIsNotNone(trace)

    def test_prepare_selector_failure_is_all(self):
        for failure in (OSError(), subprocess.TimeoutExpired("selector", 90)):
            with patch.object(c.subprocess, "run", side_effect=failure):
                c.prepare(self.context)
            self.assertEqual(c.ARTIFACT.read_text(), "ALL\n")

    def test_default_full_and_every_other_gate_config_preserved(self):
        import yaml
        # Compare the merge base with the default branch, never candidate HEAD
        # itself: every job except the two the canary edits must be unchanged.
        base = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA") or subprocess.check_output(
            ["git", "merge-base", "HEAD", "origin/main"], cwd=ROOT).decode().strip()
        previous = yaml.safe_load(subprocess.check_output(["git", "show",
            f"{base}:.gitlab-ci.yml"], cwd=ROOT))
        current = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())
        if current == previous:
            # No change to the pipeline config against the base (a push to the
            # default branch, or an MR that does not touch it): the edits this
            # test expects are already in the base, so there is no diff to guard.
            self.skipTest("pipeline config equals its merge base; nothing to compare")
        # The mutation batch (test_ci_config.py pins it): a job may open its
        # rules with the batch's `when: never`, and the workflow may carry the
        # batch rule and the pipeline name, each exactly as below. The base may
        # already carry them (main does): then both sides drop them.
        batch_never = {"if": '$KEEP_MUTATION_BATCH == "true"', "when": "never"}
        batch_rule = {"if": '$KEEP_MUTATION_BATCH == "true" && $CI_COMMIT_BRANCH',
                      "variables": {"KEEP_PIPELINE_NAME": "mutation-batch"},
                      "auto_cancel": {"on_new_commit": "none"}}
        self.assertEqual(current["workflow"].get("name"), "$KEEP_PIPELINE_NAME")
        self.assertEqual(current["workflow"]["rules"].count(batch_rule), 1)
        for cfg in (current, previous):
            for key, job in list(cfg.items()):
                if not isinstance(job, dict):
                    continue
                if key == "workflow":
                    # A new dict and list: the YAML anchors share the old ones.
                    cfg[key] = {k: v for k, v in job.items() if k != "name"}
                    cfg[key]["rules"] = [r for r in job.get("rules", []) if r != batch_rule]
                elif isinstance(job.get("rules"), list) and job["rules"][:1] == [batch_never]:
                    cfg[key] = dict(job, rules=job["rules"][1:])
        # Jobs may move to or from the dedicated mutation runner tag; that tag
        # is the only difference allowed on them (test_ci_config.py pins which).
        for key, job in list(current.items()):
            prev = previous.get(key)
            if not (isinstance(job, dict) and isinstance(prev, dict)):
                continue
            if job.get("tags") == ["keep-mutations"] and "tags" not in prev:
                current[key] = {k: v for k, v in job.items() if k != "tags"}
            elif prev.get("tags") == ["keep-mutations"] and "tags" not in job:
                previous[key] = {k: v for k, v in prev.items() if k != "tags"}
        # A post-review job may gain `dependencies: []` (no earlier artifact,
        # above all not the hour-long image tar; test_ci_config.py pins it).
        for key, job in list(current.items()):
            prev = previous.get(key)
            if (isinstance(job, dict) and isinstance(prev, dict) and job.get("stage") == "post-review"
                    and job.get("dependencies") == [] and "dependencies" not in prev):
                current[key] = {k: v for k, v in job.items() if k != "dependencies"}
        # A postgres service may gain or lose its start-up `command` (the
        # fsync=off flags, pinned by check-ci-postgres-fsync.sh); nothing else
        # about a service is allowed to differ.
        service_commands = {key: [sv.get("command") for sv in job.get("services", []) if isinstance(sv, dict)]
                            for key, job in current.items() if isinstance(job, dict)}
        for cfg in (current, previous):
            for job in cfg.values():
                if isinstance(job, dict):
                    job["services"] = [
                        {k: v for k, v in svc.items() if k != "command"}
                        if isinstance(svc, dict) and str(svc.get("name", "")).startswith("postgres:") else svc
                        for svc in job.get("services", [])] or job.get("services")
                    if job["services"] is None:
                        del job["services"]
        # The heavy shared-pool jobs may join their fan-out-cap resource group;
        # that key, with exactly this value, is the only difference allowed on
        # them (test_ci_config.py pins the groups).
        for key, group in {"w3-stubs": "keep-w3-stubs", "mesh-rotation-e2e": "keep-mesh-rotation-e2e",
                           "targets-loaders": "keep-targets-loaders", "e2e-w2": "keep-e2e-w2"}.items():
            self.assertEqual(current[key].get("resource_group"), group, key)
            current[key] = {k: v for k, v in current[key].items() if k != "resource_group"}
            previous[key] = {k: v for k, v in previous[key].items() if k != "resource_group"}
        # e2e-w2 also carries the apt diagnostics: DEBIAN_FRONTEND and a bounded
        # `apt-get install` that dumps `ps -ef` and the apt term.log on a hang
        # replace the plain install line. Everything else equals the base.
        e2e, e2e_prev = current["e2e-w2"], previous["e2e-w2"]
        self.assertEqual(e2e["variables"].get("DEBIAN_FRONTEND"), "noninteractive")
        install = e2e["before_script"][0]
        for needle in ("apt-get update", "timeout 300 apt-get install -y --no-install-recommends "
                       "chromium curl ca-certificates xz-utils", "ps -ef", "/var/log/apt/term.log", "exit 1"):
            self.assertIn(needle, install, needle)
        self.assertEqual(e2e["before_script"][1:], e2e_prev["before_script"][1:], "e2e-w2 before_script")
        current["e2e-w2"] = {k: v for k, v in e2e.items() if k not in ("variables", "before_script")}
        previous["e2e-w2"] = {k: v for k, v in e2e_prev.items() if k not in ("variables", "before_script")}
        # The base may already carry DEBIAN_FRONTEND (shared-pool cap commit).
        self.assertEqual({k: v for k, v in e2e["variables"].items() if k != "DEBIAN_FRONTEND"},
                         {k: v for k, v in e2e_prev["variables"].items() if k != "DEBIAN_FRONTEND"},
                         "e2e-w2 variables")
        def rules_only_gain_paths(job, prev, key):
            # A merge-request rule may only gain `changes` paths, never lose
            # one: more triggers, the same gate.
            rules, prev_rules = job.pop("rules", []), prev.pop("rules", [])
            self.assertEqual(len(rules), len(prev_rules), key)
            for rule, prev_rule in zip(rules, prev_rules):
                rule, prev_rule = dict(rule), dict(prev_rule)
                paths, prev_paths = rule.pop("changes", []), prev_rule.pop("changes", [])
                self.assertEqual(rule, prev_rule, key)
                self.assertTrue(set(prev_paths) <= set(paths), key)

        # The mesh plugin's mutation script moved out of mesh-plugin into the
        # sharded mesh-plugin-mutations (pinned by test_ci_config.py): dropping
        # that one line is the only script change allowed on mesh-plugin.
        mesh_mutations = "./scripts/check-mesh-plugin-mutations.sh"
        self.assertFalse([l for l in current["mesh-plugin"]["script"] if mesh_mutations in l])
        self.assertTrue([l for l in current["mesh-plugin-mutations"]["script"] if mesh_mutations in l])
        previous["mesh-plugin"] = dict(previous["mesh-plugin"])
        previous["mesh-plugin"]["script"] = [
            l for l in previous["mesh-plugin"]["script"] if mesh_mutations not in l]

        def same(name, skip_keys=()):
            self.assertEqual({k: v for k, v in current[name].items() if k not in skip_keys},
                             {k: v for k, v in previous[name].items() if k not in skip_keys}, name)

        def node_apk_only(name):
            before, base_before = current[name]["before_script"], previous[name]["before_script"]
            self.assertEqual(len(before), len(base_before), name)
            for line, base_line in zip(before, base_before):
                if base_line.startswith("apk add ") and "nodejs" not in base_line.split():
                    self.assertIn(line, (base_line, base_line + " nodejs"), name)
                else:
                    self.assertEqual(line, base_line, name)

        # The light security and lint gates may move between the shared runner,
        # the fast lane and the burst pool; that tag is the only difference
        # allowed on them.
        pools = (None, ["ci-fast"], ["ci-burst"], ["docker", "ci-burst"])
        fast_lane = {"secret-scan-scope-selftest", "security-hygiene",
                     "golangci-lint", "ci-selftests"}
        directives = "./scripts/check-lint-directives.sh"
        for key in previous:
            if key == "import-boundaries":
                # Sharded (`parallel`) with path-filtered MR rules, both pinned by
                # test_ci_config.py; the whole-tree directive gate moved to fmt-vet.
                # Invariant, independent of the base: everything else as in the base.
                job = dict(current[key])
                self.assertIn(job.pop("tags", None), pools, key)
                self.assertGreaterEqual(job.pop("parallel", 1), 2, key)
                prev = {k: v for k, v in previous[key].items() if k not in ("tags", "parallel")}
                self.assertEqual([l for l in job.pop("script") if l != directives],
                                 [l for l in prev.pop("script") if l != directives], key)
                self.assertNotIn(directives, current[key]["script"])
                self.assertIn(directives, current["fmt-vet"]["script"])
                self.assertEqual({k: v for k, v in job.items() if k != "rules"},
                                 {k: v for k, v in prev.items() if k != "rules"}, key)
            elif key in {"mesh-plugin", "mesh-rotation-e2e", "e2e-w2"}:
                # Merge request gates: no tag or the docker+burst runners, never the
                # dedicated mutation runner; every other field equals the base,
                # except that the mutation script line moved into <key>-mutations.
                job = dict(current[key])
                moved = {"mesh-plugin": 'cd "$CI_PROJECT_DIR" && ./scripts/check-mesh-plugin-mutations.sh',
                         "mesh-rotation-e2e": 'cd "$CI_PROJECT_DIR" && ./scripts/check-mesh-rotation-e2e-mutations.sh'}
                if key in moved:
                    self.assertNotIn(moved[key], job["script"], key)
                    self.assertIn(moved[key].split("&& ./")[1], " ".join(current[key + "-mutations"]["script"]), key)
                    previous[key] = dict(previous[key], script=[l for l in previous[key]["script"] if l != moved[key]])
                self.assertIn(job.pop("tags", None), (None, ["docker", "ci-burst"]), key)
                prev = {k: v for k, v in previous[key].items() if k != "tags"}
                rules_only_gain_paths(job, prev, key)
                self.assertEqual(job, prev, key)
            elif key in fast_lane:
                job = dict(current[key])
                self.assertIn(job.pop("tags", None), pools, key)
                # The fsync guard moved from ci-selftests to fmt-vet (pinned by
                # test_ci_config.py); the script is otherwise as in the base.
                guard = "sh scripts/check-ci-postgres-fsync.sh"
                prev = {k: v for k, v in previous[key].items() if k != "tags"}
                if "script" in job:
                    job["script"] = [l for l in job["script"] if l != guard]
                    prev["script"] = [l for l in prev["script"] if l != guard]
                if key == "ci-selftests":
                    # The selector's tests joined it from mutation-select-test,
                    # with the packages they need (pinned by test_ci_config.py).
                    added = ["python3 scripts/test_mutation_select.py", "./scripts/check-mutation-select-redrun.sh"]
                    self.assertEqual(job["script"][-2:], added)
                    job["script"] = [l for l in job["script"] if l not in added]
                    prev["script"] = [l for l in prev["script"] if l not in added]
                    strip = lambda lines: [l.replace(" perl tar", "") for l in lines]
                    job["before_script"], prev["before_script"] = strip(job["before_script"]), strip(prev["before_script"])
                    # Its rules list the sources the selftests copy; that list may grow.
                    rules_only_gain_paths(job, prev, key)
                self.assertEqual(job, prev, key)
            elif key in {"fmt-vet", "tenancy-mutations"}:
                continue
            elif key == "workflow":
                # The only allowed difference: per-rule auto_cancel, pinned exactly.
                job = copy.deepcopy(current[key])
                # Release tags run the full set (pinned by test_ci_config.py):
                # the one rule the workflow may gain over the base.
                tag_rule = {"if": "$CI_COMMIT_TAG", "auto_cancel": {"on_new_commit": "none"}}
                # The base may already carry it (main does): then both sides drop it.
                self.assertEqual(job["rules"].count(tag_rule), 1)
                job["rules"].remove(tag_rule)
                expected = {
                    '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH': {"on_new_commit": "none"},
                    '$CI_PIPELINE_SOURCE == "schedule"': {"on_new_commit": "none"},
                    '$CI_PIPELINE_SOURCE == "merge_request_event"': {"on_new_commit": "interruptible"},
                }
                seen = set()
                for rule in job["rules"]:
                    if rule.get("if") in expected:
                        self.assertEqual(rule.pop("auto_cancel"), expected[rule["if"]], rule["if"])
                        seen.add(rule["if"])
                self.assertEqual(seen, set(expected))
                job.pop("auto_cancel", None)
                previous_job = copy.deepcopy(previous[key])
                previous_job.pop("auto_cancel", None)
                if tag_rule in previous_job["rules"]:
                    previous_job["rules"].remove(tag_rule)
                for rule in previous_job["rules"]:
                    rule.pop("auto_cancel", None)
                self.assertEqual(job, previous_job, key)
            elif key == "stages":
                # Mutation jobs live in post-review, followed only by the tag's
                # release stage; test_ci_config.py pins the list. Invariant,
                # independent of the base: both once, in that order, at the end.
                self.assertEqual(current[key].count("post-review"), 1)
                self.assertEqual(current[key][-2:], ["post-review", "release"])
                self.assertEqual(current[key][:-2], [s for s in previous[key] if s not in ("post-review", "release")])
            elif key in {"mutation-select", "start-mutations", "mutations", "mutation-select-test"}:
                # No mutation job on a merge request: the selector, its gate and
                # the child trigger are gone (test_ci_config.py refuses them),
                # and the selector's own tests moved into ci-selftests.
                self.assertNotIn(key, current)
            elif key in {"golangci-lint", "import-boundaries"}:
                # Invariant, independent of the base: the module cache template
                # and one leading `go mod download`; everything else as in the base.
                same(key, skip_keys={"extends", "script"})
                self.assertEqual(current[key]["extends"], ".golangci-module-cache", key)
                self.assertEqual(current[key]["script"].count("go mod download"), 1, key)
                self.assertEqual(current[key]["script"][0], "go mod download", key)
                self.assertEqual([l for l in current[key]["script"] if l != "go mod download"],
                                 [l for l in previous[key]["script"] if l != "go mod download"], key)
            elif key == "netns-tests":
                # Only the mutation run moved out, into netns-mutation-run (not
                # on a main push); the netns tests themselves are unchanged.
                same(key, skip_keys={"script"})
                mutation_line = "timeout -k 10s 18m ./scripts/check-netns-mutations.sh"
                self.assertEqual(current[key]["script"],
                                 [l for l in previous[key]["script"] if l != mutation_line])
                self.assertEqual(current["netns-mutation-run"]["script"], [mutation_line])
            elif key == "identity-attack-mutations":
                # Invariant, independent of the base: before_script carries
                # exactly one private GOCACHE export, ahead of `migrate up`,
                # and every other line equals the base's (export removed).
                same(key, skip_keys={"rules", "before_script", "resource_group"})
                export = 'export GOCACHE="$(mktemp -d /tmp/keep-gocache.XXXXXXXX)"'
                before = current[key]["before_script"]
                self.assertEqual(before.count(export), 1)
                self.assertLess(before.index(export),
                                before.index("go run ./cmd/keep-server migrate up"))
                self.assertEqual([l for l in before if l != export],
                                 [l for l in previous[key]["before_script"] if l != export])
            elif key == "mesh-mutations":
                # The one-caller guard and its own mutation script join the job;
                # the mutants are sharded over at least 2 jobs, each running
                # the whole script under the same 15 m limit; every other line
                # and key equals the base.
                same(key, skip_keys={"rules", "stage", "script", "before_script", "parallel", "resource_group"})
                node_apk_only(key)
                self.assertGreaterEqual(current[key].get("parallel", 1), 2)
                added = ["./scripts/check-resolve-callers.sh", "./scripts/check-resolve-callers-mutations.sh"]
                whole = "timeout -k 10s 15m ./scripts/check-mesh-mutations.sh"
                sharded = "MUTATION_SHARD_INDEX=$CI_NODE_INDEX MUTATION_SHARD_TOTAL=$CI_NODE_TOTAL " + whole
                # The base may already carry them (main itself) or not (the MR
                # that added them): compare both sides without the added lines.
                self.assertEqual([l for l in current[key]["script"] if l not in added],
                                 [sharded if l == whole else l for l in previous[key]["script"] if l not in added])
                self.assertEqual([l for l in current[key]["script"] if l in added], added)
            elif key in NODE_JOBS:
                # Its baseline can run ./internal/api, whose screen script test
                # needs node in CI. Invariant, independent of the base: the apk
                # line gains exactly `nodejs`; every other before_script line
                # and field equals the base.
                same(key, skip_keys={"rules", "stage", "resource_group", "before_script"})
                node_apk_only(key)
            elif key == "rotation-mutations":
                # Shard count may grow to keep each shard under the job limit;
                # invariant, independent of the base: never fewer than 4 shards.
                same(key, skip_keys={"rules", "stage", "parallel", "resource_group"})
                self.assertGreaterEqual(current[key]["parallel"], 4)
            elif key == "loghygiene-mutations":
                # Shards were merged (6 -> 3) because per-shard setup cost more
                # than the mutations; every other field still equals the base.
                same(key, skip_keys={"rules", "stage", "parallel"})
                self.assertGreaterEqual(current[key]["parallel"], 3)
            elif key in {"mesh-mutations", "meshgate-mutations"}:
                # Invariant, independent of the base: the postgres service
                # runs without fsync (CREATE DATABASE stalled past its
                # deadline on the shared runner disk); every other field of
                # the service, and of the job, equals the base's.
                same(key, skip_keys={"rules", "stage", "services", "resource_group"})
                fast = ["-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"]
                self.assertEqual(
                    [{k: v for k, v in sv.items() if k != "command"} for sv in current[key]["services"]],
                    [{k: v for k, v in sv.items() if k != "command"} for sv in previous[key]["services"]], key)
                self.assertEqual(service_commands[key], [fast], key)
            elif key == "mutation-select-shadow":
                # The shadow report became the selection itself: mutation-select,
                # with the gate and trigger beside it (pinned by test_ci_config.py).
                self.assertNotIn(key, current)
                self.assertIn("mutation-select", current)
            elif (key.endswith("-mutations") or key in {".mutation-rules", "netns-mutation-run"}) and isinstance(previous[key], dict):
                # When a mutation job runs is pinned by test_ci_config.py
                # (manual on a merge request, scheduled, not on a main push).
                # resource_group (the fan-out cap) is pinned by test_ci_config.py.
                same(key, skip_keys={"rules", "stage", "resource_group"})
            else:
                self.assertEqual(current[key], previous[key], key)
        old, new = previous["tenancy-mutations"], current["tenancy-mutations"]
        for key in old:
            if key not in {"script", "rules", "stage", "resource_group", "parallel"}:
                self.assertEqual(new[key], old[key], key)
        # tenancy shards were merged 4 -> 2: only the shard literals may differ.
        old_script = (old["script"][0].replace("1|2|3|4)", "1|2)").replace('= "4"', '= "2"')
                      .replace('/4"', '/2"').replace("/4;", "/2;"))
        self.assertIn(old_script, new["script"][0])
        self.assertEqual(new["parallel"], 2)
        self.assertEqual(new["dependencies"], ["fmt-vet"])
        # fmt-vet keeps its fast path; the self-tests it ran moved to
        # ci-selftests (pinned by test_ci_config.py). Invariant, independent of
        # the base: no command the base ran in fmt-vet is dropped, the ones
        # that stay keep their order, and the canary decision stays in fmt-vet,
        # whose artifact tenancy-mutations depends on.
        old_fmt, new_fmt = previous["fmt-vet"]["script"], current["fmt-vet"]["script"]
        moved = current.get("ci-selftests", {}).get("script", [])
        self.assertEqual([l for l in old_fmt if l not in new_fmt and l not in moved], [])
        self.assertEqual([l for l in old_fmt if l in new_fmt], [l for l in new_fmt if l in old_fmt])
        self.assertIn("python3 scripts/mutation-canary.py prepare", new_fmt)
        self.assertEqual(current["fmt-vet"]["artifacts"], previous["fmt-vet"]["artifacts"])


class BaselineDiagnosticsTests(unittest.TestCase):
    """The red baseline of check-mesh-mutations names the failing test and
    where it is declared; nothing taken from the log text reaches the output
    (rule 1). The log is untrusted: an assertion with a newline can forge a
    verdict line, a location line or a subtest name."""

    CANARIES = ("c4n4ry-16chars-ab", "c4n4ry-" + "x" * 33, "C4N4RYSECRETVALUE")

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tree = Path(cls.tmp.name)
        (cls.tree / "pkg").mkdir()
        (cls.tree / "pkg/a_test.go").write_text("package pkg\n\nfunc TestA(t *testing.T) {}\nfunc TestOk(t *testing.T) {}\nfunc helperX(t *testing.T) {}\n")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_script(self, log):
        if not isinstance(log, str):
            log = "".join(json.dumps(e) + "\n" for e in log)
        out = subprocess.run([str(ROOT / "scripts/baseline-diagnostics.sh"), str(self.tree)], input=log,
                             capture_output=True, text=True, check=True)
        return out.stdout

    @staticmethod
    def ev(action, test=None, output=None, pkg="example/pkg"):
        e = {"Action": action, "Package": pkg}
        if test is not None:
            e["Test"] = test
        if output is not None:
            e["Output"] = output
        return e

    def logs(self):
        a, b, c = self.CANARIES
        ev = self.ev
        return {
            "plain": [ev("output", "TestA", f"    a_test.go:12: got {a} want {b}\n"), ev("fail", "TestA"), ev("fail")],
            "pass-then-fail": [ev("pass", "TestOk"), ev("output", "TestOk", f"    ok_test.go:3: log {b}\n"),
                               ev("output", "TestA", f"    a_test.go:12: got {a}\n"), ev("fail", "TestA")],
            "multiline-verdict": [ev("output", "TestA", f"boom\n--- FAIL: {a} (0.00s)\n"), ev("fail", "TestA")],
            "multiline-location": [ev("fail", "TestA"), ev("output", "TestA", f"    a_test.go:12: boom\n    {c}.go:9: {a}\n    {a}_test.go:9: x\n")],
            "subtest": [ev("fail", f"TestA/{a}"), ev("fail", "TestA")],
            "subtest-of-declared": [ev("fail", f"TestA/{a}")],
            "subtest-only": [ev("fail", f"{b}/{a}")],
            "panic": [ev("output", None, f"panic: {a} boom\n"), ev("fail")],
            "package-line": [ev("output", None, f"FAIL\t{b}\t0.1s\n"), ev("skip", "TestOk")],
            "garbage": f"# example/pkg\n{a}.go:3: undefined: {b}\n{{not json {c}\n[1]\n",
        }

    def test_output_never_carries_log_text(self):
        for name, log in self.logs().items():
            out = self.run_script(log)
            for canary in self.CANARIES:
                self.assertNotIn(canary, out, name)
            self.assertNotIn("want", out, name)
            self.assertNotIn("boom", out, name)
            self.assertNotIn("example/pkg", out, name)

    def test_output_names_declared_tests_with_declaration_location(self):
        for name in ("plain", "pass-then-fail", "multiline-verdict", "multiline-location", "subtest"):
            out = self.run_script(self.logs()[name])
            self.assertIn("--- FAIL: TestA at pkg/a_test.go:3", out, name)
        self.assertIn("--- SKIP: TestOk at pkg/a_test.go:4", self.run_script(self.logs()["package-line"]))
        self.assertNotIn("TestOk", self.run_script(self.logs()["pass-then-fail"]))
        self.assertIn("panics: 1", self.run_script(self.logs()["panic"]))
        self.assertIn("--- FAIL: TestA at pkg/a_test.go:3", self.run_script(self.logs()["subtest-of-declared"]))
        self.assertIn("not matching a declared test: 1", self.run_script(self.logs()["subtest-only"]))

    def test_dedupe_counts_helpers_and_forged_leading_text(self):
        ev = self.ev
        out = self.run_script([ev("fail", "TestA"), ev("fail", "TestA"), ev("fail", pkg="example/a"), ev("fail", pkg="example/b")])
        self.assertEqual(out.count("--- FAIL: TestA at"), 1)
        self.assertIn("failed packages: 2", out)
        out = self.run_script([ev("fail", "helperX")])
        self.assertNotIn("helperX", out)
        self.assertIn("not matching a declared test: 1", out)
        out = self.run_script([ev("output", "TestA", "text before --- FAIL: TestA (0.00s)\n")])
        self.assertNotIn("TestA", out)
        many = [ev("fail", f"TestA/s{i}") for i in range(3)]
        self.assertEqual(self.run_script(many).count("--- FAIL: TestA at"), 1)
        self.assertIn("unparsed lines: 4", self.run_script(self.logs()["garbage"]))

    def test_forged_verdict_naming_another_declared_test_is_not_printed(self):
        # TestA really failed; its assertion text forges a verdict for TestOk,
        # as a bare line and in the shape of a real go test verdict.
        for forged in ("--- FAIL: TestOk (0.00s)\n", "    --- FAIL: TestOk (0.00s)\nFAIL\tpkg\t0.1s\n"):
            ev = self.ev
            out = self.run_script([ev("output", "TestA", "    a_test.go:12: got x\n" + forged), ev("fail", "TestA")])
            self.assertNotIn("TestOk", out)
            self.assertIn("--- FAIL: TestA at pkg/a_test.go:3", out)

    def test_failing_test_not_declared_in_the_tree_is_not_named(self):
        self.assertNotIn("TestElsewhere", self.run_script([self.ev("fail", "TestElsewhere")]))


class InternalApiNodeTests(unittest.TestCase):
    def test_internal_api_jobs_install_node(self):
        # TestMeshUIScriptPostMessageProtocol fails in CI without node, so a
        # mutation job that installs packages and whose script touches
        # internal/api must install nodejs too.
        import re
        import yaml
        current = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())
        checked = 0
        for key, job in current.items():
            if not (key.endswith("-mutations") and isinstance(job, dict)):
                continue
            lines = list(job.get("before_script") or []) + list(job.get("script") or [])
            apk = [l for l in lines if l.startswith("apk add")]
            scripts = {m for l in lines for m in re.findall(r"scripts/(check-[\w-]+-mutations\.sh)", l)}
            if apk and any("internal/api" in (ROOT / "scripts" / s).read_text() for s in scripts):
                checked += 1
                for line in apk:
                    self.assertIn("nodejs", line.split(), f"{key}: {line}")
        self.assertGreaterEqual(checked, 10)


if __name__ == "__main__":
    unittest.main()
