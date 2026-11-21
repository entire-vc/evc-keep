#!/usr/bin/env python3
"""Tests of scripts/release-nightly-gate.py: a real git history, a fake API.

Each red scenario is a way the release could be published on a nightly that
does not prove the mutation suites; each mutant of the gate below switches one
of its checks off and must be caught by at least one scenario.
"""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts/release-nightly-gate.py"
SOURCE = GATE.read_text()
PROJECT = "70"


def load(source=SOURCE):
    module = types.ModuleType("release_nightly_gate")
    module.__file__ = str(GATE)
    exec(compile(source, str(GATE), "exec"), module.__dict__)  # noqa: S102 - the gate under test
    return module


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Repo:
    """main: c1 -> c2 -> c3 -> c4 (the tag); side: c1 -> s1 (not an ancestor of c4)."""

    def __init__(self, path):
        self.path = path
        git(path, "init", "-q", "-b", "main")
        git(path, "config", "user.email", "test@example.invalid")
        git(path, "config", "user.name", "test")
        self.c = {}
        for name in ("c1", "c2", "c3", "c4"):
            git(path, "commit", "-q", "--allow-empty", "-m", name)
            self.c[name] = git(path, "rev-parse", "HEAD")
        git(path, "checkout", "-q", "-b", "side", self.c["c1"])
        git(path, "commit", "-q", "--allow-empty", "-m", "s1")
        self.c["s1"] = git(path, "rev-parse", "HEAD")
        git(path, "checkout", "-q", "main")
        self.c["unknown"] = "f" * 40


MUTATION_JOBS = [{"name": "sealer-mutations", "status": "success"},
                 {"name": "carriers-mutations 2/4", "status": "success"},
                 {"name": "netns-mutation-run", "status": "success"},
                 {"name": "fmt-vet", "status": "success"}]


class FakeAPI:
    """Serves the pipeline list newest first and each pipeline's jobs."""

    def __init__(self, pipelines, jobs=None, fail=None):
        self.pipelines, self.jobs, self.fail, self.calls = pipelines, jobs or {}, fail, []

    def __call__(self, path):
        self.calls.append(path)
        if self.fail and self.fail in path:
            raise self.module.GateError(f"GET {path}: HTTP 403")
        page = int(path.rsplit("page=", 1)[1])
        if "/jobs" in path:
            pid = int(path.split("/pipelines/")[1].split("/")[0])
            items = self.jobs.get(pid, MUTATION_JOBS)
        else:
            assert f"projects/{PROJECT}/pipelines?ref=main&source=schedule&order_by=id&sort=desc" in path, path
            items = sorted(self.pipelines, key=lambda p: p["id"], reverse=True)
        return items if page == 1 else []


def nightly(pid, sha, status="success", **extra):
    return {"id": pid, "sha": sha, "status": status, "source": "schedule", "name": None} | extra


# name -> (pipelines over the commits of Repo, jobs per pipeline id, API failure, expected exit)
def scenarios(c):
    return {
        "positive: newest ancestor nightly green": ([nightly(10, c["c2"]), nightly(11, c["c3"])], {}, None, 0),
        "positive: nightly on the tag commit itself": ([nightly(12, c["c4"])], {}, None, 0),
        # A tag clone holds the tag's history only: newer nightlies on later main
        # commits are missing objects there, not ancestors, and are skipped.
        "positive: a newer nightly on a commit missing from the clone": (
            [nightly(10, c["c3"]), nightly(12, c["unknown"], "failed")], {}, None, 0),
        "newest ancestor failed, an older one green": ([nightly(10, c["c2"]), nightly(11, c["c3"], "failed")], {}, None, 1),
        "newest ancestor cancelled": ([nightly(10, c["c2"]), nightly(11, c["c3"], "canceled")], {}, None, 1),
        "newest ancestor still running": ([nightly(10, c["c2"]), nightly(11, c["c3"], "running")], {}, None, 1),
        "green without mutation jobs": ([nightly(10, c["c3"])], {10: [{"name": "fmt-vet", "status": "success"}]}, None, 1),
        "green pipeline, a soft mutation job red": ([nightly(10, c["c3"])], {10: MUTATION_JOBS[:2] + [
            {"name": "netns-mutation-run", "status": "failed"}]}, None, 1),
        "green pipeline, a mutation shard skipped": ([nightly(10, c["c3"])], {10: [
            {"name": "sealer-mutations", "status": "success"}, {"name": "carriers-mutations 1/4", "status": "skipped"}]}, None, 1),
        "green non-ancestor is not counted": ([nightly(10, c["c2"], "failed"), nightly(11, c["s1"])], {}, None, 1),
        "only a green non-ancestor": ([nightly(11, c["s1"]), nightly(12, c["unknown"])], {}, None, 1),
        "green batch pipeline is ignored": ([nightly(10, c["c2"], "failed"), nightly(11, c["c3"], name="mutation-batch")],
                                            {}, None, 1),
        "red batch pipeline is ignored": ([nightly(10, c["c2"]), nightly(11, c["c3"], "failed", name="mutation-batch")],
                                          {}, None, 0),
        "no nightly at all": ([], {}, None, 1),
        "API refuses the pipeline list": ([nightly(10, c["c3"])], {}, "source=schedule", 1),
        "API refuses the job list": ([nightly(10, c["c3"])], {}, "/jobs", 1),
    }


class GateScenarios(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repo(self.tmp.name)
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.env = {k: os.environ.pop(k) for k in list(os.environ)
                    if k in ("CI_JOB_TOKEN", "CI_API_V4_URL", "CI_PROJECT_ID", "CI_DEFAULT_BRANCH", "CI_COMMIT_SHA")}
        os.environ["CI_PROJECT_ID"] = PROJECT

    def tearDown(self):
        os.chdir(self.cwd)
        os.environ.pop("CI_PROJECT_ID", None)
        os.environ.update(self.env)
        self.tmp.cleanup()

    def run_gate(self, module, pipelines, jobs, fail, sha=None):
        api = FakeAPI(pipelines, jobs, fail)
        api.module = module
        lines = []
        module.print = lambda *a, **k: lines.append(" ".join(map(str, a)))
        code = module.main(["--sha", sha or self.repo.c["c4"]], api=api)
        return code, lines

    def test_scenarios(self):
        module = load()
        for name, (pipelines, jobs, fail, want) in scenarios(self.repo.c).items():
            with self.subTest(name):
                code, lines = self.run_gate(module, pipelines, jobs, fail)
                self.assertEqual(code, want, lines)
                self.assertEqual(len(lines), 1, lines)

    def test_verdict_line_names_the_nightly(self):
        module = load()
        c = self.repo.c
        code, lines = self.run_gate(module, [nightly(10, c["c2"]), nightly(11, c["c3"], "failed")], {}, None)
        self.assertEqual(code, 1)
        self.assertTrue(lines[0].startswith(f"nightly 11 {c['c3']} failed"), lines)
        code, lines = self.run_gate(module, [nightly(10, c["c2"])], {}, None)
        self.assertEqual(code, 0)
        self.assertTrue(lines[0].startswith(f"nightly 10 {c['c2']} success: 3 mutation jobs green; 2 commits"), lines)

    def test_shallow_clone_fails_closed(self):
        module = load()
        clone = Path(self.tmp.name) / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + self.tmp.name, str(clone)],
                       check=True, capture_output=True)
        os.chdir(clone)
        code, lines = self.run_gate(module, [nightly(10, self.repo.c["c4"])], {}, None, sha="HEAD")
        self.assertEqual(code, 1, lines)
        self.assertIn("shallow clone", lines[0])
        os.chdir(self.tmp.name)
        self.assertEqual(self.run_gate(module, [nightly(10, self.repo.c["c4"])], {}, None)[0], 0)

    def test_unknown_release_commit_fails(self):
        code, lines = self.run_gate(load(), [nightly(10, self.repo.c["c3"])], {}, None, sha="e" * 40)
        self.assertEqual(code, 1, lines)

    def test_pipeline_list_is_walked_past_the_first_page(self):
        module = load()
        c = self.repo.c
        newer = [nightly(1000 + i, c["s1"]) for i in range(module.PER_PAGE)]
        older = nightly(10, c["c3"], "failed")

        def api(path):
            page = int(path.rsplit("page=", 1)[1])
            if "/jobs" in path:
                return MUTATION_JOBS if page == 1 else []
            return {1: newer, 2: [older]}.get(page, [])
        lines = []
        module.print = lambda *a, **k: lines.append(" ".join(map(str, a)))
        self.assertEqual(module.main(["--sha", c["c4"]], api=api), 1, lines)
        self.assertTrue(lines[0].startswith("nightly 10 "), lines)

    def test_mutants_are_caught(self):
        """Red run kept in place: each check of the gate switched off is caught."""
        mutants = {
            "newest green instead of newest": ('        if is_ancestor(p["sha"], sha):',
                                               '        if is_ancestor(p["sha"], sha) and p.get("status") == "success":'),
            "ancestry not checked": ('        if is_ancestor(p["sha"], sha):', "        if True:"),
            "missing object counted as ancestor": ("        return False\n    raise GateError",
                                                   "        return True\n    raise GateError"),
            "missing object fails the gate": ("        return False\n    raise GateError",
                                              '        raise GateError("missing")\n    raise GateError'),
            "batch not skipped": ('if p.get("name") == BATCH_NAME or ', "if False or "),
            "status not checked": ('    if status != "success":', "    if False:"),
            "no mutation jobs accepted": ("    if not jobs:", "    if False:"),
            "red mutation job accepted": ("    if red:", "    if False:"),
            "every job counted as a mutation job": ("if MUTATION_JOB.search(", "if True or MUTATION_JOB.search("),
            "API refusal passes": ('        print(f"release gate: {e}")\n        return 1',
                                   '        print(f"release gate: {e}")\n        return 0'),
            "shallow clone accepted": ('    if git("rev-parse", "--is-shallow-repository").stdout.strip() != "false":',
                                       "    if False:"),
        }
        for label, (old, new) in mutants.items():
            with self.subTest(label):
                self.assertEqual(SOURCE.count(old), 1, old)
                module = load(SOURCE.replace(old, new))
                caught = []
                for name, (pipelines, jobs, fail, want) in scenarios(self.repo.c).items():
                    code, _ = self.run_gate(module, pipelines, jobs, fail)
                    if code != want:
                        caught.append(name)
                if label == "shallow clone accepted":
                    clone = Path(self.tmp.name) / "shallow"
                    subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + self.tmp.name, str(clone)],
                                   check=True, capture_output=True)
                    os.chdir(clone)
                    if self.run_gate(module, [nightly(10, self.repo.c["c4"])], {}, None, sha="HEAD")[0] != 1:
                        caught.append("shallow clone")
                    os.chdir(self.tmp.name)
                self.assertTrue(caught, f"mutant {label!r} survives every scenario")
                print(f"mutant {label}: caught by {caught[0]}", file=sys.stderr)


class Handler(http.server.BaseHTTPRequestHandler):
    routes, seen = {}, []

    def do_GET(self):  # noqa: N802 - http.server API
        Handler.seen.append((self.path, self.headers.get("JOB-TOKEN")))
        status, body = next(((s, b) for prefix, (s, b) in Handler.routes.items() if self.path.startswith(prefix)),
                            (404, {"message": "404 Not Found"}))
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class GateOverHTTP(unittest.TestCase):
    """The CI path: the job token against a real HTTP server, as a subprocess."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repo(self.tmp.name)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        Handler.seen.clear()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def run_gate(self, routes):
        Handler.routes = routes
        env = {"PATH": os.environ["PATH"], "HOME": self.tmp.name,
               "CI_JOB_TOKEN": "job-token-for-test", "CI_API_V4_URL": f"http://127.0.0.1:{self.server.server_port}/api/v4",
               "CI_PROJECT_ID": PROJECT, "CI_DEFAULT_BRANCH": "main", "CI_COMMIT_SHA": self.repo.c["c4"]}
        return subprocess.run([sys.executable, "-I", str(GATE)], cwd=self.tmp.name, env=env,
                              capture_output=True, text=True, timeout=60)

    def test_job_token_and_verdicts(self):
        c = self.repo.c
        pipes = f"/api/v4/projects/{PROJECT}/pipelines?ref=main&source=schedule&order_by=id&sort=desc&per_page=100&page=1"
        jobs = f"/api/v4/projects/{PROJECT}/pipelines/10/jobs?per_page=100&page=1"
        run = self.run_gate({pipes: (200, [nightly(10, c["c3"])]), jobs: (200, MUTATION_JOBS)})
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn(f"nightly 10 {c['c3']} success", run.stdout)
        self.assertTrue(Handler.seen and all(token == "job-token-for-test" for _, token in Handler.seen), Handler.seen)
        self.assertNotIn("job-token-for-test", run.stdout + run.stderr)
        for status in (401, 403, 500):
            with self.subTest(status=status):
                run = self.run_gate({pipes: (status, {"message": "refused"})})
                self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
                self.assertIn("release gate: GET", run.stdout)
        run = self.run_gate({pipes: (200, [nightly(10, c["c3"])]), jobs: (403, {"message": "403 Forbidden"})})
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        run = self.run_gate({pipes: (200, {"message": "not a list"})})
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
