#!/usr/bin/env python3
"""Tests of the mutation selector and the child pipeline built from it:
prepared cases, map/script agreement, "changing anything a script mentions
selects that script", scripts and CI job definitions, and the generator."""
import copy
import hashlib
import http.server
import json
from unittest.mock import patch
import importlib.util
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("mutation_select", ROOT / "scripts" / "mutation-select.py")
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)

MAP = ROOT / "scripts" / "mutation-select.map"
REAL_LOAD_GRAPH = ms.load_graph
PKGS = ms.load_graph()
ms.load_graph = lambda: PKGS  # one `go list` for the whole run


def run(files, mapfile=MAP, refs=None):
    rep = ms.report(files, mapfile, refs=refs)
    return rep, {s["script"] for s in rep["selected"]}, {s["script"] for s in rep["skipped"]}


def jobs(rep):
    return {j["job"] for j in rep["jobs"]["selected"]}


ALWAYS = {s for s, v in ms.Map(MAP.read_text()).scripts.items() if v["always"]}


class PreparedCases(unittest.TestCase):
    def test_shared_library(self):
        rep, sel, skip = run(["pkg/secret/value.go"])
        self.assertFalse(rep["all"])
        # everything that imports pkg/secret, directly or through a package
        self.assertTrue({"builtin", "dispatch", "loop", "keep-cli", "public-hygiene", "metadata"} <= sel, sel)
        # a package that cannot see pkg/secret stays out
        self.assertIn("tenancy", skip)

    def test_migration(self):
        rep, sel, skip = run(["internal/store/migrations/00016_deployment.sql"])
        self.assertFalse(rep["all"], rep.get("reason"))
        # every check that opens a migrated scratch database
        self.assertTrue({"deployment", "carriers", "tenancy", "audit", "loghygiene", "dispatch", "runner-enroll"} <= sel, sel)
        # and not a pure-crypto or pure-argv one that is only in by "always"
        self.assertTrue(rep["selected"], "something must be selected")
        self.assertNotIn("sealer", {s["script"] for s in rep["selected"] if not s["always"]})

    def test_config(self):
        rep, sel, skip = run(["internal/config/config.go"])
        self.assertFalse(rep["all"], rep.get("reason"))
        self.assertTrue({"runner-enroll", "intake-service"} <= sel, sel)
        self.assertTrue({"carriers", "tenancy", "deployment"} <= skip, skip)

    def test_test_helper_selects_everything(self):
        for f in ("internal/testutil/pgscratch/pgscratch.go", "internal/testutil/canary/canary.go"):
            rep, sel, skip = run([f])
            self.assertTrue(rep["all"] and not skip and sel == set(ms.Map(MAP.read_text()).scripts), f)

    def test_embedded_asset_and_testdata_belong_to_their_package(self):
        for f in ("web/intake/app.js", "web/intake/testdata/rfc9180-x25519-aes256.json"):
            rep, sel, skip = run([f])
            self.assertFalse(rep["all"], f)
            self.assertTrue({"intake-browser", "intake-page"} <= sel, f)
            self.assertIn("tenancy", skip, f)

    def test_docs_select_nothing(self):
        # No package changed: the security zone's suites test the same code.
        rep, sel, skip = run(["README.md", "docs/anything.md"])
        self.assertFalse(rep["all"])
        self.assertEqual(sel, set())
        self.assertEqual(jobs(rep), set())
        self.assertFalse(rep["jobs"]["all"])

    def test_leaf_change_stays_narrow(self):
        _, sel, skip = run(["internal/carriers/repo.go"])
        self.assertIn("carriers", sel)
        # The API, MCP server and CLI import carriers, so their checks are in
        # by reachability; the checks of packages that cannot see it stay out.
        self.assertTrue({"netns", "tenancy", "deployment"} <= skip, skip)


# The security zone is decided by the lead (exec, targets, runner, sealer,
# fingerprint, execpolicy, provider/secret, identity, audit, loghygiene);
# narrowing it is not an edit to the map made in passing.
SECURITY_ZONE = {"public-hygiene", "sealer", "fingerprint", "execpolicy", "providertest", "identity", "identity-attack", "audit", "loghygiene",
                 "targets", "runnerproto", "deploy", "discovery", "health", "loop", "runner-enroll"}


class Uncertainty(unittest.TestCase):
    def test_security_zone_is_pinned(self):
        always = {s for s, v in ms.Map(MAP.read_text()).scripts.items() if v["always"]}
        self.assertTrue(SECURITY_ZONE <= always, SECURITY_ZONE - always)

    def test_unknown_path_selects_everything(self):
        # Only the root Dockerfile is inert: another one is an unknown path.
        rep, sel, skip = run([".gitlab/images/intake-browser/Dockerfile"])
        self.assertTrue(rep["all"] and not skip)
        self.assertIn("unknown path", rep["reason"])

    def test_shared_ci_paths_select_everything(self):
        for f in (".gitlab-ci.yml", ".gitlab/ci/x.yml", ".golangci.yml", "go.mod", "go.sum", "scripts/mutation-helpers.sh",
                  "scripts/mutation-select.py", "scripts/mutation-select.map", "scripts/generate-mutation-pipeline.py",
                  "scripts/mutation-range.py", "internal/zonecheck/plaintext_api.txt"):
            rep = run([f])[0]
            self.assertTrue(rep["all"] and rep["jobs"]["all"], f)
            self.assertEqual(jobs(rep), set(ms.post_review_jobs(ms.Layout((ROOT / ".gitlab-ci.yml").read_text()).config)), f)

    def test_every_fixed_all_path_wins_over_inert_and_package_rules(self):
        # a doc or a test file under a shared path is still a shared-path change
        for f in ("internal/zonecheck/zone_test.go", "internal/zonecheck/x.txt", "internal/testutil/pgscratch/README.md",
                  "go.mod", "go.sum", ".golangci.yml", "scripts/mutation-select.map"):
            rep = run([f])[0]
            self.assertTrue(rep["all"] and "shared path" in rep["reason"], f)

    def test_unknown_nested_directory_selects_everything(self):
        for f in ("internal/carriers/sub/x.txt", "internal/nope/x.go", "Makefile", ".gitignore"):
            rep = run([f])[0]
            self.assertTrue(rep["all"] and "unknown path" in rep["reason"], f)

    def test_testdata_belongs_to_the_package_above_the_first_testdata(self):
        rep, sel, skip = run(["web/intake/testdata/deep/testdata/x.json"])
        self.assertFalse(rep["all"], rep.get("reason"))
        self.assertTrue({"intake-page", "intake-browser"} <= sel and "tenancy" in skip)

    def test_glob_double_star_crosses_directories(self):
        rep, sel, _ = run(["internal/store/migrations/sub/dir/x.sql"])
        self.assertFalse(rep["all"], rep.get("reason"))
        self.assertTrue({"deployment", "tenancy"} <= sel)

    def test_inert_rule_applies_inside_a_package_directory(self):
        rep, sel, skip = run(["cmd/keep/README.md"])
        self.assertFalse(rep["all"])
        self.assertNotIn("keep-cli", sel)

    def test_non_go_paths_select_nothing(self):
        # Paths no mutation suite reads: no family, not ALL.
        for files in (["Dockerfile"], ["api/openapi.yaml"], ["docs/deploy.md"], ["LICENSE"], ["CONTRIBUTING.md"],
                      ["Dockerfile", "api/openapi.yaml", "docs/deploy.md", "LICENSE", "README.md"]):
            rep, sel, skip = run(files)
            self.assertFalse(rep["all"], (files, rep.get("reason")))
            self.assertEqual((sel, jobs(rep)), (set(), set()), files)
        # control: with a Go file beside them the families come back
        rep, sel, _ = run(["Dockerfile", "internal/carriers/repo.go"])
        self.assertIn("carriers", sel)

    def test_empty_diff_selects_nothing(self):
        rep, sel, skip = run([])
        self.assertFalse(rep["all"])
        self.assertEqual((sel, jobs(rep)), (set(), set()))

    def test_closure_follows_only_the_roots_own_tests(self):
        # a dependency's test files are not run by a script that tests the root:
        # whatever only a dependency's tests import must stay out of the closure
        pairs = []
        for r in PKGS:
            c = ms.closure({r}, PKGS)
            extra = set().union(*(set(PKGS[d]["tests"]) for d in c - {r}), set()) - c
            if extra:
                pairs.append((r, extra))
        self.assertTrue(pairs, "the graph has no case that pins the rule any more")
        for r, extra in pairs:
            self.assertFalse(extra & ms.closure({r}, PKGS), r)
        self.assertIn("pkg/secret", ms.closure({"internal/builtin/sealer"}, PKGS))

    def test_roots_expansion_is_exact(self):
        fake = {"a": {}, "a/b": {}, "ab": {}, "a/b/c": {}}
        self.assertEqual(ms.expand_roots(["a/..."], fake), {"a", "a/b", "a/b/c"})  # not "ab", and the base itself is in
        self.assertEqual(ms.expand_roots(["a"], fake), {"a"})
        with self.assertRaises(ValueError):
            ms.expand_roots(["gone/..."], fake)

    def test_duplicate_script_in_map_is_refused(self):
        with self.assertRaises(ValueError):
            ms.Map("script x roots=a\nscript x roots=b\n")

    def test_diff_listing_names_renames_both_ways_and_deletions(self):
        with tempfile.TemporaryDirectory() as d:
            def g(*a):
                subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a], cwd=d, check=True, capture_output=True)
            g("init", "-q", "-b", "main")
            (Path(d) / "internal" / "carriers").mkdir(parents=True)
            (Path(d) / "internal/carriers/repo.go").write_text("package carriers\n" * 20)
            (Path(d) / "gone.go").write_text("package x\n")
            g("add", "-A"); g("commit", "-q", "-m", "base")
            g("checkout", "-q", "-b", "topic")
            (Path(d) / "docs").mkdir()
            g("mv", "internal/carriers/repo.go", "docs/repo.md")
            g("rm", "-q", "gone.go")
            g("commit", "-q", "-am", "move")
            self.assertEqual(ms.changed_files("main", "topic", cwd=d), ["docs/repo.md", "gone.go", "internal/carriers/repo.go"])
            self.assertIn("carriers", run(ms.changed_files("main", "topic", cwd=d))[1])

    def test_unreachable_base_spells_out_everything(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "o.json"
            subprocess.run([sys.executable, str(ROOT / "scripts/mutation-select.py"), "--base", "no-such-ref", "--json", str(out)], capture_output=True, text=True, check=True)
            rep = __import__("json").loads(out.read_text())
            self.assertTrue(rep["all"] and not rep["skipped"])
            self.assertEqual({x["script"] for x in rep["selected"]}, set(ms.Map(MAP.read_text()).scripts))

    def test_unreachable_base_lists_a_script_the_map_forgot(self):
        with tempfile.TemporaryDirectory() as d:
            short = Path(d) / "short.map"
            short.write_text("\n".join(l for l in MAP.read_text().splitlines() if not l.startswith("script tenancy ")))
            out = Path(d) / "o.json"
            subprocess.run([sys.executable, str(ROOT / "scripts/mutation-select.py"), "--base", "no-such-ref", "--map", str(short), "--json", str(out)],
                           capture_output=True, text=True, check=True)
            rep = __import__("json").loads(out.read_text())
            self.assertTrue(rep["all"] and "selector error" in rep["reason"], rep.get("reason"))
            self.assertEqual({x["script"] for x in rep["selected"]}, ms.scripts_on_disk())

    def test_selector_failure_selects_everything(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.map"
            bad.write_text("script x roots=does/not/exist\nthis is not a directive\n")
            js = Path(d) / "o.json"
            out = subprocess.run([sys.executable, str(ROOT / "scripts/mutation-select.py"), "--files", "pkg/secret/value.go", "--map", str(bad), "--json", str(js)],
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 0)
            self.assertTrue(out.stdout.startswith("ALL"), out.stdout)
            self.assertIn("selector error", out.stdout)
            # the map itself is unreadable, so "everything" comes from scripts/ on disk
            rep = __import__("json").loads(js.read_text())
            self.assertTrue(rep["all"] and not rep["skipped"])
            self.assertEqual({x["script"] for x in rep["selected"]}, set(ms.Map(MAP.read_text()).scripts))

    def test_symlink_in_the_diff_is_listed(self):
        with tempfile.TemporaryDirectory() as d:
            def g(*a):
                subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a], cwd=d, check=True, capture_output=True)
            g("init", "-q", "-b", "main")
            (Path(d) / "internal" / "carriers").mkdir(parents=True)
            (Path(d) / "internal/carriers/repo.go").write_text("package carriers\n")
            (Path(d) / "internal/carriers/old.go").symlink_to("repo.go")
            g("add", "-A"); g("commit", "-q", "-m", "base")
            g("checkout", "-q", "-b", "topic")
            (Path(d) / "internal/carriers/new.go").symlink_to("repo.go")
            (Path(d) / "internal/carriers/old.go").unlink()
            (Path(d) / "internal/carriers/old.go").write_text("package carriers\n")  # a symlink replaced by a file
            (Path(d) / "internal/carriers/repo.go").write_text("package carriers\n\n")
            g("add", "-A"); g("commit", "-q", "-m", "links")
            files, links = ms.diff_listing("main", "topic", cwd=d)
            self.assertEqual(files, ["internal/carriers/new.go", "internal/carriers/old.go", "internal/carriers/repo.go"])
            self.assertEqual(links, ["internal/carriers/new.go", "internal/carriers/old.go"])
            self.assertEqual(ms.changed_files("main", "topic", cwd=d), files)

    def test_symlink_in_the_diff_selects_everything(self):
        rep = ms.report(["internal/carriers/repo.go"], MAP, symlinks=["internal/carriers/repo.go"])
        self.assertTrue(rep["all"] and not rep["skipped"])
        self.assertIn("symlink internal/carriers/repo.go", rep["reason"])
        self.assertFalse(ms.report(["internal/carriers/repo.go"], MAP)["all"])  # the same file as a plain file stays narrow
        # and the command line passes the diff's symlinks on
        orig = ms.diff_listing
        ms.diff_listing = lambda base, head, cwd=ms.ROOT: (["internal/carriers/repo.go"], ["internal/carriers/repo.go"])
        try:
            with tempfile.TemporaryDirectory() as d:
                js = Path(d) / "o.json"
                with open(Path(d) / "stdout", "w") as so:
                    real, sys.stdout = sys.stdout, so
                    try:
                        ms.main(["--json", str(js)])
                    finally:
                        sys.stdout = real
                rep = __import__("json").loads(js.read_text())
        finally:
            ms.diff_listing = orig
        self.assertTrue(rep["all"], rep)
        self.assertIn("symlink", rep["reason"])

    def test_map_and_scripts_agree(self):
        with tempfile.TemporaryDirectory() as d:
            short = Path(d) / "short.map"
            short.write_text("\n".join(l for l in MAP.read_text().splitlines() if not l.startswith("script tenancy ")))
            rep, sel, _ = run(["pkg/secret/value.go"], short)
            self.assertTrue(rep["all"] and "tenancy" in rep["reason"], rep.get("reason"))
            # "everything" includes the script the map forgot
            self.assertEqual(sel, ms.scripts_on_disk())

    def test_map_rule_naming_a_missing_package_is_not_silent(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.map"
            bad.write_text(MAP.read_text().replace("-> pkg internal/store,internal/testutil/pgscratch", "-> pkg internal/nope"))
            rep, _, _ = run(["internal/store/migrations/00016_deployment.sql"], bad)
            self.assertTrue(rep["all"])

    def test_every_package_diff_selects_the_security_zone(self):
        for f in ("internal/carriers/repo.go", "internal/config/config.go", "internal/store/migrations/00016_deployment.sql",
                  "mesh-extension.json", "web/intake/app.js"):
            rep, sel, _ = run([f])
            self.assertTrue(ALWAYS <= sel, f)
            # and every job that runs a zone suite
            self.assertTrue({"sealer-mutations", "public-hygiene-mutations", "mesh-mutations"} <= jobs(rep), f)
        for f in ("README.md", "scripts/check-audit-mutations.sh", "plugins/mesh/gate.go"):
            self.assertFalse(ALWAYS & run([f])[1] - {"audit"}, f)


class Mechanics(unittest.TestCase):
    """Links of the selector that the current map does not exercise yet."""

    def test_glob_is_anchored_and_literal(self):
        md = ms.glob_re("**/*.md")
        self.assertTrue(md.match("a/b.md") and md.match("b.md"))
        for f in ("a/b.mdx", "a/x.md/y.go", "a/bxmd"):
            self.assertIsNone(md.match(f), f)
        sql = ms.glob_re("a/*.sql")
        self.assertTrue(sql.match("a/c.sql"))
        self.assertIsNone(sql.match("a/b/c.sql"))

    def test_first_matching_rule_wins(self):
        pkgs = {"p": {"dir": "elsewhere", "imports": [], "tests": []}}
        inert_first = ms.Map("path a/** -> inert\npath a/x.go -> pkg p\n")
        self.assertEqual(ms.changed_packages(["a/x.go"], pkgs, inert_first)[0], set())
        pkg_first = ms.Map("path a/x.go -> pkg p\npath a/** -> inert\n")
        self.assertEqual(ms.changed_packages(["a/x.go"], pkgs, pkg_first)[0], {"p"})

    def test_external_test_imports_are_test_edges(self):
        out = subprocess.run(["go", "list", "-f", '{{.ImportPath}} {{join .XTestImports " "}}', "./..."], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
        seen = 0
        for line in out.splitlines():
            path, *xt = line.split()
            rel = path[len(ms.MODULE_PREFIX):]
            for x in xt:
                if x.startswith(ms.MODULE_PREFIX) and x != path:
                    seen += 1
                    self.assertIn(x[len(ms.MODULE_PREFIX):], PKGS[rel]["tests"], rel)
        self.assertTrue(seen, "no external test package imports the module any more")

    def test_files_mode_checks_symlinks_in_the_tree(self):
        orig = ms.ROOT
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "internal/carriers").mkdir(parents=True)
            (Path(d) / "internal/carriers/repo.go").symlink_to("/dev/null")
            (Path(d) / "internal/carriers/plain.go").write_text("package carriers\n")
            js = Path(d) / "o.json"
            reps = {}
            try:
                ms.ROOT = Path(d)
                for f in ("internal/carriers/repo.go", "internal/carriers/plain.go"):
                    with open(Path(d) / "stdout", "w") as so:
                        real, sys.stdout = sys.stdout, so
                        try:
                            ms.main(["--files", f, "--map", str(MAP), "--json", str(js)])
                        finally:
                            sys.stdout = real
                    reps[f] = __import__("json").loads(js.read_text())
            finally:
                ms.ROOT = orig
        self.assertTrue(reps["internal/carriers/repo.go"]["all"])
        self.assertIn("symlink", reps["internal/carriers/repo.go"]["reason"])
        self.assertFalse(reps["internal/carriers/plain.go"]["all"], reps["internal/carriers/plain.go"].get("reason"))

    def test_map_naming_a_script_not_on_disk_selects_everything(self):
        with tempfile.TemporaryDirectory() as d:
            extra = Path(d) / "extra.map"
            extra.write_text(MAP.read_text() + "\nscript ghost roots=pkg/secret\n")
            rep, _, _ = run(["internal/carriers/repo.go"], extra)
            self.assertTrue(rep["all"] and "ghost" in rep["reason"], rep.get("reason"))

    def test_go_list_failure_is_everything(self):
        class Failed:
            returncode, stdout, stderr = 1, "", "go: boom\n"
        orig = ms.subprocess.run
        ms.subprocess.run = lambda *a, **k: Failed()
        try:
            with self.assertRaises(ms.Everything) as e:
                REAL_LOAD_GRAPH()
        finally:
            ms.subprocess.run = orig
        self.assertIn("go list failed", str(e.exception))

MENTION = re.compile(r"(?:internal|pkg|cmd|web|test)/[A-Za-z0-9_./-]*[A-Za-z0-9_]")


class ScriptsAreCovered(unittest.TestCase):
    def test_changing_anything_a_script_mentions_selects_it(self):
        m = ms.Map(MAP.read_text())
        bad = []
        for sid in sorted(m.scripts):
            path = next(p for p in (ROOT / "scripts").glob("*mutations.sh") if re.sub(r"^(check-)?(.*)-mutations\.sh$", r"\2", p.name) == sid)
            for mention in sorted(set(MENTION.findall(path.read_text()))):
                target = ROOT / mention
                if target.is_dir():
                    gos = sorted(p for p in target.glob("*.go") if not p.name.endswith("_test.go"))
                    if not gos:
                        continue
                    target = gos[0]
                if not target.is_file():
                    continue
                rel = str(target.relative_to(ROOT))
                rep, sel, _ = run([rel])
                if not rep["all"] and sid not in sel:
                    bad.append(f"{sid}: {rel}")
        self.assertEqual(bad, [], "a script's own input does not select it")


CI_TEXT = (ROOT / ".gitlab-ci.yml").read_text()
POST_REVIEW = set(ms.post_review_jobs(ms.load_config(CI_TEXT)))
gspec = importlib.util.spec_from_file_location("generate_mutation_pipeline", ROOT / "scripts" / "generate-mutation-pipeline.py")
gen = importlib.util.module_from_spec(gspec)
gspec.loader.exec_module(gen)


def edit(text, after, line):
    """`text` with `line` inserted after the first line that equals `after`."""
    lines = text.splitlines(keepends=True)
    i = next(n for n, l in enumerate(lines) if l.rstrip("\n") == after)
    return "".join(lines[:i + 1] + [line + "\n"] + lines[i + 1:])


def replace_in_job(text, job, old, new):
    """`text` with the first `old` inside the top-level block of `job` replaced."""
    start = text.index("\n" + job + ":\n") + 1
    i = text.index(old, start)
    return text[:i] + new + text[i + len(old):]


class ScriptsAndJobs(unittest.TestCase):
    """Changes under scripts/: a suite's own script, shared helpers, test-stage scripts."""

    def test_a_suites_own_script_selects_only_its_job(self):
        rep, sel, _ = run(["scripts/check-audit-mutations.sh"])
        self.assertFalse(rep["all"] or rep["jobs"]["all"], rep.get("reason"))
        self.assertEqual((sel, jobs(rep)), ({"audit"}, {"audit-mutations"}))
        # a script only one job runs, through a wrapper or as a fixture
        for f, job in (("scripts/run-builtin-mutation-job.sh", "builtin-mutations"),
                       ("scripts/testdata/intake-wipe-probe.go.txt", "builtin-mutations"),
                       ("scripts/check-resolve-callers.sh", "mesh-mutations"),
                       ("scripts/check-no-silent-skip.sh", "loghygiene-mutations"),
                       ("scripts/check-intake-page-mutations.sh", "intake-browser-mutations"),
                       ("scripts/check-intake-browser.sh", "intake-browser-mutations"),
                       ("scripts/check-mesh-ui-browser-mutations.sh", "intake-browser-mutations"),
                       ("scripts/check-mesh-ui-mutations.sh", "mesh-ui-mutations"),
                       ("scripts/lib/chromium-startup.mjs", "intake-browser-mutations")):
            rep = run([f])[0]
            self.assertEqual(jobs(rep), {job}, f)

    def test_shared_helpers_select_everything(self):
        for f in ("scripts/mutation-helpers.sh", "scripts/lib/gocache.sh", "scripts/temp-workspace.sh",
                  "scripts/lib/baseline-diag.sh"):
            rep = run([f])[0]
            self.assertTrue(rep["all"] and rep["jobs"]["all"], f)
            self.assertEqual(jobs(rep), POST_REVIEW, f)

    def test_scripts_no_mutation_suite_runs_select_nothing(self):
        for f in ("scripts/check-core-shard-balance.sh", "scripts/core-shard.sh", "scripts/core-shard-weights.txt",
                  "scripts/test_ci_config.py", "scripts/check-ci-dry-run.py", "scripts/check-no-silent-skip-selftest.sh",
                  "scripts/generate-test-pipeline.py", "scripts/ci-play-mutation-jobs.sh", "scripts/README.md",
                  "scripts/new-tool.sh"):
            rep, sel, _ = run([f])
            self.assertFalse(rep["all"], (f, rep.get("reason")))
            self.assertEqual((sel, jobs(rep)), (set(), set()), f)

    def test_a_script_built_from_a_variable_selects_everything(self):
        g = ms.ScriptGraph({"scripts/a.sh": '. "$root/scripts/$helper"\n', "scripts/b.sh": "echo b\n"})
        self.assertEqual(g.opaque(["scripts/a.sh", "scripts/b.sh"]), ["scripts/a.sh"])
        ctx = ms.Context(ms.Map(MAP.read_text()))
        ctx._graph = g
        ctx._head = ({}, {"x-mutations": {"script": ["./scripts/a.sh"]}})
        with self.assertRaises(ms.Everything):
            ctx.classify("scripts/b.sh")
        # control: the same graph without the variable path narrows
        ctx._graph = ms.ScriptGraph({"scripts/a.sh": ". scripts/b.sh\n", "scripts/b.sh": "echo b\n"})
        ctx.classify("scripts/b.sh")
        self.assertEqual(ctx.jobs, {"x-mutations": "scripts/b.sh (script)"})

    def test_globs_and_comments(self):
        g = ms.ScriptGraph({"scripts/a.sh": "for f in scripts/lib/*.mjs; do :; done\n# scripts/c.sh\n",
                            "scripts/lib/x.mjs": "// a.sh\n", "scripts/c.sh": ""})
        self.assertEqual(g.edges["scripts/a.sh"], {"scripts/lib/x.mjs"})  # glob yes, comment no
        self.assertEqual(g.edges["scripts/lib/x.mjs"], set())

    def test_every_post_review_job_runs_a_known_suite(self):
        rep = run(["internal/carriers/repo.go"])[0]
        self.assertFalse(any(j["reason"] == "runs no suite the map knows" for j in rep["jobs"]["selected"]))
        self.assertEqual(jobs(rep) | {j["job"] for j in rep["jobs"]["skipped"]}, POST_REVIEW)

    def test_plugin_paths_select_their_suites(self):
        rep, sel, _ = run(["plugins/mesh/gate.go", "plugins/mesh/go.mod"])
        self.assertFalse(rep["all"], rep.get("reason"))
        self.assertEqual(sel, {"meshgate", "mesh-plugin", "mesh-rotation-e2e"})
        self.assertEqual(jobs(rep), {"meshgate-mutations", "mesh-plugin-mutations", "mesh-rotation-e2e-mutations"})

    def test_lane_poller_paths_select_its_suite(self):
        for f in ("plugins/mesh/lanepoller/poller.go", "plugins/mesh/cmd/keep-lane-poller/main.go"):
            rep, sel, _ = run([f])
            self.assertFalse(rep["all"], rep.get("reason"))
            self.assertEqual(sel, {"lanepoller", "meshgate", "mesh-plugin", "mesh-rotation-e2e"}, f)
            self.assertEqual(jobs(rep), {"lanepoller-mutations", "meshgate-mutations",
                                         "mesh-plugin-mutations", "mesh-rotation-e2e-mutations"}, f)


class CIDefinitions(unittest.TestCase):
    """Changes to .gitlab-ci.yml select the post-review jobs whose definitions changed."""

    def changes(self, new, old=CI_TEXT):
        return ms.ci_definition_changes(old, new)

    def test_comments_and_other_jobs_select_nothing(self):
        self.assertEqual(self.changes(CI_TEXT), set())
        self.assertEqual(self.changes(edit(CI_TEXT, "stages: [security, lint, test, build, post-review, release]", "# a comment")), set())
        self.assertEqual(self.changes(replace_in_job(CI_TEXT, "w3-stubs", "rules: *full-pipeline-only", "timeout: 25m\n  rules: *full-pipeline-only")), set())
        self.assertEqual(self.changes(replace_in_job(CI_TEXT, "mesh-plugin", "timeout: 15m", "timeout: 16m")), set())

    def test_a_post_review_definition_selects_that_job(self):
        new = replace_in_job(CI_TEXT, "audit-mutations", "timeout: ", "timeout: 3")
        self.assertEqual(self.changes(new), {"audit-mutations"})
        # a `#` line inside a block scalar is script, not a YAML comment
        new = replace_in_job(CI_TEXT, "tenancy-mutations", "      canary_omit=false\n", "      canary_omit=false\n      # changed\n")
        self.assertEqual(self.changes(new), {"tenancy-mutations"})

    def test_shared_parts_select_everything(self):
        cases = {
            "workflow": replace_in_job(CI_TEXT, "workflow", "on_new_commit: conservative", "on_new_commit: none"),
            "variables": replace_in_job(CI_TEXT, "variables", 'GOFLAGS: "-buildvcs=false"', 'GOFLAGS: "-buildvcs=true"'),
            "default": replace_in_job(CI_TEXT, "default", "interruptible: true", "interruptible: false"),
            "template": replace_in_job(CI_TEXT, ".go-module-cache", "policy: pull", "policy: pull-push"),
            "rules anchor": replace_in_job(CI_TEXT, ".mutation-rules", "    - when: on_success", "    - when: manual"),
            "schedule anchor": replace_in_job(CI_TEXT, ".mutation-schedule-rules", '"schedule"', '"web"'),
            "runner anchor": replace_in_job(CI_TEXT, ".mutation-runner", "[keep-mutations]", "[docker]"),
            "unparsable": CI_TEXT + "\n  broken: [\n",
        }
        for label, new in cases.items():
            with self.subTest(label):
                self.assertNotEqual(new, CI_TEXT)
                with self.assertRaises(ms.Everything):
                    self.changes(new)
        with self.assertRaises(ms.Everything):
            self.changes(None)
        # The selection jobs left the pipeline, but the selector still treats a
        # change to one of them as reaching every post-review job.
        for name in ("mutation-select", "start-mutations", "mutations"):
            with self.subTest(selection_job=name):
                old = CI_TEXT + f"\n{name}:\n  stage: test\n  script: [\"true\"]\n"
                with self.assertRaises(ms.Everything):
                    self.changes(old.replace('script: ["true"]', 'script: ["false"]'), old)

    def test_ci_files_through_the_report(self):
        new = replace_in_job(CI_TEXT, "audit-mutations", "timeout: ", "timeout: 3")
        with patch.object(ms.Context, "blob", lambda self, ref, path: CI_TEXT if ref == "BASE" else new), \
             patch.object(ms.Context, "merge_base", lambda self: "BASE"):
            rep, sel, _ = run([".gitlab-ci.yml", ".gitlab/ci/full-tests.yml"], refs=("BASE", "HEAD"))
        self.assertFalse(rep["all"] or rep["jobs"]["all"], rep.get("reason"))
        self.assertEqual((sel, jobs(rep)), (set(), {"audit-mutations"}))
        # without a diff base, and for an unknown file under .gitlab/ci/, everything
        self.assertTrue(run([".gitlab-ci.yml"])[0]["jobs"]["all"])
        self.assertTrue(run([".gitlab/ci/other.yml"], refs=("BASE", "HEAD"))[0]["jobs"]["all"])


class Generator(unittest.TestCase):
    """The child pipeline built from the selector's answer."""

    def answer(self, names, **over):
        rep = {"all": False, "provenance": {"head": {"commit": "a" * 40}},
               "jobs": {"all": False, "selected": [{"job": n, "reason": "x"} for n in sorted(names)],
                        "skipped": [{"job": n} for n in sorted(POST_REVIEW - set(names))]}}
        rep.update(over)
        return rep

    def test_decide_narrows_only_a_complete_answer_about_this_commit(self):
        every = sorted(POST_REVIEW)
        self.assertEqual(gen.decide(self.answer({"audit-mutations"}), POST_REVIEW, "a" * 40), (["audit-mutations"], None))
        self.assertEqual(gen.decide(self.answer(set()), POST_REVIEW, "a" * 40), ([], None))
        bad = [None, {}, self.answer({"audit-mutations"}, all=True),
               self.answer({"audit-mutations"}, jobs={"all": True, "selected": [], "skipped": []}),
               self.answer({"audit-mutations"}, provenance={"head": {"commit": "b" * 40}})]
        ghost = self.answer({"audit-mutations"})
        ghost["jobs"]["selected"].append({"job": "ghost-mutations"})
        lost = self.answer({"audit-mutations"})
        lost["jobs"]["skipped"].pop()
        twice = self.answer({"audit-mutations"})
        twice["jobs"]["skipped"].append({"job": "audit-mutations"})
        for answer in bad + [ghost, lost, twice]:
            names, reason = gen.decide(answer, POST_REVIEW, "a" * 40)
            self.assertEqual(names, every, answer)
            self.assertTrue(reason, answer)

    def test_malformed_answers_select_every_job_without_raising(self):
        every = sorted(POST_REVIEW)
        def with_selected(*extra):
            a = self.answer({"audit-mutations"})
            a["jobs"]["selected"].extend(extra)
            return a
        def mutate(fn):
            a = self.answer({"audit-mutations"})
            fn(a)
            return a
        cases = {
            "non-string job": with_selected({"job": 7}),
            "None job": with_selected({"job": None}),
            "missing job key": with_selected({"reason": "x"}),
            "duplicate job": with_selected({"job": "audit-mutations"}),
            "nested list job": with_selected({"job": ["sealer-mutations"]}),
            "list entry": with_selected(["sealer-mutations"]),
            "string entry": with_selected("sealer-mutations"),
            "None entry": with_selected(None),
            "unknown job": with_selected({"job": "ghost-mutations"}),
            "skipped not a list": mutate(lambda a: a["jobs"].__setitem__("skipped", {"job": "x"})),
            "all not a bool": mutate(lambda a: a.__setitem__("all", "false")),
            "all is None": mutate(lambda a: a.__setitem__("all", None)),
            "jobs all not a bool": mutate(lambda a: a["jobs"].__setitem__("all", 0)),
            "jobs part a list": mutate(lambda a: a.__setitem__("jobs", [])),
            "missing head": mutate(lambda a: a["provenance"].pop("head")),
            "head not a string": mutate(lambda a: a["provenance"]["head"].__setitem__("commit", 1234)),
            "head not a sha": mutate(lambda a: a["provenance"]["head"].__setitem__("commit", "HEAD")),
            "provenance a string": mutate(lambda a: a.__setitem__("provenance", "x")),
            "reason a dict": mutate(lambda a: a.update(all=True, reason={"x": 1})),
        }
        for label, answer in cases.items():
            for head in ("a" * 40, None):
                with self.subTest(label, head=head):
                    names, reason = gen.decide(answer, POST_REVIEW, head)
                    self.assertEqual(names, every)
                    self.assertTrue(isinstance(reason, str) and reason)
        # control: the well-formed answer narrows, with and without a commit to compare
        for head in ("a" * 40, None):
            self.assertEqual(gen.decide(self.answer({"audit-mutations"}), POST_REVIEW, head), (["audit-mutations"], None))

    def test_render_copies_the_selected_jobs(self):
        cfg = ms.load_config(CI_TEXT)
        for names in ([], ["audit-mutations", "tenancy-mutations", "netns-mutation-run"], sorted(POST_REVIEW)):
            child = yaml.safe_load(gen.render(cfg, names))
            jobs_ = {k for k, v in child.items() if ms.is_job(k, v)}
            self.assertEqual(jobs_, set(names) or {gen.NO_JOB}, names)
            self.assertEqual(child["stages"], ["post-review"])
            self.assertEqual(child["default"], cfg["default"])
            for n in names:
                job, orig = child[n], cfg[n]
                self.assertEqual(job["rules"], [{"when": "on_success"}], n)
                self.assertEqual({k: v for k, v in job.items() if k not in ("rules", "needs")},
                                 {k: v for k, v in orig.items() if k not in ("rules", "dependencies")}, n)
                for parent in [orig.get("extends")] if isinstance(orig.get("extends"), str) else orig.get("extends", []):
                    self.assertEqual(child[parent], cfg[parent], (n, parent))
            if "tenancy-mutations" in names:
                self.assertEqual(child["tenancy-mutations"]["needs"], [{"pipeline": "$PARENT_PIPELINE_ID", "job": "fmt-vet"}])

    def test_main_falls_back_to_every_job(self):
        with tempfile.TemporaryDirectory() as d:
            out, summary = Path(d) / "child.yml", Path(d) / "summary.txt"
            for content in (None, "not json", json.dumps({"all": True})):
                answer = Path(d) / "answer.json"
                if answer.exists():
                    answer.unlink()
                if content is not None:
                    answer.write_text(content)
                with patch("sys.stdout"):
                    self.assertEqual(gen.main([str(answer), str(out), str(summary)]), 0)
                child = yaml.safe_load(out.read_text())
                self.assertEqual({k for k, v in child.items() if ms.is_job(k, v)}, POST_REVIEW, content)
                self.assertIn("all:", summary.read_text().splitlines()[0])

    def test_selector_failure_answers_every_job(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.map"
            bad.write_text("this is not a directive\n")
            js = Path(d) / "o.json"
            subprocess.run([sys.executable, str(ROOT / "scripts/mutation-select.py"), "--files", "README.md", "--map", str(bad),
                            "--json", str(js)], capture_output=True, text=True, check=True)
            rep = json.loads(js.read_text())
            self.assertTrue(rep["jobs"]["all"])
            self.assertEqual(gen.decide(rep, POST_REVIEW)[0], sorted(POST_REVIEW))


class ProvenanceCases(unittest.TestCase):
    def test_shared_fallback_retains_single_graph(self):
        with patch.object(ms, "load_graph", return_value=PKGS) as listing:
            rep = ms.report([".gitlab-ci.yml"], MAP)
        listing.assert_called_once_with()
        self.assertTrue(rep["all"])
        self.assertEqual(rep["graph"]["packages"], ms.graph_evidence(PKGS)["packages"])
        self.assertEqual(rep["graph"]["sha256"], ms.canonical_hash(rep["graph"]["packages"]))

    def test_graph_binding_and_unknown(self):
        self.assertEqual(ms.graph_evidence(None)["status"], "unknown")
        graph = {k: dict(v) for k, v in PKGS.items()}
        first = next(iter(graph))
        before = ms.graph_evidence(graph)
        self.assertEqual(before["status"], "unknown")  # no real listing metadata
        graph[first]["imports"] = graph[first]["imports"] + ["corrupted-edge"]
        self.assertNotEqual(before["sha256"], ms.graph_evidence(graph)["sha256"])
        with self.assertRaises((KeyError, TypeError)):
            ms.graph_evidence({"broken": {}})

    def test_failed_listing_is_all_error(self):
        with patch.object(ms, "load_graph", side_effect=ms.Everything("go list failed: offline")):
            rep = ms.report([".gitlab-ci.yml"], MAP)
        self.assertTrue(rep["all"])
        self.assertEqual(rep["graph"]["status"], "error")
        self.assertFalse(rep["skipped"])

    def test_empty_graph_fails_closed_cli(self):
        with tempfile.TemporaryDirectory() as d, patch.object(ms, "load_graph", return_value={}):
            out = Path(d) / "report.json"
            with patch("builtins.print"):
                self.assertEqual(ms.main(["--files", "--json", str(out)]), 0)
            rep = json.loads(out.read_text())
        self.assertTrue(rep["all"])
        self.assertFalse(rep["skipped"])
        self.assertEqual(rep["graph"]["status"], "error")

    def test_metadata_failure_preserves_policy(self):
        files = ["internal/carriers/carriers.go"]
        baseline = ms.report(files, MAP)
        real_run = subprocess.run
        def no_version(argv, **kwargs):
            if argv == ["go", "version"]:
                raise OSError("version unavailable")
            return real_run(argv, **kwargs)
        for fault in (patch.object(ms.subprocess, "run", side_effect=no_version),
                      patch.object(ms.shutil, "which", return_value="/nonexistent/provenance/go"),
                      patch.object(ms, "source_snapshot", side_effect=RuntimeError("metadata failure"))):
            with fault, patch.object(ms, "load_graph", REAL_LOAD_GRAPH):
                rep = ms.report(files, MAP)
            self.assertEqual(rep["selected"], baseline["selected"])
            self.assertEqual(rep["skipped"], baseline["skipped"])
            self.assertEqual(rep["all"], baseline["all"])
            self.assertEqual(rep["graph"]["status"], "error")

    def test_source_binding_and_missing_ref(self):
        proof = ms.provenance("HEAD", "HEAD", MAP)
        self.assertEqual(proof["selector_sha256"], hashlib.sha256((ROOT / "scripts/mutation-select.py").read_bytes()).hexdigest())
        self.assertEqual(proof["map_sha256"], hashlib.sha256(MAP.read_bytes()).hexdigest())
        self.assertEqual(proof["mutation_inventory_sha256"], ms.canonical_hash(proof["mutation_inventory"]))
        if proof["working_tracked_sources"] is not None:
            self.assertEqual(proof["working_tracked_sha256"], ms.canonical_hash(proof["working_tracked_sources"]))
        else:
            self.assertIsNone(proof["working_tracked_sha256"])
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(["git", "init", "-q", d], check=True)
            (root / "source.go").write_text("before")
            subprocess.run(["git", "add", "source.go"], cwd=root, check=True)
            with patch.object(ms, "ROOT", root):
                before = ms.source_snapshot()
                (root / "source.go").write_text("after")
                after = ms.source_snapshot()
            self.assertNotEqual(ms.canonical_hash(before), ms.canonical_hash(after))
        missing = ms.provenance("nonexistent-provenance-ref", "HEAD", ROOT / "missing-map")
        self.assertIsNone(missing["base"]["commit"])
        self.assertIsNone(missing["map_sha256"])
        with patch.dict(ms.os.environ, {"CI_JOB_ID": "123", "CI_PIPELINE_ID": "private-value", "UNRELATED_SECRET": "must-not-export"}):
            ids = ms.provenance("HEAD", "HEAD", MAP)["ci_ids"]
        self.assertEqual(ids.get("CI_JOB_ID"), "123")
        self.assertNotIn("CI_PIPELINE_ID", ids)
        self.assertNotIn("UNRELATED_SECRET", ids)


rspec = importlib.util.spec_from_file_location("mutation_range", ROOT / "scripts" / "mutation-range.py")
mr = importlib.util.module_from_spec(rspec)
rspec.loader.exec_module(mr)


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=cwd,
                          capture_output=True, text=True, check=True).stdout.strip()


class MutationRange(unittest.TestCase):
    """The batch's base commit: only a commit the head descends from narrows."""

    def test_green_base(self):
        with tempfile.TemporaryDirectory() as d:
            git(d, "init", "-q")
            for n in ("a", "b"):
                (Path(d) / n).write_text(n)
                git(d, "add", n)
                git(d, "commit", "-qm", n)
            first, head = git(d, "rev-parse", "HEAD~1"), git(d, "rev-parse", "HEAD")
            git(d, "checkout", "-qb", "side", first)
            (Path(d) / "c").write_text("c")
            git(d, "add", "c")
            git(d, "commit", "-qm", "c")
            side = git(d, "rev-parse", "HEAD")
            self.assertEqual(mr.green_base(first + "\n", head, d), (first, None))
            self.assertEqual(mr.green_base(head, head, d), (head, None))
            for text in (None, "", "not a sha", head[:12], head.upper(), head + "0", "f" * 40, side):
                base, reason = mr.green_base(text, head, d)
                self.assertIsNone(base, text)
                self.assertTrue(reason, text)

    def run_range(self, green):
        with tempfile.TemporaryDirectory() as d:
            out, gf = Path(d) / "answer.json", Path(d) / "green"
            if green is not None:
                gf.write_text(green)
            r = subprocess.run([sys.executable, str(ROOT / "scripts/mutation-range.py"), "--json", str(out),
                                "--green-file", str(gf)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            return (json.loads(out.read_text()) if out.exists() else None), r.stdout

    def test_head_already_green_selects_nothing(self):
        head = git(ROOT, "rev-parse", "HEAD")
        answer, log = self.run_range(head)
        self.assertIsNotNone(answer, log)
        self.assertEqual(answer["changed"], [])
        names, reason = gen.decide(answer, POST_REVIEW, head)
        self.assertEqual((names, reason), ([], None), log)

    def test_no_green_commit_runs_every_job(self):
        for green in (None, "garbage", "0" * 40):
            answer, log = self.run_range(green)
            self.assertIsNone(answer, green)
            self.assertIn("every post-review job runs", log)
            self.assertEqual(gen.decide(answer, POST_REVIEW)[0], sorted(POST_REVIEW))

    def test_fetch_without_ci_variables_is_no_answer(self):
        with patch.dict(mr.os.environ, {}, clear=True), patch("sys.stdout"):
            self.assertIsNone(mr.fetch_green())

    def test_fetch_reads_the_artifact_with_the_job_token(self):
        head = git(ROOT, "rev-parse", "HEAD")
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("JOB-TOKEN")))
                ok = self.path.endswith("/projects/42/jobs/artifacts/feat%2Fx/raw/mutation-green.sha?job=mutation-green")
                self.send_response(200 if ok else 404)
                self.end_headers()
                self.wfile.write((head + "\n").encode() if ok else b"")

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            env = {"CI_API_V4_URL": f"http://127.0.0.1:{server.server_port}/api/v4", "CI_PROJECT_ID": "42",
                   "CI_COMMIT_REF_NAME": "feat/x", "CI_JOB_TOKEN": "job-token-for-test"}
            with patch.dict(mr.os.environ, env, clear=True), patch("sys.stdout"):
                self.assertEqual(mr.fetch_green(), head + "\n")
                # Another branch has no green commit: the 404 is no answer.
                with patch.dict(mr.os.environ, {"CI_COMMIT_REF_NAME": "main"}):
                    self.assertIsNone(mr.fetch_green())
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual([t for _, t in seen], ["job-token-for-test"] * 2)

    def test_no_stale_answer_survives(self):
        """An answer left from before is never read as this run's."""
        head = git(ROOT, "rev-parse", "HEAD")
        real = subprocess.run

        def failing_selector(cmd, *args, **kwargs):
            if cmd[0] != sys.executable:
                return real(cmd, *args, **kwargs)
            # A selector that wrote part of an answer, then failed.
            Path(cmd[cmd.index("--json") + 1]).write_text('{"all": false}')
            return subprocess.CompletedProcess(cmd, 1)

        with tempfile.TemporaryDirectory() as d:
            out, gf = Path(d) / "answer.json", Path(d) / "green"
            for green, selector in ((None, real), (head, failing_selector)):
                out.write_text('{"stale": true}')
                gf.unlink(missing_ok=True)
                if green:
                    gf.write_text(green)
                with patch.object(mr.subprocess, "run", side_effect=selector), patch("sys.stdout"):
                    self.assertEqual(mr.main(["--json", str(out), "--green-file", str(gf)]), 0)
                self.assertFalse(out.exists(), green)


class Receipts(unittest.TestCase):
    """A job skips itself only on the exact hash of its inputs."""

    @classmethod
    def setUpClass(cls):
        cls.config = ms.load_config(CI_TEXT)
        cls.m = ms.Map(MAP.read_text())
        cls.files = {f: v["sha256"] for f, v in ms.source_snapshot().items()}

    def digests(self, files=None, config=None):
        config = config or self.config
        return gen.receipts(config, sorted(ms.post_review_jobs(config)), PKGS, self.m, files or self.files)

    def test_every_post_review_job_has_a_receipt(self):
        self.assertEqual(set(self.digests()), POST_REVIEW)

    def test_hash_follows_the_inputs(self):
        base = self.digests()
        def changed(path):
            files = dict(self.files, **{path: "0" * 64})
            new = self.digests(files)
            return {n for n in base if base[n] != new[n]}
        # a package file: the jobs whose suites reach it, not the others
        hit = changed("internal/tenancy/tenancy.go" if "internal/tenancy/tenancy.go" in self.files
                      else next(f for f in sorted(self.files) if f.startswith("internal/tenancy/") and f.endswith(".go")))
        self.assertIn("tenancy-mutations", hit)
        self.assertNotIn("sealer-mutations", hit)
        # the job's own mutation script, a file the map links to its packages, go.sum
        self.assertEqual(changed("scripts/check-sealer-mutations.sh"), {"sealer-mutations"})
        # files outside any package directory that the map links to a package or a script
        self.assertTrue({"mesh-mutations", "mesh-ui-mutations"} <= changed("mesh-extension.json"))
        self.assertNotIn("sealer-mutations", changed("mesh-extension.json"))
        plugin = next(f for f in sorted(self.files) if f.startswith("plugins/mesh/") and f.endswith(".go"))
        self.assertIn("meshgate-mutations", changed(plugin))
        self.assertEqual(changed("go.sum"), POST_REVIEW)
        self.assertEqual(changed("internal/testutil/canary/canary.go"), POST_REVIEW)
        # a test file in the package counts like its code
        test_file = next(f for f in sorted(self.files) if f.startswith("internal/builtin/sealer/") and f.endswith("_test.go"))
        self.assertIn("sealer-mutations", changed(test_file))
        # documentation changes nothing
        self.assertEqual(changed("docs/deploy.md"), set())
        # the job definition is an input
        config = copy.deepcopy(self.config)
        config["sealer-mutations"]["timeout"] = "1m"
        new = self.digests(config=config)
        self.assertEqual({n for n in base if base[n] != new[n]}, {"sealer-mutations"})

    def run_lines(self, lines, project):
        env = {"PATH": "/usr/bin:/bin", "CI_PROJECT_DIR": project}
        r = subprocess.run(["sh", "-c", "\n".join(lines + ["exit 3"])], env=env, capture_output=True, text=True)
        return r.returncode, r.stdout

    def test_receipt_skips_only_on_the_same_hash(self):
        a, b = "a" * 64, "b" * 64
        with tempfile.TemporaryDirectory() as d:
            check = gen.receipt_check("sealer-mutations", a)
            # no receipt: the job runs (reaches the line after the check)
            self.assertEqual(self.run_lines([check], d)[0], 3)
            # the last line writes it; the next run skips, saying so
            code, _ = self.run_lines([gen.receipt_write("sealer-mutations", a)], d)
            self.assertEqual(code, 3)
            code, log = self.run_lines([check], d)
            self.assertEqual(code, 0)
            self.assertIn("already green at " + a, log)
            # a receipt for other inputs, an empty one, another job's: the job runs
            for content in (b, "", a + "x", a[:-1]):
                (Path(d) / ".mutation-receipt" / "sealer-mutations-0").write_text(content + "\n")
                self.assertEqual(self.run_lines([check], d)[0], 3, content)
            (Path(d) / ".mutation-receipt" / "sealer-mutations-0").write_text(a + "\n")
            self.assertEqual(self.run_lines([gen.receipt_check("audit-mutations", a)], d)[0], 3)
            # a shard reads its own receipt
            code, _ = self.run_lines(["export CI_NODE_INDEX=2", check], d)
            self.assertEqual(code, 3)

    def test_receipt_is_written_only_after_the_script(self):
        a = "a" * 64
        with tempfile.TemporaryDirectory() as d:
            child = yaml.safe_load(gen.render(self.config, ["sealer-mutations"], digests={"sealer-mutations": a}))
            job, orig = child["sealer-mutations"], ms.post_review_jobs(self.config)["sealer-mutations"]
            self.assertEqual(job["before_script"], [gen.receipt_check("sealer-mutations", a)] + gen.as_list(orig.get("before_script")))
            self.assertEqual(job["script"], gen.as_list(orig["script"]) + [gen.receipt_write("sealer-mutations", a)])
            # the module cache of the template is kept, the receipt cache is keyed by the hash
            self.assertEqual(job["cache"][:-1], gen.as_list(orig.get("cache")))
            self.assertEqual(job["cache"][-1], {"key": f"mutation-receipt-sealer-mutations-{a}-$CI_NODE_INDEX",
                                                "paths": [".mutation-receipt/"], "when": "on_success"})
            # a failing script line stops before the receipt: GitLab runs each line under errexit
            code, _ = self.run_lines(["set -e", "false"] + job["script"][-1:], d)
            self.assertNotEqual(code, 3)
            self.assertFalse((Path(d) / ".mutation-receipt").exists())
        # no digest, no receipt
        child = yaml.safe_load(gen.render(self.config, ["sealer-mutations"]))
        self.assertNotIn("mutation-receipt", json.dumps(child["sealer-mutations"]))

    def test_batch_child_is_never_cancelled(self):
        self.assertEqual(yaml.safe_load(gen.render(self.config, [], batch=True))["workflow"]["auto_cancel"],
                         {"on_new_commit": "none"})
        self.assertEqual(yaml.safe_load(gen.render(self.config, []))["workflow"]["auto_cancel"],
                         {"on_new_commit": "interruptible"})

    def test_batch_variable_makes_the_child_uncancellable(self):
        with tempfile.TemporaryDirectory() as d, patch.object(gen.ms, "load_graph", side_effect=ms.Everything("not needed")):
            out, summary = Path(d) / "child.yml", Path(d) / "summary.txt"
            for value, cancel in (("true", "none"), ("false", "interruptible"), (None, "interruptible")):
                env = {"KEEP_MUTATION_BATCH": value} if value else {}
                with patch.dict(gen.os.environ, env), patch("sys.stdout"):
                    if value is None:
                        gen.os.environ.pop("KEEP_MUTATION_BATCH", None)
                    gen.main([str(Path(d) / "none.json"), str(out), str(summary)])
                self.assertEqual(yaml.safe_load(out.read_text())["workflow"]["auto_cancel"],
                                 {"on_new_commit": cancel}, value)

    def test_no_graph_means_no_receipts(self):
        with tempfile.TemporaryDirectory() as d, patch.object(gen.ms, "load_graph", side_effect=ms.Everything("go list failed")):
            out, summary = Path(d) / "child.yml", Path(d) / "summary.txt"
            with patch("sys.stdout"):
                gen.main([str(Path(d) / "none.json"), str(out), str(summary)])
            self.assertNotIn("mutation-receipt", out.read_text())
            self.assertIn("no receipts", summary.read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
