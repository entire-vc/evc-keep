#!/usr/bin/env python3
"""Validate expanded job sets against GitLab without creating pipelines.

Usage: python3 scripts/check-ci-dry-run.py <unprotected-ref>
The ref must have no open MR: lint applies its real open-MR state to the
branch-push scenario.
Requires PyYAML and an authenticated glab. Lint simulates push pipelines,
so predefined source/branch variables are overridden only in the submitted
simulation content, never in the repository's actual CI configuration.
"""
import copy
import importlib.util
import functools
import json
from pathlib import Path
import re
import subprocess
import sys

import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("contracts", ROOT / "scripts/test_ci_config.py")
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)
selector = contracts.selector
gspec = importlib.util.spec_from_file_location("mutations", ROOT / "scripts/generate-mutation-pipeline.py")
mutations = importlib.util.module_from_spec(gspec)
gspec.loader.exec_module(mutations)


@functools.lru_cache(maxsize=None)
def lint(content, ref):
    request = json.dumps({"content": content, "dry_run": True,
                          "include_jobs": True, "ref": ref})
    run = subprocess.run(["glab", "api", "-X", "POST", "-H", "Content-Type: application/json",
                          "projects/entire-vc%2Fevc-keep/ci/lint", "--input", "-"],
                         input=request, text=True, capture_output=True, check=True)
    data = json.loads(run.stdout)
    if not data["valid"] or data["errors"]:
        raise RuntimeError("GitLab rejected the simulated configuration")
    # No job may soft-pass, the selector included: its answer gates post-review jobs.
    assert all(job["allow_failure"] is False for job in data["jobs"])
    return data


def main():
    ref = sys.argv[1]
    parent = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())
    contracts.check_config(parent, parent["security-hygiene"]["script"][0])
    parent["variables"].update(CI_PIPELINE_SOURCE="merge_request_event", CI_COMMIT_BRANCH="")
    expanded = lint(yaml.safe_dump(parent), ref)
    gate = next(job for job in expanded["jobs"] if job["name"] == "security-hygiene")
    assert all("./scripts/" + name in "\n".join(gate["script"]) for name in contracts.GATES)
    mr_jobs = {job["name"] for job in expanded["jobs"]}
    post_review = set(mutations.ms.post_review_jobs(parent))
    mr_names = {re.sub(r" \d+/\d+$", "", n) for n in mr_jobs}
    assert not {n for n in mr_names if "mutation" in n}, sorted(mr_names)
    assert not mr_names & post_review, mr_names & post_review
    assert not any(re.search(r"check-[\w-]*mutations\.sh", "\n".join(job["script"])) for job in expanded["jobs"])
    assert "release" not in mr_names
    print(f"PASS parent: valid=true; four required gates; no soft-pass; no mutation job ({len(mr_jobs)} jobs)")
    parent["variables"].update(CI_PIPELINE_SOURCE="web", CI_COMMIT_BRANCH="topic",
                               CI_OPEN_MERGE_REQUESTS="113")
    manual = lint(yaml.safe_dump(parent), ref)
    assert any(job["name"] == "full-tests" for job in manual["jobs"])
    print("PASS manual parent with open MR: valid=true; full-tests trigger included")
    # Before its MR exists GitLab does not define CI_OPEN_MERGE_REQUESTS at all.
    parent["variables"].update(CI_PIPELINE_SOURCE="push", CI_COMMIT_BRANCH="topic")
    del parent["variables"]["CI_OPEN_MERGE_REQUESTS"]
    branch = lint(yaml.safe_dump(parent), ref)
    jobs = {job["name"] for job in branch["jobs"]}
    assert jobs == contracts.SCAN_ONLY_JOBS, jobs
    print("PASS branch push before its MR exists: valid=true; jobs=" + ",".join(sorted(jobs)))
    # A push to the default branch runs no mutation job; the schedule runs all.
    every_mutation = {name + "-mutations" for name in contracts.MUTATIONS}
    parent["variables"].update(CI_COMMIT_BRANCH="main", CI_DEFAULT_BRANCH="main")
    def names(data):
        # Sharded jobs expand to "<name> <i>/<n>".
        return {re.sub(r" \d+/\d+$", "", job["name"]) for job in data["jobs"]}

    def runners(data):
        # Jobs that execute a mutation suite, whatever the job is called.
        return {job["name"] for job in data["jobs"]
                if re.search(r"check-[\w-]*mutations\.sh", "\n".join(job["script"]))}

    main_data = lint(yaml.safe_dump(parent), ref)
    main_push = names(main_data)
    assert "full-tests" in main_push and "security-hygiene" in main_push, main_push
    assert not main_push & every_mutation, sorted(main_push & every_mutation)
    # The intake browser suites keep the main push they had inside intake-browser.
    assert runners(main_data) == {contracts.INTAKE_MUTATIONS}, sorted(runners(main_data))
    print("PASS main push: valid=true; ordinary checks present; mutation jobs=0; mutation scripts run only in "
          + contracts.INTAKE_MUTATIONS)
    parent["variables"].update(CI_PIPELINE_SOURCE="schedule")
    sched_data = lint(yaml.safe_dump(parent), ref)
    scheduled = names(sched_data)
    assert post_review <= scheduled, sorted(post_review - scheduled)
    assert "netns-mutation-run" in runners(sched_data), sorted(runners(sched_data))
    assert "release" not in scheduled
    print(f"PASS schedule: valid=true; all {len(post_review)} post-review jobs present")
    # A release tag runs the full set like the schedule, then `release`.
    # Lint evaluates workflow:rules against the real (branch) ref, where the
    # branch-push rule would match first; on a tag CI_COMMIT_BRANCH is unset and
    # it cannot. So this simulation keeps only the tag rule of the workflow (its
    # place in the full list is pinned by test_ci_config.py); job rules see the
    # overridden variables as a tag pipeline would.
    tagged_parent = copy.deepcopy(parent)
    tagged_parent["variables"].update(CI_PIPELINE_SOURCE="push", CI_COMMIT_BRANCH="", CI_COMMIT_TAG="v0.0.0-dry-run")
    tagged_parent["workflow"]["rules"] = [r for r in parent["workflow"]["rules"] if r.get("if") == contracts.TAG_IF]
    assert len(tagged_parent["workflow"]["rules"]) == 1
    tag_data = lint(yaml.safe_dump(tagged_parent), ref)
    tagged = names(tag_data)
    assert post_review <= tagged, sorted(post_review - tagged)
    assert not any(job["when"] == "manual" for job in tag_data["jobs"]), tagged
    release = [job for job in tag_data["jobs"] if job["name"] == "release"]
    assert len(release) == 1 and release[0]["stage"] == "release", release
    assert release[0]["when"] == "on_success" and not release[0].get("needs"), release
    stages = tagged_parent["stages"]
    assert stages[-1] == "release", stages
    late = [job["name"] for job in tag_data["jobs"] if job["name"] != "release" and job["stage"] == "release"]
    assert not late, late
    mutation_jobs = [job for job in tag_data["jobs"] if job["stage"] == "post-review" or job["name"] in runners(tag_data)]
    assert all(stages.index(job["stage"]) < stages.index("release") for job in mutation_jobs)
    print(f"PASS release tag: valid=true; all {len(post_review)} post-review jobs present; "
          f"release last, no needs, after {len(mutation_jobs)} mutation job instances")
    # The child generator (no pipeline uses it now): everything, nothing, one job.
    config = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())
    for label, chosen in (("all", sorted(post_review)), ("none", []), ("one", ["audit-mutations"])):
        data = lint(mutations.render(config, chosen, "dry run" if label == "all" else None), ref)
        got = names(data)
        assert got == (set(chosen) or {mutations.NO_JOB}), (label, got)
        assert all(job["when"] == "on_success" for job in data["jobs"]), label
        print(f"PASS mutation child ({label}): valid=true; jobs={len(data['jobs'])}")
    scenarios = [
        ("docs-only", [("M", "README.md")], "merge_request_event", False),
        ("go", [("M", "pkg/secret/value.go")], "merge_request_event", False),
        ("browser", [("M", "web/intake/index.html")], "merge_request_event", False),
        ("scripts", [("M", "scripts/check-no-silent-skip.sh")], "merge_request_event", False),
        ("ci", [("M", ".gitlab-ci.yml")], "merge_request_event", False),
        ("dependencies", [("M", "go.mod"), ("M", "go.sum")], "merge_request_event", False),
        ("mixed", [("M", "README.md"), ("M", "go.mod")], "merge_request_event", False),
        ("unknown", [("M", "new.txt")], "merge_request_event", False),
        ("added-doc", [("A", "docs/new.md")], "merge_request_event", False),
        ("deleted", [("D", "README.md")], "merge_request_event", False),
        ("renamed", [("D", "README.md"), ("A", "docs/README.md")], "merge_request_event", False),
        ("schedule", [("M", "README.md")], "schedule", False),
        ("main", [("M", "README.md")], "push", True),
        ("manual-full", [("M", "README.md")], "web", False),
    ]
    full = {"test: [core-1]", "test: [core-2]", "test: [targets]", "test: [targets-heavy]", "intake-browser"}
    for name, changes, source, main_branch in scenarios:
        context = {"CI_PIPELINE_SOURCE": source, "CI_COMMIT_BRANCH": "main" if main_branch else "topic",
                   "CI_DEFAULT_BRANCH": "main"}
        skip = selector.can_skip(context) and selector.docs_only(changes)
        data = lint(selector.render(skip, main_branch), ref)
        jobs = {job["name"] for job in data["jobs"]}
        expected = {"docs-only"} if name == "docs-only" else full
        assert jobs == expected, (name, jobs)
        print(f"PASS {name}: valid=true; jobs=" + ",".join(sorted(jobs)))


if __name__ == "__main__":
    main()
