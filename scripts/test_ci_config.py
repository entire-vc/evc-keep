#!/usr/bin/env python3
"""Fail-closed CI contract checks, including deliberately broken controls."""
import ast
import copy
import fnmatch
import importlib.util
import os
import re
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("selector", ROOT / "scripts/generate-test-pipeline.py")
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)

GATES = ["check-secret-scan.sh", "check-secret-scan-selftest.sh",
         "check-identity-secret-scan-selftest.sh", "check-ci-public-hygiene.sh"]
MUTATIONS = {"public-hygiene", "execpolicy", "sealer", "fingerprint", "runnerproto",
             "identity", "loghygiene", "identity-attack", "builtin", "tenancy", "targets",
             "audit", "keep-cli", "health", "deploy", "loop", "deployment", "runner-enroll", "discovery",
             "providertest", "carriers", "dispatch", "deploy-api", "approvals", "execrun", "mcp", "rotation", "rotate-audit",
             "rotation-wiring",
             "carrier-verify", "pgscratch", "mesh", "mesh-ui", "meshgate", "mesh-hierarchy",
             "keylevel-reconcile", "mesh-plugin", "mesh-rotation-e2e", "bootstrap-org",
             "lanepoller"}
# The mutation batch (a schedule on main every 4 hours) runs only the jobs
# check_mutation_batch names: every other job opens its rules with this one.
BATCH_IF = '$KEEP_MUTATION_BATCH == "true"'
BATCH_NEVER = {"if": BATCH_IF, "when": "never"}
# Rules shared by jobs that run in every pipeline except a scan-only branch push
# and the mutation batch.
FULL_PIPELINE_ONLY = [BATCH_NEVER, {"if": '$KEEP_BRANCH_PUSH_SCAN_ONLY == "true"', "when": "never"},
                      {"when": "on_success"}]
# fmt-vet: the same, but it runs in the batch too (tenancy-mutations reads its artifact).
FMT_VET_RULES = FULL_PIPELINE_ONLY[1:]
# The same, for mutation jobs: never on a merge request (mutation suites are not
# a merge condition); a push to the default branch does not run them (the
# nightly schedule does); everywhere else they run at once.
MAIN_PUSH_IF = '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $CI_PIPELINE_SOURCE == "push"'
MR_IF = '$CI_PIPELINE_SOURCE == "merge_request_event"'
MUTATION_RULES = [BATCH_NEVER, {"if": '$KEEP_BRANCH_PUSH_SCAN_ONLY == "true"', "when": "never"},
                  {"if": MR_IF, "when": "never"},
                  {"if": MAIN_PUSH_IF, "when": "never"},
                  {"when": "on_success"}]
# Mutation jobs that run only in schedules and on release tags.
TAG_IF = "$CI_COMMIT_TAG"
SCHEDULE_RULES = [BATCH_NEVER, {"if": MR_IF, "when": "never"},
                  {"if": '$CI_PIPELINE_SOURCE == "schedule"'},
                  {"if": TAG_IF}]
# The intake browser suites: like MUTATION_RULES, but they keep the push to the
# default branch they had inside the test child's intake-browser job.
INTAKE_MUTATIONS = "intake-browser-mutations"
INTAKE_RULES = [BATCH_NEVER, {"if": '$KEEP_BRANCH_PUSH_SCAN_ONLY == "true"', "when": "never"},
                {"if": MR_IF, "when": "never"},
                {"when": "on_success"}]
# The mutation batch: its range job, the trigger of its child pipeline, and the
# job that keeps the commit the post-review jobs last passed on.
RANGE_JOB, BATCH_TRIGGER, GREEN_JOB = "mutation-range", "mutations-batch", "mutation-green"
TRIGGERS = (BATCH_TRIGGER,)
# Publishes a release on a tag; needs every mutation job of the tag pipeline.
RELEASE_JOB = "release"
SCAN_ONLY_JOBS = {"security-hygiene", "secret-scan-scope-selftest"}


def unconditional(job):
    """True when a job runs in every full pipeline (no narrower rules)."""
    return job.get("rules", FULL_PIPELINE_ONLY) in (FULL_PIPELINE_ONLY, MUTATION_RULES)


def check_mutations_never_on_mr(config):
    """Every mutation job: never created on an MR, automatic in schedules and on
    tags, absent on a main push; none is filtered by changed paths."""
    for name in sorted(MUTATIONS) + ["netns-mutation-run"]:
        job = config[name if name == "netns-mutation-run" else name + "-mutations"]
        assert job["rules"] in (MUTATION_RULES, SCHEDULE_RULES), name
        assert job.get("when", "on_success") == "on_success", name
        assert job.get("allow_failure", False) is False, name
    assert config[INTAKE_MUTATIONS]["rules"] == INTAKE_RULES
    for name, job in config.items():
        if isinstance(job, dict) and job.get("stage") == "post-review":
            assert not any("changes" in r for r in job.get("rules", [])), name


def check_no_manual_jobs(config):
    """No job of the parent is manual: nothing waits for someone to play it."""
    manual = set()
    for name, job in config.items():
        if name.startswith(".") or not isinstance(job, dict):
            continue
        rules = job.get("rules", [])
        if job.get("when") == "manual" or any(isinstance(r, dict) and r.get("when") == "manual" for r in rules):
            manual.add(name)
    assert not manual, manual


MR = {"CI_DEFAULT_BRANCH": "main", "CI_PIPELINE_SOURCE": "merge_request_event"}


def check_no_mutation_on_mr(config):
    """A merge request pipeline creates no mutation job, no job that runs a
    mutation script, and no trigger but the test child pipeline."""
    for extra in ({}, {"KEEP_FULL_CI": "1"}, {"CI_MERGE_REQUEST_LABELS": "full-ci"}):
        jobs = pipeline_jobs(config, MR | extra)
        assert jobs is not None, extra
        assert not {name for name in jobs if "mutation" in name}, (extra, sorted(jobs))
        assert not mutation_runners(config, jobs), (extra, mutation_runners(config, jobs))
        assert not {name for name in jobs if config[name].get("stage") in ("post-review", RELEASE_JOB)}, extra
        bridges = {name for name in jobs if "trigger" in config[name]}
        assert bridges == {"full-tests"}, (extra, bridges)


def tag_mutation_jobs(config):
    """The mutation jobs of a release tag pipeline: every post-review job, and any
    other job whose script runs a mutation suite."""
    tag = {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_TAG": "v1.0.0", "CI_PIPELINE_SOURCE": "push"}
    jobs = pipeline_jobs(config, tag) or set()
    return jobs, {name for name in jobs if config[name].get("stage") == "post-review"} | mutation_runners(config, jobs)


def check_release(config):
    """`release` runs only on a tag, alone in the last stage, without `needs`, so
    it starts only after every job of the earlier stages succeeded; every mutation
    job of the tag pipeline is among them and none can fail softly. (A `needs`
    list of the mutation jobs is refused by GitLab: shards count one by one, and
    there are more than 50.)"""
    stages = config["stages"]
    assert stages[-1] == RELEASE_JOB and stages.count(RELEASE_JOB) == 1, stages
    job = config[RELEASE_JOB]
    assert job["stage"] == RELEASE_JOB
    assert job["rules"] == [{"if": TAG_IF}], job["rules"]
    assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"
    assert job.get("interruptible") is False
    # Any `needs` (even `[]`) makes it start as soon as those are done, not the rest.
    assert "needs" not in job, job.get("needs")
    jobs, mutation = tag_mutation_jobs(config)
    assert RELEASE_JOB in jobs
    assert len(mutation) > 30, mutation
    for name in jobs - {RELEASE_JOB}:
        other = config[name]
        assert other.get("stage", "test") in stages[:-1], (name, other.get("stage"))
        assert other.get("allow_failure", False) is False, name
        assert other.get("when", "on_success") == "on_success", name
    for name in mutation:
        assert stages.index(config[name]["stage"]) < stages.index(RELEASE_JOB), name
    for name, other in config.items():
        if name != RELEASE_JOB and isinstance(other, dict):
            assert other.get("stage") != RELEASE_JOB, name


MUTATION_POOLS = 12


def check_mutation_fan_out_cap(config):
    """Every post-review mutation job on the shared runner joins one of the capped resource-group pools."""
    pools = {f"keep-mutation-pool-{i}" for i in range(1, MUTATION_POOLS + 1)}
    for name, job in config.items():
        if name.startswith(".") or not isinstance(job, dict) or job.get("stage") != "post-review":
            continue
        if name in TRIGGERS:  # no runner at all
            continue
        if job.get("tags") == ["keep-netns"]:  # its own privileged runner, not the shared queue
            continue
        if name == INTAKE_MUTATIONS:  # the one-slot keep-intake runner: a group of its own
            assert job.get("tags") == ["keep-intake"] and job.get("resource_group") == "keep-intake-browser-mutations", name
            continue
        if name == ROTATION_E2E_MUTATIONS:  # the docker+burst runners, one at a time with the e2e
            assert job.get("resource_group") == HEAVY_GROUPS["mesh-rotation-e2e"], (name, job.get("resource_group"))
            continue
        group = job.get("resource_group")
        if job.get("parallel"):
            assert group == "keep-mutation-pool-$CI_NODE_INDEX" and job["parallel"] <= MUTATION_POOLS, name
        else:
            assert group in pools, (name, group)


IMAGE_JOB = "image-build"
# The post-review jobs that read an earlier artifact, and the jobs they read it
# from; every other post-review job downloads none (`dependencies: []`).
POST_REVIEW_ARTIFACTS = {"tenancy-mutations": ["fmt-vet"]}


def check_post_review_artifacts(config):
    """Every post-review job names the artifacts it downloads (`dependencies` or
    `needs`), and none of them is the image tar: its artifact expires in an hour,
    and a job still waiting for a pool after that fails before it starts."""
    for name, job in config.items():
        if name.startswith(".") or not isinstance(job, dict) or job.get("stage") != "post-review":
            continue
        assert "dependencies" in job or "needs" in job, (
            f"{name}: post-review job without dependencies or needs downloads every earlier artifact")
        if name in TRIGGERS:  # pinned by check_post_review_gating and check_mutation_batch
            continue
        assert "needs" not in job, f"{name}: post-review job with needs"
        assert job["dependencies"] == POST_REVIEW_ARTIFACTS.get(name, []), (
            f"{name}: dependencies {job['dependencies']!r}")


def check_netns_mutation_run_manual_on_mr(config):
    """The netns mutation run is a mutation job too: never on an MR, automatic in schedules and on tags."""
    job = config["netns-mutation-run"]
    assert job["rules"] == SCHEDULE_RULES
    assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"


# Mutation suites run on a runner of their own, off the shared docker runners;
# the netns mutation run keeps its privileged keep-netns runner, and the rotation
# e2e mutation run the docker+burst runners its e2e needs.
MUTATION_RUNNER_TAGS = ["keep-mutations"]
ROTATION_E2E_MUTATIONS = "mesh-rotation-e2e-mutations"
MUTATION_RUNNER_JOBS = {name + "-mutations" for name in MUTATIONS} - {ROTATION_E2E_MUTATIONS}


def check_mutation_runner(config):
    """Mutation jobs, and only they, carry the dedicated mutation runner tag."""
    for name, job in config.items():
        if name.startswith(".") or not isinstance(job, dict) or name in ("default", "variables", "workflow"):
            continue
        tags = job.get("tags", [])
        if name in MUTATION_RUNNER_JOBS or (job.get("stage") == "post-review" and name not in (
                "netns-mutation-run", INTAKE_MUTATIONS, ROTATION_E2E_MUTATIONS) + TRIGGERS):
            assert tags == MUTATION_RUNNER_TAGS, name
        else:
            assert "keep-mutations" not in tags, name
    assert config["netns-mutation-run"]["tags"] == ["keep-netns"]
    assert config[INTAKE_MUTATIONS]["tags"] == ["keep-intake"]
    assert not any("tags" in config[n] for n in TRIGGERS)
    assert config["default"]["tags"] == ["docker"]
    assert config["mesh-rotation-e2e"]["tags"] == config[ROTATION_E2E_MUTATIONS]["tags"] == ["docker", "ci-burst"]
    # The dedicated runner never takes a merge request job.
    for name, job in config.items():
        if isinstance(job, dict) and job.get("tags") == MUTATION_RUNNER_TAGS:
            for rule in job.get("rules", []):
                if isinstance(rule, dict) and "merge_request_event" in str(rule.get("if", "")):
                    assert rule.get("when") == "never", name


def check_mesh_plugin_mutations(config):
    """The plugin's mutation script runs in shards after review, with the other
    mutation suites, blocking, and with a 40% margin under the job timeout per shard."""
    plugin, job = config["mesh-plugin"], config["mesh-plugin-mutations"]
    assert not mutation_runners(config, ["mesh-plugin"]), plugin["script"]
    assert "go test -race" in "\n".join(plugin["script"])
    assert job["rules"] == config[".mutation-schedule-rules"]["rules"], job["rules"]
    assert job["stage"] == "post-review"
    assert job["parallel"] == 3 and job["timeout"] == "20m"
    assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"
    assert job["dependencies"] == []
    assert job["resource_group"] == "keep-mutation-pool-$CI_NODE_INDEX"
    assert job["script"] == [
        "MUTATION_SHARD_INDEX=$CI_NODE_INDEX MUTATION_SHARD_TOTAL=$CI_NODE_TOTAL "
        "timeout -k 10s 19m ./scripts/check-mesh-plugin-mutations.sh"]


MUTATION_RUNNER_ANCHOR = "tags: &mutation-runner [keep-mutations]"


def job_blocks(text):
    """Top-level job name -> its raw YAML block (until the next top-level key)."""
    blocks, name, lines = {}, None, []
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9][\w./ -]*):\s*(#.*)?$", line)
        if m:
            if name is not None:
                blocks[name] = "\n".join(lines)
            name, lines = m.group(1).strip(), []
        elif name is not None:
            lines.append(line)
    if name is not None:
        blocks[name] = "\n".join(lines)
    return blocks


def check_mutation_runner_anchor(text):
    """The tag is written once, as the `.mutation-runner` anchor, and every mutation
    job takes it by reference, so the runner can be moved in one place."""
    assert text.count(MUTATION_RUNNER_ANCHOR) == 1
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert code.count("keep-mutations") == 1
    blocks = job_blocks(text)
    for name in MUTATION_RUNNER_JOBS:
        assert "tags: *mutation-runner" in blocks.get(name, ""), name


HEAVY_GROUPS = {"w3-stubs": "keep-w3-stubs", "mesh-rotation-e2e": "keep-mesh-rotation-e2e",
                "targets-loaders": "keep-targets-loaders", "e2e-w2": "keep-e2e-w2"}


def check_heavy_fan_out_cap(config, child):
    """Heavy jobs of the shared docker pool run one instance at a time per project."""
    for name, group in HEAVY_GROUPS.items():
        assert config[name].get("resource_group") == group, name
    assert child["test"].get("resource_group") == "keep-test-$TEST_SUITE"


def check_child_dag(config):
    """Early child may overlap lint; final build still observes every gate."""
    stages = config["stages"]
    assert stages == ["security", "lint", "test", "build", "post-review", "release"]
    generator, bridge, build = (config[name] for name in ("fmt-vet", "full-tests", "build"))
    assert bridge.get("needs") == [{"job": "fmt-vet", "artifacts": True}]
    assert bridge["trigger"]["strategy"] == "depend"
    assert bridge.get("allow_failure", False) is False
    assert bridge.get("when", "on_success") == "on_success"
    assert bridge["rules"] == build["rules"] == FULL_PIPELINE_ONLY
    assert generator["rules"] == FMT_VET_RULES
    # No DAG override may let fmt-vet bypass either security producer, or let
    # build bypass still-running lint, mutations or the child's bridge status.
    for job in (generator, build):
        assert "needs" not in job
        assert job.get("when", "on_success") == "on_success"
        assert job.get("allow_failure", False) is False
    assert generator["stage"] == "lint" and build["stage"] == "build"
    for name, job in config.items():
        if not isinstance(job, dict) or job.get("stage") not in ("security", "lint"):
            continue
        assert job.get("allow_failure", False) is False, name
        assert job.get("when", "on_success") == "on_success", name
    for name in MUTATIONS:
        job = config[name + "-mutations"]
        assert "needs" not in job, name  # preserve independent stage scheduling
        assert job.get("allow_failure", False) is False, name


def check_config(config, driver):
    gate = config["security-hygiene"]
    assert gate["stage"] == "security"
    assert gate["image"] == {"name": "$GITLEAKS_IMAGE", "entrypoint": [""]}
    assert gate["variables"]["GIT_DEPTH"] == 0
    assert gate["tags"] == ["ci-fast"]  # light gate: fast-lane runner
    assert gate["script"] == [driver]
    assert "rules" not in gate and "only" not in gate and "except" not in gate
    assert gate.get("allow_failure", False) is False
    assert gate.get("when", "on_success") == "on_success"
    assert config["variables"]["GITLEAKS_IMAGE"] == (
        "zricethezav/gitleaks:v8.30.1@sha256:"
        "c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f")
    assert "allow_failure" not in config["default"]
    assert "set -eu" in driver
    calls = [line for line in driver.splitlines() if line.startswith("./scripts/")]
    assert calls == ["./scripts/" + name for name in GATES]
    assert "||" not in driver and "set +e" not in driver
    for name in ("fmt-vet", "golangci-lint", "import-boundaries", "ci-selftests"):
        assert config[name]["stage"] == "lint", name
    for name in ("fmt-vet", "golangci-lint"):
        assert config[name]["tags"] == ["ci-fast"], name  # light lint gate: fast lane
    # minutes of CPU each: burst pool, so they do not hold fast-lane slots
    assert config["import-boundaries"]["tags"] == ["ci-burst"]
    assert config["ci-selftests"]["tags"] == ["docker", "ci-burst"]
    scope = config["secret-scan-scope-selftest"]
    assert scope["stage"] == "security"
    assert scope["image"] == gate["image"]
    assert scope["script"] == ["./scripts/check-secret-scan-scope.sh"]
    assert scope["tags"] == ["ci-fast"]
    assert scope.get("allow_failure", False) is False
    assert scope["rules"] == [
        {"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'},
        {"if": "$CI_COMMIT_BRANCH"}]
    workflow = config["workflow"]
    assert workflow["rules"][0] == {"if": BATCH_IF + " && $CI_COMMIT_BRANCH",
                                    "variables": {"KEEP_PIPELINE_NAME": "mutation-batch"},
                                    "auto_cancel": {"on_new_commit": "none"}}
    main, _, mr = workflow["rules"][1:4]
    assert main["if"] == "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"
    assert main["auto_cancel"]["on_new_commit"] == "none"
    assert mr["if"] == '$CI_PIPELINE_SOURCE == "merge_request_event"'
    assert mr["auto_cancel"]["on_new_commit"] == "interruptible"
    assert workflow["rules"][4] == {
        "if": '$CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS && $CI_PIPELINE_SOURCE == "push"',
        "when": "never"}
    assert workflow["rules"][5] == {
        "if": '$CI_COMMIT_BRANCH && $CI_PIPELINE_SOURCE == "push"',
        "variables": {"KEEP_BRANCH_PUSH_SCAN_ONLY": "true"}}
    assert workflow["rules"][6:] == [{"if": "$CI_COMMIT_BRANCH"},
                                     {"if": TAG_IF, "auto_cancel": {"on_new_commit": "none"}}]
    trigger = config["full-tests"]
    assert trigger["trigger"]["strategy"] == "depend"
    assert trigger.get("allow_failure", False) is False
    assert trigger["trigger"]["include"] == [{"artifact": "full-tests.generated.yml", "job": "fmt-vet"}]
    generator = config["fmt-vet"]
    assert generator["variables"]["GIT_DEPTH"] == 0
    assert "python3 scripts/test_ci_config.py" in generator["script"]
    assert "python3 scripts/test_ci_play_gate.py" in generator["script"]
    assert "python3 scripts/test_mutation_canary.py" in generator["script"]
    assert "./scripts/check-lint-directives.sh" in generator["script"]
    assert "go vet ./..." in generator["script"]
    assert "python3 scripts/generate-test-pipeline.py full-tests.generated.yml" in generator["script"]
    assert "python3 scripts/mutation-canary.py prepare" in generator["script"]
    assert generator["artifacts"]["paths"] == ["full-tests.generated.yml", "mutation-canary.decision"]
    check_selftests_job(config)
    check_import_boundaries_job(config)
    assert "full-tests.generated.yml" in generator["artifacts"]["paths"]
    assert {name.removesuffix("-mutations") for name in config
            if name.endswith("-mutations") and name != INTAKE_MUTATIONS} == MUTATIONS
    for name in MUTATIONS:
        assert config[name + "-mutations"].get("allow_failure", False) is False
    check_mutations_never_on_mr(config)
    check_no_manual_jobs(config)
    check_no_mutation_on_mr(config)
    check_release(config)
    check_mutation_fan_out_cap(config)
    check_post_review_artifacts(config)
    check_netns_mutation_run_manual_on_mr(config)
    check_mutation_runner(config)
    check_mesh_plugin_mutations(config)
    capture = config["providertest-mutations"]
    assert capture["stage"] == "post-review"
    assert capture["script"] == ["timeout -k 10s 9m ./scripts/check-providertest-mutations.sh"]
    assert capture["rules"] == MUTATION_RULES
    assert "only" not in capture and "except" not in capture
    assert capture.get("when", "on_success") == "on_success"
    dispatch = config["dispatch-mutations"]
    assert dispatch["stage"] == "post-review"
    assert dispatch.get("timeout") == "20m"
    assert dispatch["script"] == ["timeout -k 10s 19m ./scripts/check-dispatch-mutations.sh"]
    assert dispatch.get("when", "on_success") == "on_success"
    carriers = config["carriers-mutations"]
    assert carriers.get("parallel") == 4
    assert carriers.get("timeout") == "20m"
    assert carriers["script"] == [
        "MUTATION_SHARD_INDEX=$CI_NODE_INDEX MUTATION_SHARD_TOTAL=$CI_NODE_TOTAL "
        "timeout -k 10s 19m ./scripts/check-carriers-mutations.sh"]
    assert carriers.get("when", "on_success") == "on_success"
    assert carriers["rules"] == MUTATION_RULES
    assert "only" not in carriers and "except" not in carriers


# The self-tests moved out of fmt-vet into ci-selftests, in their order.
SELFTESTS = [
    "python3 scripts/test_mutation_shards.py",
    "python3 scripts/test_carriers_mutations.py",
    "python3 scripts/test_intake_baseline_diagnostics.py",
    "python3 scripts/test_intake_mutant_diagnostics.py",
    "python3 scripts/test_catalog_mutant_diagnostics.py",
    "python3 scripts/test_runnerproto_mutations.py",
    "python3 scripts/test_tenancy_mutations.py",
    "python3 scripts/test_cli_mutation_witnesses.py",
    "python3 scripts/test_approvals_baseline_diagnostics.py",
    "KEEP_JOB_CACHE_REAL_TIMEOUT=1 python3 scripts/test_builtin_job_cache.py",
    "./scripts/check-baseline-diag.sh",
    "python3 scripts/test_w3_stubs_diagnostics.py",
    "python3 scripts/test_dispatch_baseline_diagnostics.py",
    "python3 scripts/test_mutation_select.py",
    "./scripts/check-mutation-select-redrun.sh",
]
SELFTESTS_APK = "apk add --no-cache bash git python3 py3-yaml perl tar"
SCAN_ONLY_NEVER = {"if": '$KEEP_BRANCH_PUSH_SCAN_ONLY == "true"', "when": "never"}
# Go sources test_mutation_shards.py copies for the identity-attack suite.
IDENTITY_ATTACK_SOURCES = [
    "internal/identity/" + name for name in
    ("token.go", "repo.go", "middleware.go", "rights.go", "principal.go")] + [
    "internal/obs/obs.go", "internal/testutil/canary/canary.go",
    "test/security/identity_attack_test.go"]


def gitlab_glob(pattern, path):
    """`changes:` matching as GitLab does it (File.fnmatch? with FNM_PATHNAME
    and FNM_DOTMATCH): `*` stops at `/`, `**/` spans zero or more directories.
    Python's fnmatch lets `*` cross `/` and makes `a/**/*` miss `a/x`, so it
    cannot answer whether a path is covered."""
    assert not set(pattern) & set("{}[]"), pattern
    regex, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            regex, i = regex + "(?:[^/]*/)*", i + 3
        elif pattern[i] == "*":
            regex, i = regex + "[^/]*", i + 1
        elif pattern[i] == "?":
            regex, i = regex + "[^/]", i + 1
        else:
            regex, i = regex + re.escape(pattern[i]), i + 1
    return re.fullmatch(regex, path) is not None


def mr_changes(job):
    rules = [r for r in job["rules"] if r.get("if") == MR_IF and "changes" in r]
    assert len(rules) == 1, rules
    return rules[0]["changes"]


def uncovered(changes, paths):
    return sorted(p for p in paths if not any(gitlab_glob(c, p) for c in changes))


def selftest_sources(root=ROOT):
    """Go sources (and the one migration) the moved self-tests copy from the tree."""
    sources = set(IDENTITY_ATTACK_SOURCES)
    for suite in ("tenancy", "carriers"):
        text = (root / f"scripts/check-{suite}-mutations.sh").read_text()
        found = set(re.findall(r"^mutate \S+ (\S+)", text, re.M))
        assert found, suite
        sources |= found
    sources |= {str(p.relative_to(root)) for p in (root / "cmd/keep").glob("*test.go")}
    return sources


def check_selftests_job(config):
    """ci-selftests: a light lint gate off the fmt-vet critical path that still
    runs everywhere it ran before, except on an MR that touches none of its inputs."""
    job = config["ci-selftests"]
    assert job["stage"] == "lint" and job["tags"] == ["docker", "ci-burst"]
    assert job["extends"] == ".go-module-cache"
    assert job["before_script"] == [SELFTESTS_APK], job["before_script"]
    assert job["script"] == SELFTESTS, job["script"]
    assert not set(SELFTESTS) & set(config["fmt-vet"]["script"])
    assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"
    assert "needs" not in job and "dependencies" not in job
    rules = job["rules"]
    assert rules[:2] == [BATCH_NEVER, SCAN_ONLY_NEVER], rules
    assert rules[2] == {"if": MR_IF + " && $KEEP_FULL_CI"}, rules
    assert set(rules[3]) == {"if", "changes"} and rules[3]["if"] == MR_IF, rules
    assert rules[4:] == [{"if": MR_IF, "when": "never"}, {"when": "on_success"}], rules
    changes = mr_changes(job)
    paths = {".gitlab-ci.yml", ".gitlab/ci/full-tests.yml", "go.mod", "go.sum",
             "scripts/mutation-helpers.sh", "scripts/lib/gocache.sh"}
    paths |= {line.split()[-1].removeprefix("./") for line in SELFTESTS}
    paths |= selftest_sources()
    assert not uncovered(changes, paths), uncovered(changes, paths)
    # Nothing waits for it: no job takes it as a need or an artifact source.
    for name, other in config.items():
        if not isinstance(other, dict):
            continue
        needs = [n["job"] if isinstance(n, dict) else n for n in other.get("needs", [])]
        assert "ci-selftests" not in needs + list(other.get("dependencies", [])), name


IMPORT_BOUNDARIES = "scripts/check-import-boundaries.sh"
PROBE_FUNCS = ("probe", "allow", "call", "directive", "depdirective", "nocompile", "allow_test",
               "crypto_call", "check_enabled")
MODULE = "github.com/entire-vc/evc-keep/"


def probe_locations(text):
    """Every repo path a probe of check-import-boundaries.sh plants a file in,
    edits, stubs or imports from the module."""
    paths = {"scripts/check-lint-directives.sh", "scripts/lint/descriptor-sign.go",
             "scripts/mutation-helpers.sh", "scripts/temp-workspace.sh", IMPORT_BOUNDARIES}
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    for imported in re.findall(r"(?:\$m/|" + re.escape(MODULE) + r")([\w./-]+)", code):
        paths.add(imported.rstrip("/") + "/x.go")
    calls = 0
    for line in code.splitlines():
        head = line.split(" ", 1)[0]
        if head not in PROBE_FUNCS or line.startswith(head + "()"):
            continue
        calls += 1
        if head in ("nocompile", "check_enabled"):  # scratch package / no location
            continue
        a = shlex.split(line)
        dirs = {"probe": a[3:4] + a[5:6], "allow": a[2:3] + a[4:5], "call": a[3:4],
                "allow_test": a[2:3], "crypto_call": a[3:4],
                "directive": a[3:4] or ["internal/catalog"], "depdirective": a[3:4]}[head]
        for d in dirs:
            paths.add(d + "/zz_boundary_probe.go")
        if head == "crypto_call":
            paths.add(a[3] + "/" + a[4])
    assert calls > 100, calls
    return paths


DEPGUARD_DIRECTIVE_FORMS = ("nolint-depguard", "nolint-bare", "nolint-all", "nolint-list", "nolint-upper",
                            "nolint-block", "nolint-file", "line-before-package", "line-block-before-package")
GUARD_NAMES_PROBE = 'if [ $guard = fail ] && grep -q "zz_boundary_probe.go" "$work/guard.out"; then'


def check_directive_probes(text):
    """The directive probes keep their red-run property: each passes only when
    check-lint-directives.sh rejects the probe file by name, and the depguard
    forms stay probed for both the secret-value and plaintext-digest rules."""
    for func in ("directive", "depdirective"):
        # A heredoc's closing "}" sits at column 0 too, followed by GO.
        body = re.search(r"^" + func + r"\(\) \{\n(.*?)^\}\n(?!GO\n)", text, re.M | re.S)
        assert body, func
        assert '"$work/tree/scripts/check-lint-directives.sh" "$work/tree" >"$work/guard.out"' in body.group(1), func
        assert GUARD_NAMES_PROBE in body.group(1), func
    calls = {}
    for line in text.splitlines():
        if line.startswith("depdirective "):
            a = shlex.split(line)
            calls[a[1]] = a[2]
    for rule in ("secret-value", "plaintext-digest"):
        for form in DEPGUARD_DIRECTIVE_FORMS:
            assert calls.get(rule + "-" + form) == rule, (rule, form)


def lint_directive_guard_run(pattern_edit, probes):
    """Run scripts/check-lint-directives.sh, with PATTERN_EDIT applied to its
    text, once per depdirective probe on a tree holding only go.mod and that
    probe's file (written as depdirective writes it). Return the names of the
    probes the guard did not reject by file name."""
    guard = (ROOT / "scripts/check-lint-directives.sh").read_text()
    edited = pattern_edit(guard)
    missed = set()
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "guard.sh"
        script.write_text(edited)
        for name, _rule, d, imp, head, tail in probes:
            tree = Path(tmp) / name
            (tree / d).mkdir(parents=True)
            (tree / "go.mod").write_text("module example.com/probe\n")
            src = (head + "\n" if head else "") + "package %s\n\nimport _ \"%s\"" % (os.path.basename(d), imp)
            (tree / d / "zz_boundary_probe.go").write_text(src + (" " + tail if tail else "") + "\n")
            r = subprocess.run(["sh", str(script), str(tree)], capture_output=True, text=True)
            if r.returncode != 1 or "zz_boundary_probe.go" not in r.stdout:
                missed.add(name)
    return missed


def depdirective_calls(text):
    calls = []
    for line in text.splitlines():
        if line.startswith("depdirective "):
            a = shlex.split(line.replace("$m/", MODULE))
            calls.append(tuple(a[1:6]) + (a[6] if len(a) > 6 else "",))
    return calls


def check_probe_functions_take_a_shard(text):
    """Every probe-like function starts by taking its shard number, and the
    script defines no probe function that this check does not know."""
    defined = re.findall(r"^(\w+)\(\) \{\n[ \t]*(.*)$", text, re.M)
    names = {name for name, _ in defined}
    assert names == set(PROBE_FUNCS) | {"shard_take"}, names
    for name, first in defined:
        if name != "shard_take":
            assert first == "shard_take || return 0", (name, first)


def check_import_boundaries_job(config, text=None):
    text = text if text is not None else (ROOT / IMPORT_BOUNDARIES).read_text()
    job = config["import-boundaries"]
    assert job.get("parallel") == 4, job.get("parallel")
    assert "timeout -k 10s 19m ./" + IMPORT_BOUNDARIES in job["script"]
    assert "./scripts/check-lint-directives.sh" not in job["script"]  # whole-tree gate lives in fmt-vet
    assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"
    assert job["rules"][:3] == [BATCH_NEVER, {"if": '$CI_PIPELINE_SOURCE == "schedule"'},
                                {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"}], job["rules"]
    changes = mr_changes(job)
    missing = uncovered(changes, probe_locations(text) | {".golangci.yml", ".gitlab-ci.yml", "go.mod", "go.sum"})
    assert not missing, missing
    check_probe_functions_take_a_shard(text)
    check_directive_probes(text)


GO_CACHE_JOBS = {name + "-mutations" for name in MUTATIONS} | {
    "fmt-vet", "ci-selftests", "w3-stubs", "targets-loaders", "build"}
# Go jobs on the Debian image (cgo with glibc, as their e2e or plugin tests need).
BOOKWORM_JOBS = {"targets-loaders", "mesh-plugin-mutations", "mesh-rotation-e2e-mutations"}
GO_IMAGE_ALPINE = ("golang:1.25.14-alpine3.24@sha256:"
                   "1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59")
GO_IMAGE_BOOKWORM = ("golang:1.25.14-bookworm@sha256:"
                     "3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437")
LINT_IMAGE = ("golangci/golangci-lint:$GOLANGCI_LINT_VERSION-alpine@sha256:"
              "91b27804074a0bacea298707f016911e60cf0cdbc6c7bf5ccacb5f0606d18d60")


def check_go_cache(config, child):
    for name, image in [(".go-module-cache", GO_IMAGE_ALPINE),
                        (".go-module-cache-bookworm", GO_IMAGE_BOOKWORM)]:
        template = config[name]
        assert template == child[name], name
        assert template["image"] == image, name
        assert template["variables"] == {"GOMODCACHE": "$CI_PROJECT_DIR/.gomodcache"}, name
        assert template["cache"] == {
            "key": {"files": ["go.mod", "go.sum"],
                    "prefix": "go-1.25.14-linux-amd64"},
            "paths": [".gomodcache/"], "policy": "pull"}, name
    assert config[".go-module-cache-publisher"] == {
        "extends": ".go-module-cache", "cache": {"policy": "pull-push"}}
    assert config["fmt-vet"]["extends"] == ".go-module-cache-publisher"
    assert config["fmt-vet"]["script"][:2] == ["go mod download", "go mod verify"]
    for name in GO_CACHE_JOBS - {"fmt-vet"}:
        job = config[name]
        template = ".go-module-cache-bookworm" if name in BOOKWORM_JOBS else ".go-module-cache"
        assert job.get("extends") == template, name
        assert "cache" not in job and "image" not in job, name
    for name, template in [("test", ".go-module-cache"),
                           ("intake-browser", ".go-module-cache-bookworm")]:
        job = child[name]
        assert job.get("extends") == template, name
        if name == "intake-browser":
            # Publish the inherited module cache without replacing its key/paths.
            assert job.get("cache") == {"policy": "pull-push"}, name
        else:
            assert "cache" not in job, name
        if name == "intake-browser":
            assert re.fullmatch(
                r"\$CI_REGISTRY_IMAGE/ci/intake-browser@sha256:[0-9a-f]{64}",
                job.get("image", "")), name
            assert job["before_script"] == [
                'test "$(node --version)" = v22.22.3',
                "go version && chromium --version && python3 --version"], name
        else:
            assert "image" not in job, name
    for pipeline in (config, child):
        # Global and default variables are inherited by every Go job. Checking
        # only job-level variables would miss a shared compiled-build cache.
        assert "GOCACHE" not in pipeline.get("variables", {}), "global variables"
        assert "cache" not in pipeline, "global cache"
        defaults = pipeline.get("default", {})
        assert "GOCACHE" not in defaults.get("variables", {}), "default variables"
        assert "cache" not in defaults, "default cache"
        allowed_cache_owners = {".go-module-cache", ".go-module-cache-bookworm", ".golangci-module-cache"}
        if pipeline is config:
            allowed_cache_owners.add(".go-module-cache-publisher")
        else:
            allowed_cache_owners.add("intake-browser")

        publisher_roots = {".go-module-cache-publisher"} if pipeline is config else {"intake-browser"}
        allowed_publishers = {"fmt-vet", ".go-module-cache-publisher"} if pipeline is config else {"intake-browser"}

        def inherits_publisher(name, seen=()):
            assert name not in seen, name
            if name in publisher_roots:
                return True
            job = pipeline.get(name, {})
            parents = job.get("extends", []) if isinstance(job, dict) else []
            if isinstance(parents, str):
                parents = [parents]
            return any(inherits_publisher(parent, (*seen, name)) for parent in parents)

        for name, job in pipeline.items():
            if isinstance(job, dict) and name not in ("variables", "default"):
                assert "GOCACHE" not in job.get("variables", {}), name
                assert ".gocache/" not in job.get("cache", {}).get("paths", []), name
                assert "cache" not in job or name in allowed_cache_owners, name
                if name not in allowed_publishers:
                    assert not inherits_publisher(name), name
    for name in ("golangci-lint", "import-boundaries"):
        assert config[name]["image"] == LINT_IMAGE, name


def rule_matches(expression, context):
    """Evaluate the `if:` subset this config uses: `&&` of `$A`, `$A == $B`, `$A == "x"`.

    Anything else raises, so a new operator cannot be silently misread.
    """
    def value(token):
        token = token.strip()
        if token.startswith("$"):
            return context.get(token[1:])
        if len(token) >= 2 and token[0] == token[-1] == '"':
            return token[1:-1]
        raise ValueError("unsupported operand: " + token)

    for unsupported in ("||", "(", ")", "!=", "=~", "!~"):
        if unsupported in expression:
            raise ValueError("unsupported rule expression: " + expression)
    for term in expression.split("&&"):
        if "==" in term:
            left, right = term.split("==")
            if value(left) != value(right):
                return False
        elif not value(term):
            return False
    return True


def first_rule(rules, context):
    """GitLab semantics: the first rule whose `if` matches (or has no `if`) wins.

    `changes` is treated as matching: the scenarios below ask which jobs can
    run in a pipeline, not which paths select them.
    """
    return next((rule for rule in rules
                 if "if" not in rule or rule_matches(rule["if"], context)), None)


def pipeline_jobs(config, context):
    """Jobs that can run for `context`, or None when the workflow creates no pipeline."""
    rule = first_rule(config["workflow"]["rules"], context)
    if rule is None or rule.get("when") == "never":
        return None
    context = context | rule.get("variables", {})
    jobs = set()
    for name, job in config.items():
        if (name.startswith(".") or not isinstance(job, dict)
                or name in ("workflow", "variables", "default")):
            continue
        if "rules" not in job:
            jobs.add(name)
            continue
        selected = first_rule(job["rules"], context)
        if selected is not None and selected.get("when", "on_success") != "never":
            jobs.add(name)
    return jobs


# Path-filtered merge request jobs that the default-branch push does not run.
MR_AND_SCHEDULE_ONLY = {"mesh-plugin", "mesh-rotation-e2e"}
TOPIC = {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "topic", "CI_COMMIT_REF_NAME": "topic"}
MAIN = {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "main", "CI_COMMIT_REF_NAME": "main"}


def mutation_runners(config, jobs):
    """Jobs among `jobs` whose script runs a mutation suite, whatever the job is called."""
    return {name for name in jobs
            if re.search(r"check-[\w-]*mutations\.sh", "\n".join(map(str, config[name].get("script", []))))}


ANCHORS_JOB = "mutant-anchors"
ANCHORS_MR_RUN = "MUTANT_ANCHORS_BASE=$CI_MERGE_REQUEST_DIFF_BASE_SHA timeout -k 10s 12m ./scripts/check-mutant-anchors.sh"


def check_mutant_anchors(config, root=ROOT):
    """The apply-only anchor check runs on every merge request as a hard gate,
    before review, through its driver only; every mutation suite supports it."""
    job = config[ANCHORS_JOB]
    for extra in ({}, {"KEEP_FULL_CI": "1"}):
        assert ANCHORS_JOB in pipeline_jobs(config, MR | extra), extra
    assert ANCHORS_JOB in pipeline_jobs(config, MAIN | {"CI_PIPELINE_SOURCE": "push"})
    assert job["stage"] not in ("post-review", RELEASE_JOB), job["stage"]
    assert job.get("allow_failure", False) is False
    assert job.get("when", "on_success") == "on_success"
    assert not any(isinstance(r, dict) and ("changes" in r or r.get("when") == "manual")
                   for r in job.get("rules", [])), job.get("rules")
    script = "\n".join(map(str, job["script"]))
    assert ANCHORS_MR_RUN in script, script
    assert "./scripts/check-mutant-anchors-selftest.sh" in script, script
    # The suites run only through the driver, which forces apply-only mode.
    assert not mutation_runners(config, {ANCHORS_JOB}), script
    assert "MUTATION_APPLY_ONLY" not in script + str(job.get("variables", {})), script
    assert "MUTATION_APPLY_ONLY=1" in (root / "scripts/check-mutant-anchors.sh").read_text()
    for path in sorted(p for p in (root / "scripts").glob("*-mutations.sh") if p.name != "mutation-helpers.sh"):
        text = path.read_text()
        assert re.search(r"mutation_appl(ied|y_only)|MUTATION_APPLY_ONLY|no source anchors", text), path.name


def check_branch_push_scope(config):
    """One full pipeline per MR SHA; every other pipeline kind keeps its coverage."""
    # The open-MR rule is evaluated when the push pipeline is created. An MR
    # opened right after the push (push option or `glab mr create`) is not
    # visible yet, so this context is the duplicate of the later MR pipeline.
    push = pipeline_jobs(config, TOPIC | {"CI_PIPELINE_SOURCE": "push"})
    assert push == SCAN_ONLY_JOBS, push
    assert pipeline_jobs(config, TOPIC | {"CI_PIPELINE_SOURCE": "push",
                                          "CI_OPEN_MERGE_REQUESTS": "entire-vc/evc-keep!1"}) is None
    mr = pipeline_jobs(config, MR)
    full = mr
    heavy = {"fmt-vet", "golangci-lint", "full-tests", "w3-stubs", "build", "carriers-mutations"}
    every_mutation = {name + "-mutations" for name in MUTATIONS}
    post_review = every_mutation | {"netns-mutation-run", INTAKE_MUTATIONS}
    # On an MR no mutation job runs at all.
    assert SCAN_ONLY_JOBS | (heavy - every_mutation) <= mr, mr
    assert not mr & post_review, mr & post_review
    assert not mutation_runners(config, mr), mutation_runners(config, mr)
    # The push to the default branch runs every ordinary check but no mutation
    # job; the plugin's own tests run on the merge requests that touch it and
    # in the schedule, as before.
    main_push = pipeline_jobs(config, MAIN | {"CI_PIPELINE_SOURCE": "push"})
    assert main_push is not None and (
        full - every_mutation - MR_AND_SCHEDULE_ONLY <= main_push), main_push
    assert not main_push & every_mutation, main_push & every_mutation
    # The intake browser suites keep the main push they had inside intake-browser.
    assert mutation_runners(config, main_push) == {INTAKE_MUTATIONS}, mutation_runners(config, main_push)
    assert RELEASE_JOB not in main_push
    for context in [MAIN | {"CI_PIPELINE_SOURCE": "schedule"},
                    TOPIC | {"CI_PIPELINE_SOURCE": "schedule"}]:
        jobs = pipeline_jobs(config, context)
        assert jobs is not None and full | post_review <= jobs, (context, jobs)
        assert RELEASE_JOB not in jobs, context
    for source in ("web", "api"):
        for extra in ({}, {"CI_OPEN_MERGE_REQUESTS": "entire-vc/evc-keep!1"}):
            jobs = pipeline_jobs(config, TOPIC | {"CI_PIPELINE_SOURCE": source} | extra)
            assert jobs is not None and SCAN_ONLY_JOBS | heavy <= jobs, (source, jobs)
    # A release tag runs the full set, as the schedule does, and then `release`.
    tag = {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_TAG": "v1.0.0", "CI_PIPELINE_SOURCE": "push"}
    jobs = pipeline_jobs(config, tag)
    assert jobs is not None and post_review <= jobs, (jobs, post_review - (jobs or set()))
    assert {"security-hygiene", "fmt-vet", "full-tests", "build", RELEASE_JOB} <= jobs, jobs


BATCH = MAIN | {"CI_PIPELINE_SOURCE": "schedule", "KEEP_MUTATION_BATCH": "true"}
# The mutation batch runs the secret scan, fmt-vet (tenancy-mutations reads its
# artifact) and its own three jobs; the post-review jobs run in its child.
BATCH_JOBS = SCAN_ONLY_JOBS | {"fmt-vet", RANGE_JOB, BATCH_TRIGGER, GREEN_JOB}
GREEN_RULES = [{"if": BATCH_IF, "variables": {"KEEP_MUTATION_GREEN": "head"}},
               {"if": '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $CI_PIPELINE_SOURCE == "schedule"',
                "variables": {"KEEP_MUTATION_GREEN": "head"}},
               {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", "variables": {"KEEP_MUTATION_GREEN": "carry"}}]


def check_mutation_batch(config):
    """The batch runs only its own jobs and the post-review jobs of its range;
    every successful pipeline of the default branch keeps the green commit."""
    assert config["workflow"]["name"] == "$KEEP_PIPELINE_NAME"
    for context in (BATCH, TOPIC | {"CI_PIPELINE_SOURCE": "api", "KEEP_MUTATION_BATCH": "true"}):
        rule = first_rule(config["workflow"]["rules"], context)
        assert rule.get("variables") == {"KEEP_PIPELINE_NAME": "mutation-batch"}, rule
        assert rule.get("auto_cancel", {}).get("on_new_commit") == "none", rule
        jobs = pipeline_jobs(config, context)
        assert jobs == BATCH_JOBS, (context, jobs ^ BATCH_JOBS)
    # No other pipeline runs the range or its trigger, or is named.
    others = [MAIN | {"CI_PIPELINE_SOURCE": s} for s in ("push", "schedule", "web")]
    others += [TOPIC | {"CI_PIPELINE_SOURCE": "push"}, {"CI_DEFAULT_BRANCH": "main", "CI_PIPELINE_SOURCE": "merge_request_event"},
               {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_TAG": "v1.0.0", "CI_PIPELINE_SOURCE": "push"}]
    for context in others:
        jobs = pipeline_jobs(config, context)
        assert not jobs & {RANGE_JOB, BATCH_TRIGGER}, (context, jobs)
        assert "variables" not in first_rule(config["workflow"]["rules"], context) or \
            "KEEP_PIPELINE_NAME" not in first_rule(config["workflow"]["rules"], context)["variables"], context
        # Every pipeline of the default branch keeps (or carries) the green commit; nothing else does.
        assert (GREEN_JOB in jobs) == (context.get("CI_COMMIT_BRANCH") == "main"), (context, jobs)
    select, trigger, green = (config[n] for n in (RANGE_JOB, BATCH_TRIGGER, GREEN_JOB))
    assert select["stage"] == "test" and select["rules"] == [{"if": BATCH_IF}]
    assert select["variables"]["GIT_DEPTH"] == 0
    run, fallback = select["script"][0].split(" || ", 1)
    assert run == "python3 scripts/mutation-range.py --json mutation-select.json", run
    assert "rm -f mutation-select.json" in fallback and "exit" not in fallback, fallback
    assert select["script"][1:] == ["python3 scripts/generate-mutation-pipeline.py mutation-select.json "
                                    "mutations.generated.yml mutation-select.txt"]
    assert set(select["artifacts"]["paths"]) >= {"mutation-select.json", "mutations.generated.yml"}
    assert trigger["stage"] == "post-review" and trigger["rules"] == [{"if": BATCH_IF}]
    assert trigger["needs"] == [{"job": RANGE_JOB, "artifacts": True}, {"job": "fmt-vet", "artifacts": False}]
    assert trigger["trigger"] == {"include": [{"artifact": "mutations.generated.yml", "job": RANGE_JOB}],
                                  "strategy": "depend"}
    assert trigger.get("variables") == {"PARENT_PIPELINE_ID": "$CI_PIPELINE_ID"}
    for job in (select, trigger, green):
        assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"
    # .post: it runs only once every other job of the pipeline passed.
    assert green["stage"] == ".post" and "needs" not in green and green["dependencies"] == []
    assert green["rules"] == GREEN_RULES, green["rules"]
    assert green["artifacts"]["paths"] == ["mutation-green.sha"]


def run_green(config, mode, wget=None):
    """Run mutation-green's script in a scratch directory; (exit code, kept file or None)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "bin").mkdir()
        fake = root / "bin" / "wget"
        fake.write_text("#!/bin/sh\n" + (wget or "exit 8") + "\n")
        fake.chmod(0o755)
        env = {"PATH": f"{root / 'bin'}:/usr/bin:/bin", "KEEP_MUTATION_GREEN": mode, "CI_COMMIT_SHA": "c" * 40,
               "CI_COMMIT_REF_NAME": "main", "CI_API_V4_URL": "http://127.0.0.1:9/api/v4", "CI_PROJECT_ID": "1",
               "CI_JOB_TOKEN": "x"}
        run = subprocess.run(["sh", "-c", "\n".join(config[GREEN_JOB]["script"])], cwd=root, env=env,
                             capture_output=True, text=True)
        kept = root / "mutation-green.sha"
        return run.returncode, kept.read_text() if kept.exists() else None


# Jobs that may not be cancelled by a newer push, by name: only `release`, on a
# tag. A job whose script has such a side effect must be listed here AND set
# `interruptible: false`.
NON_INTERRUPTIBLE = {RELEASE_JOB}
# Any of these words in a job's name or script makes it a suspected side-effect job
# (wrappers like ./scripts/publish.sh included). Jobs that only run mutation checks
# of deploy code, and image-build/image-build-mesh (kaniko builds that never push), are the named false positives.
SIDE_EFFECT = re.compile(r"\b(deploy|release|publish|upload|push|tag|registry)\b", re.I)
SIDE_EFFECT_FALSE_POSITIVES = {"deploy-api-mutations", "deploy-mutations", "image-build", "image-build-mesh", "deploy-smoke"}

def effective_interruptible(config, job, default, seen=()):
    """`interruptible` as GitLab resolves it: own key, then `extends` (later wins), then default."""
    if "interruptible" in job:
        return job["interruptible"]
    parents = job.get("extends", [])
    for parent in reversed([parents] if isinstance(parents, str) else parents):
        if parent in seen or not isinstance(config.get(parent), dict):
            continue
        value = effective_interruptible(config, config[parent], None, seen + (parent,))
        if value is not None:
            return value
    inherit = job.get("inherit", {}).get("default", True)
    if inherit is False or (isinstance(inherit, list) and "interruptible" not in inherit):
        return False
    return default

def merged_script(config, job, seen=()):
    """Script lines of the job plus those it inherits through `extends`."""
    lines = [str(x) for x in job.get("script", [])]
    parents = job.get("extends", [])
    for parent in ([parents] if isinstance(parents, str) else parents):
        if parent not in seen and isinstance(config.get(parent), dict):
            lines += merged_script(config, config[parent], seen + (parent,))
    return lines

def interruptible_violations(config):
    """Jobs whose effective `interruptible` contradicts the contract."""
    default = config.get("default", {}).get("interruptible", False)
    bad = []
    for name, job in config.items():
        if name.startswith(".") or not isinstance(job, dict) or not (merged_script(config, job) or "trigger" in job):
            continue
        effective = effective_interruptible(config, job, default)
        text = name + "\n" + "\n".join(merged_script(config, job))
        suspect = SIDE_EFFECT.search(text) and name not in SIDE_EFFECT_FALSE_POSITIVES
        if name in NON_INTERRUPTIBLE or suspect:
            if effective is not False or name not in NON_INTERRUPTIBLE:
                bad.append(name)
        elif effective is not True:
            bad.append(name)
    return bad


class CIConfig(unittest.TestCase):
    @staticmethod
    def backtest_module():
        spec = importlib.util.spec_from_file_location(
            "mutation_backtest", ROOT / "scripts/mutation-select-backtest.py")
        backtest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(backtest)
        return backtest

    def test_core_shard_timeout_marker_for_gnu_and_busybox_codes(self):
        child = yaml.safe_load((ROOT / ".gitlab/ci/full-tests.yml").read_text())
        script = "\n".join(str(x) for x in child["test"]["script"])
        guard = next(l.strip() for l in script.splitlines() if l.strip().startswith('if [ "$rc"'))
        for rc, marked in ((124, True), (143, True), (1, False), (0, False)):
            out = subprocess.run(["sh", "-c", f'rc={rc}; TEST_SUITE=core-1; {guard.removesuffix("; fi")}; fi'],
                                 capture_output=True, text=True).stdout
            self.assertEqual("CI-TIMEOUT" in out, marked, (rc, out))

    def test_backtest_builtin_wrapper_crosswalk(self):
        backtest = self.backtest_module()
        text = (ROOT / ".gitlab-ci.yml").read_text()
        expected = {"builtin", "intake-receiver", "intake-service"}
        self.assertEqual(backtest.job_scripts(text).get("builtin-mutations"), expected)
        command = "    - ./scripts/run-builtin-mutation-job.sh\n"
        self.assertEqual(text.count(command), 1)
        legacy = text.replace(command, "".join(
            "    - timeout -k 10s 19m ./scripts/check-" + sid + "-mutations.sh\n"
            for sid in ("builtin", "intake-receiver", "intake-service")))
        self.assertEqual(backtest.job_scripts(text), backtest.job_scripts(legacy))

    def test_backtest_wrapper_target_order_and_broken_controls(self):
        backtest = self.backtest_module()
        wrapper = (ROOT / "scripts/run-builtin-mutation-job.sh").read_text()

        def check_targets(text):
            python = text.split("<<'PY' &\n", 1)[1].split("\nPY\n", 1)[0]
            loops = [node for node in ast.walk(ast.parse(python))
                     if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
                     and node.target.id == "script"]
            self.assertEqual(len(loops), 1)
            self.assertEqual(ast.literal_eval(loops[0].iter), tuple(
                "check-" + sid + "-mutations.sh" for sid in backtest.BUILTIN_JOB_SCRIPTS))

        self.assertEqual(backtest.BUILTIN_JOB_SCRIPTS,
                         ("builtin", "intake-receiver", "intake-service"))
        check_targets(wrapper)
        for broken in (
            wrapper.replace('    "check-intake-receiver-mutations.sh",\n', ''),
            wrapper.replace('"check-intake-service-mutations.sh"', '"check-other-mutations.sh"'),
            wrapper.replace('"check-builtin-mutations.sh"', '"swap-placeholder"', 1)
                   .replace('"check-intake-receiver-mutations.sh"', '"check-builtin-mutations.sh"', 1)
                   .replace('"swap-placeholder"', '"check-intake-receiver-mutations.sh"', 1),
        ):
            with self.assertRaises(AssertionError):
                check_targets(broken)

    def test_backtest_wrapper_requires_exact_command(self):
        backtest = self.backtest_module()
        for line in (
            "    # ./scripts/run-builtin-mutation-job.sh",
            '        - "scripts/run-builtin-mutation-job.sh"',
            "    - ./scripts/run-builtin-mutation-job.sh.extra",
            "    - ./scripts/run-builtin-mutation-job.sh unexpected",
            "    - ./scripts/other/run-builtin-mutation-job.sh",
        ):
            self.assertEqual(backtest.job_scripts("example:\n" + line), {})
        self.assertEqual(backtest.job_scripts(
            "example:\n    - ./scripts/run-builtin-mutation-job.sh"),
            {"example": set(backtest.BUILTIN_JOB_SCRIPTS)})

    def test_gofmt_checks_tracked_go_without_module_cache(self):
        block = next(line for line in self.config["fmt-vet"]["script"] if "gofmt" in line)
        self.assertIn("git ls-files -z -- '*.go' | xargs -0 -r gofmt -l", block)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", tmp], check=True, capture_output=True)
            source = root / "tracked.go"
            source.write_text("package sample\n\nfunc f() {}\n")
            cache = root / ".gomodcache"
            cache.mkdir()
            (cache / "bad.templ.go").write_text("{{ not Go source }}\n")
            subprocess.run(["git", "-C", tmp, "add", "tracked.go"],
                           check=True, capture_output=True)
            clean = subprocess.run(["sh", "-ec", block], cwd=tmp,
                                   capture_output=True, text=True)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            source.write_text("package sample\nfunc f(){ }\n")
            unformatted = subprocess.run(["sh", "-ec", block], cwd=tmp,
                                         capture_output=True, text=True)
            self.assertNotEqual(unformatted.returncode, 0)
            self.assertIn("tracked.go", unformatted.stdout)

    def setUp(self):
        self.config = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())
        self.driver = self.config["security-hygiene"]["script"][0]

    def test_fsync_guard_is_called_by_fmt_vet_and_can_fail(self):
        guard = "sh scripts/check-ci-postgres-fsync.sh"
        self.assertIn(guard, self.config["fmt-vet"]["script"])
        # Control: with the call replaced by a no-op the contract must notice.
        disabled = [":" if line == guard else line for line in self.config["fmt-vet"]["script"]]
        self.assertNotIn(guard, disabled)
        good = '    services:\n      - name: postgres:17\n        command: ["-c", "fsync=off"]\n'
        broken = {
            "commented command": '    services:\n      - name: postgres:17\n        # command: ["-c", "fsync=off"]\n',
            "command of the next service": good.replace('command', 'alias: db\n      - name: redis:7\n        command'),
            "no postgres service": "    services:\n      - name: redis:7\n",
            "trailing comment names fsync=off": '    services:\n      - name: postgres:17\n        command: ["-c", "synchronous_commit=off"] # "fsync=off"\n',
            "commented postgres beside a real redis": "    services:\n      # - name: postgres:17\n      - name: redis:7\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            def run(text):
                path = Path(tmp) / "ci.yml"
                path.write_text(text)
                return subprocess.run(["sh", str(ROOT / "scripts/check-ci-postgres-fsync.sh"), str(path)],
                                      capture_output=True, text=True).returncode
            self.assertEqual(run(good), 0)
            for label, text in broken.items():
                self.assertEqual(run(text), 1, label)

    def test_early_child_preserves_security_and_final_build_barriers(self):
        check_child_dag(self.config)
        cases = [("fmt-vet", "needs", []),
                 ("build", "needs", [{"job": "fmt-vet"}]),
                 ("security-hygiene", "allow_failure", True),
                 ("secret-scan-scope-selftest", "allow_failure", True),
                 ("golangci-lint", "allow_failure", True),
                 ("build", "when", "always"),
                 ("full-tests", "allow_failure", True),
                 ("full-tests", "needs", []),
                 ("full-tests", "needs", [{"job": "fmt-vet", "artifacts": False}]),
                 ("execpolicy-mutations", "needs", [{"job": "full-tests"}])]
        for name, field, value in cases:
            with self.subTest(job=name, field=field):
                broken = copy.deepcopy(self.config)
                broken[name][field] = value
                with self.assertRaises(AssertionError):
                    check_child_dag(broken)
        broken = copy.deepcopy(self.config)
        broken["full-tests"]["trigger"]["strategy"] = "mirrorless"
        with self.assertRaises(AssertionError):
            check_child_dag(broken)

    def test_mutations_never_on_mr(self):
        check_mutations_never_on_mr(self.config)
        for name in sorted(MUTATIONS) + ["netns-mutation-run", INTAKE_MUTATIONS]:
            key = name if name in ("netns-mutation-run", INTAKE_MUTATIONS) else name + "-mutations"
            for mutate in ("auto", "manual", "main_manual", "changes"):
                with self.subTest(job=name, mutate=mutate):
                    broken = copy.deepcopy(self.config)
                    rules = broken[key]["rules"]
                    mr = next(r for r in rules if r.get("if") == MR_IF)
                    if mutate == "auto":
                        del mr["when"]
                    elif mutate == "manual":
                        mr.update(when="manual", allow_failure=False)
                    elif mutate == "changes":
                        mr["changes"] = ["**/*.go"]
                    else:
                        next(r for r in reversed(rules)
                             if r is not mr and r.get("when") != "never")["when"] = "manual"
                    with self.assertRaises(AssertionError):
                        check_mutations_never_on_mr(broken)

    def test_per_mr_browser_job_runs_no_mutation_suite(self):
        child = yaml.safe_load((ROOT / ".gitlab/ci/full-tests.yml").read_text())
        runs = lambda job: [l for l in map(str, job["script"]) if re.search(r"mutations\.sh", l)]
        self.assertEqual(runs(child["intake-browser"]), [])
        self.assertEqual(runs(self.config[INTAKE_MUTATIONS]), [
            "./scripts/check-intake-browser-mutations.sh", "./scripts/check-intake-page-mutations.sh",
            "./scripts/check-mesh-ui-browser-mutations.sh"])
        broken = copy.deepcopy(child["intake-browser"])
        broken["script"].append("./scripts/check-mesh-ui-browser-mutations.sh")
        self.assertTrue(runs(broken))

    def test_no_mutation_job_on_mr_and_broken_controls(self):
        check_no_mutation_on_mr(self.config)
        check_no_manual_jobs(self.config)
        # Any way of putting a mutation run back on a merge request fails.
        start = {"stage": "post-review", "tags": ["ci-fast"], "script": ["true"], "dependencies": [],
                 "rules": [{"if": MR_IF, "when": "manual", "allow_failure": False}]}
        trigger = {"stage": "post-review", "rules": [{"if": MR_IF}],
                   "trigger": {"include": [{"artifact": "mutations.generated.yml", "job": "fmt-vet"}],
                               "strategy": "depend"}}
        cases = {
            "start-mutations manual on MR": lambda c: c.__setitem__("start-mutations", start),
            "child trigger on MR": lambda c: c.__setitem__("child", trigger),
            "mutation job on MR": lambda c: c["sealer-mutations"].__setitem__("rules", [{"if": MR_IF}]),
            "shared rules lose MR never": lambda c: c["execrun-mutations"].__setitem__(
                "rules", [r for r in c["execrun-mutations"]["rules"] if r.get("if") != MR_IF]),
            "full-ci forces mutations": lambda c: c["sealer-mutations"]["rules"].insert(
                0, {"if": MR_IF + " && $KEEP_FULL_CI"}),
            "mutation script in a test job": lambda c: c["mesh-plugin"]["script"].append(
                "./scripts/check-mesh-plugin-mutations.sh"),
            "mutation script in e2e": lambda c: c["mesh-rotation-e2e"]["script"].append(
                'cd "$CI_PROJECT_DIR" && ./scripts/check-mesh-rotation-e2e-mutations.sh'),
            "release on MR": lambda c: c[RELEASE_JOB]["rules"].insert(0, {"if": MR_IF}),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_no_mutation_on_mr(broken)
        broken = copy.deepcopy(self.config)
        broken["start-mutations"] = start
        with self.assertRaises(AssertionError):
            check_no_manual_jobs(broken)
        broken = copy.deepcopy(self.config)
        broken["execrun-mutations"]["when"] = "manual"
        with self.assertRaises(AssertionError):
            check_no_manual_jobs(broken)

    def test_release_waits_for_every_tag_mutation_job(self):
        check_release(self.config)
        _, mutation = tag_mutation_jobs(self.config)
        # A `needs` list that leaves out any one mutation job lets it start early.
        for name in sorted(mutation)[:5] + sorted(mutation)[-5:]:
            with self.subTest(needs_without=name):
                broken = copy.deepcopy(self.config)
                broken[RELEASE_JOB]["needs"] = sorted(mutation - {name})
                with self.assertRaises(AssertionError):
                    check_release(broken)
        new_job = {"stage": RELEASE_JOB, "dependencies": [], "script": ["./scripts/check-x-mutations.sh"],
                   "rules": [{"if": TAG_IF}]}
        cases = {
            "empty needs": lambda c: c[RELEASE_JOB].__setitem__("needs", []),
            "mutation job beside release": lambda c: c.__setitem__("x-mutations", new_job),
            "mutation job moved after release": lambda c: (c["stages"].append("late"),
                                                           c["sealer-mutations"].__setitem__("stage", "late")),
            "soft mutation job": lambda c: c["sealer-mutations"].__setitem__("allow_failure", True),
            "soft shard job": lambda c: c["carriers-mutations"].__setitem__("allow_failure", {"exit_codes": [1]}),
            "always mutation job": lambda c: c["mesh-plugin-mutations"].__setitem__("when", "always"),
            "soft test job on tag": lambda c: c["build"].__setitem__("allow_failure", True),
            "soft release": lambda c: c[RELEASE_JOB].__setitem__("allow_failure", True),
            "release always": lambda c: c[RELEASE_JOB].__setitem__("when", "always"),
            "release off tag": lambda c: c[RELEASE_JOB].__setitem__("rules", [{"when": "on_success"}]),
            "release cancellable": lambda c: c[RELEASE_JOB].__setitem__("interruptible", True),
            "release not last": lambda c: c["stages"].append("after"),
            "release missing": lambda c: c.pop(RELEASE_JOB),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises((AssertionError, KeyError)):
                    check_release(broken)

    def test_mutation_jobs_run_on_dedicated_runner(self):
        check_mutation_runner(self.config)
        cases = [("tenancy-mutations", None), ("mesh-plugin", ["keep-mutations"]),
                 ("mesh-plugin-mutations", ["docker"]), (ROTATION_E2E_MUTATIONS, ["keep-mutations"]),
                 ("execrun-mutations", ["docker"]), ("mesh-rotation-e2e", ["docker", "keep-mutations"]),
                 ("netns-mutation-run", ["keep-mutations"]), ("build", ["keep-mutations"]),
                 ("fmt-vet", ["ci-fast", "keep-mutations"])]
        for name, tags in cases:
            with self.subTest(job=name, tags=tags):
                broken = copy.deepcopy(self.config)
                if tags is None:
                    del broken[name]["tags"]
                else:
                    broken[name]["tags"] = tags
                with self.assertRaises(AssertionError):
                    check_mutation_runner(broken)
        # A job on the mutation runner that starts in a merge request, even manual, is refused.
        for rule in ({"if": MR_IF}, {"if": MR_IF, "when": "manual"}):
            broken = copy.deepcopy(self.config)
            broken["execrun-mutations"]["rules"] = [rule]
            with self.assertRaises(AssertionError):
                check_mutation_runner(broken)
        # A new post-review job lands on the mutation runner too.
        broken = copy.deepcopy(self.config)
        broken["late-check"] = {"stage": "post-review", "script": ["true"]}
        with self.assertRaises(AssertionError):
            check_mutation_runner(broken)

    def test_mutation_runner_tag_is_one_anchor(self):
        text = (ROOT / ".gitlab-ci.yml").read_text()
        check_mutation_runner_anchor(text)
        broken = [
            text.replace("tags: *mutation-runner", "tags: [keep-mutations]", 1),
            text.replace(MUTATION_RUNNER_ANCHOR, "tags: &mutation-runner [docker]"),
        ]
        for case in broken:
            with self.assertRaises(AssertionError):
                check_mutation_runner_anchor(case)

    def test_mutation_fan_out_cap_can_fail(self):
        check_mutation_fan_out_cap(self.config)
        for name in sorted(MUTATIONS):
            for mutate in ("drop", "foreign"):
                with self.subTest(job=name, mutate=mutate):
                    broken = copy.deepcopy(self.config)
                    job = broken[name + "-mutations"]
                    if mutate == "drop":
                        del job["resource_group"]
                    else:
                        job["resource_group"] = "keep-mutation-unbounded"
                    with self.assertRaises(AssertionError):
                        check_mutation_fan_out_cap(broken)

    def test_post_review_jobs_skip_image_artifact(self):
        check_post_review_artifacts(self.config)
        jobs = [n for n, j in self.config.items()
                if not n.startswith(".") and isinstance(j, dict) and j.get("stage") == "post-review"]
        self.assertGreater(len(jobs), 30)
        for name in jobs:
            with self.subTest(job=name):
                broken = copy.deepcopy(self.config)
                broken[name].pop("dependencies", None)
                broken[name].pop("needs", None)
                with self.assertRaisesRegex(AssertionError, "^" + re.escape(name) + ":"):
                    check_post_review_artifacts(broken)
        for name, deps in (("sealer-mutations", [IMAGE_JOB]), ("sealer-mutations", ["fmt-vet"]),
                           ("sealer-mutations", "image-build"), ("tenancy-mutations", ["fmt-vet", IMAGE_JOB]),
                           ("tenancy-mutations", [])):
            with self.subTest(job=name, deps=deps):
                broken = copy.deepcopy(self.config)
                broken[name]["dependencies"] = deps
                with self.assertRaises(AssertionError):
                    check_post_review_artifacts(broken)
        broken = copy.deepcopy(self.config)
        broken["sealer-mutations"]["needs"] = [{"job": "fmt-vet", "artifacts": False}]
        with self.assertRaises(AssertionError):
            check_post_review_artifacts(broken)
        broken = copy.deepcopy(self.config)
        broken["late-check"] = {"stage": "post-review", "needs": [{"job": IMAGE_JOB, "artifacts": True}]}
        with self.assertRaises(AssertionError):
            check_post_review_artifacts(broken)
        broken["late-check"] = {"stage": "post-review", "script": ["true"]}
        with self.assertRaisesRegex(AssertionError, "^late-check:"):
            check_post_review_artifacts(broken)

    def test_heavy_fan_out_cap_can_fail(self):
        child = yaml.safe_load((ROOT / ".gitlab/ci/full-tests.yml").read_text())
        check_heavy_fan_out_cap(self.config, child)
        for name in HEAVY_GROUPS:
            for mutate in ("drop", "foreign"):
                with self.subTest(job=name, mutate=mutate):
                    broken = copy.deepcopy(self.config)
                    if mutate == "drop":
                        del broken[name]["resource_group"]
                    else:
                        broken[name]["resource_group"] = "keep-unbounded"
                    with self.assertRaises(AssertionError):
                        check_heavy_fan_out_cap(broken, child)
        for value in (None, "keep-test"):
            with self.subTest(job="test", value=value):
                broken = copy.deepcopy(child)
                if value is None:
                    del broken["test"]["resource_group"]
                else:
                    broken["test"]["resource_group"] = value
                with self.assertRaises(AssertionError):
                    check_heavy_fan_out_cap(self.config, broken)

    def test_module_cache_and_image_negative_controls(self):
        child = yaml.safe_load((ROOT / ".gitlab/ci/full-tests.yml").read_text())
        check_go_cache(self.config, child)
        cases = [
            (self.config, ".go-module-cache", "image", "golang:1.25-alpine"),
            (self.config, ".go-module-cache", "cache", {"paths": [".gocache/"]}),
            (self.config, ".go-module-cache-bookworm", "cache", {"policy": "pull-push"}),
            (self.config, ".go-module-cache-publisher", "cache", {"policy": "pull"}),
            (self.config, "builtin-mutations", "extends", None),
            (self.config, "golangci-lint", "image", "golangci/golangci-lint:v2.12.2-alpine"),
            (child, "test", "variables", {"GOCACHE": "$CI_PROJECT_DIR/.gocache"}),
            (child, ".go-module-cache", "image", "golang:1.25-alpine"),
            (child, "test", "cache", {"policy": "pull-push"}),
            (child, "intake-browser", "cache", None),
            (child, "intake-browser", "cache", {"policy": "pull"}),
            (child, "intake-browser", "cache", {"policy": "pull-push", "key": "foreign"}),
            (child, "intake-browser", "cache", {"policy": "pull-push", "paths": [".gomodcache/"]}),
            # Reject mutable tags, corrupt digests and images outside this registry.
            (child, "intake-browser", "image", "$CI_REGISTRY_IMAGE/ci/intake-browser:latest"),
            (child, "intake-browser", "image", "$CI_REGISTRY_IMAGE/ci/intake-browser@sha256:" + "a" * 63),
            (child, "intake-browser", "image", "registry.invalid/ci/intake-browser@sha256:" + "a" * 64),
        ]
        for original, name, field, value in cases:
            with self.subTest(job=name, field=field, value=value):
                parent_copy, child_copy = copy.deepcopy(self.config), copy.deepcopy(child)
                target = parent_copy if original is self.config else child_copy
                target[name][field] = value
                with self.assertRaises(AssertionError):
                    check_go_cache(parent_copy, child_copy)
        missing_cache = copy.deepcopy(child)
        del missing_cache["intake-browser"]["cache"]
        with self.assertRaises(AssertionError):
            check_go_cache(self.config, missing_cache)
        for parents in ("intake-browser", ["intake-browser"], ".hidden-intake-writer"):
            with self.subTest(child_inherits_publisher=parents):
                broken = copy.deepcopy(child)
                broken["extra-cache-writer"] = {"stage": "test", "extends": parents,
                                               "script": ["go version"]}
                if parents == ".hidden-intake-writer":
                    broken[".hidden-intake-writer"] = {"extends": "intake-browser"}
                with self.assertRaisesRegex(AssertionError, "extra-cache-writer|hidden-intake-writer"):
                    check_go_cache(self.config, broken)
        for field, value in [("files", ["go.sum"]), ("prefix", "go-branch")]:
            with self.subTest(cache_key=field):
                broken = copy.deepcopy(self.config)
                broken[".go-module-cache"]["cache"]["key"][field] = value
                with self.assertRaises(AssertionError):
                    check_go_cache(broken, child)
        for which in ("parent", "child"):
            for scope in ("variables", "default.variables", "default.cache"):
                with self.subTest(pipeline=which, scope=scope):
                    parent_copy, child_copy = copy.deepcopy(self.config), copy.deepcopy(child)
                    target = parent_copy if which == "parent" else child_copy
                    if scope == "variables":
                        target.setdefault("variables", {})["GOCACHE"] = "$CI_PROJECT_DIR/.gocache"
                    elif scope == "default.variables":
                        target.setdefault("default", {}).setdefault("variables", {})["GOCACHE"] = "$CI_PROJECT_DIR/.gocache"
                    else:
                        target.setdefault("default", {})["cache"] = {
                            "key": "shared-build-cache", "paths": [".cache/go-build/"],
                            "policy": "pull-push"}
                    with self.assertRaises(AssertionError):
                        check_go_cache(parent_copy, child_copy)
        for which, mutations in (("parent", ("direct_writer", "inherited_writer", "direct_cache")),
                                 ("child", ("direct_cache",))):
            for mutation in mutations:
                with self.subTest(pipeline=which, second_publisher=mutation):
                    parent_copy, child_copy = copy.deepcopy(self.config), copy.deepcopy(child)
                    target = parent_copy if which == "parent" else child_copy
                    if mutation == "direct_writer":
                        target["extra-cache-writer"] = {
                            "stage": "test", "extends": ".go-module-cache-publisher",
                            "script": ["go version"]}
                    elif mutation == "inherited_writer":
                        target["extra-cache-writer"] = {
                            "stage": "test", "extends": ".extra-cache-template",
                            "script": ["go version"]}
                        target[".extra-cache-template"] = {
                            "extends": ".go-module-cache-publisher"}
                    else:
                        target["extra-cache-writer"] = {
                            "stage": "test", "extends": ".go-module-cache",
                            "cache": {"key": "build", "paths": [".cache/go-build/"],
                                      "policy": "pull-push"},
                            "script": ["go version"]}
                    with self.assertRaisesRegex(AssertionError, "extra-cache-writer"):
                        check_go_cache(parent_copy, child_copy)

    def test_carriers_budget_and_mandatory_gate_controls(self):
        check_config(self.config, self.driver)
        for field, value in [("parallel", 1), ("timeout", "15m"),
                             ("script", [":"]), ("allow_failure", True),
                             ("when", "manual"), ("rules", [{"when": "never"}])]:
            with self.subTest(field=field):
                broken = copy.deepcopy(self.config)
                broken["carriers-mutations"][field] = value
                with self.assertRaises(AssertionError):
                    check_config(broken, self.driver)
        broken = copy.deepcopy(self.config)
        broken["ci-selftests"]["script"].remove("python3 scripts/test_carriers_mutations.py")
        with self.assertRaises(AssertionError):
            check_config(broken, self.driver)

    def test_mesh_plugin_mutations_shard_controls(self):
        check_config(self.config, self.driver)
        for field, value in [("parallel", 1), ("timeout", "15m"), ("script", [":"]),
                             ("allow_failure", True), ("when", "manual"),
                             ("rules", [{"if": MR_IF}]), ("stage", "test"),
                             ("resource_group", "keep-mutation-pool-9")]:
            with self.subTest(field=field):
                broken = copy.deepcopy(self.config)
                broken["mesh-plugin-mutations"][field] = value
                with self.assertRaises(AssertionError):
                    check_mesh_plugin_mutations(broken)
        # The unsharded run left in mesh-plugin is refused too.
        broken = copy.deepcopy(self.config)
        broken["mesh-plugin"]["script"].append("./scripts/check-mesh-plugin-mutations.sh")
        with self.assertRaises(AssertionError):
            check_mesh_plugin_mutations(broken)

    def test_catalog_diagnostics_mandatory_gate_control(self):
        check_config(self.config, self.driver)
        broken = copy.deepcopy(self.config)
        broken["ci-selftests"]["script"].remove("python3 scripts/test_catalog_mutant_diagnostics.py")
        with self.assertRaises(AssertionError):
            check_config(broken, self.driver)

    def test_w3_stubs_diagnostics_mandatory_gate_control(self):
        check_config(self.config, self.driver)
        broken = copy.deepcopy(self.config)
        broken["ci-selftests"]["script"].remove("python3 scripts/test_w3_stubs_diagnostics.py")
        with self.assertRaises(AssertionError):
            check_config(broken, self.driver)

    def test_selftests_job_and_broken_controls(self):
        check_selftests_job(self.config)
        def drop_rule(rules, index):
            del rules[index]
        cases = [
            ("removed self-test", lambda c: c["ci-selftests"]["script"].pop()),
            ("self-test back in fmt-vet", lambda c: c["fmt-vet"]["script"].append(SELFTESTS[0])),
            ("soft", lambda c: c["ci-selftests"].__setitem__("allow_failure", True)),
            ("manual", lambda c: c["ci-selftests"].__setitem__("when", "manual")),
            ("off main", lambda c: c["ci-selftests"]["rules"].__setitem__(-1, {"when": "never"})),
            ("in scan-only push", lambda c: drop_rule(c["ci-selftests"]["rules"], 0)),
            ("no forced run", lambda c: drop_rule(c["ci-selftests"]["rules"], 1)),
            ("needed", lambda c: c["build"].__setitem__("needs", [{"job": "ci-selftests"}])),
            ("dependency", lambda c: c["tenancy-mutations"]["dependencies"].append("ci-selftests")),
            ("uncovered script", lambda c: mr_changes(c["ci-selftests"]).remove("scripts/**/*")),
            ("uncovered tenancy source", lambda c: mr_changes(c["ci-selftests"]).remove("internal/tenancy/*")),
            ("uncovered identity source", lambda c: mr_changes(c["ci-selftests"]).remove("internal/identity/*")),
            ("uncovered migration", lambda c: mr_changes(c["ci-selftests"]).remove("internal/store/migrations/*")),
            ("uncovered cli tests", lambda c: mr_changes(c["ci-selftests"]).remove("cmd/keep/*")),
        ]
        for label, mutate in cases:
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_selftests_job(broken)
        # A mutation suite that starts copying a new Go source must list it.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "cmd/keep").mkdir(parents=True)
            for suite in ("tenancy", "carriers"):
                text = (ROOT / f"scripts/check-{suite}-mutations.sh").read_text()
                if suite == "tenancy":
                    text += "\nmutate planted internal/apperr/apperr.go 'a' 'b'\n"
                (root / f"scripts/check-{suite}-mutations.sh").write_text(text)
            sources = selftest_sources(root)
            self.assertIn("internal/apperr/apperr.go", sources)
            self.assertTrue(uncovered(mr_changes(self.config["ci-selftests"]), sources))

    def test_mutant_anchors_on_mr_and_broken_controls(self):
        check_mutant_anchors(self.config)
        def set_rules(c, rules):
            c[ANCHORS_JOB]["rules"] = rules
        cases = [
            ("removed", lambda c: c.pop(ANCHORS_JOB)),
            ("post-review", lambda c: c[ANCHORS_JOB].__setitem__("stage", "post-review")),
            ("soft", lambda c: c[ANCHORS_JOB].__setitem__("allow_failure", True)),
            ("manual", lambda c: c[ANCHORS_JOB].__setitem__("when", "manual")),
            ("never on MR", lambda c: set_rules(c, [{"if": MR_IF, "when": "never"}] + FULL_PIPELINE_ONLY)),
            ("path filtered", lambda c: set_rules(c, [{"if": MR_IF, "changes": ["scripts/**/*"]}])),
            ("no MR run", lambda c: c[ANCHORS_JOB]["script"].pop()),
            ("no selftest", lambda c: c[ANCHORS_JOB]["script"].pop(0)),
            ("suite run directly", lambda c: c[ANCHORS_JOB]["script"].append(
                "./scripts/check-lanepoller-mutations.sh")),
            ("mode switched off", lambda c: c[ANCHORS_JOB].setdefault("variables", {}).__setitem__(
                "MUTATION_APPLY_ONLY", "0")),
        ]
        for label, mutate in cases:
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises((AssertionError, KeyError)):
                    check_mutant_anchors(broken)
        # A suite without apply-only support fails the check.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts/check-mutant-anchors.sh").write_text(
                (ROOT / "scripts/check-mutant-anchors.sh").read_text())
            (root / "scripts/check-x-mutations.sh").write_text("#!/bin/sh\ngo test ./...\n")
            with self.assertRaises(AssertionError):
                check_mutant_anchors(self.config, root)

    def test_resolve_callers_apply_only_refuses_stale_source(self):
        """The apply-only run of check-resolve-callers-mutations.sh on a minimal
        copy of the tree: the real handler declaration applies, and a source
        already renamed or reformatted with the new name in a comment is a
        stranded mutation, never `applies`."""
        decl = "func (m *meshRoutes) handleResolveSecret(w http.ResponseWriter"
        mesh = (ROOT / "internal/api/mesh.go").read_text()
        self.assertEqual(mesh.count(decl), 1)
        cases = [
            ("current source", mesh, 0),
            ("already renamed", mesh.replace(decl, decl.replace("Secret(", "SecretRenamed(")), 1),
            ("reformatted, new name in a comment",
             mesh.replace(decl, decl.replace("Secret(", "Secret( ")) +
             "\n// handleResolveSecretRenamed(w http.ResponseWriter\n", 1),
        ]
        for label, source, want in cases:
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                shutil.copytree(ROOT / "scripts", root / "scripts")
                shutil.copy(ROOT / "go.mod", root / "go.mod")
                (root / "internal/api").mkdir(parents=True)
                (root / "internal/api/mesh.go").write_text(source)
                env = {**os.environ, "MUTATION_APPLY_ONLY": "1"}
                r = subprocess.run(["sh", "scripts/check-resolve-callers-mutations.sh"], cwd=root,
                                   env=env, capture_output=True, text=True, timeout=60)
                self.assertEqual(r.returncode, want, r.stdout + r.stderr)
                self.assertEqual("ok   handler-renamed: applies" in r.stdout, want == 0, r.stdout)

    def test_gitlab_glob(self):
        for pattern, path, hit in [("internal/api/**/*", "internal/api/x.go", True),
                                   ("internal/api/**/*", "internal/api/a/b/x.go", True),
                                   ("internal/api/**/*", "internal/apix/x.go", False),
                                   ("cmd/keep/*", "cmd/keep/x_test.go", True),
                                   ("cmd/keep/*", "cmd/keep/sub/x.go", False),
                                   ("cmd/keep/*", "cmd/keep-runner/x.go", False),
                                   ("scripts/**/*", "scripts/lib/gocache.sh", True),
                                   (".gitlab/ci/**/*", ".gitlab/ci/full-tests.yml", True)]:
            with self.subTest(pattern=pattern, path=path):
                self.assertEqual(gitlab_glob(pattern, path), hit)

    def test_lint_directive_guard_red_runs(self):
        """The red run of the depguard directive probes, on every CI run: the
        real guard rejects each probe file by name, and each weakened guard
        lets through exactly the probes of the branch it lost."""
        probes = depdirective_calls((ROOT / IMPORT_BOUNDARIES).read_text())
        self.assertEqual(len(probes), 2 * len(DEPGUARD_DIRECTIVE_FORMS))
        names = {p[0] for p in probes}
        line_forms = {n for n in names if "-line-" in n}
        depguard_forms = {n for n in names if n.split("-", 2)[-1] in
                          ("nolint-depguard", "nolint-list", "nolint-upper", "nolint-block", "nolint-file")}

        def edit(old, new):
            def apply(text):
                self.assertIn(old, text)
                return text.replace(old, new, 1)
            return apply

        cases = (
            ("real guard", lambda t: t, set()),
            ("no //line branch", edit('pattern="^//line |', 'pattern="'),
             {n for n in line_forms if "-line-block-" not in n}),
            ("no line branches", edit('pattern="^//line |/\\\\*line |', 'pattern="'), line_forms),
            ("depguard not in the nolint list", edit("(forbidigo|depguard|all)", "(forbidigo|all)"), depguard_forms),
            ("guard is a no-op", lambda t: "#!/bin/sh\nexit 0\n", names),
        )
        for label, pattern_edit, expected in cases:
            with self.subTest(label):
                self.assertEqual(lint_directive_guard_run(pattern_edit, probes), expected)

    def test_import_boundaries_shards_and_broken_controls(self):
        text = (ROOT / IMPORT_BOUNDARIES).read_text()
        check_import_boundaries_job(self.config, text)
        locations = probe_locations(text)
        for path in ("pkg/secret/x.go", "pkg/fingerprint/x.go", "internal/identity/x.go",
                     "internal/builtin/intake.go", "internal/builtin/orgpki/sign_job.go",
                     "web/intake/zz_boundary_probe.go", "internal/api/pkg/secret/zz_boundary_probe.go",
                     "internal/catalog/node_modules/zz_boundary_probe.go"):
            self.assertIn(path, locations)
        cases = [
            ("unsharded", lambda c: c["import-boundaries"].pop("parallel")),
            ("soft", lambda c: c["import-boundaries"].__setitem__("allow_failure", True)),
            ("not on schedule", lambda c: c["import-boundaries"]["rules"].pop(0)),
            ("not on main", lambda c: c["import-boundaries"]["rules"].pop(1)),
            ("uncovered config", lambda c: mr_changes(c["import-boundaries"]).remove(".golangci.yml")),
            ("uncovered secret", lambda c: mr_changes(c["import-boundaries"]).remove("pkg/secret/**/*")),
            ("uncovered intake page", lambda c: mr_changes(c["import-boundaries"]).remove("web/intake/**/*")),
            ("uncovered lookalike root", lambda c: mr_changes(c["import-boundaries"]).remove("internal/api/**/*")),
            ("uncovered script", lambda c: mr_changes(c["import-boundaries"]).remove("scripts/**/*")),
            ("directive gate duplicated", lambda c: c["import-boundaries"]["script"].insert(1, "./scripts/check-lint-directives.sh")),
        ]
        for label, mutate in cases:
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_import_boundaries_job(broken, text)
        # The whole-tree directive gate must stay in the unconditional fmt-vet.
        broken = copy.deepcopy(self.config)
        broken["fmt-vet"]["script"].remove("./scripts/check-lint-directives.sh")
        with self.assertRaises(AssertionError):
            check_config(broken, self.driver)
        # A new probe location outside the listed packages, a probe function
        # that skips its shard number, and an unknown probe function all fail.
        new_probe = text.replace("\nexit $fail", "\nprobe store-probe secret-value internal/store $m/pkg/secret\nexit $fail")
        unsharded = text.replace("allow_test() {\n\tshard_take || return 0\n", "allow_test() {\n")
        unknown = text.replace("\nexit $fail", "\nextra() {\n\ttrue\n}\nexit $fail")
        # The depguard directive probes: dropped, or passing without the
        # guard naming the probe file.
        no_depdirective = "\n".join(l for l in text.splitlines() if not l.startswith("depdirective "))
        no_line_probe = text.replace("\ndepdirective plaintext-digest-line-before-package ", "\n# ")
        always_ok = text.replace(GUARD_NAMES_PROBE, "if true; then")
        unnamed = text.replace(GUARD_NAMES_PROBE, "if [ $guard = fail ]; then")
        for label, case in (("new location", new_probe), ("unsharded function", unsharded),
                            ("unknown function", unknown), ("no depguard probes", no_depdirective),
                            ("no line probe", no_line_probe), ("always ok", always_ok),
                            ("guard need not name the file", unnamed)):
            with self.subTest(label):
                self.assertNotEqual(case, text)
                with self.assertRaises(AssertionError):
                    check_import_boundaries_job(self.config, case)

    def test_config_and_removed_gate_controls(self):
        check_config(self.config, self.driver)
        for name in MUTATIONS:
            with self.subTest(removed_mutation=name):
                broken = copy.deepcopy(self.config)
                del broken[name + "-mutations"]
                with self.assertRaises(AssertionError):
                    check_config(broken, self.driver)
        for name in GATES:
            with self.subTest(removed=name):
                with self.assertRaises(AssertionError):
                    broken = copy.deepcopy(self.config)
                    broken["security-hygiene"]["script"][0] = self.driver.replace("./scripts/" + name, ":")
                    check_config(broken, broken["security-hygiene"]["script"][0])
        for field, value in [("allow_failure", True), ("rules", [{"when": "manual"}]),
                             ("when", "manual")]:
            broken = copy.deepcopy(self.config)
            broken["security-hygiene"][field] = value
            with self.assertRaises(AssertionError):
                check_config(broken, self.driver)
        for field, value in [("script", [":"]), ("allow_failure", True),
                             ("rules", [{"when": "never"}]), ("when", "manual")]:
            with self.subTest(capture_gate=field):
                broken = copy.deepcopy(self.config)
                broken["providertest-mutations"][field] = value
                with self.assertRaises(AssertionError):
                    check_config(broken, self.driver)
        for field, value in [("script", [":"]), ("timeout", "1m"), ("allow_failure", True), ("when", "manual")]:
            with self.subTest(dispatch_gate=field):
                broken = copy.deepcopy(self.config)
                broken["dispatch-mutations"][field] = value
                with self.assertRaises(AssertionError):
                    check_config(broken, self.driver)

    def test_each_stage_failure_stops_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts/check-security-gates.sh").write_text(self.driver)
            for failed in [None] + GATES:
                for name in GATES:
                    path = root / "scripts" / name
                    path.write_text(f"#!/bin/sh\necho {name}\nexit {73 if name == failed else 0}\n")
                    path.chmod(0o755)
                run = subprocess.run(["sh", "scripts/check-security-gates.sh"], cwd=root,
                                     capture_output=True, text=True)
                self.assertEqual(run.returncode, 73 if failed else 0)
                count = GATES.index(failed) + 1 if failed else len(GATES)
                self.assertEqual(run.stdout.splitlines(), GATES[:count])

    def test_scanner_evidence_and_redaction(self):
        for name in GATES[:3]:
            script = (ROOT / "scripts" / name).read_text()
            for line in script.splitlines():
                if "gitleaks detect" in line:
                    self.assertIn("--redact --exit-code 1", line)
        scanner = (ROOT / "scripts" / GATES[0]).read_text()
        self.assertIn("CI_MERGE_REQUEST_DIFF_BASE_SHA", scanner)
        self.assertIn("CI_COMMIT_BEFORE_SHA", scanner)
        self.assertIn("CI_COMMIT_SHA", scanner)
        self.assertIn("leaks found: 1", (ROOT / "scripts" / GATES[1]).read_text())
        identity = (ROOT / "scripts" / GATES[2]).read_text()
        self.assertIn("for kind in a s u", identity)
        self.assertIn("keep-identity-token", identity)
        self.assertIn("check-intake-scan-allowlist.sh", identity)
        self.assertIn("HYGIENE_RANGE", (ROOT / "scripts" / GATES[3]).read_text())

    def test_scanner_ranges_after_main_integration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            for name in [GATES[0], "scan-secret-history.sh"]:
                path = root / "scripts" / name
                path.write_bytes((ROOT / "scripts" / name).read_bytes())
                path.chmod(0o755)
            stub = root / "gitleaks"
            stub.write_text('#!/bin/sh\nprintf "arg:%s\\n" "$@"\n')
            stub.chmod(0o755)
            tip, base = "1" * 40, "2" * 40
            env = {"PATH": str(root) + os.pathsep + os.defpath,
                   "CI_COMMIT_REF_NAME": "topic", "CI_COMMIT_SHA": tip}
            cases = [
                ("first-push", {"CI_PIPELINE_SOURCE": "push"}, tip),
                ("zero-before", {"CI_COMMIT_BEFORE_SHA": "0" * 40}, tip),
                ("mr", {"CI_PIPELINE_SOURCE": "merge_request_event",
                        "CI_MERGE_REQUEST_DIFF_BASE_SHA": base}, base + ".." + tip),
                ("push", {"CI_COMMIT_BEFORE_SHA": base}, base + ".." + tip),
            ]
            for name, context, expected in cases:
                with self.subTest(name=name):
                    run = subprocess.run(["sh", "scripts/" + GATES[0]], cwd=root,
                                         env=env | context, capture_output=True, text=True)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertIn("arg:--log-opts=" + expected, run.stdout.splitlines())
                    self.assertIn("arg:--redact", run.stdout.splitlines())
            env.pop("CI_COMMIT_SHA")
            run = subprocess.run(["sh", "scripts/" + GATES[0]], cwd=root, env=env,
                                 capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertNotIn("arg:detect", run.stdout)

    def test_branch_push_runs_one_full_pipeline_per_mr_sha(self):
        check_branch_push_scope(self.config)
        self.assertFalse(rule_matches('$A == "x"', {"A": "y"}))
        with self.assertRaises(ValueError):
            rule_matches('$A || $B', {})
        # The config before this check: the open-MR rule alone left a full
        # push pipeline (lint, tests, child pipeline) racing the MR pipeline.
        old = copy.deepcopy(self.config)
        del old["workflow"]["rules"][5]
        for job in old.values():
            if isinstance(job, dict) and job.get("rules") == FULL_PIPELINE_ONLY:
                del job["rules"]
        with self.assertRaises(AssertionError):
            check_branch_push_scope(old)
        # The secret scan must stay in the branch push pipeline.
        broken = copy.deepcopy(self.config)
        broken["security-hygiene"]["rules"] = FULL_PIPELINE_ONLY
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        # Any heavy job without the scan-only rule leaks back into it.
        for name in ("fmt-vet", "full-tests", "carriers-mutations", "build"):
            with self.subTest(unscoped=name):
                broken = copy.deepcopy(self.config)
                del broken[name]["rules"]
                with self.assertRaises(AssertionError):
                    check_branch_push_scope(broken)
        # Main, web and api pipelines must keep full coverage.
        for index in (1, 6):
            with self.subTest(removed_workflow_rule=index):
                broken = copy.deepcopy(self.config)
                del broken["workflow"]["rules"][index]
                with self.assertRaises(AssertionError):
                    check_branch_push_scope(broken)
        broken = copy.deepcopy(self.config)
        broken["workflow"]["rules"][5]["if"] = "$CI_COMMIT_BRANCH"
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)

    def test_main_push_runs_no_mutation_job(self):
        """Red controls: any way of putting a mutation job back on the main push fails."""
        check_mutations_never_on_mr(self.config)
        check_branch_push_scope(self.config)
        selective = next(n for n in sorted(MUTATIONS)
                         if not unconditional(self.config[n + "-mutations"]))
        every_mutation = {name + "-mutations" for name in MUTATIONS}
        # 1. the old rule is put back on a selective job
        broken = copy.deepcopy(self.config)
        broken[selective + "-mutations"]["rules"].insert(
            1, {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"})
        with self.assertRaises(AssertionError):
            check_mutations_never_on_mr(broken)
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        # 2. the shared rule list loses its main-push exclusion
        broken = copy.deepcopy(self.config)
        for name in MUTATIONS:
            job = broken[name + "-mutations"]
            if unconditional(job):
                job["rules"] = [r for r in job["rules"] if r.get("if") != MAIN_PUSH_IF]
        with self.assertRaises(AssertionError):
            check_mutations_never_on_mr(broken)
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        # 3. a selective job loses its schedule rule: the nightly would skip it
        broken = copy.deepcopy(self.config)
        rules = broken[selective + "-mutations"]["rules"]
        rules.remove({"if": '$CI_PIPELINE_SOURCE == "schedule"'})
        with self.assertRaises(AssertionError):
            check_mutations_never_on_mr(broken)
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        # 4. a mutation suite is run from a job that is not named *-mutations
        broken = copy.deepcopy(self.config)
        broken["netns-tests"]["script"].append("timeout -k 10s 18m ./scripts/check-netns-mutations.sh")
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        # 5. the dedicated netns mutation job gets the main push back
        broken = copy.deepcopy(self.config)
        broken["netns-mutation-run"]["rules"].insert(1, {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"})
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        # 5b. the parent creates the netns mutation run on an MR again (by itself or manual)
        for field, value in [("when", None), ("when", "on_success"), ("when", "manual")]:
            broken = copy.deepcopy(self.config)
            rule = next(r for r in broken["netns-mutation-run"]["rules"] if r.get("if") == MR_IF)
            if value is None:
                del rule[field]
            else:
                rule[field] = value
            with self.assertRaises(AssertionError, msg=(field, value)):
                check_netns_mutation_run_manual_on_mr(broken)
        check_netns_mutation_run_manual_on_mr(self.config)
        # 6. the netns mutation run is dropped from the schedule: the nightly would skip it
        broken = copy.deepcopy(self.config)
        broken["netns-mutation-run"]["rules"].remove({"if": '$CI_PIPELINE_SOURCE == "schedule"'})
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        # 7. a release tag loses the full set: a job drops its tag rule, a
        # shared rule list sends tags to the selector path, or the workflow
        # stops creating tag pipelines
        broken = copy.deepcopy(self.config)
        broken["netns-mutation-run"]["rules"].remove({"if": TAG_IF})
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        broken = copy.deepcopy(self.config)
        broken["carriers-mutations"]["rules"].insert(0, {"if": TAG_IF, "when": "never"})
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        broken = copy.deepcopy(self.config)
        broken["workflow"]["rules"] = [r for r in broken["workflow"]["rules"] if r.get("if") != TAG_IF]
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        # positive control of the evaluator: the schedule still runs every one
        jobs = pipeline_jobs(self.config, MAIN | {"CI_PIPELINE_SOURCE": "schedule"})
        self.assertTrue(mutation_runners(self.config, jobs) >= {"netns-mutation-run"}, jobs)
        self.assertTrue(every_mutation <= jobs, every_mutation - jobs)
        jobs = pipeline_jobs(self.config, MAIN | {"CI_PIPELINE_SOURCE": "push"})
        self.assertFalse(every_mutation & jobs, every_mutation & jobs)

    def test_mutation_batch_scope_and_broken_controls(self):
        check_mutation_batch(self.config)
        check_post_review_artifacts(self.config)
        cases = [
            # a heavy job loses its batch rule (anchor or own rules)
            ("full-pipeline anchor", lambda c: c["full-tests"]["rules"].remove(BATCH_NEVER)),
            ("schedule anchor", lambda c: c["sealer-mutations"]["rules"].remove(BATCH_NEVER)),
            ("mutation anchor", lambda c: c["execrun-mutations"]["rules"].remove(BATCH_NEVER)),
            ("own rules", lambda c: c["mesh-rotation-e2e"]["rules"].remove(BATCH_NEVER)),
            ("intake", lambda c: c[INTAKE_MUTATIONS]["rules"].remove(BATCH_NEVER)),
            # fmt-vet drops out of the batch: the child's tenancy job has no artifact
            ("fmt-vet", lambda c: c["fmt-vet"]["rules"].insert(0, BATCH_NEVER)),
            # the batch is no longer named, or is cancelled by a newer commit
            ("name", lambda c: c["workflow"]["rules"][0]["variables"].clear()),
            ("cancel", lambda c: c["workflow"]["rules"][0]["auto_cancel"].update(on_new_commit="interruptible")),
            ("workflow order", lambda c: c["workflow"]["rules"].append(c["workflow"]["rules"].pop(0))),
            # the range job fails open: it exits instead of dropping its answer
            ("range fallback", lambda c: c[RANGE_JOB]["script"].__setitem__(
                0, c[RANGE_JOB]["script"][0].replace("rm -f mutation-select.json", "exit 1"))),
            ("trigger depend", lambda c: c[BATCH_TRIGGER]["trigger"].pop("strategy")),
            ("trigger fmt-vet", lambda c: c[BATCH_TRIGGER]["needs"].pop()),
            ("trigger parent id", lambda c: c[BATCH_TRIGGER].pop("variables")),
            # the green commit is written before the other jobs finished, or by a main push
            ("green stage", lambda c: c[GREEN_JOB].__setitem__("stage", "post-review")),
            ("green needs", lambda c: c[GREEN_JOB].__setitem__("needs", [RANGE_JOB])),
            ("green on main push", lambda c: c[GREEN_JOB]["rules"][2]["variables"].update(KEEP_MUTATION_GREEN="head")),
            ("green allow_failure", lambda c: c[GREEN_JOB].__setitem__("allow_failure", True)),
            ("green dropped from main push", lambda c: c[GREEN_JOB]["rules"].pop()),
        ]
        for label, breaker in cases:
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                breaker(broken)
                with self.assertRaises(AssertionError):
                    check_mutation_batch(broken)

    def test_mutation_green_keeps_only_a_commit(self):
        self.assertEqual(run_green(self.config, "head"), (0, "c" * 40 + "\n"))
        # carry: the previous green commit, as the API served it
        good = 'for a; do o=$a; done; [ "$1" = -q ] && printf "%s\\n" ' + "b" * 40 + ' > mutation-green.sha'
        self.assertEqual(run_green(self.config, "carry", good), (0, "b" * 40 + "\n"))
        # nothing to carry (404, the API down) or not a commit: nothing kept, still green
        self.assertEqual(run_green(self.config, "carry"), (0, None))
        junk = 'echo "<html>not found</html>" > mutation-green.sha'
        self.assertEqual(run_green(self.config, "carry", junk), (0, None))
        # control: a script that keeps whatever it read fails the junk case
        broken = copy.deepcopy(self.config)
        broken[GREEN_JOB]["script"] = [s.replace("grep -Eqx '[0-9a-f]{40}' mutation-green.sha", "true")
                                       for s in broken[GREEN_JOB]["script"]]
        self.assertNotEqual(run_green(broken, "carry", junk), (0, None))

    def test_child_preserves_main_protection(self):
        for main, policy in [(True, "none"), (False, "interruptible")]:
            config = yaml.safe_load(selector.render(False, main))
            self.assertEqual(config["workflow"]["auto_cancel"]["on_new_commit"], policy)
            self.assertTrue(config["default"]["interruptible"])
            self.assertTrue(self.config["default"]["interruptible"])

    def test_every_job_is_interruptible_with_named_exceptions(self):
        self.assertEqual(interruptible_violations(self.config), [])
        self.assertEqual(self.config["workflow"]["auto_cancel"]["on_new_commit"], "conservative")
        # main and the nightly schedule are never cancelled by a newer commit
        rules = self.config["workflow"]["rules"]
        for cond in ('$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH', '$CI_PIPELINE_SOURCE == "schedule"'):
            rule = [r for r in rules if r.get("if") == cond]
            self.assertEqual(len(rule), 1, cond)
            self.assertEqual(rule[0]["auto_cancel"]["on_new_commit"], "none", cond)
        # red controls: a job opting out, a side-effect job without the opt-out,
        # a missing default, and a named exception that is still interruptible
        broken = copy.deepcopy(self.config)
        broken["fmt-vet"]["interruptible"] = False
        self.assertEqual(interruptible_violations(broken), ["fmt-vet"])
        broken = copy.deepcopy(self.config)
        broken["publish"] = {"script": ["docker push registry/x:latest"]}
        self.assertEqual(interruptible_violations(broken), ["publish"])
        broken["wrapped"] = {"script": ["./scripts/ship.sh --publish"]}
        self.assertEqual(interruptible_violations(broken), ["publish", "wrapped"])
        broken = copy.deepcopy(self.config)
        del broken["default"]["interruptible"]
        self.assertTrue(len(interruptible_violations(broken)) > 20)
        broken = copy.deepcopy(self.config)
        broken["publish"] = {"script": ["docker push registry/x:latest"], "interruptible": False}
        self.assertEqual(interruptible_violations(broken), ["publish"])  # not named
        inherited_script = copy.deepcopy(self.config)
        inherited_script[".shipper"] = {"script": ["./scripts/x.sh --publish"]}
        inherited_script["via-template"] = {"extends": [".shipper"]}
        self.assertEqual(interruptible_violations(inherited_script), ["via-template"])
        global NON_INTERRUPTIBLE
        NON_INTERRUPTIBLE = {RELEASE_JOB, "publish"}
        try:
            self.assertEqual(interruptible_violations(broken), [])
            broken["publish"]["interruptible"] = True
            self.assertEqual(interruptible_violations(broken), ["publish"])
        finally:
            NON_INTERRUPTIBLE = {RELEASE_JOB}
        # the release job itself, cancellable by a newer commit
        broken = copy.deepcopy(self.config)
        broken[RELEASE_JOB]["interruptible"] = True
        self.assertEqual(interruptible_violations(broken), [RELEASE_JOB])
        # inherited opt-outs: via extends template, and via inherit:default:false
        inherited = copy.deepcopy(self.config)
        inherited[".no-cancel"] = {"interruptible": False}
        inherited["fmt-vet"]["extends"] = [".no-cancel"]
        self.assertEqual(interruptible_violations(inherited), ["fmt-vet"])
        inherited = copy.deepcopy(self.config)
        inherited["fmt-vet"]["inherit"] = {"default": False}
        self.assertEqual(interruptible_violations(inherited), ["fmt-vet"])


# A job is retried only when the runner or GitLab failed it, never when its
# own code did: script_failure, unknown_failure and the timeouts would turn a
# red mutant or a hung test green on the second try.
RETRY_WHEN = {"runner_system_failure", "scheduler_failure", "api_failure"}
RETRY_FORBIDDEN = {"always", "script_failure", "unknown_failure",
                   "stuck_or_timeout_failure", "job_execution_timeout"}
gen_spec = importlib.util.spec_from_file_location(
    "generate_mutation_pipeline", ROOT / "scripts/generate-mutation-pipeline.py")
mutation_gen = importlib.util.module_from_spec(gen_spec)
gen_spec.loader.exec_module(mutation_gen)


def retry_violations(config):
    """`default.retry` other than the infrastructure set, and any job-level
    retry that also covers a failure of the job itself."""
    def bad_retry(retry, exact):
        # A bare number, or a dict without `when`, retries on every failure;
        # `exit_codes` retries a script failure whatever `when` says.
        if not isinstance(retry, dict) or set(retry) != {"max", "when"}:
            return True
        when = retry["when"]
        when = {when} if isinstance(when, str) else set(when or [])
        if not when or not when <= RETRY_WHEN or (exact and when != RETRY_WHEN):
            return True
        return not isinstance(retry["max"], int) or isinstance(retry["max"], bool) \
            or not 1 <= retry["max"] <= 2

    bad = []
    if bad_retry(config.get("default", {}).get("retry"), True):
        bad.append(f"default: {config.get('default', {}).get('retry')!r}")
    for name, job in config.items():
        if name != "default" and isinstance(job, dict) and "retry" in job and bad_retry(job["retry"], False):
            bad.append(f"{name}: {job['retry']!r}")
    return bad

class RetryPolicy(unittest.TestCase):
    def setUp(self):
        self.config = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())

    def test_retry_only_on_infrastructure_failures(self):
        self.assertEqual(retry_violations(self.config), [])
        child = yaml.safe_load((ROOT / ".gitlab/ci/full-tests.yml").read_text())
        child["default"] = self.config["default"]
        self.assertEqual(retry_violations(child), [])

    def test_retry_violations_broken_controls(self):
        cases = {
            "missing": lambda c: c["default"].pop("retry"),
            "script_failure": lambda c: c["default"]["retry"]["when"].append("script_failure"),
            "unknown_failure": lambda c: c["default"]["retry"]["when"].append("unknown_failure"),
            "narrowed": lambda c: c["default"]["retry"]["when"].remove("api_failure"),
            "max 3": lambda c: c["default"]["retry"].update(max=3),
            "bare number": lambda c: c["default"].update(retry=2),
            "job always": lambda c: c["fmt-vet"].update(retry=1),
            "job no when": lambda c: c["fmt-vet"].update(retry={"max": 1}),
            "job timeout": lambda c: c["fmt-vet"].update(retry={"max": 1, "when": "stuck_or_timeout_failure"}),
            "job execution timeout": lambda c: c["fmt-vet"].update(
                retry={"max": 1, "when": ["api_failure", "job_execution_timeout"]}),
            "default exit_codes": lambda c: c["default"]["retry"].update(exit_codes=[1]),
            "job exit_codes": lambda c: c["fmt-vet"].update(
                retry={"max": 1, "when": "api_failure", "exit_codes": [1]}),
            "job max 5": lambda c: c["fmt-vet"].update(retry={"max": 5, "when": "api_failure"}),
            "job no max": lambda c: c["fmt-vet"].update(retry={"when": "api_failure"}),
            "job empty when": lambda c: c["fmt-vet"].update(retry={"max": 1, "when": []}),
        }
        for name, edit in cases.items():
            with self.subTest(name):
                config = copy.deepcopy(self.config)
                edit(config)
                self.assertNotEqual(retry_violations(config), [])
        config = copy.deepcopy(self.config)
        config["fmt-vet"]["retry"] = {"max": 1, "when": "runner_system_failure"}
        self.assertEqual(retry_violations(config), [])

    def test_child_pipelines_carry_the_same_retry(self):
        retry = self.config["default"].get("retry")
        self.assertIsNotNone(retry)
        names = sorted(mutation_gen.ms.post_review_jobs(self.config))
        for batch in (True, False):
            for selected in (names, names[:1], []):
                with self.subTest(batch=batch, jobs=len(selected)):
                    child = yaml.safe_load(mutation_gen.render(self.config, selected, batch=batch))
                    self.assertEqual(child["default"]["retry"], retry)
        for docs, main in ((False, False), (False, True), (True, False)):
            with self.subTest(docs=docs, main=main):
                child = yaml.safe_load(selector.render(docs, main))
                self.assertEqual(child["default"], self.config["default"])


class MutationSelector(unittest.TestCase):
    def test_transport_dependencies_and_broken_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            source = (ROOT / "scripts/mutations-for-diff.sh").read_text()
            target = scripts / "mutations-for-diff.sh"
            target.write_text(source)
            for guard in (ROOT / "scripts").glob("check-*-mutations.sh"):
                (scripts / guard.name).write_text("#!/bin/sh\n")
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True).strip()
            git("init", "-q")
            git("config", "user.name", "CI test")
            git("config", "user.email", "ci-test@localhost")
            git("add", ".")
            git("commit", "-qm", "test: selector fixture")
            base = git("rev-parse", "HEAD")
            def select(path, selector_source=source):
                git("switch", "--detach", "-q", base)
                target.write_text(selector_source)
                changed = root / path
                changed.parent.mkdir(parents=True, exist_ok=True)
                changed.write_text("changed\n")
                git("add", path)
                git("commit", "-qm", "test: isolated dependency")
                run = subprocess.run(["bash", str(target), base], cwd=root,
                                     capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                return run.stdout.splitlines()
            for path in ("internal/api/router.go", "internal/api/middleware.go",
                         "internal/builtin/orgpki/orgpki.go",
                         "internal/store/deployment_result_migration_test.go"):
                with self.subTest(path=path):
                    self.assertEqual(select(path).count("scripts/check-dispatch-mutations.sh"), 1)
            self.assertIn("scripts/check-providertest-mutations.sh", select("pkg/provider/providertest/capture.go"))
            self.assertNotIn("scripts/check-dispatch-mutations.sh", select("README.md"))
            broken = source.replace("dispatch: internal/dispatch internal/api ", "dispatch: internal/dispatch ")
            self.assertNotIn("scripts/check-dispatch-mutations.sh", select("internal/api/router.go", broken))
            # A missing table row must fail closed even for an unrelated diff.
            broken = source.replace("providertest: pkg/provider\n", "")
            target.write_text(broken)
            run = subprocess.run(["bash", str(target), base], cwd=root,
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertIn("providertest-mutations.sh has no table entry", run.stderr)


class BaselineFirst(unittest.TestCase):
    """A red baseline must stop the long mutation suites before their first
    mutant, not after the whole inventory."""

    SUITES = {
        "scripts/check-targets-mutations.sh": "mutation_baseline ",
        "scripts/check-tenancy-mutations.sh": "baseline_pkg",
    }

    @staticmethod
    def order(text, marker):
        lines = text.splitlines()
        first_mutant = next(i for i, l in enumerate(lines) if l.startswith(("mutate ", "mutate2 ", "mutateN ")))
        baseline = next(i for i, l in enumerate(lines) if marker in l and not l.lstrip().startswith("#"))
        return baseline, first_mutant

    def test_baseline_precedes_the_first_mutant(self):
        for path, marker in self.SUITES.items():
            baseline, mutant = self.order((ROOT / path).read_text(), marker)
            self.assertLess(baseline, mutant, path)

    def test_the_check_can_fail(self):
        text = (ROOT / "scripts/check-targets-mutations.sh").read_text().splitlines()
        i = next(i for i, l in enumerate(text) if "mutation_baseline " in l)
        moved = text[:i] + text[i + 1:] + [text[i]]
        baseline, mutant = self.order("\n".join(moved), "mutation_baseline ")
        self.assertGreater(baseline, mutant)


class DocsSelector(unittest.TestCase):
    def test_job_sets_and_bad_selector_control(self):
        cases = [
            ("docs-only", [("M", "README.md")], True),
            ("docs-page", [("M", "docs/carrier-discovery.md")], True),
            ("go", [("M", "pkg/secret/value.go")], False),
            ("browser", [("M", "web/intake/index.html")], False),
            ("scripts", [("M", "scripts/check-no-silent-skip.sh")], False),
            ("ci", [("M", ".gitlab-ci.yml")], False),
            ("child-ci", [("M", ".gitlab/ci/full-tests.yml")], False),
            ("dependencies", [("M", "go.mod"), ("M", "go.sum")], False),
            ("mixed", [("M", "README.md"), ("M", "cmd/keep/main.go")], False),
            ("unknown", [("M", "new.txt")], False),
            ("new-doc", [("A", "docs/new.md")], False),
            ("deleted", [("D", "README.md")], False),
            ("renamed", [("D", "README.md"), ("A", "docs/README.md")], False),
            ("empty", [], False),
        ]
        for name, changes, docs in cases:
            with self.subTest(name=name):
                self.assertEqual(selector.docs_only(changes), docs)
                config = yaml.safe_load(selector.render(docs, False))
                self.assertEqual("test" not in config and "intake-browser" not in config, docs)
                for job in (["docs-only"] if docs else ["test", "intake-browser"]):
                    self.assertEqual(config[job]["rules"], [{"when": "on_success"}])
                if not docs:
                    self.assertEqual(config["test"]["parallel"]["matrix"][0]["TEST_SUITE"],
                                     ["core-1", "core-2", "targets", "targets-heavy"])
                    self.assertFalse(config["test"].get("allow_failure", False))
                    self.assertFalse(config["intake-browser"].get("allow_failure", False))
        # A deliberately broad selector must fail the same scenario oracle.
        broad = lambda changes: bool(changes)
        with self.assertRaises(AssertionError):
            for _, changes, expected in cases:
                assert broad(changes) == expected

    def test_non_mr_contexts_always_full(self):
        for source in ["schedule", "web", "api", "push", "parent_pipeline", ""]:
            self.assertFalse(selector.can_skip({"CI_PIPELINE_SOURCE": source}))
        mr = {"CI_PIPELINE_SOURCE": "merge_request_event", "CI_COMMIT_BRANCH": "topic",
              "CI_DEFAULT_BRANCH": "main"}
        self.assertTrue(selector.can_skip(mr))
        for override in ["1", "true", "anything"]:
            self.assertFalse(selector.can_skip(dict(mr, KEEP_FULL_CI=override)))
        self.assertFalse(selector.can_skip(dict(mr, CI_COMMIT_BRANCH="main")))

    def test_real_git_statuses_and_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root).decode().strip()
            git("init", "-q")
            git("config", "user.name", "CI test")
            git("config", "user.email", "ci-test@localhost")
            (root / "README.md").write_text("before\n")
            git("add", ".")
            git("commit", "-qm", "docs: initial")
            base = git("rev-parse", "HEAD")
            (root / "README.md").write_text("after\n")
            git("commit", "-qam", "docs: edit")
            head = git("rev-parse", "HEAD")
            self.assertTrue(selector.docs_only(selector.read_diff(base, head, root)))
            (root / "README.md").unlink()
            os.symlink("SECURITY.md", root / "README.md")
            git("add", ".")
            git("commit", "-qm", "docs: symlink")
            self.assertFalse(selector.docs_only(selector.read_diff(base, git("rev-parse", "HEAD"), root)))
            with self.assertRaises(subprocess.CalledProcessError):
                selector.read_diff("missing-ref", head, root)

    def test_missing_diff_and_manual_full_use_full_jobs(self):
        for context in [
            {"CI_PIPELINE_SOURCE": "merge_request_event", "CI_DEFAULT_BRANCH": "main"},
            {"CI_PIPELINE_SOURCE": "merge_request_event", "CI_DEFAULT_BRANCH": "main",
             "CI_MERGE_REQUEST_DIFF_BASE_SHA": "f" * 40, "CI_COMMIT_SHA": "e" * 40},
            {"CI_PIPELINE_SOURCE": "web", "CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "main"},
            {"CI_PIPELINE_SOURCE": "schedule", "CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "main"},
            {"CI_PIPELINE_SOURCE": "merge_request_event", "CI_DEFAULT_BRANCH": "main", "KEEP_FULL_CI": "1"},
        ]:
            with self.subTest(context=context), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "child.yml"
                run = subprocess.run([sys.executable, str(ROOT / "scripts/generate-test-pipeline.py"),
                                      str(output)], env=context, capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                jobs = yaml.safe_load(output.read_text())
                self.assertIn("test", jobs)
                self.assertIn("intake-browser", jobs)



class ImportBoundaryShardSetup(unittest.TestCase):
    """The shard prologue of check-import-boundaries.sh, run on its own."""

    def setup_block(self):
        text = (ROOT / "scripts" / "check-import-boundaries.sh").read_text()
        start, end = text.index("# BEGIN shard-setup"), text.index("# END shard-setup")
        return text[start:end] + 'echo "$shard_index/$shard_total"\n'

    def run_block(self, **env):
        clean = {k: v for k, v in os.environ.items() if k not in ("CI_NODE_TOTAL", "CI_NODE_INDEX")}
        clean.update(env)
        return subprocess.run(["sh", "-c", self.setup_block()], env=clean, capture_output=True, text=True)

    def test_unsharded_runs_everything_even_with_a_stray_index(self):
        for env in ({}, {"CI_NODE_INDEX": "1"}, {"CI_NODE_INDEX": "3"}):
            r = self.run_block(**env)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, "1/1"), env)

    def test_sharded_values_and_refusals(self):
        self.assertEqual(self.run_block(CI_NODE_TOTAL="4", CI_NODE_INDEX="3").stdout.strip(), "3/4")
        for env in ({"CI_NODE_TOTAL": "4"}, {"CI_NODE_TOTAL": "4", "CI_NODE_INDEX": "5"},
                    {"CI_NODE_TOTAL": "04", "CI_NODE_INDEX": "1"}, {"CI_NODE_TOTAL": "4", "CI_NODE_INDEX": "x"}):
            self.assertEqual(self.run_block(**env).returncode, 2, env)

if __name__ == "__main__":
    unittest.main(verbosity=2)
