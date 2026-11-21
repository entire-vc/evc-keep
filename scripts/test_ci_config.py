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
             "carrier-verify", "pgscratch", "mesh", "mesh-ui", "meshgate", "mesh-hierarchy", "mesh-metadata",
             "keylevel-reconcile", "mesh-plugin", "mesh-rotation-e2e", "bootstrap-org",
             "lanepoller", "listening", "console-exec-predicate", "transfer", "transfer-profile", "upgrade-rollback"}
# The mutation batch (a schedule on main every 4 hours) runs only the jobs
# check_mutation_batch names: every other job opens its rules with this one.
BATCH_IF = '$KEEP_MUTATION_BATCH == "true"'
BATCH_NEVER = {"if": BATCH_IF, "when": "never"}
# Rules shared by jobs that run in every pipeline except the mutation batch.
FULL_PIPELINE_ONLY = [BATCH_NEVER, {"when": "on_success"}]
# fmt-vet: the same, but it runs in the batch too (tenancy-mutations reads its artifact).
FMT_VET_RULES = FULL_PIPELINE_ONLY[1:]
MAIN_PUSH_IF = '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $CI_PIPELINE_SOURCE == "push"'
MR_IF = '$CI_PIPELINE_SOURCE == "merge_request_event"'
SCHEDULE_IF = '$CI_PIPELINE_SOURCE == "schedule"'
TAG_IF = "$CI_COMMIT_TAG"
# The one rule list of every mutation job (owner decision of 16.11.2026: one
# pass, at night): the nightly schedule and nothing else. Not on a merge
# request, the push to the default branch, a release tag, or a web, api or
# trigger pipeline; the batch runs its own child (scripts/generate-mutation-pipeline.py).
MUTATION_RULES = [BATCH_NEVER, {"if": SCHEDULE_IF}]
# The intake browser suites run on their own keep-intake runner, under the same rules.
INTAKE_MUTATIONS = "intake-browser-mutations"
# The mutation batch: its range job, the trigger of its child pipeline, and the
# job that keeps the commit the post-review jobs last passed on.
RANGE_JOB, BATCH_TRIGGER, GREEN_JOB = "mutation-range", "mutations-batch", "mutation-green"
# Owner decision of 13.11.2026: a merge request pipeline holds no mutation job and
# no mutation child pipeline. These four jobs once carried the merge request's
# selection (c74493c); none of them may exist again, in any pipeline.
REMOVED_MR_MUTATION_JOBS = ("mutation-range-mr", "start-mutations", "mutations-mr", "mutations-mr-check")
# The one job with "mutation" in its name that a merge request pipeline may still
# list: a manual replay of the selector that runs no mutation suite (see
# check_mutation_backtest).
MR_BACKTEST = "mutation-backtest"
MR_JOBS = {MR_BACKTEST}
TRIGGERS = (BATCH_TRIGGER,)
# Publishes a release on a tag, once the nightly gate passed.
RELEASE_JOB = "release"
RELEASE_GATE = "python3 scripts/release-nightly-gate.py"
RELEASE_VARIABLES = {"GIT_DEPTH": 0}
RELEASE_BEFORE_SCRIPT = ["apk add --no-cache curl git python3"]
PREDEFINED_VARIABLE = re.compile(r"(CI|GITLAB)_")
# The secret-scan gates of every pipeline but the schedule-only branch scan.
SECURITY_JOBS = {"security-hygiene", "secret-scan-scope-selftest"}
# The daily scan of every branch outside the default branch, which replaced the
# scan-only push pipeline of a non-default branch.
BRANCH_SCAN_JOB = "branch-secret-scan"
BRANCH_SCAN_SCRIPT = "./scripts/scan-branch-secrets.sh"
BRANCH_SCAN_SELFTEST = "./scripts/check-branch-secret-scan-selftest.sh"


def check_mutations_never_on_mr(config):
    """Every mutation job uses the one schedule-only rule list: automatic in the
    nightly schedule, absent everywhere else; none is filtered by changed paths."""
    assert config[".mutation-rules"]["rules"] == MUTATION_RULES, config[".mutation-rules"]["rules"]
    assert ".mutation-schedule-rules" not in config, "a second mutation rule anchor is back"
    for name in sorted(MUTATIONS) + ["netns-mutation-run", INTAKE_MUTATIONS]:
        job = config[name if name in ("netns-mutation-run", INTAKE_MUTATIONS) else name + "-mutations"]
        assert job["rules"] == MUTATION_RULES, (name, job["rules"])
        assert job.get("when", "on_success") == "on_success", name
        assert job.get("allow_failure", False) is False, name
    for name, job in config.items():
        if isinstance(job, dict) and job.get("stage") == "post-review":
            assert not any("changes" in r for r in job.get("rules", [])), name


def check_no_manual_jobs(config):
    """No job of the parent waits for a person to play it. One manual job exists
    and it is pinned: the backtest."""
    manual = set()
    for name, job in config.items():
        if name.startswith(".") or not isinstance(job, dict):
            continue
        rules = job.get("rules", [])
        if job.get("when") == "manual" or any(isinstance(r, dict) and r.get("when") == "manual" for r in rules):
            manual.add(name)
    assert manual == {MR_BACKTEST}, manual
    # The historical backtest is played by hand on a merge request and gates
    # nothing (no job needs or depends on it).
    if manual:
        job = config[MR_BACKTEST]
        assert job["rules"] == [{"if": MR_IF, "when": "manual"}], job
        assert job.get("allow_failure") is True, job
        assert "when" not in job, job
        for name, other in config.items():
            if name == MR_BACKTEST or name.startswith(".") or not isinstance(other, dict):
                continue
            for key in ("needs", "dependencies"):
                refs = [n.get("job") if isinstance(n, dict) else n for n in other.get(key, []) or []]
                assert MR_BACKTEST not in refs, (name, key)


def check_mutation_backtest(config):
    """The backtest job replays at least 14 days, writes the bound exhibit, keeps it
    as an artifact, and runs on the shared docker pool, never the mutation runner."""
    assert MR_BACKTEST in config, "the backtest job is missing"
    job = config[MR_BACKTEST]
    assert job["script"] == ["python3 scripts/mutation-select-backtest.py --days 14 --cache backtest-cache.json "
                             "--md backtest-table.md --json backtest.json --exhibit backtest-exhibit.md"], job
    assert "backtest-exhibit.md" in job["artifacts"]["paths"] and job["artifacts"]["when"] == "always", job
    assert job.get("variables", {}).get("GIT_DEPTH") == 0, job
    assert "tags" not in job and job.get("resource_group") == "keep-mutation-backtest", job
    assert job.get("needs") == [], job  # playable at once, waits for no stage
    assert "--no-reproduce" not in " ".join(job["script"]), job


MR = {"CI_DEFAULT_BRANCH": "main", "CI_PIPELINE_SOURCE": "merge_request_event"}


def check_no_mutation_on_mr(config):
    """The owner's guard (13.11.2026): a merge request pipeline carries no mutation
    suite and no mutation child pipeline, however it is created. It has no job with
    the keep-mutations tag, none whose script runs a check-*-mutations.sh script,
    no post-review or release job, no `trigger:` job but the test child, and no job
    with "mutation" in its name but the manual, non-mutating backtest. The four jobs
    that once bridged a merge request to a mutation child do not exist at all."""
    for name in REMOVED_MR_MUTATION_JOBS:
        assert name not in config, f"{name}: a mutation job on merge requests is back"
    for extra in ({}, {"KEEP_FULL_CI": "1"}, {"CI_MERGE_REQUEST_LABELS": "full-ci"}):
        jobs = pipeline_jobs(config, MR | extra)
        assert jobs is not None, extra
        for name in jobs:
            job = effective_job(config, config[name])
            assert "keep-mutations" not in (job.get("tags") or []), (extra, name, "runs on the mutation runner")
        assert not mutation_runners(config, jobs), (extra, mutation_runners(config, jobs))
        assert {name for name in jobs if "mutation" in name} <= MR_JOBS, (extra, sorted(jobs))
        assert {name for name in jobs
                if config[name].get("stage") in ("post-review", RELEASE_JOB)} == set(), extra
        bridges = {name for name in jobs if "trigger" in effective_job(config, config[name])}
        assert bridges == {"full-tests"}, (extra, bridges)
        assert config["full-tests"]["trigger"]["include"] == [
            {"artifact": "full-tests.generated.yml", "job": "fmt-vet"}], config["full-tests"]["trigger"]
    # No other pipeline kind brings them back either: the batch's range and trigger
    # run only for KEEP_MUTATION_BATCH, the rest of the set only for a schedule or a tag.
    for context in (MAIN | {"CI_PIPELINE_SOURCE": "push"}, MAIN | {"CI_PIPELINE_SOURCE": "schedule"},
                    TOPIC | {"CI_PIPELINE_SOURCE": "push"},
                    {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_TAG": "v1.0.0", "CI_PIPELINE_SOURCE": "push"}):
        assert not (pipeline_jobs(config, context) or set()) & set(REMOVED_MR_MUTATION_JOBS), context


TAG = {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_TAG": "v1.0.0", "CI_PIPELINE_SOURCE": "push"}


def every_mutation_job(config):
    """Every mutation job, discovered rather than listed: effective tags include
    keep-mutations, the name ends with -mutations, or the netns run."""
    return {name for name, job in config.items()
            if isinstance(job, dict) and not name.startswith(".") and name not in ("workflow", "default", "variables")
            and ("keep-mutations" in (effective_job(config, job).get("tags") or [])
                 or name.endswith("-mutations") or name == "netns-mutation-run")}


def tag_mutation_jobs(config):
    """The jobs of a release tag pipeline, and those of them that run a mutation
    suite: a post-review job, a mutation job, or any job whose script runs one."""
    jobs = pipeline_jobs(config, TAG) or set()
    return jobs, ({name for name in jobs if config[name].get("stage") == "post-review"}
                  | (jobs & every_mutation_job(config)) | mutation_runners(config, jobs))


def check_release(config):
    """`release` runs only on a tag, alone in the last stage, without `needs`, so
    it starts only after every job of the earlier stages succeeded, none of them
    soft. The tag pipeline runs no mutation suite (they run once a night): before
    publishing, `release` runs the nightly gate over the whole history, and the
    publishing call comes after it in the same job."""
    stages = config["stages"]
    assert stages[-1] == RELEASE_JOB and stages.count(RELEASE_JOB) == 1, stages
    job = config[RELEASE_JOB]
    assert job["stage"] == RELEASE_JOB
    assert job["rules"] == [{"if": TAG_IF}], job["rules"]
    assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"
    assert job.get("interruptible") is False
    # Any `needs` (even `[]`) makes it start as soon as those are done, not the rest.
    assert "needs" not in job, job.get("needs")
    # The gate: its own script line, first, before the line that publishes; a
    # full clone (an ancestor needs the history) with git and python3.
    script = [str(line) for line in job["script"]]
    assert script[0] == RELEASE_GATE, script
    assert sum(RELEASE_GATE in line for line in script) == 1, script
    assert len(script) == 2 and "/releases" in script[1] and "curl --fail-with-body" in script[1], script
    for soft in ("|| true", "|| :", "set +e", "allow_failure", "exit 0"):
        assert soft not in "\n".join(script), soft
    # Pinned exactly: an extra variable (CI_COMMIT_SHA, CI_DEFAULT_BRANCH, the
    # token) points the gate at another commit, and an extra before_script line
    # can rewrite the gate file or re-shallow the clone before the gate runs.
    assert job.get("variables") == RELEASE_VARIABLES, job.get("variables")
    # Global variables reach `release` too and outrank the predefined ones: a
    # global CI_COMMIT_SHA, CI_DEFAULT_BRANCH, CI_PROJECT_ID, CI_API_V4_URL or
    # CI_JOB_TOKEN would point the gate at another commit, branch or project.
    # `extends` would bring variables of a template past the pin above.
    assert not [k for k in config.get("variables") or {} if PREDEFINED_VARIABLE.match(str(k))], config.get("variables")
    assert "extends" not in job, job.get("extends")
    assert job.get("before_script") == RELEASE_BEFORE_SCRIPT, job.get("before_script")
    assert "after_script" not in job
    gate = (ROOT / "scripts/release-nightly-gate.py").read_text()
    assert "--is-ancestor" in gate and "source=schedule" in gate and "mutation-batch" in gate
    jobs, mutation = tag_mutation_jobs(config)
    assert RELEASE_JOB in jobs
    assert not mutation, sorted(mutation)
    for name in jobs - {RELEASE_JOB}:
        other = config[name]
        assert other.get("stage", "test") in stages[:-1], (name, other.get("stage"))
        assert other.get("allow_failure", False) is False, name
        assert other.get("when", "on_success") == "on_success", name
    for name, other in config.items():
        if name != RELEASE_JOB and isinstance(other, dict):
            assert other.get("stage") != RELEASE_JOB, name


CHANGELOG_SCRIPT = ROOT / "scripts" / "changelog-section.sh"
SAMPLE_CHANGELOG = """# Changelog

## [9.9.1]

- marker-new-one

### Breaking changes

- marker-new-two

## [9.9.0]

- marker-old
"""
SAMPLE_SECTION = "- marker-new-one\n\n### Breaking changes\n\n- marker-new-two"


def changelog_section(version, text=None, path=None):
    """Runs scripts/changelog-section.sh on `text` (or the file `path`)."""
    with tempfile.TemporaryDirectory() as tmp:
        if path is None:
            path = Path(tmp) / "CHANGELOG.md"
            path.write_text(text)
        return subprocess.run(["sh", str(CHANGELOG_SCRIPT), version, str(path)],
                              capture_output=True, text=True)


def run_release_job(job, changelog, tag):
    """Runs the publishing step after the nightly gate, in a checkout holding
    `changelog` and the extraction script. Only the external Releases API is
    replaced by a curl stub. The gate and its position are checked separately
    by check_release and test_release_nightly_gate.py."""
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp)
        (tree / "scripts").mkdir()
        shutil.copy(CHANGELOG_SCRIPT, tree / "scripts" / "changelog-section.sh")
        (tree / "CHANGELOG.md").write_text(changelog)
        (tree / "bin").mkdir()
        record = tree / "curl.args"
        stub = tree / "bin" / "curl"
        stub.write_text('#!/bin/sh\nfor a in "$@"; do printf \'%s\\0\' "$a"; done > "$CURL_RECORD"\n')
        stub.chmod(0o755)
        env = {"PATH": f"{tree / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}",
               "CI_COMMIT_TAG": tag, "CI_JOB_TOKEN": "job-token-stub",  # pragma: allowlist secret
               "CI_API_V4_URL": "https://gitlab.invalid/api/v4", "CI_PROJECT_ID": "1",
               "CI_COMMIT_SHA": "0" * 40, "CURL_RECORD": str(record)}
        script = "\n".join(job["script"][1:])
        run = subprocess.run(["sh", "-c", script], cwd=tree, env=env, capture_output=True, text=True)
        args = record.read_text().split("\0")[:-1] if record.exists() else None
        return run.returncode, args


def check_release_notes(config):
    """The `release` job describes the release with the tag's section of
    CHANGELOG.md, verbatim, and publishes nothing for a tag without one. The
    job's own script is run against a sample changelog with curl stubbed."""
    check_release(config)
    job = config[RELEASE_JOB]
    # The section is read from the tag's checkout, so the job must check it out.
    assert job.get("variables", {}).get("GIT_STRATEGY", "fetch") != "none", job.get("variables")
    assert job["before_script"] == RELEASE_BEFORE_SCRIPT, job["before_script"]
    code, args = run_release_job(job, SAMPLE_CHANGELOG, "9.9.1")
    assert code == 0 and args is not None, code
    descriptions = [a for a in args if a.startswith("description=")]
    assert descriptions == ["description=" + SAMPLE_SECTION], descriptions
    assert "tag_name=9.9.1" in args and "name=9.9.1" in args, args
    # A refusal by the Releases API (an existing release, missing rights) is a red job.
    assert "--fail-with-body" in args, args
    # No section, or an empty one, stops the job before curl is ever called.
    for changelog, tag in ((SAMPLE_CHANGELOG, "9.9.2"),
                           (SAMPLE_CHANGELOG.replace("- marker-old", ""), "9.9.0"),
                           ("", "9.9.1")):
        code, args = run_release_job(job, changelog, tag)
        assert code != 0 and args is None, (tag, code, args)


def check_changelog_has_manifest_version(root=ROOT):
    """The version in mesh-extension.json has its own non-empty section in
    CHANGELOG.md, so the tag of that version gets a release description."""
    import json
    version = json.loads((root / "mesh-extension.json").read_text())["version"]
    run = changelog_section(version, path=root / "CHANGELOG.md")
    assert run.returncode == 0 and run.stdout.strip(), (version, run.stderr)


# Every pipeline kind but the nightly schedule: none may start a mutation suite.
NON_SCHEDULE_CONTEXTS = {
    "merge request": MR,
    "merge request, KEEP_FULL_CI": MR | {"KEEP_FULL_CI": "1"},
    "merge request, full-ci label": MR | {"CI_MERGE_REQUEST_LABELS": "full-ci"},
    **{f"main {source}": {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "main", "CI_COMMIT_REF_NAME": "main",
                          "CI_PIPELINE_SOURCE": source} for source in ("push", "web", "api", "trigger")},
    **{f"topic {source}": {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "topic", "CI_COMMIT_REF_NAME": "topic",
                           "CI_PIPELINE_SOURCE": source} for source in ("web", "api", "trigger")},
    "release tag": TAG,
}


def check_mutations_only_in_schedule(config):
    """Owner decision of 16.11.2026: mutation suites run once a night. No pipeline
    but the schedule holds a job on the keep-mutations runner, a job running a
    check-*-mutations.sh script, or any mutation job; the schedule holds every one.
    (The hand-started batch is pinned by check_mutation_batch.)"""
    every = every_mutation_job(config)
    assert len(every) > 40 and INTAKE_MUTATIONS in every and "netns-mutation-run" in every, sorted(every)
    for label, context in NON_SCHEDULE_CONTEXTS.items():
        jobs = pipeline_jobs(config, context)
        assert jobs is not None, label
        on_runner = {name for name in jobs
                     if "keep-mutations" in (effective_job(config, config[name]).get("tags") or [])}
        assert not on_runner, (label, "keep-mutations runner", sorted(on_runner))
        assert not mutation_runners(config, jobs), (label, "mutation script", sorted(mutation_runners(config, jobs)))
        assert not jobs & every, (label, sorted(jobs & every))
    schedule = pipeline_jobs(config, MAIN | {"CI_PIPELINE_SOURCE": "schedule"})
    assert schedule is not None and every <= schedule, sorted(every - (schedule or set()))


CRANE_PIN = r"gcr\.io/go-containerregistry/crane:debug@sha256:[0-9a-f]{64}"


PROBE_CALL = 'python3 -I "$(dirname "$0")/registry_auth_probe.py" allow || fail "registry authorization probe refused"\n'


def check_publish_script(text):
    """The push is reachable only after the CI server and the registry showed this job as the publisher."""
    assert text.count("registry_auth_probe.py") == 1 and text.count(PROBE_CALL) == 1, "no (or a swallowed) authorization probe"
    assert text.startswith("#!") and "set -eu" in text
    assert text.index(PROBE_CALL) < text.index('check-mesh-tag-absent.sh"') < text.index("crane ${CRANE_OPTS:-} push"), \
        "probe, tag check and push must run in this order"


GO_ALPINE = r"golang:1\.25\.14-alpine3\.24@sha256:[0-9a-f]{64}"


def check_auth_deny(config, script_text):
    """The merge-request negative control exists, is required and runs nowhere else."""
    assert "image-auth-deny-mesh" in config, "no negative authorization control"
    job = config["image-auth-deny-mesh"]
    assert job["script"] == ["python3 -I scripts/registry_auth_probe.py deny"]
    assert job.get("before_script") == ["apk add --no-cache python3"]
    assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"
    assert re.fullmatch(GO_ALPINE, job["image"] if isinstance(job["image"], str) else job["image"]["name"])
    assert job["rules"] == [{"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'}]
    assert "needs" not in job and "trigger" not in job
    assert "resource_group" not in job and not job.get("services")
    assert not job.get("artifacts"), "the probe leaves no artifact"
    mr = {"CI_DEFAULT_BRANCH": "main", "CI_PIPELINE_SOURCE": "merge_request_event", "CI_COMMIT_BRANCH": "topic",
          "CI_COMMIT_REF_PROTECTED": "false"}
    assert "image-auth-deny-mesh" in pipeline_jobs(config, mr), "merge request pipelines do not run the deny probe"
    main = MAIN | {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_REF_PROTECTED": "true"}
    for label, context in {"main push": main, "schedule": {**main, "CI_PIPELINE_SOURCE": "schedule"},
                           "topic push": {**TOPIC, "CI_PIPELINE_SOURCE": "push"}}.items():
        assert "image-auth-deny-mesh" not in (pipeline_jobs(config, context) or set()), label
    for banned in ("docker login", "printenv", "set -x", "CI_JOB_TOKEN", "CI_REGISTRY_PASSWORD"):
        assert banned not in "\n".join(job["script"]), banned
    assert PROBE_CALL in (ROOT / "scripts/publish-mesh-image.sh").read_text()
    assert 'SCOPES = ("pull", "pull,push", "pull,delete", "pull,*")' in script_text and "/jwt/auth" in script_text
    assert "/api/v4/job" in script_text, "the probe must read the server-side job context"
    fmt = "\n".join(merged_script(config, config["fmt-vet"]))
    assert "python3 scripts/test_registry_auth_probe.py" in fmt, "the probe tests are not run by CI"


def check_auth_only(config, publish_text, pull_text):
    """Without the protected opt-in naming this commit nothing is written, and nothing downstream runs."""
    guard = 'if [ "${KEEP_MESH_IMAGE_WRITE_SHA:-}" != "$CI_COMMIT_SHA" ]; then'
    assert publish_text.count(guard) == 1, "no opt-in guard"
    assert publish_text.index(PROBE_CALL) < publish_text.index(guard) \
        < publish_text.index('check-mesh-tag-absent.sh"') < publish_text.index("crane ${CRANE_OPTS:-} push"), "guard order"
    block = publish_text[publish_text.index(guard):publish_text.index("fi\n", publish_text.index(guard))]
    assert "exit 0" in block and "mesh-image-auth-only.json" in block and "push" not in block.replace("registry push authorization", "")
    assert "mesh-image-auth-only.json" in config["image-publish-mesh"]["artifacts"]["paths"]
    assert "mesh-image-publish.json" in config["image-publish-mesh"]["artifacts"]["paths"]
    assert "mesh-image-auth-only.json" in pull_text.split("pub=${PUBLISH_JSON")[0], "pull job ignores the auth-only marker"
    receipt = config["image-receipt-mesh"]["script"]
    assert "mesh-image-auth-only.json" in receipt[0] and "exit 0" in receipt[0], "receipt job writes a receipt for an auth-only run"


def check_image_publish(config):
    """The Mesh image is published only by a push to the protected default branch,
    after every earlier job succeeded, to the project registry, by commit SHA."""
    main = MAIN | {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_REF_PROTECTED": "true"}
    contexts = {
        "merge request": {"CI_DEFAULT_BRANCH": "main", "CI_PIPELINE_SOURCE": "merge_request_event",
                          "CI_COMMIT_BRANCH": "topic", "CI_COMMIT_REF_PROTECTED": "false"},
        "merge request from a protected branch": {**main, "CI_PIPELINE_SOURCE": "merge_request_event"},
        "topic push": {**TOPIC, "CI_PIPELINE_SOURCE": "push", "CI_COMMIT_REF_PROTECTED": "false"},
        "unprotected default push": {**main, "CI_COMMIT_REF_PROTECTED": "false"},
        "schedule": {**main, "CI_PIPELINE_SOURCE": "schedule"},
        "web": {**main, "CI_PIPELINE_SOURCE": "web"},
        "mutation batch": {**main, "KEEP_MUTATION_BATCH": "true"},
        "tag": {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_TAG": "v1.0.0", "CI_PIPELINE_SOURCE": "push",
                "CI_COMMIT_REF_PROTECTED": "true"},
    }
    for label, context in contexts.items():
        jobs = pipeline_jobs(config, context) or set()
        assert not jobs & set(PUBLISH_JOBS), (label, jobs & set(PUBLISH_JOBS))
    jobs = pipeline_jobs(config, main)
    assert set(PUBLISH_JOBS) <= jobs, "the protected default-branch push does not publish"
    stages = config["stages"]
    assert stages.index("post-review") < stages.index("publish") < stages.index(RELEASE_JOB), stages
    # Nothing before `publish` may fail softly or wait for a person: the stage
    # starts only when every earlier job of the main pipeline succeeded.
    for name in jobs - set(PUBLISH_JOBS):
        job = config[name]
        stage = job.get("stage", "test")
        if stage in stages and stages.index(stage) < stages.index("publish"):
            assert job.get("allow_failure", False) is False, name
            assert job.get("when", "on_success") == "on_success", name
    assert "needs" not in config["image-tar-mesh"], "needs would start the build before the earlier stages finish"
    assert config["image-publish-mesh"].get("needs") == [{"job": "image-tar-mesh", "artifacts": True},
                                                         {"job": "image-crane-mesh", "artifacts": True}]
    crane_job = config["image-crane-mesh"]
    assert crane_job["script"] == ["cp /ko-app/crane crane"] and crane_job["artifacts"] == {"paths": ["crane"], "expire_in": "1 day"}
    assert re.fullmatch(CRANE_PIN, crane_job["image"]["name"]) and "needs" not in crane_job
    assert config["image-publish-mesh"].get("before_script") == [
        "apk add --no-cache python3",
        'echo "9ffac7be7938a2cc38b7e76a9ef2181805c74f848279049697b7efac96349e23  crane" | sha256sum -c -',
        "chmod +x crane", 'export PATH="$PWD:$PATH"'], "crane must be checksum-verified before it is used"
    assert config["image-publish-mesh"].get("resource_group") == "keep-image-publish-mesh", \
        "the tag check and the push must be serialized"
    assert config["image-publish-mesh"]["script"] == ["sh scripts/publish-mesh-image.sh"]
    publisher_image = config["image-publish-mesh"]["image"]
    assert re.fullmatch(GO_ALPINE, publisher_image if isinstance(publisher_image, str) else publisher_image["name"])
    assert config["image-pull-mesh"]["needs"] == [{"job": "image-publish-mesh", "artifacts": True}]
    assert {n["job"] for n in config["image-receipt-mesh"]["needs"]} == {"image-publish-mesh", "image-pull-mesh"}
    for name in PUBLISH_JOBS:
        job = config[name]
        assert job["stage"] == "publish", name
        assert job.get("allow_failure", False) is False, name
        assert job.get("when", "on_success") == "on_success", name
        assert job.get("interruptible") is False, name
        assert job["rules"] == config["image-publish-mesh"]["rules"], name
        assert "trigger" not in job, name
        if name not in ("image-tar-mesh", "image-crane-mesh"):
            assert job["artifacts"]["expire_in"] == "1 year", name  # not the one hour of the build tar
        script = "\n".join(merged_script(config, job))
        for banned in ("printenv", "set -x", "set -o xtrace", "docker login", "latest", "ghcr.io", "docker.io"):
            assert banned not in script, (name, banned)
        assert not re.search(r"(^|\s)env(\s|$)", script), name
        assert "KEEP_" not in script.replace("KEEP_ADMIN_URL", ""), name
        assert ".docker" not in " ".join(job.get("artifacts", {}).get("paths", [])), name
    rule_text = " ".join(r.get("if", "") for r in config["image-publish-mesh"]["rules"])
    assert "CI_COMMIT_REF_PROTECTED" in rule_text and "$CI_PIPELINE_SOURCE == \"push\"" in rule_text
    tar = "\n".join(config["image-tar-mesh"]["script"])
    assert "--no-push" in tar and "--tar-path" in tar and "CI_REGISTRY" not in tar, "the build job must hold no registry login"
    assert tar.count("--destination") == 1
    for arg in ("SERVER_VARIANT=mesh", 'BUILD_COMMIT="$CI_COMMIT_SHA"', 'BUILD_TIME="$CI_COMMIT_TIMESTAMP"', "--reproducible"):
        assert arg in tar, arg
    assert config["image-tar-mesh"]["image"]["name"].startswith("gcr.io/kaniko-project/executor:v1.23.2")
    script_text = (ROOT / "scripts/publish-mesh-image.sh").read_text()
    assert 'repo="$CI_REGISTRY_IMAGE/keep-server-mesh"' in script_text
    assert script_text.count("crane ${CRANE_OPTS:-} push") == 1 and '"$repo:$CI_COMMIT_SHA"' in script_text
    assert script_text.index("check-mesh-tag-absent.sh") < script_text.index("push"), "check must precede the push"
    assert re.fullmatch(r"gcr\.io/go-containerregistry/crane:debug@sha256:[0-9a-f]{64}",
                        config["image-pull-mesh"]["image"]["name"])
    assert config["image-pull-mesh"]["script"] == ["sh scripts/pull-mesh-image.sh"]
    receipt = "\n".join(merged_script(config, config["image-receipt-mesh"]))
    assert "mesh_image_receipt.py build" in receipt and "mesh_image_receipt.py verify" in receipt
    check_publish_script(script_text)
    check_auth_deny(config, (ROOT / "scripts/registry_auth_probe.py").read_text())
    check_auth_only(config, script_text, (ROOT / "scripts/pull-mesh-image.sh").read_text())
    # The existing no-push build check stays.
    assert "--no-push" in "\n".join(config["image-build-mesh"]["script"])
    assert config["image-build-mesh"]["rules"] == config["image-build"]["rules"]


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
    assert job["rules"] == MUTATION_RULES
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


def filter_drivers(root=ROOT):
    """Drivers that report through scripts/test-result-names.sh (python3)."""
    return {p.name for p in (root / "scripts").glob("check-*.sh")
            if "test-result-names.sh" in p.read_text()}


def check_filter_has_python(config, drivers):
    """A job running such a driver on the alpine Go image (no python3) installs
    it; else the filter exits 127 and a red mutant is reported with no names."""
    seen = set()
    for name, job in config.items():
        if name.startswith(".") or not isinstance(job, dict):
            continue
        script = "\n".join(str(line) for line in job.get("script", []))
        used = {d for d in drivers if d in script}
        if not used:
            continue
        seen |= used
        if job.get("extends") != ".go-module-cache" or "image" in job:
            continue  # bookworm and browser images ship python3
        apk = [shlex.split(str(line)) for line in job.get("before_script", []) if str(line).startswith("apk add")]
        assert any("python3" in words for words in apk), f"{name}: runs {sorted(used)} without python3"
    assert drivers and seen, "no job runs a driver that reports through test-result-names.sh"


def check_mesh_plugin_mutations(config):
    """The plugin's mutation script runs in shards after review, with the other
    mutation suites, blocking, and with a 40% margin under the job timeout per shard."""
    plugin, job = config["mesh-plugin"], config["mesh-plugin-mutations"]
    assert not mutation_runners(config, ["mesh-plugin"]), plugin["script"]
    assert "go test -race" in "\n".join(plugin["script"])
    assert any(service.get("alias") == "postgres" for service in plugin.get("services", [])), "workspace approval test needs PostgreSQL"
    assert plugin.get("variables", {}).get("KEEP_DATABASE_URL"), "workspace approval test must not skip"
    assert job["rules"] == config[".mutation-rules"]["rules"], job["rules"]
    assert job["stage"] == "post-review"
    assert job["parallel"] == 3 and job["timeout"] == "20m"
    assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"
    assert job["dependencies"] == []
    assert job["resource_group"] == "keep-mutation-pool-$CI_NODE_INDEX"
    assert job["script"] == [
        "MUTATION_SHARD_INDEX=$CI_NODE_INDEX MUTATION_SHARD_TOTAL=$CI_NODE_TOTAL "
        "timeout -k 10s 19m ./scripts/check-mesh-plugin-mutations.sh"]


def check_mesh_mutations_limits(config):
    """mesh-mutations shards run ~17 min at p95; the limits keep p95 <= 60% of the
    30 m script limit, so a slow runner does not turn the job red (exit 143)."""
    job = config["mesh-mutations"]
    assert job["parallel"] == 2 and job["timeout"] == "35m", (job["parallel"], job["timeout"])
    assert ("MUTATION_SHARD_INDEX=$CI_NODE_INDEX MUTATION_SHARD_TOTAL=$CI_NODE_TOTAL "
            "timeout -k 10s 30m ./scripts/check-mesh-mutations.sh") in job["script"], job["script"]


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
    assert stages == ["security", "lint", "test", "build", "post-review", "publish", "release"]
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
    # The merged-parent lookup needs curl and jq; without them the check
    # excuses nothing and a stacked merge request stays red.
    assert gate["before_script"][0] == "apk add --no-cache curl jq", gate.get("before_script")
    hygiene_mutations = config.get("public-hygiene-mutations", {}).get("before_script", [""])
    assert hygiene_mutations[0].split()[3:] == ["git", "nodejs", "python3", "curl", "jq"], hygiene_mutations
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
    for name in ("fmt-vet", "golangci-lint", "import-boundaries"):
        assert config[name]["stage"] == "lint", name
    for name in ("fmt-vet", "golangci-lint"):
        assert config[name]["tags"] == ["ci-fast"], name  # light lint gate: fast lane
    # minutes of CPU each: burst pool, so they do not hold fast-lane slots
    assert config["import-boundaries"]["tags"] == ["ci-burst"]
    assert config["ci-selftests"]["tags"] == ["docker", "ci-burst"]
    scope = config["secret-scan-scope-selftest"]
    assert scope["stage"] == "security"
    assert scope["image"] == gate["image"]
    assert scope["script"] == ["./scripts/check-secret-scan-scope.sh", BRANCH_SCAN_SELFTEST]
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
        "if": '$CI_COMMIT_BRANCH && $CI_PIPELINE_SOURCE == "push"', "when": "never"}
    assert workflow["rules"][5:] == [{"if": "$CI_COMMIT_BRANCH"},
                                     {"if": TAG_IF, "auto_cancel": {"on_new_commit": "none"}}]
    check_branch_secret_scan(config)
    trigger = config["full-tests"]
    assert trigger["trigger"]["strategy"] == "depend"
    assert trigger.get("allow_failure", False) is False
    assert trigger["trigger"]["include"] == [{"artifact": "full-tests.generated.yml", "job": "fmt-vet"}]
    generator = config["fmt-vet"]
    assert generator["variables"]["GIT_DEPTH"] == 0
    assert "python3 scripts/test_ci_config.py" in generator["script"]
    assert "python3 scripts/test_mutation_canary.py" in generator["script"]
    assert "./scripts/check-lint-directives.sh" in generator["script"]
    assert "go vet ./..." in generator["script"]
    assert "python3 scripts/generate-test-pipeline.py full-tests.generated.yml" in generator["script"]
    assert "python3 scripts/mutation-canary.py prepare" in generator["script"]
    assert generator["artifacts"]["paths"] == ["full-tests.generated.yml", "mutation-canary.decision"]
    check_selftests_job(config)
    check_import_boundaries_job(config)
    check_rotation_testbed_job(config)
    check_rotation_testbed_mesh_job(config)
    assert "full-tests.generated.yml" in generator["artifacts"]["paths"]
    assert {name.removesuffix("-mutations") for name in config
            if name.endswith("-mutations") and name != INTAKE_MUTATIONS} == MUTATIONS
    for name in MUTATIONS:
        assert config[name + "-mutations"].get("allow_failure", False) is False
    check_mutations_never_on_mr(config)
    check_no_manual_jobs(config)
    check_no_mutation_on_mr(config)
    check_mutation_backtest(config)
    check_release(config)
    check_release_notes(config)
    check_changelog_has_manifest_version()
    check_mutations_only_in_schedule(config)
    check_mutation_fan_out_cap(config)
    check_post_review_artifacts(config)
    check_netns_mutation_run_manual_on_mr(config)
    check_mutation_runner(config)
    check_mesh_plugin_mutations(config)
    check_mesh_mutations_limits(config)
    check_filter_has_python(config, filter_drivers())
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
    rollback = config["upgrade-rollback-mutations"]
    assert rollback["stage"] == "post-review"
    assert rollback["script"] == ["./scripts/check-upgrade-rollback-mutations.sh"]
    assert "REDRUN_ONLY" not in rollback.get("variables", {}), "the job must run all mutants"
    assert rollback["rules"] == MUTATION_RULES
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
    "python3 scripts/test_intake_hpke_mutant_diagnostics.py",
    "python3 scripts/test_upgrade_rollback_output_leak.py",
    "python3 scripts/test_driver_output_leak.py",
    "python3 scripts/test_release_nightly_gate.py",
    "python3 scripts/test_quickstart_output_leak.py",
    "python3 scripts/test_public_hygiene_merged_parent.py",
]
SELFTESTS_APK = "apk add --no-cache bash git python3 py3-yaml perl tar curl jq"
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
    # test_quickstart_output_leak.py: the page the red runs mutate and tests
    # whose declared names the result filter may print.
    sources.add("docs/quickstart.md")
    sources |= {str(p.relative_to(root)) for p in (root / "test/e2e").glob("*_test.go")}
    sources.add("test/quickstart/leak_test.go")
    return sources


def check_selftests_job(config):
    """ci-selftests: a light lint gate off the fmt-vet critical path that still
    runs everywhere it ran before, except on an MR that touches none of its inputs."""
    job = config["ci-selftests"]
    assert job["tags"] == ["docker", "ci-burst"]
    # Four nodes from the test stage, needing nothing: it neither waits for the
    # lint stage nor holds the test stage (dispatch_ci_selftests.py shards it).
    assert job.get("stage") == "test", job.get("stage")
    assert job.get("needs") == [], job.get("needs")
    assert job.get("parallel") == 4, job.get("parallel")
    assert job["extends"] == ".go-module-cache"
    assert job["before_script"] == [SELFTESTS_APK], job["before_script"]
    assert job["script"] == ["python3 scripts/test_ci_selftests_dispatcher.py",
                              "python3 scripts/dispatch_ci_selftests.py"], job["script"]
    dispatcher = (ROOT / "scripts/dispatch_ci_selftests.py").read_text()
    tree = ast.parse(dispatcher)
    commands = next(node.value for node in tree.body
                    if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "COMMANDS"
                            for target in node.targets))
    command_names = ("mutation_shards", "carriers", "intake_baseline", "intake_mutant",
                     "catalog_mutant", "runnerproto", "tenancy", "cli_witnesses",
                     "approvals", "builtin_job_cache", "baseline_diag", "w3_stubs",
                     "dispatch_baseline", "mutation_select", "mutation_select_redrun",
                     "intake_hpke_mutant", "upgrade_rollback_output",
                     "driver_output_leak", "release_nightly_gate", "quickstart_output_leak",
                     "public_hygiene_parent")
    expected_commands = []
    for name, command in zip(command_names, SELFTESTS, strict=True):
        words = shlex.split(command)
        extra = {}
        while words and "=" in words[0] and not words[0].startswith("./"):
            key, value = words.pop(0).split("=", 1)
            extra[key] = value
        expected_commands.append((name, tuple(words), extra))
    assert ast.literal_eval(commands) == tuple(expected_commands)
    assert not set(SELFTESTS) & set(config["fmt-vet"]["script"])
    assert job.get("allow_failure", False) is False and job.get("when", "on_success") == "on_success"
    assert "dependencies" not in job
    rules = job["rules"]
    assert rules[:1] == [BATCH_NEVER], rules
    assert rules[1] == {"if": MR_IF + " && $KEEP_FULL_CI"}, rules
    assert set(rules[2]) == {"if", "changes"} and rules[2]["if"] == MR_IF, rules
    assert rules[3:] == [{"if": MR_IF, "when": "never"}, {"when": "on_success"}], rules
    changes = mr_changes(job)
    paths = {".gitlab-ci.yml", ".gitlab/ci/full-tests.yml", "go.mod", "go.sum",
             "scripts/mutation-helpers.sh", "scripts/lib/gocache.sh"}
    paths.add("scripts/dispatch_ci_selftests.py")
    paths |= {line.split()[-1].removeprefix("./") for line in SELFTESTS}
    paths |= selftest_sources()
    assert not uncovered(changes, paths), uncovered(changes, paths)
    # Nothing waits for it: no job takes it as a need or an artifact source.
    for name, other in config.items():
        if not isinstance(other, dict):
            continue
        needs = [n["job"] if isinstance(n, dict) else n for n in other.get("needs", [])]
        assert "ci-selftests" not in needs + list(other.get("dependencies", [])), name


ROTATION_TESTBED = "rotation-testbed"
ROTATION_TESTBED_ARTIFACTS = ["testbed-out/receipt.json", "testbed-out/scan.result", "testbed-out/scan.control"]
ROTATION_TESTBED_PATHS = ["scripts/testbed/**/*", "internal/rotation/**/*", "cmd/keep-server/**/*",
                          "cmd/keep-runner/**/*", "cmd/keep/**/*", "internal/runner/**/*",
                          "internal/carriers/**/*", "internal/targets/**/*", "pkg/rotation/**/*",
                          "Dockerfile", ".gitlab-ci.yml", "go.mod", "go.sum"]


ROTATION_TESTBED_OTHER_SOURCES = ("web", "api", "trigger", "pipeline", "parent_pipeline", "chat",
                                  "external", "webide", "ondemand_dast_scan")


def check_rotation_testbed_job(config):
    """The rotation testbed runs by itself, on the privileged runner, whenever
    its paths change, fails the pipeline when it fails, and uploads only the
    receipt and the scan logs (the out directory holds needles and input links)."""
    assert ROTATION_TESTBED in config, "rotation-testbed job is missing"
    job = config[ROTATION_TESTBED]
    assert job["tags"] == ["keep-netns"] and job["stage"] == "test", job
    assert job["resource_group"] == "keep-rotation-testbed"
    assert job.get("allow_failure", False) is False
    assert job.get("when", "on_success") == "on_success"
    assert job["image"] == "docker:27-cli"
    assert job["services"] == [{"name": "docker:27-dind", "alias": "docker", "command": ["--tls=false"]}]
    assert job["variables"]["DOCKER_HOST"] == "tcp://docker:2375"
    assert job["variables"]["DOCKER_TLS_CERTDIR"] == ""
    assert job["variables"]["TESTBED_OUT"] == "$CI_PROJECT_DIR/testbed-out"
    minutes = int(str(job["timeout"]).removesuffix("m"))
    assert 0 < minutes <= 30, job["timeout"]
    rules = job["rules"]
    assert rules[:1] == [BATCH_NEVER], rules
    assert {"if": '$CI_PIPELINE_SOURCE == "schedule"'} in rules, rules
    assert {"if": MAIN_PUSH_IF} in rules, rules
    for rule in rules:
        assert rule.get("when", "on_success") != "manual", rule
    # Outside merge requests the privileged testbed starts only from a schedule
    # or a push to the default branch: not from web, api, trigger or a topic push.
    def runs(ref, source):
        rule = first_rule(rules, ref | {"CI_PIPELINE_SOURCE": source})
        return rule is not None and rule.get("when", "on_success") != "never"
    for source in ROTATION_TESTBED_OTHER_SOURCES + ("push", "schedule"):
        assert runs(MAIN, source) == (source in ("push", "schedule")), ("main", source, rules)
        assert runs(TOPIC, source) == (source == "schedule"), ("topic", source, rules)
    mr = [r for r in rules if r.get("if") == MR_IF]
    assert len(mr) == 1 and "when" not in mr[0] and "changes" in mr[0], rules
    missing = uncovered(mr_changes(job), set(ROTATION_TESTBED_PATHS))
    assert not missing, missing
    # The single steps exit 0 whatever the rotation answered; only `all` checks
    # both scenarios and fails on a broken property.
    assert job["script"] == ["./scripts/testbed/rotation.sh all"], job["script"]
    assert job.get("after_script") == ["./scripts/testbed/rotation.sh down"], job.get("after_script")
    artifacts = job["artifacts"]
    assert artifacts["when"] == "always" and artifacts["expire_in"] == "14 days", artifacts
    assert artifacts["paths"] == ROTATION_TESTBED_ARTIFACTS, artifacts["paths"]
    assert "exclude" not in artifacts and "untracked" not in artifacts, artifacts
    # Artifacts of earlier stages are unpacked into the checkout as untracked
    # files, and the receipt then says working_tree_dirty=true. The job reads
    # none of them.
    assert job.get("dependencies") == [], job.get("dependencies")
    for need in job.get("needs", []):
        assert isinstance(need, dict) and need.get("artifacts") is False, need
    for name, other in config.items():
        if not isinstance(other, dict):
            continue
        needs = [n["job"] if isinstance(n, dict) else n for n in other.get("needs", [])]
        assert ROTATION_TESTBED not in needs + list(other.get("dependencies", [])), name


ROTATION_TESTBED_MESH = "rotation-testbed-mesh"
ROTATION_TESTBED_MESH_ARTIFACTS = ["testbed-mesh-out/receipt.json", "testbed-mesh-out/scan.result",
                                   "testbed-mesh-out/scan.control"]
ROTATION_TESTBED_MESH_PATHS = ROTATION_TESTBED_PATHS + ["plugins/mesh/**/*", "internal/deployment/**/*"]
MESH_FETCH = ('git -C "$TESTBED_MESH_SRC" fetch -q --depth 1 '
              '"${CI_REPOSITORY_URL%/$CI_PROJECT_PATH.git}/entire-vc/evc-mesh.git" "$TESTBED_MESH_SHA"')
MESH_PIN_CHECK = 'test "$(git -C "$TESTBED_MESH_SRC" rev-parse HEAD)" = "$TESTBED_MESH_SHA"'
ROTATION_TESTBED_MESH_VARIABLES = {"DOCKER_HOST", "DOCKER_TLS_CERTDIR", "TESTBED_OUT", "TESTBED_MESH_SRC",
                                   "TESTBED_MESH_SHA"}
# What would put the job token (it is in CI_REPOSITORY_URL) or a stand value into
# the public job log: a shell, git or curl trace, or the runner's debug trace.
TRACE_WORDS = re.compile(r"GIT_TRACE|GIT_CURL_VERBOSE|CI_DEBUG_TRACE|CI_DEBUG_SERVICES|SHELLOPTS|BASH_ENV"
                         r"|BASH_XTRACEFD|\bENV\s*[:=]|\bxtrace\b|\bset\s+[-+]o\s+verbose\b"
                         r"|\bcurl\b[^|;&]*(?:\s-[A-Za-z]*v|--verbose|--trace)")
# The short flags of `set` and of a shell started by name: x (xtrace) or v
# (verbose) anywhere among them, in any case and any grouping, is a trace.
SHELL_FLAGS = re.compile(r"\b(?:set|shopt|(?:ba|da)?sh)((?:\s+[-+][A-Za-z]+)+)")
# The scripts the Mesh testbed job runs, found rather than listed, so a new one
# is covered; their text must not turn a trace on either.
ROTATION_TESTBED_MESH_SCRIPTS = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "scripts/testbed").rglob("*.sh"))


def logical_lines(lines):
    """Shell logical lines: the input (lines, or job steps that may hold several
    lines each) split on newlines, with every backslash-newline continuation
    joined, so `curl \\` followed by `-v ...` is one line to the trace check."""
    return re.sub(r"\\\n", " ", "\n".join(lines)).split("\n")


def traced(lines):
    """The logical lines that turn a trace on; comment lines do not count."""
    out = []
    for line in logical_lines(lines):
        if line.lstrip().startswith("#"):
            continue
        flags = [f for m in SHELL_FLAGS.finditer(line) for f in m.group(1).split() if not f.startswith("--")]
        if TRACE_WORDS.search(line) or any(set(f[1:].lower()) & {"x", "v"} for f in flags):
            out.append(line)
    return out


def unignored_testbed_dirs(config, gitignore):
    """Paths inside the build directory that the rotation testbed jobs write to
    (TESTBED_OUT, TESTBED_MESH_SRC) and that the given .gitignore does not ignore:
    each would make the receipt's working_tree_dirty true for the wrong reason.
    Returns (in-tree dirs found, git status lines they caused)."""
    dirs = []
    for name in (ROTATION_TESTBED, ROTATION_TESTBED_MESH):
        variables = config[name].get("variables", {})
        for key in ("TESTBED_OUT", "TESTBED_MESH_SRC"):
            value = str(variables.get(key, ""))
            if value.startswith("$CI_PROJECT_DIR/"):
                dirs.append(value.removeprefix("$CI_PROJECT_DIR/"))
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "init", "-q", tmp], check=True, capture_output=True)
        Path(tmp, ".gitignore").write_text(gitignore)
        for d in dirs:
            Path(tmp, d, "sub").mkdir(parents=True, exist_ok=True)
            Path(tmp, d, "sub", "f").write_text("")
        status = subprocess.run(["git", "-C", tmp, "status", "--porcelain", "--untracked-files=all"],
                                capture_output=True, text=True, check=True).stdout
    return dirs, [line[3:] for line in status.splitlines() if line[3:] != ".gitignore"]


def check_rotation_testbed_mesh_job(config):
    """The testbed with a disposable Mesh runs by itself on the privileged
    runner, builds Mesh from a pinned evc-mesh commit fetched with the job token,
    runs both scenarios with their checks (`all --mesh`), fails the pipeline
    when it fails, and uploads only the receipt and the scan logs."""
    assert ROTATION_TESTBED_MESH in config, "rotation-testbed-mesh job is missing"
    job = config[ROTATION_TESTBED_MESH]
    assert job["tags"] == ["keep-netns"] and job["stage"] == "test", job
    assert job["resource_group"] == "keep-rotation-testbed"
    # No artifact of an earlier job lands in the tree: the receipt records
    # working_tree_dirty, and a downloaded file would make the tree dirty.
    assert job.get("dependencies") == [], job.get("dependencies", "<unset>")
    assert "needs" not in job, job["needs"]
    assert job.get("allow_failure", False) is False
    assert job.get("when", "on_success") == "on_success"
    assert job["image"] == "docker:27-cli"
    assert job["services"] == [{"name": "docker:27-dind", "alias": "docker", "command": ["--tls=false"]}]
    variables = job["variables"]
    assert variables["DOCKER_HOST"] == "tcp://docker:2375"
    assert variables["DOCKER_TLS_CERTDIR"] == ""
    assert variables["TESTBED_OUT"] == "$CI_PROJECT_DIR/testbed-mesh-out"
    # In the build directory: the after_script container (rotation.sh down) needs it.
    assert variables["TESTBED_MESH_SRC"] == "$CI_PROJECT_DIR/.testbed-mesh-src"
    # A commit, never a branch or a tag: the receipt names what it stands on.
    assert re.fullmatch(r"[0-9a-f]{40}", str(variables.get("TESTBED_MESH_SHA", ""))), variables
    # A closed list: no trace switch (GIT_TRACE, CI_DEBUG_TRACE ...) rides in here.
    assert set(variables) == ROTATION_TESTBED_MESH_VARIABLES, sorted(variables)
    assert not traced(f"{k}: {v}" for k, v in config.get("variables", {}).items()), config.get("variables")
    minutes = int(str(job["timeout"]).removesuffix("m"))
    assert 0 < minutes <= 30, job["timeout"]
    rules = job["rules"]
    assert rules[:1] == [BATCH_NEVER], rules
    assert {"if": '$CI_PIPELINE_SOURCE == "schedule"'} in rules, rules
    assert {"if": MAIN_PUSH_IF} in rules, rules
    for rule in rules:
        assert rule.get("when", "on_success") != "manual", rule
    # Outside merge requests the privileged stand starts only from a schedule or a
    # push to the default branch: not from web, api, trigger or a topic push.
    def runs(ref, source):
        rule = first_rule(rules, ref | {"CI_PIPELINE_SOURCE": source})
        return rule is not None and rule.get("when", "on_success") != "never"
    for source in ROTATION_TESTBED_OTHER_SOURCES + ("push", "schedule"):
        assert runs(MAIN, source) == (source in ("push", "schedule")), ("main", source, rules)
        assert runs(TOPIC, source) == (source == "schedule"), ("topic", source, rules)
    mr = [r for r in rules if r.get("if") == MR_IF]
    assert len(mr) == 1 and "when" not in mr[0] and "changes" in mr[0], rules
    missing = uncovered(mr_changes(job), set(ROTATION_TESTBED_MESH_PATHS))
    assert not missing, missing
    before = job["before_script"]
    # The fetch is by the pinned commit, and what was checked out is that commit.
    assert MESH_FETCH in before and MESH_PIN_CHECK in before, before
    assert before.index(MESH_FETCH) < before.index(MESH_PIN_CHECK), before
    assert not any("CI_JOB_TOKEN" in line or "PRIVATE-TOKEN" in line for line in before), before
    assert job["script"] == ["./scripts/testbed/rotation.sh all --mesh"], job["script"]
    assert job.get("after_script") == ["./scripts/testbed/rotation.sh down"], job.get("after_script")
    steps = before + job["script"] + job["after_script"]
    assert not traced(steps), traced(steps)
    for path in ROTATION_TESTBED_MESH_SCRIPTS:
        lines = (ROOT / path).read_text().splitlines()
        assert not traced(lines), (path, traced(lines))
    artifacts = job["artifacts"]
    assert artifacts["when"] == "always" and artifacts["expire_in"] == "14 days", artifacts
    assert artifacts["paths"] == ROTATION_TESTBED_MESH_ARTIFACTS, artifacts["paths"]
    assert "exclude" not in artifacts and "untracked" not in artifacts, artifacts
    for name, other in config.items():
        if not isinstance(other, dict):
            continue
        needs = [n["job"] if isinstance(n, dict) else n for n in other.get("needs", [])]
        assert ROTATION_TESTBED_MESH not in needs + list(other.get("dependencies", [])), name


def check_rotation_testbed_out_ignored(config, gitignore):
    """The job's TESTBED_OUT lies inside the checkout; git must ignore it, or the
    stand's own output makes every CI receipt say working_tree_dirty=true."""
    out = config[ROTATION_TESTBED]["variables"]["TESTBED_OUT"]
    prefix = "$CI_PROJECT_DIR/"
    assert out.startswith(prefix) and "$" not in out[len(prefix):], out
    rel = out[len(prefix):].strip("/")
    assert rel and not rel.startswith(".."), out
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "init", "-q", tmp], check=True, capture_output=True)
        Path(tmp, ".gitignore").write_text(gitignore)
        for name in ROTATION_TESTBED_ARTIFACTS + [rel + "/runs/01-meta.json"]:
            path = rel + "/" + name.split("/", 1)[1] if name.startswith("testbed-out/") else name
            done = subprocess.run(["git", "-C", tmp, "check-ignore", "-q", "--no-index", path],
                                  capture_output=True)
            assert done.returncode == 0, ("not ignored by git", path)


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
# Runs on merge requests only: the negative control of the registry push authorization.
MR_ONLY = {"image-auth-deny-mesh"}
TOPIC = {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "topic", "CI_COMMIT_REF_NAME": "topic"}
MAIN = {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "main", "CI_COMMIT_REF_NAME": "main"}


def effective_job(config, job, seen=()):
    """The job as GitLab resolves it: its `extends` chain (a name or a list, nested)
    merged in order, later entries and then the job's own keys overriding earlier
    ones; hashes merge deeply, every other value (tags, script) is replaced."""
    def merge(base, top):
        out = dict(base)
        for key, value in top.items():
            out[key] = merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
        return out
    parents = job.get("extends", [])
    result = {}
    for parent in ([parents] if isinstance(parents, str) else parents):
        if parent not in seen and isinstance(config.get(parent), dict):
            result = merge(result, effective_job(config, config[parent], seen + (parent,)))
    return merge(result, {k: v for k, v in job.items() if k != "extends"})


def effective_scripts(config, name):
    """script, before_script and after_script of the effective job, as one text."""
    job = effective_job(config, config[name])
    return "\n".join(str(x) for key in ("before_script", "script", "after_script") for x in job.get(key) or [])


def job_variable_values(config, name):
    """Values of the global and the effective job variables, as one text: a
    script path can reach the shell through a variable (`sh -c "$S"`)."""
    values = {**(config.get("variables") or {}), **(effective_job(config, config[name]).get("variables") or {})}
    return "\n".join(str(v.get("value", "") if isinstance(v, dict) else v) for v in values.values())


def mutation_runners(config, jobs):
    """Jobs among `jobs` whose effective scripts or variables name a mutation suite, whatever the job is called."""
    return {name for name in jobs if re.search(r"check-[\w-]*mutations\.sh", "\n".join(
        (effective_scripts(config, name), job_variable_values(config, name))))}


ANCHORS_JOB = "mutant-anchors"
ANCHORS_MR_RUN = "MUTANT_ANCHORS_BASE=$CI_MERGE_REQUEST_DIFF_BASE_SHA timeout -k 10s 12m ./scripts/check-mutant-anchors.sh"
# Every suite, outside a merge request: 500-530s green, two main runs stopped at
# 12m. The job timeout stays above the inner budget so the driver, not the
# runner, ends the run and names the unfinished suites.
ANCHORS_MAIN_RUN = "timeout -k 10s 20m ./scripts/check-mutant-anchors.sh --all"
ANCHORS_JOB_TIMEOUT = "25m"


# An install line the mutation editor's python3 may ride on: the whole line is
# one of these commands and a list of bare package names, nothing before it,
# nothing after it. A prefix (`exit 0; `, `: && `) or a suffix is no match.
EDITOR_INSTALL_LINES = (
    re.compile(r"(apk add --no-cache)((?: [a-z0-9][a-z0-9.+_-]*)+)"),
    re.compile(r"(apt-get update -qq && apt-get install -y -qq(?: --no-install-recommends)?)"
               r"((?: [a-z0-9][a-z0-9.+_-]*)+)"),
)


def editor_install_line(line):
    """(command, packages) of a whole install line, or None."""
    for shape in EDITOR_INSTALL_LINES:
        match = shape.fullmatch(str(line))
        if match:
            return match.group(1), match.group(2).split()
    return None


def check_mutation_editor_runtime(config):
    """Every consumer of the shared editor or the tree snapshot
    (scripts/lib/mutation_snapshot.py, no fallback) has Python before its
    mutation command."""
    jobs = {name + "-mutations" for name in MUTATIONS}
    jobs |= {"netns-mutation-run", INTAKE_MUTATIONS}
    for name in sorted(jobs):
        job = effective_job(config, config[name])
        lines = list(map(str, job.get("before_script", [])))
        # The browser image carries Python and verifies its runtime explicitly.
        provisioned = any("python3" in (editor_install_line(line) or ("", []))[1] for line in lines)
        browser_runtime = name == INTAKE_MUTATIONS and "python3 --version" in "\n".join(lines)
        assert provisioned or browser_runtime, f"{name}: shared mutation editor needs python3"


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
    assert ANCHORS_MAIN_RUN in script, script
    budgets = re.findall(r"timeout -k 10s (\d+)m \./scripts/check-mutant-anchors\.sh", script)
    assert budgets == ["12", "20"], budgets
    assert job.get("timeout") == ANCHORS_JOB_TIMEOUT, job.get("timeout")
    assert "./scripts/check-mutant-anchors-selftest.sh" in script, script
    helper_test = "timeout -k 10s 2m ./scripts/check-mutation-helpers.sh"
    assert job["script"].count(helper_test) == 1, script
    assert job["script"][0] == helper_test, script
    assert not any("check-mutation-helpers.sh" in str(line)
                   for line in config["public-hygiene-mutations"]["script"])
    # The suites run only through the driver, which forces apply-only mode.
    assert not mutation_runners(config, {ANCHORS_JOB}), script
    assert "MUTATION_APPLY_ONLY" not in script + str(job.get("variables", {})), script
    assert "MUTATION_APPLY_ONLY=1" in (root / "scripts/check-mutant-anchors.sh").read_text()
    for path in sorted(p for p in (root / "scripts").glob("*-mutations.sh") if p.name != "mutation-helpers.sh"):
        text = path.read_text()
        assert re.search(r"mutation_appl(ied|y_only)|MUTATION_APPLY_ONLY|no source anchors", text), path.name


# Branch names the non-default push checks walk: a plain one and the
# <author>/<id>-<topic> shape most branches here have.
TOPIC_BRANCHES = ("topic", "dev/1234abcd-some-topic")


def topic_push(branch, **extra):
    return {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": branch, "CI_COMMIT_REF_NAME": branch,
            "CI_PIPELINE_SOURCE": "push"} | extra


def check_branch_push_scope(config):
    """A push to a non-default branch creates no pipeline, with or without an MR;
    every other pipeline kind keeps its coverage."""
    # GitLab evaluates workflow:rules when the push pipeline is created; an MR
    # opened right after the push is not visible yet. Neither state may matter.
    for branch in TOPIC_BRANCHES:
        for extra in ({}, {"CI_OPEN_MERGE_REQUESTS": "entire-vc/evc-keep!1"}, {"KEEP_FULL_CI": "1"},
                      {"CI_COMMIT_REF_PROTECTED": "true"}):
            assert pipeline_jobs(config, topic_push(branch, **extra)) is None, (branch, extra)
    mr = pipeline_jobs(config, MR)
    # Everything but the manual backtest is an ordinary check.
    full = mr - MR_JOBS
    heavy = {"fmt-vet", "golangci-lint", "full-tests", "w3-stubs", "build"}
    every_mutation = {name + "-mutations" for name in MUTATIONS}
    post_review = every_mutation | {"netns-mutation-run", INTAKE_MUTATIONS}
    # On an MR no mutation job runs at all.
    assert SECURITY_JOBS | (heavy - every_mutation) <= mr, mr
    assert not mr & post_review, mr & post_review
    assert BRANCH_SCAN_JOB not in mr, mr
    assert not mutation_runners(config, mr), mutation_runners(config, mr)
    # The push to the default branch runs every ordinary check but no mutation
    # job; the plugin's own tests run on the merge requests that touch it and
    # in the schedule, as before.
    main_push = pipeline_jobs(config, MAIN | {"CI_PIPELINE_SOURCE": "push"})
    assert main_push is not None and (
        full - every_mutation - MR_AND_SCHEDULE_ONLY - MR_ONLY <= main_push), main_push
    assert not main_push & post_review, main_push & post_review
    # No mutation suite at all on the main push, the browser ones included.
    assert not mutation_runners(config, main_push), mutation_runners(config, main_push)
    assert RELEASE_JOB not in main_push
    for context in [MAIN | {"CI_PIPELINE_SOURCE": "schedule"},
                    TOPIC | {"CI_PIPELINE_SOURCE": "schedule"}]:
        jobs = pipeline_jobs(config, context)
        assert jobs is not None and (full - MR_ONLY) | post_review <= jobs, (context, jobs)
        assert RELEASE_JOB not in jobs, context
    for source in ("web", "api"):
        for extra in ({}, {"CI_OPEN_MERGE_REQUESTS": "entire-vc/evc-keep!1"}):
            jobs = pipeline_jobs(config, TOPIC | {"CI_PIPELINE_SOURCE": source} | extra)
            assert jobs is not None and SECURITY_JOBS | heavy <= jobs, (source, jobs)
            assert not jobs & post_review, (source, jobs & post_review)
    # A release tag runs lint, tests and build, then `release`; no mutation job
    # (`release` reads the nightly result instead).
    jobs = pipeline_jobs(config, TAG)
    assert jobs is not None and not jobs & post_review, (jobs or set()) & post_review
    assert not mutation_runners(config, jobs), mutation_runners(config, jobs)
    assert {"security-hygiene", "fmt-vet", "full-tests", "build", RELEASE_JOB} <= jobs, jobs


BATCH = MAIN | {"CI_PIPELINE_SOURCE": "schedule", "KEEP_MUTATION_BATCH": "true"}


def check_branch_secret_scan(config, scanner=None, selftest=None):
    """What replaced the scan-only branch push pipeline: a hard job of the schedule
    pipeline that runs scripts/scan-branch-secrets.sh, and the selftest of that
    same script in every pipeline that carries the secret-scan gates."""
    assert BRANCH_SCAN_JOB in config, "the branch secret scan is missing"
    job = config[BRANCH_SCAN_JOB]
    assert job["stage"] == "security", job
    assert job.get("allow_failure", False) is False, job
    assert job.get("when", "on_success") == "on_success", job
    assert job["script"] == [BRANCH_SCAN_SCRIPT], job["script"]
    assert job.get("variables", {}).get("GIT_DEPTH") == 0, job
    assert not any(isinstance(r, dict) and ("changes" in r or r.get("when") in ("manual", "delayed"))
                   for r in job.get("rules", [])), job.get("rules")
    # The schedule ("Daily full verification", on the default branch) runs it;
    # no other pipeline does: a finding on someone else's branch must not turn
    # an unrelated merge request or the default branch red.
    schedule = pipeline_jobs(config, MAIN | {"CI_PIPELINE_SOURCE": "schedule"})
    assert schedule is not None and BRANCH_SCAN_JOB in schedule, schedule
    tag = {"CI_DEFAULT_BRANCH": "main", "CI_COMMIT_TAG": "v1.0.0", "CI_PIPELINE_SOURCE": "push"}
    for context in (MR, MAIN | {"CI_PIPELINE_SOURCE": "push"}, TOPIC | {"CI_PIPELINE_SOURCE": "web"}, tag, BATCH):
        jobs = pipeline_jobs(config, context)
        assert jobs is not None and BRANCH_SCAN_JOB not in jobs, context
    # The scanner reads every branch head, excludes the default branch, uses the
    # repository config, redacts, and exits 1 on a finding.
    scanner = (ROOT / BRANCH_SCAN_SCRIPT).read_text() if scanner is None else scanner
    code = "\n".join(line for line in scanner.splitlines() if not line.lstrip().startswith("#"))
    assert 'git fetch --quiet --prune "$remote" "+refs/heads/*:refs/remotes/$remote/*"' in code, "fetch"
    assert 'base="refs/remotes/$remote/$default"' in code, "base"
    assert '--log-opts="--remotes=$remote ^$base"' in code, "default branch exclusion"
    assert "--config .gitleaks.toml" in code and "--redact --exit-code 1" in code, "gitleaks flags"
    assert "|| true" not in code and "set +e" not in code and "set -eu" in code, "soft exit"
    # Its selftest runs this same file, in the job that carries the scan-scope selftest.
    selftest = (ROOT / BRANCH_SCAN_SELFTEST).read_text() if selftest is None else selftest
    assert "scanner=${1:-$root/scripts/scan-branch-secrets.sh}" in selftest, "selftest scanner"
    assert BRANCH_SCAN_SELFTEST in config["secret-scan-scope-selftest"]["script"], "selftest job"


# The mutation batch runs the secret scan, fmt-vet (tenancy-mutations reads its
# artifact) and its own three jobs; the post-review jobs run in its child.
BATCH_JOBS = SECURITY_JOBS | {"fmt-vet", RANGE_JOB, BATCH_TRIGGER, GREEN_JOB}
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
    others += [TOPIC | {"CI_PIPELINE_SOURCE": "web"}, {"CI_DEFAULT_BRANCH": "main", "CI_PIPELINE_SOURCE": "merge_request_event"},
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
PUBLISH_JOBS = ("image-tar-mesh", "image-crane-mesh", "image-publish-mesh", "image-pull-mesh", "image-receipt-mesh")
NON_INTERRUPTIBLE = {RELEASE_JOB, *PUBLISH_JOBS}
# Any of these words in a job's name or script makes it a suspected side-effect job
# (wrappers like ./scripts/publish.sh included). Jobs that only run mutation checks
# of deploy code, and image-build/image-build-mesh (kaniko builds that never push), are the named false positives.
SIDE_EFFECT = re.compile(r"\b(deploy|release|publish|upload|push|tag|registry)\b", re.I)
SIDE_EFFECT_FALSE_POSITIVES = {"deploy-api-mutations", "deploy-mutations", "image-build", "image-build-mesh", "deploy-smoke",
                               "image-auth-deny-mesh"}  # asks for a token, writes nothing

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

    def test_filter_drivers_have_python(self):
        """Each job whose driver prints through test-result-names.sh has
        python3; dropping it from one job, or the filter from every driver
        list, turns the check red."""
        drivers = filter_drivers()
        self.assertIn("check-rotate-audit-mutations.sh", drivers)
        check_filter_has_python(self.config, drivers)
        broken = copy.deepcopy(self.config)
        broken["rotate-audit-mutations"]["before_script"] = []
        with self.assertRaises(AssertionError):
            check_filter_has_python(broken, drivers)
        broken = copy.deepcopy(self.config)
        broken["targets-mutations"]["before_script"] = [
            line.replace(" python3", "") for line in broken["targets-mutations"]["before_script"]]
        with self.assertRaises(AssertionError):
            check_filter_has_python(broken, drivers)
        with self.assertRaises(AssertionError):
            check_filter_has_python(self.config, set())

    def test_rotation_testbed_out_is_ignored_by_git(self):
        """The stand writes into the checkout; an unignored out directory turns
        every CI receipt dirty. Each broken control turns the check red."""
        gitignore = (ROOT / ".gitignore").read_text()
        check_rotation_testbed_out_ignored(self.config, gitignore)
        line = "/testbed-out/\n"
        self.assertIn(line, gitignore)
        moved = copy.deepcopy(self.config)
        moved[ROTATION_TESTBED]["variables"]["TESTBED_OUT"] = "$CI_PROJECT_DIR/testbed-run"
        cases = [
            ("line removed", self.config, gitignore.replace(line, "")),
            ("negated", self.config, gitignore + "!/testbed-out/\n"),
            ("empty .gitignore", self.config, ""),
            ("out moved to an unignored dir", moved, gitignore),
        ]
        for label, config, text in cases:
            with self.subTest(label):
                with self.assertRaises(AssertionError):
                    check_rotation_testbed_out_ignored(config, text)

    def test_rotation_testbed_job_dies_on_each_broken_control(self):
        """Each way to weaken the testbed job turns the check red."""
        check_rotation_testbed_job(self.config)

        def drop(c):
            del c[ROTATION_TESTBED]

        def manual_job(c):
            c[ROTATION_TESTBED]["when"] = "manual"

        def manual_rule(c):
            for r in c[ROTATION_TESTBED]["rules"]:
                if r.get("if") == MR_IF:
                    r["when"] = "manual"

        def no_testbed_changes(c):
            mr_changes(c[ROTATION_TESTBED]).remove("scripts/testbed/**/*")

        def no_changes_key(c):
            for r in c[ROTATION_TESTBED]["rules"]:
                r.pop("changes", None)

        def whole_dir(c):
            c[ROTATION_TESTBED]["artifacts"]["paths"] = ["testbed-out/"]

        def extra_artifact(c):
            c[ROTATION_TESTBED]["artifacts"]["paths"].append("testbed-out/terminal.log")

        def untracked(c):
            c[ROTATION_TESTBED]["artifacts"]["untracked"] = True

        cases = [
            ("job deleted", drop),
            ("job manual", manual_job),
            ("MR rule manual", manual_rule),
            ("no changes on scripts/testbed", no_testbed_changes),
            ("no changes key", no_changes_key),
            ("allow_failure", lambda c: c[ROTATION_TESTBED].__setitem__("allow_failure", True)),
            ("wrong runner", lambda c: c[ROTATION_TESTBED].__setitem__("tags", ["docker"])),
            ("artifacts = whole directory", whole_dir),
            ("extra artifact", extra_artifact),
            ("untracked artifacts", untracked),
            ("no down", lambda c: c[ROTATION_TESTBED].pop("after_script")),
            ("steps without the scenario checks", lambda c: c[ROTATION_TESTBED].__setitem__("script", [
                "./scripts/testbed/rotation.sh " + step
                for step in ("up", "rotate", "break-third", "rotate", "receipt")])),
            ("receipt only", lambda c: c[ROTATION_TESTBED].__setitem__("script", ["./scripts/testbed/rotation.sh receipt"])),
            ("no schedule", lambda c: c[ROTATION_TESTBED]["rules"].remove({"if": '$CI_PIPELINE_SOURCE == "schedule"'})),
            ("no batch guard", lambda c: c[ROTATION_TESTBED]["rules"].remove(BATCH_NEVER)),
            ("timeout 31m", lambda c: c[ROTATION_TESTBED].__setitem__("timeout", "31m")),
            ("main rule without push", lambda c: c[ROTATION_TESTBED]["rules"].__setitem__(
                c[ROTATION_TESTBED]["rules"].index({"if": MAIN_PUSH_IF}),
                {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"})),
            ("no main push rule", lambda c: c[ROTATION_TESTBED]["rules"].remove({"if": MAIN_PUSH_IF})),
            ("web rule", lambda c: c[ROTATION_TESTBED]["rules"].insert(2, {"if": '$CI_PIPELINE_SOURCE == "web"'})),
            ("api rule", lambda c: c[ROTATION_TESTBED]["rules"].insert(2, {"if": '$CI_PIPELINE_SOURCE == "api"'})),
            ("topic push rule", lambda c: c[ROTATION_TESTBED]["rules"].append({"if": '$CI_PIPELINE_SOURCE == "push"'})),
            ("rule without if", lambda c: c[ROTATION_TESTBED]["rules"].append({"when": "on_success"})),
            ("needed", lambda c: c["build"].__setitem__("needs", [{"job": ROTATION_TESTBED}])),
            ("downloads every earlier artifact", lambda c: c[ROTATION_TESTBED].pop("dependencies", None)),
            ("depends on fmt-vet", lambda c: c[ROTATION_TESTBED].__setitem__("dependencies", ["fmt-vet"])),
            ("needs fmt-vet artifacts", lambda c: c[ROTATION_TESTBED].__setitem__("needs", [{"job": "fmt-vet"}])),
            ("needs fmt-vet by name", lambda c: c[ROTATION_TESTBED].__setitem__("needs", ["fmt-vet"])),
        ]
        for label, mutate in cases:
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_rotation_testbed_job(broken)

    def test_trace_switches_are_found_in_the_testbed_scripts(self):
        """The scripts of the Mesh job are scanned by traced(); each way to turn a
        trace on is caught, the ordinary lines are not."""
        for path in ROTATION_TESTBED_MESH_SCRIPTS:
            self.assertEqual(traced((ROOT / path).read_text().splitlines()), [], path)
        self.assertIn("scripts/testbed/stand-init.sh", ROTATION_TESTBED_MESH_SCRIPTS)
        self.assertIn("scripts/testbed/host/seen.sh", ROTATION_TESTBED_MESH_SCRIPTS)
        for line in ("set -x", "set -euxo pipefail", "set -Eeuxo pipefail", "set -e -x", "set -eu -o xtrace",
                     "set -o errexit -o xtrace", "  set -o xtrace", "set +o xtrace", "shopt -os xtrace", "set -v",
                     "set -o verbose", "bash -x ./x.sh", "sh -ex ./x.sh", "sh -xc 'true'", "bash -xe x.sh",
                     "bash -e -x x.sh", "SHELLOPTS: xtrace", "export SHELLOPTS=xtrace", "BASH_ENV=/x", "ENV=/x sh",
                     "BASH_XTRACEFD=2", "curl -v http://x", "curl -fsSv http://x", "curl --verbose http://x",
                     "curl -s --trace-ascii - http://x", "export GIT_TRACE=1", "GIT_CURL_VERBOSE=1 git fetch",
                     "CI_DEBUG_TRACE=true"):
            with self.subTest(line):
                self.assertEqual(traced(["set -euo pipefail", line]), [line])
        # A continued command is one shell line: its trace flag on the next physical
        # line, or inside one multi-line job step, is still found.
        for lines in (["curl -fsS \\", "  -v http://x"], ["curl \\", "  --header @h \\", "  --verbose http://x"],
                      ["set -eu \\", "  -x"], ["bash \\", "  -x ./x.sh"], ["curl -fsS \\\n  -v http://x"],
                      ["curl \\", "  --trace-ascii - http://x"]):
            with self.subTest(continued=lines):
                self.assertEqual(len(traced(["set -euo pipefail", *lines])), 1)
        for line in ("set -euo pipefail", "set -Eeuo pipefail", "# set -x", "sh -c 'true'", "find . -exec true {} +",
                     "bash ./x.sh", "grep -v x", "curl -fsS --max-time 5 http://x", "docker compose exec -T x sh -c 'y'"):
            with self.subTest(line):
                self.assertEqual(traced([line]), [])

    def test_testbed_dirs_in_the_build_directory_are_ignored(self):
        """The out directories and the Mesh checkout of the testbed jobs are in
        .gitignore, so a CI receipt says working_tree_dirty=false for a clean
        commit; dropping any line, or moving a job's directory, turns it red."""
        gitignore = (ROOT / ".gitignore").read_text()
        dirs, dirty = unignored_testbed_dirs(self.config, gitignore)
        self.assertEqual(sorted(set(dirs)), [".testbed-mesh-src", "testbed-mesh-out", "testbed-out"])
        self.assertEqual(dirty, [])
        for line in ("/testbed-out/", "/testbed-mesh-out/", "/.testbed-mesh-src/"):
            with self.subTest(dropped=line):
                self.assertIn(line + "\n", gitignore)
                self.assertNotEqual(unignored_testbed_dirs(self.config, gitignore.replace(line + "\n", ""))[1], [])
        for job, key in ((ROTATION_TESTBED, "TESTBED_OUT"), (ROTATION_TESTBED_MESH, "TESTBED_OUT"),
                         (ROTATION_TESTBED_MESH, "TESTBED_MESH_SRC")):
            with self.subTest(moved=f"{job} {key}"):
                c = copy.deepcopy(self.config)
                c[job]["variables"][key] = "$CI_PROJECT_DIR/elsewhere"
                self.assertNotEqual(unignored_testbed_dirs(c, gitignore)[1], [])

    def test_rotation_testbed_mesh_job_dies_on_each_broken_control(self):
        """Each way to weaken the Mesh testbed job turns the check red."""
        check_rotation_testbed_mesh_job(self.config)
        J = ROTATION_TESTBED_MESH

        def drop(c):
            del c[J]

        def manual_rule(c):
            for r in c[J]["rules"]:
                if r.get("if") == MR_IF:
                    r["when"] = "manual"

        def no_changes_key(c):
            for r in c[J]["rules"]:
                r.pop("changes", None)

        def sha(value):
            return lambda c: c[J]["variables"].__setitem__("TESTBED_MESH_SHA", value)

        def before(f):
            return lambda c: c[J].__setitem__("before_script", f(c[J]["before_script"]))

        cases = [
            ("job deleted", drop),
            ("job manual", lambda c: c[J].__setitem__("when", "manual")),
            ("MR rule manual", manual_rule),
            ("no changes on scripts/testbed", lambda c: mr_changes(c[J]).remove("scripts/testbed/**/*")),
            ("no changes on plugins/mesh", lambda c: mr_changes(c[J]).remove("plugins/mesh/**/*")),
            ("no changes on internal/rotation", lambda c: mr_changes(c[J]).remove("internal/rotation/**/*")),
            ("no changes key", no_changes_key),
            ("allow_failure", lambda c: c[J].__setitem__("allow_failure", True)),
            ("wrong runner", lambda c: c[J].__setitem__("tags", ["docker"])),
            ("downloads every earlier artifact", lambda c: c[J].pop("dependencies")),
            ("downloads the fmt-vet artifacts", lambda c: c[J].__setitem__("dependencies", ["fmt-vet"])),
            ("needs an earlier job", lambda c: c[J].__setitem__("needs", ["fmt-vet"])),
            ("Mesh at the head of main", sha("main")),
            ("Mesh at HEAD", sha("HEAD")),
            ("Mesh sha empty", sha("")),
            ("Mesh sha short", sha("b789a94f")),
            ("Mesh sha not set", lambda c: c[J]["variables"].pop("TESTBED_MESH_SHA")),
            ("Mesh source outside the build dir", lambda c: c[J]["variables"].__setitem__("TESTBED_MESH_SRC", "/tmp/evc-mesh")),
            ("no fetch of the pin", before(lambda b: [x for x in b if x != MESH_FETCH])),
            ("fetch of main", before(lambda b: [x.replace('"$TESTBED_MESH_SHA"', "main") if x == MESH_FETCH else x for x in b])),
            ("no check of the checked out commit", before(lambda b: [x for x in b if x != MESH_PIN_CHECK])),
            ("check before fetch", before(lambda b: [MESH_PIN_CHECK] + [x for x in b if x != MESH_PIN_CHECK])),
            ("personal token", before(lambda b: b + ['git config --global http.extraHeader "PRIVATE-TOKEN: $MESH_TOKEN"'])),
            ("without --mesh", lambda c: c[J].__setitem__("script", ["./scripts/testbed/rotation.sh all"])),
            ("steps without the scenario checks", lambda c: c[J].__setitem__("script", [
                "./scripts/testbed/rotation.sh " + step
                for step in ("up --mesh", "rotate-mesh", "break-third", "rotate-mesh", "receipt")])),
            ("artifacts = whole directory", lambda c: c[J]["artifacts"].__setitem__("paths", ["testbed-mesh-out/"])),
            ("extra artifact", lambda c: c[J]["artifacts"]["paths"].append("testbed-mesh-out/mcp")),
            ("Mesh source uploaded", lambda c: c[J]["artifacts"]["paths"].append(".testbed-mesh-src/")),
            ("untracked artifacts", lambda c: c[J]["artifacts"].__setitem__("untracked", True)),
            ("no down", lambda c: c[J].pop("after_script")),
            ("no schedule", lambda c: c[J]["rules"].remove({"if": '$CI_PIPELINE_SOURCE == "schedule"'})),
            ("no main push rule", lambda c: c[J]["rules"].remove({"if": MAIN_PUSH_IF})),
            ("main rule without push", lambda c: c[J]["rules"].__setitem__(
                c[J]["rules"].index({"if": MAIN_PUSH_IF}), {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"})),
            ("web rule", lambda c: c[J]["rules"].insert(2, {"if": '$CI_PIPELINE_SOURCE == "web"'})),
            ("api rule", lambda c: c[J]["rules"].insert(2, {"if": '$CI_PIPELINE_SOURCE == "api"'})),
            ("topic push rule", lambda c: c[J]["rules"].append({"if": '$CI_PIPELINE_SOURCE == "push"'})),
            ("no batch guard", lambda c: c[J]["rules"].remove(BATCH_NEVER)),
            ("timeout 31m", lambda c: c[J].__setitem__("timeout", "31m")),
            ("needed", lambda c: c["build"].__setitem__("needs", [{"job": J}])),
            ("GIT_TRACE in the job", lambda c: c[J]["variables"].__setitem__("GIT_TRACE", "1")),
            ("GIT_CURL_VERBOSE in the job", lambda c: c[J]["variables"].__setitem__("GIT_CURL_VERBOSE", "1")),
            ("CI_DEBUG_TRACE in the job", lambda c: c[J]["variables"].__setitem__("CI_DEBUG_TRACE", "true")),
            ("CI_DEBUG_TRACE for the pipeline", lambda c: c["variables"].__setitem__("CI_DEBUG_TRACE", "true")),
            ("GIT_TRACE for the pipeline", lambda c: c["variables"].__setitem__("GIT_TRACE", "1")),
            ("set -x before the fetch", before(lambda b: ["set -x"] + b)),
            ("git trace on the fetch", before(lambda b: ["GIT_TRACE=1 " + x if x == MESH_FETCH else x for x in b])),
            ("bash -x for the scenario", lambda c: c[J].__setitem__("script", ["bash -x ./scripts/testbed/rotation.sh all --mesh"])),
            ("set -x in down", lambda c: c[J].__setitem__("after_script", ["set -x", "./scripts/testbed/rotation.sh down"])),
            ("set -Eeux before the fetch", before(lambda b: ["set -Eeuxo pipefail"] + b)),
            ("SHELLOPTS for the pipeline", lambda c: c["variables"].__setitem__("SHELLOPTS", "xtrace")),
        ]
        for label, mutate in cases:
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_rotation_testbed_mesh_job(broken)

    def test_core_go_test_deadline_is_15m_under_shard_and_job_limits(self):
        """go test's per-package deadline for core shards is >= 15m, with the
        27m shard limit and the 30m job limit both above it by >= 5m."""
        child = yaml.safe_load((ROOT / ".gitlab/ci/full-tests.yml").read_text())
        script = "\n".join(str(x) for x in child["test"]["script"])
        m = re.search(r"timeout (\d+) env [^\n]*KEEP_GO_TEST_TIMEOUT=(\d+)m ", script)
        self.assertIsNotNone(m, "core shard must set KEEP_GO_TEST_TIMEOUT")
        shard_s, go_min = int(m.group(1)), int(m.group(2))
        job_min = int(str(child["test"]["timeout"]).removesuffix("m"))
        self.assertGreaterEqual(go_min, 15)
        self.assertGreaterEqual(shard_s, go_min * 60 + 300)
        self.assertGreaterEqual(job_min, go_min + 5)
        wrapper = (ROOT / "scripts/check-no-silent-skip.sh").read_text()
        self.assertIn('-timeout "${KEEP_GO_TEST_TIMEOUT:-600s}"', wrapper)

    def test_core_shard_timeout_marker_for_gnu_and_busybox_codes(self):
        child = yaml.safe_load((ROOT / ".gitlab/ci/full-tests.yml").read_text())
        script = "\n".join(str(x) for x in child["test"]["script"])
        guard = next(l.strip() for l in script.splitlines() if l.strip().startswith('if [ "$rc"'))
        for rc, marked in ((124, True), (143, True), (1, False), (0, False)):
            out = subprocess.run(["sh", "-c", f'rc={rc}; TEST_SUITE=core-1; {guard.removesuffix("; fi")}; fi'],
                                 capture_output=True, text=True).stdout
            self.assertEqual("CI-TIMEOUT" in out, marked, (rc, out))

    def test_backtest_explains_or_refuses_each_skipped_failure(self):
        """A failed job the selector would skip is explained from its own trace
        or counted against the run; each unexplained shape is a red control."""
        bt = self.backtest_module()
        gone = ("\x1b[31;1mfatal: couldn't find remote ref refs/heads/contributor/x-contract\x1b[0m\n"
                "ERROR: Job failed: exit code 128\n")
        red = ("ok   a: T went red\nFAIL log-claim-token: mutation did not apply - the source changed\n"
               "ERROR: Job failed: exit code 1\n")
        junk = "Executing step_script\nERROR: Job failed: exit code 1\n"
        self.assertEqual(bt.classify(gone), ("branch-deleted",
                         "exit 128: fatal: couldn't find remote ref refs/heads/contributor/x-contract"))
        self.assertEqual(bt.classify(red), ("red-mutant", "FAIL log-claim-token: mutation did not apply - the source changed"))
        self.assertEqual(bt.classify(junk)[0], "unexplained")
        # exit 128 without the missing-ref line, a green `went red` line, an empty trace: none is explained
        self.assertEqual(bt.classify("ERROR: Job failed: exit code 128\n")[0], "unexplained")
        self.assertEqual(bt.classify("ok   a: T went red\n")[0], "unexplained")
        self.assertEqual(bt.classify("")[0], "unexplained")
        miss = {"mr": 1, "pipeline": 2, "job": "lanepoller-mutations", "job_id": 3}
        same = lambda scripts, base: "FAIL log-claim-token: mutation did not apply - the source changed"
        for trace, again, explained in (
                (gone, lambda s_, b: None, True),           # no mutant ran
                (red, same, True),                          # reproduces without the MR's changes
                (red, lambda s_, b: None, False),           # does not reproduce: the MR may have caused it
                (red, lambda s_, b: "FAIL other: x", False),  # a different red at the base
                (junk, same, False)):                       # unexplained stays unexplained
            with self.subTest(trace=trace[:30], again=again(None, None)):
                out = bt.explain(miss, trace, "2026-10-28T00:00:00+00:00", "a" * 40, {"lanepoller"}, again)
                self.assertEqual(out["explained"], explained, out)

    def test_backtest_reads_mr_pipelines_by_ref_with_a_job_token(self):
        """The MR endpoint answers a job token 404, so there the pipelines of an MR
        are read by its head ref and its source branch, each once."""
        bt = self.backtest_module()
        self.assertEqual(bt.source_branch("Merge branch 'fix/a-b' into 'main'"), "fix/a-b")
        self.assertIsNone(bt.source_branch("Squash commit subject"))
        asked = []

        def fake(path):
            asked.append(path)
            return [{"id": 7, "sha": "x"}] if "merge-requests" in path or "fix%2Fa-b" in path else []

        old = (bt.api, dict(bt.os.environ))
        bt.os.environ.update({"CI_JOB_TOKEN": "t", "CI_API_V4_URL": "https://x/api/v4"})
        bt.api = fake
        try:
            got = bt.mr_pipelines(5, "fix/a-b")
        finally:
            bt.api = old[0]
            bt.os.environ.clear()
            bt.os.environ.update(old[1])
        self.assertEqual([p["id"] for p in got], [7])  # the same pipeline under both refs is one
        self.assertTrue(any("refs%2Fmerge-requests%2F5%2Fhead" in a for a in asked), asked)
        self.assertTrue(any("fix%2Fa-b" in a for a in asked), asked)
        self.assertFalse(any("/merge_requests/" in a for a in asked), asked)

    def test_backtest_uses_the_read_token_for_traces_and_never_prints_it(self):
        """A job token is answered 401 on other jobs' traces; with KEEP_BACKTEST_TOKEN
        set the request carries it (and not the job token), with none it falls back."""
        import io
        import contextlib
        import urllib.request
        bt = self.backtest_module()
        seen = []

        class Resp:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"ok"

        def fake_open(req, timeout=0):
            seen.append(dict(req.header_items()))
            return Resp()

        saved_env, saved_open = dict(bt.os.environ), urllib.request.urlopen
        urllib.request.urlopen = fake_open
        out = io.StringIO()
        try:
            bt.os.environ.update({"CI_JOB_TOKEN": "job-tok", "CI_API_V4_URL": "https://x/api/v4"})
            bt.os.environ.pop("KEEP_BACKTEST_TOKEN", None)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                bt.http_text("projects/1/jobs/2/trace")
                bt.os.environ["KEEP_BACKTEST_TOKEN"] = "read-tok"
                bt.http_text("projects/1/jobs/2/trace")
        finally:
            urllib.request.urlopen = saved_open
            bt.os.environ.clear()
            bt.os.environ.update(saved_env)
        self.assertEqual(seen[0].get("Job-token"), "job-tok", seen)
        self.assertNotIn("Private-token", seen[0])
        self.assertEqual(seen[1].get("Private-token"), "read-tok", seen)
        self.assertNotIn("Job-token", seen[1])
        self.assertNotIn("read-tok", out.getvalue())

    def test_backtest_exhibit_is_bound_to_selector_map_head_and_ids(self):
        bt = self.backtest_module()

        class A:
            days = 14

        row = {"mr": 289, "skipped": ["lanepoller"]}
        ex = {"mr": 289, "pipeline": 20973, "job_id": 442627, "job": "lanepoller-mutations", "class": "red-mutant",
              "evidence": "FAIL x: y", "explained": True, "verdict": "same red", "reproduced_at_base": "FAIL x: y",
              "base": "a41366ac6d18"}
        text = bt.exhibit(A, [row], [ex], [ex], [("HEAD", 289)])
        for needle in (bt.digest("scripts/mutation-select.py"), bt.digest("scripts/mutation-select.map"),
                       "window: 14 days, 1 merged MRs", "| !289 | 20973 | 442627 |", "unexplained or diff-dependent: 0",
                       "command: scripts/mutation-select-backtest.py"):
            self.assertIn(needle, text)
        # the count line follows the data: one unexplained miss changes it
        text = bt.exhibit(A, [row], [ex], [{**ex, "explained": False}], [("HEAD", 289)])
        self.assertIn("unexplained or diff-dependent: 1", text)

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
        rule_cases = {
            "on MR": lambda r: r.insert(1, {"if": MR_IF}),
            "manual on MR": lambda r: r.insert(1, {"if": MR_IF, "when": "manual", "allow_failure": False}),
            "on MR by changes": lambda r: r.insert(1, {"if": MR_IF, "changes": ["**/*.go"]}),
            "on a tag": lambda r: r.append({"if": TAG_IF}),
            "on the main push": lambda r: r.append({"if": MAIN_PUSH_IF}),
            "trailing on_success": lambda r: r.append({"when": "on_success"}),
            "manual anywhere": lambda r: r.append({"when": "manual"}),
            "schedule rule dropped": lambda r: r.pop(),
        }
        for name in sorted(MUTATIONS) + ["netns-mutation-run", INTAKE_MUTATIONS]:
            key = name if name in ("netns-mutation-run", INTAKE_MUTATIONS) else name + "-mutations"
            for label, mutate in rule_cases.items():
                with self.subTest(job=name, mutate=label):
                    broken = copy.deepcopy(self.config)
                    broken[key]["rules"] = copy.deepcopy(broken[key]["rules"])
                    mutate(broken[key]["rules"])
                    with self.assertRaises(AssertionError):
                        check_mutations_never_on_mr(broken)
        # The shared anchor itself, and a second anchor coming back.
        for label, mutate in {"anchor gains the tag": lambda c: c[".mutation-rules"]["rules"].append({"if": TAG_IF}),
                              "schedule anchor back": lambda c: c.__setitem__(
                                  ".mutation-schedule-rules", {"rules": [BATCH_NEVER, {"if": SCHEDULE_IF}, {"if": TAG_IF}]})
                              }.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_mutations_never_on_mr(broken)

    def test_image_publish_only_from_protected_default_branch(self):
        check_image_publish(self.config)
        mrs = [r for r in self.config["image-publish-mesh"]["rules"] if r.get("if") == MR_IF]
        self.assertEqual(len(mrs), 1)
        def broken(mutate):
            cfg = copy.deepcopy(self.config)
            mutate(cfg)
            with self.assertRaises(AssertionError):
                check_image_publish(cfg)
        def set_rules(cfg, rules):
            for name in PUBLISH_JOBS:
                cfg[name]["rules"] = copy.deepcopy(rules)
        good = self.config["image-publish-mesh"]["rules"]
        controls = {
            "publish from a merge request": lambda c: set_rules(c, [r for r in good if r.get("if") != MR_IF]
                                                               + [{"if": MR_IF}]),
            "publish from every pipeline": lambda c: set_rules(c, [{"when": "on_success"}]),
            "publish from a tag": lambda c: set_rules(c, good + [{"if": TAG_IF}]),
            "publish from a schedule": lambda c: set_rules(c, good + [{"if": '$CI_PIPELINE_SOURCE == "schedule"'}]),
            "publish from an unprotected branch": lambda c: set_rules(
                c, [dict(r, **{"if": r["if"].replace(' && $CI_COMMIT_REF_PROTECTED == "true"', "")}) for r in good]),
            "publish on the mutation batch": lambda c: set_rules(c, good[1:]),
            "needs skips the earlier stages": lambda c: c["image-tar-mesh"].update(needs=[]),
            "publish not behind the build": lambda c: c["image-publish-mesh"].update(needs=[]),
            "publish needs removed": lambda c: c["image-publish-mesh"].pop("needs"),
            "publish not serialized": lambda c: c["image-publish-mesh"].pop("resource_group"),
            "publish does nothing": lambda c: c["image-publish-mesh"].update(script=[":"]),
            "build job pushes": lambda c: c["image-tar-mesh"].update(
                script=[c["image-tar-mesh"]["script"][0].replace("--no-push", "--digest-file d")]),
            "build job holds a login": lambda c: c["image-tar-mesh"].update(
                script=[c["image-tar-mesh"]["script"][0] + '\necho "$CI_REGISTRY_PASSWORD"']),
            "allow_failure": lambda c: c["image-publish-mesh"].update(allow_failure=True),
            "build may fail": lambda c: c["image-tar-mesh"].update(allow_failure=True),
            "manual publish": lambda c: c["image-publish-mesh"].update(when="manual"),
            "interruptible publish": lambda c: c["image-publish-mesh"].update(interruptible=True),
            "short artifact expiry": lambda c: c["image-receipt-mesh"]["artifacts"].update(expire_in="1 hour"),
            "earlier job may fail": lambda c: c["image-build"].update(allow_failure=True),
            "earlier job is manual": lambda c: c["deploy-smoke"].update(when="manual"),
            "latest tag": lambda c: c["image-tar-mesh"].update(
                script=[c["image-tar-mesh"]["script"][0] + "\n--destination keep-server-mesh:latest"]),
            "wrong variant": lambda c: c["image-tar-mesh"].update(
                script=[c["image-tar-mesh"]["script"][0].replace("SERVER_VARIANT=mesh", "SERVER_VARIANT=core")]),
            "no commit build arg": lambda c: c["image-tar-mesh"].update(
                script=[c["image-tar-mesh"]["script"][0].replace('BUILD_COMMIT="$CI_COMMIT_SHA"', "BUILD_COMMIT=unknown")]),
            "unpinned crane": lambda c: c["image-pull-mesh"]["image"].update(name="gcr.io/go-containerregistry/crane:debug"),
            "env dump": lambda c: c["image-receipt-mesh"]["script"].insert(0, "env"),
            "registry login in artifacts": lambda c: c["image-publish-mesh"]["artifacts"]["paths"].append("/kaniko/.docker/config.json"),
            "pull job outside the stage": lambda c: c["image-pull-mesh"].update(stage="build"),
            "receipt job without verify": lambda c: c["image-receipt-mesh"].update(
                script=[l for l in c["image-receipt-mesh"]["script"] if "verify" not in l]),
            "publish stage before post-review": lambda c: c.update(
                stages=["security", "lint", "test", "build", "publish", "post-review", "release"]),
        }
        controls.update({
            "deny probe is advisory": lambda c: c["image-auth-deny-mesh"].update(allow_failure=True),
            "deny probe is manual": lambda c: c["image-auth-deny-mesh"].update(when="manual"),
            "deny probe does nothing": lambda c: c["image-auth-deny-mesh"].update(script=[":"]),
            "deny probe asks for allow": lambda c: c["image-auth-deny-mesh"].update(
                script=["python3 -I scripts/registry_auth_probe.py allow"]),
            "publisher without the pinned python image": lambda c: c["image-publish-mesh"].update(image="alpine:3"),
            "publisher without python": lambda c: c["image-publish-mesh"]["before_script"].pop(0),
            "crane not verified": lambda c: c["image-publish-mesh"].update(
                before_script=[l for l in c["image-publish-mesh"]["before_script"] if "sha256sum" not in l]),
            "crane checksum changed": lambda c: c["image-publish-mesh"].update(
                before_script=[l.replace("9ffac7be", "00000000") for l in c["image-publish-mesh"]["before_script"]]),
            "crane artifact not needed": lambda c: c["image-publish-mesh"].update(needs=[c["image-publish-mesh"]["needs"][0]]),
            "crane job unpinned": lambda c: c["image-crane-mesh"]["image"].update(name="gcr.io/go-containerregistry/crane:debug"),
            "crane job may fail": lambda c: c["image-crane-mesh"].update(allow_failure=True),
            "crane artifact kept long": lambda c: c["image-crane-mesh"]["artifacts"].update(expire_in="1 year"),
            "crane job removed": lambda c: c.pop("image-crane-mesh"),
            "deny probe without python": lambda c: c["image-auth-deny-mesh"].pop("before_script"),
            "receipt job ignores auth-only": lambda c: c["image-receipt-mesh"]["script"].pop(0),
            "auth-only marker not kept": lambda c: c["image-publish-mesh"]["artifacts"].update(paths=["mesh-image-publish.json"]),
            "deny tests not run by CI": lambda c: c["fmt-vet"].update(
                script=[l for l in c["fmt-vet"]["script"] if "test_registry_auth_probe" not in str(l)]),
            "deny probe never runs": lambda c: c["image-auth-deny-mesh"].update(
                rules=[{"if": '$CI_PIPELINE_SOURCE == "merge_request_event"', "when": "never"}]),
            "deny probe runs on every pipeline": lambda c: c["image-auth-deny-mesh"].update(rules=[{"when": "on_success"}]),
            "deny probe unpinned": lambda c: c["image-auth-deny-mesh"].update(image="golang:1.25"),
            "deny probe removed": lambda c: c.pop("image-auth-deny-mesh"),
            "deny probe prints the token": lambda c: c["image-auth-deny-mesh"].update(
                script=["python3 -I scripts/registry_auth_probe.py deny", "echo $CI_REGISTRY_PASSWORD"]),
        })
        for name, mutate in controls.items():
            with self.subTest(control=name):
                broken(mutate)

    def test_publish_script_runs_the_authorization_probe_before_the_push(self):
        text = (ROOT / "scripts/publish-mesh-image.sh").read_text()
        check_publish_script(text)
        probe = PROBE_CALL
        controls = {
            "probe removed": text.replace(probe, ""),
            "probe swallowed": text.replace(probe, 'python3 -I "$(dirname "$0")/registry_auth_probe.py" allow || true\n'),
            "probe result unchecked": text.replace(probe, 'python3 -I "$(dirname "$0")/registry_auth_probe.py" allow\n'),
            "probe after the tag check": text.replace(probe, "").replace(
                'sh "$(dirname "$0")/check-mesh-tag-absent.sh"\n', 'sh "$(dirname "$0")/check-mesh-tag-absent.sh"\n' + probe),
            "probe after the push": text.replace(probe, "") + probe,
            "probe in deny mode": text.replace('registry_auth_probe.py" allow', 'registry_auth_probe.py" deny'),
        }
        for name, mutated in controls.items():
            with self.subTest(control=name):
                with self.assertRaises(AssertionError):
                    check_publish_script(mutated)

    def test_auth_only_stop_guards(self):
        text = (ROOT / "scripts/publish-mesh-image.sh").read_text()
        pull = (ROOT / "scripts/pull-mesh-image.sh").read_text()
        check_auth_only(self.config, text, pull)
        guard = 'if [ "${KEEP_MESH_IMAGE_WRITE_SHA:-}" != "$CI_COMMIT_SHA" ]; then'
        controls = {
            "guard removed": text.replace(guard, "if false; then"),
            "guard inverted": text.replace("!= \"$CI_COMMIT_SHA\" ]; then\n\tprintf", "= \"$CI_COMMIT_SHA\" ]; then\n\tprintf"),
            "guard accepts any value": text.replace(guard, 'if [ -z "${KEEP_MESH_IMAGE_WRITE_SHA:-}" ]; then'),
            "guard does not stop": text.replace("\texit 0\nfi", "\t:\nfi"),
        }
        for name, mutated in controls.items():
            with self.subTest(control=name):
                with self.assertRaises(AssertionError):
                    check_auth_only(self.config, mutated, pull)
        with self.assertRaises(AssertionError):
            check_auth_only(self.config, text, pull.replace("mesh-image-auth-only.json", "x"))

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
        runner_job = {"stage": "test", "tags": ["keep-mutations"], "script": ["true"], "rules": [{"if": MR_IF}]}
        via_runner = {"stage": "test", "extends": ".mutation-runner", "script": ["echo ok"], "rules": [{"if": MR_IF}]}
        via_script = {"stage": "test", "extends": [".go-module-cache", ".runs-foo-mutations"],
                      "rules": [{"if": MR_IF}]}
        via_nested = {"stage": "test", "extends": ".nested-runner", "script": ["echo ok"], "rules": [{"if": MR_IF}]}
        via_before = {"stage": "test", "extends": ".before-foo", "script": ["echo ok"], "rules": [{"if": MR_IF}]}
        script_job = {"stage": "test", "script": ["./scripts/check-sealer-mutations.sh"], "rules": [{"if": MR_IF}]}
        named_job = {"stage": "test", "script": ["true"], "rules": [{"if": MR_IF}]}
        cases = {
            "a start job on MR": lambda c: c.__setitem__("start-more-mutations", start),
            "child trigger on MR": lambda c: c.__setitem__("child", trigger),
            "a job on the mutation runner on MR": lambda c: c.__setitem__("anything", runner_job),
            "a job extending .mutation-runner on MR": lambda c: c.__setitem__("anything", via_runner),
            "a job extending a template that runs a mutation script on MR": lambda c: (
                c.__setitem__(".runs-foo-mutations", {"script": ["scripts/check-foo-mutations.sh"]}),
                c.__setitem__("anything", via_script)),
            "a job extending a template that extends the runner on MR": lambda c: (
                c.__setitem__(".nested-runner", {"extends": ".mutation-runner"}),
                c.__setitem__("anything", via_nested)),
            "a job whose template runs a mutation script in before_script on MR": lambda c: (
                c.__setitem__(".before-foo", {"before_script": ["./scripts/check-foo-mutations.sh"]}),
                c.__setitem__("anything", via_before)),
            "a job running a check-*-mutations.sh script on MR": lambda c: c.__setitem__("anything", script_job),
            "a job named for mutations on MR": lambda c: c.__setitem__("run-mutations-now", named_job),
            "mutation job on MR": lambda c: c["sealer-mutations"].__setitem__("rules", [{"if": MR_IF}]),
            "shared rules gain a trailing on_success": lambda c: c["execrun-mutations"].__setitem__(
                "rules", c["execrun-mutations"]["rules"] + [{"when": "on_success"}]),
            "full-ci forces mutations": lambda c: c["sealer-mutations"]["rules"].insert(
                0, {"if": MR_IF + " && $KEEP_FULL_CI"}),
            "mutation script in a test job": lambda c: c["mesh-plugin"]["script"].append(
                "./scripts/check-mesh-plugin-mutations.sh"),
            "mutation script in e2e": lambda c: c["mesh-rotation-e2e"]["script"].append(
                'cd "$CI_PROJECT_DIR" && ./scripts/check-mesh-rotation-e2e-mutations.sh'),
            "the test child reads a mutation pipeline": lambda c: c["full-tests"]["trigger"]["include"][0].update(
                artifact="mutations.generated.yml"),
            "release on MR": lambda c: c[RELEASE_JOB]["rules"].insert(0, {"if": MR_IF}),
        }
        # The four jobs of the old merge request bridge, each put back as it was.
        for name in REMOVED_MR_MUTATION_JOBS:
            cases["removed job back: " + name] = (
                lambda c, name=name: c.__setitem__(name, {"stage": "test", "script": ["true"], "rules": [{"if": MR_IF}]}))
        for label, mutate in cases.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_no_mutation_on_mr(broken)
        broken = copy.deepcopy(self.config)
        broken["start-more-mutations"] = start
        with self.assertRaises(AssertionError):
            check_no_manual_jobs(broken)
        broken = copy.deepcopy(self.config)
        broken["execrun-mutations"]["when"] = "manual"
        with self.assertRaises(AssertionError):
            check_no_manual_jobs(broken)

    def test_merge_request_pipeline_has_no_mutation_job_at_all(self):
        """The guard of the 13.11.2026 owner decision, stated directly: render the
        pipeline of a merge request event and look at every job it contains."""
        jobs = pipeline_jobs(self.config, MR)
        self.assertIsNotNone(jobs)
        effective = {n: effective_job(self.config, self.config[n]) for n in jobs}
        self.assertEqual([n for n in sorted(jobs) if "keep-mutations" in (effective[n].get("tags") or [])], [])
        self.assertEqual(sorted(mutation_runners(self.config, jobs)), [])
        self.assertEqual([n for n in sorted(jobs) if "trigger" in effective[n] and n != "full-tests"], [])
        self.assertEqual([n for n in sorted(jobs) if "mutation" in n and n not in MR_JOBS], [])
        # What it may still list is cheap and runs no suite: the apply-only anchor
        # check, and the manual backtest.
        self.assertIn(ANCHORS_JOB, jobs)
        self.assertNotIn("keep-mutations", effective[ANCHORS_JOB].get("tags") or [])
        self.assertEqual(self.config[MR_BACKTEST]["rules"], [{"if": MR_IF, "when": "manual"}])
        # The schedule carries every mutation job, a release tag none (owner decision
        # of 16.11.2026: one pass, at night). The expected set is discovered, not
        # listed: every job whose effective tags include keep-mutations, whose name
        # ends with -mutations, or the netns run; intake-browser-mutations included.
        every = every_mutation_job(self.config)
        self.assertGreater(len(every), 40, every)
        self.assertIn(INTAKE_MUTATIONS, every)
        self.assertLessEqual({name + "-mutations" for name in MUTATIONS}, every)
        self.assertEqual(sorted(every - pipeline_jobs(self.config, MAIN | {"CI_PIPELINE_SOURCE": "schedule"})), [])
        self.assertEqual(sorted(every & pipeline_jobs(self.config, TAG)), [])

    def test_the_manual_jobs_are_pinned(self):
        """Only the backtest may be manual; it is soft, MR-only and needed by nothing."""
        check_no_manual_jobs(self.config)
        cases = {
            "backtest made gating": lambda c: c[MR_BACKTEST].__setitem__("allow_failure", False),
            "backtest not manual": lambda c: c[MR_BACKTEST].__setitem__("rules", [{"if": MR_IF}]),
            "backtest on every pipeline": lambda c: c[MR_BACKTEST].__setitem__("rules", [{"when": "manual"}]),
            "job level manual": lambda c: c[MR_BACKTEST].__setitem__("when", "manual"),
            "a second manual job": lambda c: c["fmt-vet"].__setitem__("when", "manual"),
            "a job needs the backtest": lambda c: c["build"].setdefault("needs", []).append(MR_BACKTEST),
            "a job depends on the backtest": lambda c: c["build"].__setitem__("dependencies", [MR_BACKTEST]),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_no_manual_jobs(broken)

    def test_backtest_red_controls(self):
        """The manual backtest keeps its shape: window, exhibit, no mutation runner."""
        check_mutation_backtest(self.config)
        cases = {
            "backtest job dropped": lambda c: c.pop(MR_BACKTEST),
            "backtest without the exhibit": lambda c: c[MR_BACKTEST]["script"].__setitem__(
                0, c[MR_BACKTEST]["script"][0].replace(" --exhibit backtest-exhibit.md", "")),
            "backtest window shortened": lambda c: c[MR_BACKTEST]["script"].__setitem__(
                0, c[MR_BACKTEST]["script"][0].replace("--days 14", "--days 3")),
            "backtest exhibit not kept": lambda c: c[MR_BACKTEST]["artifacts"]["paths"].remove("backtest-exhibit.md"),
            "backtest waits for the stages": lambda c: c[MR_BACKTEST].pop("needs"),
            "backtest on the mutation runner": lambda c: c[MR_BACKTEST].__setitem__("tags", ["keep-mutations"]),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_mutation_backtest(broken)

    def test_release_calls_the_nightly_gate_and_runs_no_mutation_job(self):
        check_release(self.config)
        jobs, mutation = tag_mutation_jobs(self.config)
        self.assertEqual(sorted(mutation), [])
        self.assertIn("build", jobs)
        new_job = {"stage": RELEASE_JOB, "dependencies": [], "script": ["./scripts/check-x-mutations.sh"],
                   "rules": [{"if": TAG_IF}]}
        script = lambda c: c[RELEASE_JOB]["script"]
        cases = {
            "gate call removed": lambda c: script(c).pop(0),
            "gate replaced by a no-op": lambda c: script(c).__setitem__(0, ":"),
            "gate made soft": lambda c: script(c).__setitem__(0, RELEASE_GATE + " || true"),
            "gate after the publish": lambda c: script(c).reverse(),
            "gate inside the publish block, softened": lambda c: (
                script(c).pop(0), script(c).__setitem__(0, RELEASE_GATE + " || :\n" + script(c)[0])),
            "gate on a shallow clone": lambda c: c[RELEASE_JOB]["variables"].pop("GIT_DEPTH"),
            "no clone at all": lambda c: c[RELEASE_JOB]["variables"].__setitem__("GIT_STRATEGY", "none"),
            "gate without git": lambda c: c[RELEASE_JOB].__setitem__("before_script", ["apk add --no-cache curl python3"]),
            "gate file rewritten before it runs": lambda c: c[RELEASE_JOB]["before_script"].append(
                "echo 'import sys; sys.exit(0)' > scripts/release-nightly-gate.py"),
            "clone re-shallowed before the gate": lambda c: c[RELEASE_JOB]["before_script"].append(
                "git fetch --depth 1 origin"),
            "gate pointed at another commit": lambda c: c[RELEASE_JOB]["variables"].__setitem__(
                "CI_COMMIT_SHA", "119c350f699112ecf7ba53d810cb9f122055fc90"),
            "gate pointed at another branch": lambda c: c[RELEASE_JOB]["variables"].__setitem__(
                "CI_DEFAULT_BRANCH", "old-green"),
            "gate without the job token": lambda c: c[RELEASE_JOB]["variables"].__setitem__("CI_JOB_TOKEN", ""),
            # A global variable outranks the predefined one and reaches release.
            "gate pointed at another commit globally": lambda c: c.setdefault("variables", {}).__setitem__(
                "CI_COMMIT_SHA", "119c350f699112ecf7ba53d810cb9f122055fc90"),
            "gate pointed at another branch globally": lambda c: c.setdefault("variables", {}).__setitem__(
                "CI_DEFAULT_BRANCH", {"value": "old-green", "description": "x"}),
            "gate pointed at another project globally": lambda c: c.setdefault("variables", {}).__setitem__(
                "CI_PROJECT_ID", "1"),
            "gate without the job token globally": lambda c: c.setdefault("variables", {}).__setitem__(
                "CI_JOB_TOKEN", ""),
            "release variables through a template": lambda c: (
                c.__setitem__(".old-sha", {"variables": {"CI_COMMIT_SHA": "119c350f699112ecf7ba53d810cb9f122055fc90"}}),
                c[RELEASE_JOB].__setitem__("extends", ".old-sha")),
            "mutation jobs back on the tag": lambda c: [
                c[n].__setitem__("rules", c[n]["rules"] + [{"if": TAG_IF}])
                for n in ("sealer-mutations", "carriers-mutations")],
            "intake browser suites on the tag": lambda c: c[INTAKE_MUTATIONS].__setitem__(
                "rules", [BATCH_NEVER, {"when": "on_success"}]),
            # YAML aliases share one list: appending to the anchor reaches every job on it.
            "the shared anchor gains the tag": lambda c: c[".mutation-rules"]["rules"].append({"if": TAG_IF}),
            "a mutation script in a tag job": lambda c: c["build"]["script"].append("./scripts/check-sealer-mutations.sh"),
            "a mutation script through a variable": lambda c: (
                c["build"].setdefault("variables", {}).__setitem__("S", "./scripts/check-sealer-mutations.sh"),
                c["build"]["script"].append('sh -c "$S"')),
            "empty needs": lambda c: c[RELEASE_JOB].__setitem__("needs", []),
            "mutation job beside release": lambda c: c.__setitem__("x-mutations", new_job),
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

    def test_release_description_is_changelog_section(self):
        check_release_notes(self.config)
        script = self.config[RELEASE_JOB]["script"]
        cases = {
            "fixed description": lambda j: j.__setitem__("script", [script[0], script[1].replace(
                '"description=$notes"', '"description=Release $CI_COMMIT_TAG"')]),
            "no checkout": lambda j: j.setdefault("variables", {}).__setitem__("GIT_STRATEGY", "none"),
            "missing section ignored": lambda j: j.__setitem__("script", [script[0], script[1].replace(
                "CHANGELOG.md)", "CHANGELOG.md || echo Release)")]),
            "section from another file": lambda j: j.__setitem__("script", [script[0], script[1].replace(
                "CHANGELOG.md)", "README.md)")]),
            "extraction dropped": lambda j: j.__setitem__("script", [script[0], script[1].replace(
                'notes=$(sh scripts/changelog-section.sh "$CI_COMMIT_TAG" CHANGELOG.md)',
                'notes="Release $CI_COMMIT_TAG"')]),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken[RELEASE_JOB])
                self.assertNotEqual(broken[RELEASE_JOB], self.config[RELEASE_JOB])
                with self.assertRaises(AssertionError):
                    check_release_notes(broken)

    def test_changelog_has_manifest_version(self):
        check_changelog_has_manifest_version()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = (ROOT / "mesh-extension.json").read_text()
            (root / "mesh-extension.json").write_text(
                re.sub(r'"version": "[0-9.]+"', '"version": "99.0.0"', manifest, count=1))
            shutil.copy(ROOT / "CHANGELOG.md", root / "CHANGELOG.md")
            with self.assertRaises(AssertionError):
                check_changelog_has_manifest_version(root)

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
        broken["ci-selftests"]["script"].remove("python3 scripts/test_ci_selftests_dispatcher.py")
        with self.assertRaises(AssertionError):
            check_config(broken, self.driver)

    def test_mesh_mutations_limits_controls(self):
        check_config(self.config, self.driver)
        for name, edit in [
                ("script 15m", lambda j: j.update(script=[x.replace("30m", "15m") for x in j["script"]])),
                ("job 20m", lambda j: j.update(timeout="20m")),
                ("parallel 1", lambda j: j.update(parallel=1))]:
            with self.subTest(name=name):
                broken = copy.deepcopy(self.config)
                edit(broken["mesh-mutations"])
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

        # Without the DB service or DSN, the workspace approval test would
        # skip while the plugin job remained green.
        for field, value in [("services", []), ("variables", {})]:
            with self.subTest(plugin_field=field):
                broken = copy.deepcopy(self.config)
                broken["mesh-plugin"][field] = value
                with self.assertRaises(AssertionError):
                    check_mesh_plugin_mutations(broken)

    def test_catalog_diagnostics_mandatory_gate_control(self):
        check_config(self.config, self.driver)
        broken = copy.deepcopy(self.config)
        broken["ci-selftests"]["script"].remove("python3 scripts/dispatch_ci_selftests.py")
        with self.assertRaises(AssertionError):
            check_config(broken, self.driver)

    def test_w3_stubs_diagnostics_mandatory_gate_control(self):
        check_config(self.config, self.driver)
        broken = copy.deepcopy(self.config)
        broken["ci-selftests"]["script"].remove("python3 scripts/dispatch_ci_selftests.py")
        with self.assertRaises(AssertionError):
            check_config(broken, self.driver)

    def test_selftests_job_and_broken_controls(self):
        check_selftests_job(self.config)
        def drop_rule(rules, index):
            del rules[index]
        cases = [
            ("removed self-test", lambda c: c["ci-selftests"]["script"].pop()),
            ("parallel removed", lambda c: c["ci-selftests"].pop("parallel")),
            ("one node", lambda c: c["ci-selftests"].__setitem__("parallel", 1)),
            ("needs removed", lambda c: c["ci-selftests"].pop("needs")),
            ("waits for lint", lambda c: c["ci-selftests"].__setitem__("needs", [{"job": "fmt-vet"}])),
            ("back in lint", lambda c: c["ci-selftests"].__setitem__("stage", "lint")),
            ("self-test back in fmt-vet", lambda c: c["fmt-vet"]["script"].append(SELFTESTS[0])),
            ("soft", lambda c: c["ci-selftests"].__setitem__("allow_failure", True)),
            ("manual", lambda c: c["ci-selftests"].__setitem__("when", "manual")),
            ("off main", lambda c: c["ci-selftests"]["rules"].__setitem__(-1, {"when": "never"})),
            ("in the mutation batch", lambda c: drop_rule(c["ci-selftests"]["rules"], 0)),
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

    def test_mutation_editor_runtime_and_missing_dependency_controls(self):
        check_mutation_editor_runtime(self.config)
        jobs = {name + "-mutations" for name in MUTATIONS}
        for name in sorted(jobs | {"netns-mutation-run", INTAKE_MUTATIONS}):
            with self.subTest(name):
                broken = copy.deepcopy(self.config)
                broken[name]["before_script"] = []
                with self.assertRaisesRegex(AssertionError, re.escape(name)):
                    check_mutation_editor_runtime(broken)
        # An install line that does not run as written does not provision Python.
        for line in ("exit 0; apk add --no-cache python3", ": && apk add --no-cache python3",
                     "apk add --no-cache python3; exit 0", "# apk add --no-cache python3"):
            with self.subTest(line):
                broken = copy.deepcopy(self.config)
                broken["sealer-mutations"]["before_script"] = [line]
                with self.assertRaisesRegex(AssertionError, "sealer-mutations"):
                    check_mutation_editor_runtime(broken)

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
            ("no helper selftest", lambda c: c[ANCHORS_JOB]["script"].pop(0)),
            ("no anchor selftest", lambda c: c[ANCHORS_JOB]["script"].remove(
                "timeout -k 10s 2m ./scripts/check-mutant-anchors-selftest.sh")),
            ("helper in mutation job", lambda c: c["public-hygiene-mutations"]["script"].insert(
                0, "./scripts/check-mutation-helpers.sh")),
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

    def test_branch_push_creates_no_pipeline_and_broken_controls(self):
        check_branch_push_scope(self.config)
        self.assertFalse(rule_matches('$A == "x"', {"A": "y"}))
        with self.assertRaises(ValueError):
            rule_matches('$A || $B', {})
        push_if = '$CI_COMMIT_BRANCH && $CI_PIPELINE_SOURCE == "push"'
        index = self.config["workflow"]["rules"].index({"if": push_if, "when": "never"})
        def put(rule):
            return lambda c: c["workflow"]["rules"].__setitem__(index, rule)
        cases = [
            # The rule this one replaced: a scan-only pipeline on every branch push.
            ("scan-only push back", put({"if": push_if, "variables": {"KEEP_BRANCH_PUSH_SCAN_ONLY": "true"}})),
            # The rule before that: it misses an MR opened right after the push.
            ("open-MR rule only", put({"if": "$CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS && "
                                             '$CI_PIPELINE_SOURCE == "push"', "when": "never"})),
            ("push rule dropped", lambda c: c["workflow"]["rules"].pop(index)),
            ("branch rule ahead of it", lambda c: c["workflow"]["rules"].insert(index, {"if": "$CI_COMMIT_BRANCH"})),
            # Main, web and api pipelines must keep full coverage.
            ("main rule dropped", lambda c: c["workflow"]["rules"].pop(1)),
            ("web/api rule dropped", lambda c: c["workflow"]["rules"].pop(index + 1)),
            ("push rule widened", put({"if": "$CI_COMMIT_BRANCH", "when": "never"})),
        ]
        for label, mutate in cases:
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_branch_push_scope(broken)
        self.assertNotIn("KEEP_BRANCH_PUSH_SCAN_ONLY", (ROOT / ".gitlab-ci.yml").read_text())

    def test_branch_secret_scan_in_schedule_and_broken_controls(self):
        check_branch_secret_scan(self.config)
        scanner = (ROOT / BRANCH_SCAN_SCRIPT).read_text()
        selftest = (ROOT / BRANCH_SCAN_SELFTEST).read_text()
        job = lambda c: c[BRANCH_SCAN_JOB]
        config_cases = [
            ("removed", lambda c: c.pop(BRANCH_SCAN_JOB)),
            ("soft", lambda c: job(c).__setitem__("allow_failure", True)),
            ("manual", lambda c: job(c).__setitem__("when", "manual")),
            ("not in the schedule", lambda c: job(c).__setitem__("rules", [{"if": MR_IF}])),
            ("never", lambda c: job(c).__setitem__("rules", [{"when": "never"}])),
            ("on every pipeline", lambda c: job(c).pop("rules")),
            ("no-op script", lambda c: job(c).__setitem__("script", [":"])),
            ("shallow clone", lambda c: job(c)["variables"].pop("GIT_DEPTH")),
            ("selftest dropped", lambda c: c["secret-scan-scope-selftest"]["script"].remove(BRANCH_SCAN_SELFTEST)),
        ]
        for label, mutate in config_cases:
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_branch_secret_scan(broken)
        text_cases = [
            ("no fetch", 'git fetch --quiet --prune "$remote" "+refs/heads/*:refs/remotes/$remote/*"', ":"),
            ("fetch commented out", "git fetch --quiet", "# git fetch --quiet"),
            ("main scanned", '--log-opts="--remotes=$remote ^$base"', '--log-opts="--remotes=$remote"'),
            ("exit code 0", "--exit-code 1", "--exit-code 0"),
            ("not redacted", "--redact ", ""),
            ("other config", "--config .gitleaks.toml", "--config /dev/null"),
            ("soft exit", "--redact --exit-code 1 -v", "--redact --exit-code 1 -v || true"),
        ]
        for label, old, new in text_cases:
            with self.subTest(label):
                self.assertIn(old, scanner)
                with self.assertRaises(AssertionError):
                    check_branch_secret_scan(self.config, scanner=scanner.replace(old, new))
        with self.assertRaises(AssertionError):
            check_branch_secret_scan(self.config, selftest=selftest.replace(
                "scanner=${1:-$root/scripts/scan-branch-secrets.sh}", "scanner=${1:-/bin/true}"))

    def test_main_push_runs_no_mutation_job(self):
        """Red controls: any way of putting a mutation job back outside the nightly
        schedule fails; the schedule losing one fails too."""
        check_mutations_never_on_mr(self.config)
        check_branch_push_scope(self.config)
        check_mutations_only_in_schedule(self.config)
        every_mutation = {name + "-mutations" for name in MUTATIONS}
        anchor = lambda c: c[".mutation-rules"]["rules"]
        cases = {
            # The intake browser suites back on the main push (as before 16.11.2026).
            "intake browser suites on the main push": lambda c: c[INTAKE_MUTATIONS].__setitem__(
                "rules", [BATCH_NEVER, {"if": MR_IF, "when": "never"}, {"when": "on_success"}]),
            # The tag back in the one anchor: every mutation job on a release tag.
            "the anchor gains $CI_COMMIT_TAG": lambda c: anchor(c).append({"if": TAG_IF}),
            # The old trailing on_success: web, api and trigger pipelines run them.
            "the anchor gains a trailing on_success": lambda c: anchor(c).append({"when": "on_success"}),
            "the main push rule on one job": lambda c: c["sealer-mutations"].__setitem__(
                "rules", [BATCH_NEVER, {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"}]),
            "the netns run on the main push": lambda c: c["netns-mutation-run"].__setitem__(
                "rules", c["netns-mutation-run"]["rules"] + [{"if": MAIN_PUSH_IF}]),
            "a web pipeline on a branch": lambda c: c["carriers-mutations"].__setitem__(
                "rules", c["carriers-mutations"]["rules"] + [{"if": '$CI_PIPELINE_SOURCE == "web"'}]),
            "a mutation script in an ordinary job": lambda c: c["netns-tests"]["script"].append(
                "timeout -k 10s 18m ./scripts/check-netns-mutations.sh"),
            "a mutation script through a job variable": lambda c: (
                c["build"].setdefault("variables", {}).__setitem__("S", "./scripts/check-sealer-mutations.sh"),
                c["build"]["script"].append('sh -c "$S"')),
            "a mutation script through a global variable": lambda c: (
                c.setdefault("variables", {}).__setitem__("S", {"value": "./scripts/check-sealer-mutations.sh"}),
                c["build"]["script"].append('sh -c "$S"')),
            "an ordinary job on the mutation runner": lambda c: c["build"].__setitem__("tags", ["keep-mutations"]),
            "a mutation job without rules": lambda c: c["sealer-mutations"].pop("rules"),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_mutations_only_in_schedule(broken)
        # The schedule must keep every one: dropping it from one job, or from the anchor.
        for label, mutate in {"one job off the schedule": lambda c: c["netns-mutation-run"].__setitem__(
                                  "rules", [BATCH_NEVER, {"if": '$CI_PIPELINE_SOURCE == "web"'}]),
                              "anchor off the schedule": lambda c: anchor(c).pop()}.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.config)
                mutate(broken)
                with self.assertRaises(AssertionError):
                    check_mutations_only_in_schedule(broken)
                with self.assertRaises(AssertionError):
                    check_branch_push_scope(broken)
        # The release tag pipeline keeps its ordinary checks and `release`.
        broken = copy.deepcopy(self.config)
        broken["workflow"]["rules"] = [r for r in broken["workflow"]["rules"] if r.get("if") != TAG_IF]
        with self.assertRaises(AssertionError):
            check_branch_push_scope(broken)
        # positive control of the evaluator: the schedule still runs every one
        jobs = pipeline_jobs(self.config, MAIN | {"CI_PIPELINE_SOURCE": "schedule"})
        self.assertTrue(mutation_runners(self.config, jobs) >= {"netns-mutation-run", INTAKE_MUTATIONS}, jobs)
        self.assertTrue(every_mutation <= jobs, every_mutation - jobs)
        for context in (MAIN | {"CI_PIPELINE_SOURCE": "push"}, TAG):
            jobs = pipeline_jobs(self.config, context)
            self.assertFalse(every_mutation & jobs, every_mutation & jobs)
            self.assertFalse(mutation_runners(self.config, jobs), context)

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
        NON_INTERRUPTIBLE = {RELEASE_JOB, "publish", *PUBLISH_JOBS}
        try:
            self.assertEqual(interruptible_violations(broken), [])
            broken["publish"]["interruptible"] = True
            self.assertEqual(interruptible_violations(broken), ["publish"])
        finally:
            NON_INTERRUPTIBLE = {RELEASE_JOB, *PUBLISH_JOBS}
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



class ChangelogSection(unittest.TestCase):
    """scripts/changelog-section.sh on its own: one exact section or a refusal
    with nothing on stdout."""

    def test_extracts_exactly_one_section(self):
        for version in ("9.9.1", "v9.9.1"):
            run = changelog_section(version, SAMPLE_CHANGELOG)
            self.assertEqual((run.returncode, run.stdout), (0, SAMPLE_SECTION + "\n"), run.stderr)
        run = changelog_section("9.9.0", SAMPLE_CHANGELOG)
        self.assertEqual((run.returncode, run.stdout), (0, "- marker-old\n"))
        crlf = changelog_section("9.9.1", SAMPLE_CHANGELOG.replace("\n", "\r\n"))
        self.assertEqual((crlf.returncode, crlf.stdout), (0, SAMPLE_SECTION + "\n"))

    def test_refusals(self):
        cases = {
            "absent": ("9.9.2", SAMPLE_CHANGELOG),
            "prefix of another version": ("9.9", SAMPLE_CHANGELOG),
            "dot is not a wildcard": ("9x9x1", SAMPLE_CHANGELOG.replace("[9.9.1]", "[9x9x1]")),
            "regex metacharacter": ("9.9.*", SAMPLE_CHANGELOG),
            "empty section": ("9.9.0", SAMPLE_CHANGELOG.replace("- marker-old", "")),
            "duplicate section": ("9.9.0", SAMPLE_CHANGELOG + "\n## [9.9.0]\n\n- again\n"),
            "heading without brackets": ("9.9.1", SAMPLE_CHANGELOG.replace("[9.9.1]", "9.9.1")),
            "heading with a suffix": ("9.9.1", SAMPLE_CHANGELOG.replace("[9.9.1]", "[9.9.1]x")),
            "heading with a spaced suffix": ("9.9.1", SAMPLE_CHANGELOG.replace("[9.9.1]", "[9.9.1] unexpected")),
            "heading with a date suffix": ("9.9.1", SAMPLE_CHANGELOG.replace("[9.9.1]", "[9.9.1] - 2030-01-02")),
            "heading with trailing space": ("9.9.1", SAMPLE_CHANGELOG.replace("[9.9.1]", "[9.9.1] ")),
            "subheading only": ("9.9.1", SAMPLE_CHANGELOG.replace("## [9.9.1]", "### [9.9.1]")),
            "empty version": ("", SAMPLE_CHANGELOG),
        }
        for label, (version, text) in cases.items():
            with self.subTest(label):
                run = changelog_section(version, text)
                self.assertNotEqual(run.returncode, 0, run.stdout)
                self.assertEqual(run.stdout, "")
        missing = subprocess.run(["sh", str(CHANGELOG_SCRIPT), "9.9.1", "/nonexistent/CHANGELOG.md"],
                                 capture_output=True, text=True)
        self.assertEqual((missing.returncode, missing.stdout), (1, ""))


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
