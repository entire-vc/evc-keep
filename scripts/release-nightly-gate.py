#!/usr/bin/env python3
"""Release gate: the newest nightly mutation run behind a commit must be green.

Mutation suites run once a night, in the schedule pipeline of the default
branch, and nowhere else: a release tag does not run them again. Before the
`release` job publishes, this gate reads the schedule pipelines of the default
branch, newest first, skips the mutation batch (named "mutation-batch"), and
takes the NEWEST one whose commit is the release commit or an ancestor of it.
It passes (exit 0) only when that pipeline succeeded and holds at least one
mutation job (a name with "-mutations", or netns-mutation-run), every one of
them successful. Anything else exits 1: a failed, cancelled or still running
newest nightly (an older green one does not count), a green pipeline without
mutation jobs, no nightly behind the commit, a shallow clone, an API refusal.

  scripts/release-nightly-gate.py [--sha <commit>]

In CI it reads the API with the job token (CI_JOB_TOKEN, CI_API_V4_URL,
CI_PROJECT_ID, CI_DEFAULT_BRANCH, CI_COMMIT_SHA); elsewhere through `glab api`.
It needs a clone with the whole history of the commit (GIT_DEPTH 0).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

PROJECT = "entire-vc%2Fevc-keep"
BATCH_NAME = "mutation-batch"
PER_PAGE = 100
# Upper bound on the pipelines walked; reaching it is a failure, not a pass.
MAX_PAGES = 50
MUTATION_JOB = re.compile(r"-mutations\b|^netns-mutation-run\b")


class GateError(Exception):
    """The gate cannot answer: the release must not be published."""


def ci_api():
    return bool(os.environ.get("CI_JOB_TOKEN") and os.environ.get("CI_API_V4_URL"))


def api_get(path):
    """GET one API page, parsed. Any refusal or unreadable body raises GateError."""
    try:
        if ci_api():
            req = urllib.request.Request(f"{os.environ['CI_API_V4_URL']}/{path}",
                                         headers={"JOB-TOKEN": os.environ["CI_JOB_TOKEN"]})
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read().decode("utf-8")
        else:
            r = subprocess.run(["glab", "api", path], capture_output=True, text=True, timeout=120)
            if r.returncode:
                raise GateError(f"glab api {path}: exit {r.returncode}")
            body = r.stdout
        data = json.loads(body)
    except GateError:
        raise
    except Exception as e:  # noqa: BLE001 - any failure to read the API fails closed
        raise GateError(f"GET {path}: {type(e).__name__}: {e}") from None
    if not isinstance(data, list):
        raise GateError(f"GET {path}: expected a list, got {type(data).__name__}")
    return data


def pages(api, path):
    """Every item of a paginated list, page by page, until an empty page."""
    sep = "&" if "?" in path else "?"
    for page in range(1, MAX_PAGES + 1):
        items = api(f"{path}{sep}per_page={PER_PAGE}&page={page}")
        if not items:
            return
        yield from items
        if len(items) < PER_PAGE:
            return
    raise GateError(f"{path}: more than {MAX_PAGES} pages")


def git(*args, check=True):
    r = subprocess.run(["git", *args], capture_output=True, text=True)
    if check and r.returncode:
        raise GateError(f"git {' '.join(args)}: exit {r.returncode}: {r.stderr.strip()}")
    return r


def is_ancestor(candidate, sha):
    """True when `candidate` is `sha` or an ancestor of it. In a full clone an
    object that is missing (exit 128) is not reachable from `sha`."""
    r = git("merge-base", "--is-ancestor", candidate, sha, check=False)
    if r.returncode in (0, 1):
        return r.returncode == 0
    if git("cat-file", "-e", f"{candidate}^{{commit}}", check=False).returncode:
        return False
    raise GateError(f"git merge-base --is-ancestor {candidate} {sha}: exit {r.returncode}: {r.stderr.strip()}")


def newest_nightly(api, project, branch, sha):
    ref = urllib.parse.quote(branch, safe="")
    path = f"projects/{project}/pipelines?ref={ref}&source=schedule&order_by=id&sort=desc"
    for p in pages(api, path):
        if p.get("name") == BATCH_NAME or p.get("source", "schedule") != "schedule":
            continue
        if not isinstance(p.get("sha"), str) or not re.fullmatch(r"[0-9a-f]{40}", p["sha"]):
            raise GateError(f"pipeline {p.get('id')}: no commit sha")
        if is_ancestor(p["sha"], sha):
            return p
    return None


def mutation_jobs(api, project, pipeline_id):
    return [j for j in pages(api, f"projects/{project}/pipelines/{pipeline_id}/jobs")
            if MUTATION_JOB.search(str(j.get("name", "")))]


def check(api, project, branch, sha, out=None):
    """Exit status of the gate for `sha`; prints one line per verdict."""
    out = out or print
    if git("rev-parse", "--is-shallow-repository").stdout.strip() != "false":
        out("release gate: shallow clone, cannot tell an ancestor (GIT_DEPTH 0 needed)")
        return 1
    sha = git("rev-parse", "--verify", f"{sha}^{{commit}}").stdout.strip()
    nightly = newest_nightly(api, project, branch, sha)
    if nightly is None:
        out(f"release gate: no nightly schedule pipeline of {branch} on {sha} or an ancestor of it")
        return 1
    pid, psha, status = nightly["id"], nightly["sha"], nightly.get("status")
    behind = git("rev-list", "--count", f"{psha}..{sha}").stdout.strip()
    line = f"nightly {pid} {psha} {status}"
    if status != "success":
        out(f"{line}: the newest nightly behind {sha} is not green; {behind} commits from it to {sha}")
        return 1
    jobs = mutation_jobs(api, project, pid)
    if not jobs:
        out(f"{line}: holds no mutation job; {behind} commits from it to {sha}")
        return 1
    red = sorted(f"{j.get('name')}={j.get('status')}" for j in jobs if j.get("status") != "success")
    if red:
        out(f"{line}: mutation jobs not green: {', '.join(red)}")
        return 1
    out(f"{line}: {len(jobs)} mutation jobs green; {behind} commits from it to {sha}")
    return 0


def main(argv=None, api=api_get):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sha", default=os.environ.get("CI_COMMIT_SHA") or "HEAD")
    args = ap.parse_args(argv)
    project = os.environ.get("CI_PROJECT_ID") or PROJECT
    branch = os.environ.get("CI_DEFAULT_BRANCH") or "main"
    try:
        return check(api, project, branch, args.sha)
    except GateError as e:
        print(f"release gate: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
