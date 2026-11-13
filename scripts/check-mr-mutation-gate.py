#!/usr/bin/env python3
"""Review and merge side of the merge request mutation gate (not in use).

No pipeline runs this gate since the owner decision of 13.11.2026: a merge request
pipeline has no mutation job and no `mutations-mr` bridge, so there is nothing
to check. The code and its tests stay until it is removed on purpose; the text
below describes the gate as it was.

  scripts/check-mr-mutation-gate.py <iid> [project]        (needs an authenticated glab)
  scripts/check-mr-mutation-gate.py --files mr.json bridges.json child_jobs.json generated.yml
  scripts/check-mr-mutation-gate.py --ci mutations.generated.yml      (the `mutations-mr-check` job)

A merge request pipeline runs the mutation suites its diff needs as the child
pipeline of the `mutations-mr` bridge (.gitlab-ci.yml, "mutations on a merge
request"). A green parent alone proves nothing if that bridge or one of the
selected jobs is not there, so this check reads the facts and refuses
(exit 3, every reason printed) unless:

  * the head pipeline has a `mutations-mr` bridge (a missing bridge is a
    failure, never a pass and never "pending");
  * the bridge succeeded and its child pipeline ran on the MR's head commit
    (a child of another commit proves nothing about this one);
  * every job the generated child pipeline selected exists in the child,
    succeeded and is not allowed to fail (a missing job is a failure).

Exit 0 = go. Exit 2 = it could not read the facts (never a go).

--ci is the consumer inside the pipeline: `mutations-mr-check` (stage .post,
after the child finished) reads this pipeline's own bridges and the child's
jobs with the job token and fails the pipeline on any reason above, so a merge
request cannot be green without the check, whoever merges it.
"""
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

import yaml

BRIDGE = "mutations-mr"
GENERATED = "mutations.generated.yml"
RANGE_JOB = "mutation-range-mr"
NO_JOB = "no-mutations"
SHA = re.compile(r"[0-9a-f]{40}")
# GitLab names the jobs of a `parallel` job "<name> <n>/<total>".
NODE = re.compile(r" \d+/\d+$")


def selected_jobs(generated):
    """Names of the jobs the generated child pipeline runs (hidden templates and the placeholder aside)."""
    if not isinstance(generated, dict):
        return None
    reserved = {"workflow", "stages", "default", "variables", NO_JOB}
    return sorted(k for k, v in generated.items()
                  if isinstance(k, str) and k not in reserved and not k.startswith(".") and isinstance(v, dict))


def reasons(mr, bridges, child_jobs, generated):
    """Every reason the gate refuses, as strings; an empty list is a go."""
    out = []
    head = mr.get("sha") if isinstance(mr, dict) else None
    if not isinstance(head, str) or not SHA.fullmatch(head):
        return ["the MR names no head commit"]
    bridge = [b for b in bridges if isinstance(b, dict) and b.get("name") == BRIDGE]
    if not bridge:
        return [f"no {BRIDGE} bridge in the head pipeline: the selected mutation jobs were never created"]
    if len(bridge) != 1:
        return [f"{len(bridge)} {BRIDGE} bridges in the head pipeline"]
    bridge = bridge[0]
    if bridge.get("status") != "success":
        out.append(f"bridge {BRIDGE} is {bridge.get('status')}, not success")
    down = bridge.get("downstream_pipeline")
    if not isinstance(down, dict):
        out.append(f"bridge {BRIDGE} has no child pipeline")
    else:
        if down.get("sha") != head:
            out.append(f"child pipeline {down.get('id')} ran on {down.get('sha')}, not on the MR head {head}")
        if down.get("status") != "success":
            out.append(f"child pipeline {down.get('id')} is {down.get('status')}, not success")
    names = selected_jobs(generated)
    if names is None:
        return out + [f"{GENERATED} is unreadable: the selected jobs are unknown"]
    placeholder = isinstance(generated, dict) and NO_JOB in generated
    if not names and not placeholder:
        out.append(f"{GENERATED} selects no job and no placeholder")
    by_name = {}
    for j in child_jobs:
        if isinstance(j, dict) and isinstance(j.get("name"), str):
            by_name.setdefault(NODE.sub("", j["name"]), []).append(j)
    for name in names:
        jobs = by_name.get(name)
        if not jobs:
            out.append(f"selected job {name} is missing from the child pipeline")
            continue
        parallel = generated[name].get("parallel")
        if parallel is not None and (not isinstance(parallel, int) or isinstance(parallel, bool)):
            out.append(f"selected job {name}: `parallel` is not a plain count, so its shards cannot be checked")
        elif isinstance(parallel, int) and len(jobs) != parallel:
            out.append(f"selected job {name}: {len(jobs)} of {parallel} shards exist")
        for j in jobs:
            if j.get("status") != "success":
                out.append(f"selected job {j['name']} is {j.get('status')}, not success")
            if j.get("allow_failure"):
                out.append(f"selected job {j['name']} is allowed to fail")
    if placeholder and not names:
        if NO_JOB not in by_name or any(j.get("status") != "success" for j in by_name[NO_JOB]):
            out.append(f"placeholder job {NO_JOB} is missing or not success")
    return out


def glab(*args):
    r = subprocess.run(["glab", "api", *args], capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(f"glab api {' '.join(args)} failed")
    return r.stdout


def fetch(iid, project):
    mr = json.loads(glab(f"projects/{project}/merge_requests/{iid}"))
    pipeline = (mr.get("head_pipeline") or {}).get("id")
    if not pipeline:
        raise RuntimeError(f"MR !{iid} has no head pipeline")
    bridges = json.loads(glab("--paginate", f"projects/{project}/pipelines/{pipeline}/bridges?per_page=100").replace("][", ","))
    if (mr.get("head_pipeline") or {}).get("sha") != mr.get("sha"):
        raise RuntimeError("the head pipeline is not about the MR head")
    child, generated = [], None
    for b in bridges:
        if isinstance(b, dict) and b.get("name") == BRIDGE and isinstance(b.get("downstream_pipeline"), dict):
            cid = b["downstream_pipeline"]["id"]
            child = json.loads(glab("--paginate", f"projects/{project}/pipelines/{cid}/jobs?per_page=100"
                                    ).replace("][", ","))
    jobs = json.loads(glab("--paginate", f"projects/{project}/pipelines/{pipeline}/jobs?per_page=100").replace("][", ","))
    rng = [j for j in jobs if j.get("name") == RANGE_JOB and j.get("status") == "success"]
    if rng:
        generated = yaml.safe_load(glab(f"projects/{project}/jobs/{rng[0]['id']}/artifacts/{GENERATED}"))
    return mr, bridges, child, generated


def http_get(url, token):
    """(body, next page or None) of a GitLab API page; the token is sent, never printed."""
    req = urllib.request.Request(url, headers={"JOB-TOKEN": token})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8"), r.headers.get("X-Next-Page") or None


def api_list(api, path, token, get=http_get):
    """Every item of a paginated GitLab list."""
    items, page = [], "1"
    while page:
        body, page = get(f"{api}/{path}{'&' if '?' in path else '?'}per_page=100&page={page}", token)
        data = json.loads(body)
        if not isinstance(data, list):
            raise ValueError(f"{path}: not a list")
        items += data
    return items


def ci_facts(env, generated_path, get=http_get):
    """(mr, bridges, child jobs, generated) of the running MR pipeline, from the job environment."""
    api, project, pipeline, token = (env[k] for k in
                                     ("CI_API_V4_URL", "CI_PROJECT_ID", "CI_PIPELINE_ID", "CI_JOB_TOKEN"))
    if env.get("CI_PIPELINE_SOURCE") != "merge_request_event":
        raise RuntimeError("not a merge request pipeline")
    project = urllib.parse.quote(project, safe="")
    bridges = api_list(api, f"projects/{project}/pipelines/{pipeline}/bridges", token, get)
    child = []
    for b in bridges:
        if isinstance(b, dict) and b.get("name") == BRIDGE and isinstance(b.get("downstream_pipeline"), dict):
            child = api_list(api, f"projects/{project}/pipelines/{b['downstream_pipeline']['id']}/jobs", token, get)
    with open(generated_path) as f:
        generated = yaml.safe_load(f)
    return {"sha": env["CI_COMMIT_SHA"]}, bridges, child, generated


def main(argv):
    try:
        if argv[:1] == ["--ci"]:
            mr, bridges, child, generated = ci_facts(os.environ, argv[1])
        elif argv[:1] == ["--files"]:
            mr, bridges, child, gen = argv[1:5]
            mr, bridges, child = (json.load(open(p)) for p in (mr, bridges, child))
            generated = yaml.safe_load(open(gen))
        else:
            iid = argv[0]
            project = argv[1] if len(argv) > 1 else "entire-vc%2Fevc-keep"
            mr, bridges, child, generated = fetch(iid, project)
    except (IndexError, KeyError, OSError, ValueError, RuntimeError, yaml.YAMLError) as e:
        print(f"cannot read the facts: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    why = reasons(mr, bridges, child, generated)
    if why:
        print("mutation gate REFUSED:", file=sys.stderr)
        for w in why:
            print("  - " + w, file=sys.stderr)
        return 3
    print("mutation gate ok: child ran on the MR head, every selected job succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
