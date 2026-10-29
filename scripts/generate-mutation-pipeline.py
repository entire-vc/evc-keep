#!/usr/bin/env python3
"""Generate the merge request's child pipeline of post-review jobs.

  scripts/generate-mutation-pipeline.py <mutation-select.json> <out.yml> <summary.txt>

Reads the selector's answer (scripts/mutation-select.py --json) and copies the
post-review jobs it selected out of .gitlab-ci.yml into a child pipeline, where
they run as soon as the `mutations` trigger starts it (the manual, blocking
gate is `start-mutations` in the parent). Every job goes in, and the summary
says why, when the answer cannot be trusted to narrow anything: it is missing
or unreadable, it says "all", it is about another commit, or it names a job
the configuration does not have. A selection with no job yields a child with
one no-op job, because a child pipeline cannot be empty.

Each copied job that runs a suite of scripts/mutation-select.map carries a
receipt: a hash of everything its result depends on (the job definition, the
scripts it reaches, the files of the packages its suites mutate and test, the
files the map links to them, go.mod/go.sum and the selector's own fixed
paths). The hash is the key of a GitLab cache holding the file
.mutation-receipt/<job>-<shard>, written by the last line of the job's script,
so only when every line before it passed. The job's first line exits at once,
saying so in the log, when that file holds exactly this hash: the same inputs
already passed. Any other content, or no file, runs the job.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("mutation_select", ROOT / "scripts" / "mutation-select.py")
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)

NO_JOB = "no-mutations"
RECEIPTS = ".mutation-receipt"
RECEIPT_SCHEMA = "keep-mutation-receipt-v1"


class Dumper(yaml.SafeDumper):
    """Writes every value in full, never as an anchor and alias."""

    def ignore_aliases(self, data):
        return True


SHA = re.compile(r"[0-9a-f]{40}")


def decide(answer, jobs, head=None):
    """(names to run, reason when that is every job).

    The answer is untrusted input: anything but the exact expected shape
    selects every job, and nothing about its shape can make this raise.
    """
    every = sorted(jobs)
    if not isinstance(answer, dict):
        return every, "no selector answer"
    part = answer.get("jobs")
    if not isinstance(part, dict):
        return every, "selector answer has no job part"
    if answer.get("all") is not False or part.get("all") is not False:
        if isinstance(answer.get("all"), bool) and isinstance(part.get("all"), bool):
            reason = part.get("reason") or answer.get("reason")
            return every, "selector answered all: " + (reason if isinstance(reason, str) else "no reason")
        return every, "selector answer: `all` is not a bool"
    provenance = answer.get("provenance")
    commit = provenance.get("head") if isinstance(provenance, dict) else None
    commit = commit.get("commit") if isinstance(commit, dict) else None
    if not isinstance(commit, str) or not SHA.fullmatch(commit):
        return every, "selector answer names no head commit"
    if head and commit != head:
        return every, "selector answer is not about this commit"
    lists = []
    for key in ("selected", "skipped"):
        entries = part.get(key)
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            return every, f"selector answer: {key} is not a list of jobs"
        names = [e.get("job") for e in entries]
        if not all(isinstance(n, str) for n in names):
            return every, f"selector answer: {key} has an entry without a job name"
        lists.append(names)
    picked, rest = lists
    known = set(jobs)
    # Every post-review job must be accounted for exactly once, by name.
    if (len(set(picked + rest)) != len(picked + rest) or set(picked + rest) != known):
        return every, "selector job lists do not match the post-review jobs"
    return sorted(picked), None


def as_list(value):
    if value is None:
        return []
    return copy.deepcopy(value) if isinstance(value, list) else [copy.deepcopy(value)]


def receipt_file(name):
    return f'"$CI_PROJECT_DIR/{RECEIPTS}/{name}-${{CI_NODE_INDEX:-0}}"'


def receipt_check(name, digest):
    """The first line of a job with a receipt: exit 0 only on this exact hash."""
    return (f"f={receipt_file(name)}; "
            f'if [ -f "$f" ] && [ "$(cat "$f")" = "{digest}" ]; then '
            f'echo "mutation family {name} already green at {digest}: skipped (receipt $f)"; exit 0; fi; '
            f'echo "mutation family {name}: no receipt for {digest}, running"')


def receipt_write(name, digest):
    """The last line of a job with a receipt: reached only when every line before it passed."""
    return f"mkdir -p \"$CI_PROJECT_DIR/{RECEIPTS}\" && printf '%s\\n' {digest} > {receipt_file(name)}"


def with_receipt(out, resolved, name, digest):
    out["before_script"] = [receipt_check(name, digest)] + as_list(resolved.get("before_script"))
    out["script"] = as_list(resolved.get("script")) + [receipt_write(name, digest)]
    out["cache"] = as_list(resolved.get("cache")) + [
        {"key": f"mutation-receipt-{name}-{digest}-$CI_NODE_INDEX", "paths": [RECEIPTS + "/"], "when": "on_success"}]
    return out


def receipts(config, names, pkgs, m, files):
    """name -> hash of what the job's result depends on, for jobs that run a suite the map knows.

    `files` maps each tracked path to its content hash (mutation-select's
    source_snapshot). Inputs are taken generously: a package directory
    brings every file below it.
    """
    ctx = ms.Context(m, ROOT)
    ctx._head = (config, ms.post_review_jobs(config))
    graph, entries = ctx.graph(), ctx.entries()
    # The paths that select every suite (go.mod, go.sum, test helpers, the selector...) feed every receipt.
    fixed = {f for f in files if any(re.search(p, f) for p in ms.ALL_PATTERNS)}
    out = {}
    for name in names:
        reach = set(graph.closure(entries.get(name, set())))
        ids = {sid for sid in m.scripts if ms.own_script(sid, ROOT) in reach}
        if not ids:
            continue
        packages = set()
        for sid in ids:
            packages |= ms.closure(ms.expand_roots(m.scripts[sid]["roots"], pkgs), pkgs)
        dirs = {pkgs[p]["dir"] for p in packages}
        inputs = reach | fixed | {f for f in files if any(d == "." or f.startswith(d + "/") for d in dirs)}
        for regex, _, kind, targets in m.paths:
            if (kind == "pkg" and packages & set(targets)) or (kind == "script" and ids & set(targets)):
                inputs |= {f for f in files if regex.match(f)}
        out[name] = ms.canonical_hash({
            "schema": RECEIPT_SCHEMA, "job": ms.resolve_job(config, name),
            "files": {f: files.get(f) for f in sorted(inputs)}})
    return out


def child_job(job, parent_jobs, name=None, resolved=None, digest=None):
    """A post-review job as it runs in the child pipeline."""
    out = copy.deepcopy(job)
    out.pop("only", None)
    out.pop("except", None)
    out["rules"] = [{"when": "on_success"}]
    # Artifacts of a parent job reach a child job only through needs:pipeline.
    deps = out.pop("dependencies", None)
    if deps:
        needs = out.setdefault("needs", [])
        for dep in deps:
            if dep not in parent_jobs:
                raise ValueError(f"dependency {dep} is not a job")
            needs.append({"pipeline": "$PARENT_PIPELINE_ID", "job": dep})
    if "needs" in job:
        raise ValueError("a post-review job with its own needs cannot be copied")
    if digest is not None:
        with_receipt(out, resolved, name, digest)
    return out


def templates(config, names):
    """Hidden jobs the given jobs extend, transitively, in file order."""
    want, stack = set(), list(names)
    while stack:
        job = config.get(stack.pop(), {})
        parents = job.get("extends", []) if isinstance(job, dict) else []
        for parent in [parents] if isinstance(parents, str) else parents:
            if parent not in want:
                want.add(parent)
                stack.append(parent)
    return [k for k in config if k in want]


def render(config, names, reason=None, digests=None, batch=False):
    jobs = ms.post_review_jobs(config)
    parent_jobs = {k for k, v in config.items() if ms.is_job(k, v)}
    digests = digests or {}
    out = {
        # The batch runs on a protected branch: like its parent, never cancelled by a newer commit.
        "workflow": {"auto_cancel": {"on_new_commit": "none" if batch else "interruptible"}, "rules": [{"when": "always"}]},
        "stages": ["post-review"],
    }
    for key in ("default", "variables"):
        if key in config:
            out[key] = copy.deepcopy(config[key])
    for name in templates(config, names):
        out[name] = copy.deepcopy(config[name])
    for name in names:
        out[name] = child_job(config[name], parent_jobs, name, jobs[name], digests.get(name))
    if not names:
        out[NO_JOB] = {"stage": "post-review", "tags": ["ci-fast"], "image": "alpine:3.22",
                       "variables": {"GIT_STRATEGY": "none"}, "rules": [{"when": "on_success"}],
                       "script": ["echo 'No post-review job selected for this diff'"]}
    head = ["# Generated by scripts/generate-mutation-pipeline.py from .gitlab-ci.yml.",
            f"# post-review jobs: {len(names)} of {len(jobs)}" + (f" (all: {reason})" if reason else "")]
    return "\n".join(head) + "\n" + yaml.dump(out, Dumper=Dumper, sort_keys=False, width=1000)


def summary(answer, names, jobs, reason, digests=None, note=None):
    digests = digests or {}
    lines = [f"post-review jobs: {len(names)} of {len(jobs)}" + (f"; all: {reason}" if reason else "")]
    if note:
        lines.append(note)
    why = {}
    if reason is None:
        why = {j["job"]: j.get("reason", "") for j in answer["jobs"]["selected"]}
    for name in names:
        lines.append(f"  run   {name}" + (f"  <- {why[name]}" if why.get(name) else "")
                     + (f"  [receipt {digests[name][:12]}]" if name in digests else "  [no receipt]"))
    for name in sorted(set(jobs) - set(names)):
        lines.append(f"  skip  {name}")
    return "\n".join(lines) + "\n"


def main(argv):
    answer_path, out_path, summary_path = (Path(a) for a in argv)
    config = yaml.safe_load((ROOT / ms.CI_CONFIG).read_text())
    jobs = ms.post_review_jobs(config)
    try:
        answer = json.loads(answer_path.read_text())
    except (OSError, ValueError):
        answer = None
    names, reason = decide(answer, jobs, os.environ.get("CI_COMMIT_SHA"))
    note = None
    try:
        files = ms.source_snapshot()
        if files is None:
            raise RuntimeError("tracked files not listed")
        digests = receipts(config, names, ms.load_graph(), ms.Map((ROOT / "scripts" / "mutation-select.map").read_text()),
                           {f: v["sha256"] for f, v in files.items()})
    except Exception as e:  # no hash, no skipping: every selected job runs in full
        digests, note = {}, f"no receipts: {type(e).__name__}: {e}"
    batch = os.environ.get("KEEP_MUTATION_BATCH") == "true"
    out_path.write_text(render(config, names, reason, digests, batch))
    text = summary(answer, names, jobs, reason, digests, note)
    summary_path.write_text(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
