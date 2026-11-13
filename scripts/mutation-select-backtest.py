#!/usr/bin/env python3
"""Backtest of the shadow mutation selector against merged MRs.

For every MR merged into origin/main in the last N days and every pipeline it
ran, the selector is applied to that pipeline's own diff (MR base...pipeline
SHA; the MR's final diff when the SHA is not fetchable) and compared with what
really happened: which mutation jobs of that pipeline failed. A failed
mutation job whose scripts the selector would have skipped is a MISS.

  scripts/mutation-select-backtest.py --days 30 --md table.md --json out.json

Every failed-but-skipped job is then EXPLAINED from its own trace, never just
counted: a job that died fetching a deleted MR branch ran no mutant ("branch-
deleted"); a red mutant is re-run at the pipeline's merge base, without the
MR's changes, and only a red that reproduces there is independent of the MR.
A red that does not reproduce, or a trace that is neither, is a real or
unexplained miss and the run exits 1. The exhibit (--exhibit) binds the
result to the selector, map and head SHA, the command, the window and the
project, pipeline and job ids.

Needs read access to the project: `glab`, or in CI the job token
(CI_JOB_TOKEN + CI_API_V4_URL), and a clone with origin/main.
Selector and map are the ones in the working tree, applied to the working
tree's import graph; a path that no longer exists there is "unknown" and
selects everything, which can only hide a miss, never create one.
"""
import argparse
import datetime
import hashlib
import os
import tempfile
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT = "entire-vc%2Fevc-keep"
# Ordered wrapper contract; CI controls compare this with its actual targets.
BUILTIN_JOB_SCRIPTS = ("builtin", "intake-receiver", "intake-service")

spec = importlib.util.spec_from_file_location("mutation_select", ROOT / "scripts" / "mutation-select.py")
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)


def sh(*cmd, check=True):
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r


def http_text(path):
    """GET <api>/<path> with the job token (CI); returns the body."""
    # The job token cannot read other jobs' traces (HTTP 401). A read-only token in
    # KEEP_BACKTEST_TOKEN, when the project sets one, is used instead; never printed.
    tok = os.environ.get("KEEP_BACKTEST_TOKEN")
    headers = {"PRIVATE-TOKEN": tok} if tok else {"JOB-TOKEN": os.environ["CI_JOB_TOKEN"]}
    req = urllib.request.Request(f"{os.environ['CI_API_V4_URL']}/{path}", headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", "replace"), r.headers.get("X-Next-Page") or None


def http_paginated(path):
    out, page = "", "1"
    while page:
        body, page = http_text(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
        out += body + "\n"
    return out


def api_text(path):
    """Raw GET (job traces)."""
    if os.environ.get("CI_JOB_TOKEN") and os.environ.get("CI_API_V4_URL"):
        return http_text(path)[0]
    return sh("glab", "api", path).stdout


def api(path, attempts=5):
    for n in range(attempts):  # a timeout to the API must not lose a long run
        try:
            if os.environ.get("CI_JOB_TOKEN") and os.environ.get("CI_API_V4_URL"):
                r = subprocess.CompletedProcess([], 0, http_paginated(path), "")
            else:
                r = sh("glab", "api", "--paginate", path)
            break
        except (RuntimeError, OSError):
            if n == attempts - 1:
                raise
            time.sleep(2 ** n)
    out, dec, s, i = [], json.JSONDecoder(), r.stdout, 0
    while i < len(s):  # --paginate concatenates JSON arrays
        while i < len(s) and s[i].isspace():
            i += 1
        if i >= len(s):
            break
        o, i = dec.raw_decode(s, i)
        out.extend(o if isinstance(o, list) else [o])
    return out


def job_scripts(ci_text):
    """CI job name -> set of selector ids its script runs."""
    jobs, name = {}, None
    for line in ci_text.splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+):\s*$", line)
        if m:
            name = m.group(1)
            jobs[name] = set()
        elif name:
            if re.fullmatch(r"\s*-\s+\./scripts/run-builtin-mutation-job\.sh\s*", line):
                jobs[name].update(BUILTIN_JOB_SCRIPTS)
            for sid in re.findall(r"scripts/(?:check-)?([a-z-]+?)-mutations\.sh", line):
                if "./scripts/" in line:
                    jobs[name].add(sid)
    return {k: v for k, v in jobs.items() if v}


def merges(days):
    out = sh("git", "log", "--first-parent", f"--since={days} days ago", "--merges", "--format=%H", "origin/main").stdout.split()
    for h in out:
        body = sh("git", "log", "-1", "--format=%B", h).stdout
        m = re.search(r"merge_requests/(\d+)|![\s]*(\d+)", body)
        iid = re.search(r"entire-vc/evc-keep!(\d+)", body)
        if iid:
            yield h, int(iid.group(1))


def source_branch(subject):
    """MR source branch from a merge commit subject: Merge branch 'x' into 'main'."""
    m = re.match(r"Merge branch '([^']+)' into '[^']+'", subject)
    return m.group(1) if m else None


def mr_pipelines(iid, branch=None):
    """Every pipeline of one MR. The MR endpoint is not open to a job token, so
    there the same set is read by ref: the MR head ref and the source branch."""
    if not (os.environ.get("CI_JOB_TOKEN") and os.environ.get("CI_API_V4_URL")):
        return api(f"projects/{PROJECT}/merge_requests/{iid}/pipelines?per_page=100")
    seen = {}
    for ref in [f"refs/merge-requests/{iid}/head"] + ([branch] if branch else []):
        for p in api(f"projects/{PROJECT}/pipelines?ref={urllib.parse.quote(ref, safe='')}&per_page=100"):
            seen[p["id"]] = p
    return sorted(seen.values(), key=lambda p: p["id"], reverse=True)


def fetch_mr(iid, branch=None):
    out = []
    for p in mr_pipelines(iid, branch):
        failed = api(f"projects/{PROJECT}/pipelines/{p['id']}/jobs?scope[]=failed&per_page=100")
        for b in api(f"projects/{PROJECT}/pipelines/{p['id']}/bridges?per_page=100"):  # child pipelines
            down = (b.get("downstream_pipeline") or {}).get("id")
            if down:
                failed += api(f"projects/{PROJECT}/pipelines/{down}/jobs?scope[]=failed&per_page=100")
        out.append({"id": p["id"], "sha": p["sha"], "status": p["status"],
                    "failed": [{"name": re.sub(r"\s+\d+/\d+$", "", j["name"]), "reason": j.get("failure_reason"),
                               "id": j["id"], "started_at": j.get("started_at")} for j in failed]})
    return out


FAIL_LINE = re.compile(r"\bFAIL\s+(\S+?):\s*(.*)")
REF_GONE = re.compile(r"fatal: couldn't find remote ref (refs/heads/\S+)")


def classify(trace):
    """(class, evidence) of one failed mutation job from its own trace.

    branch-deleted  the job's git fetch found no MR branch (exit 128): no mutant ran
    red-mutant      a mutant script printed `FAIL <name>: <why>`: evidence is the first one
    unexplained     anything else; never counted as explained
    """
    clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", trace)
    code = (re.findall(r"Job failed: exit code (\d+)", clean) or ["?"])[-1]
    if code == "128":
        m = REF_GONE.search(clean)
        if m:
            return "branch-deleted", f"exit 128: {m.group(0)}"
    for line in clean.splitlines():
        m = FAIL_LINE.search(line)
        if m and "went red" not in line:
            return "red-mutant", f"FAIL {m.group(1)}: {m.group(2).strip()}"
    return "unexplained", f"exit {code}: " + " | ".join(l.strip()[-120:] for l in clean.splitlines()[-4:] if l.strip())


def reproduce_at_base(scripts, base, timeout=600):
    """First `FAIL <name>: <why>` line the job's mutation scripts print at `base`
    (a commit without the MR's changes), or None when none printed one."""
    with tempfile.TemporaryDirectory() as d:
        wt = Path(d) / "base"
        sh("git", "worktree", "add", "--detach", "-f", str(wt), base)
        try:
            for sid in sorted(scripts):
                script = wt / "scripts" / f"check-{sid}-mutations.sh"
                if not script.exists():
                    continue
                try:
                    r = subprocess.run([str(script)], cwd=wt, capture_output=True, text=True, timeout=timeout)
                except subprocess.TimeoutExpired as e:
                    r = subprocess.CompletedProcess([], 124, (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), "")
                for line in (r.stdout + "\n" + r.stderr).splitlines():
                    m = FAIL_LINE.search(line)
                    if m and "went red" not in line:
                        return f"FAIL {m.group(1)}: {m.group(2).strip()}"
        finally:
            sh("git", "worktree", "remove", "--force", str(wt), check=False)
    return None


def explain(miss, trace, merge_time, base, scripts, reproduce=reproduce_at_base):
    """The verdict of one miss: explained (with its evidence) or a real or unexplained one."""
    cls, evidence = classify(trace)
    out = {**miss, "class": cls, "evidence": evidence, "explained": False, "merge_time": merge_time}
    if cls == "branch-deleted":
        out["explained"] = True
        out["verdict"] = "no mutation ran: the MR branch was gone when the job fetched it"
    elif cls == "red-mutant":
        again = reproduce(scripts, base)
        out["reproduced_at_base"] = again
        out["base"] = base[:12]
        if again == evidence:
            out["explained"] = True
            out["verdict"] = "the same red reproduces at the merge base without the MR's changes"
        else:
            out["verdict"] = "red did not reproduce at the merge base: may be caused by the MR, a real miss"
    else:
        out["verdict"] = "unexplained"
    return out


def have(sha):
    return sh("git", "cat-file", "-e", sha + "^{commit}", check=False).returncode == 0


def digest(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def exhibit(a, rows, misses, explained, merges_list):
    """Markdown exhibit: what was measured, with what, over which window, and why each miss is explained."""
    times = [sh("git", "log", "-1", "--format=%cI", h).stdout.strip() for h, _ in merges_list]
    env = os.environ
    lines = [
        "# Mutation selector backtest exhibit", "",
        f"- head: {env.get('CI_COMMIT_SHA') or sh('git', 'rev-parse', 'HEAD').stdout.strip()}",
        f"- selector sha256: {digest('scripts/mutation-select.py')}",
        f"- map sha256: {digest('scripts/mutation-select.map')}",
        f"- backtest sha256: {digest('scripts/mutation-select-backtest.py')}",
        f"- command: scripts/mutation-select-backtest.py {' '.join(sys.argv[1:])}",
        f"- window: {a.days} days, {len(merges_list)} merged MRs, merges {min(times) if times else '-'} .. {max(times) if times else '-'}",
        f"- generated: {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}",
        f"- project: {env.get('CI_PROJECT_ID', PROJECT)} pipeline: {env.get('CI_PIPELINE_ID', '-')} job: {env.get('CI_JOB_ID', '-')}",
        f"- MRs {len(rows)}; with a skipped script {sum(1 for r in rows if r['skipped'])}; "
        f"failed jobs the selector would have skipped: {len(explained)} jobs ({len(misses)} job entries with shards)",
        f"- unexplained or diff-dependent: {sum(1 for e in explained if not e['explained'])}", "",
        "| MR | pipeline | job id | job | class | evidence | reproduced at merge base | verdict |", "|---|---|---|---|---|---|---|---|"]
    for e in sorted(explained, key=lambda e: (e["mr"], e["pipeline"], e["job"])):
        lines.append(f"| !{e['mr']} | {e['pipeline']} | {e.get('job_id')} | {e['job']} | {e['class']} | "
                     f"{e['evidence'].replace('|', '/')[:160]} | {e.get('reproduced_at_base') or '-'}"
                     f"{' @' + e['base'] if e.get('base') else ''} | {'explained: ' if e['explained'] else ''}{e['verdict']} |")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--json")
    ap.add_argument("--md")
    ap.add_argument("--cache", default="mutation-backtest-cache.json")
    ap.add_argument("--exhibit", help="write the bound, explained exhibit (markdown) here")
    ap.add_argument("--no-reproduce", action="store_true", help="classify from traces only; never re-run a script")
    a = ap.parse_args()
    cache_path = Path(a.cache)
    cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    m = ms.Map((ROOT / "scripts" / "mutation-select.map").read_text())
    pkgs = ms.load_graph()
    jobmap = job_scripts("\n".join(p.read_text() for p in [ROOT / ".gitlab-ci.yml", *sorted((ROOT / ".gitlab" / "ci").glob("*.yml"))]))
    rows, misses = [], []
    todo = list(merges(a.days))
    with ThreadPoolExecutor(8) as pool:  # the API round trips dominate; fetch them side by side
        want = [(h, i) for h, i in todo if str(i) not in cache]
        subjects = {i: source_branch(sh("git", "log", "-1", "--format=%s", h).stdout.strip()) for h, i in want}
        for iid, got in zip([i for _, i in want], pool.map(lambda hi: fetch_mr(hi[1], subjects[hi[1]]), want)):
            cache[str(iid)] = got
    cache_path.write_text(json.dumps(cache))
    for merge, iid in todo:
        key = str(iid)
        base = merge + "^1"
        final = sh("git", "diff", "--name-only", "--no-renames", f"{base}...{merge}^2").stdout.split()
        sel_names, skip_names, modes, caught, approx = set(), None, set(), [], False
        per_pipeline = []
        for p in cache[key] or [{"id": None, "sha": None, "failed": []}]:
            sha = p["sha"]
            if sha and (have(sha) or sh("git", "fetch", "-q", "origin", sha, check=False).returncode == 0) and have(sha):
                files = sh("git", "diff", "--name-only", "--no-renames", f"{base}...{sha}").stdout.split()
            else:
                files, approx = final, approx or bool(sha)
            rep = ms.report(sorted(set(files)), ROOT / "scripts" / "mutation-select.map")
            selected = {s["script"] for s in rep["selected"]}
            skipped = {s["script"] for s in rep["skipped"]}
            per_pipeline.append((p, rep, selected, skipped))
            modes.add("ALL" if rep["all"] else "graph")
            for j in p["failed"]:
                ids = jobmap.get(j["name"])
                if not ids:
                    continue
                if ids <= skipped:  # every script of this job would have been dropped
                    miss = {"mr": iid, "pipeline": p["id"], "sha": (sha or "")[:8], "job": j["name"], "reason": j["reason"],
                            "job_id": j.get("id"), "started_at": j.get("started_at"), "full_sha": sha, "merge": merge}
                    misses.append(miss)
                    caught.append(j["name"])
        last = per_pipeline[-1]
        rows.append({"mr": iid, "merge": merge[:8], "pipelines": len(cache[key]), "files": len(final),
                     "mode": "/".join(sorted(modes)), "selected": len(last[2]), "skipped": sorted(last[3]),
                     "skipped_failed": sorted(set(caught)), "approx": approx})
    explained = []
    seen = set()
    for m in misses:  # one explanation per failed job, however many shards
        key = (m["pipeline"], m["job"], m["job_id"])
        if key in seen:
            continue
        seen.add(key)
        if not m.get("job_id"):
            explained.append({**m, "class": "unexplained", "evidence": "no job id in the cached answer", "explained": False,
                              "verdict": "unexplained"})
            continue
        try:
            trace = api_text(f"projects/{PROJECT}/jobs/{m['job_id']}/trace")
        except (RuntimeError, OSError) as e:
            explained.append({**m, "class": "unexplained", "evidence": f"trace unreadable: {str(e)[-100:]}", "explained": False,
                              "verdict": "unexplained"})
            continue
        head = m["full_sha"] or (m["merge"] + "^2")
        mb = sh("git", "merge-base", head, m["merge"] + "^1", check=False).stdout.strip() or (m["merge"] + "^1")
        when = sh("git", "log", "-1", "--format=%cI", m["merge"]).stdout.strip()
        none = lambda scripts, base: None
        explained.append(explain(m, trace, when, mb, jobmap.get(m["job"], set()), none if a.no_reproduce else reproduce_at_base))
    unexplained = [e for e in explained if not e["explained"]]
    out = {"days": a.days, "mrs": rows, "misses": misses, "explained": explained, "unexplained": len(unexplained)}
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=1) + "\n")
    lines = ["| MR | pipelines | files | mode | selected | skipped | skipped that failed |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| !{r['mr']} | {r['pipelines']} | {r['files']} | {r['mode']}{'~' if r['approx'] else ''} | {r['selected']} | "
                     f"{', '.join(r['skipped']) or '-'} | {', '.join(r['skipped_failed']) or 0} |")
    lines.append("")
    lines.append(f"MRs: {len(rows)}; MRs with at least one skipped script: {sum(1 for r in rows if r['skipped'])}; "
                 f"skipped scripts that failed in a pipeline of their MR: {len(misses)}. (~ = pipeline SHA not fetchable, MR final diff used)")
    text = "\n".join(lines) + "\n"
    if a.md:
        Path(a.md).write_text(text)
    if a.exhibit:
        Path(a.exhibit).write_text(exhibit(a, rows, misses, explained, merges_list=todo))
    print(text.splitlines()[-1])
    print(f"failed-but-skipped jobs: {len(explained)}; unexplained or diff-dependent: {len(unexplained)}")
    return 1 if unexplained else 0


if __name__ == "__main__":
    sys.exit(main())
