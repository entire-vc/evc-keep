#!/usr/bin/env python3
"""Backtest of the shadow mutation selector against merged MRs.

For every MR merged into origin/main in the last N days and every pipeline it
ran, the selector is applied to that pipeline's own diff (MR base...pipeline
SHA; the MR's final diff when the SHA is not fetchable) and compared with what
really happened: which mutation jobs of that pipeline failed. A failed
mutation job whose scripts the selector would have skipped is a MISS.

  scripts/mutation-select-backtest.py --days 30 --md table.md --json out.json

Needs `glab` (read access to the project) and a clone with origin/main.
Selector and map are the ones in the working tree, applied to the working
tree's import graph; a path that no longer exists there is "unknown" and
selects everything, which can only hide a miss, never create one.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import re
import subprocess
import sys
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


def api(path):
    r = sh("glab", "api", "--paginate", path)
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


def fetch_mr(iid):
    out = []
    for p in api(f"projects/{PROJECT}/merge_requests/{iid}/pipelines?per_page=100"):
        failed = api(f"projects/{PROJECT}/pipelines/{p['id']}/jobs?scope[]=failed&per_page=100")
        for b in api(f"projects/{PROJECT}/pipelines/{p['id']}/bridges?per_page=100"):  # child pipelines
            down = (b.get("downstream_pipeline") or {}).get("id")
            if down:
                failed += api(f"projects/{PROJECT}/pipelines/{down}/jobs?scope[]=failed&per_page=100")
        out.append({"id": p["id"], "sha": p["sha"], "status": p["status"],
                    "failed": [{"name": re.sub(r"\s+\d+/\d+$", "", j["name"]), "reason": j.get("failure_reason")} for j in failed]})
    return out


def have(sha):
    return sh("git", "cat-file", "-e", sha + "^{commit}", check=False).returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--json")
    ap.add_argument("--md")
    ap.add_argument("--cache", default="mutation-backtest-cache.json")
    a = ap.parse_args()
    cache_path = Path(a.cache)
    cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    m = ms.Map((ROOT / "scripts" / "mutation-select.map").read_text())
    pkgs = ms.load_graph()
    jobmap = job_scripts("\n".join(p.read_text() for p in [ROOT / ".gitlab-ci.yml", *sorted((ROOT / ".gitlab" / "ci").glob("*.yml"))]))
    rows, misses = [], []
    todo = list(merges(a.days))
    with ThreadPoolExecutor(8) as pool:  # the API round trips dominate; fetch them side by side
        for iid, got in zip([i for _, i in todo if str(i) not in cache], pool.map(fetch_mr, [i for _, i in todo if str(i) not in cache])):
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
                    miss = {"mr": iid, "pipeline": p["id"], "sha": (sha or "")[:8], "job": j["name"], "reason": j["reason"]}
                    misses.append(miss)
                    caught.append(j["name"])
        last = per_pipeline[-1]
        rows.append({"mr": iid, "merge": merge[:8], "pipelines": len(cache[key]), "files": len(final),
                     "mode": "/".join(sorted(modes)), "selected": len(last[2]), "skipped": sorted(last[3]),
                     "skipped_failed": sorted(set(caught)), "approx": approx})
    out = {"days": a.days, "mrs": rows, "misses": misses}
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
    print(text.splitlines()[-1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
