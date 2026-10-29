#!/usr/bin/env python3
"""The selector's answer for the mutation batch: the commits since the last
green batch.

  scripts/mutation-range.py --json mutation-select.json [--green-file F] [--head HEAD]

The batch runs on a branch (main, from a schedule every few hours) instead of
on each merge request. Its last job, mutation-green, keeps the commit the
post-review jobs last passed on as the artifact mutation-green.sha; this
script reads it (from F, or from the API with the job token), checks it is a
commit this head descends from, and runs scripts/mutation-select.py on
<green>..<head>. A green commit equal to the head is an empty range: nothing
is selected. Anything else (no artifact, an unreadable one, a commit that is
not an ancestor of the head, the selector failing) writes no answer, and
scripts/generate-mutation-pipeline.py then runs every post-review job.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
SHA = re.compile(r"[0-9a-f]{40}")
ARTIFACT, JOB = "mutation-green.sha", "mutation-green"


def fetch_green():
    """The last green commit kept for this branch, or None. Never prints the token."""
    try:
        api, project, ref, token = (os.environ[k] for k in
                                    ("CI_API_V4_URL", "CI_PROJECT_ID", "CI_COMMIT_REF_NAME", "CI_JOB_TOKEN"))
    except KeyError as e:
        print(f"no {e.args[0]} to read {ARTIFACT} with")
        return None
    url = (f"{api}/projects/{urllib.parse.quote(project, safe='')}/jobs/artifacts/"
           f"{urllib.parse.quote(ref, safe='')}/raw/{ARTIFACT}?job={JOB}")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"JOB-TOKEN": token}), timeout=30) as r:
            return r.read(1024).decode("ascii", errors="replace")
    except Exception as e:  # 404 before the first green batch, or the API is down
        print(f"{ARTIFACT} of the last green {JOB} on {ref} not read: {type(e).__name__}")
        return None


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=30)


def green_base(text, head, cwd=ROOT):
    """(base commit, None) when <base>..<head> can be narrowed, else (None, reason)."""
    if text is None:
        return None, f"no {ARTIFACT}"
    green = text.strip()
    if not SHA.fullmatch(green):
        return None, f"{ARTIFACT} is not a commit id"
    if git(cwd, "cat-file", "-e", green + "^{commit}").returncode:
        return None, f"green commit {green} is not in this clone"
    if git(cwd, "merge-base", "--is-ancestor", green, head).returncode:
        return None, f"green commit {green} is not an ancestor of {head}"
    return green, None


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True)
    ap.add_argument("--green-file")
    ap.add_argument("--head", default="HEAD")
    a = ap.parse_args(argv)
    out = Path(a.json)
    out.unlink(missing_ok=True)
    r = git(ROOT, "rev-parse", "--verify", a.head + "^{commit}")
    if r.returncode:
        print(f"every post-review job runs: head {a.head} does not resolve")
        return 0
    head = r.stdout.strip()
    if a.green_file is None:
        text = fetch_green()
    else:
        try:
            text = Path(a.green_file).read_text(errors="replace")
        except OSError:
            text = None
    base, reason = green_base(text, head)
    if base is None:
        print(f"every post-review job runs: {reason}")
        return 0
    count = git(ROOT, "rev-list", "--count", f"{base}..{head}").stdout.strip()
    print(f"range {base}..{head} ({count or '?'} commits since the last green batch)")
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "mutation-select.py"),
                        "--base", base, "--head", head, "--json", str(out)], cwd=ROOT)
    if r.returncode:
        out.unlink(missing_ok=True)
        print("every post-review job runs: the selector failed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
