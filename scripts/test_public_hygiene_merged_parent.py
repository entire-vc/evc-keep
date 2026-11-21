#!/usr/bin/env python3
"""Merged-parent exemption of scripts/check-public-hygiene.sh.

A stacked merge request starts from its parent's branch. When the parent is
squash-merged, the parent's own merges of main ("Merge remote-tracking branch
'origin/main' into <parent branch>") are not on main, so they reappear in the
child's commit range. Their subject names the parent branch, which may hold
a deny-listed word. The check excuses that branch name, and only it, when
GitLab and git prove all of:

  1. exactly one merge request of the project has that source branch, and it
     is merged into the child's target branch;
  2. its merge or squash commit is an ancestor of the child's diff base;
  3. the excused commit is an ancestor of that merge request's head (fetched
     from refs/merge-requests/<iid>/head when the clone lacks it).

Each scenario builds a throwaway origin repository (main, the parent branch,
the child branch, the parent's squash merge on main, the child's merge of
main) and a clone holding only main and the child, then runs the check over
the child's range against a stub of the GitLab merge request API on
127.0.0.1 (the network is the one external boundary). The deny-list holds a
made-up word; the parent branch name holds it. Every red scenario differs
from the green one by one fact, and must fail on the deny-listed word.

HYGIENE_CHECK names the check to run (default: this tree's), so the mutation
suite can run these tests against a mutated copy. Needs git, curl and jq.
"""
import http.server
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECK = os.environ.get("HYGIENE_CHECK") or str(ROOT / "scripts/check-public-hygiene.sh")
# Built from parts: the hygiene mutation suite copies this tree and checks it
# with a probe list holding this word.
WORD = "zebra" + "quux"
PARENT = WORD + "/1111aaaa-parent"
CHILD = "child/2222bbbb-work"
PROJECT = "4242"
IID = 7
JOB_TOKEN = "job-token-stub"  # pragma: allowlist secret
API_TOKEN = "api-token-stub"  # pragma: allowlist secret
# A branch name holding every character a query string must encode.
ODD_PARENT = WORD + "/a&state=opened+x#y"
DENY_FAIL = "FAIL deny-listed word in commit messages"
TEMPLATES = {
    "remote": "Merge remote-tracking branch 'origin/main' into %s",
    "local": "Merge branch 'main' into %s",
    "quoted": "Merge branch 'main' into '%s'",
}
GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
}


class Api:
    """Stub of GET /projects/:id/merge_requests: filters `mrs` by the query as
    GitLab does (source_branch exact, state unless "all", target_branch), or
    misbehaves as `mode` says. Records every request."""

    def __init__(self):
        self.mrs, self.mode, self.seen, self.project = [], "normal", [], PROJECT
        api = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
                api.seen.append((url.path, query, self.headers.get("JOB-TOKEN"),
                                 self.headers.get("PRIVATE-TOKEN")))
                if api.mode == "slow":
                    time.sleep(4)
                # The raw path: a project path must arrive URL-encoded.
                want = "/api/v4/projects/%s/merge_requests" % urllib.parse.quote(api.project, safe="")
                if url.path != want:
                    return self.answer(404, b'{"message":"404 Not Found"}')
                if (self.headers.get("JOB-TOKEN") != JOB_TOKEN
                        and self.headers.get("PRIVATE-TOKEN") != API_TOKEN):
                    return self.answer(401, b'{"message":"401 Unauthorized"}')
                if api.mode == "error":
                    return self.answer(500, b'{"message":"500 Internal Server Error"}')
                if api.mode == "garbage":
                    return self.answer(200, b"<html>not json</html>")
                if api.mode == "object":
                    return self.answer(200, b'{"message":"not a list"}')
                got = list(api.mrs)
                if api.mode != "ignore-filter":
                    one = lambda k: query.get(k, [None])[0]
                    got = [m for m in got if m["source_branch"] == one("source_branch")]
                    if one("state") not in (None, "all"):
                        got = [m for m in got if m["state"] == one("state")]
                    if one("target_branch") is not None:
                        got = [m for m in got if m["target_branch"] == one("target_branch")]
                    got = got[:int(one("per_page") or 20)]
                self.answer(200, json.dumps(got).encode())

            def answer(self, code, body):
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the client gave up (timeout scenario)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api/v4"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def closed_port_url():
    """An API URL nothing listens on."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/api/v4"


class World:
    """Throwaway origin + clone for one scenario."""

    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.origin, self.work = self.tmp / "origin", self.tmp / "work"
        (self.tmp / "gitconfig").write_text("")
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.tmp),
                    "GIT_CONFIG_GLOBAL": str(self.tmp / "gitconfig"), "LC_ALL": "C", **GIT_ENV}
        (self.tmp / "deny").write_text(f"{WORD}\n")

    def git(self, cwd, *args):
        r = subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
        return r.stdout.strip()

    def commit(self, cwd, msg, name=None, text=None, body=None):
        if name:
            (Path(cwd) / name).write_text(text or (name + "\n"))
            self.git(cwd, "add", "-A")
        args = ["commit", "-q", "--allow-empty", "-m", msg] + (["-m", body] if body else [])
        self.git(cwd, "-c", "gc.auto=0", *args)
        return self.git(cwd, "rev-parse", "HEAD")

    def build(self, template="remote", subject=None, body=None, after_fork=False,
              mr_ref=True, child_extra=None, parent_extra=None, parent=PARENT):
        """Origin with the stack; returns the facts the API would report.

        template/subject: the parent's merge of main (subject overrides the
        template); body: its body; after_fork: the parent gets one more
        commit after the child forked, so the clone lacks the parent's head;
        mr_ref: origin publishes refs/merge-requests/<iid>/head; child_extra:
        a callable run on origin with the child branch checked out, before
        the child merges main; parent_extra: the same on the parent branch,
        after its merge of main and before the child forks."""
        o = self.origin
        o.mkdir()
        self.parent = parent
        self.git(o, "init", "-q", "-b", "main")
        self.commit(o, "chore: base", "README", "base\n")
        self.git(o, "checkout", "-q", "-b", parent)
        self.commit(o, "feat: parent work", "p.txt")
        self.git(o, "checkout", "-q", "main")
        self.commit(o, "fix: main moves", "m1.txt")
        self.git(o, "update-ref", "refs/remotes/origin/main", "main")
        self.git(o, "checkout", "-q", parent)
        if subject is None and template == "remote" and body is None:
            self.git(o, "-c", "gc.auto=0", "merge", "-q", "--no-edit", "origin/main")
        else:
            subj = subject if subject is not None else TEMPLATES[template] % parent
            self.git(o, "-c", "gc.auto=0", "merge", "-q", "--no-ff", "-m", subj,
                     *(["-m", body] if body else []), "origin/main")
        self.parent_merge = self.git(o, "rev-parse", "HEAD")
        if parent_extra:
            parent_extra(self)
        self.git(o, "checkout", "-q", "-b", CHILD)
        self.commit(o, "feat: child work", "c.txt")
        if child_extra:
            child_extra(self)
        self.git(o, "checkout", "-q", parent)
        if after_fork:
            self.commit(o, "fix: parent review remark", "p2.txt")
        head = self.git(o, "rev-parse", "HEAD")
        # GitLab's squash merge: a squash commit on main, then a merge commit.
        self.git(o, "checkout", "-q", "main")
        ptree = self.git(o, "rev-parse", f"{head}^{{tree}}")
        squash = self.git(o, "commit-tree", ptree, "-p", "main", "-m", "feat: parent work")
        merge = self.git(o, "commit-tree", ptree, "-p", "main", "-p", squash,
                         "-m", f"Merge branch '{parent}' into 'main'")
        self.git(o, "reset", "-q", "--hard", merge)
        if mr_ref:
            self.git(o, "update-ref", f"refs/merge-requests/{IID}/head", head)
        self.git(o, "update-ref", "refs/remotes/origin/main", "main")
        self.git(o, "checkout", "-q", CHILD)
        self.git(o, "-c", "gc.auto=0", "merge", "-q", "--no-edit", "origin/main")
        self.git(o, "checkout", "-q", "main")
        # The clone knows only main and the child, as a CI clone of the child
        # does; --no-local copies reachable objects only.
        self.git(self.tmp, "clone", "-q", "--no-local", "--no-tags", "--single-branch",
                 "-b", CHILD, str(o), str(self.work))
        self.git(self.work, "fetch", "-q", "origin", "main:refs/remotes/origin/main")
        self.base = self.git(self.work, "rev-parse", "origin/main")
        self.head = self.git(self.work, "rev-parse", "HEAD")
        self.mr = {"iid": IID, "state": "merged", "source_branch": parent, "target_branch": "main",
                   "sha": head, "merge_commit_sha": merge, "squash_commit_sha": squash}
        return self.mr

    def run(self, api_url, **override):
        env = dict(self.env)
        env.update({
            "CI_PIPELINE_SOURCE": "merge_request_event",
            "HYGIENE_RANGE": f"{self.base}..{self.head}",
            "CI_MERGE_REQUEST_DIFF_BASE_SHA": self.base,
            "CI_COMMIT_SHA": self.head,
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": CHILD,
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
            "CI_MERGE_REQUEST_TITLE": "feat: clean title",
            "CI_API_V4_URL": api_url,
            "CI_PROJECT_ID": PROJECT,
            "CI_JOB_TOKEN": JOB_TOKEN,
            "PUBLIC_HYGIENE_DENYLIST": str(self.tmp / "deny"),
            "PUBLIC_HYGIENE_API_TIMEOUT": "2",
        })
        for k, v in override.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
        r = subprocess.run(["sh", CHECK, str(self.work)], env=env, capture_output=True,
                           text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr


class MergedParent(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="hygiene-parent-")
        self.w = World(self.tmpdir)
        self.api = Api()

    def tearDown(self):
        self.api.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def short(self, sha):
        return self.w.git(self.w.work, "rev-parse", "--short", sha)

    def excused_line(self):
        return (f"commit {self.short(self.w.parent_merge)}: default merge subject of merged parent "
                f"!{IID}, branch name not checked")

    def green(self, **override):
        code, out = self.w.run(self.api.url, **override)
        self.assertEqual(code, 0, out)
        self.assertIn(self.excused_line(), out)
        self.assertNotIn(WORD, out)
        return out

    def red(self, want=DENY_FAIL, api_url=None, excused=False, **override):
        """Exit 1 on `want`. excused: the genuine parent merge is still
        excused (the planted fact elsewhere must fail the run on its own);
        otherwise nothing is excused as a merged parent."""
        code, out = self.w.run(api_url or self.api.url, **override)
        self.assertEqual(code, 1, out)
        self.assertIn(want, out)
        if excused:
            self.assertIn(self.excused_line(), out)
            self.assertEqual(out.count("default merge subject of merged parent"), 1, out)
        else:
            self.assertNotIn("default merge subject of merged parent", out)
        self.assertNotIn(WORD, out)
        return out

    def git_failure(self, condition, after=False):
        # Git is an external process: run the real executable, but inject a
        # failing exit for one invocation, optionally after its side effects.
        bindir = self.w.tmp / "bin"
        bindir.mkdir()
        real_git = shlex.quote(shutil.which("git"))
        wrapper = bindir / "git"
        command = f'{real_git} "$@"' if after else ":"
        wrapper.write_text(f'#!/bin/sh\nif {condition}; then\n'
                           f'  {command}\n  exit 2\nfi\nexec {real_git} "$@"\n')
        wrapper.chmod(0o755)
        return str(bindir) + os.pathsep + self.w.env["PATH"]

    # ---- green: the three templates, full binding ----

    def test_green_remote_tracking_template(self):
        self.api.mrs = [self.w.build("remote")]
        self.green()
        # The stub saw the exact branch, every merge request state, the token.
        path, query, token, private = self.api.seen[0]
        self.assertEqual(query.get("source_branch"), [PARENT])
        self.assertEqual(query.get("state"), ["all"])
        self.assertEqual(query.get("per_page"), ["100"])
        self.assertEqual((token, private), (JOB_TOKEN, None))

    def test_green_local_main_template(self):
        self.api.mrs = [self.w.build("local")]
        self.green()

    def test_green_quoted_template(self):
        self.api.mrs = [self.w.build("quoted")]
        self.green()

    def test_green_parent_head_fetched_from_merge_request_ref(self):
        self.api.mrs = [self.w.build("remote", after_fork=True)]
        missing = subprocess.run(["git", "cat-file", "-e", self.w.mr["sha"] + "^{commit}"],
                                 cwd=self.w.work, env=self.w.env, capture_output=True)
        self.assertNotEqual(missing.returncode, 0, "the clone must lack the parent's head")
        self.green()

    def test_green_only_squash_commit_in_base(self):
        mr = self.w.build("remote")
        self.api.mrs = [dict(mr, merge_commit_sha=None)]
        self.green()

    def test_green_branch_name_needing_url_encoding(self):
        self.api.mrs = [self.w.build("remote", parent=ODD_PARENT)]
        self.green()
        self.assertEqual(self.api.seen[0][1].get("source_branch"), [ODD_PARENT])
        self.assertEqual(self.api.seen[0][1].get("state"), ["all"])

    def test_green_project_path_needing_url_encoding(self):
        self.api.project = "group/keep"
        self.api.mrs = [self.w.build("remote")]
        self.green(CI_PROJECT_ID="group/keep")

    def test_green_private_token_outside_ci(self):
        self.api.mrs = [self.w.build("remote")]
        self.green(CI_JOB_TOKEN=None, PUBLIC_HYGIENE_API_TOKEN=API_TOKEN)
        self.assertEqual(self.api.seen[0][2:], (None, API_TOKEN))

    # ---- red: condition 1, the merge request ----

    def test_red_parent_opened(self):
        self.api.mrs = [dict(self.w.build(), state="opened")]
        self.red()

    def test_red_parent_closed(self):
        self.api.mrs = [dict(self.w.build(), state="closed")]
        self.red()

    def test_red_parent_targets_another_branch(self):
        self.api.mrs = [dict(self.w.build(), target_branch="release")]
        self.red()

    def test_red_empty_answer(self):
        self.w.build()
        self.api.mrs = []
        self.red()

    def test_red_iid_not_an_integer(self):
        self.api.mrs = [dict(self.w.build(), iid=7.5)]
        self.red()

    def test_red_iid_a_string(self):
        self.api.mrs = [dict(self.w.build(), iid=str(IID))]
        self.red()

    def test_red_head_not_a_commit_id(self):
        # A ref name the clone resolves is still no commit id.
        self.api.mrs = [dict(self.w.build(), sha="HEAD")]
        self.red()

    def test_red_ambiguous_answer(self):
        mr = self.w.build()
        self.api.mrs = [mr, dict(mr, iid=IID + 1)]
        self.red()

    def test_red_answer_about_another_branch(self):
        self.api.mrs = [dict(self.w.build(), source_branch="other/3333cccc-x")]
        self.api.mode = "ignore-filter"
        self.red()

    def test_red_answer_not_a_list(self):
        self.api.mrs = [self.w.build()]
        self.api.mode = "object"
        self.red()

    def test_red_answer_not_json(self):
        self.api.mrs = [self.w.build()]
        self.api.mode = "garbage"
        self.red()

    def test_red_api_error(self):
        self.api.mrs = [self.w.build()]
        self.api.mode = "error"
        self.red()

    def test_red_api_timeout(self):
        self.api.mrs = [self.w.build()]
        self.api.mode = "slow"
        self.red()

    def test_red_api_unreachable(self):
        self.w.build()
        self.red(api_url=closed_port_url())

    def test_red_without_job_token(self):
        self.api.mrs = [self.w.build()]
        self.red(CI_JOB_TOKEN=None)

    def test_red_without_api_url(self):
        self.api.mrs = [self.w.build()]
        self.red(CI_API_V4_URL=None)

    def test_red_without_target_branch(self):
        self.api.mrs = [self.w.build()]
        self.red(CI_MERGE_REQUEST_TARGET_BRANCH_NAME=None)

    def test_red_without_diff_base(self):
        self.api.mrs = [self.w.build()]
        self.red(CI_MERGE_REQUEST_DIFF_BASE_SHA=None)

    # ---- red: condition 2, merge or squash commit in the diff base ----

    def test_red_merge_and_squash_not_in_base(self):
        mr = self.w.build()
        # The parent's head is a real commit, but not an ancestor of the base.
        self.api.mrs = [dict(mr, merge_commit_sha=mr["sha"], squash_commit_sha=None)]
        self.red()

    def test_red_merge_commit_not_a_commit_id(self):
        # origin/main is the diff base itself, but a ref name is no commit id.
        self.api.mrs = [dict(self.w.build(), merge_commit_sha="origin/main", squash_commit_sha=None)]
        self.red()

    def test_red_merge_and_squash_unknown(self):
        self.api.mrs = [dict(self.w.build(), merge_commit_sha=None, squash_commit_sha=None)]
        self.red()

    def test_red_base_git_error_despite_valid_squash(self):
        mr = self.w.build()
        self.api.mrs = [mr]
        path = self.git_failure('[ "$1" = merge-base ] && [ "$3" = ' + mr["merge_commit_sha"] + ' ]')
        self.red(PATH=path)

    # ---- red: condition 3, the commit is in the parent's head ----

    def test_red_fake_merge_outside_the_parent(self):
        def fake(w):
            # A merge with the parent's default subject made on the child.
            w.git(w.origin, "checkout", "-q", "-b", "side", "main")
            w.commit(w.origin, "fix: side", "s.txt")
            w.git(w.origin, "checkout", "-q", CHILD)
            w.git(w.origin, "-c", "gc.auto=0", "merge", "-q", "--no-ff", "-m",
                  TEMPLATES["remote"] % PARENT, "side")
        self.api.mrs = [self.w.build(child_extra=fake)]
        self.red(excused=True)

    def test_red_parent_head_missing(self):
        self.api.mrs = [self.w.build(after_fork=True, mr_ref=False)]
        self.red()

    def test_red_fetched_ref_does_not_contain_head(self):
        # Fetch succeeds, but cannot supply the head named by the API.
        self.api.mrs = [dict(self.w.build(after_fork=True), sha="f" * 40)]
        self.red()

    def test_red_fetch_error_after_objects_arrive(self):
        self.api.mrs = [self.w.build(after_fork=True)]
        path = self.git_failure('[ "$1" = fetch ]', after=True)
        self.red(PATH=path)

    # ---- red: the commit and its subject ----

    def test_red_single_parent_with_the_subject(self):
        # On the parent branch, so conditions 1-3 all hold for it: only its
        # single parent keeps it from being excused.
        def single(w):
            w.commit(w.origin, TEMPLATES["remote"] % PARENT)
        self.api.mrs = [self.w.build(parent_extra=single)]
        self.red(excused=True)

    def test_red_text_after_the_template(self):
        self.api.mrs = [self.w.build(subject=TEMPLATES["remote"] % PARENT + " and more")]
        self.red()

    def test_red_text_before_the_template(self):
        self.api.mrs = [self.w.build(subject="Note: " + TEMPLATES["remote"] % PARENT)]
        self.red()

    def test_red_text_before_the_branch_name(self):
        # The name GitLab is asked about is everything after the template's
        # prefix, not the subject's last word.
        self.api.mrs = [self.w.build(subject=TEMPLATES["remote"] % ("extra " + PARENT))]
        self.red()

    def test_red_git_pull_subject(self):
        self.api.mrs = [self.w.build(
            subject=f"Merge branch 'main' of https://example.invalid/keep into {PARENT}")]
        self.red()

    def test_red_outside_a_merge_request_pipeline(self):
        self.api.mrs = [self.w.build()]
        out = self.red(CI_PIPELINE_SOURCE="push", PUBLIC_HYGIENE_DENYLIST=str(self.w.tmp / "deny"))
        self.assertEqual(self.api.seen, [], out)

    def test_red_source_template_with_text_after(self):
        # The MR's own branch is excused only under the exact template too.
        def merge(w):
            w.git(w.origin, "checkout", "-q", "-b", "side", "main")
            w.commit(w.origin, "fix: side", "s.txt")
            w.git(w.origin, "checkout", "-q", CHILD)
            w.git(w.origin, "-c", "gc.auto=0", "merge", "-q", "--no-ff", "-m",
                  TEMPLATES["remote"] % CHILD + " and " + WORD, "side")
        self.api.mrs = [self.w.build(child_extra=merge)]
        self.red(excused=True)

    # ---- red: everything else is still checked ----

    def test_red_word_in_the_body(self):
        self.api.mrs = [self.w.build(body="asked by " + WORD)]
        self.red(excused=True)

    def test_red_word_in_the_title(self):
        self.api.mrs = [self.w.build()]
        self.red("FAIL deny-listed word in merge request title", excused=True,
                 CI_MERGE_REQUEST_TITLE="feat: asked by " + WORD)

    def test_red_word_in_the_tree(self):
        self.api.mrs = [self.w.build(child_extra=lambda w: w.commit(
            w.origin, "feat: notes", "notes.txt", f"see {WORD}\n"))]
        self.red("FAIL deny-listed word in tracked files", excused=True)

    def test_red_word_in_a_file_name(self):
        self.api.mrs = [self.w.build(child_extra=lambda w: w.commit(
            w.origin, "feat: notes", f"{WORD}.txt", "clean\n"))]
        self.red("FAIL deny-listed word in tracked file names", excused=True)


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1] + sys.argv[1:], verbosity=2)
