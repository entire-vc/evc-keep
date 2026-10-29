#!/usr/bin/env python3
"""Selector for the mutation checks.

Reads the files a diff changed, the Go import graph, scripts/mutation-select.map,
the scripts that call each other and the post-review job definitions in
.gitlab-ci.yml, and answers which scripts/check-*-mutations.sh a diff needs and
which post-review jobs run them. On a merge request, and in the mutation
batch (scripts/mutation-range.py: the commits since the last green batch),
scripts/generate-mutation-pipeline.py turns the "jobs" part of the answer into
the child pipeline of post-review jobs; the nightly schedule and release tags
do not use it and run every job.

  scripts/mutation-select.py [--base origin/main] [--head HEAD] [--json out.json]
  scripts/mutation-select.py --files a.go b/c.sql        (explicit file list)

Any doubt selects every script and every job and says why in "reason": a fixed
shared path, a path no rule knows, a script several jobs use, a CI change that
reaches every job, a failure of the selector itself.
"""
import argparse
import difflib
import fnmatch
import functools
import hashlib
import shutil
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE_PREFIX = "github.com/entire-vc/evc-keep/"

ALL_PATTERNS = [
    r"^go\.mod$", r"^go\.sum$", r"^\.golangci\.yml$",
    # The selector, its map and the pipeline generator never narrow their own change.
    r"^scripts/mutation-select\.(py|map)$", r"^scripts/mutation-range\.py$",
    r"^scripts/generate-mutation-pipeline\.py$",
    r"^internal/testutil/", r"^internal/zonecheck/",
]
CI_CONFIG = ".gitlab-ci.yml"
# The job file of the test child pipeline: generate-test-pipeline.py reads it,
# no post-review job does. Any other file under .gitlab/ci/ is unknown.
TEST_CHILD_CONFIG = ".gitlab/ci/full-tests.yml"
POST_REVIEW = "post-review"
# The selection machinery itself: a change to one of these jobs changes how
# every post-review job is chosen, so it selects all of them.
GATING_JOBS = ("mutation-select", "start-mutations", "mutations",
               "mutation-range", "mutations-batch", "mutation-green")
# Top-level keys whose change reaches every job.
GLOBAL_CI_KEYS = frozenset({"workflow", "variables", "default", "stages", "include",
                            "image", "services", "cache", "before_script", "after_script"})


class Everything(Exception):
    """The diff cannot be narrowed; carries the reason."""


def glob_re(pattern):
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile("^" + out + "$")


class Map:
    def __init__(self, text):
        self.scripts = {}  # id -> {"roots": [...], "always": bool}
        self.paths = []  # (regex, glob, kind, packages or script ids)
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r"^script\s+(\S+)\s+roots=(\S+)(\s+always)?$", line)
            if m:
                if m.group(1) in self.scripts:
                    raise ValueError(f"map line {n}: duplicate script {m.group(1)}")
                self.scripts[m.group(1)] = {"roots": m.group(2).split(","), "always": bool(m.group(3))}
                continue
            m = re.match(r"^path\s+(\S+)\s+->\s+(inert|pkg\s+(\S+)|script\s+(\S+))$", line)
            if m:
                kind = m.group(2).split()[0]
                self.paths.append((glob_re(m.group(1)), m.group(1), kind, (m.group(3) or m.group(4) or "").split(",") if kind != "inert" else []))
                continue
            raise ValueError(f"map line {n}: cannot parse {raw!r}")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical_hash(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


class Graph(dict):
    """The one listing used by selection, with observation metadata."""


def graph_evidence(pkgs):
    if pkgs is None:
        return {"status": "unknown", "reason": "listing not observed"}
    normalized = {k: {"dir": v["dir"], "imports": sorted(set(v["imports"])),
                      "tests": sorted(set(v["tests"]))} for k, v in sorted(pkgs.items())}
    return {"status": getattr(pkgs, "observation", {}).get("status", "unknown"),
            "scope": "local imports and root test imports from one go list; not universal completeness",
            "packages": normalized, "sha256": canonical_hash(normalized),
            "listing": getattr(pkgs, "observation", {"status": "unknown", "reason": "caller supplied graph"})}



def source_snapshot():
    try:
        r = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, timeout=10)
        if r.returncode:
            return None
        files = {}
        for raw in sorted(r.stdout.split(b"\0")):
            if not raw:
                continue
            name = os.fsdecode(raw)
            path = ROOT / name
            files[name] = {"kind": "symlink" if path.is_symlink() else "file",
                           "sha256": digest(os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes())}
        return files
    except (OSError, subprocess.TimeoutExpired):
        return None


def provenance(base, head, mapfile, explicit=False):
    def git(*args):
        try:
            r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=10)
            return r.stdout.strip() if r.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None
    def file_hash(path):
        try:
            return digest(path.read_bytes())
        except OSError:
            return None
    inventory = {str(p.relative_to(ROOT)): file_hash(p) for p in sorted((ROOT / "scripts").glob("*mutations.sh"))}
    # Bind the actual working source bytes, including uncommitted edits, rather
    # than claiming that the Git tree alone describes the listing's input.
    sources = source_snapshot()
    return {"schema": "keep-mutation-shadow-provenance-v1", "input_mode": "explicit-files" if explicit else "git-diff",
            "base": {"requested": base, "commit": git("rev-parse", "--verify", base + "^{commit}")},
            "head": {"requested": head, "commit": git("rev-parse", "--verify", head + "^{commit}")},
            "merge_base": git("merge-base", base, head), "checkout_commit": git("rev-parse", "HEAD"),
            "source_tree": git("rev-parse", "HEAD^{tree}"),
            "working_tracked_sources": sources, "working_tracked_sha256": canonical_hash(sources) if sources is not None else None,
            "source_scope": "tracked working files only; untracked/generated inputs and external dependencies not certified",
            "map_sha256": file_hash(mapfile), "selector_sha256": file_hash(Path(__file__)),
            "mutation_inventory": inventory, "mutation_inventory_sha256": canonical_hash(inventory),
            "ci_ids": {k: os.environ[k] for k in ("CI_PROJECT_ID", "CI_PIPELINE_ID", "CI_JOB_ID", "CI_MERGE_REQUEST_IID")
                       if re.fullmatch(r"[0-9]+", os.environ.get(k, ""))}}


def load_graph():
    env = dict(os.environ, GOOS="linux", GOARCH="amd64", GOFLAGS="-buildvcs=false")
    try:
        before_sources = source_snapshot()
    except Exception:
        before_sources = None
    r = subprocess.run(["go", "list", "-json", "./..."], cwd=ROOT, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise Everything("go list failed: " + r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "go list failed")
    dec, s, i, pkgs = json.JSONDecoder(), r.stdout, 0, Graph()
    try:
        after_sources = source_snapshot()
        binary = shutil.which("go")
        version = subprocess.run(["go", "version"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
        pkgs.observation = {"status": "observed", "argv": ["go", "list", "-json", "./..."],
                            "version": version.stdout.strip() if version.returncode == 0 else None,
                            "binary_sha256": digest(Path(binary).read_bytes()) if binary else None,
                            "target": {k: env.get(k) for k in ("GOOS", "GOARCH", "GOFLAGS", "CGO_ENABLED")},
                            "raw_listing_sha256": digest(r.stdout.encode()), "exit_code": r.returncode,
                            "source_before_sha256": canonical_hash(before_sources) if before_sources is not None else None,
                            "source_after_sha256": canonical_hash(after_sources) if after_sources is not None else None,
                            "source_binding_status": "observed-stable" if before_sources is not None and before_sources == after_sources else "unknown",
                            "environment_scope": "explicit target overrides; inherited CGO_ENABLED may be unset; dependency/toolchain inputs not certified"}
    except Exception:
        pkgs.observation = {"status": "error", "reason": "listing metadata unavailable"}
    while i < len(s):
        while i < len(s) and s[i].isspace():
            i += 1
        if i >= len(s):
            break
        o, i = dec.raw_decode(s, i)
        rel = o["ImportPath"][len(MODULE_PREFIX):] if o["ImportPath"].startswith(MODULE_PREFIX) else o["ImportPath"]
        imp = lambda key: [x[len(MODULE_PREFIX):] for x in (o.get(key) or []) if x.startswith(MODULE_PREFIX)]
        pkgs[rel] = {"imports": imp("Imports"), "tests": imp("TestImports") + imp("XTestImports"),
                     "dir": os.path.relpath(os.path.realpath(o["Dir"]), ROOT)}
    return pkgs


def expand_roots(roots, pkgs):
    out = set()
    for r in roots:
        if r.endswith("/..."):
            base = r[:-4]
            hit = {p for p in pkgs if p == base or p.startswith(base + "/")}
        else:
            hit = {r} & set(pkgs)
        if not hit:
            raise ValueError(f"root {r} matches no package")
        out |= hit
    return out


def closure(roots, pkgs):
    """Roots plus everything they or their tests import, transitively. Only
    the roots' own tests count: a dependency's test files are not run."""
    seen = set(roots)
    stack = [x for r in roots for x in pkgs[r]["imports"] + pkgs[r]["tests"]]
    while stack:
        p = stack.pop()
        if p in seen or p not in pkgs:
            continue
        seen.add(p)
        stack.extend(pkgs[p]["imports"])
    return seen


def changed_packages(files, pkgs, m, ctx=None, direct=None):
    """Packages a set of changed files touches. Raises Everything if unsure.

    Changes under scripts/ and to the CI configuration are not packages: `ctx`
    (a Context) turns them into scripts and post-review jobs; without it they
    select everything. `direct` collects the script ids that map rules
    (`path ... -> script ...`) name.
    """
    by_dir = {v["dir"]: k for k, v in pkgs.items()}
    changed, reasons = set(), {}
    direct = {} if direct is None else direct
    for f in files:
        for pat in ALL_PATTERNS:
            if re.search(pat, f):
                raise Everything(f"shared path {f}")
        if f == CI_CONFIG or f.startswith((".gitlab/ci/", "scripts/")):
            if ctx is None:
                raise Everything(f"shared path {f}")
            ctx.classify(f)
            continue
        # An explicit rule wins over the directory convention below.
        rule = next((p for p in m.paths if p[0].match(f)), None)
        if rule:
            if rule[2] == "pkg":
                for pk in rule[3]:
                    if pk not in pkgs:
                        raise Everything(f"map rule {rule[1]} names unknown package {pk}")
                    changed.add(pk)
                    reasons.setdefault(pk, f"{f} (rule {rule[1]})")
            elif rule[2] == "script":
                for sid in rule[3]:
                    if sid not in m.scripts:
                        raise Everything(f"map rule {rule[1]} names unknown script {sid}")
                    direct.setdefault(sid, f"{f} (rule {rule[1]})")
            continue
        d = os.path.dirname(f)
        parts = f.split("/")
        if "testdata" in parts:
            d = "/".join(parts[:parts.index("testdata")])
        if d in by_dir:
            changed.add(by_dir[d])
            reasons.setdefault(by_dir[d], f)
            continue
        raise Everything(f"unknown path {f}")
    return changed, reasons


def scripts_on_disk(root=ROOT):
    """Ids of the scripts/check-*-mutations.sh that exist."""
    on_disk = {re.sub(r"^(check-)?(.*)-mutations\.sh$", r"\2", p.name) for p in (root / "scripts").glob("*mutations.sh")}
    return on_disk - {"mutation-helpers"}


def own_script(sid, root=ROOT):
    """The script of map id `sid`, relative to the repository root."""
    for name in (f"scripts/check-{sid}-mutations.sh", f"scripts/{sid}-mutations.sh"):
        if (root / name).is_file():
            return name
    return f"scripts/check-{sid}-mutations.sh"


def select(files, pkgs, m, root=ROOT, ctx=None):
    ids = set(m.scripts)
    on_disk = scripts_on_disk(root)
    missing = (on_disk - ids) | {i for i in ids if i not in on_disk}
    if missing:
        raise Everything("map and scripts/ disagree on: " + ", ".join(sorted(missing)))
    direct = {}
    changed, why = changed_packages(files, pkgs, m, ctx, direct)
    if ctx is not None:
        for sid, reason in ctx.scripts.items():
            direct.setdefault(sid, reason)
    selected, skipped = [], []
    for sid in sorted(ids):
        spec = m.scripts[sid]
        reach = closure(expand_roots(spec["roots"], pkgs), pkgs)
        hit = sorted(changed & reach)
        if hit:
            selected.append({"script": sid, "always": spec["always"], "reason": f"{why[hit[0]]} -> {hit[0]}"})
        elif sid in direct:
            selected.append({"script": sid, "always": spec["always"], "reason": direct[sid]})
        # The security zone runs on every change to a package. A diff that
        # changes no package (documentation, one suite's own script, a CI job
        # definition) cannot change what the zone's suites test.
        elif spec["always"] and changed:
            selected.append({"script": sid, "always": True, "reason": "security zone"})
        else:
            skipped.append({"script": sid})
    return selected, skipped


# ── scripts and CI job definitions ───────────────────────────────────────
# A script is used by the scripts and post-review jobs that name it, directly
# or through scripts that name it: its file name as a word of their text
# (full-line comments do not count). A glob over scripts/ names every file it
# matches; a script path built from a variable cannot be followed, so a
# post-review job that reaches one makes every change under scripts/ select
# everything.
WORD = re.compile(r"[\w.-]+")
SCRIPT_GLOB = re.compile(r"scripts/[\w./*?-]*[*?][\w./*?-]*")
SCRIPT_OPAQUE = re.compile(r"scripts/\$|\$\{?[A-Za-z_]\w*\}?-mutations\.sh|/\$\{?[A-Za-z_]\w*\}?\.(?:sh|py|mjs)\b")
LINE_COMMENT = {".mjs": "//", ".js": "//", ".go": "//"}


def code_text(name, text):
    """`text` without full-line comments."""
    mark = LINE_COMMENT.get(os.path.splitext(name)[1], "#")
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(mark))


class ScriptGraph:
    """Which tracked file under scripts/ names which."""

    def __init__(self, texts):
        # texts: path -> file text, for every tracked file under scripts/
        self.texts = {f: code_text(f, t) for f, t in texts.items()}
        self.by_name = {}
        for f in texts:
            self.by_name.setdefault(os.path.basename(f), set()).add(f)
        self.edges = {f: self.named(t) - {f} for f, t in self.texts.items()}
        self._closures = {}

    @classmethod
    def from_tree(cls, root=ROOT):
        try:
            r = subprocess.run(["git", "ls-files", "-z", "--", "scripts"], cwd=root, capture_output=True, timeout=10)
            names = [os.fsdecode(raw) for raw in r.stdout.split(b"\0") if raw] if r.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            names = None
        if names is None:
            # Not a checkout: every file on disk, a superset of the tracked ones.
            names = sorted(str(p.relative_to(root)) for p in (root / "scripts").rglob("*") if p.is_file() or p.is_symlink())
        stamp = []
        for name in sorted(names):
            path = root / name
            try:
                st = path.lstat()
                stamp.append((name, st.st_mtime_ns, st.st_size, st.st_mode))
            except OSError:
                stamp.append((name, None, None, None))
        return cls._cached(cls, str(root), tuple(stamp))

    @staticmethod
    @functools.lru_cache(maxsize=4)
    def _cached(cls, root, stamp):
        # One graph per tree state: a test or a backtest asks many questions of the same tree.
        texts = {}
        for name, *_ in stamp:
            path = Path(root) / name
            texts[name] = "" if path.is_symlink() or not path.is_file() else path.read_text(errors="replace")
        return cls(texts)

    def named(self, text):
        """Tracked files `text` names, by file name or by a glob over scripts/."""
        out = {f for w in set(WORD.findall(text)) for f in self.by_name.get(w, ())}
        for g in SCRIPT_GLOB.findall(text):
            out |= {f for f in self.texts if fnmatch.fnmatchcase(f, g)}
        return out

    def closure(self, starts):
        key = frozenset(starts)
        if key not in self._closures:
            self._closures[key] = frozenset(self._walk(key))
        return self._closures[key]

    def _walk(self, starts):
        seen, stack = set(starts), list(starts)
        while stack:
            for g in self.edges.get(stack.pop(), ()):
                if g not in seen:
                    seen.add(g)
                    stack.append(g)
        return seen

    def opaque(self, files):
        """Files among `files` that build a script path from a variable."""
        return sorted(f for f in files if SCRIPT_OPAQUE.search(self.texts.get(f, "")))


def load_yaml():
    try:
        import yaml
    except ImportError as e:
        raise Everything("PyYAML is not available") from e
    return yaml


@functools.lru_cache(maxsize=8)
def load_config(text):
    """A CI config text, parsed (anchors resolved). Callers must not modify it."""
    yaml = load_yaml()
    try:
        config = yaml.load(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
    except yaml.YAMLError as e:
        raise Everything("CI config does not parse") from e
    if not isinstance(config, dict):
        raise Everything("CI config is not a mapping")
    return config


def merge(base, over):
    """GitLab's `extends` merge: hashes merge deeply, everything else is replaced."""
    out = dict(base)
    for k, v in over.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def resolve_job(config, name, seen=()):
    """A job with its `extends` chain merged in."""
    job = config.get(name)
    if not isinstance(job, dict):
        raise Everything(f"CI job {name} is not a mapping")
    parents = job.get("extends", [])
    out = {}
    for parent in [parents] if isinstance(parents, str) else parents:
        if parent in seen + (name,):
            raise Everything(f"CI extends cycle at {parent}")
        out = merge(out, resolve_job(config, parent, seen + (name,)))
    return merge(out, {k: v for k, v in job.items() if k != "extends"})


def is_job(name, job):
    return isinstance(job, dict) and not name.startswith(".") and name not in GLOBAL_CI_KEYS


def post_review_jobs(config):
    """name -> resolved job, for the post-review mutation jobs of a CI config."""
    if not isinstance(config, dict):
        raise Everything("CI config is not a mapping")
    out = {}
    for name, job in config.items():
        if is_job(name, job) and name not in GATING_JOBS:
            resolved = resolve_job(config, name)
            if resolved.get("stage") == POST_REVIEW and "trigger" not in resolved:
                out[name] = resolved
    return out


def job_commands(job):
    return json.dumps([job.get(k) for k in ("before_script", "script", "after_script")])


class Layout:
    """Top-level keys of one CI config text: their lines and what feeds what."""

    def __init__(self, text):
        yaml = load_yaml()
        try:
            self.config = yaml.safe_load(text)
            root = yaml.compose(text, Loader=yaml.SafeLoader)
            events = list(yaml.parse(text, Loader=yaml.SafeLoader))
        except yaml.YAMLError as e:
            raise Everything("CI config does not parse") from e
        if not isinstance(root, yaml.MappingNode) or not isinstance(self.config, dict):
            raise Everything("CI config is not a mapping")
        self.lines = text.splitlines()
        self.spans = []  # (first line, last line, key), 0-based, inclusive
        for k, v in root.value:
            last = v.end_mark.line - (1 if v.end_mark.column == 0 else 0)
            self.spans.append((k.start_mark.line, max(k.start_mark.line, last), k.value))
        # Lines inside block scalars (`|`, `>`): a `#` there is content, not a comment.
        self.scalar_lines, seen, stack = set(), set(), [root]
        while stack:
            n = stack.pop()
            if id(n) in seen:
                continue
            seen.add(id(n))
            if isinstance(n, yaml.ScalarNode) and n.style in ("|", ">"):
                self.scalar_lines.update(range(n.start_mark.line + 1, n.end_mark.line + 1))
            elif isinstance(n, yaml.SequenceNode):
                stack.extend(n.value)
            elif isinstance(n, yaml.MappingNode):
                stack.extend(x for pair in n.value for x in pair)
        # Each key's dependencies: what it extends and the anchors it aliases.
        anchors, self.deps = [], {key: set() for _, _, key in self.spans}
        for ev in events:
            line = ev.start_mark.line
            if isinstance(ev, yaml.AliasEvent):
                owner = self.key_at(line)
                where = [k for l, k in anchors if l <= line and k[0] == ev.anchor]
                if owner is not None and where:
                    self.deps[owner].add(where[-1][1])
            elif getattr(ev, "anchor", None):
                anchors.append((line, (ev.anchor, self.key_at(line))))
        for key in self.deps:
            job = self.config.get(key)
            parents = job.get("extends", []) if isinstance(job, dict) else []
            self.deps[key] |= set([parents] if isinstance(parents, str) else parents)
            self.deps[key].discard(key)
            self.deps[key].discard(None)
        self.post_review = set(post_review_jobs(self.config))

    def key_at(self, line):
        return next((key for first, last, key in self.spans if first <= line <= last), None)

    def is_comment(self, line):
        text = self.lines[line].strip() if line < len(self.lines) else ""
        return not text or (text.startswith("#") and line not in self.scalar_lines)

    def feeds_post_review(self, key):
        """A post-review job other than `key` is built from `key`."""
        for job in self.post_review - {key}:
            seen, stack = set(), [job]
            while stack:
                for dep in self.deps.get(stack.pop(), ()):
                    if dep == key:
                        return job
                    if dep not in seen:
                        seen.add(dep)
                        stack.append(dep)
        return None

    def effect(self, key):
        """The post-review jobs a change to `key` selects; Everything if all of them."""
        if key in GLOBAL_CI_KEYS:
            raise Everything(f"{CI_CONFIG}: {key} reaches every job")
        if key in GATING_JOBS:
            raise Everything(f"{CI_CONFIG}: {key} decides which post-review jobs run")
        user = self.feeds_post_review(key)
        if user is not None:
            raise Everything(f"{CI_CONFIG}: {key} is part of post-review job {user}")
        return {key} if key in self.post_review else set()


def ci_definition_changes(old_text, new_text):
    """Post-review jobs whose definition differs between two CI config texts.

    Raises Everything when the change reaches every post-review job: a global
    key, the selection jobs, a template, `extends` parent or anchor a
    post-review job is built from, or a line outside any top-level key.
    Comments and blank lines change nothing.
    """
    if old_text is None or new_text is None:
        raise Everything(f"{CI_CONFIG} added or deleted")
    old, new = Layout(old_text), Layout(new_text)
    jobs = set()
    ops = difflib.SequenceMatcher(None, old.lines, new.lines, autojunk=False).get_opcodes()
    for tag, i1, i2, j1, j2 in ops:
        if tag == "equal":
            continue
        for side, lines in ((old, range(i1, i2)), (new, range(j1, j2))):
            for line in lines:
                if side.is_comment(line):
                    continue
                key = side.key_at(line)
                if key is None:
                    raise Everything(f"{CI_CONFIG}: change outside any top-level key")
                jobs |= side.effect(key)
    return jobs & new.post_review


class Context:
    """Changes under scripts/ and to CI files, turned into scripts and jobs."""

    def __init__(self, m, root=ROOT, refs=None):
        self.m, self.root, self.refs = m, root, refs
        self.scripts = {}  # map script id -> reason
        self.jobs = {}  # post-review job -> reason
        self._head = self._graph = None

    def head(self):
        if self._head is None:
            try:
                text = (self.root / CI_CONFIG).read_text()
            except OSError as e:
                raise Everything(f"{CI_CONFIG} unreadable") from e
            config = load_config(text)
            self._head = (config, post_review_jobs(config))
        return self._head

    def graph(self):
        if self._graph is None:
            self._graph = ScriptGraph.from_tree(self.root)
        return self._graph

    def entries(self):
        """post-review job -> the scripts its commands name."""
        g = self.graph()
        return {name: g.named(job_commands(job)) for name, job in self.head()[1].items()}

    def users(self, f):
        """(post-review jobs, map script ids) whose scripts reach `f`."""
        g = self.graph()
        jobs = {j for j, e in self.entries().items() if f in g.closure(e)}
        ids = {sid for sid in self.m.scripts if f in g.closure({own_script(sid, self.root)})}
        return jobs, ids

    def classify(self, f):
        if f == CI_CONFIG:
            for job in sorted(self.ci_changes()):
                self.jobs.setdefault(job, f"{CI_CONFIG}: definition of {job} changed")
            return
        if f.startswith(".gitlab/ci/"):
            if "include" in self.head()[0] or "include" in (self.base_config() or {}):
                raise Everything(f"shared path {f} ({CI_CONFIG} includes files)")
            if f != TEST_CHILD_CONFIG:
                raise Everything(f"unknown path {f}")
            return
        g = self.graph()
        reachable = set().union(set(), *(g.closure(e) for e in self.entries().values()))
        opaque = g.opaque(reachable)
        if opaque:
            raise Everything(f"shared path {f} ({opaque[0]} builds script paths from a variable)")
        jobs, ids = self.users(f)
        own = {sid for sid in self.m.scripts if own_script(sid, self.root) == f}
        if not own and len(jobs) > 1:
            raise Everything(f"shared script {f} (used by {len(jobs)} post-review jobs)")
        for sid in sorted(ids):
            self.scripts.setdefault(sid, f"{f} (script)")
        for job in sorted(jobs):
            self.jobs.setdefault(job, f"{f} (script)")

    def blob(self, ref, path):
        r = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=self.root, capture_output=True, timeout=10)
        return r.stdout.decode(errors="replace") if r.returncode == 0 else None

    def merge_base(self):
        base, head = self.refs
        r = subprocess.run(["git", "merge-base", base, head], cwd=self.root, capture_output=True, text=True, timeout=10)
        if r.returncode:
            raise Everything("no merge base for the CI comparison")
        return r.stdout.strip()

    def base_config(self):
        if self.refs is None:
            return None
        text = self.blob(self.merge_base(), CI_CONFIG)
        return load_config(text) if text is not None else None

    def ci_changes(self):
        if self.refs is None:
            raise Everything(f"shared path {CI_CONFIG} (no diff base to compare)")
        return ci_definition_changes(self.blob(self.merge_base(), CI_CONFIG), self.blob(self.refs[1], CI_CONFIG))

    def job_report(self, selected):
        """Post-review jobs that run the selected scripts or were selected directly."""
        g = self.graph()
        why = {s["script"]: s["reason"] for s in selected}
        own = {sid: own_script(sid, self.root) for sid in self.m.scripts}
        out, skipped = [], []
        for name, entry in sorted(self.entries().items()):
            reach = g.closure(entry)
            runs = sorted(sid for sid, f in own.items() if f in reach)
            hit = [sid for sid in runs if sid in why]
            if name in self.jobs:
                out.append({"job": name, "reason": self.jobs[name]})
            elif not runs:
                out.append({"job": name, "reason": "runs no suite the map knows"})
            elif hit:
                out.append({"job": name, "reason": f"{hit[0]}: {why[hit[0]]}"})
            else:
                skipped.append({"job": name})
        return {"all": False, "selected": out, "skipped": skipped}


def all_jobs(reason, root=ROOT):
    """The job part of an "everything" answer, listing the jobs when it can."""
    try:
        names = sorted(post_review_jobs(load_config((root / CI_CONFIG).read_text())))
    except Exception:
        names = []
    return {"all": True, "reason": reason, "selected": [{"job": n, "reason": reason} for n in names], "skipped": []}


def diff_listing(base, head, cwd=ROOT):
    """(changed files, changed files that are a symlink before or after)."""
    out = subprocess.run(["git", "diff", "--raw", "-z", "--no-renames", f"{base}...{head}"], cwd=cwd, capture_output=True, text=True, check=True).stdout
    files, links, it = set(), set(), iter(out.split("\0"))
    for meta in it:
        if not meta:
            continue
        path = next(it)
        files.add(path)
        if "120000" in meta.lstrip(":").split()[:2]:
            links.add(path)
    return sorted(files), sorted(links)


def changed_files(base, head, cwd=ROOT):
    return diff_listing(base, head, cwd)[0]


def report(files, mapfile, symlinks=(), refs=None):
    """The answer for `files`. `refs` = (base, head) of the diff, needed to
    compare CI job definitions; without it a CI file change selects everything."""
    m = Map(mapfile.read_text())
    # "everything" is every script the map or scripts/ knows: a script the
    # map forgot is exactly the one a reader of "selected" must not miss
    every = sorted(set(m.scripts) | scripts_on_disk())
    pkgs = None
    try:
        if symlinks:
            # A link's content is a path the import graph does not see.
            raise Everything(f"symlink {sorted(symlinks)[0]}")
        pkgs = load_graph()
        ctx = Context(m, ROOT, refs)
        selected, skipped = select(files, pkgs, m, ctx=ctx)
        try:
            jobs = ctx.job_report(selected)
        except Exception as e:  # no job list, no narrowing: every post-review job runs
            jobs = all_jobs(f"post-review jobs not resolved: {e}")
        return {"mode": "graph", "changed": files, "all": False, "selected": selected, "skipped": skipped,
                "jobs": jobs, "graph": graph_evidence(pkgs)}
    except Everything as e:
        evidence = graph_evidence(pkgs)
        if pkgs is None and str(e).startswith("go list failed"):
            evidence = {"status": "error", "reason": "go list failed", "argv": ["go", "list", "-json", "./..."]}
        return {"mode": "all", "changed": files, "all": True, "reason": str(e),
                "selected": [{"script": s, "always": m.scripts.get(s, {}).get("always", False), "reason": str(e)} for s in every], "skipped": [],
                "jobs": all_jobs(str(e)), "graph": evidence}


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--files", nargs="*")
    ap.add_argument("--map", default=str(ROOT / "scripts" / "mutation-select.map"))
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    try:
        if a.files is not None:
            files, links = sorted(set(a.files)), sorted(f for f in set(a.files) if (ROOT / f).is_symlink())
        else:
            files, links = diff_listing(a.base, a.head)
        rep = report(files, Path(a.map), links, None if a.files is not None else (a.base, a.head))
    except Exception as e:  # the selector never decides on a failure of its own
        try:  # even now the answer is "everything", spelled out so a reader of "selected" runs it all
            known = set(Map(Path(a.map).read_text()).scripts)
        except Exception:  # an unreadable map still leaves the scripts on disk
            known = set()
        every = sorted(known | scripts_on_disk())
        rep = {"mode": "all", "all": True, "reason": f"selector error: {e}", "changed": [],
               "selected": [{"script": x, "always": False, "reason": "selector error"} for x in every], "skipped": [],
               "jobs": all_jobs(f"selector error: {e}")}
    rep.setdefault("graph", {"status": "error", "reason": "selector failed before graph evidence was retained"})
    try:
        rep["provenance"] = provenance(a.base, a.head, Path(a.map), a.files is not None)
    except Exception:
        # Evidence must never alter the original selection policy or CLI exit.
        rep["provenance"] = {"schema": "keep-mutation-shadow-provenance-v1", "status": "error"}
    if a.json:
        Path(a.json).write_text(json.dumps(rep, indent=1) + "\n")
    sel = [s["script"] for s in rep["selected"]]
    print(f"{'ALL' if rep['all'] else 'selected'}: {len(sel)}; skipped: {len(rep['skipped'])}" + (f"; reason: {rep['reason']}" if rep["all"] else ""))
    for s in rep["selected"]:
        print(("  always " if s["always"] else "  graph  ") + s["script"] + ("" if rep["all"] else "  <- " + s["reason"]))
    for s in rep["skipped"]:
        print("  skip   " + s["script"])
    jobs = rep["jobs"]
    print(f"post-review jobs: {'ALL' if jobs['all'] else 'selected'}: {len(jobs['selected'])}; skipped: {len(jobs['skipped'])}")
    for j in jobs["selected"]:
        print("  run    " + j["job"] + ("" if jobs["all"] else "  <- " + j["reason"]))
    for j in jobs["skipped"]:
        print("  skip   " + j["job"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
