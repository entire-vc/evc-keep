#!/usr/bin/env python3
"""Names what a plain-text `go test` log (stdin) says about results, and
nothing else: a mutation driver prints this instead of its raw log.

The log is untrusted: a test or a mutant can put a value into an assertion, a
subtest name, a panic or a compiler message, and a multi-line message can
forge any line `go test` prints. So no text from the log is echoed. A line is
printed only in a fixed shape, rebuilt from what the source tree at ROOT
vouches for (one walk of ROOT; a path is printed as the walk spells it, never
as the log does):

  --- FAIL|SKIP: TestName at path_test.go:N[, other_test.go:M ...]
      the log line is exactly a go test verdict, the name is a top-level
      `func TestName(` declared in a *_test.go file under ROOT, and the
      locations are its declarations, not one taken from the log: a name
      declared in several files (packages, build tags) lists every one, the
      first 4 then a count, since the log line cannot tell them apart. A
      subtest is cut to its parent (subtest names may be values).
  FAIL|ok <import path>
      the module of ROOT/go.mod plus a directory under ROOT holding .go files.
  build failed at path.go:N
      the log names a compiler location in a .go file under ROOT, N within
      the file's length; the message is not printed.

Each kind is deduplicated, sorted and cut at 40 lines, so neither the order
nor the repetition of log lines carries anything. The last line counts what
was not printed (result-shaped lines that matched nothing above, panics,
build failures), each count capped at 40.

Usage: test-result-names.sh ROOT < go-test-log
       test-result-names.sh --resolve-callers ROOT < resolve-callers guard output
       test-result-names.sh --goroutines ROOT < goroutine dump

--resolve-callers keeps only the fixed lines of the resolve-callers guard:
its three failure headers verbatim, and HANDLER/ADAPTERDECL/FORBIDDEN with a
.go file under ROOT (the source text after it is dropped).

--goroutines keeps, per goroutine of a timeout dump, the frames of this module
(package directory under ROOT, file and line under ROOT) and of pgx (file
present in the module cache), with arguments dropped; the goroutine header
and every other frame are not printed.

Boundary: the filter guards against an accidental leak through go test
output (a value in an assertion, a subtest name, a panic or a compiler
message). Test code acting on purpose is outside this model: it can encode a
value in which declared names it reports, in counters and line numbers, or
bypass the filter altogether; a snapshot of the tree would not close that.
This residual is accepted by the Keep lead.
"""
import os
import posixpath
import re
import sys

MAX_LINES = 40
VERDICT = re.compile(r"^\s*--- (FAIL|SKIP): (Test[A-Za-z0-9_]*)(/\S*)? \([0-9.]+s\)$")
PACKAGE = re.compile(r"^(FAIL|ok)\s+(\S+)(\s.*)?$")
LOCATION = re.compile(r"^([A-Za-z0-9_./-]+\.go):([0-9]+)(?::[0-9]+)?: ")
PANIC = re.compile(r"^(panic|fatal error): ")
BUILD = re.compile(r"\[(build|setup) failed\]")
RESULT_SHAPED = re.compile(r"^\s*(--- [A-Z]+:|FAIL\b|ok\b)")

RESOLVE_HEADERS = frozenset((
    "FAIL: ResolveSecret used outside handleResolveSecret:",
    "FAIL: ResolveSecret handler/adapter must be declared exactly once, in "
    "internal/api/mesh.go and cmd/keep-server/app/main.go (second ResolveSecret declaration?):",
    "FAIL: handleResolveSecret no longer calls ResolveSecret; the guard cannot see it, update it",
))
RESOLVE_LINE = re.compile(r"^(HANDLER|ADAPTERDECL|FORBIDDEN) \./([A-Za-z0-9_./-]+\.go)(?::([0-9]+))?(?:$|: )")

FRAME = re.compile(r"^([A-Za-z0-9_./*()\[\]-]+)\(.*\)$")
FRAME_FILE = re.compile(r"^\t(/[^\s:]+\.go):([0-9]+)(?: \+0x[0-9a-f]+)?$")
PGX_FILE = re.compile(r"/pkg/mod/(github\.com/jackc/pgx/v5@v[0-9][0-9A-Za-z.+-]*(?:/[A-Za-z0-9_]+)*/[A-Za-z0-9_]+\.go)$")
IDENT_TAIL = re.compile(r"^[A-Za-z0-9_.*()\[\]]+$")


class Tree:
    """The .go files and package directories under root, from one walk."""

    def __init__(self, root, given=None):
        self.root = root
        self.prefixes = sorted({root + os.sep, (given or root).rstrip(os.sep) + os.sep})
        self.files, self.dirs = set(), set()
        for d, dirs, files in os.walk(root):
            dirs[:] = sorted(x for x in dirs if x not in {".git", "node_modules", "vendor"})
            rel = os.path.relpath(d, root).replace(os.sep, "/")
            gofiles = [f for f in files if f.endswith(".go") and os.path.isfile(os.path.join(d, f))]
            for f in gofiles:
                self.files.add(f if rel == "." else f"{rel}/{f}")
            if gofiles:
                self.dirs.add("" if rel == "." else rel)
        self._lines = {}

    def file(self, rel):
        """rel as the walk spells it, or None."""
        rel = posixpath.normpath(rel)
        return rel if rel in self.files else None

    def lines(self, rel):
        if rel not in self._lines:
            try:
                with open(os.path.join(self.root, rel), "rb") as fh:
                    self._lines[rel] = sum(1 for _ in fh)
            except OSError:
                self._lines[rel] = 0
        return self._lines[rel]

    def location(self, rel, line):
        """'rel:line' for a file of the tree and a line within it, or None."""
        rel = self.file(rel)
        if rel is None or not line.isdigit() or not 0 < int(line) <= self.lines(rel):
            return None
        return f"{rel}:{int(line)}"


def capped(n):
    return str(n) if n < MAX_LINES else f"{MAX_LINES}+"


def emit(lines):
    for out in sorted(set(lines))[:MAX_LINES]:
        print(out)


DECL_SHOWN = 4


def declared_tests(tree):
    """TestName -> 'at a_test.go:N, b_test.go:M' over every declaration."""
    decl = {}
    for rel in sorted(tree.files):
        if not rel.endswith("_test.go"):
            continue
        try:
            with open(os.path.join(tree.root, rel), encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    m = re.match(r"func (Test[A-Za-z0-9_]*)\(", line)
                    if m:
                        decl.setdefault(m.group(1), []).append(f"{rel}:{n}")
        except OSError:
            pass
    return {name: ", ".join(locs[:DECL_SHOWN]) + (f" and {len(locs) - DECL_SHOWN} more" if len(locs) > DECL_SHOWN else "")
            for name, locs in decl.items()}


def module_path(root):
    try:
        with open(os.path.join(root, "go.mod"), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"^module\s+(\S+)\s*$", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


def go_test_names(tree, lines):
    decl = declared_tests(tree)
    module = module_path(tree.root)
    tests, packages, builds = [], [], []
    unknown = panics = build_failures = 0
    for line in lines:
        if BUILD.search(line):
            build_failures += 1
            continue
        if PANIC.match(line):
            panics += 1
            continue
        m = VERDICT.match(line)
        if m:
            if m.group(2) in decl:
                tests.append(f"--- {m.group(1)}: {m.group(2)} at {decl[m.group(2)]}")
            else:
                unknown += 1
            continue
        m = PACKAGE.match(line)
        if m:
            path = m.group(2)
            if module and path == module and "" in tree.dirs:
                packages.append(f"{m.group(1)} {module}")
            elif module and path.startswith(module + "/") and path[len(module) + 1:] in tree.dirs:
                packages.append(f"{m.group(1)} {module}/{path[len(module) + 1:]}")
            else:
                unknown += 1
            continue
        if line in ("FAIL", "PASS"):
            continue  # the bare per-package line go test prints before its summary
        # A compiler location is unindented; an indented `x_test.go:N:` is a
        # test's own message. The line number is bounded by the file's length
        # so it cannot carry the digits of a value.
        m = LOCATION.match(line)
        if m:
            loc = tree.location(m.group(1), m.group(2))
            if loc:
                builds.append(f"build failed at {loc}")
            else:
                unknown += 1
            continue
        if RESULT_SHAPED.match(line):
            unknown += 1
    emit(tests)
    emit(packages)
    emit(builds)
    print(f"result lines not printed: {capped(unknown)}; panics: {capped(panics)}; "
          f"build failures: {capped(build_failures)}")


def resolve_callers(tree, lines):
    unknown = 0
    headers, found = [], []
    for line in lines:
        if line in RESOLVE_HEADERS:
            headers.append(line)
            continue
        m = RESOLVE_LINE.match(line)
        rel = tree.file(m.group(2)) if m else None
        if rel and m.group(3) is None:
            found.append(f"{m.group(1)} ./{rel}")
        elif rel and tree.location(rel, m.group(3)):
            found.append(f"{m.group(1)} ./{tree.location(rel, m.group(3))}")
        else:
            unknown += 1
    emit(headers)
    emit(found)
    print(f"guard lines not printed: {capped(unknown)}")


DECL = re.compile(r"^(?:func\s+(?:\([^)]*\)\s*)?|type\s+)([A-Za-z_][A-Za-z0-9_]*)", re.M)
SYNTHETIC = re.compile(r"^(?:func|gowrap|deferwrap)[0-9]{1,3}$|^[0-9]{1,3}$|^glob$")
_declared = {}


def declared_names(directory):
    """Functions, methods and types declared in the .go files of directory."""
    if directory not in _declared:
        names = set()
        try:
            entries = sorted(os.listdir(directory))
        except OSError:
            entries = []
        for f in entries:
            if f.endswith(".go"):
                try:
                    with open(os.path.join(directory, f), encoding="utf-8", errors="replace") as fh:
                        names.update(DECL.findall(fh.read()))
                except OSError:
                    pass
        _declared[directory] = names
    return _declared[directory]


def exact_file(base, rel):
    """rel exists under base, each segment spelled as on disk (a
    case-insensitive file system would accept another spelling); the caller's
    open() turns a directory away."""
    cur = base
    for seg in rel.split("/"):
        try:
            if seg not in os.listdir(cur):
                return False
        except OSError:
            return False
        cur = os.path.join(cur, seg)
    return True


def frame(tree, module, func, path, line):
    """'func(...)' and 'file:line' for a frame of this module (file under
    ROOT) or of pgx (file in the module cache), the function in the file's
    package and every identifier in its name declared there; else None."""
    root = next((r for r in tree.prefixes if path.startswith(r)), None)
    if root and module:
        where = tree.location(path[len(root):], line)
        if where is None:
            return None
        rel_dir = posixpath.dirname(where.rsplit(":", 1)[0])
        package = module + ("/" + rel_dir if rel_dir else "")
    else:
        m = PGX_FILE.search(path)
        if not m or not exact_file(path[:m.start(1)], m.group(1)):
            return None
        try:
            with open(path, "rb") as fh:
                count = sum(1 for _ in fh)
        except OSError:
            return None
        if not 0 < int(line) <= count:
            return None
        where = f"{m.group(1)}:{int(line)}"
        # github.com/jackc/pgx/v5@vX/sub/dir -> github.com/jackc/pgx/v5/sub/dir
        parts = posixpath.dirname(m.group(1)).split("/")
        package = "/".join(parts[:3] + [parts[3].split("@", 1)[0]] + parts[4:])
    if not func.startswith(package + ".") or not IDENT_TAIL.match(func[len(package) + 1:]):
        return None
    declared = declared_names(os.path.dirname(path))
    for ident in re.split(r"[.*()\[\]]+", func[len(package) + 1:]):
        if ident and ident != "..." and ident not in declared and not SYNTHETIC.match(ident):
            return None
    return f"{func}(...)", where


def goroutines(tree, lines):
    module = module_path(tree.root)
    out, block, skipped = [], [], 0
    goroutine_count = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("goroutine ") and line.endswith(":"):
            if block:
                out.append("goroutine")
                out.extend(block)
            block = []
            goroutine_count += 1
            i += 1
            continue
        m = FRAME.match(line)
        f = FRAME_FILE.match(lines[i + 1]) if m and i + 1 < len(lines) else None
        if f:
            got = frame(tree, module, m.group(1), f.group(1), f.group(2))
            if got:
                block.append("  " + got[0])
                block.append("  \t" + got[1])
            else:
                skipped += 1
            i += 2
            continue
        i += 1
    if block:
        out.append("goroutine")
        out.extend(block)
    # Frames keep their order: it is the call chain. Only code locations
    # vouched for by the tree or the module cache are printed.
    for line in out[:3 * MAX_LINES]:
        print(line)
    print(f"goroutines: {capped(goroutine_count)}; frames not printed: {capped(skipped)}")


def main(argv):
    modes = {"--resolve-callers": resolve_callers, "--goroutines": goroutines}
    mode = go_test_names
    if argv[:1] and argv[0] in modes:
        mode, argv = modes[argv[0]], argv[1:]
    if len(argv) != 1 or not os.path.isdir(argv[0]):
        print("usage: test-result-names.sh [--resolve-callers|--goroutines] ROOT < log", file=sys.stderr)
        return 2
    tree = Tree(os.path.realpath(argv[0]), os.path.abspath(argv[0]))
    data = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    mode(tree, data.splitlines())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
