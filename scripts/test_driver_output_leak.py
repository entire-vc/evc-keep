#!/usr/bin/env python3
"""Mutation drivers must not copy go test output into the CI log.

A test or a mutant can carry a value into an assertion, a subtest name, a
panic or a compiler message; a driver that prints its raw log (head, tail,
cat, grep) puts it into the job log and the artifact mirror. Each driver runs
here on a small copy of the tree with `go` replaced by a stub that prints a
canary, in six encodings and in every shape go test output takes, on the
paths a driver reports from: a red baseline, a mutant red on the wrong test,
on the right test with a missing needle or step, a build or SQL error, a
timeout with a goroutine dump. (scripts/mutation-helpers.sh prints on its
own and is guarded with it, not here.) The filter itself is tested directly
too: what it prints does not depend on how the log spells a path, on order
or on repetition.
The canary must not reach stdout or stderr. Positive controls: the stub's
decoy test, declared in the tree, is named; and with the filter swapped for
`cat` the same runs do leak, so the detector can see a leak.
"""
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest
import urllib.parse

ROOT = Path(__file__).resolve().parent.parent
MODULE = "github.com/entire-vc/evc-keep"
DECOY = "TestHarnessDecoy"
SCRIPTS = ("mutation-helpers.sh", "temp-workspace.sh", "test-result-names.sh", "test-result-names.py",
           "instrument-discovery-wipes.py", "check-resolve-callers.sh", "intake_baseline_diagnostics.py",
           "intake_mutant_diagnostics.py", "check-no-silent-skip.sh")

# Per driver: the source directories it mutates (a missing one shows as a
# driver that never reached a mutant, asserted below), the stub modes that
# reach each of its reporting paths, the shard total (1000 keeps only the
# first mutant), and whether to cut a long inventory to the first call of
# each kind (the reporting functions are untouched).
#   red          every run red on the decoy (red-baseline paths)
#   decoy        baseline green, mutants red on the decoy (wrong-test paths)
#   witness      baseline green, mutants red on every test -run selects
#                (missing needle, leak message, step or both-layers paths)
#   build, sql   baseline green, mutants red with a build or SQL error
#   nopass       baseline green, mutants exit 0 without a PASS line
#   chatty       witness, and the green baseline also prints the canary lines
#                (a driver that prints a passing verbose log)
#   infra        baseline green, mutants red with a process fault (timeout)
DRIVERS = {
    "targets": (("internal/targets",), ("decoy", "witness", "nopass"), 1, True),
    "mesh-rotation-e2e": (("cmd/keep-server/app", "internal/rotation", "plugins/mesh"),
                          ("red", "decoy", "witness"), 1, False),
    "mesh-ui-browser": (("cmd/keep-server/app", "internal/api"), ("red", "decoy"), 1, False),
    "runnerproto": (("pkg/runnerproto",), ("decoy",), 1, True),
    "rotate-audit": (("internal/api", "internal/rotation"), ("red",), 1000, False),
    "tenancy": (("internal/catalog", "internal/tenancy"), ("red", "decoy"), 1000, False),
    "console-exec-predicate": (("internal/api",), ("red",), 1, False),
    "discovery": (("internal/runner/discover",), ("red",), 1, True),
    "identity-attack": (("internal/identity", "internal/obs", "internal/testutil/canary", "test/security"),
                        ("decoy", "witness", "build", "sql"), 1000, False),
    "meshgate-concurrency": (("internal/meshgate", "internal/deployment"), ("red", "infra"), 1, False),
    "intake-page": (("web/intake", "internal/intake/descriptor", "internal/builtin"), ("chatty",), 1, True),
}
# Driver file when it is not scripts/check-DRIVER-mutations.sh.
SCRIPT_FILE = {"meshgate-concurrency": "check-meshgate-concurrency.sh"}
# Lines a witness mutant adds to its red log: the assertion the driver needs
# (the first intake-page mutant after trimming).
WITNESS_EXTRA = {"intake-page": ["    page_test.go:1: expected UI state was not reached (secret-name)"]}
# What a driver must print in a mode besides the decoy (positive controls).
EXPECT = {("meshgate-concurrency", "infra"): [
    f"  {MODULE}/internal/meshgate.(*PG).Settle(...)\n  \tinternal/meshgate/pgstore.go:122"]}
CALLS = ("mutate", "mutate2", "mutateN", "assert_still_green")


def trim_inventory(text):
    """Keep the first top-level call of each kind; drop the rest with their
    continuation lines. Function bodies and indented calls stay."""
    out, seen, skipping = [], set(), False
    for line in text.splitlines(keepends=True):
        if skipping:
            skipping = line.rstrip("\n").endswith("\\")
            continue
        word = line.split(" ", 1)[0]
        if word in CALLS and not line.startswith(word + "()"):
            if word in seen:
                skipping = line.rstrip("\n").endswith("\\")
                continue
            seen.add(word)
        out.append(line)
    return "".join(out)


def canary_encodings(base):
    """The six encodings of internal/testutil/canary: raw, hex, URL-escaped,
    reversed, and base64 (standard and URL-safe) at all three alignments."""
    raw = base.encode()
    out = [base, binascii.hexlify(raw).decode(), urllib.parse.quote_plus(base), base[::-1]]
    for enc in (base64.standard_b64encode, base64.urlsafe_b64encode):
        for offset in range(3):
            encoded = enc(b"\0" * offset + raw).decode()
            first, end = (offset + 2) // 3, (offset + len(raw)) // 3
            if end > first:
                out.append(encoded[4 * first:4 * end])
    return out


def leaked(text, base):
    low = text.lower()
    return [e for e in canary_encodings(base) if e and (e in text or e.lower() in low)]


STUB = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, re, sys
conf = json.loads(pathlib.Path(os.environ["HARNESS_CONF"]).read_text())
args = sys.argv[1:]
if args[:2] == ["env", "GOOS"]:
    print("harness"); sys.exit(0)
if not args or args[0] != "test":
    sys.exit(0)
cwd = pathlib.Path.cwd()
tree = cwd
while not (tree / "go.mod").exists() and tree != tree.parent:
    tree = tree.parent
digest = hashlib.sha256()
for p in sorted(tree.rglob("*")):
    if p.is_file() and ".git" not in p.parts:
        digest.update(str(p.relative_to(tree)).encode() + b"\0" + p.read_bytes())
baseline = digest.hexdigest() in conf["baselines"]
mode = conf["mode"]
pattern = args[args.index("-run") + 1] if "-run" in args else ""
pkgs = [a for a in args[1:] if a.startswith("./")]
names, dirs = [], []
for pkg in pkgs or ["./"]:
    rel = pkg.rstrip("/").removesuffix("/...").removesuffix("...")
    d = (cwd / rel).resolve()
    dirs.append(d)
    files = d.rglob("*_test.go") if pkg.endswith("...") else d.glob("*_test.go")
    for f in sorted(files):
        for m in re.finditer(r"(?m)^func (Test[A-Za-z0-9_]*)\(", f.read_text(errors="replace")):
            if m.group(1) != "%s" and re.search(pattern, m.group(1)):
                names.append(m.group(1))
with open(conf["trace"], "a") as t:
    t.write(json.dumps({"baseline": baseline, "args": args}) + "\n")
summary = ["%s/" + str(d.relative_to(tree)) if d != tree else "%s" for d in dirs]
if baseline and mode != "red":
    if mode == "chatty":
        print("\n".join(conf["noise"]))
    for n in names:
        print("=== RUN   " + n); print("--- PASS: " + n + " (0.00s)")
    print("PASS")
    for s in summary:
        print("ok  \t" + s + "\t0.010s")
    sys.exit(0)
if mode == "nopass":
    print("\n".join(conf["noise"]))
    for s in summary:
        print("ok  \t" + s + "\t0.010s")
    sys.exit(0)
print("=== RUN   %s")
print("\n".join(conf["noise"]))
if mode in ("witness", "chatty", "infra") and not baseline:
    for n in names:
        print("--- FAIL: " + n + " (0.00s)")
    print("\n".join(conf["witness_extra"]))
if mode == "infra" and not baseline:
    print("panic: test timed out after 600s")
    print("\n".join(conf["frames"]).replace("{tree}", str(tree)))
print("--- FAIL: %s (0.00s)")
if mode == "build" and not baseline:
    print(conf["build"])
    for s in summary:
        print("FAIL\t" + s + " [build failed]")
if mode == "sql" and not baseline:
    print("    harness_test.go:1: SQLSTATE 42P01 " + conf["canary"])
print("FAIL")
for s in summary:
    print("FAIL\t" + s + "\t0.010s")
sys.exit(1)
''' % (DECOY, MODULE, MODULE, DECOY, DECOY)


def noise(base):
    """Canary-laden lines in every shape go test output takes, none of which
    is an infrastructure signature a driver stops on before printing."""
    enc = canary_encodings(base)
    lines = [f"    harness_test.go:{i + 1}: got {e} want x" for i, e in enumerate(enc)]
    lines += [f"    {base}_test.go:9: {base}",
              f"    --- FAIL: {DECOY}/{base} (0.00s)",
              f"--- FAIL: Test{base} (0.00s)",
              f"FAIL step={base}: {base}",
              f"{base}.go:3:1: undefined: {base}",
              f"FAIL\t{base}\t0.010s",
              f"ok  \t{MODULE}/{base}\t0.010s",
              f"\t{base} (1s)"]
    return lines


def frames(base):
    """A goroutine dump with the canary in the header, the arguments, a
    function and file name, a forged path spelling and a line past the end;
    one genuine frame ({tree} is the tree the stub runs in)."""
    return [f"goroutine 7 [{base}]:",
            f"{MODULE}/internal/meshgate.(*PG).Settle(0x1, {{0x{binascii.hexlify(base.encode()).decode()}}})",
            "\t{tree}/internal/meshgate/pgstore.go:122 +0x1f",
            f"{MODULE}/internal/meshgate.{base}(...)",
            "\t{tree}/internal/meshgate/pgstore.go:2",
            f"{MODULE}/internal/{base}.F()",
            f"\t{{tree}}/internal/meshgate/{base}.go:1",
            "github.com/jackc/pgx/v5/pgxpool.(*Pool).Acquire(0x1)",
            f"\t/go/pkg/mod/github.com/jackc/pgx/v5@v5.7.5/pgxpool/{base}.go:9 +0x1",
            f"{MODULE}/internal/meshgate.(*PG).Settle(...)",
            f"\t{{tree}}/internal/meshgate/pgstore.go:{int(binascii.hexlify(base.encode()[:4]), 16)}",
            f"created by {base} in goroutine 1"]


def tree_digest(tree):
    digest = hashlib.sha256()
    for p in sorted(tree.rglob("*")):
        if p.is_file() and ".git" not in p.parts:
            digest.update(str(p.relative_to(tree)).encode() + b"\0" + p.read_bytes())
    return digest.hexdigest()


def run_driver(driver, mode, cat_filter=False, guard=None):
    """Runs scripts/check-DRIVER-mutations.sh on a copy of the tree with go
    stubbed; returns (stdout+stderr, trace, canary base)."""
    base = "kc" + secrets.token_hex(8)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        root = tmp / "repo"
        (root / "scripts").mkdir(parents=True)
        shutil.copy2(ROOT / "go.mod", root / "go.mod")
        shutil.copytree(ROOT / "scripts/lib", root / "scripts/lib")
        driver_file = SCRIPT_FILE.get(driver, f"check-{driver}-mutations.sh")
        for name in SCRIPTS + (driver_file,):
            shutil.copy2(ROOT / "scripts" / name, root / "scripts" / name)
        dirs, _, total, trim = DRIVERS.get(driver, (("internal/api", "cmd/keep-server/app"), (), 1, False))
        script = root / "scripts" / driver_file
        if trim:
            script.write_text(trim_inventory(script.read_text()))
        for d in dirs:
            shutil.copytree(ROOT / d, root / d, ignore=shutil.ignore_patterns("node_modules"))
            pkg = (root / d).glob("*.go")
            package = next((l.split()[1] for p in sorted(pkg) if not p.name.endswith("_test.go")
                            for l in p.read_text().splitlines() if l.startswith("package ")), None)
            if package is None:
                package = next(l.split()[1] for p in sorted((root / d).glob("*_test.go"))
                               for l in p.read_text().splitlines() if l.startswith("package "))
            (root / d / "zz_harness_test.go").write_text(
                f"package {package}\n\nimport \"testing\"\n\nfunc {DECOY}(t *testing.T) {{}}\n")
        if cat_filter:
            (root / "scripts/test-result-names.py").write_text(
                "import sys\nsys.stdout.write(sys.stdin.read())\n")
        if guard == "stub":
            (root / "scripts/check-resolve-callers.sh").write_text(
                "#!/bin/sh\ncat <<'EOF'\n" + "\n".join(noise(base)) +
                f"\nFORBIDDEN ./{base}.go:1: {base}\nFORBIDDEN ./internal/api/mesh.go:1: {base}\nEOF\nexit 1\n")
        elif guard == "real":
            enc = " ".join(canary_encodings(base))
            (root / "internal/api/zz_canary.go").write_text(
                f"package api\n\nvar _ = meshVault{{}}.ResolveSecret // {enc}\n")
        baselines = [tree_digest(root)]
        if driver == "discovery":
            inst = tmp / "instrumented"
            shutil.copytree(root, inst)
            subprocess.run(["python3", str(inst / "scripts/instrument-discovery-wipes.py"), str(inst)], check=True)
            baselines.append(tree_digest(inst))
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "go"
        stub.write_text(STUB)
        stub.chmod(0o755)
        trace = tmp / "trace"
        conf = tmp / "conf.json"
        conf.write_text(json.dumps({
            "mode": mode, "baselines": baselines, "trace": str(trace), "canary": base,
            "noise": noise(base), "witness_extra": WITNESS_EXTRA.get(driver, []), "frames": frames(base),
            "build": f"{dirs[0]}/{base}.go:3:1: undefined: {base}\n{dirs[0]}/zz_harness_test.go:3:1: undefined: {base}",
        }))
        scratch = tmp / "scratch"
        scratch.mkdir()
        env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp), "TMPDIR": str(scratch),
               "HARNESS_CONF": str(conf), "KEEP_DATABASE_URL": "harness-no-database",
               "MUTATION_SHARD_INDEX": "1", "MUTATION_SHARD_TOTAL": str(total)}
        run = subprocess.run(["sh", str(script)], cwd=root, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        out = run.stdout.decode("utf-8", errors="replace")
        calls = [json.loads(l) for l in trace.read_text().splitlines()] if trace.exists() else []
        return out, calls, base


class DriverOutputLeak(unittest.TestCase):
    maxDiff = None

    def check(self, driver, mode, **kw):
        out, calls, base = run_driver(driver, mode, **kw)
        self.assertEqual(leaked(out, base), [], f"{driver}/{mode}: canary in driver output:\n{out[-4000:]}")
        return out, calls

    def test_go_test_drivers(self):
        for driver, (_, modes, _, _) in DRIVERS.items():
            named = mutants = False
            for mode in modes:
                with self.subTest(driver=driver, mode=mode):
                    out, calls = self.check(driver, mode)
                    self.assertTrue(calls, f"{driver}/{mode}: go test never ran:\n{out[-2000:]}")
                    mutants = mutants or any(not c["baseline"] for c in calls)
                    named = named or f"--- FAIL: {DECOY} at " in out
                    for want in EXPECT.get((driver, mode), []):
                        self.assertIn(want, out, f"{driver}/{mode}: positive control missing")
            with self.subTest(driver=driver, control="named"):
                self.assertTrue(mutants, f"{driver}: no mutant reached go test (sources not copied?)")
                self.assertTrue(named, f"{driver}: the declared decoy test is never named")

    def test_resolve_callers_driver(self):
        out, _ = self.check("resolve-callers", "red", guard="stub")
        self.assertIn("FORBIDDEN ./internal/api/mesh.go:1", out)
        out, _ = self.check("resolve-callers", "red", guard="real")
        self.assertIn("FORBIDDEN ./internal/api/zz_canary.go:3", out)

    def test_detector_sees_a_raw_print(self):
        """Control: with the filter replaced by `cat`, each driver leaks."""
        for driver, (_, modes, _, _) in DRIVERS.items():
            with self.subTest(driver=driver, mode=modes[0]):
                out, _, base = run_driver(driver, modes[0], cat_filter=True)
                self.assertNotEqual(leaked(out, base), [], f"{driver}/{modes[0]}: control did not leak:\n{out[-2000:]}")
        for guard in ("stub", "real"):
            with self.subTest(driver="resolve-callers", guard=guard):
                out, _, base = run_driver("resolve-callers", "red", cat_filter=True, guard=guard)
                self.assertNotEqual(leaked(out, base), [])


def names(*args, stdin):
    run = subprocess.run(["python3", "-I", str(ROOT / "scripts/test-result-names.py"), *args],
                         input="\n".join(stdin).encode(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         timeout=120, check=True)
    return run.stdout.decode()


class Filter(unittest.TestCase):
    """The filter run on this repository with crafted logs."""
    PKG, FILE = "internal/meshgate", "internal/meshgate/pgstore.go"

    def test_spelling_order_and_repetition_carry_nothing(self):
        test = "TestWorkspacesOfTxListsExtensionsOnly"
        canonical = [f"--- FAIL: {test} (0.00s)", f"FAIL\t{MODULE}/{self.PKG}\t0.1s",
                     f"{self.FILE}:3:1: undefined: x", f"ok  \t{MODULE}/{self.PKG}\t0.1s"]
        want = names(str(ROOT), stdin=canonical)
        self.assertIn(f"--- FAIL: {test} at internal/meshgate/pgstore_test.go:", want)
        self.assertIn(f"FAIL {MODULE}/{self.PKG}\nok {MODULE}/{self.PKG}\n", want)
        self.assertIn(f"build failed at {self.FILE}:3\n", want)
        spelled = [f"    --- FAIL: {test}/kc0123 (0.00s)",
                   f"FAIL\t{MODULE}/internal/.//./meshgate\t0.1s", f"FAIL\t{MODULE}/internal//meshgate",
                   f"./{self.FILE}:3:9: x", f"internal/./meshgate//pgstore.go:3: y",
                   f"ok  \t{MODULE}/{self.PKG}\t9.9s"]
        variants = [canonical + spelled, list(reversed(canonical + spelled)), (canonical + spelled) * 7]
        for log in variants:
            got = names(str(ROOT), stdin=log)
            self.assertEqual(got.splitlines()[:-1], want.splitlines()[:-1], log)
        # Spellings the tree does not vouch for are counted, never printed.
        bad = [f"FAIL\t{MODULE}/INTERNAL/Meshgate", f"FAIL\t{MODULE}/internal/../internal/meshgate",
               f"FAIL\t{MODULE}/.git", "INTERNAL/meshgate/pgstore.go:3: x", f"{self.FILE}:9999: x",
               f"{self.FILE}:0: x", "/etc/hosts.go:1: x"]
        self.assertEqual(names(str(ROOT), stdin=bad).splitlines(),
                         ["result lines not printed: 7; panics: 0; build failures: 0"])

    def test_a_name_declared_twice_lists_every_declaration(self):
        # The verdict line cannot tell which declaration failed (another
        # package, another build tag), so none is picked: all are listed.
        test = "TestAncestorACLGrantingWriteRefused"
        out = names(str(ROOT), stdin=[f"--- FAIL: {test} (0.00s)"])
        self.assertRegex(out.splitlines()[0], rf"^--- FAIL: {test} at internal/targets/acl_darwin_test\.go:[0-9]+, "
                                              r"internal/targets/acl_linux_test\.go:[0-9]+$")
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(6):
                (Path(tmp) / f"p{i}").mkdir()
                (Path(tmp) / f"p{i}/x_test.go").write_text("package p\n\nfunc TestSame(t *testing.T) {}\n")
            out = names(tmp, stdin=["--- SKIP: TestSame (0.00s)"])
            self.assertEqual(out.splitlines()[0], "--- SKIP: TestSame at p0/x_test.go:3, p1/x_test.go:3, "
                                                  "p2/x_test.go:3, p3/x_test.go:3 and 2 more")

    def test_counters_are_capped(self):
        out = names(str(ROOT), stdin=["FAIL x"] * 4242 + ["panic: x"] * 39 + ["[build failed]"] * 40)
        self.assertEqual(out, "result lines not printed: 40+; panics: 39; build failures: 40+\n")
        out = names("--resolve-callers", str(ROOT), stdin=["FORBIDDEN ./x.go:1: y"] * 41)
        self.assertEqual(out, "guard lines not printed: 40+\n")
        # Each kind of line is capped too: a long run of distinct packages
        # prints the first 40 in sorted order, never the whole run.
        pkgs = sorted({str(p.parent.relative_to(ROOT)) for p in ROOT.glob("internal/**/*.go")})
        self.assertGreater(len(pkgs), 45)
        out = names(str(ROOT), stdin=[f"ok  \t{MODULE}/{p}\t0.1s" for p in reversed(pkgs)])
        self.assertEqual([x for x in out.splitlines() if x.startswith("ok ")],
                         [f"ok {MODULE}/{p}" for p in pkgs[:40]])

    def test_resolve_callers_lines_are_rebuilt(self):
        out = names("--resolve-callers", str(ROOT), stdin=[
            "FORBIDDEN ./internal/.//api/mesh.go:1: kc0123", "FORBIDDEN ./internal/api/mesh.go:1",
            "HANDLER ./internal/api/mesh.go", "FORBIDDEN ./internal/api/MESH.go:1: x",
            "FORBIDDEN ./internal/api/mesh.go:99999: x"])
        self.assertEqual(out.splitlines(), ["FORBIDDEN ./internal/api/mesh.go:1", "HANDLER ./internal/api/mesh.go",
                                            "guard lines not printed: 2"])

    def test_goroutine_dump(self):
        base = "kc" + secrets.token_hex(8)
        dump = [line.replace("{tree}", str(ROOT)) for line in frames(base)]
        out = names("--goroutines", str(ROOT), stdin=dump)
        self.assertEqual(leaked(out, base), [], out)
        self.assertEqual(out.splitlines(), [
            "goroutine", f"  {MODULE}/internal/meshgate.(*PG).Settle(...)", "  \tinternal/meshgate/pgstore.go:122",
            "goroutines: 1; frames not printed: 4"])

    def test_pgx_frame_needs_the_on_disk_spelling(self):
        # A pgx frame is printed only for a file in the module cache spelled
        # segment by segment as on disk: a case-insensitive file system
        # would otherwise accept, and print, another spelling of the path.
        with tempfile.TemporaryDirectory() as tmp:
            mod = Path(tmp) / "pkg/mod/github.com/jackc/pgx/v5@v5.7.5/pgxpool"
            mod.mkdir(parents=True)
            (mod / "pool.go").write_text("package pgxpool\n\ntype Pool struct{}\n\n"
                                         "func (p *Pool) Acquire() {}\n")
            (mod / "dir.go").mkdir()
            frame = "github.com/jackc/pgx/v5/pgxpool.(*Pool).Acquire(0x1)"
            for spelling, shown in (("pgxpool/pool.go", True), ("PGXPOOL/pool.go", False),
                                    ("pgxpool/Pool.go", False), ("pgxpool/dir.go", False)):
                with self.subTest(spelling=spelling):
                    path = f"{tmp}/pkg/mod/github.com/jackc/pgx/v5@v5.7.5/{spelling}"
                    out = names("--goroutines", str(ROOT), stdin=["goroutine 7 [select]:", frame, f"\t{path}:5 +0x1"])
                    self.assertEqual(f"v5@v5.7.5/{spelling}:5" in out, shown, out)
                    self.assertEqual("frames not printed: 0" in out, shown, out)

    def test_root_given_through_a_symlink(self):
        # go prints the resolved path; ROOT may be handed over through a
        # symlink. Both spellings name the frame, nothing else does.
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "tree"
            link.symlink_to(ROOT.resolve(), target_is_directory=True)
            for spelling in (ROOT.resolve(), link):
                with self.subTest(spelling=str(spelling)):
                    dump = [line.replace("{tree}", str(spelling)) for line in frames("kc" + secrets.token_hex(8))]
                    out = names("--goroutines", str(link), stdin=dump)
                    self.assertIn("  \tinternal/meshgate/pgstore.go:122", out.splitlines(), out)


class CanaryEncodings(unittest.TestCase):
    def test_six_encodings_found_in_their_contexts(self):
        base = "kc" + secrets.token_hex(8)
        self.assertEqual(len(canary_encodings(base)), 10)
        for prefix in (b"", b"u", b"us", b"user:"):
            for enc in (base64.standard_b64encode, base64.urlsafe_b64encode):
                text = enc(prefix + base.encode() + b"!").decode()
                self.assertTrue(leaked(text, base), (prefix, text))
        for text in (base, base.upper(), binascii.hexlify(base.encode()).decode(), base[::-1],
                     urllib.parse.quote_plus(base)):
            self.assertTrue(leaked("x " + text + " y", base))
        self.assertFalse(leaked("nothing here", base))


if __name__ == "__main__":
    unittest.main(verbosity=2)
