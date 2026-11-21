#!/usr/bin/env python3
"""Run security mutation drivers against controlled process and test outcomes."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import unittest
import urllib.parse

ROOT = Path(__file__).resolve().parent.parent
SUITES = ("identity-attack", "tenancy")


class ShardDrivers(unittest.TestCase):
    def run_driver(self, suite, index, mode="good"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            sources = ({"internal/identity/" + name for name in
                        ("token.go", "repo.go", "middleware.go", "rights.go", "principal.go")} |
                       {"internal/obs/obs.go", "internal/testutil/canary/canary.go",
                        "test/security/identity_attack_test.go"}
                       if suite == "identity-attack" else
                       set(re.findall(r"^(?:MUTATION_OCCURRENCE=\d+ )?mutate \S+ (\S+)",
                           (ROOT / "scripts/check-tenancy-mutations.sh").read_text(), re.M)))
            for name in sources | {"go.mod", "scripts/mutation-helpers.sh", "scripts/lib/mutation_edit.py", "scripts/lib/mutation_snapshot.py",
                                    "scripts/temp-workspace.sh", "scripts/lib/gocache.sh",
                                    f"scripts/check-{suite}-mutations.sh"}:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            script = root / f"scripts/check-{suite}-mutations.sh"
            text = script.read_text()
            # Only instrument the process boundary; execute the actual shell driver.
            text = text.replace("set -eu\n", '''set -eu
go() {
    DRIVER_NAME=${name:-} DRIVER_WANT=${want:-} DRIVER_NEEDLE=${needle:-} DRIVER_EXPECT=${expect:-clean} DRIVER_SUITE=%s command go "$@"
}
''' % suite, 1)
            script.write_text(text)
            sources = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for d in ("internal", "test") for p in (root / d).rglob("*")
                       if p.suffix in (".go", ".sql")}
            stub = Path(tmp) / "go"
            trace = Path(tmp) / "trace"
            stub.write_text('''#!/usr/bin/env python3
import hashlib, json, os, pathlib, sys
''' + f"sources = {sources!r}\nmode = {mode!r}\ntrace = {str(trace)!r}\n" + r'''
baseline = all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() == h for p, h in sources.items())
name = os.environ['DRIVER_NAME']
want = os.environ['DRIVER_WANT']
with open(trace, 'a') as out:
    out.write(json.dumps(dict(baseline=baseline, name=name, want=want, args=sys.argv[1:], cache=os.environ.get('GOCACHE'))) + '\n')
if baseline:
    baseline_packages = sys.argv[sys.argv.index('-v') + 1:]
    expected_packages = ('./internal/tenancy/', './internal/catalog/')
    valid_tenancy_invocations = [[package] for package in expected_packages] + [list(expected_packages)]
    if os.environ['DRIVER_SUITE'] == 'tenancy' and baseline_packages not in valid_tenancy_invocations:
        print('FAIL fixture: unexpected tenancy baseline packages ' + repr(baseline_packages))
        sys.exit(2)
    if mode == 'baseline-red':
        print('--- FAIL: TestBaseline (0.00s)'); sys.exit(1)
    if mode == 'baseline-skip': print('--- SKIP: TestUnavailable (0.00s)')
    empty_package = {'baseline-partial-empty-tenancy': './internal/tenancy/',
                     'baseline-partial-empty-catalog': './internal/catalog/'}.get(mode)
    green_packages = [package for package in baseline_packages if package != empty_package]
    if mode != 'baseline-empty' and green_packages:
        print('--- PASS: TestIdentity_Baseline (0.00s)')
    for package in ['test/security', 'internal/tenancy', 'internal/catalog']:
        print('ok\tgithub.com/entire-vc/evc-keep/' + package + '\t0.001s')
    sys.exit(0)
if mode == 'green-mutant': sys.exit(0)
names = want.split() or ['TestUnrelated']
if mode == 'wrong-test': names = ['TestUnrelated']
if mode == 'missing-witness': names = names[:1]
for test in names: print('--- FAIL: ' + test + ' (0.00s)')
needle = os.environ['DRIVER_NEEDLE']
if name != 'diagnostics-are-masked': print('    fixture_test.go:1: ' + needle)
if os.environ['DRIVER_EXPECT'] == 'leak' or name == 'diagnostics-are-masked':
    print('    fixture_test.go:1: ' + 'A' * 52)
if mode == 'skip': print('--- SKIP: TestUnavailable (0.00s)')
if mode == 'build': print('FAIL\tother/package [build failed]')
if mode == 'setup': print('FAIL\tother/package [setup failed]')
if mode == 'timeout': print('panic: test timed out after 1s')
if mode == 'database': print('database operation deadline exceeded')
if mode == 'sql': print('SQLSTATE 42P01')
if mode != 'truncated':
    omitted = {'partial-summary-tenancy': 'internal/tenancy',
               'partial-summary-catalog': 'internal/catalog'}.get(mode)
    green = {'mixed-tenancy-ok': 'internal/tenancy',
             'mixed-catalog-ok': 'internal/catalog'}.get(mode)
    for package in ['test/security', 'internal/tenancy', 'internal/catalog']:
        if package == omitted: continue
        result = 'ok' if package == green else 'FAIL'
        print(result + '\tgithub.com/entire-vc/evc-keep/' + package + '\t0.001s')
sys.exit(143 if mode == 'signal' else 1)
''')
            stub.chmod(0o755)
            run_env = {"PATH": tmp + os.pathsep + os.environ["PATH"],
                       "KEEP_DATABASE_URL": "disposable-driver-control", "TMPDIR": tmp,
                       "MUTATION_SHARD_INDEX": str(index), "MUTATION_SHARD_TOTAL": "4"}
            run = subprocess.run(["sh", str(script)], cwd=root, env=run_env,
                                 capture_output=True, text=True, timeout=45)
            calls = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
            return run, calls

    def test_all_shards_have_baseline_and_expected_reds(self):
        for suite in SUITES:
            selected = set()
            for index in range(1, 5):
                with self.subTest(suite=suite, shard=index):
                    run, calls = self.run_driver(suite, index)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    expected_baselines = 2 if suite == 'tenancy' else 1
                    self.assertEqual(sum(call['baseline'] for call in calls), expected_baselines, run.stdout)
                    if suite == 'tenancy':
                        baseline_calls = [call for call in calls if call['baseline']]
                        self.assertTrue(all(call['args'][call['args'].index('-v') + 1:] in
                                            [['./internal/tenancy/'], ['./internal/catalog/']]
                                            for call in baseline_calls))
                        baseline_packages = {call['args'][-1] for call in baseline_calls}
                        self.assertEqual(baseline_packages, {'./internal/tenancy/', './internal/catalog/'})
                    mutants = [call for call in calls if not call['baseline']]
                    self.assertTrue(mutants)
                    self.assertTrue(all(call['want'] for call in mutants), run.stdout)
                    names = {call['name'] for call in mutants}
                    self.assertFalse(selected & names)
                    selected.update(names)
                    self.assertIn(f"shard {index}/4:", run.stdout)
                    self.assertIn("baseline:", run.stdout)
                    self.assertTrue(all('-v' in call['args'] for call in calls))
                    caches = {call['cache'] for call in calls}
                    self.assertEqual(len(caches), 1)
                    cache = next(iter(caches))
                    self.assertIn("keep-gocache.", cache)
                    self.assertFalse(Path(cache).exists())
            count = len(re.findall(r'^(?:MUTATION_OCCURRENCE2?=\d+ )*(?:mutate|begin) ',
                                  (ROOT / f'scripts/check-{suite}-mutations.sh').read_text(), re.M))
            self.assertEqual(len(selected), count)

    def test_baseline_failures_rejected_on_each_shard(self):
        for suite in SUITES:
            for index in range(1, 5):
                modes = ('baseline-red', 'baseline-skip', 'baseline-empty')
                if suite == 'tenancy':
                    modes += ('baseline-partial-empty-tenancy', 'baseline-partial-empty-catalog')
                for mode in modes:
                    with self.subTest(suite=suite, shard=index, mode=mode):
                        run, _ = self.run_driver(suite, index, mode)
                        self.assertNotEqual(run.returncode, 0, run.stdout)
                        self.assertIn('FAIL baseline:', run.stdout)

    def test_invalid_or_unrelated_reds_rejected_on_each_shard(self):
        for suite in SUITES:
            for index in range(1, 5):
                for mode in ('skip', 'build', 'setup', 'timeout', 'database', 'sql', 'signal',
                             'truncated', 'wrong-test', 'green-mutant'):
                    with self.subTest(suite=suite, shard=index, mode=mode):
                        run, _ = self.run_driver(suite, index, mode)
                        self.assertNotEqual(run.returncode, 0, run.stdout)

    def test_both_context_gate_witnesses_required(self):
        run, _ = self.run_driver('tenancy', 4, 'missing-witness')
        self.assertNotEqual(run.returncode, 0, run.stdout)
        self.assertIn('FAIL authz-context-gate-off:', run.stdout)

    def test_tenancy_mutant_requires_completion_of_both_packages_on_all_shards(self):
        for index in range(1, 5):
            for mode in ('partial-summary-tenancy', 'partial-summary-catalog'):
                with self.subTest(shard=index, mode=mode):
                    run, _ = self.run_driver('tenancy', index, mode)
                    self.assertNotEqual(run.returncode, 0, run.stdout)
                    self.assertIn('invalid test run', run.stdout)

    def test_tenancy_mutant_accepts_mixed_completed_packages_on_all_shards(self):
        for index in range(1, 5):
            for mode in ('mixed-tenancy-ok', 'mixed-catalog-ok'):
                with self.subTest(shard=index, mode=mode):
                    run, _ = self.run_driver('tenancy', index, mode)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


class MeshUITemplateMutants(unittest.TestCase):
    """Apply the real driver to a minimal shared-import fixture, without Go or DB."""
    def apply(self, missing_anchor=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'
            output = Path(tmp) / 'applied'
            output.mkdir()
            sources = ('internal/api/mesh_ui.go', 'internal/api/mesh_ui_rotation_pages.go')
            for name in ('go.mod', 'scripts/mutation-helpers.sh',
                         'scripts/lib/mutation_edit.py', 'scripts/lib/mutation_snapshot.py',
                         'scripts/lib/gocache.sh', 'scripts/temp-workspace.sh'):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            for name in sources:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('package api\nimport (\n\t"html/template"\n)\n')
            if missing_anchor:
                companion = root / sources[1]
                companion.write_text(companion.read_text().replace('"html/template"', '"text/template"'))
            script = (ROOT / 'scripts/check-mesh-ui-mutations.sh').read_text()
            prefix = script.split('# A red baseline', 1)[0]
            # Observe the real driver's apply-only result before scratch cleanup.
            observer = '''
mutation_applied() {
    mkdir "$PROBE_OUTPUT/$name"
    cp "$work/tree/internal/api/mesh_ui.go" "$PROBE_OUTPUT/$name/main.go"
    cp "$work/tree/internal/api/mesh_ui_rotation_pages.go" "$PROBE_OUTPUT/$name/rotation.go"
    return 0
}
'''
            declarations = '\n'.join(line for line in script.splitlines()
                                     if re.match(r'^[A-Z]=internal/api/', line))
            cases = '\n'.join(line for line in script.splitlines()
                              if re.match(r'^mutate (?:names-unescaped|secret-names-unescaped) ', line))
            probe = root / 'scripts/probe.sh'
            probe.write_text(prefix + observer + declarations + '\n' + cases + '\nexit "$fail"\n')
            run = subprocess.run(['sh', str(probe)], capture_output=True, text=True, timeout=30,
                                 env=dict(os.environ, MUTATION_APPLY_ONLY='1', PROBE_OUTPUT=str(output)))
            applied = {p.name: {f.name: f.read_text() for f in p.iterdir()} for p in output.iterdir()}
            return run, applied

    def test_shared_template_clones_switch_imports_together(self):
        run, applied = self.apply()
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(set(applied), {'names-unescaped', 'secret-names-unescaped'})
        for name, files in applied.items():
            for path, source in files.items():
                with self.subTest(mutant=name, file=path):
                    self.assertTrue('"text/template"' in source, 'text/template import missing')
                    self.assertFalse('"html/template"' in source, 'html/template import survived')

    def test_missing_companion_anchor_refuses_the_mutant(self):
        run, applied = self.apply(missing_anchor=True)
        self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(applied, {})
        self.assertIn('mutation did not apply', run.stdout)


class RotationDriver(unittest.TestCase):
    """Exercise the real shell driver; only the external go process is stubbed.

    A tiny inventory replaces the production inventory in a private copy. The
    selector, editor, refusal guards, classifier and baseline remain unchanged.
    These checks cover the driver, not the PostgreSQL-backed rotation product.
    """

    def run_driver(self, source="pre a.b a.b post\nnext a.b end\n", anchor="a.b",
                   occurrence="2", apply_only=False, wrong_witness=False, canary=""):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            for name in ("go.mod", "scripts/check-rotation-mutations.sh",
                         "scripts/mutation-helpers.sh", "scripts/lib/mutation_edit.py", "scripts/lib/mutation_snapshot.py",
                         "scripts/temp-workspace.sh", "scripts/lib/gocache.sh"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            fixture = root / "internal/rotation/fixture.go"
            fixture.parent.mkdir(parents=True)
            fixture.write_text(source)
            # Only these declared test functions may be named in a diagnostic.
            (fixture.parent / "fixture_test.go").write_text(
                "package rotation\n\nimport \"testing\"\n\n"
                "func TestExpected(t *testing.T) {\n}\n\nfunc TestOther(t *testing.T) {\n}\n")
            script = root / "scripts/check-rotation-mutations.sh"
            text = script.read_text()
            start = text.index("# Each mutant switches off")
            end = text.index("# The unmutated tree is green:")
            args = ["probe", "internal/rotation/fixture.go", anchor, "CHANGED", "TestExpected"]
            if occurrence is not None:
                args.append(occurrence)
            script.write_text(text[:start] + "mutate " + " ".join(map(shlex.quote, args)) +
                              "\n\n" + text[end:])
            trace = Path(tmp) / "trace"
            stub = Path(tmp) / "go"
            # Mock: external process boundary. Record the actual snapshot bytes;
            # completed go-test output controls only the driver's classification.
            stub.write_text("#!/usr/bin/env python3\n" +
                            "import json, pathlib, sys\n" +
                            f"original = {source!r}\ntrace = {str(trace)!r}\n" +
                            f"wrong_witness = {wrong_witness!r}\ncanary = {canary!r}\n" + '''
actual = pathlib.Path("internal/rotation/fixture.go").read_text()
with open(trace, "a") as out:
    out.write(json.dumps({"source": actual, "args": sys.argv[1:]}) + "\\n")
if actual == original:
    print("--- PASS: TestBaseline (0.00s)")
    print("ok\\tgithub.com/entire-vc/evc-keep/internal/rotation\\t0.001s")
    sys.exit(0)
witness = "TestOther/subtest" if wrong_witness else "TestExpected/subtest"
if canary:
    # A value can reach go-test output as a subtest name, inside a test
    # message, or as a line shaped like a result record.
    print("        fixture_test.go:9: --- FAIL: " + canary + " (0.00s)")
    print("--- FAIL: " + canary + " (0.00s)")
    print("--- FAIL: Test" + canary + " (0.00s)")
    print("    --- FAIL: TestOther/" + canary + " (0.00s)")
print("    --- FAIL: " + witness + " (0.00s)")
if wrong_witness:
    print("--- FAIL: TestOther (0.00s)")
print("FAIL\\tgithub.com/entire-vc/evc-keep/internal/rotation\\t0.001s")
sys.exit(1)
''')
            stub.chmod(0o755)
            env = {"PATH": tmp + os.pathsep + os.environ["PATH"], "TMPDIR": tmp,
                   "MUTATION_APPLY_ONLY": "1" if apply_only else "0"}
            if not apply_only:
                env["KEEP_DATABASE_URL"] = "disposable-driver-control"
            run = subprocess.run(["sh", str(script)], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=30)
            calls = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
            self.assertEqual(fixture.read_text(), source, "driver changed the original tree")
            return run, calls

    def test_literal_occurrence_changes_only_selected_bytes(self):
        cases = (
            ("pre a.b a.b post\n", "1", "pre CHANGED a.b post\n"),
            ("pre a.b a.b post\n", "2", "pre a.b CHANGED post\n"),
            ("pre a.b post\nnext a.b end\n", "1", "pre CHANGED post\nnext a.b end\n"),
            ("pre a.b post\nnext a.b end\n", "2", "pre a.b post\nnext CHANGED end\n"),
            ("aXb then a.b end\n", None, "aXb then CHANGED end\n"),
        )
        for source, occurrence, expected in cases:
            with self.subTest(source=source, occurrence=occurrence):
                run, calls = self.run_driver(source=source, occurrence=occurrence)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertEqual([call["source"] for call in calls], [expected, source])
                self.assertIn("confirmed on: TestExpected", run.stdout)
                self.assertIn("baseline: tests green on the real code (0 SKIP)", run.stdout)

    def test_refusals_also_hold_in_apply_only_mode(self):
        cases = [("a.b", None, "anchor occurs 3 times, name the occurrence"),
                 ("", "1", "mutation anchor is empty"),
                 ("absent", "1", "mutation did not apply"),
                 ("a.b", "4", "mutation did not apply")]
        cases += [("a.b", value, "occurrence must be a positive number")
                  for value in ("0", "01", "-1", "x", "1.5")]
        for apply_only in (False, True):
            for anchor, occurrence, diagnostic in cases:
                with self.subTest(apply_only=apply_only, anchor=anchor, occurrence=occurrence):
                    run, calls = self.run_driver(anchor=anchor, occurrence=occurrence,
                                                 apply_only=apply_only)
                    self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
                    self.assertIn("FAIL probe: " + diagnostic, run.stdout)
                    self.assertNotIn("probe: applies", run.stdout)
                    # A refusal never starts a mutant's go test. Normal mode
                    # still runs its unchanged positive baseline control.
                    expected = [] if apply_only else ["pre a.b a.b post\nnext a.b end\n"]
                    self.assertEqual([call["source"] for call in calls], expected)

    def test_apply_only_accepts_explicit_and_unique_anchors_without_go(self):
        for source, occurrence in (("a.b a.b\n", "2"), ("one a.b\n", None)):
            with self.subTest(occurrence=occurrence):
                run, calls = self.run_driver(source=source, occurrence=occurrence, apply_only=True)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn("ok   probe: applies", run.stdout)
                self.assertEqual(calls, [])

    def test_wrong_witness_names_only_declared_failing_tests(self):
        run, calls = self.run_driver(wrong_witness=True)
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        self.assertIn("FAIL probe: red, but not on: TestExpected (the wrong test/subtest "
                      "caught it); failed: TestOther\n", run.stdout)
        self.assertNotIn("TestOther/", run.stdout + run.stderr)
        self.assertIn("baseline: tests green on the real code (0 SKIP)", run.stdout)
        self.assertEqual([call["source"] for call in calls],
                         ["pre a.b CHANGED post\nnext a.b end\n", "pre a.b a.b post\nnext a.b end\n"])

    def test_wrong_witness_diagnostic_never_echoes_test_output(self):
        canary = "keepcanary" + secrets.token_hex(16)
        run, _ = self.run_driver(wrong_witness=True, canary=canary)
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        self.assertNotIn(canary, run.stdout + run.stderr)
        self.assertNotIn("TestOther/", run.stdout + run.stderr)
        self.assertIn("FAIL probe: red, but not on: TestExpected (the wrong test/subtest "
                      "caught it); failed: TestOther\n", run.stdout)


MESH_PLUGIN = ROOT / "scripts/check-mesh-plugin-mutations.sh"


class MeshPluginShards(unittest.TestCase):
    """The mesh-plugin driver with go stubbed: baseline green, every mutant red
    unless named as the survivor. Python applies the real mutations."""

    def run_shard(self, index, total=3, survivor="", baseline_red=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            sources = set(re.findall(r"^src=(\S+)", MESH_PLUGIN.read_text(), re.M))
            for name in sources | {"go.mod", "scripts/mutation-helpers.sh", "scripts/lib/mutation_edit.py", "scripts/lib/mutation_snapshot.py", "scripts/temp-workspace.sh",
                                    "scripts/lib/gocache.sh", "scripts/check-mesh-plugin-mutations.sh"}:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            script = root / "scripts/check-mesh-plugin-mutations.sh"
            script.write_text(script.read_text().replace("set -eu\n", '''set -eu
go() {
    DRIVER_NAME=${name:-} command go "$@"
}
''', 1))
            trace = Path(tmp) / "trace"
            stub = Path(tmp) / "go"
            stub.write_text("#!/bin/sh\n"
                            f'echo "${{DRIVER_NAME:-baseline}}" >>"{trace}"\n'
                            'if [ -z "$DRIVER_NAME" ]; then exit ' + ("1" if baseline_red else "0") + "; fi\n"
                            f'[ "$DRIVER_NAME" = "{survivor}" ] && exit 0\n'
                            'echo "--- FAIL: TestStub (0.00s)"; exit 1\n')
            stub.chmod(0o755)
            env = {"PATH": tmp + os.pathsep + os.environ["PATH"], "TMPDIR": tmp,
                   "MUTATION_SHARD_INDEX": str(index), "MUTATION_SHARD_TOTAL": str(total)}
            run = subprocess.run(["sh", str(script)], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=120)
            calls = trace.read_text().split() if trace.exists() else []
            return run, calls

    def test_shards_cover_every_mutant_once_with_a_baseline_each(self):
        names = re.findall(r"^mutate (\S+)", MESH_PLUGIN.read_text(), re.M)
        selected = []
        for index in (1, 2, 3):
            with self.subTest(shard=index):
                run, calls = self.run_shard(index)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertEqual(calls[0], "baseline")
                self.assertEqual(calls.count("baseline"), 1)
                mutants = calls[1:]
                self.assertIn(f"shard {index}/3: {len(mutants)} selected mutants", run.stdout)
                self.assertEqual(mutants, names[index - 1::3])
                selected += mutants
        self.assertEqual(sorted(selected), sorted(names))
        self.assertEqual(len(set(selected)), len(names))

    def test_a_surviving_mutant_fails_only_its_shard(self):
        names = re.findall(r"^mutate (\S+)", MESH_PLUGIN.read_text(), re.M)
        survivor = names[len(names) // 2]
        owner = len(names) // 2 % 3 + 1
        for index in (1, 2, 3):
            with self.subTest(shard=index):
                run, _ = self.run_shard(index, survivor=survivor)
                if index == owner:
                    self.assertNotEqual(run.returncode, 0, run.stdout)
                    self.assertIn(f"FAIL {survivor}: tests stayed green", run.stdout)
                else:
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_red_baseline_and_bad_shard_fail(self):
        for index in (1, 2, 3):
            with self.subTest(shard=index):
                run, calls = self.run_shard(index, baseline_red=True)
                self.assertNotEqual(run.returncode, 0, run.stdout)
                self.assertIn("FAIL baseline is red", run.stdout)
                self.assertEqual(calls, ["baseline"])
        for index, total in ((4, 3), (0, 3), (1, 0), ("x", 3)):
            with self.subTest(index=index, total=total):
                run, calls = self.run_shard(index, total)
                self.assertNotEqual(run.returncode, 0, run.stdout)
                self.assertIn("FAIL invalid mutation shard", run.stdout)
                self.assertEqual(calls, [])


def canary_encodings(value):
    """The six encodings internal/testutil/canary checks: raw, hex, percent,
    reversed, and every base64 alignment (standard and URL-safe)."""
    raw = value.encode()
    out = [value, raw.hex(), urllib.parse.quote_plus(value), value[::-1]]
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        for offset in range(3):
            encoded = encode(b"\0" * offset + raw).decode().rstrip("=")
            first, end = (offset + 2) // 3, (offset + len(raw)) // 3
            if end > first:
                out.append(encoded[4 * first:4 * end])
    return out


def new_canary():
    return "kc" + os.urandom(12).hex()


class HelperDiagnosticsCanary(unittest.TestCase):
    """Text a test prints must never reach a mutation driver's stdout or
    stderr: only script literals, mutant names, declared test names, package
    paths and counts. Only the external go process is stubbed; the shell
    helpers and the rotation driver run unchanged."""

    def assert_no_canary(self, base, text):
        for encoded in canary_encodings(base):
            self.assertNotIn(encoded.lower(), text.lower(), "canary encoding reached the log")

    def run_rotation(self, lines):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            for name in ("go.mod", "scripts/check-rotation-mutations.sh",
                         "scripts/mutation-helpers.sh", "scripts/lib/mutation_edit.py", "scripts/lib/mutation_snapshot.py",
                         "scripts/temp-workspace.sh", "scripts/lib/gocache.sh"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            source = "package rotation\n\nconst probe = 1\n"
            fixture = root / "internal/rotation/fixture.go"
            fixture.parent.mkdir(parents=True)
            fixture.write_text(source)
            script = root / "scripts/check-rotation-mutations.sh"
            text = script.read_text()
            start = text.index("# Each mutant switches off")
            end = text.index("# The unmutated tree is green:")
            script.write_text(text[:start] + "mutate probe internal/rotation/fixture.go "
                              "'probe = 1' 'probe = 2' TestExpected\n\n" + text[end:])
            stub = Path(tmp) / "go"
            # Mock: external process boundary. The mutant's go test prints the
            # given lines, then a completed red package summary.
            stub.write_text("#!/usr/bin/env python3\nimport pathlib, sys\n" +
                            f"original = {source!r}\nlines = {lines!r}\n" + r"""
if pathlib.Path("internal/rotation/fixture.go").read_text() == original:
    print("--- PASS: TestBaseline (0.00s)")
    print("ok\tgithub.com/entire-vc/evc-keep/internal/rotation\t0.001s")
    sys.exit(0)
print("--- FAIL: TestExpected (0.00s)")
for line in lines:
    print(line)
print("FAIL\tgithub.com/entire-vc/evc-keep/internal/rotation\t0.001s")
sys.exit(1)
""")
            stub.chmod(0o755)
            env = {"PATH": tmp + os.pathsep + os.environ["PATH"], "TMPDIR": tmp,
                   "KEEP_DATABASE_URL": "disposable-driver-control"}
            return subprocess.run(["sh", str(script)], cwd=root, env=env,
                                  capture_output=True, text=True, timeout=30)

    def test_infrastructure_stage_prints_closed_vocabulary_only(self):
        base = new_canary()
        value = base + "-v1-secret"
        run = self.run_rotation([
            "    fixture_test.go:9: database operation deadline exceeded",
            "    fixture_test.go:9: test database refused the connection (" + value + ")",
            "    fixture_test.go:9: test database not ready after 3 attempts in 1s (" + value + ")",
            "test database not ready after 3 attempts in 1s (" + base + ")",
            "    fixture_test.go:9: test database refused the connection (network unreachable or refused)",
            "    fixture_test.go:9: test database not ready after 15 attempts in 1m30s "
            "(database operation deadline exceeded)",
        ])
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, 1, out)
        self.assert_no_canary(base, out)
        self.assertIn("FAIL probe: invalid test run", run.stdout)
        self.assertIn("FAIL mutation infrastructure detail: database_deadline count=2\n", run.stdout)
        # Positive control: a pgscratch line of the exact shape is still named.
        self.assertIn("FAIL mutation infrastructure stage: refused reason=network count=1\n", run.stdout)
        self.assertIn("FAIL mutation infrastructure stage: not_ready reason=deadline count=1\n", run.stdout)
        self.assertNotIn("reason=unclassified", run.stdout)

    def test_every_stage_reason_pair_is_counted(self):
        reasons = {"network": "network unreachable or refused",
                   "deadline": "database operation deadline exceeded",
                   "sqlstate": "SQLSTATE 57P03", "unclassified": "unclassified"}
        for key, reason in reasons.items():
            with self.subTest(reason=key):
                run = self.run_rotation([
                    "    x_test.go:9: test database refused the connection (" + reason + ")",
                    "    x_test.go:9: test database refused the connection (" + reason + ")",
                    "    x_test.go:9: test database not ready after 2 attempts in 500ms (" + reason + ")",
                    "connection failed (unclassified)",
                ])
                self.assertIn(f"stage: refused reason={key} count=2\n", run.stdout)
                self.assertIn(f"stage: not_ready reason={key} count=1\n", run.stdout)

    def test_stage_lines_outside_the_exact_shape_count_nowhere(self):
        run = self.run_rotation([
            "database operation deadline exceeded",
            "test database refused the connection (SQLSTATE 28P01 x)",
            "test database refused the connection (SQLSTATE 28P0)",
            "test database refused the connection (SQLSTATE 28p01)",
            "test database not ready after x attempts in 1s (unclassified)",
            "test database not ready after 3 attempts in zz (unclassified)",
            "test database not ready after 3 attempts in  (unclassified)",
            "test database not ready after  attempts in 1s (unclassified)",
        ])
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        self.assertIn("FAIL mutation infrastructure detail: database_deadline count=1\n", run.stdout)
        self.assertNotIn("infrastructure stage", run.stdout)

    def run_loghygiene(self, mode, canary_lines, shard=1):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            for name in ("go.mod", "scripts/check-loghygiene-mutations.sh",
                         "scripts/mutation-helpers.sh", "scripts/lib/mutation_edit.py", "scripts/lib/mutation_snapshot.py",
                         "scripts/temp-workspace.sh", "scripts/lib/gocache.sh"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            for package in ("internal/store", "cmd/keep-server/app", "internal/testutil/pgscratch"):
                shutil.copytree(ROOT / package, root / package)
            stub = Path(tmp) / "go"
            # Mock: external process boundary. The run named by mode is red
            # and prints the canary lines; every other run is green.
            stub.write_text("#!/usr/bin/env python3\nimport os, sys\n" +
                            f"root = {str(root)!r}\nmode = {mode!r}\nlines = {canary_lines!r}\n" + r"""
args = sys.argv[1:]
in_root = os.path.realpath(os.getcwd()) == os.path.realpath(root)
red = {"mutant": not in_root,
       "harness": in_root and "./internal/testutil/pgscratch/" in args,
       "baseline": in_root and "./cmd/keep-server/app/" in args}[mode]
if not red:
    print("--- PASS: TestCheckNotSuperuser (0.00s)")
    print("ok  \tgithub.com/entire-vc/evc-keep/internal/store\t0.01s")
    sys.exit(0)
for line in lines:
    print(line)
sys.exit(1)
""")
            stub.chmod(0o755)
            env = {"PATH": tmp + os.pathsep + os.environ["PATH"], "TMPDIR": tmp,
                   "KEEP_DATABASE_URL": "disposable-driver-control",
                   "MUTATION_SHARD_INDEX": str(shard),
                   "MUTATION_SHARD_TOTAL": str(len(self.loghygiene_mutants()))}
            return subprocess.run(["sh", str(root / "scripts/check-loghygiene-mutations.sh")],
                                  cwd=root, env=env, capture_output=True, text=True, timeout=60)

    @staticmethod
    def loghygiene_mutants():
        """(name, source) of every mutant, in inventory order."""
        script = (ROOT / "scripts/check-loghygiene-mutations.sh").read_text()
        return re.findall(r"^mutate (\S+) +(\S+)", script, re.M)

    def loghygiene_shard(self, source):
        """The shard (one mutant per shard) of the first mutant of source."""
        for index, (name, src) in enumerate(self.loghygiene_mutants(), 1):
            if src == source:
                return index, name
        self.fail("no loghygiene mutant on " + source)

    def test_loghygiene_driver_prints_no_test_output(self):
        base = new_canary()
        value = base + "-v1-secret"
        module = "github.com/entire-vc/evc-keep/"
        store = ("TestCheckLogSettings", "internal/store")
        app = ("TestServeRefusesSuperuserRole", "cmd/keep-server/app")
        harness = ("TestNewWaitsForLateServer", "internal/testutil/pgscratch")
        cases = []
        # A mutant names only the tests of the package it ran: the one its
        # source narrows the list to (the pgscratch mutants run pgscratch).
        for source, named, unnamed in (("$hyg", [store], [app, harness]),
                                       ("$main", [app], [store, harness]),
                                       ("internal/testutil/pgscratch/pgscratch.go", [harness], [store, app])):
            shard, name = self.loghygiene_shard(source)
            cases.append(("mutant", shard, "FAIL mutation infrastructure: test database or process "
                          "fault (" + name + ")", named, unnamed))
        cases.append(("harness", 1, "FAIL database harness baseline: tests are red or skipped",
                      [harness], [store]))
        cases.append(("baseline", 1, "FAIL baseline: tests are red or skipped", [store, app], [harness]))
        for mode, shard, marker, named, unnamed in cases:
            with self.subTest(mode=mode, shard=shard):
                lines = ["database operation deadline exceeded", "FAIL " + value]
                for test, package in named + unnamed:
                    lines += ["=== RUN   " + test + "/" + value,
                              "    --- FAIL: " + test + "/" + value + " (0.00s)",
                              "    loghygiene_test.go:42: got " + value,
                              "--- FAIL: " + test + " (0.00s)",
                              "FAIL\t" + module + package + "\t0.01s"]
                run = self.run_loghygiene(mode, lines, shard)
                out = run.stdout + run.stderr
                self.assertEqual(run.returncode, 1, out)
                self.assert_no_canary(base, out)
                self.assertIn(marker, run.stdout)
                # Positive control: the declared tests of the packages that
                # ran are named, and only those.
                for test, package in named:
                    self.assertIn("--- FAIL: " + test + "\n", run.stdout)
                    self.assertIn("FAIL\t" + module + package + "\n", run.stdout)
                for test, _ in unnamed:
                    self.assertNotIn(test, run.stdout)

    def run_witness(self, lines, args=("-run", "^TestDeclared$", "./internal/store/")):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            for name in ("go.mod", "scripts/mutation-helpers.sh"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            package = root / "internal/store"
            package.mkdir(parents=True)
            (package / "store_test.go").write_text(
                'package store\n\nimport "testing"\n\nfunc TestDeclared(t *testing.T) {\n}\n\n'
                'func TestIndented(t *testing.T) {\n}\n')
            nested = package / "nested"
            nested.mkdir()
            (nested / "nested_test.go").write_text(
                'package nested\n\nimport "testing"\n\nfunc TestNested(t *testing.T) {\n}\n')
            work = Path(tmp) / "work"
            work.mkdir()
            stub = Path(tmp) / "go"
            # Mock: external process boundary; the witness run is red.
            stub.write_text("#!/usr/bin/env python3\nimport sys\n" +
                            f"lines = {lines!r}\n" +
                            "for line in lines:\n    print(line)\nsys.exit(1)\n")
            stub.chmod(0o755)
            env = {"PATH": tmp + os.pathsep + os.environ["PATH"], "TMPDIR": tmp,
                   "root": str(root), "work": str(work)}
            return subprocess.run(["sh", "-c", '. "$root/scripts/mutation-helpers.sh"; '
                                   'mutation_db_witness "$@"', "sh", *args],
                                  cwd=root, env=env, capture_output=True, text=True, timeout=30)

    def test_db_witness_prints_declared_tests_and_package_paths_only(self):
        base = new_canary()
        value = base + "-v1-secret"
        module = "github.com/entire-vc/evc-keep/"
        run = self.run_witness([
            "--- FAIL: TestDeclared (0.00s)",
            "--- SKIP: TestDeclared (0.00s)",
            "FAIL " + value,
            "FAIL\t" + value,
            "ok  " + value,
            "ok\t" + module + value + "\t0.01s",
            "--- FAIL: " + base + " (0.00s)",
            "--- FAIL: Test" + base + " (0.00s)",
            "--- SKIP: " + value,
            "--- FAIL: TestDeclared/" + value + " (0.00s)",
            "--- " + value,
            "FAIL" + value + "\t" + module + "internal/store\t0.01s",
            "ok" + value + "\t" + module + "internal/store\t0.01s",
            # Not a result record: go test prints top-level results from column 0.
            "    --- FAIL: TestIndented (0.00s)",
            "FAIL\t" + module + "internal/store\t0.01s",
            "ok  \t" + module.rstrip("/") + "\t0.01s",
            # Lookalikes of a declared name or a real path print nothing.
            "--- FAIL: TestDecl (0.00s)",
            "--- PASS: TestDeclared (0.00s)",
            "FAIL\t" + module + "internal/../internal/store\t0.01s",
            "FAIL\t" + module + "internal//store\t0.01s",
        ])
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, 1, out)
        self.assert_no_canary(base, out)
        self.assertIn("FAIL database witness: not green", run.stdout)
        # Positive control: the declared test and the real package are named.
        self.assertIn("--- FAIL: TestDeclared\n", run.stdout)
        self.assertIn("FAIL\t" + module + "internal/store\n", run.stdout)
        self.assertNotIn("TestIndented", run.stdout)
        self.assertIn("ok\t" + module.rstrip("/") + "\n", run.stdout)
        self.assertNotIn("TestDecl\n", run.stdout)
        self.assertNotIn("PASS", run.stdout)
        self.assertNotIn("..", run.stdout)
        self.assertNotIn("//store", run.stdout)
        self.assertIn("--- SKIP: TestDeclared\n", run.stdout)
        self.assertEqual(run.stdout.count("\n"), 5, run.stdout)

    def test_db_witness_reads_declared_tests_under_a_package_pattern(self):
        run = self.run_witness(["--- FAIL: TestDeclared (0.00s)"],
                               args=("-run", "^TestDeclared$", "./internal/store/...", "./absent/..."))
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        self.assertIn("--- FAIL: TestDeclared\n", run.stdout)
        self.assertEqual(run.stderr, "")
        # A pattern covers the packages below it, so their tests are named.
        run = self.run_witness(["--- FAIL: TestNested (0.00s)"],
                               args=("./internal/store/...",))
        self.assertIn("--- FAIL: TestNested\n", run.stdout)

    def test_db_witness_reads_declared_tests_of_the_named_package_only(self):
        # go test ./internal/store/ runs that package alone: a name declared
        # only in a package below it is not a result of this run.
        for arg in ("./internal/store/", "./internal/store"):
            with self.subTest(arg=arg):
                run = self.run_witness(["--- FAIL: TestNested (0.00s)",
                                        "--- FAIL: TestDeclared (0.00s)"],
                                       args=("-run", "^Test", arg))
                self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
                self.assertNotIn("TestNested", run.stdout)
                # Positive control: the named package's own test is still named.
                self.assertIn("--- FAIL: TestDeclared\n", run.stdout)
                self.assertEqual(run.stderr, "")


if __name__ == '__main__':
    unittest.main(verbosity=2)
