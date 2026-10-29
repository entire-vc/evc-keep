#!/usr/bin/env python3
"""Run security mutation drivers against controlled process and test outcomes."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

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
                       set(re.findall(r"^mutate \S+ (\S+)",
                           (ROOT / "scripts/check-tenancy-mutations.sh").read_text(), re.M)))
            for name in sources | {"go.mod", "scripts/mutation-helpers.sh",
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
                       for d in ("internal", "test") for p in (root / d).rglob("*.go")}
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
            count = len(re.findall(r'^(?:mutate|begin) ',
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


MESH_PLUGIN = ROOT / "scripts/check-mesh-plugin-mutations.sh"


class MeshPluginShards(unittest.TestCase):
    """The mesh-plugin driver with go stubbed: baseline green, every mutant red
    unless named as the survivor. Python applies the real mutations."""

    def run_shard(self, index, total=3, survivor="", baseline_red=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            sources = set(re.findall(r"^src=(\S+)", MESH_PLUGIN.read_text(), re.M))
            for name in sources | {"go.mod", "scripts/mutation-helpers.sh", "scripts/temp-workspace.sh",
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
