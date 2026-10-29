import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
SCRIPT = (ROOT / 'scripts/check-approvals-mutations.sh').read_text()
START = SCRIPT.index('env = os.environ.copy()')
END = SCRIPT.index('for name, rel, before, after, test, pkg in mutations:')
BLOCK = SCRIPT[START:END]
PACKAGE = 'github.com/entire-vc/evc-keep/internal/deployment'
CANARY = 'secret-canary-never-print'


class BaselineDiagnostics(unittest.TestCase):
    def invoke(self, events, code=1, tests=('TestKnown',)):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scripts = root / 'scripts'; scripts.mkdir()
            (scripts / 'approvals_baseline_diagnostics.py').write_text((ROOT / 'scripts/approvals_baseline_diagnostics.py').read_text())
            source = root / 'internal/deployment'; source.mkdir(parents=True)
            (source / 'fixture_test.go').write_text('\n'.join('func ' + name + '(t *testing.T) {}' for name in tests))
            work = root / 'work'; (work / 'tree').mkdir(parents=True)
            binary = root / 'bin'; binary.mkdir()
            argvfile = root / 'argv.json'
            fake = binary / 'go'
            fake.write_text('#!' + sys.executable + '\nimport sys,json\nfrom pathlib import Path\n'
                            + 'with Path(' + repr(str(argvfile)) + ').open("a") as f: f.write(json.dumps(sys.argv[1:]) + "\\n")\n'
                            + 'if sys.argv[-1] != "./internal/deployment": sys.exit(0)\n'
                            + 'print(' + repr('\n'.join(json.dumps(e) for e in events)) + ')\nsys.exit(' + str(code) + ')\n')
            fake.chmod(0o755)
            prefix = 'import json,os,sys,subprocess\nfrom pathlib import Path\nroot=Path(sys.argv[1]); work=root/"work"\nD,A,N="internal/deployment","internal/api","internal/notify"\n'
            env = os.environ.copy(); env['PATH'] = str(binary) + os.pathsep + env['PATH']
            run = subprocess.run([sys.executable, '-c', prefix + BLOCK + '\nprint("MUTANT_BOUNDARY_REACHED")', str(root)], env=env, capture_output=True, text=True)
            return run.returncode, run.stdout + run.stderr, [json.loads(line) for line in argvfile.read_text().splitlines()]

    def test_failed_fixture_is_safe_and_stops_before_mutants(self):
        events = [{'Action': 'output', 'Package': PACKAGE, 'Output': 'open migration database ' + CANARY + '\nopen migration database https://private.invalid/' + CANARY},
                  {'Action': 'fail', 'Package': PACKAGE, 'Test': 'TestKnown'}]
        code, output, argv = self.invoke(events)
        self.assertEqual(code, 1); self.assertNotIn(CANARY, output); self.assertNotIn('https:', output)
        self.assertNotIn('MUTANT_BOUNDARY_REACHED', output)
        diagnostic = next(json.loads(line) for line in output.splitlines() if line.startswith('{'))
        self.assertEqual(diagnostic['fixture_stage_counts'], {'fixture_open_migration': 2})
        self.assertEqual(diagnostic['test_ids'], ['TestKnown'])
        self.assertEqual(argv, [['test', '-json', '-count=1', '-p', '1', '-timeout=300s', './' + pkg]
                                for pkg in ('internal/deployment', 'internal/api', 'internal/notify', 'internal/identity')])

    def test_green_baseline_reaches_mutants_without_diagnostic(self):
        code, output, _ = self.invoke([{'Action': 'pass', 'Package': PACKAGE, 'Test': 'TestKnown'}], 0)
        self.assertEqual(code, 0); self.assertIn('MUTANT_BOUNDARY_REACHED', output)
        self.assertNotIn('approvals-baseline-failure', output)

    def test_skip_still_fails_even_with_zero_exit(self):
        code, output, _ = self.invoke([{'Action': 'skip', 'Package': PACKAGE, 'Test': 'TestKnown'}], 0)
        self.assertEqual(code, 1); self.assertNotIn('MUTANT_BOUNDARY_REACHED', output)
        self.assertIn('TestKnown', output)

    def test_unknown_ids_subtests_packages_and_arbitrary_output_are_private(self):
        events = [{'Action': 'fail', 'Package': PACKAGE, 'Test': 'TestKnown/' + CANARY},
                  {'Action': 'fail', 'Package': PACKAGE, 'Test': 'TestUnknown'},
                  {'Action': 'fail', 'Package': CANARY, 'Test': 'TestKnown'},
                  {'Action': 'output', 'Package': PACKAGE, 'Output': 'SQL secret ' + CANARY},
                  {'Action': 'output', 'Package': CANARY, 'Output': 'open migration database'}]
        code, output, _ = self.invoke(events)
        self.assertEqual(code, 1); self.assertNotIn(CANARY, output); self.assertNotIn('TestUnknown', output)
        self.assertIn('"classification": "unknown"', output); self.assertIn('"test_ids": []', output)

    def test_all_fixed_stage_markers_and_bounded_test_ids(self):
        tests = tuple('TestKnown' + str(i) for i in range(20))
        events = [{'Action': 'fail', 'Package': PACKAGE, 'Test': name} for name in tests]
        events += [{'Action': 'output', 'Package': PACKAGE, 'Output': 'migrate test database\nopen test pool ' + CANARY}]
        code, output, _ = self.invoke(events, tests=tests)
        self.assertEqual(code, 1); self.assertNotIn(CANARY, output)
        data = next(json.loads(line) for line in output.splitlines() if line.startswith('{'))
        self.assertEqual(len(data['test_ids']), 16); self.assertEqual(data['test_id_count'], 20)
        self.assertTrue(data['test_ids_truncated']); self.assertEqual(data['fixture_stage_counts'], {'fixture_migrate': 1, 'fixture_open_pool': 1})

    def test_fixed_fixture_causes_and_codes_only(self):
        from approvals_baseline_diagnostics import CAUSES, SQLSTATES
        good = ['    repo_test.go:37: open migration database: ' + c for c in CAUSES]
        good += ['    repo_test.go:37: open migration database: connection_sqlstate code=' + c for c in SQLSTATES]
        bad = ['    repo_test.go:37: open migration database: invalid_dsn ' + CANARY,
               '    repo_test.go:37: open migration database: connection_sqlstate code=' + CANARY,
               '    repo_test.go:37: open migration database: connection_sqlstate code=ZZZZZ',
               '    repo_test.go:37: open migration database: connection_sqlstate code=28P01 ' + CANARY,
               CANARY + ' open migration database: database_deadline']
        code, output, _ = self.invoke([{'Action': 'output', 'Package': PACKAGE, 'Output': '\n'.join(good + bad)}])
        self.assertEqual(code, 1); self.assertNotIn(CANARY, output); self.assertNotIn('ZZZZZ', output)
        data = next(json.loads(line) for line in output.splitlines() if line.startswith('{'))
        self.assertEqual(data['fixture_cause_counts'], {**{c: 1 for c in CAUSES}, 'connection_sqlstate': len(SQLSTATES)})
        self.assertEqual(data['fixture_sqlstate_counts'], {c: 1 for c in SQLSTATES})

    def test_unexpected_event_field_types_remain_private(self):
        events = [{'Action': 'fail', 'Package': PACKAGE, 'Test': {CANARY: CANARY}},
                  {'Action': 'output', 'Package': PACKAGE, 'Output': {CANARY: CANARY}},
                  {'Action': 'output', 'Package': [CANARY], 'Output': CANARY}]
        code, output, _ = self.invoke(events)
        self.assertEqual(code, 1); self.assertNotIn(CANARY, output)
        self.assertIn('"classification": "unknown"', output)
        self.assertNotIn('MUTANT_BOUNDARY_REACHED', output)

    def test_timeout_panic_names_the_running_test(self):
        lines = ['=== RUN   TestKnown\n', 'panic: test timed out after 5m0s\n', '\trunning tests:\n',
                 '\t\tTestKnown (5m0s)\n', '\t\tTestKnown/' + CANARY + ' (5m0s)\n', '\t\tTestUnknown (5m0s)\n',
                 '\t\t' + CANARY + ' (5m0s)\n', '\n', 'goroutine 17 [running]:\n', CANARY + '\n']
        events = [{'Action': 'output', 'Package': PACKAGE, 'Test': 'TestKnown', 'Output': line} for line in lines]
        events += [{'Action': 'output', 'Package': PACKAGE, 'Output': 'FAIL\tx\t300.1s\n'},
                   {'Action': 'fail', 'Package': PACKAGE, 'Elapsed': 300.112}]
        code, output, _ = self.invoke(events)
        self.assertEqual(code, 1); self.assertNotIn(CANARY, output); self.assertNotIn('TestUnknown', output)
        self.assertNotIn('MUTANT_BOUNDARY_REACHED', output)
        data = next(json.loads(line) for line in output.splitlines() if line.startswith('{'))
        self.assertEqual(data['classification'], 'timeout')
        self.assertEqual(data['test_ids'], ['TestKnown'])
        self.assertEqual(data['packages'], [{'package': 'internal/deployment', 'action': 'fail', 'elapsed': 300.1}])

    def test_running_test_names_count_only_inside_the_block(self):
        tests = ('TestKnown', 'TestBefore', 'TestAfter')
        lines = ['\t\tTestBefore (1s)\n', 'panic: test timed out after 5m0s\n', '\t\tTestBefore (5m0s)\n',
                 '\trunning tests:\n', '\t\tTestKnown (5m0s)\n', '\n', '\t\tTestAfter (5m0s)\n',
                 'goroutine 17 [running]:\n', '\t\tTestAfter (5m0s)\n']
        events = [{'Action': 'output', 'Package': PACKAGE, 'Output': line} for line in lines]
        code, output, _ = self.invoke(events, tests=tests)
        self.assertEqual(code, 1)
        data = next(json.loads(line) for line in output.splitlines() if line.startswith('{'))
        self.assertEqual(data['classification'], 'timeout')
        self.assertEqual(data['test_ids'], ['TestKnown'])

    def test_build_failure_is_classified_without_compiler_output(self):
        events = [{'ImportPath': PACKAGE + ' [' + PACKAGE + '.test]', 'Action': 'build-output', 'Output': 'x_test.go:3: ' + CANARY + '\n'},
                  {'ImportPath': PACKAGE + ' [' + PACKAGE + '.test]', 'Action': 'build-fail'},
                  {'Action': 'fail', 'Package': PACKAGE, 'Elapsed': 0, 'FailedBuild': PACKAGE + ' [' + PACKAGE + '.test]'}]
        code, output, _ = self.invoke(events)
        self.assertEqual(code, 1); self.assertNotIn(CANARY, output)
        data = next(json.loads(line) for line in output.splitlines() if line.startswith('{'))
        self.assertEqual(data['classification'], 'build_failed')
        self.assertEqual(data['packages'], [{'package': 'internal/deployment', 'action': 'fail', 'elapsed': 0.0}])

    def test_hard_timeout_and_foreign_actions_stay_in_the_closed_set(self):
        from approvals_baseline_diagnostics import report
        import contextlib, io
        events = [{'Action': 'timeout', 'Package': PACKAGE, 'Elapsed': 420},
                  {'Action': CANARY, 'Package': 'github.com/entire-vc/evc-keep/internal/api', 'Elapsed': 1},
                  {'Action': 'pass', 'Package': 'github.com/entire-vc/evc-keep/internal/notify', 'Elapsed': CANARY}]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            report(events, ROOT)
        self.assertNotIn(CANARY, buf.getvalue())
        data = json.loads(buf.getvalue())
        self.assertEqual(data['classification'], 'timeout')
        self.assertEqual(data['packages'], [{'package': 'internal/deployment', 'action': 'timeout', 'elapsed': 420.0},
                                            {'package': 'internal/notify', 'action': 'pass', 'elapsed': None}])


if __name__ == '__main__':
    unittest.main()
