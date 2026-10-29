import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = (ROOT / 'scripts/check-dispatch-mutations.sh').read_text()
EVENTS = SCRIPT[SCRIPT.index('def events(output):'):SCRIPT.index('for name, filename, directory, test, before, after in mutations:')]
START = SCRIPT.index('baseline_run = ')
BLOCK = SCRIPT[START:SCRIPT.index('\nPY\n', START)]
CANARY = 'secret-canary-never-print'


class BaselineDiagnostics(unittest.TestCase):
    def invoke(self, events, code=1, sleep=0, fail_only=None):
        """Runs the final baseline block against a fake `go`. The fake answers
        every package with `events`, or only fail_only's package (the rest
        are green)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work = root / 'work'; (work / 'tree').mkdir(parents=True)
            binary = root / 'bin'; binary.mkdir()
            packages = root / 'packages.txt'
            fake = binary / 'go'
            fake.write_text('#!' + sys.executable + '\nimport sys,time\n'
                            + 'open(' + repr(str(packages)) + ',"a").write(sys.argv[-1]+"\\n")\n'
                            + 'if ' + repr(fail_only) + ' in (None, sys.argv[-1]):\n'
                            + '    time.sleep(' + str(sleep) + ')\n'
                            + '    print(' + repr('\n'.join(json.dumps(e) for e in events).replace('{TREE}', str(work / 'tree').replace('\\', '\\\\'))) + ')\n    sys.exit(' + str(code) + ')\n')
            fake.chmod(0o755)
            prefix = 'import json,os,re,sys,subprocess\nfrom pathlib import Path\nwork=Path(sys.argv[1])\nenv=os.environ.copy()\n' + EVENTS
            env = os.environ.copy(); env['PATH'] = str(binary) + os.pathsep + env['PATH']
            run = subprocess.run([sys.executable, '-c', prefix + BLOCK, str(work)], env=env, capture_output=True, text=True)
            seen = packages.read_text().split() if packages.exists() else []
            return run.returncode, run.stdout + run.stderr, seen

    def test_fixture_gives_the_class_the_package_and_the_test_name(self):
        pkg = 'github.com/entire-vc/evc-keep/internal/dispatch'
        cases = {
            'fail': [{'Action': 'output', 'Output': '    dispatch_test.go:42: got ' + CANARY + '\n'},
                     {'Action': 'fail', 'Package': pkg, 'Test': 'TestMaterialUses'}],
            'skip': [{'Action': 'skip', 'Package': pkg, 'Test': 'TestMaterialUses'}],
            'build-fail': [{'Action': 'build-output', 'Output': 'x.go:3:1: undefined: foo\n'},
                           {'Action': 'build-fail', 'Package': pkg}],
            # As go 1.26 emits it: the hung test has no `fail` event, only the
            # runtime's panic line attributed to it, then a package-level fail.
            'timeout': [{'Action': 'output', 'Package': pkg, 'Test': 'TestMaterialUses', 'Output': 'panic: test timed out after 3m0s\n'},
                        {'Action': 'output', 'Package': pkg, 'Test': 'TestMaterialUses', 'Output': '\t\tTestMaterialUses (3m0s)\n'},
                        {'Action': 'output', 'Package': pkg, 'Test': 'TestMaterialUses', 'Output': 'github.com/x/dispatch.TestMaterialUses(0xc000123456)\n'},
                        {'Action': 'output', 'Package': pkg, 'Test': 'TestMaterialUses', 'Output': '\t{TREE}/internal/dispatch/dispatch_test.go:77 +0x1a5\n'},
                        {'Action': 'output', 'Package': pkg, 'Test': 'TestMaterialUses', 'Output': '\t/usr/local/go/src/runtime/proc.go:300 +0x10\n'},
                        {'Action': 'fail', 'Package': pkg}],
        }
        for cls, events in cases.items():
            with self.subTest(cls):
                code, output, _ = self.invoke(events, 1 if cls != 'skip' else 0, fail_only='./internal/dispatch')
                self.assertEqual(code, 1)
                self.assertIn('FAIL baseline: dispatch tests ' + cls, output)
                self.assertIn('in ./internal/dispatch', output)
                self.assertNotIn(CANARY, output)
                if cls == 'fail':
                    self.assertIn('at dispatch_test.go:42', output)
                if cls == 'timeout':
                    self.assertIn('at internal/dispatch/dispatch_test.go:77', output)
                    self.assertNotIn('proc.go', output)
                if cls != 'build-fail':
                    self.assertIn('test: TestMaterialUses', output)
                else:
                    self.assertIn('at x.go:3:1', output)
                    self.assertNotIn('undefined: foo', output)

    def test_message_text_is_never_printed(self):
        events = [{'Action': 'output', 'Output': 'value ' + CANARY + '\n'},
                  {'Action': 'output', 'Output': '    a_test.go:7: token=' + CANARY + '\n'},
                  {'Action': 'fail', 'Package': 'p', 'Test': 'TestMaterialUses'}]
        code, output, _ = self.invoke(events, 1, fail_only='./internal/dispatch')
        self.assertEqual(code, 1)
        self.assertNotIn(CANARY, output)

    def test_wrapper_timeout_names_the_package(self):
        src = BLOCK.replace('timeout=600', 'timeout=1')
        self.assertNotEqual(src, BLOCK)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / 'work/tree').mkdir(parents=True); binary = root / 'bin'; binary.mkdir()
            fake = binary / 'go'; fake.write_text('#!' + sys.executable + '\nimport time\ntime.sleep(30)\n'); fake.chmod(0o755)
            prefix = 'import json,os,re,sys,subprocess\nfrom pathlib import Path\nwork=Path(sys.argv[1])\nenv=os.environ.copy()\n' + EVENTS
            env = os.environ.copy(); env['PATH'] = str(binary) + os.pathsep + env['PATH']
            run = subprocess.run([sys.executable, '-c', prefix + src, str(root / 'work')], env=env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertIn('FAIL baseline: dispatch tests timeout (wrapper limit 600 s, compile included) in ./internal/store', run.stdout)

    def test_green_run_covers_every_package_one_at_a_time(self):
        code, output, seen = self.invoke([{'Action': 'pass', 'Package': 'p', 'Test': 'TestMaterialUses'}], 0)
        self.assertEqual(code, 0)
        self.assertIn('ok   baseline: dispatch race tests green, no skips', output)
        self.assertEqual(seen, ['./internal/store', './internal/dispatch', './internal/builtin', './internal/builtin/orgpki', './internal/api', './pkg/runnerproto'])


if __name__ == '__main__':
    unittest.main()
