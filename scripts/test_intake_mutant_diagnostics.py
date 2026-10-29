"""Real child faults and the actual shell assertion gate, without a browser/DB."""
import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CANARY = 'private-diagnostic-canary-never-publish'


class MutantDiagnostics(unittest.TestCase):
    def invoke(self, output, code):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'scripts/lib').mkdir(parents=True)
            for path in ('scripts/lib/gocache.sh', 'scripts/temp-workspace.sh',
                         'scripts/mutation-helpers.sh', 'scripts/intake_mutant_diagnostics.py'):
                shutil.copyfile(ROOT / path, root / path)
            (root / 'go.mod').write_text('module probe\n')
            (root / 'web/intake').mkdir(parents=True)
            (root / 'web/intake/app.js').write_text('const plain = utf8.encode(field.value);')
            (root / 'internal/intake/descriptor').mkdir(parents=True)
            (root / 'internal/intake/descriptor/message.go').write_text('package descriptor\n')
            script = (ROOT / 'scripts/check-intake-page-mutations.sh').read_text()
            prefix = script.split('\nmutate signature ', 1)[0]
            case = next(line for line in script.splitlines() if line.startswith('mutate indexed-db '))
            (root / 'scripts/probe.sh').write_text(prefix + '\n' + case + '\n')
            (root / 'bin').mkdir()
            go = root / 'bin/go'
            go.write_text('#!/usr/bin/env python3\nimport os,sys\n'
                          'if "-v" not in sys.argv: sys.exit(0)\n'
                          'assert sys.argv[1:]==["test","-timeout","180s","-tags","intake_browser","-count=1","-v","-run","^TestIntakePageBrowserLifecycle","./internal/builtin"]\n'
                          'print(os.environ["PROBE_OUTPUT"])\n'
                          'print(os.environ["PROBE_CANARY"],file=sys.stderr)\n'
                          'sys.exit(int(os.environ["PROBE_CODE"]))\n')
            go.chmod(0o755)
            env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                       KEEP_DATABASE_URL='probe-only', PROBE_OUTPUT=output,
                       PROBE_CODE=str(code), PROBE_CANARY=CANARY)
            result = subprocess.run(['sh', str(root / 'scripts/probe.sh')], env=env,
                                    capture_output=True, text=True, timeout=10)
            public = result.stdout + result.stderr
            self.assertNotIn(CANARY, public)
            self.assertNotIn('private.invalid', public)
            events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
            return result, events

    def test_intended_failure_passes_and_unrelated_failure_fails(self):
        result, events = self.invoke('--- FAIL: TestIntakePageBrowserLifecycle (0.1s)\nIndexedDB side effect', 1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [])
        result, events = self.invoke('--- FAIL: TestIntakePageBrowserLifecycle (0.1s)\nunrelated assertion https://private.invalid', 7)
        self.assertEqual(result.returncode, 1)
        self.assertIn('did not reach the intended behavioral assertion', result.stdout)
        self.assertEqual(events[0]['classification'], 'testfailure')
        self.assertEqual(events[0]['exit_code'], 7)

    def test_real_process_faults_remain_rejected_and_private(self):
        cases = [('panic: test timed out after 90s', 'testtimeout', 2),
                 ('database operation deadline exceeded', 'deadline', 1),
                 ('page browser: Chromium did not start', 'browserlaunch', 1),
                 ('--- FAIL: TestUnknown (1s)', 'testfailure', 1),
                 ('unexpected process fault https://private.invalid', 'unknown', 127),
                 ('ok', 'expectedwitnessmissing', 0)]
        for output, reason, code in cases:
            with self.subTest(reason=reason):
                result, events = self.invoke(output, code)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(events[0]['classification'], reason)
                self.assertEqual(events[0]['exit_code'], code)
                self.assertGreaterEqual(events[0]['seconds'], 0)
                self.assertEqual(events[0]['test_ids'], [])

    def test_timeout_cannot_be_masked_by_intended_witness(self):
        result, events = self.invoke('--- FAIL: TestIntakePageBrowserLifecycle (0.1s)\nIndexedDB side effect\npanic: test timed out after 90s', 2)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(events[0]['classification'], 'testtimeout')
        self.assertEqual(events[0]['test_ids'], ['TestIntakePageBrowserLifecycle'])


    def test_fixed_assertion_marker_and_private_phase(self):
        cases = [
            ('page browser: browser storage side effect', ['browser-storage-side-effect']),
            ('page browser: evaluation failed', ['evaluation-failed']),
            ('page browser: unexpected network side effect; page browser: console side effect',
             ['console-side-effect', 'unexpected-network-side-effect']),
            ('page browser: expected UI state was not reached (https://private.invalid/private-phase)',
             ['expected-ui-state-was-not-reached']),
        ]
        for message, expected in cases:
            with self.subTest(expected=expected):
                output = ('--- FAIL: TestIntakePageBrowserLifecycle (0.1s)\n'
                          '    intake_page_browser_test.go:282: AssertionError [ERR_ASSERTION]: ' + message)
                result, events = self.invoke(output, 7)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(events[0]['exit_code'], 7)
                self.assertEqual(events[0]['classification'], 'testfailure')
                self.assertEqual(events[0]['assertion_marker_ids'], expected)

    def test_unrecognized_and_nonassertion_payloads_stay_unknown(self):
        payloads = [
            'AssertionError [ERR_ASSERTION]: private assertion https://private.invalid',
            'page browser: console side effect',
            'AssertionError [ERR_ASSERTION]: page browser: console side effect-private-value',
            'AssertionError [ERR_ASSERTION]: page browser: textarea privacy attribute private-value',
            'Authorization: private-value; Cookie: private-value https://private.invalid',
        ]
        for payload in payloads:
            with self.subTest(index=payloads.index(payload)):
                result, events = self.invoke('--- FAIL: TestIntakePageBrowserLifecycle (0.1s)\n' + payload, 1)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(events[0]['assertion_marker_ids'], ['unknown'])
                self.assertNotIn('private-value', result.stdout + result.stderr)

    def test_all_markers_are_fixed_bounded_and_source_bound(self):
        spec = importlib.util.spec_from_file_location('diagnostics', ROOT / 'scripts/intake_mutant_diagnostics.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # The checker plus the library that names its destination violations.
        source = ((ROOT / 'scripts/check-intake-page.mjs').read_text() +
                  (ROOT / 'scripts/lib/page-failure.mjs').read_text())
        self.assertEqual(len(module.ASSERTION_MARKERS), 49)
        self.assertEqual(len({marker_id for marker_id, _ in module.ASSERTION_MARKERS}), 49)
        for marker_id, marker in module.ASSERTION_MARKERS:
            self.assertRegex(marker_id, r'^[a-z0-9-]+$')
            if 'textarea privacy attribute' in marker:
                self.assertIn('page browser: textarea privacy attribute ', source)
            else:
                self.assertIn(marker, source)
            self.assertEqual(module.assertion_marker_ids('AssertionError [ERR_ASSERTION]: ' + marker), [marker_id])
            self.assertEqual(module.assertion_marker_ids('AssertionError [ERR_ASSERTION]: ' + marker + '-private-value'), ['unknown'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
