"""Exercise the actual HPKE shell gate with a deterministic child boundary."""
import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class HpkeDiagnostics(unittest.TestCase):
    def invoke(self, output, code):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'scripts/lib').mkdir(parents=True)
            for name in ('scripts/lib/gocache.sh', 'scripts/temp-workspace.sh',
                         'scripts/intake_mutant_diagnostics.py', 'scripts/check-intake-browser.mjs',
                         'scripts/lib/chromium-startup.mjs', 'scripts/lib/chromium-profile.mjs'):
                shutil.copyfile(ROOT / name, root / name)
            (root / 'web/intake/testdata').mkdir(parents=True)
            shutil.copyfile(ROOT / 'web/intake/testdata/rfc9180-x25519-aes256.json',
                            root / 'web/intake/testdata/rfc9180-x25519-aes256.json')
            shutil.copyfile(ROOT / 'web/intake/hpke.js', root / 'web/intake/hpke.js')
            (root / 'go.mod').write_text('module fixture\n')
            source = (ROOT / 'scripts/check-intake-browser-mutations.sh').read_text()
            prefix = source.split('\nmutate zero-dh ', 1)[0]
            case = next(line for line in source.splitlines() if line.startswith('mutate local-storage '))
            (root / 'scripts/probe.sh').write_text(prefix + '\n' + case + '\n')
            (root / 'bin').mkdir()
            node = root / 'bin/node'
            node.write_text('#!/usr/bin/env python3\nimport os,sys\n'
                'assert len(sys.argv)==2 and sys.argv[1].endswith("/tree/scripts/check-intake-browser.mjs")\n'
                'print(os.environ["PROBE_OUTPUT"])\n'
                'print("Authorization: synthetic-private-sentinel https://private.invalid",file=sys.stderr)\n'
                'sys.exit(int(os.environ["PROBE_CODE"]))\n')
            node.chmod(0o755)
            result = subprocess.run(['sh', str(root / 'scripts/probe.sh')],
                env=dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                         PROBE_OUTPUT=output, PROBE_CODE=str(code)),
                text=True, capture_output=True, timeout=10)
            public = result.stdout + result.stderr
            self.assertNotIn('synthetic-private-sentinel', public)
            self.assertNotIn('private.invalid', public)
            events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
            return result, events

    def test_native_gate_expected_verdicts_and_safe_diagnostics(self):
        startup = json.dumps({'event':'chromium-startup-failed', 'readiness':'missing',
            'spawn_error':'ENOENT', 'exit_code':None, 'signal':None,
            'stderr_signatures':['profile-in-use','synthetic-private-sentinel'],
            'raw':'https://private.invalid'})
        cases = [
            ('AssertionError [ERR_ASSERTION]: browser localStorage side effect', 1, 0, None, None),
            ('AssertionError [ERR_ASSERTION]: browser sessionStorage side effect', 1, 1, 'assertion-failure', 'session-storage-side-effect'),
            ('AssertionError [ERR_ASSERTION]: private assertion https://private.invalid', 1, 1, 'assertion-failure', 'unknown'),
            ('Error: CDP command failed', 1, 1, 'cdp-command-failed', 'unknown'),
            ('TypeError: private message https://private.invalid', 1, 1, 'runtime-error', 'unknown'),
            (startup + '\nAssertionError [ERR_ASSERTION]: Chromium did not start', 1, 1, 'browserlaunch', 'chromium-did-not-start'),
            ('unknown https://private.invalid', 7, 1, 'unknown', 'unknown'),
            ('PASS', 0, 1, 'expectedwitnessmissing', 'unknown'),
            ('AssertionError [ERR_ASSERTION]: browser localStorage side effect\nprivate', 2, 1, 'assertion-failure', 'local-storage-side-effect'),
        ]
        expected_outputs = [
            'ok   local-storage: browser assertion rejected mutant (rc=1)\n',
            'FAIL local-storage: its own side-effect observer did not fire\n',
            'FAIL local-storage: browser did not reach a behavioral assertion\n',
            'FAIL local-storage: browser did not reach a behavioral assertion\n',
            'FAIL local-storage: browser did not reach a behavioral assertion\n',
            'FAIL local-storage: browser did not reach a behavioral assertion\n',
            'FAIL local-storage: expected rc=1, got 7\n',
            'FAIL local-storage: browser accepted a broken HPKE implementation\n',
            'FAIL local-storage: expected rc=1, got 2\n',
        ]
        self.assertEqual(len(cases), len(expected_outputs))
        for (output, code, status, reason, marker), expected_output in zip(cases, expected_outputs):
            with self.subTest(code=code, reason=reason):
                after, events = self.invoke(output, code)
                self.assertEqual(after.returncode, status)
                without_diagnostic = '\n'.join(line for line in after.stdout.splitlines()
                                               if not line.startswith('{')) + '\n'
                self.assertEqual(without_diagnostic, expected_output)
                self.assertEqual(after.stderr, '')
                if reason is None:
                    self.assertEqual(events, [])
                else:
                    self.assertEqual(len(events), 1)
                    self.assertEqual(events[0]['classification'], reason)
                    self.assertEqual(events[0]['exit_code'], code)
                    self.assertEqual(events[0]['assertion_marker_ids'], [marker])
                    if reason == 'browserlaunch':
                        self.assertEqual(events[0]['startup'][0]['spawn_error'], 'ENOENT')
                        self.assertEqual(events[0]['startup'][0]['stderr_signatures'], ['profile-in-use'])

    def test_nonassertion_source_and_suffixes_remain_unknown(self):
        for output in ('browser localStorage side effect',
                       'assert(port,"Chromium did not start")',
                       'AssertionError [ERR_ASSERTION]: browser localStorage side effect-private'):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'private-child-output'
                path.write_text(output + '\nAuthorization: synthetic-private-sentinel https://private.invalid')
                result = subprocess.run(['python3', str(ROOT / 'scripts/intake_mutant_diagnostics.py'),
                                         '--hpke', str(path), '1'], capture_output=True, text=True, check=True)
                self.assertNotIn('synthetic-private-sentinel', result.stdout + result.stderr)
                self.assertNotIn('private.invalid', result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)['assertion_marker_ids'], ['unknown'])


    def test_allowlist_source_binding(self):
        spec = importlib.util.spec_from_file_location('diagnostics', ROOT / 'scripts/intake_mutant_diagnostics.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = (ROOT / 'scripts/check-intake-browser.mjs').read_text()
        self.assertEqual(len(module.HPKE_MARKERS), 30)
        self.assertEqual(len({key for key, _ in module.HPKE_MARKERS}), 30)
        for key, marker in module.HPKE_MARKERS:
            if marker in ('browser localStorage side effect', 'browser sessionStorage side effect',
                          'browser IndexedDB side effect', 'browser document title side effect'):
                kind = marker.removeprefix('browser ').removesuffix(' side effect')
                self.assertTrue("'" + kind + "'" in source and "'browser '+kind+' side effect'" in source, key)
            else:
                self.assertTrue(marker in source, key)
            self.assertRegex(key, r'^[a-z0-9-]+$')


if __name__ == '__main__':
    unittest.main(verbosity=2)
