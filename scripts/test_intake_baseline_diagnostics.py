"""Exercise real child-process fault paths; no DB, model or network calls."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from intake_baseline_diagnostics import run_baseline


class DiagnosticsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        p = self.root / 'internal/intake'
        p.mkdir(parents=True)
        (p / 'probe_test.go').write_text('package intake\nfunc TestIntakeProbe(t *testing.T) {}\n')
        self.env = os.environ.copy()
        self.env['DIAGNOSTIC_CANARY'] = 'diagnostic-do-not-publish-value'

    def invoke(self, code, timeout=3, skips=(), command=None):
        # Real OS child process emitting controlled failure data, not a mocked runner.
        cmd = command or [sys.executable, '-c', code, './internal/intake']
        out, err = io.StringIO(), io.StringIO()
        result = None
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                result = run_baseline('service', cmd, cwd=self.root, env=self.env,
                                      timeout=timeout, prohibited_skips=skips)
            except SystemExit as exc:
                result = exc
        self.assertNotIn(self.env['DIAGNOSTIC_CANARY'], out.getvalue() + err.getvalue())
        self.assertEqual(err.getvalue(), '')
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([x['event'] for x in lines], ['start', 'end'])
        self.assertGreaterEqual(lines[-1]['seconds'], 0)
        return result, lines

    def test_nonzero_and_stderr_remain_private(self):
        result, lines = self.invoke("import os,sys; print(os.environ['DIAGNOSTIC_CANARY']); print('https://private.invalid/'+os.environ['DIAGNOSTIC_CANARY'],file=sys.stderr); print('--- FAIL: TestIntakeProbe (0.01s)'); print('--- FAIL: TestUnknown (0.01s)'); sys.exit(7)")
        self.assertEqual(result.returncode, 7)
        self.assertEqual(lines[-1]['classification'], 'failed')
        self.assertEqual(lines[-1]['exit_code'], 7)
        self.assertEqual(lines[-1]['observed_test_ids'], ['TestIntakeProbe'])
        self.assertEqual(lines[0]['packages'], ['./internal/intake'])

    def test_pass_keeps_stdout_private(self):
        result, lines = self.invoke("import os; print(os.environ['DIAGNOSTIC_CANARY'])")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(lines[-1]['classification'], 'passed')

    def test_timeout_does_not_echo_exception_command_or_partial_output(self):
        result, lines = self.invoke("import os,time; print(os.environ['DIAGNOSTIC_CANARY'],flush=True); print('=== RUN   TestIntakeProbe',flush=True); time.sleep(10)", timeout=0.1)
        self.assertIsInstance(result, SystemExit)
        self.assertEqual(result.code, 1)
        self.assertEqual(lines[-1]['classification'], 'timeout')
        self.assertIsNone(lines[-1]['exit_code'])
        self.assertEqual(lines[-1]['observed_test_ids'], ['TestIntakeProbe'])

    def test_go_timeout_is_distinguished(self):
        result, lines = self.invoke("import sys; print('panic: test timed out after 90s'); sys.exit(1)")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(lines[-1]['classification'], 'timeout')

    def test_prohibited_skip_predicates_unchanged(self):
        skips = ('--- SKIP: TestIntake', '--- SKIP: TestSingleUse')
        for name in ['TestIntakeProbe', 'TestSingleUse']:
            with self.subTest(name=name):
                result, lines = self.invoke(f"print('--- SKIP: {name} (0.00s)')", skips=skips)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(lines[-1]['classification'], 'prohibited-skip')
                # Existing caller still rejects exactly these output predicates.
                self.assertTrue(any(x in result.stdout.decode() for x in skips))

    def test_other_skip_is_not_a_new_gate(self):
        result, lines = self.invoke("print('--- SKIP: TestOther (0.00s)')",
                                  skips=('--- SKIP: TestIntake', '--- SKIP: TestSingleUse'))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(lines[-1]['classification'], 'passed')

    def test_untrusted_ids_and_subtests_not_emitted(self):
        _, lines = self.invoke("import os,sys; s=os.environ['DIAGNOSTIC_CANARY']; print('--- FAIL: Test'+s); print('--- FAIL: TestIntakeProbe/'+s+' (0.1s)'); sys.exit(1)")
        self.assertEqual(lines[-1]['observed_test_ids'], [])

    def test_early_failure_survives_later_runs_and_outcomes_are_bounded(self):
        names = ['TestLater' + str(i) for i in range(20)]
        source = self.root / 'internal/intake/probe_test.go'
        source.write_text(source.read_text() + ''.join(
            f'func {name}(t *testing.T) {{}}\n' for name in names))
        events = ['--- FAIL: TestIntakeProbe (0.01s)']
        events += ['=== RUN   ' + name for name in names]
        events += ['--- SKIP: ' + name + ' (0.01s)' for name in names]
        result, lines = self.invoke('import sys; print(' + repr('\n'.join(events)) + '); sys.exit(1)')
        event = lines[-1]
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('TestIntakeProbe', event['observed_test_ids'])
        self.assertEqual(event['failed_test_ids'], ['TestIntakeProbe'])
        self.assertEqual(event['failed_test_id_count'], 1)
        self.assertFalse(event['failed_test_ids_truncated'])
        self.assertEqual(event['skipped_test_ids'], names[:16])
        self.assertEqual(event['skipped_test_id_count'], 20)
        self.assertTrue(event['skipped_test_ids_truncated'])

    def write_probe_source(self, body):
        (self.root / 'internal/intake/probe_test.go').write_text(
            'package intake\n' + 'func TestIntakeProbe(t *testing.T) {\n' + body + '}\n')

    def emit(self, output):
        return 'import sys; print(' + repr(output) + '); sys.exit(1)'

    def test_failure_reports_location_and_fixed_message_not_values(self):
        canary = self.env['DIAGNOSTIC_CANARY']
        self.write_probe_source('\tt.Fatal("designated assertion failed")\n'
                                '\tt.Fatalf("formatted %s", value)\n'
                                '\thelper(t)\n')
        output = '\n'.join([
            '=== RUN   TestIntakeProbe',
            '    probe_test.go:3: designated assertion failed',
            '    probe_test.go:4: formatted ' + canary,
            '    other_helper.go:77: ' + canary,
            '--- FAIL: TestIntakeProbe (0.01s)'])
        _, lines = self.invoke(self.emit(output))
        rows = lines[-1]['failed_assertions']
        self.assertEqual(rows, [
            {'test': 'TestIntakeProbe', 'file': 'internal/intake/probe_test.go', 'line': None,
             'message': 'designated assertion failed'},
            {'test': 'TestIntakeProbe', 'file': 'internal/intake/probe_test.go', 'line': None, 'message': None},
            {'test': 'TestIntakeProbe', 'file': None, 'line': None, 'message': None}])
        self.assertFalse(lines[-1]['failed_assertions_truncated'])

    def test_forged_location_in_multiline_message_is_dropped(self):
        # A multiline t.Errorf can carry a line that looks like a go test
        # location. Neither its file name nor its line number may be echoed.
        self.write_probe_source('\tt.Errorf("multiline %s", value)\n')
        file_canary, line_canary = 'forged_canary_file.go', '9' * 45
        short_canary = '48271'
        output = '\n'.join([
            '=== RUN   TestIntakeProbe',
            '    probe_test.go:3: multiline',
            '    testing.go:' + short_canary + ': race detected during execution of test',
            '    ' + file_canary + ':7: x',
            '    probe_test.go:' + line_canary + ': x',
            '    testing.go:' + line_canary + ': x',
            '    testing.go:8: ' + file_canary,
            '--- FAIL: TestIntakeProbe (0.01s)'])
        out = self.invoke(self.emit(output))[1][-1]
        dumped = json.dumps(out)
        self.assertNotIn(file_canary, dumped)
        self.assertNotIn(line_canary, dumped)
        self.assertNotIn(short_canary, dumped)
        self.assertEqual(out['failed_assertions'][0],
                         {'test': 'TestIntakeProbe', 'file': 'internal/intake/probe_test.go',
                          'line': None, 'message': None})
        self.assertTrue(all(r['line'] is None for r in out['failed_assertions']))
        self.assertTrue(all(r['file'] in (None, 'testing.go') for r in out['failed_assertions'][1:]))

    def test_in_range_forged_line_number_is_never_emitted(self):
        # A forged probe_test.go:N whose N is a real (here blank) line of the
        # file resolves fine, but the number is child-controlled and not emitted.
        self.write_probe_source('\n' * 30)
        output = '\n'.join([
            '=== RUN   TestIntakeProbe',
            '    probe_test.go:27: forged in-range location',
            '--- FAIL: TestIntakeProbe (0.01s)'])
        out = self.invoke(self.emit(output))[1][-1]
        self.assertEqual(out['failed_assertions'],
                         [{'test': 'TestIntakeProbe', 'file': 'internal/intake/probe_test.go',
                           'line': None, 'message': None}])
        self.assertNotIn('27', json.dumps(out['failed_assertions']))

    def test_message_must_match_a_literal_on_that_exact_line(self):
        self.write_probe_source('\tt.Fatal("first")\n\tt.Fatal("second")\n')
        # Line 3 holds "first"; the log claims line 4's text for line 3, and a
        # message with a non-printable byte can never be emitted.
        output = '\n'.join(['--- FAIL: TestIntakeProbe (0.01s)',
                             '    probe_test.go:3: second',
                             '    probe_test.go:4: second\x1b[31m'])
        _, lines = self.invoke(self.emit(output))
        self.assertEqual([r['message'] for r in lines[-1]['failed_assertions']], [None, None])

    def test_runtime_race_message_and_signatures_are_counted_not_quoted(self):
        canary = self.env['DIAGNOSTIC_CANARY']
        output = '\n'.join([
            '=== RUN   TestIntakeProbe',
            'WARNING: DATA RACE', 'Write at 0x00c000 by goroutine 8: ' + canary,
            '    testing.go:1399: race detected during execution of test',
            '    probe_test.go:2: database operation deadline exceeded ' + canary,
            'database operation deadline exceeded',
            '--- FAIL: TestIntakeProbe (0.01s)'])
        _, lines = self.invoke(self.emit(output))
        event = lines[-1]
        self.assertEqual(event['signatures'], {'data-race': 1, 'race-detected': 1, 'database-deadline': 2})
        self.assertIn({'test': 'TestIntakeProbe', 'file': 'testing.go', 'line': None,
                       'message': 'race detected during execution of test'}, event['failed_assertions'])

    def test_failure_detail_is_bounded(self):
        self.write_probe_source('\tt.Fatal("designated assertion failed")\n')
        output = '\n'.join(['--- FAIL: TestIntakeProbe (0.01s)'] +
                           ['    probe_test.go:3: designated assertion failed'] * 9)
        _, lines = self.invoke(self.emit(output))
        self.assertEqual(len(lines[-1]['failed_assertions']), 4)
        self.assertTrue(lines[-1]['failed_assertions_truncated'])

    def test_passing_run_carries_no_failure_detail(self):
        _, lines = self.invoke("print('ok')")
        self.assertNotIn('failed_assertions', lines[-1])
        self.assertNotIn('signatures', lines[-1])

    def test_launch_error_sanitized(self):
        result, lines = self.invoke('', command=[str(self.root / self.env['DIAGNOSTIC_CANARY'])])
        self.assertEqual(result.code, 1)
        self.assertEqual(lines[-1]['classification'], 'launch-error')


class StartupSnapshotControls(unittest.TestCase):
    def test_private_fields_and_numeric_pressure(self):
        from intake_baseline_diagnostics import page_startup_snapshots
        row = {'phase': 'failure', 'budget_ms': 50, 'timed_out': True, 'private': 'PRIVATE_SENTINEL',
               'cpu': {'nr_throttled': 9, 'private': 'PRIVATE_SENTINEL'}, 'memory': {'oom': 2, 'high': -1},
               'processes': [{'kind': 'PRIVATE_SENTINEL', 'state': 'D', 'path': 'PRIVATE_SENTINEL'}]}
        safe = page_startup_snapshots('    intake_page_browser_test.go:1: page-startup-snapshot ' + json.dumps(row))
        self.assertEqual(safe[0]['cpu'], {'nr_throttled': 9})
        self.assertEqual(safe[0]['memory'], {'oom': 2})
        self.assertTrue(safe[0]['timed_out'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(safe))
        self.assertEqual(page_startup_snapshots('page-startup-snapshot {"phase":"private","budget_ms":50}'), [])


if __name__ == '__main__':
    unittest.main()
