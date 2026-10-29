"""The w3-stubs guard must say why a run did not match, in bounded form."""

import ast
import contextlib
import importlib.util
import io
import json
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_w3_stubs", HERE / "check-w3-stubs.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def ev(action, test=None, output=None):
    e = {"Action": action}
    if test:
        e["Test"] = test
    if output is not None:
        e["Output"] = output
    return e


class Why(unittest.TestCase):
    def test_names_the_failed_test_and_its_reason(self):
        events = [
            ev("run", "TestW3_A03_X_Carriers"),
            ev("output", "TestW3_A03_X_Carriers", "    w3_carriers_attack_test.go:128: test database not ready after 90 attempts in 1m30s\n"),
            ev("fail", "TestW3_A03_X_Carriers"),
            ev("fail"),
        ]
        text = guard.why((1, events))
        self.assertIn("exit 1, 1 fail", text)
        self.assertIn("failed test TestW3_A03_X_Carriers", text)
        self.assertIn("test database not ready after 90 attempts", text)

    def test_output_of_tests_that_did_not_fail_stays_out(self):
        events = [
            ev("output", "TestW3_A01_Y", "    w3_attack_stubs_test.go:13: W3-A01: pending target rotation absent\n"),
            ev("skip", "TestW3_A01_Y"),
            ev("output", "TestW3_B_Z", "    other_test.go:9: deadline exceeded\n"),
            ev("pass", "TestW3_B_Z"),
        ]
        text = guard.why((0, events))
        self.assertNotIn("pending target", text)
        self.assertNotIn("deadline exceeded", text)
        self.assertIn("1 pass", text)
        self.assertIn("1 skip", text)

    def test_only_the_failed_tests_output_is_shown(self):
        events = [
            ev("output", "TestW3_Ok", "    ok_test.go:4: pass-side noise\n"),
            ev("pass", "TestW3_Ok"),
            ev("output", "TestW3_Bad", "    bad_test.go:9: the real reason\n"),
            ev("output", "TestW3_Bad", "    plain line without a location\n"),
            ev("fail", "TestW3_Bad"),
        ]
        text = guard.why((1, events))
        self.assertIn("the real reason", text)
        self.assertNotIn("pass-side noise", text)
        self.assertNotIn("plain line", text)

    def test_reason_lines_without_a_file_location_are_kept(self):
        events = [
            ev("output", "TestW3_Bad", "context deadline exceeded\n"),
            ev("output", "TestW3_Bad", "database not ready yet\n"),
            ev("output", "TestW3_Bad", "unrelated chatter\n"),
            ev("fail", "TestW3_Bad"),
        ]
        text = guard.why((1, events))
        self.assertIn("deadline exceeded", text)
        self.assertIn("not ready yet", text)
        self.assertNotIn("unrelated chatter", text)

    def test_main_reports_the_reason_of_both_runs(self):
        source = (HERE / "check-w3-stubs.py").read_text()
        self.assertIn('require_run(run(ROOT, "^TestW3_", "baseline")', source)
        calls = [n for n in ast.walk(ast.parse(source))
                 if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "require_run"]
        planted = [c for c in calls if ast.unparse(c.args[0]).startswith("run(ROOT, pattern,")]
        self.assertTrue(planted)
        for c in planted:
            self.assertEqual(len(c.args), 4, "planted run must pass the expected reasons")

    def test_panic_line_without_a_location_is_kept(self):
        events = [
            ev("output", "TestW3_Bad", "panic: runtime error: boom\n"),
            ev("fail", "TestW3_Bad"),
        ]
        self.assertIn("panic: runtime error: boom", guard.why((2, events)))

    def test_subtests_are_not_counted_as_tests(self):
        events = [
            ev("pass", "TestW3_A/sub"),
            ev("fail", "TestW3_A/sub"),
            ev("pass", "TestW3_A"),
        ]
        text = guard.why((0, events))
        self.assertIn("1 pass", text)
        self.assertNotIn("fail,", text)
        self.assertNotIn("1 fail", text)

    def test_red_runs_are_judged_against_their_markers(self):
        # require_run must hand `red` to valid(): a red run that carries the
        # wrong marker is rejected, the right one accepted.
        name = "TestW3_A01_Q"
        events = [ev("run", name), ev("output", name, "wrong reason\n"), ev("fail", name), ev("fail")]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(RuntimeError):
            guard.require_run((1, events), {name}, "red label", {name: "right reason"})
        events = [ev("run", name), ev("output", name, "right reason\n"), ev("fail", name), ev("fail")]
        with contextlib.redirect_stdout(io.StringIO()):
            guard.require_run((1, events), {name}, "red label", {name: "right reason"})

    def test_output_is_bounded(self):
        events = []
        for i in range(40):
            events.append(ev("output", "TestW3_Big", "    f_test.go:%d: %s\n" % (i, "x" * 500)))
        events.append(ev("fail", "TestW3_Big"))
        text = guard.why((1, events))
        lines = text.splitlines()
        self.assertLessEqual(len(lines), 13)
        self.assertTrue(all(len(line) <= 210 for line in lines))

    def test_nothing_finished_is_said_plainly(self):
        self.assertIn("no test finished", guard.why((2, [])))

    def test_require_run_prints_the_reason_before_failing(self):
        events = [ev("output", "TestW3_A01_Q", "    f_test.go:1: boom\n"), ev("fail", "TestW3_A01_Q"), ev("fail")]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(RuntimeError):
            guard.require_run((1, events), {"TestW3_A01_Q"}, "baseline label")
        self.assertIn("failed test TestW3_A01_Q", out.getvalue())
        self.assertIn("boom", out.getvalue())

    def test_matching_run_is_silent_and_ok(self):
        name = "TestW3_A01_Q_Carriers"
        guard.REAL.add(name)
        try:
            events = [ev("run", name), ev("pass", name), ev("pass")]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                guard.require_run((0, events), {name}, "ok label")
            self.assertEqual(out.getvalue().strip(), "ok   ok label")
        finally:
            guard.REAL.discard(name)


if __name__ == "__main__":
    unittest.main()
