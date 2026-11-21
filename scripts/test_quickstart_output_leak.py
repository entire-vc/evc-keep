#!/usr/bin/env python3
"""The quickstart check, its red runs and the W2 acceptance check must not
copy raw go test or step output into the CI log.

A step's output, the go test log and the log of a mutant run hold what the
server, the CLI and the leak tests printed; an assertion, a subtest name or a
panic that quotes what it saw would carry a value. The real scripts run here
on a copy of the tree with the outside world stubbed on PATH, on every path
that reports from such a log:

  redruns-wrong          a mutant of check-quickstart-redruns.sh fails without
                         the expected message: a fixed diagnostic is printed;
  redruns-wrong-no-line  the same with no such line in the log: a fixed text;
  redruns-dynamic        a FAIL quickstart line carries encoded canaries;
  redruns-duplicate      the real checker rejects a repeated canary-bearing ID;
  redruns-expected       a matching diagnostic has a canary-bearing suffix;
  step-scan-red          a quickstart step fails and the partial leak search
                         finds the value: nothing is printed;
  step-scan-skip         the step fails, the leak search exits 0 but skipped
                         TestQuickstartNoLeak: nothing is printed;
  step-scan-other-skip   the same with another leak test skipped;
  step-scan-none         the same with no test matched by -run;
  step-scan-pass         the leak search passed: the step's output is printed
                         (positive control: the guard does not hide output a
                         search has cleared);
  e2e-red                check-e2e-w2.sh, go test fails: only declared test
                         names and packages (scripts/test-result-names.sh);
  e2e-skip               go test passes with a skipped subtest;
  e2e-pass               go test passes: the check passes and prints names.
  raw-scan-red           the raw API leak test fails: declared test names and
                         fixed classes, without raw API paths or errors;
  full-scan-red          the final leak search fails: the same diagnostics,
                         without scanned file names.

The stubs print a canary in six encodings and in the shapes go test output
takes; the canary must not reach stdout or stderr. Positive controls: the
fixed message of what failed is printed, and with each call site put back to
its old raw print (tail, grep, cat without the search check) the same run leaks, so
the detector sees a leak on every path.
"""
import base64
import binascii
import io
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest
import urllib.parse

ROOT = Path(__file__).resolve().parent.parent
CHECK = "scripts/check-quickstart.sh"
REDRUNS = "scripts/check-quickstart-redruns.sh"
E2E = "scripts/check-e2e-w2.sh"
# What the copy of the tree holds: the scripts, and for the result filter the
# module and the tests whose declared names it may print.
FILES = (CHECK, REDRUNS, E2E, "docs/quickstart.md", "go.mod", "scripts/test-result-names.sh",
         "scripts/test-result-names.py", "test/e2e/w2_test.go", "test/e2e/world_test.go",
         "test/quickstart/leak_test.go")
REAL_BASH = shutil.which("bash")

# Each call site: the file, the code as it is, the old raw print.
REDRUNS_SITE = (REDRUNS,
                '\t\techo "(unexpected quickstart failure; raw diagnostics suppressed)"\n',
                '\t\ttail -15 "$log"\n')
PREFIX_SITE = (REDRUNS, REDRUNS_SITE[1],
               "\t\tgrep -m1 -- '^FAIL quickstart: ' \"$log\" || echo \"(no FAIL quickstart line)\"\n")
EXPECTED_SITE = (REDRUNS, '\t\techo "RED ok   $name: $want"\n',
                 '\t\techo "RED ok   $name: $(grep -m1 -- "$want" "$log" | sed \'s/^[[:space:]]*//\')"\n')
STEP_SITE = (CHECK,
             "\t\tgrep -q -- '--- PASS: TestQuickstartNoLeak' \"$work/go-test.log\" && "
             "! grep -q -- '--- SKIP' \"$work/go-test.log\" \\\n"
             '\t\t\t|| fail "the leak search after the failed step $id did not run '
             '(TestQuickstartNoLeak did not pass, or a test was skipped); nothing is printed"\n',
             "")
E2E_SITE = (E2E,
            '"$root/scripts/test-result-names.sh" "$root" <"$log" || echo "FAIL diagnostics: test-result-names.sh exited $?"\n'
            '[ "$status" -eq 0 ] || fail "go test exited $status"\n',
            "grep -E '^\\s*(---|ok|FAIL|PASS)' \"$log\" || true\n"
            '[ "$status" -eq 0 ] || { tail -40 "$log"; fail "go test exited $status"; }\n')
RAW_SCAN_SITE = (CHECK, 'scan_diagnostics "$work/go-raw.log"',
                 "grep -E '^\\s*(---|FAIL|ok|leak_test)' \"$work/go-raw.log\" || true")
FULL_SCAN_SITE = (CHECK, 'scan_diagnostics "$log"',
                  "grep -E '^\\s*(---|FAIL|ok|leak_test)' \"$log\" || true")
CALL_SITES = {
    "raw-scan-red": RAW_SCAN_SITE,
    "full-scan-red": FULL_SCAN_SITE,
    "e2e-red": E2E_SITE,
    "e2e-skip": E2E_SITE,
    "e2e-pass": E2E_SITE,
    "redruns-wrong": REDRUNS_SITE,
    "redruns-wrong-no-line": REDRUNS_SITE,
    "redruns-dynamic": PREFIX_SITE,
    "redruns-duplicate": PREFIX_SITE,
    "redruns-expected": EXPECTED_SITE,
    "step-scan-skip": STEP_SITE,
    "step-scan-other-skip": STEP_SITE,
    "step-scan-none": STEP_SITE,
}
SCAN_SKIPPED = "FAIL quickstart: the leak search after the failed step build did not run"
# What each path must still print: the fixed message of what failed.
CONTROLS = {
    "raw-scan-red": ("--- FAIL: TestRawAnswersNoLeak at test/quickstart/leak_test.go:",
                      "FAIL quickstart: a raw API answer carries the value"),
    "full-scan-red": ("--- FAIL: TestQuickstartNoLeak at test/quickstart/leak_test.go:",
                       "FAIL quickstart: the leak search failed"),
    "redruns-wrong": ("WRONG    bad-flag: failed, but without \"step audit exited non-zero\"; the check said:",
                      "\n(unexpected quickstart failure; raw diagnostics suppressed)\n", "FAIL quickstart red runs"),
    "redruns-wrong-no-line": ("WRONG    bad-flag: ", "\n(unexpected quickstart failure; raw diagnostics suppressed)\n", "FAIL quickstart red runs"),
    "redruns-dynamic": ("WRONG    bad-flag: ", "\n(unexpected quickstart failure; raw diagnostics suppressed)\n", "FAIL quickstart red runs"),
    "redruns-duplicate": ("WRONG    bad-flag: ", "\n(unexpected quickstart failure; raw diagnostics suppressed)\n", "FAIL quickstart red runs"),
    "redruns-expected": ("RED ok   bad-flag: step audit exited non-zero\n", "PASS quickstart red runs"),
    "step-scan-red": ("== build",
                      "FAIL quickstart: step build exited non-zero and a leak search found the value; "
                      "nothing is printed"),
    "step-scan-skip": ("== build", SCAN_SKIPPED),
    "step-scan-other-skip": ("== build", SCAN_SKIPPED),
    "step-scan-none": ("== build", SCAN_SKIPPED),
    "step-scan-pass": ("--- stdout\nharness step output\n--- stderr\nharness step error\n",
                       "FAIL quickstart: step build exited non-zero"),
    "e2e-red": ("--- FAIL: TestW2InputLinkToRunnerPlacement at test/e2e/w2_test.go:",
                "FAIL github.com/entire-vc/evc-keep/test/e2e", "FAIL e2e-w2: go test exited 1"),
    "e2e-skip": ("ok github.com/entire-vc/evc-keep/test/e2e",
                 "FAIL e2e-w2: a subtest was skipped; SKIP is not PASS"),
    "e2e-pass": ("ok github.com/entire-vc/evc-keep/test/e2e", "PASS e2e-w2"),
}
# Paths that pass.
GREEN = ("e2e-pass", "redruns-expected")
# What the e2e go stub prints after the canary noise, and its exit.
AGENT_READABLE = "--- PASS: TestW2InputLinkToRunnerPlacement/forbidden_targets/agent-readable_path (0.00s)\n"
E2E_RUN = {
    "e2e-red": ("    --- FAIL: TestW2InputLinkToRunnerPlacement/{base} (0.00s)\n"
                "--- FAIL: TestW2InputLinkToRunnerPlacement (0.00s)\nFAIL\n"
                "FAIL\tgithub.com/entire-vc/evc-keep/test/e2e\t1.000s\n", 1),
    "e2e-skip": ("    --- SKIP: TestW2InputLinkToRunnerPlacement/{base} (0.00s)\n" + AGENT_READABLE * 2 +
                 "--- PASS: TestW2InputLinkToRunnerPlacement (0.00s)\nPASS\n"
                 "ok  \tgithub.com/entire-vc/evc-keep/test/e2e\t1.000s\n", 0),
    "e2e-pass": ("    --- PASS: TestW2InputLinkToRunnerPlacement/{base} (0.00s)\n" + AGENT_READABLE * 2 +
                 "--- PASS: TestW2InputLinkToRunnerPlacement (0.00s)\nPASS\n"
                 "ok  \tgithub.com/entire-vc/evc-keep/test/e2e\t1.000s\n", 0),
}
# Paths that must print nothing of the step: no "--- stdout" header at all.
SILENT = ("step-scan-red", "step-scan-skip", "step-scan-other-skip", "step-scan-none")
# What the go stub prints for the partial leak search, and its exit.
SCAN = {
    "step-scan-red": ("=== RUN   TestQuickstartNoLeak\n--- FAIL: TestQuickstartNoLeak (0.00s)\nFAIL\n", 1),
    "step-scan-skip": ("=== RUN   TestQuickstartNoLeak\n--- SKIP: TestQuickstartNoLeak (0.00s)\nPASS\n", 0),
    "step-scan-other-skip": ("=== RUN   TestScanCanFail\n--- SKIP: TestScanCanFail (0.00s)\n"
                             "=== RUN   TestQuickstartNoLeak\n--- PASS: TestQuickstartNoLeak (0.00s)\nPASS\n", 0),
    "step-scan-none": ("testing: warning: no tests to run\nPASS\n"
                       "ok  \tgithub.com/entire-vc/evc-keep/test/quickstart\t0.01s [no tests to run]\n", 0),
    "step-scan-pass": ("=== RUN   TestQuickstartNoLeak\n--- PASS: TestQuickstartNoLeak (0.00s)\nPASS\n", 0),
}
STEPS = ("build", "migrate", "server-start", "bootstrap-org", "create-ref", "input-link", "open-link", "list-meta", "target",
         "mcp", "consumer", "restart-permission", "runner-enroll", "runner-start", "deploy-policy", "deploy",
         "deploy-outside-policy", "audit", "cleanup")
# The failing first step: its stdout, stderr and the server log carry the canary.
LEAKY_STEP = '''cat "$HARNESS_NOISE"
cat "$HARNESS_NOISE" >&2
mkdir -p "$HOME/keep-quickstart"
cat "$HARNESS_NOISE" >"$HOME/keep-quickstart/server.log"
exit 1
'''
CLEAN_STEP = 'echo "harness step output"\necho "harness step error" >&2\nexit 1\n'
SCAN_CLASSES = ("value canary found in", "db.pw found in", "root.key found in", "admin.token found in",
                "QS_CLI_TOKEN_FILE does not hold")
FULL_BUILD = r'''mkdir -p "$HOME/keep-quickstart"
printf '%s\n' 'KEEP_ORG=harness-org' 'SECRET_ID=harness-secret' 'KEEP_SERVER=http://harness.invalid' >"$HOME/keep-quickstart/env.sh"
printf '%s' harness-password >"$HOME/keep-quickstart/db.pw"
'''


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


def noise(base):
    """Canary-laden lines in the shapes go test and step output take."""
    enc = canary_encodings(base)
    lines = [f"    leak_test.go:{i + 1}: got {e} want x" for i, e in enumerate(enc)]
    lines += [f"    leak_test.go:330: {kind} /tmp/{e}/response?value={e}"
              for kind in SCAN_CLASSES for e in enc]
    lines += [f"=== RUN   TestQuickstartNoLeak/{base}",
              f"    leak_test.go:330: value canary found in {base}",
              f"Error: deploy failed: {base}",
              f"panic: {base} [recovered]",
              f"\t{base}.go:3 +0x1d",
              f"--- FAIL: TestQuickstartNoLeak/{base} (0.00s)",
              f"FAIL\tgithub.com/entire-vc/evc-keep/{base}\t0.010s"]
    return lines + lines[:len(enc)]  # canary-laden lines last, inside any tail


def doc(first_step, full=False):
    parts = ["# Quickstart (harness)\n"]
    for step in STEPS:
        mode = " human" if step == "open-link" else ""
        body = first_step if step == "build" else "true\n"
        if full:
            length = len("kc00112233445566778899aabb-v1-secret")
            body = {"build": FULL_BUILD, "list-meta": f"echo 'harness-fp {length}'\n",
                    "target": f"echo '600 {length} target'\n", "audit": "echo 'ok: true'\n"}.get(step, body)
        parts.append(f"<!-- quickstart: {step}{mode} -->\n```sh\n{body}```\n")
    return "\n".join(parts)


def stub(bin_dir, name, body):
    (bin_dir / name).write_text("#!/bin/sh\n" + body)
    (bin_dir / name).chmod(0o755)


GO_STUB = '''case "$1" in
test)
    if [ -n "${HARNESS_FULL:-}" ]; then
        case "$*" in
        *TestRawAnswersNoLeak*)
            if [ "$HARNESS_FULL" != raw-scan-red ]; then
                echo '--- PASS: TestRawAnswersNoLeak (0.00s)'; exit 0
            fi
            name=TestRawAnswersNoLeak ;;
        *) name=TestQuickstartNoLeak ;;
        esac
        cat "$HARNESS_NOISE"
        echo "--- FAIL: $name (0.00s)"
        echo FAIL
        exit 1
    fi
    [ -z "${HARNESS_E2E:-}" ] || cat "$HARNESS_NOISE"
    printf '%s' "$HARNESS_SCAN"; exit "$HARNESS_SCAN_RC" ;;
esac
echo "go stub: unexpected go $*" >&2
exit 3
'''
# The red runs' check: prints the canary around one fixed fail() line (or none).
CHECK_STUB = '''cat "$HARNESS_NOISE"
if [ -n "${HARNESS_EXPECTED:-}" ]; then
    while IFS= read -r value; do printf 'FAIL quickstart: step audit exited non-zero %s\\n' "$value"; done <"$HARNESS_NOISE"
    exit 1
fi
if [ -n "${HARNESS_DYNAMIC:-}" ]; then
    while IFS= read -r value; do printf 'FAIL quickstart: duplicate step %s\\n' "$value"; done <"$HARNESS_NOISE"
    exit 1
fi
[ -n "${HARNESS_NO_LINE:-}" ] || echo "FAIL quickstart: step deploy exited non-zero" >&2
cat "$HARNESS_NOISE" >&2
exit 1
'''


def run_path(path, old=False):
    """Runs one reporting path on a copy of the tree; returns (output, canary, exit)."""
    # Reserved URL characters and non-ASCII bytes distinguish URL escaping
    # and the standard/URL-safe base64 alphabets from the raw value.
    base = "kc" + secrets.token_hex(8) + "?+/\uffff"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        root = tmp / "repo"
        for name in FILES:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, root / name)
        if old:
            name, new, raw = CALL_SITES[path]
            text = (root / name).read_text()
            assert text.count(new) == 1, f"{path}: call site not found in {name}, update this test"
            (root / name).write_text(text.replace(new, raw))
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        for name in ("psql", "pkill", "node", "sudo", "systemctl", "make", "jq", "curl", "git"):
            stub(bin_dir, name, "exit 0\n")
        stub(bin_dir, "uname", "echo Linux\n")
        stub(bin_dir, "id", 'case "$1" in -u) echo 1000 ;; esac\nexit 0\n')
        stub(bin_dir, "openssl", "echo 00112233445566778899aabb\n")
        stub(bin_dir, "go", GO_STUB)
        if path in ("raw-scan-red", "full-scan-red"):
            stub(bin_dir, "node", 'cat >/dev/null\necho \'{"fingerprint":"harness-fp"}\'\n')
            stub(bin_dir, "jq", '''case "$1:$2" in
-r:.fingerprint) echo harness-fp ;;
-r:.request_id) echo harness-id ;;
-r:.url) echo http://harness.invalid ;;
-n:*) echo '{}' ;;
-e:*) exit 0 ;;
*) echo 'jq stub: unexpected query' >&2; exit 3 ;;
esac
''')
            stub(bin_dir, "psql", '''case "$*" in
*"SELECT tablename"*) exit 0 ;;
*) echo '[]' ;;
esac
''')
        noise_file = tmp / "noise"
        noise_file.write_text("\n".join(noise(base)) + "\n")
        home = tmp / "home"
        scratch = tmp / "scratch"
        home.mkdir()
        scratch.mkdir()
        env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(home), "TMPDIR": str(scratch),
               "LC_ALL": "C", "HARNESS_NOISE": str(noise_file), "CHROME_BIN": str(bin_dir / "node"),
               "GOCACHE": str(scratch / "gocache"), "GOMODCACHE": str(scratch / "gomodcache")}
        if path.startswith("e2e-"):
            body, rc = E2E_RUN[path]
            env.update({"HARNESS_E2E": "1", "HARNESS_SCAN": body.format(base=base), "HARNESS_SCAN_RC": str(rc),
                        "KEEP_DATABASE_URL": "postgres://harness@harness.invalid:1/keep"})
            script = E2E
        elif path.startswith("redruns-"):
            check = root / CHECK
            if path == "redruns-duplicate":
                page = root / "docs/quickstart.md"
                fragment = f"<!-- quickstart: {base.encode().hex()} -->\n```sh\ntrue\n```\n"
                page.write_text(fragment * 2 + page.read_text())
                # Positive control: the real checker reaches the duplicated ID
                # before the wrapper runs it on the deliberately mutated page.
                control = subprocess.run([REAL_BASH, str(check)], cwd=root, env=env,
                                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, timeout=30)
                text = control.stdout.decode("utf-8", errors="replace")
                assert control.returncode != 0 and "duplicate step" in text and leaked(text, base), \
                    "real checker duplicate-ID positive control missing"
            else:
                check.write_text("#!/bin/sh\n" + CHECK_STUB)
            if path == "redruns-dynamic":
                env["HARNESS_DYNAMIC"] = "1"
            if path == "redruns-expected":
                env["HARNESS_EXPECTED"] = "1"
            if path == "redruns-wrong-no-line":
                env["HARNESS_NO_LINE"] = "1"
            env["QS_ONLY"] = "^bad-flag$"
            script = REDRUNS
        else:
            page = tmp / "quickstart.md"
            full = path in ("raw-scan-red", "full-scan-red")
            page.write_text(doc(CLEAN_STEP if path == "step-scan-pass" else LEAKY_STEP, full=full))
            env["QUICKSTART_DOC"] = str(page)
            if full:
                env["HARNESS_FULL"] = path
            else:
                env["HARNESS_SCAN"], rc = SCAN[path]
                env["HARNESS_SCAN_RC"] = str(rc)
            script = CHECK
        run = subprocess.run([REAL_BASH, str(root / script)], cwd=root, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        return run.stdout.decode("utf-8", errors="replace"), base, run.returncode


class QuickstartOutputLeak(unittest.TestCase):
    maxDiff = None

    def check_output(self, path, out, base, rc):
        needles = CONTROLS[path]
        # unittest's equality/membership helpers include operands in failures.
        # Only booleans and closed diagnostic text may reach the report.
        self.assertFalse(bool(leaked(out, base)), f"{path}: canary in the output")
        self.assertTrue((rc == 0) == (path in GREEN), f"{path}: unexpected exit status")
        self.assertFalse("stub: unexpected" in out, f"{path}: a stub was called unexpectedly")
        for needle in needles:
            self.assertTrue(needle in out, f"{path}: the fixed message is missing")
        if path in ("raw-scan-red", "full-scan-red"):
            for kind in SCAN_CLASSES:
                self.assertTrue(kind in out, f"{path}: a fixed class is missing")
        if path in SILENT:
            self.assertFalse("--- stdout" in out, f"{path}: the step output was printed")

    def test_no_canary_on_any_path(self):
        for path in CONTROLS:
            with self.subTest(path=path):
                out, base, rc = run_path(path)
                self.check_output(path, out, base, rc)

    def test_failure_report_does_not_repeat_canary(self):
        # Exercise the actual assertion path with the old scanner restored,
        # capturing the failing unittest report instead of publishing it.
        out, base, rc = run_path("full-scan-red", old=True)
        checker = self

        class Probe(unittest.TestCase):
            def runTest(self):
                checker.check_output("full-scan-red", out, base, rc)

        capture = io.StringIO()
        result = unittest.TextTestRunner(stream=capture).run(Probe())
        self.assertTrue(len(result.failures) == 1 and not result.errors,
                        "restored scanner did not produce the expected assertion failure")
        self.assertFalse(bool(leaked(capture.getvalue(), base)),
                         "unittest failure report repeated a canary encoding")

    def test_old_raw_print_leaks(self):
        """Control: each call site put back to its old raw print leaks on its path."""
        for path in CALL_SITES:
            with self.subTest(path=path):
                out, base, _ = run_path(path, old=True)
                self.assertTrue(bool(leaked(out, base)), f"{path}: the old print did not leak")
                if path in ("raw-scan-red", "full-scan-red"):
                    self.assertTrue(CONTROLS[path][-1] in out, f"{path}: the scanner failure was not reached")


class CanaryEncodings(unittest.TestCase):
    def test_six_encodings_found_in_their_contexts(self):
        base = "kc" + secrets.token_hex(8) + "?+/\uffff"
        self.assertEqual(len(canary_encodings(base)), 10)
        self.assertEqual(len(set(canary_encodings(base)[:4])), 4)
        for prefix in (b"", b"u", b"us", b"user:"):
            for enc in (base64.standard_b64encode, base64.urlsafe_b64encode):
                text = enc(prefix + base.encode() + b"!").decode()
                self.assertTrue(bool(leaked(text, base)), "base64 context encoding was not detected")
        for text in (base, base.upper(), binascii.hexlify(base.encode()).decode(), base[::-1],
                     urllib.parse.quote_plus(base)):
            self.assertTrue(bool(leaked("x " + text + " y", base)), "canary encoding was not detected")
        self.assertFalse(bool(leaked("nothing here", base)), "clean text was marked as a leak")


if __name__ == "__main__":
    unittest.main(verbosity=2)
