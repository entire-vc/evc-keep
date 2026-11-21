#!/usr/bin/env python3
"""The upgrade-rollback check and its red runs must not copy probe or check
output into the CI log.

The probe (go test -tags upgradeprobe) holds the canary and the root key, and
the check's own output holds what psql, docker and the server printed; an
assertion, a subtest name or a panic that quotes what it saw would carry a
value. The real scripts run here on a copy of the tree with the outside world
stubbed on PATH (go, psql, pg_dump, pg_restore, curl, jq; bash for the outer
scan), on every path that reports from such a log:

  scan-red    the outer canary scan fails (check-upgrade-rollback.sh, the
              report after the scan);
  scan-green  the outer canary scan passes (the "scanned N bytes" line; the
              run's own output is printed, after the scan);
  stream      the inner run prints the canary itself: its output goes to a
              file that is scanned first and, dirty, never printed (the
              control puts the old `| tee` back and the canary streams out);
  late        a writer that outlived the run appends the canary to the run's
              file while the canary scan runs: the snapshot that was scanned
              is what is printed (control: print the live file);
  short       the canary scan passes but reports fewer bytes than the
              snapshot holds: the log is not printed (control: no size check);
  orphan      the run ends normally and leaves a process of its group
              behind: the check stops it (OrphanStopped; control: without the
              stop after the run the process outlives the check);
  hang        the run hangs with a child that ignores TERM, under a 3s limit:
              the check ends it with "the run exceeded", prints the scanned
              output and leaves no child (HangStopped; controls: KILL to the
              pid only, no timeout flag);
  first       the password is printed on the statement right after it is made,
              before any psql: the scan sees it (FirstStatement; control: the
              password listed only after psql, as before, reaches the output);
  probe       the inner probe seal fails (the probe report);
  early       the inner run prints the database password and fails before
              the seal (the password scan must still run);
  baseline    the mutation driver's unmutated check is red;
  mutant      a mutant is red with the wrong message.

The stubs print a canary in six encodings and in the shapes go test output
takes; the canary must not reach stdout or stderr. Positive controls: the
fixed message of the failed check is printed, and with each call site put
back to its old raw print (tail, grep, sed) the same run leaks, so the
detector sees a leak on every path.
"""
import base64
import binascii
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import unittest
import urllib.parse

ROOT = Path(__file__).resolve().parent.parent
CHECK = "scripts/check-upgrade-rollback.sh"
DRIVER = "scripts/check-upgrade-rollback-mutations.sh"
REPORT = "scripts/upgrade-rollback-report.sh"
PROBE = "cmd/keep-server/app/upgrade_probe_test.go"
FILES = (CHECK, DRIVER, REPORT, PROBE, "go.mod", "docs/deploy.md",
         "scripts/temp-workspace.sh", "scripts/mutation-helpers.sh")
REAL_BASH = shutil.which("bash")

# Each call site: the file, the line(s) as they are, the old raw print.
CALL_SITES = {
    "late": (CHECK, '\tcat "$work/scanned.log"\n', '\tcat "$work/job.log"\n'),
    "short": (CHECK, '\t\t\tif [ "$scanned" != "$size" ]; then\n', '\t\t\tif false; then\n'),
    "stream": (CHECK, '\tUPG_INNER=1 bash "$0" "$@" >"$work/job.log" 2>&1 </dev/null &\n',
               '\tUPG_INNER=1 bash "$0" "$@" 2>&1 </dev/null | tee "$work/job.log" &\n'),
    "scan-red": (CHECK, '\t\t\t"$root/scripts/upgrade-rollback-report.sh" "$work/scan.out" || true\n',
                 '\t\t\ttail -8 "$work/scan.out"\n'),
    "scan-green": (CHECK, '\t[ -z "$scanned" ] || echo "ok: scanned $scanned bytes of job output: '
                          'the canary is absent"\n',
                   "\tgrep -E 'scanned [0-9]+ bytes' \"$work/scan.out\" || true\n"),
    "probe": (CHECK, '|| { "$root/scripts/upgrade-rollback-report.sh" "$work/probe.log" "probe: " || true; '
                     'fail "probe $1 in $2"; }',
              '|| { sed \'s/^/probe: /\' "$work/probe.log" | tail -15; fail "probe $1 in $2"; }'),
    "baseline": (DRIVER, '\t"$root/scripts/upgrade-rollback-report.sh" "$work/out" || true; echo "FAIL baseline',
                 '\ttail -15 "$work/out"; echo "FAIL baseline'),
    "mutant": (DRIVER, '\t\t"$root/scripts/upgrade-rollback-report.sh" "$work/out" || true; echo "FAIL $name',
               '\t\ttail -8 "$work/out"; echo "FAIL $name'),
}
# What each path must still print: the fixed message of what failed.
CONTROLS = {
    "scan-red": ("the canary appears in the job output",
                 "FAIL upgrade-rollback: the canary scan of the job output failed"),
    "scan-green": ("inner: harness", "bytes of job output: the canary is absent"),
    "late": ("inner: harness", "bytes of job output: the canary is absent"),
    "short": ("FAIL upgrade-rollback: the canary scan read 1 bytes",
              "upgrade-rollback: the job output is not printed"),
    "stream": ("upgrade-rollback: the job output is not printed",
               "FAIL upgrade-rollback: the canary scan of the job output failed"),
    "probe": ("probe: seal canary: ", "FAIL upgrade-rollback: probe seal in "),
    "early": ("FAIL upgrade-rollback: stopped before the seal",
              "FAIL upgrade-rollback: the job output carries the database password or the root key"),
    "baseline": ("FAIL upgrade-rollback: the canary scan of the job output failed",
                 "FAIL baseline: the unmutated check is red"),
    "mutant": ("FAIL upgrade-rollback: the canary scan of the job output failed",
               "FAIL no-pg-dump: red, but not with 'the upgrade block wrote no backup'"),
}


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
    """Canary-laden lines in the shapes go test output takes, the canary also
    glued to the fixed messages the report prints."""
    enc = canary_encodings(base)
    lines = [f"    upgrade_probe_test.go:{i + 1}: got {e} want x" for i, e in enumerate(enc)]
    lines += [f"=== RUN   TestUpgradeProbe/{base}",
              f"    upgrade_probe_test.go:139: the canary appears in the job output: {base}",
              f"    upgrade_probe_test.go:100: seal canary: pq: password authentication failed {base}",
              f"FAIL upgrade-rollback: the canary scan of the job output failed {base}",
              f"panic: {base} [recovered]",
              f"\t{base}.go:3 +0x1d",
              f"--- FAIL: TestUpgradeProbe/{base} (0.00s)",
              f"FAIL\tgithub.com/entire-vc/evc-keep/{base}\t0.010s"]
    return lines + lines[:len(enc)]  # canary-laden lines last, inside any tail


GO_STUB = r'''#!/bin/sh
case "$1" in
build)
	out=""
	while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done
	cat >"$out" <<'EOF'
#!/bin/sh
case "$1 $2" in
"migrate up") exit 0 ;;
"migrate status") echo "up to date at version 5"; exit 0 ;;
"bootstrap-org "*) echo "org_id=org-harness"; exit 0 ;;
esac
[ -n "$1" ] || exec sleep 60
exit 0
EOF
	chmod +x "$out"; exit 0 ;;
test) ;;
*) exit 0 ;;
esac
case "${KEEP_PROBE_ACTION:-}:$HARNESS_MODE" in
scan:late)
	echo "late: $HARNESS_CANARY" >>"$(dirname "$KEEP_PROBE_LOG")/job.log"
	echo "    upgrade_probe_test.go:141: scanned $(wc -c <"$KEEP_PROBE_LOG" | tr -d ' ') bytes of job output: the canary is absent"
	echo "--- PASS: TestUpgradeProbe (0.00s)"; echo PASS; exit 0 ;;
scan:short)
	echo "    upgrade_probe_test.go:141: scanned 1 bytes of job output: the canary is absent"
	echo "--- PASS: TestUpgradeProbe (0.00s)"; echo PASS; exit 0 ;;
scan:scan-green | scan:orphan | scan:hang)
	echo "=== RUN   TestUpgradeProbe"
	echo "    upgrade_probe_test.go:141: scanned $(wc -c <"$KEEP_PROBE_LOG" | tr -d ' ') bytes of job output: the canary is absent $HARNESS_CANARY"
	cat "$HARNESS_NOISE"
	echo "--- PASS: TestUpgradeProbe (0.00s)"; echo PASS; exit 0 ;;
scan:*|seal:*)
	echo "=== RUN   TestUpgradeProbe"
	cat "$HARNESS_NOISE"; echo FAIL; exit 1 ;;
esac
echo "go stub: unexpected probe action ${KEEP_PROBE_ACTION:-none} in $HARNESS_MODE" >&2
exit 3
'''
STUBS = {
    "go": GO_STUB,
    "psql": '#!/bin/sh\nfor a in "$@"; do case $a in -Atc) echo 5; exit 0 ;; -c) exit 0 ;; esac; done\ncat >/dev/null\n',
    "pg_dump": "#!/bin/sh\nexit 0\n",
    "pg_restore": "#!/bin/sh\nexit 0\n",
    "curl": '#!/bin/sh\ncase "$*" in\n*http_code*) printf 200 ;;\n'
            '*/version*) printf \'{"commit":"%s"}\' "$HARNESS_SHA" ;;\nesac\n',
    "jq": "#!/bin/sh\nsed -n 's/.*\"commit\":\"\\([0-9a-f]*\\)\".*/\\1/p'\n",
}
# The outer scan: the inner run only leaves a canary to scan for. Any other
# bash (a #!/usr/bin/env bash script) is the real one.
BASH_STUB = '''#!/bin/sh
if [ -n "${UPG_INNER:-}" ]; then
	mkdir -p "$UPG_WORK/state" && printf '%s' "$HARNESS_CANARY" >"$UPG_WORK/state/canary.value"
	case "$HARNESS_MODE" in stream | short) cat "$HARNESS_NOISE" ;; esac
	if [ "$HARNESS_MODE" = orphan ]; then sleep 60 & echo $! >"$HARNESS_ORPHAN"; fi
	echo "inner: harness"
	if [ "$HARNESS_MODE" = hang ]; then
		sh -c 'trap "" TERM; exec sleep 120' & echo $! >"$HARNESS_ORPHAN"
		sleep 120
	fi
	exit 0
fi
exec "$HARNESS_BASH" "$@"
'''
# The driver's check: a copy of the real script that prints the canary and is
# red before it does anything (the fixed messages and mutant anchors stay).
CHECK_RED = '''if [ -n "${HARNESS_CHECK_RED:-}" ]; then
	cat "$HARNESS_NOISE"
	echo "FAIL upgrade-rollback: the canary scan of the job output failed" >&2
	exit 1
fi
'''


# The password printed before the canary is sealed, then a failure.
EARLY_ANCHOR = 'start_server "$work/bin-old/keep-server"'
EARLY_LEAK = 'echo "psql: password authentication failed: $pw"; fail "stopped before the seal"\n'
# The password printed on the statement after it is made, before any psql.
FIRST_ANCHOR = 'head -c 32 /dev/urandom >"$work/root.key"'
FIRST_MARK = "UPGLEAKMARK"
FIRST_LEAK = f'echo "{FIRST_MARK} $pw"; fail "stopped before psql"\n'


def bad_entries(entries):
    """List entries the report must not rely on: empty, shorter than six
    characters or without a letter (they would count punctuation)."""
    return [e for e in entries if len(e) < 6 or not re.search("[A-Za-z]", e)]


def run_path(path, old=False, edits=(), orphan_file=None, timeout=300):
    """Runs one reporting path on a copy of the tree; returns (output, canary).
    edits: (old, new) replacements in the check's copy, each found once;
    orphan_file: where the orphan and hang paths' inner run writes the pid of
    the process it leaves behind."""
    base = "kc" + secrets.token_hex(8)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        root = tmp / "repo"
        for name in FILES:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, root / name)
        shutil.copytree(ROOT / "scripts/lib", root / "scripts/lib")
        if old:
            name, new, raw = CALL_SITES[path]
            text = (root / name).read_text()
            assert text.count(new) == 1, f"{path}: call site not found in {name}, update this test"
            (root / name).write_text(text.replace(new, raw))
        for edit_old, edit_new in edits:
            check = root / CHECK
            text = check.read_text()
            assert text.count(edit_old) == 1, f"{path}: text to edit not in the check, update this test"
            check.write_text(text.replace(edit_old, edit_new))
        if path == "first":
            check = root / CHECK
            text = check.read_text()
            assert text.count(FIRST_ANCHOR) == 1, "first: anchor not in the check, update this test"
            check.write_text(text.replace(FIRST_ANCHOR, FIRST_LEAK + FIRST_ANCHOR))
        if path in ("baseline", "mutant"):
            check = root / CHECK
            first, rest = check.read_text().split("\n", 1)
            check.write_text(first + "\n" + CHECK_RED + rest)
        if path == "early":
            check = root / CHECK
            text = check.read_text()
            assert text.count(EARLY_ANCHOR) == 1, "early: anchor not in the check, update this test"
            check.write_text(text.replace(EARLY_ANCHOR, EARLY_LEAK + EARLY_ANCHOR))
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        stubs = dict(STUBS)
        if path in ("scan-red", "scan-green", "stream", "late", "short", "orphan", "hang"):
            stubs["bash"] = BASH_STUB
        for name, body in stubs.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        noise_file = tmp / "noise"
        noise_file.write_text("\n".join(noise(base)) + "\n")
        scratch = tmp / "scratch"
        scratch.mkdir()
        env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp), "TMPDIR": str(scratch),
               "LC_ALL": "C", "HARNESS_MODE": path, "HARNESS_CANARY": base, "HARNESS_NOISE": str(noise_file),
               "HARNESS_BASH": REAL_BASH, "KEEP_ADMIN_URL": "postgres://harness@harness.invalid:1/postgres",
               "HARNESS_ORPHAN": str(orphan_file or tmp / "orphan.pid")}
        if path == "hang":
            env["KEEP_UPGRADE_INNER_TIMEOUT"] = "3"
        git = ["git", "-c", "user.name=harness", "-c", "user.email=harness@example.test", "-c", "commit.gpgsign=false"]
        for argv in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "harness"], ["tag", "0.6.5"]):
            subprocess.run(git + argv, cwd=root, env=env, check=True, stdout=subprocess.DEVNULL)
        env["HARNESS_SHA"] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, env=env, check=True,
                                            stdout=subprocess.PIPE).stdout.decode().strip()
        if path in ("baseline", "mutant"):
            env["HARNESS_CHECK_RED"] = "1"
            if path == "mutant":
                env["REDRUN_ONLY"] = "no-pg-dump"
            script = DRIVER
        else:
            script = CHECK
        run = subprocess.run([REAL_BASH, str(root / script)], cwd=root, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        out = run.stdout.decode("utf-8", errors="replace")
        return out, base, run.returncode


class UpgradeRollbackOutputLeak(unittest.TestCase):
    maxDiff = None

    def test_no_canary_on_any_path(self):
        for path, needles in CONTROLS.items():
            with self.subTest(path=path):
                out, base, rc = run_path(path)
                self.assertEqual(leaked(out, base), [], f"{path}: canary in the output:\n{out[-4000:]}")
                self.assertEqual(rc == 0, path in ("scan-green", "late"), f"{path}: exit {rc}:\n{out[-2000:]}")
                for needle in needles:
                    self.assertIn(needle, out, f"{path}: the fixed message is missing:\n{out[-2000:]}")
                if path not in ("scan-green", "early", "late"):
                    self.assertRegex(out, r"not printed: [1-9][0-9]* lines", f"{path}: no count:\n{out[-2000:]}")

    def test_old_raw_print_leaks(self):
        """Control: each call site put back to its old raw print leaks on its path."""
        for path in CALL_SITES:
            with self.subTest(path=path):
                out, base, _ = run_path(path, old=True)
                self.assertNotEqual(leaked(out, base), [], f"{path}: the old print did not leak:\n{out[-2000:]}")


STOP_AFTER_RUN = "\tstop_inner # whatever of the group outlived the run\n"


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class OrphanStopped(unittest.TestCase):
    def orphan_alive(self, drop=None):
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / "orphan.pid"
            out, _, rc = run_path("orphan", edits=[(drop, "")] if drop else (), orphan_file=pid_file)
            self.assertEqual(rc, 0, out[-2000:])
            pid = int(pid_file.read_text())
            try:
                return alive(pid)
            finally:
                if alive(pid):
                    os.kill(pid, 9)

    def test_left_process_is_stopped(self):
        self.assertFalse(self.orphan_alive(), "a process of the run's group outlived the check")

    def test_without_the_stop_it_outlives(self):
        """Control: without the stop after the run the same process is still there."""
        self.assertTrue(self.orphan_alive(drop=STOP_AFTER_RUN), "the orphan died by itself: the test proves nothing")


KILL_GROUP = '\t\tkill -KILL -- "-$inner" 2>/dev/null || true\n'
TIMED_OUT = "\t\ttimed_out=1\n"


class HangStopped(unittest.TestCase):
    def run_hang(self, edits=()):
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / "hang.pid"
            out, _, rc = run_path("hang", edits=edits, orphan_file=pid_file, timeout=120)
            pid = int(pid_file.read_text())
            survived = alive(pid)
            if survived:
                os.kill(pid, 9)
            return out, rc, survived

    def test_hang_is_ended_whole(self):
        out, rc, survived = self.run_hang()
        self.assertNotEqual(rc, 0, out[-2000:])
        self.assertIn("FAIL upgrade-rollback: the run exceeded 3s", out)
        self.assertIn("inner: harness", out, "the scanned output was not printed")
        self.assertFalse(survived, "a child that ignores TERM outlived the check")

    def test_kill_to_the_pid_only_leaves_the_child(self):
        """Control: KILL sent to the pid instead of the group leaves the child."""
        _, _, survived = self.run_hang([(KILL_GROUP, KILL_GROUP.replace('-- "-$inner"', '"$inner"'))])
        self.assertTrue(survived, "the child died anyway: the test proves nothing")

    def test_without_the_flag_no_message(self):
        """Control: without the timeout flag the run's end is not named."""
        out, rc, _ = self.run_hang([(TIMED_OUT, "\t\t:\n")])
        self.assertNotIn("the run exceeded", out)


# secrets.txt as on 86f2e96e: the password lives in a variable and is listed
# only after the first psql.
LISTED_FIRST = ("""( umask 077; printf 'upg%s\\n' "$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \\n')" >"$work/secrets.txt" )\n"""
                """pw=$(head -n 1 "$work/secrets.txt")\n""")
LISTED_LATE = """pw="upg$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \\n')"\n"""
AFTER_PSQL = """psql "$admin_db" -v ON_ERROR_STOP=1 -q -c 'ALTER SCHEMA public OWNER TO keepupg' >/dev/null\n"""


class FirstStatement(unittest.TestCase):
    def test_password_printed_first_is_found(self):
        out, _, rc = run_path("first")
        self.assertNotEqual(rc, 0, out[-2000:])
        self.assertNotIn(FIRST_MARK, out)
        self.assertIn("FAIL upgrade-rollback: the job output carries the database password or the root key", out)

    def test_listed_after_psql_it_leaks(self):
        """Control: listed after psql, as before, the same password reaches the output."""
        out, _, _ = run_path("first", edits=[(LISTED_FIRST, LISTED_LATE),
                                             (AFTER_PSQL, AFTER_PSQL + """printf '%s\\n' "$pw" >>"$work/secrets.txt"\n""")])
        self.assertIn(FIRST_MARK, out)


def call_sites(probe, check):
    """Independent count of the report's sources: t.Fatal/t.Fatalf calls in
    the probe, fail "..." calls and echo "FAIL upgrade-rollback: ..." lines
    (not the one inside fail() itself) in the check."""
    fatal = len(re.findall(r't\.Fatalf?\("', probe))
    fails = len(re.findall(r'(?:^|[^A-Za-z0-9_])fail "', check, re.M))
    echoes = len(re.findall(r'echo "FAIL upgrade-rollback: [^"$]', check))
    return fatal, fails, echoes


class ReportList(unittest.TestCase):
    def list_of(self, root):
        run = subprocess.run([REAL_BASH, str(root / REPORT), "--list"], check=True, stdout=subprocess.PIPE)
        return run.stdout.decode().split("\n")[:-1]

    def copy(self, tmp):
        root = Path(tmp)
        for name in (CHECK, REPORT, PROBE):
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, root / name)
        return root

    def test_every_call_site_has_a_message(self):
        fatal, fails, echoes = call_sites((ROOT / PROBE).read_text(), (ROOT / CHECK).read_text())
        self.assertGreater(fatal, 10)
        self.assertGreater(fails, 30)
        self.assertGreaterEqual(echoes, 3)
        entries = self.list_of(ROOT)
        self.assertEqual(len(entries), fatal + fails + echoes, entries)
        self.assertEqual(bad_entries(entries), [], "a call site without enough literal text")
        self.assertIn("the canary appears in the job output", entries)
        self.assertIn("FAIL upgrade-rollback: the sealed canary's state is malformed", entries)
        self.assertIn(" is not set", entries)  # t.Fatalf("%s is not set", ...)
        self.assertIn(" is required", entries)  # fail "$t is required"

    def test_self_check_sees_a_message_without_text(self):
        """Control: a fail whose message is all expansion, and a t.Fatalf that
        is all verb, show up as empty entries the check above rejects."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self.copy(tmp)
            with open(root / CHECK, "a") as f:
                f.write('fail "$secret_value"\nfail "$a: $b"\n')
            with open(root / PROBE, "a") as f:
                f.write('func x(t *testing.T) { t.Fatalf("%v", v) }\n')
            entries = self.list_of(root)
            self.assertEqual(sorted(bad_entries(entries)), ["", "", ": "], entries)
            log = root / "log"
            log.write_text("a: b\nc: d\n")
            run = subprocess.run([REAL_BASH, str(root / REPORT), str(log)], check=True, stdout=subprocess.PIPE)
            self.assertEqual(run.stdout.decode(), "not printed: 2 lines\n", "a short entry reached the output")

    def test_report_prints_only_listed_messages(self):
        base = "kc" + secrets.token_hex(8)
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "log"
            log.write_bytes(("\n".join(noise(base)) + "\nplain line\n").encode()
                            + b"\xff\xfe " + base.encode() + b"\0 not text\n")
            run = subprocess.run([REAL_BASH, str(ROOT / REPORT), str(log), "probe: "], check=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = run.stdout.decode()
            self.assertEqual(leaked(out, base), [], out)
            listed = set(self.list_of(ROOT)) | {"FAIL upgrade-rollback: "}
            lines = out.split("\n")[:-1]
            # busybox grep reads the NUL line as two lines, GNU and BSD as one.
            count = re.fullmatch(r"probe: not printed: ([0-9]+) lines", lines[-1])
            self.assertTrue(count, lines[-1])
            self.assertIn(int(count.group(1)), (len(noise(base)) + 2 - 3, len(noise(base)) + 3 - 3), lines[-1])
            for line in lines[:-1]:
                self.assertTrue(line.startswith("probe: ") and line[len("probe: "):] in listed, line)
            self.assertIn("probe: the canary appears in the job output", lines)


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
