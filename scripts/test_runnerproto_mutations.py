"""Exercise real shell verdicts/argv with subprocess faults; no Go/DB/browser."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "scripts/check-runnerproto-mutations.sh").read_text()
PREFIX = SOURCE.split("# Signed job:", 1)[0]
BASELINE = SOURCE[SOURCE.index('# And the unmutated tree'):]


class RunnerWitness(unittest.TestCase):
    def execute(self, form="mutate", mode="failure", witness="TestWitness", race=False, strict=False):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "scripts/lib").mkdir(parents=True)
            (root / "pkg/runnerproto").mkdir(parents=True)
            (root / "go.mod").write_text("module fixture\n")
            (root / "pkg/runnerproto/value.go").write_text('e.str(tagSecretScope, j.Secret.Scope)\nx = 1\n')
            for path in ("mutation-helpers.sh", "temp-workspace.sh", "lib/gocache.sh"):
                shutil.copy(ROOT / "scripts" / path, root / "scripts" / path)
            # The real prefix runs its own six strict subprocess fault controls.
            args = (f"control value.go '{witness}' 'x = 1' 'x = 2'" if form == "mutate"
                    else f"control '{witness}' value.go 'x = 1' 'x = 2'")
            flags = ("RACE=1 " if race else "") + ("FAIL_LINE_ONLY=1 " if strict else "")
            script = root / "scripts/check.sh"
            script.write_text(PREFIX + f"\n{flags}{form} {args}\n" + BASELINE)
            fake = root / "bin"
            fake.mkdir()
            (fake / "go").write_text("""#!/usr/bin/env python3
import json, os, re, sys
args=sys.argv[1:]
with open(os.environ['ARGV_LOG'],'a') as f: f.write(json.dumps(args)+'\\n')
if '-run' not in args:
    sys.exit(1 if os.environ['FAULT']=='baseline' else 0)
pattern=args[args.index('-run')+1]
name=pattern[1:-1]
fault=os.environ['FAULT']
if fault=='missing': print('testing: warning: no tests to run'); sys.exit(0)
if fault=='wrong': print('--- FAIL: TestOther (0.00s)'); sys.exit(1)
if fault=='killed': print('signal: killed'); sys.exit(137)
if fault=='crash': print('panic: synthetic failure\\nrunnerproto.'+name+'.func1()'); sys.exit(1)
print('--- FAIL: '+name+' (0.00s)')
if fault=='timeout': print('panic: test timed out after 2m0s')
if fault=='build': print('FAIL package [build failed]')
if fault=='setup': print('FAIL package [setup failed]')
sys.exit(1)
""")
            (fake / "go").chmod(0o755)
            log = root / "argv"
            env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ["PATH"],
                       ARGV_LOG=str(log), FAULT=mode, GOCACHE=str(root / "cache"))
            run = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
            rows = [json.loads(s) for s in log.read_text().splitlines()] if log.exists() else []
            return run.returncode, rows, run.stdout

    def test_both_mutators_use_exact_anchored_witness_and_full_baseline(self):
        for form in ("mutate", "mutateN"):
            for race in (False, True):
                rc, rows, _ = self.execute(form=form, race=race)
                self.assertEqual(rc, 0)
                wanted = ["test", "-timeout", "120s", "-count=1"] + (["-race"] if race else [])
                self.assertEqual(rows, [wanted + ["-run", "^TestWitness$", "./pkg/runnerproto/"],
                                        ["test", "-timeout", "120s", "-count=1", "./pkg/runnerproto/"]])

    def test_wrong_missing_killed_and_process_timeout_cannot_kill_mutant(self):
        for form in ("mutate", "mutateN"):
            for fault in ("wrong", "missing", "killed", "timeout"):
                with self.subTest(form=form, fault=fault):
                    rc, _, _ = self.execute(form=form, mode=fault)
                    self.assertNotEqual(rc, 0)

    def test_strict_build_setup_and_own_crash_are_rejected(self):
        for fault in ("build", "setup", "crash"):
            self.assertNotEqual(self.execute(mode=fault, strict=True)[0], 0)
        self.assertEqual(self.execute(mode="crash")[0], 0)

    def test_full_baseline_failure_cannot_be_rescued_by_named_red(self):
        self.assertNotEqual(self.execute(mode="baseline")[0], 0)

    def test_unsupported_witness_never_reaches_go_mutant_run(self):
        for form in ("mutate", "mutateN"):
            for witness in ("Test", "Other", "TestWitness|TestOther", "TestWitness/subtest"):
                rc, rows, _ = self.execute(form=form, witness=witness)
                self.assertNotEqual(rc, 0)
                self.assertEqual(rows, [["test", "-timeout", "120s", "-count=1", "./pkg/runnerproto/"]])


class InfrastructureCounts(unittest.TestCase):
    def verdict(self, helper, output, allow_connect=False):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "helper").write_text(helper)
            (root / "output").write_text(output)
            run = subprocess.run(["sh", "-c",
                                  '. "$1/helper"; name=fixture; mutation_connect_faults_are_mutants="$2"; '
                                  'if mutation_infrastructure_failed "$1/output"; then exit 0; else exit 1; fi',
                                  "fixture", str(root), "1" if allow_connect else "0"], capture_output=True, text=True)
            return run.returncode, run.stdout

    def test_fixed_signatures_counts_and_secret_absence_preserve_all_verdicts(self):
        new = (ROOT / "scripts/mutation-helpers.sh").read_text()
        old = subprocess.check_output(["git", "-C", str(ROOT), "show", "HEAD:scripts/mutation-helpers.sh"]).decode()
        signatures = {"process_timeout": "panic: test timed out",
                      "database_deadline": "database operation deadline exceeded",
                      "scratch_create": "create scratch database failed",
                      "admin_pool_open": "open admin pool on scratch database failed",
                      "database_connect": "connection failed (unclassified)"}
        canary = "private-output-canary-never-print"
        cases = [s + " " + canary for s in signatures.values()]
        cases += ["context deadline exceeded " + canary, "--- FAIL: TestGuard " + canary,
                  "\n".join(cases) + "\n" + signatures["process_timeout"]]
        for output in cases:
            for allow in (False, True):
                old_rc, _ = self.verdict(old, output, allow)
                rc, printed = self.verdict(new, output, allow)
                expected_fault = any(signature in output for label, signature in signatures.items() if label != "database_connect" or not allow)
                self.assertEqual(rc, 0 if expected_fault else 1)
                self.assertEqual(rc, old_rc)
                self.assertNotIn(canary, printed)
                if rc == 0:
                    for label, signature in signatures.items():
                        count = sum(signature in line for line in output.splitlines())
                        if count:
                            self.assertIn(f"detail: {label} count={count}\n", printed)
                else:
                    self.assertEqual(printed, "")


if __name__ == "__main__":
    unittest.main()
