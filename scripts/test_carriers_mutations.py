#!/usr/bin/env python3
"""Exercise the real mutation driver with controlled go-test process outcomes."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "github.com/entire-vc/evc-keep/internal/carriers"


class CarrierDriver(unittest.TestCase):
    def run_driver(self, mode="good", shard=None):
        script = (ROOT / "scripts/check-carriers-mutations.sh").read_text()
        calls = [shlex.split(match.replace("\\\n", "")) for match in
                 re.findall(r"^mutate [^\n]*(?:\n[^\n]*)*?\n(?=mutate |\n|#)",
                            script, re.MULTILINE)]
        self.assertEqual(len(calls), 55)
        sources = {call[2] for call in calls}
        witnesses = sorted({w for call in calls for w in call[5].split()})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            for name in sources | {"go.mod", "scripts/check-carriers-mutations.sh",
                                   "scripts/lib/gocache.sh", "scripts/temp-workspace.sh",
                                   "scripts/mutation-helpers.sh"}:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                      for name in sources}
            stub = Path(tmp) / "go"
            stub.write_text("#!/usr/bin/env python3\n" +
                            "import hashlib, pathlib, sys\n" +
                            f"hashes = {hashes!r}\n" +
                            "baseline = all(hashlib.sha256(pathlib.Path(n).read_bytes()).hexdigest() == h for n, h in hashes.items())\n" +
                            f"package = {PACKAGE!r}\n" +
                            "if baseline:\n print('ok\\t' + package + '\\t0.001s'); sys.exit(0)\n" +
                            f"names = {witnesses!r}\nmode = {mode!r}\n" +
                            "removed = pathlib.Path('internal/carriers/format.go').read_text().strip() == 'package carriers'\n" +
                            "if not removed: mode = 'good'\n" +
                            "if mode == 'missing-canary': names = [n for n in names if n != 'TestMetadataCanary']\n" +
                            "if mode == 'missing-serialization': names = [n for n in names if n != 'TestMetadataSerializationRefused']\n" +
                            "if mode == 'interrupted-witness': names = ['TestMetadataCanary']\n" +
                            "if mode == 'shadow': names = [n + 'Shadow' for n in names]\n" +
                            "for name in names: print('--- FAIL: ' + name + ' (0.00s)')\n" +
                            "if mode == 'timeout': print('panic: test timed out after 1s')\n" +
                            "if mode == 'panic': print('panic: unexpected runtime fault')\n" +
                            "if mode == 'skip': print('--- SKIP: TestUnavailable (0.00s)')\n" +
                            "if mode == 'build': print('FAIL\\t' + package + ' [build failed]')\n" +
                            "if mode == 'setup': print('FAIL\\t' + package + ' [setup failed]')\n" +
                            "if mode == 'database-deadline': print('database operation deadline exceeded')\n" +
                            "if mode == 'scratch-create': print('create scratch database failed')\n" +
                            "if mode == 'admin-pool': print('open admin pool on scratch database failed')\n" +
                            "if mode == 'connection': print('connection failed (unclassified)')\n" +
                            "if mode == 'pgx-connect': print('failed to connect to `host=127.0.0.1 user=keep database=keep`: dial error (dial tcp 127.0.0.1:1: connect: connection refused)')\n" +
                            "if mode == 'pgx-dns': print('failed to connect to `host=postgres.invalid user=keep database=keep`: hostname resolving error: lookup postgres.invalid: no such host')\n" +
                            "if mode == 'pgx-reset': print('write tcp: connection reset by peer')\n" +
                            "if mode == 'store-auth': print('open migration database handle: connection failed (28P01)')\n" +
                            "if mode == 'pgx-closed': print('conn closed')\n" +
                            "if mode == 'sql-closed': print('sql: database is closed')\n" +
                            "if mode == 'bad-connection': print('driver: bad connection')\n" +
                            "if mode == 'pgx-eof': print('unexpected EOF')\n" +
                            "if mode == 'pgx-timeout': print('read tcp: i/o timeout')\n" +
                            "if mode == 'pgx-shutdown': print('FATAL: terminating connection due to administrator command (SQLSTATE 57P01)')\n" +
                            "if mode == 'pgx-connection-state': print('ERROR: connection failure (SQLSTATE 08006)')\n" +
                            "if mode == 'constraint': print('ERROR: violates foreign key constraint (SQLSTATE 23503)')\n" +
                            "if mode == 'context-deadline': print('context deadline exceeded')\n" +
                            "if mode not in ('truncated', 'interrupted-witness'): print('FAIL\\t' + package + '\\t0.001s')\n" +
                            "sys.exit(143 if mode == 'interrupted-witness' else 137 if mode == 'signal' else 1)\n")
            stub.chmod(0o755)
            run_env = {"PATH": str(Path(tmp)) + os.pathsep + os.environ["PATH"],
                       "KEEP_DATABASE_URL": "disposable-driver-control",
                       "TMPDIR": tmp}
            if shard:
                run_env.update(MUTATION_SHARD_INDEX=str(shard[0]),
                               MUTATION_SHARD_TOTAL=str(shard[1]))
            return subprocess.run(["sh", "scripts/check-carriers-mutations.sh"],
                                  cwd=root, env=run_env, capture_output=True, text=True,
                                  timeout=30)

    def test_complete_named_reds_and_baseline(self):
        run = self.run_driver()
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertEqual(run.stdout.count("tests went red"), 55)
        self.assertIn("confirmed on: TestMetadataCanary TestMetadataSerializationRefused", run.stdout)
        self.assertIn("baseline: tests green on the real code (0 SKIP)", run.stdout)

    def test_both_witnesses_are_mandatory(self):
        for mode in ["missing-canary", "missing-serialization", "shadow"]:
            with self.subTest(mode=mode):
                run = self.run_driver(mode, shard=(4, 4))
                self.assertNotEqual(run.returncode, 0, run.stdout)
                self.assertIn("FAIL metadata-formatting-removed", run.stdout)

    def test_partial_and_infrastructure_reds_are_rejected(self):
        for mode in ["interrupted-witness", "truncated", "signal", "panic", "timeout", "skip", "build",
                     "database-deadline", "scratch-create", "admin-pool", "connection",
                     "pgx-connect", "pgx-dns", "pgx-reset", "pgx-eof", "pgx-timeout",
                     "pgx-shutdown", "pgx-connection-state", "store-auth", "pgx-closed",
                     "sql-closed", "bad-connection"]:
            with self.subTest(mode=mode):
                run = self.run_driver(mode, shard=(4, 4))
                self.assertNotEqual(run.returncode, 0, run.stdout)
                self.assertIn("FAIL metadata-formatting-removed: invalid test run", run.stdout)

    def test_product_deadline_red_is_valid(self):
        run = self.run_driver("context-deadline", shard=(4, 4))
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertEqual(run.stdout.count("tests went red"), 13)

    def test_setup_failure_cannot_count_as_red(self):
        run = self.run_driver("setup", shard=(4, 4))
        self.assertNotEqual(run.returncode, 0, run.stdout)
        self.assertIn("FAIL metadata-formatting-removed: invalid test run", run.stdout)

    def test_product_constraint_red_is_valid(self):
        run = self.run_driver("constraint", shard=(4, 4))
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertEqual(run.stdout.count("tests went red"), 13)

    def test_all_shards_cover_the_inventory_and_baseline(self):
        total = 0
        selected = set()
        for index in range(1, 5):
            run = self.run_driver(shard=(index, 4))
            self.assertEqual(run.returncode, 0, run.stdout)
            count = run.stdout.count("tests went red")
            expected = 14 if index <= 3 else 13
            self.assertEqual(count, expected)
            self.assertIn(f"shard {index}/4: {expected} selected mutants", run.stdout)
            self.assertIn("baseline: tests green on the real code (0 SKIP)", run.stdout)
            names = set(re.findall(r"^ok\s+(\S+): tests went red", run.stdout, re.MULTILINE))
            self.assertFalse(selected & names)
            selected.update(names)
            total += count
        self.assertEqual(total, 55)
        self.assertEqual(len(selected), 55)


if __name__ == "__main__":
    unittest.main()
