"""Tracked snapshots must survive a file list larger than BusyBox xargs batches."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parent.parent


class TrackedSnapshotTests(unittest.TestCase):
    def setUp(self):
        scratch = REPO / ".artifacts"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="tracked-test-", dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        self.dest = self.base / "copy"
        self.git("init", "-q")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.source), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def put(self, name, data=b"fixture", mode=0o640):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def snapshot(self, extra_env=None):
        script = '''set -eu
root=$1
. "$2/scripts/mutation-helpers.sh"
mutation_snapshot_py=$2/scripts/lib/mutation_snapshot.py
work=$4
trap 'mutation_snapshot_end' EXIT
mutation_snapshot "$3" tracked
mutation_snapshot_report
'''
        return subprocess.run(["sh", "-c", script, "sh", str(self.source),
                               str(REPO), str(self.dest), str(self.base)],
                              env={**os.environ, **(extra_env or {})},
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=60)

    def test_large_working_tree_and_literal_names(self):
        names = [f"tree/{i:04d}-{'x' * 160}" for i in range(1200)]
        names += ["space name", "quote'and\"double", "back\\slash", "unicode-λ",
                  "-C", "--checkpoint=1", "pkg/secret/value.go"]
        self.assertGreater(len(b"\0".join(os.fsencode(n) for n in names)), 128 * 1024)
        for name in names:
            self.put(name)
        executable = self.put("executable", b"staged", 0o750)
        self.put("shared-mode", mode=0o660)
        os.symlink("space name", self.source / "link")
        os.symlink("../outside", self.source / "outside-link")
        (self.base / "outside").write_bytes(b"outside fixture")
        self.git("add", "--all")
        executable.write_bytes(b"working tree differs from index")
        self.put("untracked")
        result = self.snapshot()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = set(names + ["executable", "shared-mode", "link", "outside-link"])
        got = {str(p.relative_to(self.dest)) for p in self.dest.rglob("*")
               if p.is_file() or p.is_symlink()}
        self.assertEqual(got, expected)
        for name in names + ["executable", "shared-mode"]:
            self.assertEqual((self.dest / name).read_bytes(), (self.source / name).read_bytes())
            self.assertEqual((self.dest / name).stat().st_mode & 0o777,
                             (self.source / name).stat().st_mode & 0o777)
        self.assertEqual(os.readlink(self.dest / "outside-link"), "../outside")
        self.assertFalse((self.dest / "untracked").exists())

    def test_empty_tracked_tree(self):
        self.put("untracked")
        result = self.snapshot()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_large_file_list(self):
        names = [f"a-tree/{i:04d}-{'x' * 160}" for i in range(1200)]
        names.append("pkg/secret/value.go")
        for name in names:
            self.put(name)
        self.git("add", "--all")
        result = self.snapshot()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.dest / names[-1]).read_bytes(), b"fixture")
        self.assertEqual(sum(p.is_file() for p in self.dest.rglob("*")), len(names))

    def check_copy(self, build, message):
        """Run the copy check on a deliberately wrong copy of one tracked file.

        The copier and the check are separate commands of the helper; this
        feeds the check a copy no correct copier makes, so each of its guards
        has to refuse it on its own.
        """
        self.put("tracked")
        self.git("add", "--all")
        self.put("untracked")
        listing = self.base / "list"
        listing.write_bytes(self.git("ls-files", "-z"))
        self.dest.mkdir()
        build(self.dest)
        result = subprocess.run(["python3", "-I", str(REPO / "scripts/lib/mutation_snapshot.py"),
                                 "copy", str(self.dest), str(self.source), "1", str(listing)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(b"FAIL mutation snapshot: " + message, result.stdout)
        self.assertFalse(Path(str(self.dest) + ".copy").exists())

    def test_missing_member_fails_closed(self):
        self.check_copy(lambda d: None, b"tracked path set differs")

    def test_same_count_wrong_member_fails_closed(self):
        self.check_copy(lambda d: shutil.copy2(self.source / "untracked", d / "untracked"),
                        b"tracked path set differs")

    def test_mode_drift_fails_closed(self):
        def build(d):
            shutil.copyfile(self.source / "tracked", d / "tracked")
            (d / "tracked").chmod(0o600)
        self.check_copy(build, b"copied file modes differ")

    def git_shim(self, body):
        shim = self.base / "bin"
        shim.mkdir()
        wrapper = shim / "git"
        # mock: Git is an external executable; this one misreports its list.
        wrapper.write_text("#!/bin/sh\n" + body)
        wrapper.chmod(0o755)
        return self.snapshot({"PATH": str(shim) + os.pathsep + os.environ["PATH"]})

    def test_truncated_list_fails_closed(self):
        result = self.git_shim("printf 'tracked\\0cut-short'\n")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(b"FAIL mutation snapshot: tracked file list is truncated", result.stdout)

    def test_duplicate_list_entry_fails_closed(self):
        self.put("tracked")
        result = self.git_shim("printf 'tracked\\0tracked\\0'\n")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(b"FAIL mutation snapshot: duplicate tracked paths", result.stdout)

    def test_git_failure_fails_closed(self):
        result = self.git_shim("exit 17\n")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(b"FAIL mutation snapshot: git ls-files in", result.stdout)

    def test_parent_symlink_fails_closed(self):
        self.put("dir/file")
        self.git("add", "--all")
        shutil.rmtree(self.source / "dir")
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "file").write_bytes(b"outside fixture")
        os.symlink(outside, self.source / "dir")
        result = self.snapshot()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(b"FAIL mutation snapshot: tracked path parent is not a directory", result.stdout)

    def test_record_delimiter_in_name_fails_closed(self):
        self.put("line\nbreak")
        self.git("add", "--all")
        result = self.snapshot()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(b"FAIL mutation snapshot: unsupported tracked path", result.stdout)


if __name__ == "__main__":
    unittest.main()
