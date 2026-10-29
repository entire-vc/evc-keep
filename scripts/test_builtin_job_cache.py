"""Job cache lifecycle controls; no Go compiler, database or network."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


SOURCE = Path(os.environ.get("KEEP_JOB_CACHE_WRAPPER", Path(__file__).with_name("run-builtin-mutation-job.sh")))
LIB = Path(__file__).parent / "lib/gocache.sh"


class JobCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo with spaces"
        scripts = self.root / "scripts"
        (scripts / "lib").mkdir(parents=True)
        (self.root / "go.mod").touch()
        shutil.copy2(SOURCE, scripts / SOURCE.name)
        self.wrapper = scripts / SOURCE.name
        shutil.copy2(LIB, scripts / "lib/gocache.sh")
        self.caches = self.base / "caches"
        self.caches.mkdir()
        self.events = self.base / "events"
        self.bin = self.base / "bin"
        self.bin.mkdir()
        shim = self.bin / "timeout"
        shim.write_text('#!/bin/sh\n[ "$1" = -k ] && [ "$2" = 10s ] && [ "$3" = 19m ] || exit 98\nshift 3\nexec "$@"\n')
        shim.chmod(0o755)
        probe = self.base / "probe.py"
        probe.write_text('''import json,os,signal,subprocess,sys,time
from pathlib import Path
cache=os.environ['GOCACHE']; events=Path(os.environ['EVENTS'])
def event(kind):
 with events.open('a') as f: f.write(json.dumps({'kind':kind,'index':sys.argv[1],'cache':cache,'exists':Path(cache).is_dir() if cache not in ('','off') else None})+'\\n')
event('start')
mode=os.environ['MODE']
if mode == 'descendant' and sys.argv[1] == 'grandchild':
 def stop(sig,frame):
  event('descendant-term-start'); time.sleep(.3); event('descendant-term-end'); sys.exit(0)
 signal.signal(signal.SIGTERM,stop)
 event('ready')
 while True: time.sleep(.01)
if mode == 'descendant' and sys.argv[1] == '1':
 subprocess.Popen([sys.executable,__file__,'grandchild'])
 while not any(json.loads(line)['kind']=='ready' for line in events.read_text().splitlines()): time.sleep(.01)
 signal.signal(signal.SIGTERM,lambda sig,frame: sys.exit(0))
 event('ready')
 while True: time.sleep(.01)
if mode == 'fail' and sys.argv[1] == '1': sys.exit(17)
if mode == 'term' and sys.argv[1] == '1':
 def stop(sig,frame):
  event('term-start'); time.sleep(.2); event('term-end'); sys.exit(12)
 signal.signal(signal.SIGTERM,stop)
 event('ready')
 while True: time.sleep(.01)
''')
        for i, name in enumerate(("check-builtin-mutations.sh", "check-intake-receiver-mutations.sh", "check-intake-service-mutations.sh"), 1):
            path = scripts / name
            path.write_text('#!/bin/sh\nset -eu\nroot=$(cd "$(dirname "$0")/.." && pwd)\n. "$root/scripts/lib/gocache.sh"\nexec python3 "$PROBE" ' + str(i) + '\n')
            path.chmod(0o755)
        self.env = dict(os.environ, TMPDIR=str(self.caches), EVENTS=str(self.events), PROBE=str(probe), MODE="pass", PATH=(os.environ["PATH"] if os.environ.get("KEEP_JOB_CACHE_REAL_TIMEOUT") == "1" else str(self.bin) + os.pathsep + os.environ["PATH"]))
        self.env.pop("GOCACHE", None)

    def rows(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def start(self, **changes):
        env = dict(self.env, **changes)
        process = subprocess.Popen(["sh", str(self.wrapper)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.reap, process)
        return process

    @staticmethod
    def reap(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()

    def wait_ready(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if any(row['kind'] == 'ready' and row['index'] == '1' for row in self.rows()):
                return
            time.sleep(.01)
        self.fail('child did not become ready')

    def test_one_cache_three_children_then_cleanup(self):
        p = self.start()
        p.communicate(timeout=3)
        self.assertEqual(p.returncode, 0)
        rows = self.rows()
        self.assertEqual([r['index'] for r in rows], ['1', '2', '3'])
        self.assertEqual(len({r['cache'] for r in rows}), 1)
        self.assertTrue(all(r['exists'] for r in rows))
        self.assertEqual(list(self.caches.iterdir()), [])

    def test_child_failure_stops_and_preserves_status(self):
        p = self.start(MODE='fail')
        p.communicate(timeout=3)
        self.assertEqual(p.returncode, 17)
        self.assertEqual([r['index'] for r in self.rows()], ['1'])
        self.assertTrue(self.rows()[0]['exists'])
        self.assertEqual(list(self.caches.iterdir()), [])

    def test_term_waits_before_cache_cleanup(self):
        p = self.start(MODE='term')
        self.wait_ready()
        p.send_signal(signal.SIGTERM)
        p.communicate(timeout=3)
        self.assertEqual(p.returncode, 143)
        rows = self.rows()
        self.assertEqual([r['kind'] for r in rows], ['start', 'ready', 'term-start', 'term-end'])
        self.assertTrue(all(r['exists'] for r in rows))
        self.assertEqual(list(self.caches.iterdir()), [])

    def test_explicit_caller_values_unchanged(self):
        external = self.base / 'caller-cache'
        external.mkdir()
        sentinel = external / 'keep'
        sentinel.write_text('caller owned')
        for value in (str(external), '', 'off'):
            self.events.unlink(missing_ok=True)
            p = self.start(GOCACHE=value)
            p.communicate(timeout=3)
            self.assertEqual(p.returncode, 0)
            self.assertEqual({r['cache'] for r in self.rows()}, {value})
            self.assertTrue(sentinel.exists())
            self.assertEqual(list(self.caches.iterdir()), [])

    def test_term_waits_for_descendant_after_direct_child_exits(self):
        p = self.start(MODE='descendant')
        self.wait_ready()
        p.terminate()
        _, stderr = p.communicate(timeout=5)
        self.assertEqual(p.returncode, 143)
        rows = self.rows()
        last = [r for r in rows if r['kind'] == 'descendant-term-end']
        self.assertEqual(len(last), 1)
        self.assertTrue(last[0]['exists'])
        self.assertFalse(any(r['index'] in ('2', '3') for r in rows))
        # Some PID1 implementations retain an orphan zombie. Fail closed:
        # the wrapper may retain its ephemeral cache with a diagnostic.
        if Path(rows[0]['cache']).exists():
            self.assertIn(b'cache retained', stderr)

    def test_overlapping_parents_remain_isolated(self):
        a = self.start(MODE='term')
        self.wait_ready()
        first = self.rows()[0]['cache']
        b = self.start()
        b.communicate(timeout=3)
        self.assertEqual(b.returncode, 0)
        second = [r for r in self.rows() if r['cache'] != first]
        self.assertEqual(len(second), 3)
        self.assertTrue(Path(first).is_dir())
        self.assertFalse(Path(second[0]['cache']).exists())
        a.terminate()
        a.communicate(timeout=3)
        self.assertEqual(a.returncode, 143)
        self.assertEqual(list(self.caches.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
