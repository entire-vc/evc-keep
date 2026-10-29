"""Exercise actual embedded catalog child boundary/gate without PostgreSQL."""
import ast
import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
source = (ROOT / 'scripts/metadata-mutations.sh').read_text().split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
tree = ast.parse(source)
functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name in ('catalog_diagnostic', 'run')]
gate = next(node.test for node in ast.walk(tree) if isinstance(node, ast.If) and ast.unparse(node.test).startswith('not status or'))
GATE = compile(ast.Expression(gate), '<actual-mutant-gate>', 'eval')
CANARY = 'private-catalog-diagnostic-canary https://private.invalid/path'
TEST = 'TestCreateRefMetadataValidation'
MARKER = 'metadata guard did not return invalid_argument'
FAIL = '{"Action":"fail","Package":"private/package"}\n--- FAIL: '+TEST+'\n'+MARKER+'\n'
KEYS = {'event','returncode','exit_success','setup_failure','test_failure','package_failure','witness_count','skipped','timed_out','infrastructure_failure'}

class CatalogDiagnostics(unittest.TestCase):
    def invoke(self, code, output, timeout=False):
        with tempfile.TemporaryDirectory() as tmp:
            namespace = dict(json=json,re=re,subprocess=subprocess,os=__import__('os'),tree=Path(tmp))
            exec(compile(ast.Module(body=functions, type_ignores=[]), '<actual-child-functions>', 'exec'), namespace)
            original = subprocess.run
            def child(command, **kwargs):
                self.assertEqual(command, ['go','test','-json','-count=1','-timeout=60s','-run','^'+TEST+'$','./internal/catalog'])
                self.assertEqual(kwargs['timeout'], 120)
                if timeout:
                    raise subprocess.TimeoutExpired(command, 120, output=(output+CANARY).encode())
                return original([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.exit(int(sys.argv[1]))',str(code)], input=(output+CANARY).encode(), **kwargs)
            public = io.StringIO()
            with patch.object(subprocess, 'run', child), contextlib.redirect_stdout(public):
                if timeout:
                    with self.assertRaisesRegex(SystemExit, '^FAIL metadata: subprocess timeout$'):
                        namespace['run']('./internal/catalog', TEST)
                    rejected = True
                else:
                    status,out = namespace['run']('./internal/catalog',TEST)
                    namespace['catalog_diagnostic'](status,out,TEST,MARKER)
                    rejected = eval(GATE, dict(status=status,out=out,test=TEST,marker=MARKER,re=re))
            raw = public.getvalue()
            self.assertNotIn(CANARY,raw)
            self.assertNotIn('private/package',raw)
            self.assertNotIn(MARKER,raw)
            row=json.loads(raw)
            self.assertEqual(set(row),KEYS)
            self.assertIsInstance(row['returncode'],int)
            self.assertLess(len(raw), 512)
            return row,rejected

    def test_expected_mutation_red(self):
        row,rejected=self.invoke(1,FAIL)
        self.assertFalse(rejected)
        self.assertTrue(row['test_failure']);self.assertEqual(row['witness_count'],1)

    def test_unexpected_failures_never_count(self):
        for code,out in [(0,FAIL),(1,FAIL+'[setup failed]'),(1,FAIL+'[build failed]'),(2,FAIL+'panic: test timed out'),(1,FAIL+'database operation deadline exceeded'),(1,'{"Action":"skip"}'),(1,FAIL+'{"Action":"skip"}'),(7,'unrelated failure'),(1,'--- FAIL: '+TEST)]:
            with self.subTest(code=code,out=out):
                row,rejected=self.invoke(code,out)
                self.assertTrue(rejected)
                self.assertEqual(row['returncode'],code)

    def test_wrapper_timeout_is_private_and_fails(self):
        row,rejected=self.invoke(1,FAIL,timeout=True)
        self.assertTrue(rejected);self.assertTrue(row['timed_out'])
        self.assertEqual(row['returncode'],124);self.assertEqual(row['witness_count'],0)

    def test_skip_without_witness(self):
        row,rejected=self.invoke(0,'{"Action":"skip"}')
        self.assertTrue(rejected);self.assertTrue(row['skipped']);self.assertEqual(row['witness_count'],0)

    def test_bounded_witness_count(self):
        row,rejected=self.invoke(1,FAIL+MARKER*70000)
        self.assertFalse(rejected);self.assertEqual(row['witness_count'],65535)

if __name__=='__main__': unittest.main()
