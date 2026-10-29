import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = (ROOT / 'scripts/check-tenancy-mutations.sh').read_text()
MUTATE = SCRIPT[SCRIPT.index('mutate() {'):SCRIPT.index('# RemoveUser')]
BASELINE = SCRIPT[SCRIPT.index('for baseline_pkg in $pkgs; do'):SCRIPT.index('# mutate NAME')]
PKG = 'github.com/entire-vc/evc-keep/internal/'
GOOD = '--- FAIL: TestOne/a: (0.00s)\n--- FAIL: TestTwo/b: (0.00s)\nFAIL\t' + PKG + 'tenancy\t0.001s\nok  \t' + PKG + 'catalog\t0.001s [no tests to run]\n'
CANARY = 'private-test-canary'

class TenancyControls(unittest.TestCase):
    def invoke(self, output=GOOD, status=1, want='TestOne/a: TestTwo/b:', baseline=False):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'work/tree').mkdir(parents=True); (root/'bin').mkdir()
            (root/'target.go').write_text('before\n')
            argv = root/'argv.jsonl'
            fake = root/'bin/go'
            fake.write_text('#!/usr/bin/env python3\nimport sys,json\nfrom pathlib import Path\n'
                           + 'with open('+repr(str(argv))+', "a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                           + 'print('+repr(output)+')\nsys.exit('+str(status)+')\n')
            fake.chmod(0o755)
            prefix = 'set -eu\nroot="'+str(root)+'"\nwork="$root/work"\nfail=0\npkgs="./internal/tenancy/ ./internal/catalog/"\n'
            prefix += '. "'+str(ROOT/'scripts/mutation-helpers.sh')+'"\nmutation_selected() { return 0; }\nmutation_snapshot() { mkdir -p "$1"; }\nedit() { sed s/before/after/ "$1"; }\n'
            body = BASELINE if baseline else MUTATE + '\nmutate example target.go before after '+"'"+want+"'"+'\nexit "$fail"\n'
            env = os.environ.copy();env['PATH']=str(root/'bin')+':'+env['PATH']
            r=subprocess.run(['sh','-c',prefix+body+'\necho MUTANT_BOUNDARY'],env=env,capture_output=True,text=True)
            return r.returncode,r.stdout+r.stderr,[json.loads(l) for l in argv.read_text().splitlines()] if argv.exists() else []

    def test_actual_union_and_both_package_argv_accept_named_red(self):
        code,output,argv=self.invoke()
        self.assertEqual(code,0)
        self.assertEqual(argv,[['test','-timeout','600s','-count=1','-p','1','-v','-run','^(TestOne|TestTwo)$','./internal/tenancy/','./internal/catalog/']])
        self.assertIn('confirmed on: TestOne/a: TestTwo/b:',output)

    def test_unrelated_or_missing_required_subtest_not_kill(self):
        for out in (GOOD.replace('TestTwo/b:','TestTwo/c:'),GOOD.replace('TestOne/a:','TestUnrelated/a:')):
            with self.subTest(out=out):self.assertEqual(self.invoke(out)[0],1)

    def test_unsupported_top_names_fail_before_go(self):
        for want in ('TestOne.*','TestOne|TestOther','TestOne;echo','Other/a','Testone/a'):
            code,output,argv=self.invoke(want=want)
            self.assertEqual(code,1);self.assertEqual(argv,[]);self.assertIn('unsupported witness',output)

    def test_incomplete_skip_build_sqlstate_and_abnormal_exit_invalid(self):
        for out,status in ((GOOD.replace('ok  \t'+PKG+'catalog','missing '+PKG+'catalog'),1),
                           (GOOD+'--- SKIP: TestOne\n',1),(GOOD+'[build failed]\n',1),
                           (GOOD+'SQLSTATE 42P01\n',1),(GOOD,137),(GOOD,0),
                           (GOOD+'panic: test timed out\n',1)):
            with self.subTest(status=status,out=out):self.assertEqual(self.invoke(out,status)[0],1)

    def test_strict_infrastructure_rejects_named_red_without_raw_output(self):
        for marker in ('database operation deadline exceeded','create scratch database failed','connection failed (unclassified)'):
            code,output,_=self.invoke(GOOD+marker+' '+CANARY)
            self.assertEqual(code,1);self.assertNotIn(CANARY,output)
            self.assertIn('infrastructure',output)

    def test_full_unmutated_baselines_unchanged_and_stop_on_skip_or_failure(self):
        good='--- PASS: TestFull (0.001s)\n'
        code,_,argv=self.invoke(good,0,baseline=True)
        self.assertEqual(code,0)
        self.assertEqual(argv,[['test','-timeout','600s','-count=1','-p','1','-v',p] for p in ('./internal/tenancy/','./internal/catalog/')])
        for out,status in ((good+'--- SKIP: TestOther',0),('--- FAIL: TestFull',1),('',0)):
            code,output,argv=self.invoke(out,status,baseline=True)
            self.assertEqual(code,1);self.assertEqual(len(argv),1);self.assertNotIn('MUTANT_BOUNDARY',output)

if __name__ == '__main__':unittest.main()
