#!/usr/bin/env python3
"""Actual shell/process controls; no Go/database required."""
import hashlib,json,os,pathlib,re,shutil,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parent.parent
CANARY='PRIVATE-CLI-FAULT-CANARY'
class Controls(unittest.TestCase):
 def exercise(self,mode,unknown=False,unset_database=False):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td);r=p/'repo';(r/'scripts/lib').mkdir(parents=True);(r/'cmd/keep').mkdir(parents=True)
   for n in ['mutation-helpers.sh','temp-workspace.sh','lib/gocache.sh','cli-mutation-witnesses.sh']:shutil.copy2(ROOT/'scripts'/n,r/'scripts'/n)
   (r/'go.mod').write_text('module fixture\n')
   (r/'cmd/keep/client.go').write_text('if strings.EqualFold(k, "Authorization") {\n')
   (r/'cmd/keep/output.go').write_text('w.Write(escapeJSONControls(buf.Bytes()))\n')
   prefix=(ROOT/'scripts/check-keep-cli-mutations.sh').read_text().split('# AC red run (1):')[0]
   calls='''mutate debug-leaks-authorization client.go 'if strings.EqualFold(k, "Authorization") {' 'if false {'
metadata_mutate TestJSONValueEscapesControlsAndPreservesUnicode 'JSON writer emitted raw control' json-control-escape-noop output.go 'w.Write(escapeJSONControls(buf.Bytes()))' 'w.Write(buf.Bytes())'
if (cd "$root" && go test -count=1 ./$pkg/... >/dev/null 2>&1); then :; else fail=1; fi
exit $fail
'''
   if unknown:calls=calls.replace('debug-leaks-authorization','unmapped-new-mutant',1)
   (r/'scripts/check.sh').write_text(prefix+calls)
   subprocess.run(['git','init','-q'],cwd=r,check=True)
   b=p/'bin';b.mkdir();fake='''#!/usr/bin/env python3
import os,sys,json
args=sys.argv[1:]
with open(os.environ['RECORD'],'a')as f:f.write(json.dumps(args)+'\\n')
if not os.getcwd().endswith('/tree'):
 if os.environ['MODE']=='control_skip' and '-run'in args:print('--- SKIP: TestPositiveControl')
 sys.exit(1 if os.environ['MODE']=='baseline_failure' and '-run'not in args else 0)
w=args[args.index('-run')+1][1:-1];mode=os.environ['MODE']
print(os.environ['CANARY'])
if mode=='green':sys.exit(0)
print('--- FAIL: '+('TestUnrelated'if mode=='unrelated'else w)+' (0.00s)')
if mode!='missing_metadata_marker':print('JSON writer emitted raw control')
print({'skip':'--- SKIP: TestOther','build':'[build failed]','setup':'[setup failed]','infra':'create scratch database failed','timeout':'panic: test timed out'}.get(mode,''))
sys.exit(1)
''';(b/'go').write_text(fake);(b/'go').chmod(0o755)
   e=os.environ.copy();e.update(PATH=str(b)+':'+e['PATH'],KEEP_DATABASE_URL='test',MODE=mode,RECORD=str(p/'record'),CANARY=CANARY)
   if unset_database:e.pop('KEEP_DATABASE_URL')
   x=subprocess.run(['sh','scripts/check.sh'],cwd=r,env=e,capture_output=True,text=True)
   self.assertNotIn(CANARY,x.stdout+x.stderr)
   return x,[json.loads(l)for l in (p/'record').read_text().splitlines()]if(p/'record').exists()else[]
 def test_intended_red_exact_argv_and_metadata_control(self):
  x,record=self.exercise('red');self.assertEqual(x.returncode,0,x.stdout+x.stderr)
  self.assertIn(['test','-timeout','120s','-count=1','-v','-run','^TestCLI_TokenNeverLeaksToStdoutStderrOrDebug$','./cmd/keep/...'],record)
  self.assertIn(['test','-timeout','60s','-count=1','-v','-run','^TestJSONValueEscapesControlsAndPreservesUnicode$','./cmd/keep'],record)
  self.assertEqual(record[-1],['test','-count=1','./cmd/keep/...'])
 def test_faults_and_unrelated_red_never_kill(self):
  for mode in ['green','unrelated','skip','build','setup','infra','timeout','missing_metadata_marker','control_skip']:
   with self.subTest(mode=mode):self.assertNotEqual(self.exercise(mode)[0].returncode,0)
 def test_unknown_mapping_fails(self):
  x,record=self.exercise('red',unknown=True);self.assertNotEqual(x.returncode,0)
  self.assertFalse(any('^TestCLI_TokenNeverLeaksToStdoutStderrOrDebug$'in args for args in record))
 def test_missing_database_fails_before_go(self):
  x,record=self.exercise('red',unset_database=True);self.assertNotEqual(x.returncode,0);self.assertEqual(record,[])
 def test_unchanged_baseline_failure_fails(self):self.assertNotEqual(self.exercise('baseline_failure')[0].returncode,0)
 def test_all_62_map_to_existing_tests_and_no_inventory_edits(self):
  new=(ROOT/'scripts/check-keep-cli-mutations.sh').read_text()
  # Frozen 67-mutant inventory, metadata controls and full baseline from 52cb6cdc,
  # plus the apply-only exit before the baseline (scripts/mutation-helpers.sh).
  self.assertEqual(hashlib.sha256(new.split('# AC red run (1):')[1].encode()).hexdigest(),'cb9003cf12293d67372fb9a78b50213bff84baed857d0edc5b1eab86557add29')
  names=re.findall(r'^mutate ([a-z0-9-]+) ',new,re.M);self.assertEqual(len(names),62)
  tests=set()
  for f in (ROOT/'cmd/keep').glob('*test.go'):tests.update(re.findall(r'^func (Test[A-Za-z0-9_]+)\(',f.read_text(),re.M))
  for n in names:
   w=subprocess.check_output(['sh','-c','. "$1"; cli_mutation_witness "$2"','sh',str(ROOT/'scripts/cli-mutation-witnesses.sh'),n],text=True).strip()
   self.assertRegex(w,r'^Test[A-Za-z0-9_]+$');self.assertIn(w,tests)
 def test_malformed_witness_rejected_before_execution(self):
  # Production validator executes with a hostile resolver result through shell.
  with tempfile.TemporaryDirectory()as td:
   f=pathlib.Path(td)/'fixture.sh'
   source=(ROOT/'scripts/check-keep-cli-mutations.sh').read_text()
   validator=source.split('\tcase "$want" in',1)[1].split('\tif [ -n "${metadata_witness:-}" ]; then',1)[0]
   f.write_text('fail=0\nprobe() { name=probe; want="TestProbe.*"; case "$want" in'+validator+'echo reached; }\nprobe\nexit $fail\n')
   x=subprocess.run(['sh',str(f)],capture_output=True,text=True);self.assertEqual(x.returncode,1);self.assertNotIn('reached',x.stdout)
if __name__=='__main__':unittest.main()
