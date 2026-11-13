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
'''
   tail='# The baseline output stays'+(ROOT/'scripts/check-keep-cli-mutations.sh').read_text().split('# The baseline output stays',1)[1]
   calls+=tail
   if unknown:calls=calls.replace('debug-leaks-authorization','unmapped-new-mutant',1)
   (r/'scripts/check.sh').write_text(prefix+calls)
   subprocess.run(['git','init','-q'],cwd=r,check=True)
   b=p/'bin';b.mkdir();fake='''#!/usr/bin/env python3
import os,sys,json
args=sys.argv[1:]
with open(os.environ['RECORD'],'a')as f:f.write(json.dumps(args)+'\\n')
if not os.getcwd().endswith('/tree'):
 if os.environ['MODE']=='control_skip' and '-run'in args:print('--- SKIP: TestPositiveControl')
 if os.environ['MODE']=='baseline_skip' and '-run'not in args:print('--- SKIP: TestSomething');print(os.environ['CANARY'])
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
  self.assertEqual(record[-1],['test','-count=1','-v','./cmd/keep/...'])
  self.assertIn('ok   debug-leaks-authorization: TestCLI_TokenNeverLeaksToStdoutStderrOrDebug went red',x.stdout)
  self.assertIn('ok   baseline: CLI tests green on the real code, none skipped',x.stdout)
  self.assertNotRegex(x.stdout,r'failing\)')
 def test_faults_and_unrelated_red_never_kill(self):
  for mode in ['green','unrelated','skip','build','setup','infra','timeout','missing_metadata_marker','control_skip','baseline_skip']:
   with self.subTest(mode=mode):self.assertNotEqual(self.exercise(mode)[0].returncode,0)
 def test_unknown_mapping_fails(self):
  x,record=self.exercise('red',unknown=True);self.assertNotEqual(x.returncode,0)
  self.assertFalse(any('^TestCLI_TokenNeverLeaksToStdoutStderrOrDebug$'in args for args in record))
 def test_missing_database_fails_before_go(self):
  x,record=self.exercise('red',unset_database=True);self.assertNotEqual(x.returncode,0);self.assertEqual(record,[])
 def test_unchanged_baseline_failure_fails(self):self.assertNotEqual(self.exercise('baseline_failure')[0].returncode,0)
 def test_all_106_map_to_existing_tests_and_no_inventory_edits(self):
  new=(ROOT/'scripts/check-keep-cli-mutations.sh').read_text()
  # Frozen 67-mutant inventory, metadata controls and full baseline from 52cb6cdc,
  # plus the apply-only exit before the baseline (scripts/mutation-helpers.sh),
  # plus the two non-regular token file mutants added for --token-file FIFOs,
  # and wide-permission-guard-removed no longer dropping the mode the regular-file check reads,
  # plus the two runner decode-error mutants (enroll-token and revoke print a static line only),
  # plus the header redaction mutants of the keep --debug dump,
  # plus the harness printing the witness test name and a baseline that fails on any SKIP,
  # plus the full header redaction removal witnessed by TestDebugHeadersLoopback,
  # plus the eight keep deploy answer mutants (id/class normalisation, runner class set, poll ban).
  # plus the five runner enroll-token/revoke fail-closed and closed-field-list mutants,
  # plus the four request id contract mutants (the two old length/charset ones replaced),
  # plus the three header-name allow-list mutants of the keep --debug dump,
  # plus debug-header-dump-unfiltered mutating the name declaration so the mutant compiles,
  # plus the input-link request_id mutant (the two auditRequestID guards now call reqid.Valid),
  # plus the input-link guard's own length and charset weakenings,
  # plus eight metadata mutants for fingerprint/version/approval guards at POST and poll,
  # minus secret-name-echoed-in-not-found (unobservable once the CLI prints static class text),
  # plus the static CLI error text mutants (the server message stays out of reportErr and apiError.Error; request_id only by the reqid contract).
  # plus the two keep deploy healthcheck status mutants (guard no-op, closed list widened).
  # runner-server-ca-path-echoed re-anchored from the removed os.ReadFile branch of runner.go to the open-error branch of server_ca_read.go (same witness, same count);
  # plus the four shared-client response cap mutants (unbounded read, size check removed, off-by-one, missing extra byte);
  # debug-traces-response-body is re-anchored on the capped read line,
  # plus runner-policy-error-echoed now echoing the -policy path (readPolicyFile's error is already static).
  self.assertEqual(hashlib.sha256(new.split('# AC red run (1):')[1].encode()).hexdigest(),'7e64c77e71bf43dd04d42f1e6fedd6d7f9389c3c4f0f71f41844c08e335089ee')
  names=re.findall(r'^mutate ([a-z0-9-]+) ',new,re.M);self.assertEqual(len(names),106)
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
