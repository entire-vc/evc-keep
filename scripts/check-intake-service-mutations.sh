#!/bin/sh
# Require designated behavioral failures; compilation errors never count.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
if ! mutation_apply_only && [ -z "${KEEP_DATABASE_URL:-}" ]; then
 echo 'FAIL: a migrated PostgreSQL database is required' >&2
 exit 2
fi
python3 - <<'PY'
import os, pathlib, re, shutil, subprocess, tempfile, sys
sys.path.insert(0, str(pathlib.Path.cwd() / "scripts"))
from intake_baseline_diagnostics import run_baseline
apply_only = os.environ.get('MUTATION_APPLY_ONLY') == '1'
def behavioral_failure(code, out, test, marker):
 if code == 0 or re.search(r'panic:|fatal error:|\[build failed\]|\[setup failed\]|--- SKIP|database operation deadline exceeded|create scratch database failed|open admin pool on scratch database failed|connection failed \(unclassified\)', out):
  return False
 return '--- FAIL: '+test in out and marker in out
if not apply_only:
 for fault in ['panic: test timed out', 'fatal error: runtime', '[build failed]', '[setup failed]', '--- SKIP: Other', 'database operation deadline exceeded', 'create scratch database failed', 'open admin pool on scratch database failed', 'connection failed (unclassified)']:
  if behavioral_failure(1, '--- FAIL: TestProbe\nbehavioral witness\n'+fault, 'TestProbe', 'behavioral witness'):
   raise SystemExit('FAIL service checker accepted infrastructure fault')
 if not behavioral_failure(1, '--- FAIL: TestProbe\nbehavioral witness', 'TestProbe', 'behavioral witness'):
  raise SystemExit('FAIL service checker rejected behavioral control')
 print('ok   checker: behavioral witness required; infrastructure faults rejected',flush=True)
root=pathlib.Path.cwd()
files=subprocess.check_output(['git','ls-files','-co','--exclude-standard','-z']).decode().split('\0')
mutations=[
 # Canonical wire properties have their own cheap, DB-independent witnesses.
 ('descriptor-domain', 'internal/intake/descriptor/message.go', 'keep/intake-key/v2\\x00', 'keep/intake-key/v1\\x00', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'descriptor domain is not the fixed v2 NUL-terminated prefix'),
 ('descriptor-domain-nul', 'internal/intake/descriptor/message.go', 'keep/intake-key/v2\\x00', 'keep/intake-key/v2', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'missing UTF-8 byte length prefix'),
 ('descriptor-endian', 'internal/intake/descriptor/message.go', 'binary.BigEndian.AppendUint32', 'binary.LittleEndian.AppendUint32', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'missing UTF-8 byte length prefix'),
 ('descriptor-rune-length', 'internal/intake/descriptor/message.go', 'uint32(len(field))', 'uint32(len([]rune(field)))', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'missing UTF-8 byte length prefix'),
 ('descriptor-no-length', 'internal/intake/descriptor/message.go', 'uint32(len(field))', 'uint32(0)', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'missing UTF-8 byte length prefix'),
 ('descriptor-order', 'internal/intake/descriptor/message.go', 'm.SecretName, m.Scope', 'm.Scope, m.SecretName', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'missing UTF-8 byte length prefix'),
 ('descriptor-public-base64', 'internal/intake/descriptor/message.go', 'string(public)', 'base64.RawURLEncoding.EncodeToString(public)', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'missing UTF-8 byte length prefix'),
 ('descriptor-empty-sponsor', 'internal/intake/descriptor/message.go', 'out = binary.BigEndian.AppendUint32', 'if field == "" { continue }; out = binary.BigEndian.AppendUint32', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'empty sponsor lacks its zero length prefix'),
 ('descriptor-helper-bypass', 'internal/intake/descriptor/message.go', 'return out', 'return nil', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'descriptor domain is not the fixed v2 NUL-terminated prefix'),
 ('snapshot-downgrade', 'internal/intake/service_test.go', 'migrations.DownTo(pgscratch.Context(t), 13)', 'migrations.DownTo(pgscratch.Context(t), 12)', './internal/intake', 'TestDescriptorSnapshotMigrationPreservesHistory', 'snapshot downgrade changed a preceding migration'),
 ('descriptor-signature', 'internal/intake/service.go', '!validDescriptor(row.view) || ', '', './internal/intake', 'TestServiceRejectsDescriptorTampering', 'tampered descriptor readable'),
 ('snapshot-binding', 'internal/intake/service.go', "s.name=l.secret_name AND s.scope_level||':'||s.scope_id::text=l.scope AND s.class=l.class AND st.name=l.store_name AND ", '', './internal/intake', 'TestServiceRejectsDescriptorTampering', 'tampered descriptor readable'),
 ('zero-root', 'internal/builtin/local.go', 'if subtle.ConstantTimeCompare(raw, make([]byte, 32)) == 1 {', 'if false && subtle.ConstantTimeCompare(raw, make([]byte, 32)) == 1 {', './internal/builtin', 'TestLocalRootRejectsZero', 'zero root accepted'),
 ('nofollow', 'internal/builtin/local_unix.go', 'unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC', 'unix.O_RDONLY|unix.O_CLOEXEC', './internal/builtin', 'TestLocalRootFileSafety', 'symlink root accepted'),
 ('mode-0600', 'internal/builtin/local_unix.go', 'st.Mode&0777 != 0600', 'false', './internal/builtin', 'TestLocalRootFileSafety', 'public root file accepted'),
 # The root file's uid check (st.Uid != euid) has no mutation: exercising it
 # needs a second OS user, which a plain test run does not have.
 ('owner-user', 'cmd/keep-server/app/rotation.go', 'user = st.OwnerScope.ID.String()', 'workspace = st.OwnerScope.ID.String()', './cmd/keep-server/app', 'TestInputStoreScopeMapping', 'store mapped to wrong owner scope'),
 ('owner-workspace', 'cmd/keep-server/app/rotation.go', 'workspace = st.OwnerScope.ID.String()', 'user = st.OwnerScope.ID.String()', './cmd/keep-server/app', 'TestInputStoreScopeMapping', 'store mapped to wrong owner scope'),
 ('owner-org', 'cmd/keep-server/app/rotation.go', 'if st.OwnerScope.ID != st.OrgID {', 'if false && st.OwnerScope.ID != st.OrgID {', './cmd/keep-server/app', 'TestInputStoreScopeMapping', 'foreign organization owner accepted'),
 ('owner-project-workspace', 'cmd/keep-server/app/rotation.go', 'SELECT workspace_id::text FROM projects', "SELECT ''::text FROM projects", './cmd/keep-server/app', 'TestInputStoreScopeMapping', 'owner scope could not issue link'),
 ('owner-project-org', 'cmd/keep-server/app/rotation.go', 'FROM projects WHERE org_id=$1 AND id=$2', 'FROM projects WHERE (org_id=$1 OR true) AND id=$2', './cmd/keep-server/app', 'TestInputStoreScopeMapping', 'foreign project owner accepted'),
 # The completion hook has no mutant here: it is only the fast path, and the claim sweeper
 # starts the layout without it (see check-rotation-wiring-mutations.sh), so the end-to-end test stays green.
 # No mutant for "a plain link starts nothing" either: the hook only claims a pending row of
 # intake_rotation_links, a plain link has none, so a hook run for it is a no-op (an equivalent mutant).
 # Marking the link is guarded by rotation-link-issue below.
 ('rotation-link-issue', 'internal/api/rotate.go', 'IssueRotation(r.Context()', 'Issue(r.Context()', './cmd/keep-server/app', 'TestRotateE2E_HumanInputStartsTheLayout', 'finishing the input started no layout'),
 ('token-response', 'internal/api/intake.go', 'writeError(w, status, class, message, reqid.FromContext(r.Context()))', 'writeError(w, status, class, message+r.PathValue("token"), reqid.FromContext(r.Context()))', './internal/api', 'TestInputLinkTokenClosedSurfaces', 'input token escaped to HTTP or log'),
 ('token-header', 'internal/api/intake.go', 'writeError(w, status, class, message, reqid.FromContext(r.Context()))', 'w.Header().Set("X-Input-Token", r.PathValue("token")); writeError(w, status, class, message, reqid.FromContext(r.Context()))', './internal/api', 'TestInputLinkTokenClosedSurfaces', 'input token escaped to header'),
 ('token-log', 'internal/api/middleware.go', 'logger.Info("http_request",', 'logger.Info("http_request "+r.PathValue("token"),', './internal/api', 'TestInputLinkTokenClosedSurfaces', 'input token escaped to HTTP or log'),
 ('secret-disabled', 'internal/intake/service.go', " AND s.status='active' AND st.status='active'),false)", " AND st.status='active'),false)", './internal/builtin', 'TestIntakeServiceAvailabilityChanges', 'changed resource left link readable'),
 ('secret-moved', 'internal/intake/service.go', ' AND s.store_id=l.store_id AND ', ' AND ', './internal/builtin', 'TestIntakeServiceAvailabilityChanges', 'changed resource left link readable'),
 ('store-disabled', 'internal/intake/service.go', " AND st.status='active'),false)", '),false)', './internal/builtin', 'TestIntakeServiceAvailabilityChanges', 'changed resource left link readable'),
 ('token-length', 'internal/intake/service.go', 'if len(token) != 43 {', 'if false && len(token) != 43 {', './internal/intake', 'TestIntakeWireBounds', 'noncanonical token accepted'),
 ('enc-length', 'internal/intake/service.go', 'len(env.Enc) != 32', 'false', './internal/intake', 'TestIntakeWireBounds', 'out-of-bounds ciphertext accepted'),
 ('ciphertext-max', 'internal/intake/service.go', 'len(env.Ciphertext) > 1048592', 'false', './internal/intake', 'TestIntakeWireBounds', 'out-of-bounds ciphertext accepted'),
 ('ciphertext-min', 'internal/intake/service.go', 'len(env.Ciphertext) < 16', 'false', './internal/intake', 'TestIntakeWireBounds', 'out-of-bounds ciphertext accepted'),
 ('cli-token-stderr', 'cmd/keep/input_link.go', 'writeJSONValue(stdout, link)', 'writeJSONValue(stderr, link)', './cmd/keep', 'TestInputLinkCLITokenAndRedirectGuards', 'input token escaped to CLI stderr'),
 ('cli-redirect', 'cmd/keep/input_link.go', 'c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }', '', './cmd/keep', 'TestInputLinkCLITokenAndRedirectGuards', 'input-link CLI followed redirect'),
 ('credential-issue','internal/api/intake.go','(p.Scope != "" && p.Scope != ref.Scope.String())','false','./internal/api','TestInputLinkAuthorizationAndClosedRequest','foreign-scope credential issued link'),
 ('credential-status','internal/api/intake.go','(p.Scope != "" && p.Scope != scope.String())','false','./internal/api','TestInputLinkStatusRechecksCredentialRights','foreign-scope credential read intake status'),
 ('status-membership','internal/api/intake.go','if !perms[identity.PermReadMetadata] {','if false && !perms[identity.PermReadMetadata] {','./internal/api','TestInputLinkStatusRechecksCredentialRights','revoked issuer membership read intake status'),
 ('replay','internal/intake/service.go','if row.state != "active" {','if false && row.state != "active" {','./internal/intake','TestSingleUseAndHashOnly','one link admitted multiple completions'),
 ('expiry','internal/intake/service.go','l.expires_at<=clock_timestamp()','false','./internal/intake','TestExpiredAndInvalidTTL','expired link accepted'),
 ('ttl-default','internal/intake/service.go','ttl = 30 * time.Minute','ttl = 24 * time.Hour','./internal/intake','TestSingleUseAndHashOnly','token entropy or default TTL'),
 ('ttl-max','internal/intake/service.go','ttl > 24*time.Hour','false','./internal/intake','TestExpiredAndInvalidTTL','invalid TTL accepted'),
 ('token-hash','internal/intake/service.go','hash := sha256.Sum256(raw)','var hash [32]byte; copy(hash[:],raw)','./internal/intake','TestSingleUseAndHashOnly','token persisted without hashing'),
 ('audit-atomic','internal/intake/service.go','if err = s.record(ctx, tx, row, audit.ActionIntakeCompleted, result); err != nil {','if false {','./internal/builtin','TestIntakeServiceAtomicRaceAndRollback','audit failure accepted'),
 ('path-binding','internal/intake/service.go','s.provider_ref=l.provider_ref AND ','','./internal/builtin','TestIntakeServicePathBinding','link followed altered provider path'),
 ('plaintext-log','internal/builtin/intake.go','p.log.Info("intake sealed", "version_id", version)','p.log.Info(string(plain), "version_id", version)','./internal/builtin','TestIntakeServiceCanaryAndBinding','input canary escaped to HTTP or log'),
 ('scope-index','internal/store/migrations/00009_builtin_store_scope.sql',"WHERE provider = 'builtin';","WHERE false;",'./internal/catalog','TestBuiltinStoreUniqueOwnerScope','second builtin store accepted'),
 ('scope-preflight','internal/store/migrations/00009_builtin_store_scope.sql','IF EXISTS (','IF false AND EXISTS (','./internal/store','TestBuiltinStoreScopeMigration','migration did not explain duplicate'),
]
# Omit each request/public/metadata field independently, including empty Sponsor.
for label, before in [('request', 'requestID, '), ('public', 'string(public), '), ('name', 'm.SecretName, '), ('scope', 'm.Scope, '), ('store', 'm.StoreName, '), ('class', 'm.Class, '), ('requester', 'm.RequestedBy, '), ('sponsor', ', m.Sponsor')]:
 mutations.append(('descriptor-omit-'+label, 'internal/intake/descriptor/message.go', before, '', './internal/intake/descriptor', 'TestDescriptorCanonicalFields', 'missing UTF-8 byte length prefix'))
with tempfile.TemporaryDirectory(prefix='keep-intake-service-') as scratch:
 tree=pathlib.Path(scratch)/'tree';tree.mkdir()
 for name in set(files):
  if not name:continue
  src=root/name
  if not src.is_file():continue
  dst=tree/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
 env=os.environ.copy()
 # Inherit the cache exported and owned by the shell wrapper.
 for name,file,before,after,pkg,test,marker in mutations:
  target=tree/file;source=(root/file).read_text()
  if source.count(before)!=1:raise SystemExit('FAIL '+name+': mutation target is not unique')
  target.write_text(source.replace(before,after,1))
  if name == 'descriptor-public-base64':
   target.write_text(target.read_text().replace('"encoding/binary"', '"encoding/binary"\n\t"encoding/base64"', 1))
  secondary=None
  if name=='zero-root':
   # OpenLocal and the sealer constructor independently reject a zero key.
   # Disable both in scratch so the service assertion can witness acceptance.
   secondary=tree/'internal/builtin/sealer/rootkey.go'
   secondary_source=secondary.read_text()
   guard='if nonzero == 0 {'
   if secondary_source.count(guard)!=1:raise SystemExit('FAIL zero-root: sealer guard is not unique')
   secondary.write_text(secondary_source.replace(guard,'if false && nonzero == 0 {',1))
  try:
   if apply_only:
    print('ok   '+name+': applies',flush=True)
    continue
   r=subprocess.run(['go','test','-timeout','60s','-count=1','-run','^'+test+'$',pkg],cwd=tree,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
   out=r.stdout.decode(errors='replace')
   if not behavioral_failure(r.returncode, out, test, marker):
    raise SystemExit('FAIL '+name+': designated assertion was not reached')
   print('ok   '+name+': designated behavioral assertion rejected mutant',flush=True)
   print('  '+next(line.strip() for line in out.splitlines() if marker in line),flush=True)
  finally:
   target.write_text(source)
   if secondary is not None:secondary.write_text(secondary_source)
 if not apply_only:
  r=run_baseline('descriptor', ['go','test','-count=1','./internal/intake/descriptor'],cwd=tree,env=env,timeout=120)
  if r.returncode!=0:raise SystemExit('FAIL descriptor baseline: canonical properties did not pass')
  print('ok   descriptor baseline: canonical properties passed',flush=True)
  # Migration controls rebuild the shared test schema; restore before baseline.
  r=run_baseline('schema-restore', ['go','test','-timeout','60s','-count=1','-run','^TestBuiltinStoreScopeMigration$','./internal/store'],cwd=tree,env=env,timeout=120)
  if r.returncode!=0:raise SystemExit('FAIL schema restore: canonical migration did not pass')
  # cmd/keep-server/app alone runs ~170s with -race on a core runner and
  # crosses 240s on the shared mutation runner; the budget is per package.
  r=run_baseline('service', ['go','test','-race','-p','1','-timeout','480s','-count=1','-v','./internal/intake','./internal/builtin','./internal/api','./internal/catalog','./internal/store','./cmd/keep-server/app','./cmd/keep'],cwd=tree,env=env,timeout=900,prohibited_skips=('--- SKIP: TestIntake', '--- SKIP: TestSingleUse'))
  out=r.stdout.decode(errors='replace')
  if r.returncode!=0 or '--- SKIP: TestIntake' in out or '--- SKIP: TestSingleUse' in out:
   raise SystemExit('FAIL baseline: service tests did not pass')
  print('ok   baseline: PostgreSQL race tests passed with no intake skips',flush=True)
PY

# Write-boundary metadata guards use their own designated API/catalog probes.
"$root/scripts/metadata-mutations.sh"
