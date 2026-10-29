#!/bin/sh
# Prove receiver guards against concrete leaks and broken request binding.
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
. "$root/scripts/mutation-helpers.sh"
# Private per-run build cache: on a host shared by several clones a
# default $GOCACHE can serve one clone's half-written entries to another,
# giving spurious build failures. Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
if ! mutation_apply_only && [ -z "${KEEP_DATABASE_URL:-}" ]; then
 echo 'FAIL: a migrated PostgreSQL database is required' >&2
 exit 2
fi
. "$root/scripts/temp-workspace.sh"
temp_workspace
python3 - <<'PY'
import os, pathlib, shutil, subprocess, tempfile
apply_only=os.environ.get('MUTATION_APPLY_ONLY')=='1'
# Anchors in the circl dependency, shared by the mutants and the apply-only check.
LOW_ORDER_BEFORE='if !x25519.Shared(&ss, &sKey, &pKey) {\n\t\t\treturn ErrInvalidKEMSharedSecret\n\t\t}'
WIPE_BEFORE='return pt, nil'
root=pathlib.Path.cwd()
files=subprocess.check_output(['git','ls-files','-co','--exclude-standard','-z']).decode().split('\0')
mutations=[
 ('open-error','internal/builtin/intake.go','if openErr != nil {','if openErr != nil && false {','TestIntakeAcceptBoundCiphertext','ciphertext accepted for another request'),
 ('post-decrypt-error','internal/builtin/intake.go','value := secret.New(plain)','fail = fmt.Errorf("builtin: intake rejected: %s", plain)\n\tvalue := secret.New(plain)','TestIntakePostDecryptErrorsAreRedacted','post-decrypt error leaked plaintext'),
 ('insert-conflict','internal/builtin/intake.go','if err != nil || !inserted {','if err != nil || false && !inserted {','TestIntakePostDecryptErrorsAreRedacted','post-decrypt refusal accepted'),
 ('nil-transaction','internal/builtin/intake.go','tx == nil','false','TestIntakeNilTransaction','nil intake transaction reached backend'),
 ('bundle-length','internal/builtin/intake.go','if len(raw) != 32+ed25519.PrivateKeySize {\n\t\t\topenErr = fail','if false {\n\t\t\topenErr = fail','TestIntakeBundleLength','invalid bundle length accepted'),
 ('key-provenance','internal/builtin/intake.go','const intakeKeyName = "keep/server-intake-key/v1"','const intakeKeyName = "__keep_intake_key__"','TestIntakeRejectsUserCreatedKey','user-created intake key accepted'),
 ('uuid-validation','internal/builtin/intake.go','err == nil && id.String() == requestID && id.Version() == 7 && id.Variant() == uuid.RFC4122','err == nil && id != uuid.Nil','TestIntakeInputGuards','invalid request'),
 ('uuid-canonical','internal/builtin/intake.go','id.String() == requestID','true','TestIntakeInputGuards','invalid request'),
 ('uuid-version','internal/builtin/intake.go','id.Version() == 7','true','TestIntakeInputGuards','invalid request'),
 ('uuid-variant','internal/builtin/intake.go','id.Variant() == uuid.RFC4122','true','TestIntakeInputGuards','invalid request'),
 ('enc-size','internal/builtin/intake.go','len(enc) != 32','false','TestIntakeInputGuards','invalid intake size reached backend'),
 ('ct-min','internal/builtin/intake.go','len(ciphertext) < 16','false','TestIntakeInputGuards','invalid intake size reached backend'),
 ('ct-max','internal/builtin/intake.go','len(ciphertext) > 1048592','false','TestIntakeInputGuards','invalid intake size reached backend'),
 ('available','internal/builtin/intake.go','p.checkAvailable(ctx) != nil','false','TestIntakeInputGuards','unavailable intake reached backend'),
 ('receiver-lock','internal/builtin/intake.go','db := p.db.withTx(tx)\n\tif _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`, levelLockKey(p.scope.Org));','db := p.db.withTx(tx)\n\tif _, err := tx.Exec(ctx, `SELECT $1::text`, levelLockKey(p.scope.Org));','TestIntakeInputGuards','intake shared key-level lock missing'),
 ('key-at-rest','internal/builtin/intake.go','inserted, err := txStore.insertIfAbsent','env.Ciphertext = append([]byte(nil), bundle...)\n\tinserted, err := txStore.insertIfAbsent','TestIntakePrivateKeyIsSealedAtRest','intake private key stored as plaintext'),
 ('reserved-key','internal/builtin/fpkey.go','path == fpKeySecretID || path == intakeKeySecretID','path == fpKeySecretID','TestIntakeKeyReservedFromProvider','Resolve allowed reserved intake key'),
 ('reserved-path','internal/builtin/intake.go','if pathErr(path) != nil {','if false {','TestIntakeAcceptBoundCiphertext','reserved intake path accepted'),
 ('store-isolation','internal/builtin/intake.go','db := p.db.withTx(tx)','p.scope.User = "alice"\n\tdb := p.db.withTx(tx)','TestIntakeCiphertextStoreIsolation','store A ciphertext accepted by store B'),
 ('concurrent-key','internal/builtin/intake.go','value.Wipe()\n\t\t_ = tx.Rollback(ctx)\n\t\treturn p.intakeKeys(ctx)','_ = tx.Rollback(ctx)\n\t\treturn value, nil','TestIntakeKeyConcurrentInitialization','concurrent callers disagree on intake key'),
 ('request-binding','internal/builtin/intake.go','[]byte("keep/intake/v1\\x00"+requestID)','[]byte("keep/intake/v1\\x00"+"019a0000-0000-7000-8000-000000000001")','TestIntakeAcceptBoundCiphertext','ciphertext accepted for another request'),
 ('value-at-rest','internal/builtin/intake.go','inserted, err := db.insertIfAbsent','env.Ciphertext = append([]byte(nil), plain...)\n\tinserted, err := db.insertIfAbsent','TestIntakeAcceptBoundCiphertext','plaintext escaped intake zone'),
 ('signature','internal/builtin/intake.go','descriptor.Message(requestID, public, metadata)','descriptor.Message(requestID, public, descriptor.Metadata{})','TestIntakeAcceptBoundCiphertext','descriptor signature invalid'),
 ('caller-transaction','internal/builtin/intake.go','return version, fp, value.Len(), nil','if path == "rolled-back" { _ = tx.Commit(ctx) }; return version, fp, value.Len(), nil','TestIntakeAcceptBoundCiphertext','rollback probe'),
]
# Inherit the cache exported and owned by the shell wrapper.
env=os.environ.copy()
with tempfile.TemporaryDirectory(prefix='keep-intake-mutants-') as d:
 tree=pathlib.Path(d)/'tree';tree.mkdir()
 for name in set(files):
  if not name:continue
  src=root/name
  if not src.is_file():continue
  dest=tree/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest)
 for name,file,before,after,test,marker in mutations:
  dest=tree/file;source=(root/file).read_text()
  if source.count(before)!=1:raise SystemExit('FAIL '+name+': mutation target is not unique')
  changed=source.replace(before,after,1)
  if name=='post-decrypt-error': changed=changed.replace('"errors"','"errors"\n\t"fmt"',1)
  dest.write_text(changed)
  try:
   if apply_only:
    print('ok   '+name+': applies',flush=True)
    continue
   result=subprocess.run(['go','test','-timeout','60s','-count=1','-run','^'+test+'$','./internal/builtin'],cwd=tree,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
   out=result.stdout.decode(errors='replace')
   if result.returncode==0 or '--- FAIL: '+test not in out or marker not in out:
    raise SystemExit('FAIL '+name+': expected behavioral assertion was not reached')
   print('ok   '+name+': behavioral assertion rejected mutant',flush=True)
  finally:dest.write_text(source)
 if apply_only:
  # The dependency mutants need `go list`/`go mod edit`; check their anchors
  # in the module cache, read-only. A cache without circl is a failure: the
  # anchors would go unchecked.
  anchors=[('low-order','hpke/xkem.go',LOW_ORDER_BEFORE),('wipe','hpke/aead.go',WIPE_BEFORE)]
  version=next(l.split()[1] for l in (root/'go.mod').read_text().splitlines() if 'github.com/cloudflare/circl ' in l)
  module=pathlib.Path(subprocess.check_output(['go','env','GOMODCACHE'],cwd=root,env=env).decode().strip())/('github.com/cloudflare/circl@'+version)
  if not module.is_dir():
   raise SystemExit('FAIL low-order, wipe: circl '+version+' is not in the module cache; run go mod download')
  for name,rel,before in anchors:
   if (module/rel).read_text().count(before)!=1:raise SystemExit('FAIL '+name+': dependency mutation target is not unique')
   print('ok   '+name+': applies',flush=True)
  if (root/'internal/builtin/intake.go').read_text().count('defer clear(plain)')!=1:raise SystemExit('FAIL plaintext-wipe: caller target is not unique')
  print('ok   plaintext-wipe: applies',flush=True)
  raise SystemExit(0)
 # Mutate a private dependency copy, never the shared module cache.
 module=pathlib.Path(subprocess.check_output(['go','list','-m','-f','{{.Dir}}','github.com/cloudflare/circl'],cwd=root,env=env).decode().strip())
 dependency=pathlib.Path(d)/'circl'
 shutil.copytree(module,dependency)
 target=dependency/'hpke/xkem.go'
 source=target.read_text()
 before=LOW_ORDER_BEFORE
 if source.count(before)!=1:raise SystemExit('FAIL low-order: dependency mutation target is not unique')
 target.chmod(0o644)
 target.write_text(source.replace(before,'_ = x25519.Shared(&ss, &sKey, &pKey)',1))
 subprocess.run(['go','mod','edit','-replace=github.com/cloudflare/circl='+str(dependency)],cwd=tree,env=env,check=True)
 result=subprocess.run(['go','test','-timeout','60s','-count=1','-run','^TestIntakeRejectsLowOrderDH$','./internal/builtin'],cwd=tree,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
 out=result.stdout.decode(errors='replace')
 if result.returncode==0 or '--- FAIL: TestIntakeRejectsLowOrderDH' not in out or 'zero-DH ciphertext accepted' not in out:
  raise SystemExit('FAIL low-order: expected behavioral assertion was not reached')
 print('ok   low-order: zero-DH assertion rejected dependency mutant',flush=True)
 # Retain the actual Open buffer in this private dependency only. This
 # observes cleanup after both success and post-decryption refusal without
 # adding a plaintext hook to production or changing the shared cache.
 target.write_text(source)
 aead=dependency/'hpke/aead.go'
 aead_source=aead.read_text()
 before=WIPE_BEFORE
 if aead_source.count(before)!=1:raise SystemExit('FAIL wipe: Open probe target is not unique')
 aead.chmod(0o644)
 aead.write_text(aead_source.replace(before,'IntakePlaintextProbe = pt\n\treturn pt, nil',1))
 (dependency/'hpke').chmod(0o755)
 (dependency/'hpke/intake_plaintext_probe.go').write_text('package hpke\nvar IntakePlaintextProbe []byte\n')
 shutil.copyfile(root/'scripts/testdata/intake-wipe-probe.go.txt',tree/'internal/builtin/intake_wipe_probe_test.go')
 cmd=['go','test','-race','-timeout','60s','-count=1','-v','-run','^TestIntakePlaintextWipe$','./internal/builtin']
 result=subprocess.run(cmd,cwd=tree,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
 out=result.stdout.decode(errors='replace')
 if result.returncode or '--- SKIP' in out or '--- PASS: TestIntakePlaintextWipe' not in out:
  raise SystemExit('FAIL wipe baseline: Open buffer control failed or skipped')
 caller=tree/'internal/builtin/intake.go'
 caller_source=caller.read_text()
 if caller_source.count('defer clear(plain)')!=1:raise SystemExit('FAIL wipe: caller target is not unique')
 caller.write_text(caller_source.replace('defer clear(plain)','// plaintext wipe removed',1))
 result=subprocess.run(cmd,cwd=tree,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
 out=result.stdout.decode(errors='replace')
 if result.returncode==0 or '--- FAIL: TestIntakePlaintextWipe' not in out or 'intake plaintext wipe missing' not in out:
  raise SystemExit('FAIL plaintext-wipe: retained Open buffer assertion was not reached')
 caller.write_text(caller_source)
 print('ok   plaintext-wipe: retained Open buffer rejected mutant (success and refusal baseline passed)',flush=True)
 result=subprocess.run(['go','test','-race','-timeout','60s','-count=1','-v','-run','^TestIntake','./internal/builtin'],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
 out=result.stdout.decode(errors='replace')
 if result.returncode or '--- SKIP' in out or '--- PASS: TestIntakeAcceptBoundCiphertext' not in out:
  raise SystemExit('FAIL baseline: receiver tests failed or skipped')
 print('ok   baseline: receiver tests passed with no skips')
PY
