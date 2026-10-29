import assert from 'node:assert/strict';
import {chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, statfs, symlink, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {allocateChromiumProfile, profileAllocationDiagnostic, withChromiumProfile} from './lib/chromium-profile.mjs';

const base = await realpath(await mkdtemp(join(tmpdir(), 'keep-profile-controls-')));
const root = join(base, 'dedicated'), fallback = join(base, 'fallback');
const uid = process.getuid?.();
const prefix = 'keep-intake-browser-';
const privateError = () => new Error('PRIVATE_PROFILE_SENTINEL');
const native = {chmod, lstat, mkdtemp, realpath, rm, statfs};
// Positive admission is simulated tmpfs metadata over real private directories;
// no claim of native Linux tmpfs/Chromium execution is made by these controls.
const admitted = {...native, statfs:async () => ({type:0x01021994, bsize:4096, bavail:32768})};
const options = {root, fallbackRoot:fallback, platform:'linux', uid, io:admitted};
let controls = 0;
async function check(name, run) { await run(); controls++; console.log(JSON.stringify({control:'profile-' + name, passed:true})); }
async function absent(path) {await assert.rejects(lstat(path), error => error.code === 'ENOENT');}
async function fallbackCase(name, overrides, reason) {
  await check(name, async () => {
    const lease = await allocateChromiumProfile(prefix, {...options, ...overrides});
    assert.equal(lease.diagnostic.placement, 'fallback');
    assert.equal(lease.diagnostic.reason, reason);
    assert(lease.path.startsWith(fallback + '/'));
    await lease.cleanup(); await absent(lease.path);
  });
}
try {
  await mkdir(root, {mode:0o700}); await mkdir(fallback, {mode:0o700});
  await writeFile(join(root, 'foreign'), 'preserve', {mode:0o600});
  await check('default-native-private-unique-cleanup', async () => {
    const a = await allocateChromiumProfile(prefix, {...options, root:''});
    const b = await allocateChromiumProfile(prefix, {...options, root:''});
    assert.notEqual(a.path, b.path); assert.equal(a.diagnostic.reason, 'not-configured');
    assert.equal((await lstat(a.path)).mode & 0o777, 0o700);
    await a.cleanup(); await a.cleanup(); await b.cleanup();
    await absent(a.path); await absent(b.path);
  });
  await check('admitted-real-directory-mode', async () => {
    const lease = await allocateChromiumProfile(prefix, options);
    assert.equal(lease.diagnostic.placement, 'ram');
    assert.equal(lease.diagnostic.available_bytes, 128 * 1024 * 1024);
    assert.equal((await lstat(lease.path)).mode & 0o777, 0o700);
    assert(lease.path.startsWith(root + '/')); await lease.cleanup();
    assert.deepEqual(await readdir(root), ['foreign']);
  });
  await fallbackCase('non-linux', {platform:'darwin'}, 'non-linux');
  await fallbackCase('non-tmpfs', {io:{...native, statfs:async () => ({type:0x794c7630,bsize:4096,bavail:100000})}}, 'not-tmpfs');
  await fallbackCase('low-capacity-64MiB', {io:{...admitted, statfs:async () => ({type:0x01021994,bsize:4096,bavail:16384})}}, 'low-space');
  await fallbackCase('invalid-capacity', {io:{...admitted, statfs:async () => ({type:0x01021994,bsize:4096,bavail:NaN})}}, 'low-space');
  await chmod(root, 0o755);
  await fallbackCase('non-private-parent', {}, 'not-private'); await chmod(root, 0o700);
  await fallbackCase('foreign-parent-owner', {io:{...admitted, lstat:async path => {
    const info = await lstat(path); return path === root ? {isDirectory:() => true,mode:info.mode,uid:uid+1} : info;
  }}}, 'not-private');
  const alias = join(base, 'alias'); await symlink(root, alias);
  await fallbackCase('symlink-parent', {root:alias}, 'invalid-root');
  await fallbackCase('shared-memory-parent', {root:'/dev/shm'}, 'shared-root');
  await fallbackCase('shared-memory-descendant', {root:'/dev/shm/private'}, 'shared-root');
  await fallbackCase('shared-memory-alias', {io:{...admitted, realpath:async path => path === root ? '/dev/shm/private' : realpath(path)}}, 'shared-root');
  await fallbackCase('read-error-privacy', {io:{...admitted, statfs:async () => {throw privateError();}}}, 'unavailable');
  await check('admission-hang-no-late-allocation', async () => {
    let allocations = 0;
    const io = {...admitted, statfs:() => new Promise(resolve => setTimeout(() => resolve({type:0x01021994,bsize:4096,bavail:100000}), 100)),
      mkdtemp:async path => {allocations++;return mkdtemp(path);}};
    const start = performance.now(); const lease = await allocateChromiumProfile(prefix, {...options, io});
    assert.equal(lease.diagnostic.reason, 'timed-out'); assert(performance.now()-start < 500);
    await new Promise(resolve => setTimeout(resolve, 120)); assert.equal(allocations, 1);
    assert(lease.path.startsWith(fallback + '/')); await lease.cleanup();
  });
  await fallbackCase('ram-create-error', {io:{...admitted, mkdtemp:async path => {
    if (path.startsWith(root + '/')) throw privateError(); return mkdtemp(path);
  }}}, 'allocation-failed');
  await fallbackCase('ram-permission-error-owned-cleanup', {io:{...admitted, chmod:async (path, mode) => {
    if (path.startsWith(root + '/')) throw privateError(); return chmod(path, mode);
  }}}, 'allocation-failed');
  assert.deepEqual(await readdir(root), ['foreign']);
  await check('setup-error-cleans-profile-before-spawn', async () => {
    let owned, spawns = 0; const primary = privateError();
    await assert.rejects(withChromiumProfile(prefix, async lease => {owned=lease.path;throw primary;spawns++;}, options), error => error === primary);
    assert.equal(spawns, 0); await absent(owned);
  });
  await check('one-cleanup-even-after-primary', async () => {
    let removals=0; const io={...admitted, rm:async (...args) => {removals++;return rm(...args);}};
    const primary=privateError();
    await assert.rejects(withChromiumProfile(prefix, async lease => {await lease.cleanup();throw primary;}, {...options,io}), error => error===primary);
    assert.equal(removals,1);
  });
  await check('foreign-profile-owner-not-removed', async () => {
    let foreign=false, removals=0;
    const io={...admitted, lstat:async path => {const info=await lstat(path);return foreign && path!==root ? {isDirectory:()=>true,uid:uid+1,mode:info.mode} : info;}, rm:async () => {removals++;}};
    const lease=await allocateChromiumProfile(prefix,{...options,io}); foreign=true;
    await assert.rejects(lease.cleanup(), error => error.code==='CLEANUP_PROFILE');
    assert.equal(removals,0); await rm(lease.path,{recursive:true,force:true});
  });
  await check('replaced-same-owner-directory-not-removed', async () => {
    const lease=await allocateChromiumProfile(prefix,options);
    const old=lease.path+'-old';
    await rename(lease.path,old);await mkdir(lease.path,{mode:0o700});
    await writeFile(join(lease.path,'foreign'),'preserve');
    await assert.rejects(lease.cleanup(),error=>error.code==='CLEANUP_PROFILE');
    assert.equal(await readFile(join(lease.path,'foreign'),'utf8'),'preserve');
    await rm(lease.path,{recursive:true,force:true});await rm(old,{recursive:true,force:true});
  });
  await check('cleanup-error-retains-primary-safe-event', async () => {
    const primary=privateError(), output=[]; const write=process.stderr.write; let owned;
    process.stderr.write=line => {output.push(String(line));return true;};
    try {
      await assert.rejects(withChromiumProfile(prefix, async lease => {owned=lease.path;throw primary;},
        {...options,io:{...admitted,rm:async () => {throw privateError();}}}), error => error===primary);
    } finally {process.stderr.write=write; if(owned)await rm(owned,{recursive:true,force:true});}
    assert.deepEqual(output,[JSON.stringify({event:'chromium-profile-cleanup-failed',code:'CLEANUP_PROFILE'})+'\n']);
    assert(!output.join('').includes('PRIVATE_PROFILE_SENTINEL'));
  });
  await check('diagnostic-fixed-enums-numbers', async () => {
    const diagnostic=profileAllocationDiagnostic({placement:'PRIVATE_PROFILE_SENTINEL',reason:'/private/path',filesystem_type:'bad',available_bytes:-1,secret:'PRIVATE_PROFILE_SENTINEL'});
    assert.equal(diagnostic.placement,'fallback');assert.equal(diagnostic.reason,'unavailable');
    assert.equal(diagnostic.filesystem_type,null);assert.equal(diagnostic.available_bytes,null);
    assert(!JSON.stringify(diagnostic).includes('PRIVATE_PROFILE_SENTINEL'));assert(!JSON.stringify(diagnostic).includes('/'));
  });
  await check('shared-TMPDIR-alias-not-used', async () => {
    const io={...admitted,realpath:async path => path===fallback ? '/dev/shm/alias' : realpath(path)};
    const lease=await allocateChromiumProfile(prefix,{...options,root:'',io});
    assert(lease.path.startsWith(await realpath('/tmp') + '/')); await lease.cleanup();
  });
  await check('tmp-alias-to-shared-memory-rejected', async () => {
    let calls = 0;
    const io={...admitted,realpath:async path => {calls++; return path==='/tmp'||path===fallback ? '/dev/shm' : realpath(path);},
      mkdtemp:async () => {throw new Error('must not allocate in shared memory');}};
    await assert.rejects(allocateChromiumProfile(prefix,{...options,root:'',io}), /allocation failed/);
    assert(calls>=1);
  });
  await check('canonical-tmp-realpath-checked-and-used', async () => {
    let seen=[]; const io={...admitted,realpath:async path => {seen.push(path); return realpath(path);}};
    const lease=await allocateChromiumProfile(prefix,{...options,root:'',fallbackRoot:'/tmp',io});
    assert(seen.includes('/tmp')); assert(lease.path.startsWith(await realpath('/tmp') + '/')); await lease.cleanup();
  });
  assert.deepEqual(await readdir(root), ['foreign']);assert.deepEqual(await readdir(fallback), []);
  console.log(JSON.stringify({profile_controls:controls,passed:true,native_tmpfs_executed:false}));
} finally {await rm(base,{recursive:true,force:true});}
