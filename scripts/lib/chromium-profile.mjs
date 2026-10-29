import {chmod, lstat, mkdtemp, realpath, rm, statfs} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {basename, dirname, isAbsolute, join, resolve} from 'node:path';

// Admission only, not a measured profile peak or a filesystem quota. The
// separately configured private mount must also have a size/memory bound.
const tmpfs = 0x01021994;
const allowance = 64 * 1024 * 1024, reserve = 64 * 1024 * 1024;
const prefixes = new Set(['keep-intake-browser-', 'keep-input-page-', 'keep-mesh-ui-']);
const reasons = new Set(['admitted', 'not-configured', 'non-linux', 'shared-root',
  'invalid-root', 'not-private', 'not-tmpfs', 'low-space', 'unavailable',
  'timed-out', 'allocation-failed']);
const number = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const shared = path => path === '/dev/shm' || path.startsWith('/dev/shm/');
const fixedError = () => Object.assign(new Error('Chromium profile cleanup incomplete'), {code:'CLEANUP_PROFILE'});

// Revalidate even caller-provided metadata before placing it in diagnostics.
export function profileAllocationDiagnostic(value) {
  return {placement:value?.placement === 'ram' ? 'ram' : 'fallback',
    reason:reasons.has(value?.reason) ? value.reason : 'unavailable',
    admission_budget_ms:50, profile_allowance_bytes:allowance, reserve_bytes:reserve,
    filesystem_type:number(value?.filesystem_type), available_bytes:number(value?.available_bytes)};
}

export async function allocateChromiumProfile(prefix, options = {}) {
  if (!prefixes.has(prefix)) throw new Error('Invalid Chromium profile kind');
  const io = options.io || {chmod, lstat, mkdtemp, realpath, rm, statfs};
  const root = options.root ?? process.env.KEEP_CHROMIUM_PROFILE_ROOT;
  const platform = options.platform ?? process.platform;
  const uid = options.uid ?? process.getuid?.();
  // Do not consume Chromium's shared-memory mount through TMPDIR either.
  const requestedFallback = resolve(options.fallbackRoot ?? tmpdir());
  let fallback = platform === 'linux' && shared(requestedFallback) ? '/tmp' : requestedFallback;
  let metadata = {placement:'fallback', reason:'not-configured'}, admitted;
  if (root) {
    if (platform !== 'linux') metadata.reason = 'non-linux';
    else if (typeof root !== 'string' || !isAbsolute(root)) metadata.reason = 'invalid-root';
    else if (shared(resolve(root))) metadata.reason = 'shared-root';
    else {
      let timer;
      try {
        const check = async () => {
          const canonical = await io.realpath(root);
          if (shared(canonical)) return {reason:'shared-root'};
          // Reject symlink spellings and nonprivate roots; do not create or
          // chmod any shared/configured parent directory.
          if (canonical !== resolve(root)) return {reason:'invalid-root'};
          const info = await io.lstat(root);
          if (!info.isDirectory() || info.uid !== uid || (info.mode & 0o777) !== 0o700)
            return {reason:'not-private'};
          const fs = await io.statfs(root);
          const bytes = fs.bavail * fs.bsize;
          const fields = {filesystem_type:number(fs.type), available_bytes:number(bytes)};
          if (fs.type !== tmpfs) return {...fields, reason:'not-tmpfs'};
          if (number(bytes) === null || bytes < allowance + reserve)
            return {...fields, reason:'low-space'};
          return {...fields, reason:'admitted', root:canonical};
        };
        const result = await Promise.race([check(), new Promise(resolve => {
          timer = setTimeout(() => resolve({reason:'timed-out'}), 50);
        })]);
        metadata = {...metadata, ...result};
        admitted = result.root;
      } catch { metadata.reason = 'unavailable'; }
      finally { clearTimeout(timer); }
    }
  }
  let profile, identity, cleanupAttempted = false;
  const create = async parent => {
    const path = await io.mkdtemp(join(parent, prefix));
    // Remember only the exact path returned by our mkdtemp. Never derive a
    // parent/root deletion from configuration or a failure message.
    if (dirname(path) !== parent || !basename(path).startsWith(prefix))
      throw new Error('Invalid owned Chromium profile');
    profile = path;
    const created = await io.lstat(path);
    if (!created.isDirectory() || (uid !== undefined && created.uid !== uid))
      throw new Error('Invalid owned Chromium profile');
    identity = {uid:created.uid, dev:created.dev, ino:created.ino};
    await io.chmod(path, 0o700);
    const info = await io.lstat(path);
    if (!info.isDirectory() || (info.mode & 0o777) !== 0o700 ||
      info.uid !== identity.uid || info.dev !== identity.dev || info.ino !== identity.ino)
      throw new Error('Invalid owned Chromium profile');
  };
  const remove = async () => {
    let timer;
    try {
      const owned = async () => {
        let info;
        try { info = await io.lstat(profile); }
        catch (error) { if (error?.code === 'ENOENT') return; throw error; }
        if (!identity || !info.isDirectory() || info.uid !== identity.uid ||
          info.dev !== identity.dev || info.ino !== identity.ino) throw fixedError();
        await io.rm(profile, {recursive:true, force:true, maxRetries:10, retryDelay:100});
      };
      await Promise.race([owned(),
        new Promise((_, reject) => {timer = setTimeout(() => reject(fixedError()), 2000);})]);
    } catch { throw fixedError(); }
    finally { clearTimeout(timer); }
  };
  if (admitted) {
    try { await create(admitted); metadata.placement = 'ram'; }
    catch {
      if (profile) await remove();
      profile = identity = undefined;
      metadata.reason = 'allocation-failed';
    }
  }
  if (!profile) {
    if (platform === 'linux') {
      // Canonicalize every candidate, /tmp included: /tmp may alias /dev/shm.
      const safe = async candidate => {
        let timer;
        try {
          const canonical = await Promise.race([io.realpath(candidate), new Promise(resolve => {
            timer = setTimeout(() => resolve(null), 50);
          })]);
          return canonical && isAbsolute(canonical) && !shared(canonical) ? canonical : null;
        } catch { return null; }
        finally { clearTimeout(timer); }
      };
      fallback = await safe(fallback) ?? (fallback !== '/tmp' ? await safe('/tmp') : null);
      if (!fallback) throw new Error('Chromium profile allocation failed');
    }
    try { await create(fallback); }
    catch {
      if (profile) await remove();
      throw new Error('Chromium profile allocation failed');
    }
  }
  return {path:profile, diagnostic:profileAllocationDiagnostic(metadata),
    async cleanup() {
      if (cleanupAttempted) return;
      cleanupAttempted = true;
      await remove();
    }};
}

// Enclose setup too: a server/URL/spawn failure must not orphan the profile.
export async function withChromiumProfile(prefix, run, options) {
  const lease = await allocateChromiumProfile(prefix, options);
  let primary;
  try { return await run(lease); }
  catch (error) { primary = error; throw error; }
  finally {
    try { await lease.cleanup(); }
    catch (error) {
      if (!primary) throw error;
      process.stderr.write(JSON.stringify({event:'chromium-profile-cleanup-failed', code:'CLEANUP_PROFILE'}) + '\n');
    }
  }
}
