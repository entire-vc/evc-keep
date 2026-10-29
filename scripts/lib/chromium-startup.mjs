// Bounded readiness and fixed diagnostics; never expose child output or paths.
import {spawnSync} from 'node:child_process';
import {readdirSync, readFileSync} from 'node:fs';
import {readFile, readlink, statfs} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {basename, join} from 'node:path';
import {profileAllocationDiagnostic} from './chromium-profile.mjs';

const signals = new Set(['SIGABRT', 'SIGBUS', 'SIGILL', 'SIGKILL', 'SIGSEGV', 'SIGTERM', 'SIGTRAP']);
const errors = new Set(['ENOENT', 'EACCES', 'ENOMEM']);
const readErrors = new Set(['ENOENT', 'EACCES', 'EIO', 'ENOTDIR', 'EISDIR']);
const stderrLimit = 8192;
const signatures = [['sandbox-refused', /Running as root without --no-sandbox|No usable sandbox/], ['profile-in-use', /SingletonLock|Failed to create a ProcessSingleton/], ['shared-memory-failed', /Unable to access.*\/dev\/shm|Failed to create shared memory/], ['disk-full', /No space left on device/], ['permission-denied', /Permission denied/], ['crashpad-required', /chrome_crashpad_handler: --database is required/]];
// Live members of a process group, or null when they cannot be enumerated: an
// unreadable process table is "unknown", never "empty". A killed process stays a
// zombie until its (possibly absent) init reaps it; it holds no profile files,
// so it is not live.
export function liveGroupMembers(pgid, io = {platform: process.platform, readdirSync, readFileSync, spawnSync}) {
  const live = [];
  try {
    if (io.platform === 'linux') {
      for (const name of io.readdirSync('/proc')) {
        if (!/^[0-9]+$/.test(name)) continue;
        try {
          const stat = io.readFileSync(`/proc/${name}/stat`, 'utf8');
          const [state, , group] = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
          if (Number(group) === pgid && state !== 'Z') live.push(Number(name));
        } catch (err) { if (err?.code !== 'ENOENT' && err?.code !== 'ESRCH') return null; }
      }
    } else {
      const run = io.spawnSync('ps', ['-A', '-o', 'pid=,pgid=,stat='], {encoding: 'utf8', timeout: 2000});
      if (run.error || run.status !== 0 || typeof run.stdout !== 'string' || run.stdout.trim() === '') return null;
      for (const line of run.stdout.split('\n')) {
        if (line.trim() === '') continue;
        const [pid, group, state] = line.trim().split(/\s+/);
        if (!/^[0-9]+$/.test(pid || '') || !/^[0-9]+$/.test(group || '') || !state) return null;
        if (Number(group) === pgid && !state.startsWith('Z')) live.push(Number(pid));
      }
    }
  } catch { return null; }
  return live;
}
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

// Readiness budget for a browser start. On a loaded shared runner the browser
// has been observed still not ready after 5 s (process alive, readiness marker
// missing); the cause was not established. The checkers use 20 s.
// Every successful start logs its elapsed time. Library callers that
// pass nothing keep 5 s, which the startup controls rely on. The environment
// override exists so those controls can run the real checkers with a short
// budget; anything outside 1 s..120 s is ignored.
export const STARTUP_BUDGET_MS = 20000;
export function startupBudget(env = process.env) {
  const value = Number(env.KEEP_CHROMIUM_STARTUP_MS);
  return Number.isInteger(value) && value >= 1000 && value <= 120000 ? value : STARTUP_BUDGET_MS;
}
// True once the DevTools endpoint lists a page target. Any error, status or body
// is only "not yet": nothing from the response reaches diagnostics.
async function pageTargetReady(port) {
  try {
    const response = await fetch(`http://127.0.0.1:${port}/json/list`, {signal: AbortSignal.timeout(250)});
    if (response.status !== 200) return false;
    const targets = await response.json();
    return Array.isArray(targets) && targets.some(target => target?.type === 'page');
  } catch { return false; }
}

// Fixed fields only: no paths, command lines, environment or raw /proc content.
export async function startupSnapshot(profile, pid, io = {readFile, readlink, statfs}) {
  const number = value => Number.isSafeInteger(Number(value)) && Number(value) >= 0 ? Number(value) : null;
  const text = async path => { try { return await io.readFile(path, 'utf8'); } catch { return ''; } };
  const fs = async path => { try { const s = await io.statfs(path); return {type:number(s.type), block_bytes:number(s.bsize), blocks:number(s.blocks), available_blocks:number(s.bavail)}; } catch { return null; } };
  const metrics = async (path, keys) => {
    const out = {};
    for (const line of (await text(path)).split('\n')) {
      const [key, value] = line.trim().split(/\s+/);
      if (keys.includes(key) && /^\d+$/.test(value || '') && number(value) !== null) out[key] = number(value);
    }
    return out;
  };
  const processes = [], pending = Number.isSafeInteger(pid) && pid > 0 ? [pid] : [], seen = new Set();
  const kinds = new Set(['chromium', 'chrome', 'chrome_crashpad_handler']);
  while (pending.length && seen.size < 64) {
    const id = pending.shift(); if (seen.has(id)) continue; seen.add(id);
    const stat = await text(`/proc/${id}/stat`); if (!stat) continue;
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    let kind = 'other'; try { const name = basename(await io.readlink(`/proc/${id}/exe`)); if (kinds.has(name)) kind = name; } catch {}
    processes.push({kind, state:['R','S','D','Z','T','t','I','X'].includes(fields[0]) ? fields[0] : 'other'});
    const children = (await text(`/proc/${id}/task/${id}/children`)).trim().split(/\s+/).filter(x => /^\d+$/.test(x)).map(Number);
    pending.push(...children.slice(0, Math.max(0, 64 - seen.size - pending.length)));
  }
  const [temporary, profileFs, sharedMemory, cpu, memory] = await Promise.all([
    fs(tmpdir()), fs(profile), fs('/dev/shm'),
    metrics('/sys/fs/cgroup/cpu.stat', ['nr_periods','nr_throttled','throttled_usec']),
    metrics('/sys/fs/cgroup/memory.events', ['oom','oom_kill','high','max'])]);
  return {temporary, profile:profileFs, shared_memory:sharedMemory, cpu, memory, processes};
}

export async function boundedStartupSnapshot(profile, pid, sample = startupSnapshot) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => sample(profile, pid)).then(snapshot => ({budget_ms:50, timed_out:0, snapshot}), () => ({budget_ms:50, unavailable:1})),
      new Promise(resolve => { timer = setTimeout(() => resolve({budget_ms:50, timed_out:1}), 50); })
    ]);
  } finally { clearTimeout(timer); }
}

// Group cleanup waits. A busy renderer ignores SIGTERM, so on a loaded runner
// the first wait runs out and SIGKILL follows. After SIGKILL the group dies for
// certain, but its reaping is slowed by the same load, so the second wait is
// the long one. A caller that bounds cleanup() from outside must allow at least
// CLEANUP_BUDGET_MS, or it cuts a cleanup that would have succeeded (the intake
// check's 2 s step deadline did exactly that after all its checks had passed).
export const CLEANUP_TERM_MS = 1000, CLEANUP_KILL_MS = 5000, CLEANUP_CLOSE_MS = 100;
export const CLEANUP_BUDGET_MS = CLEANUP_TERM_MS + CLEANUP_KILL_MS + CLEANUP_CLOSE_MS + 1000;
// The monitor's cleanup as a boundedCleanup step with that allowance.
export const cleanupStep = monitor => ({run: () => monitor.cleanup(), ms: CLEANUP_BUDGET_MS});

export function monitorChromium(child, profileAllocation, {startupBudgetMs = 5000, group = false, members = liveGroupMembers} = {}) {
  const started = performance.now();
  let exited = false, closed = false, code = null, signal = null, error = null;
  let stderr = Buffer.alloc(0), truncated = false, stderrError = null, readError = null;
  child.stderr?.on('data', chunk => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const available = stderrLimit - stderr.length;
    if (bytes.length > available) truncated = true;
    if (available > 0) stderr = Buffer.concat([stderr, bytes.subarray(0, available)]);
  });
  child.stderr?.on('error', () => { stderrError = 'stream-error'; });
  const closure = new Promise(resolve => child.once('close', () => { closed = true; resolve(); }));
  child.once('exit', (value, sig) => {
    exited = true;
    code = Number.isInteger(value) && value >= 0 && value <= 255 ? value : null;
    signal = sig === null ? null : signals.has(sig) ? sig : 'other';
  });
  child.once('error', err => { error = errors.has(err.code) ? err.code : 'other'; });
  const diagnostic = readiness => ({event: 'chromium-startup-failed', phase: 'startup',
    elapsed_seconds: Math.round((performance.now() - started) / 10) / 100,
    exit_code: code, signal, spawn_error: error, readiness, readiness_read_error: readError,
    child_alive_observed: !exited && !closed && error === null, child_closed_observed: closed,
    stderr_signatures: signatures.filter(([, pattern]) => pattern.test(stderr.toString('utf8'))).map(([name]) => name),
    stderr_truncated: truncated, stderr_read_error: stderrError,
    ...(profileAllocation ? {profile_allocation:profileAllocationDiagnostic(profileAllocation)} : {})});
  return {
    async port(profile) {
      const before = boundedStartupSnapshot(profile, child.pid);
      let readiness = 'missing';
      // Bounded in time as well as in iterations: an endpoint probe that hangs
      // cannot stretch the loop.
      const until = performance.now() + startupBudgetMs;
      for (let i = 0; i < Math.ceil(startupBudgetMs / 25) && performance.now() < until; i++) {
        if (exited || error !== null) break;
        try {
          const contents = await readFile(join(profile, 'DevToolsActivePort'), 'utf8');
          const first = contents.split('\n')[0];
          const port = Number(first);
          readiness = first === '' ? 'empty' : 'invalid';
          if (contents.includes('\n') && /^[0-9]+$/.test(first) && Number.isInteger(port) && port > 0 && port <= 65535) {
            // The port file appears before DevTools serves requests. Callers make a
            // single /json/list request and need a page target, so readiness is that
            // endpoint answering with one, inside the same bounded loop.
            readiness = 'endpoint';
            if (await pageTargetReady(port)) {
              if (!exited && error === null) {
                // Fixed fields only. The elapsed time of every successful start
                // is what a budget can be tuned against.
                console.error(JSON.stringify({event:'chromium-startup-ready', phase:'startup',
                  elapsed_seconds: Math.round((performance.now() - started) / 10) / 100,
                  budget_seconds: startupBudgetMs / 1000}));
                return port;
              }
              break;
            }
          }
        } catch (err) { readiness = 'missing'; readError = readErrors.has(err.code) ? err.code : 'other'; }
        await pause(25);
      }
      const failure = diagnostic(readiness);
      const [initial, final] = await Promise.all([before, boundedStartupSnapshot(profile, child.pid)]);
      console.error(JSON.stringify({...failure, startup_snapshots:{before:initial, failure:final}}));
      return null;
    },
    async cleanup() {
      const empty = () => { const live = members(child.pid); return Array.isArray(live) && live.length === 0; };
      if (closed && !(group && child.pid && !empty())) return;
      // The main process exiting does not end its helpers (renderer, GPU,
      // zygote): they keep writing into the profile and fail its removal. A
      // `group` caller spawned the child detached, so -pid is a group it owns and
      // nothing else; signal only that group. Otherwise only the child handle.
      const signalGroup = sig => { try { process.kill(-child.pid, sig); return true; } catch { return false; } };
      const send = sig => { if (group && child.pid) signalGroup(sig); if (!exited && error === null) child.kill(sig); };
      const groupGone = () => !(group && child.pid) || empty();
      const waitExit = async ms => {
        const until = performance.now() + ms;
        while (!(exited || closed || error !== null) || !groupGone()) {
          if (performance.now() >= until) break;
          await pause(10);
        }
      };
      if (!exited && error === null || !groupGone()) { send('SIGTERM'); await waitExit(CLEANUP_TERM_MS); }
      if (!exited && !closed && error === null || !groupGone()) { send('SIGKILL'); await waitExit(CLEANUP_KILL_MS); }
      const alive = (!exited && !closed && error === null) || !groupGone();
      // An exited child's inherited pipe may outlive it. Release only our ends.
      for (const stream of [child.stdin, child.stdout, child.stderr]) stream?.destroy();
      let timer;
      try { await Promise.race([closure, new Promise(resolve => { timer = setTimeout(resolve, CLEANUP_CLOSE_MS); })]); }
      finally { clearTimeout(timer); }
      if (alive || !closed) throw Object.assign(new Error('Chromium cleanup incomplete'), {code:'CLEANUP_BROWSER'});
    }
  };
}
