// A browser helper (renderer/GPU/zygote) outlives the main process and keeps
// writing into the profile; cleanup must reap the whole group before the profile
// is removed, or removal fails with ENOTEMPTY (CLEANUP_PROFILE on loaded runners).
import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {boundedCleanup} from './lib/bounded-cleanup.mjs';
import {cleanupStep, liveGroupMembers, monitorChromium} from './lib/chromium-startup.mjs';

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
// A killed helper may linger as a zombie when the runner's init does not reap it.
const alive = pid => {
  try { process.kill(pid, 0); } catch { return false; }
  if (process.platform === 'linux') {
    try { const stat = readFileSync(`/proc/${pid}/stat`, 'utf8'); return stat[stat.lastIndexOf(')') + 2] !== 'Z'; } catch { return false; }
  }
  return !/^Z/.test(spawnSync('ps', ['-o', 'stat=', '-p', String(pid)], {encoding: 'utf8'}).stdout.trim());
};

async function scenario(group, lib = monitorChromium, clean = monitor => monitor.cleanup()) {
  const profile = await mkdtemp(join(tmpdir(), 'keep-group-cleanup-'));
  // The pid file is written by the helper itself after its first profile write, so
  // "pid visible" means the helper is running and has installed its SIGTERM handler.
  const helper = `const fs=require('fs');const p=process.argv[1];let i=0;process.on('SIGTERM',()=>{});fs.writeFileSync(p+'/h0','x');fs.writeFileSync(p+'/pid.tmp',String(process.pid));fs.renameSync(p+'/pid.tmp',p+'/pid');setInterval(()=>{try{fs.writeFileSync(p+'/h'+(i++%50),'x')}catch{}},2);`;
  // Main ignores nothing but exits on SIGTERM; the helper ignores SIGTERM like a busy renderer.
  const main = `const {spawn}=require('child_process');spawn(process.execPath,['-e',${JSON.stringify(`process.on('SIGTERM',()=>{});${helper}`)},${JSON.stringify(profile)}],{stdio:'ignore'});setInterval(()=>{},1000);`;
  const child = spawn(process.execPath, ['-e', main], {stdio: ['ignore', 'ignore', 'pipe'], detached: group});
  const monitor = lib(child, undefined, group ? {group: true} : undefined);
  let helperPid;
  for (let i = 0; i < 200 && !helperPid; i++) { try { helperPid = Number(await readFile(join(profile, 'pid'), 'utf8')) || undefined; } catch {} await pause(10); }
  assert(helperPid, 'helper did not start');
  try {
    await clean(monitor);
    await pause(50);
    assert(!alive(helperPid), 'browser helper survived cleanup');
    await rm(profile, {recursive: true, force: false, maxRetries: 0});
  } finally {
    if (alive(helperPid)) process.kill(helperPid, 'SIGKILL');
    await rm(profile, {recursive: true, force: true});
  }
}

// Negative control for the escalation: the helper ignores SIGTERM, so a library
// whose SIGKILL step is a no-op must fail the same scenario.
const source = readFileSync(new URL('./lib/chromium-startup.mjs', import.meta.url), 'utf8');
assert(source.includes("send('SIGKILL')"), 'escalation step not found; update the mutant');
const mutantPath = new URL(`./lib/.mutant-${process.pid}.mjs`, import.meta.url);
writeFileSync(mutantPath, source.replace("send('SIGKILL')", '0'));
try {
  const mutant = await import(mutantPath.href);
  await assert.rejects(scenario(true, mutant.monitorChromium), {code: 'CLEANUP_BROWSER'});
} finally { await rm(mutantPath, {force: true}); }
console.log('PASS negative control: no SIGKILL escalation fails the check');

// Unknown is not empty: an unreadable process table must fail cleanup, not pass it.
const ok = {platform: 'darwin', spawnSync: () => ({status: 0, stdout: '  10 10 S\n  11 10 Z\n  12 20 S\n'})};
assert.deepEqual(liveGroupMembers(10, ok), [10]);
for (const bad of [{error: new Error('ENOENT')}, {status: 1, stdout: ''}, {status: null, stdout: '', signal: 'SIGTERM'}, {status: 0, stdout: ''}, {status: 0, stdout: 'garbage\n'}])
  assert.equal(liveGroupMembers(10, {platform: 'darwin', spawnSync: () => bad}), null);
const deny = Object.assign(new Error('x'), {code: 'EACCES'});
assert.equal(liveGroupMembers(10, {platform: 'linux', readdirSync: () => { throw deny; }}), null);
assert.equal(liveGroupMembers(10, {platform: 'linux', readdirSync: () => ['5'], readFileSync: () => { throw deny; }}), null);
assert.deepEqual(liveGroupMembers(10, {platform: 'linux', readdirSync: () => ['5'], readFileSync: () => { throw Object.assign(new Error('x'), {code: 'ENOENT'}); }}), []);
await assert.rejects(scenario(true, (child, alloc, opts) => monitorChromium(child, alloc, {...opts, members: () => null})), {code: 'CLEANUP_BROWSER'});
console.log('PASS unknown group membership fails cleanup');

// Load: the killed group is still being reaped 2.5 s into cleanup (process table
// lags). The monitor must wait it out, and a check that bounds cleanup with
// cleanupStep must not cut it: before, the TERM and KILL waits were 1 s each and
// the intake check's step deadline 2 s, so a run whose checks had all passed
// failed with CLEANUP_BOUNDARY.
const lagging = (child, alloc, opts) => {
  let first;
  return monitorChromium(child, alloc, {...opts, members: pid => {
    first ??= performance.now();
    return performance.now() - first < 2500 ? [pid] : liveGroupMembers(pid);
  }});
};
await scenario(true, lagging, monitor => boundedCleanup([cleanupStep(monitor)]));
console.log('PASS group reaped late under load stays inside the cleanup budget');

// Negative control: without group reaping the helper survives and the check fails.
await assert.rejects(scenario(false), /helper survived cleanup/);
console.log('PASS negative control: helper outlives a main-process-only cleanup');
for (let i = 0; i < 5; i++) await scenario(true);
console.log('PASS group cleanup reaps helpers before profile removal');
