import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once, EventEmitter} from 'node:events';
import {monitorChromium} from './lib/chromium-startup.mjs';
import {cleanupPageResources, pageCleanup} from './lib/page-failure.mjs';
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
// Real owned parent exits; a disposable descendant holds its inherited stderr.
const child = spawn(process.execPath, ['-e', `const {spawn}=require('node:child_process');spawn(process.execPath,['-e','setTimeout(()=>{},2800)'],{stdio:['ignore','ignore',2]});process.exit(0)`], {stdio:['ignore','ignore','pipe']});
const monitor = monitorChromium(child);
await once(child, 'exit');
const started = performance.now();
await monitor.cleanup();
assert(performance.now() - started < 500);
console.log(JSON.stringify({control:'exited-child-inherited-pipe',passed:true}));
// Actual TERM-ignoring child must be killed through its own handle.
const stubborn = spawn(process.execPath, ['-e', `process.on('SIGTERM',()=>{});console.log('ready');setInterval(()=>{},1000)`], {stdio:['ignore','pipe','pipe']});
const stubbornMonitor = monitorChromium(stubborn);
await once(stubborn.stdout, 'data');
await stubbornMonitor.cleanup();
assert.equal(stubborn.signalCode, 'SIGKILL');
console.log(JSON.stringify({control:'owned-term-ignored-kill',passed:true}));
const attempts = [], rows = [];
const primary = Object.assign(new TypeError('PRIVATE_SENTINEL'), {code:'CDP_COMMAND_FAILED'});
await pageCleanup(primary, () => cleanupPageResources([
 ['CLEANUP_SOCKET', () => { attempts.push('socket'); throw Error('PRIVATE_SENTINEL'); }, 20],
 ['CLEANUP_BROWSER', () => { attempts.push('browser'); }, 20],
 ['CLEANUP_SERVER', () => { attempts.push('server'); return new Promise(()=>{}); }, 20],
 ['CLEANUP_PROFILE', () => { attempts.push('profile'); throw Error('PRIVATE_SENTINEL'); }, 20]
]), row => rows.push(row));
assert.deepEqual(attempts, ['socket','browser','server','profile']);
assert.equal(rows[0].code, 'CLEANUP_SOCKET');
assert(!JSON.stringify(rows).includes('PRIVATE_SENTINEL'));
assert.equal(primary.code, 'CDP_COMMAND_FAILED');
await assert.rejects(cleanupPageResources([['CLEANUP_PROFILE',()=>{throw Error('PRIVATE_SENTINEL');},20]]), error => error.code === 'CLEANUP_PROFILE');
console.log(JSON.stringify({control:'all-resources-first-error-primary-privacy',passed:true}));
const fake = new EventEmitter(); fake.kill = () => true;
const failMonitor = monitorChromium(fake);
await assert.rejects(failMonitor.cleanup(), error => error.code === 'CLEANUP_BROWSER');
console.log(JSON.stringify({control:'unconfirmed-child-fails-closed',passed:true}));
