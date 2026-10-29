import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {startupSnapshot, boundedStartupSnapshot, monitorChromium} from './lib/chromium-startup.mjs';
const sentinel = 'PRIVATE_SENTINEL';
const reads = [];
const io = {
  async statfs() {return {type:16914836,bsize:4096,blocks:200,bavail:100,secret:sentinel};},
  async readlink() {return '/private/' + sentinel + '/chrome';},
  async readFile(path) {
    reads.push(path);
    if (path.endsWith('cpu.stat')) return 'nr_throttled 17\nthrottled_usec 420\nprivate ' + sentinel + '\nusage_usec 999';
    if (path.endsWith('memory.events')) return 'oom 2\noom_kill 1\nhigh 4\nmax invalid\nprivate ' + sentinel;
    if (path.endsWith('/children')) return '2 3 4';
    return '1 (' + sentinel + ') D 0 0';
  }
};
const row = await startupSnapshot('/private/' + sentinel, 1, io);
assert.deepEqual(row.cpu, {nr_throttled:17,throttled_usec:420});
assert.deepEqual(row.memory, {oom:2,oom_kill:1,high:4});
assert.deepEqual(row.shared_memory, {type:16914836,block_bytes:4096,blocks:200,available_blocks:100});
assert.equal(row.processes.length, 4);
assert(row.processes.every(p => p.kind === 'chrome' && p.state === 'D'));
assert(!JSON.stringify(row).includes(sentinel));
assert(!JSON.stringify(row).includes('/'));
const missing = await startupSnapshot('/missing', undefined, {async statfs(){throw Error(sentinel);},async readFile(){throw Error(sentinel);}});
assert.deepEqual(missing, {temporary:null,profile:null,shared_memory:null,cpu:{},memory:{},processes:[]});
let procReads = 0;
await startupSnapshot('/missing', 1, {...io, async readFile(path) {if(path.includes('/proc/'))procReads++;return path.endsWith('/children') ? Array.from({length:100},(_,i)=>i+2).join(' ') : '1 (private) UNKNOWN 0';}});
assert(procReads <= 128, 'family traversal bounded to 64 processes');
console.log('PASS snapshot allowlist, pressure/OOM, missing facilities, bounded family');

const started = performance.now();
assert.deepEqual(await boundedStartupSnapshot('', 1, () => new Promise(() => {})), {budget_ms:50,timed_out:1});
assert(performance.now() - started < 500);
assert.deepEqual(await boundedStartupSnapshot('', 1, async () => {throw Error(sentinel);}), {budget_ms:50,unavailable:1});
console.log('PASS hung/unavailable sampling preserves numeric budget marker');

for (const field of ['statfs', 'readFile']) {
 const stuck = {...io, [field]: () => new Promise(() => {})};
 assert.deepEqual(await boundedStartupSnapshot('', 1, (profile,pid) => startupSnapshot(profile,pid,stuck)), {budget_ms:50,timed_out:1});
}
console.log('PASS hanging statfs/readFile bounded without raw errors');

const child = new EventEmitter();
child.kill = () => {throw Error('cleanup must respect already-closed child');};
const monitor = monitorChromium(child); child.emit('close');
const pendingEvidence = boundedStartupSnapshot('', 1, () => new Promise(() => {}));
await monitor.cleanup();
assert.equal((await pendingEvidence).timed_out, 1);
console.log('PASS cleanup independent of pending stuck evidence');
