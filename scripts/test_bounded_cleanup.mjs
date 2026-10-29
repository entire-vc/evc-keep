import assert from 'node:assert/strict';
import {boundedCleanup} from './lib/bounded-cleanup.mjs';

let controls = 0;
async function check(name, run) { await run(); controls++; console.log(JSON.stringify({control:'bounded-cleanup-' + name, passed:true})); }
const quiet = async run => {
  const write = process.stderr.write, out = [];
  process.stderr.write = line => {out.push(String(line)); return true;};
  try { await run(); } finally { process.stderr.write = write; }
  return out.join('');
};
const primary = new Error('PRIMARY_BOUNDARY');

await check('failing-step-keeps-primary-and-runs-all', async () => {
  const ran = [];
  const log = await quiet(async () => {
    const result = await boundedCleanup([async () => {ran.push(1); throw new Error('PRIVATE_SENTINEL');},
      async () => {ran.push(2);}, async () => {ran.push(3);}], {primary, ms:50}); // resolves; caller rethrows primary
    assert.equal(result, undefined);
  });
  assert.deepEqual(ran, [1, 2, 3]);
  assert.equal(log, JSON.stringify({event:'intake-browser-cleanup-failed', code:'CLEANUP_BOUNDARY'}) + '\n');
  assert(!log.includes('PRIVATE_SENTINEL'));
});
await check('never-returning-step-hits-deadline-and-later-steps-run', async () => {
  let reached = false;
  const started = Date.now();
  await quiet(() => boundedCleanup([() => new Promise(() => {}), async () => {reached = true;}], {primary, ms:50}));
  assert(reached); assert(Date.now() - started < 1000);
});
await check('no-primary-failure-is-fixed-error', async () => {
  await assert.rejects(boundedCleanup([async () => {throw new Error('PRIVATE_SENTINEL');}], {ms:50}),
    error => error.code === 'CLEANUP_BOUNDARY' && !error.message.includes('PRIVATE_SENTINEL'));
});
await check('success-is-silent', async () => {
  assert.equal(await quiet(() => boundedCleanup([async () => {}], {primary, ms:50})), '');
});
await check('step-deadline-overrides-shared', async () => {
  const slow = () => new Promise(resolve => setTimeout(resolve, 150));
  assert.equal(await quiet(() => boundedCleanup([{run: slow, ms: 1000}], {primary, ms:50})), '');
  await assert.rejects(boundedCleanup([slow], {ms:50}), {code: 'CLEANUP_BOUNDARY'});
});
console.log(JSON.stringify({bounded_cleanup_controls:controls, passed:true}));
