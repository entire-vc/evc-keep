// Native Node child processes exercise readiness, failure verdicts and cleanup.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {monitorChromium, startupBudget, STARTUP_BUDGET_MS} from './lib/chromium-startup.mjs';

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
// DevTools stand-in: lists a page target only while `pageListed` is true,
// answering with `listStatus` (200 unless a control changes it).
let pageListed = true, listStatus = 200;
const devtools = createServer((req, res) => {
  res.statusCode = listStatus;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(req.url === '/json/list' && pageListed ? [{type: 'page'}] : []));
});
await new Promise(resolve => devtools.listen(0, '127.0.0.1', resolve));
const PORT = devtools.address().port;
async function control(name, expected) {
  const profile = await mkdtemp(join(tmpdir(), 'keep-startup-control-'));
  const path = join(profile, 'DevToolsActivePort');
  // The same child is kept alive until production cleanup terminates it.
  const child = name === 'spawn-error' ? spawn(join(profile, 'missing-executable'), [], {stdio: 'ignore'}) :
    spawn(process.execPath, ['-e', name === 'early-exit' ? 'process.exit(7)' : 'setInterval(()=>{},1000)'], {stdio: 'ignore'});
  // Library default stays 5 s; the slow-start controls pick a budget on either
  // side of a browser that becomes ready after 1.2 s.
  const budget = name === 'slow-start-short-budget' ? {startupBudgetMs: 700} : name === 'slow-start-long-budget' ? {startupBudgetMs: 3000} : undefined;
  const monitor = monitorChromium(child, undefined, budget);
  let writer;
  const diagnostics = [];
  const originalError = console.error;
  console.error = line => diagnostics.push(JSON.parse(line));
  pageListed = !name.startsWith('endpoint-') || name === 'endpoint-201';
  listStatus = name === 'endpoint-201' ? 201 : 200;
  try {
    if (name === 'valid' || name.startsWith('endpoint-')) await writeFile(path, `${PORT}\n`);
    if (name === 'endpoint-late') writer = (async () => { await pause(300); pageListed = true; })();
    if (name.startsWith('slow-start-')) writer = (async () => { await pause(1200); await writeFile(path, `${PORT}\n`); })();
    if (name === 'numeric-partial-to-valid') {
      await writeFile(path, '4');
      writer = (async () => { await pause(200); await writeFile(path, `${PORT}\n`); })();
    }
    if (name === 'empty-to-valid') {
      await writeFile(path, '');
      writer = (async () => { await pause(100); await writeFile(path, 'invalid\n'); await pause(100); await writeFile(path, `${PORT}\n`); })();
    }
    const started = performance.now();
    const port = await monitor.port(profile);
    const elapsed = performance.now() - started;
    assert.equal(Boolean(port), expected);
    assert.equal(diagnostics.length, 1);
    if (expected) {
      // A successful start reports its elapsed time and the budget it had.
      assert.deepEqual(Object.keys(diagnostics[0]).sort(), ['budget_seconds', 'elapsed_seconds', 'event', 'phase']);
      assert.equal(diagnostics[0].event, 'chromium-startup-ready');
      assert.equal(diagnostics[0].phase, 'startup');
      assert(diagnostics[0].elapsed_seconds >= 0 && diagnostics[0].elapsed_seconds <= diagnostics[0].budget_seconds);
      assert.equal(diagnostics[0].budget_seconds, budget ? budget.startupBudgetMs / 1000 : 5);
    } else {
      const diagnostic = diagnostics[0];
      assert.deepEqual(Object.keys(diagnostic).sort(), ['child_alive_observed', 'child_closed_observed', 'elapsed_seconds', 'event', 'exit_code', 'phase', 'readiness', 'readiness_read_error', 'signal', 'spawn_error', 'startup_snapshots', 'stderr_read_error', 'stderr_signatures', 'stderr_truncated']);
      assert.equal(diagnostic.event, 'chromium-startup-failed');
      assert.equal(diagnostic.phase, 'startup');
      assert.equal(diagnostic.readiness, name.startsWith('endpoint-') ? 'endpoint' : 'missing');
      assert.equal(diagnostic.signal, null);
      assert.equal(diagnostic.exit_code, name === 'early-exit' ? 7 : null);
      assert.equal(diagnostic.spawn_error, name === 'spawn-error' ? 'ENOENT' : null);
      assert(diagnostic.elapsed_seconds >= 0);
    }
    if (expected) assert.equal(port, PORT);
    if (name === 'endpoint-late') assert(elapsed >= 250);
    if (name === 'endpoint-no-page' || name === 'endpoint-201') assert(elapsed >= 4900 && elapsed < 8000);
    if (name === 'numeric-partial-to-valid') assert(elapsed >= 150);
    if (name === 'slow-start-short-budget') assert(elapsed >= 650 && elapsed < 1200);
    if (name === 'slow-start-long-budget') assert(elapsed >= 1150 && elapsed < 3000 && diagnostics[0].elapsed_seconds >= 1.15);
    if (name === 'never-ready') assert(elapsed >= 4900 && elapsed < 8000);
    if (name === 'early-exit' || name === 'spawn-error') assert(elapsed < 2000);
    // Production's existing assertion still turns null into a red verdict.
    if (!expected) assert.throws(() => assert(port, 'Chromium did not start'));
  } finally {
    console.error = originalError;
    const started = performance.now();
    await monitor.cleanup();
    assert(performance.now() - started < 2500);
    assert(child.exitCode !== null || child.signalCode !== null || name === 'spawn-error');
    await writer;
    await rm(profile, {recursive: true, force: true});
  }
  console.log(JSON.stringify({control: name, verdict: expected ? 'green' : 'red', diagnostics}));
}

// Native file boundary exposes the old premature-break defect deterministically.
const oldProfile = await mkdtemp(join(tmpdir(), 'keep-startup-old-control-'));
try {
  await writeFile(join(oldProfile, 'DevToolsActivePort'), '');
  const oldPort = Number((await readFile(join(oldProfile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]);
  assert.throws(() => assert(oldPort, 'Chromium did not start'));
  console.log('PASS old readiness negative control: empty file is rejected prematurely');
} finally { await rm(oldProfile, {recursive: true, force: true}); }
// The old readiness returned as soon as the port file was complete, while the
// endpoint did not yet list a page: the caller's single /json/list then failed.
pageListed = false;
const early = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
assert.throws(() => assert(early.find(t => t.type === 'page')), 'old readiness negative control');
console.log('PASS old readiness negative control: complete port file before a page target');
for (const [name, expected] of [['empty-to-valid', true], ['numeric-partial-to-valid', true], ['early-exit', false], ['spawn-error', false], ['never-ready', false], ['valid', true], ['endpoint-late', true], ['endpoint-no-page', false], ['endpoint-201', false], ['slow-start-short-budget', false], ['slow-start-long-budget', true]]) {
  await control(name, expected);
}
listStatus = 200;
devtools.close();
// The checkers' budget: 20 s by default, a sane override, junk ignored.
assert.equal(STARTUP_BUDGET_MS, 20000);
assert.equal(startupBudget({}), 20000);
assert.equal(startupBudget({KEEP_CHROMIUM_STARTUP_MS: '5000'}), 5000);
for (const junk of ['', 'x', '999', '120001', '1.5', '-5000', '0']) assert.equal(startupBudget({KEEP_CHROMIUM_STARTUP_MS: junk}), 20000);
console.log('PASS checker startup budget: 20 s default, bounded override');
// The existing CI validation entrypoint also exercises the diagnostic boundary.
await import('./test_chromium_startup_diagnostics.mjs');
// Keep the production page checker wired to the same startup/cleanup contract.
await import('./test_intake_page_startup.mjs');

await import('./test_chromium_startup_snapshot.mjs');
await import('./test_chromium_group_cleanup.mjs');
// The intake checker's cleanup deadlines, per step.
await import('./test_bounded_cleanup.mjs');
await import('./test_chromium_profile.mjs');
await import('./test_chromium_profile_entrypoints.mjs');
// Fixed assertion vocabulary and the redirect classification the page checker uses.
await import('./test_page_failure.mjs');
