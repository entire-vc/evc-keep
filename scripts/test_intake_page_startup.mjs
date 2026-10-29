// Exercise the actual page checker with native disposable Chromium stand-ins.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {chmod, mkdtemp, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {EventEmitter} from 'node:events';
import {monitorChromium} from './lib/chromium-startup.mjs';

const checker = process.argv[2] || fileURLToPath(new URL('./check-intake-page.mjs', import.meta.url));
const controls = process.argv[3] ? [process.argv[3]] : ['empty-to-valid', 'numeric-partial-to-valid', 'valid', 'early-exit', 'spawn-error', 'never-ready'];
for (const control of controls) {
  const dir = await mkdtemp(join(tmpdir(), 'keep-page-startup-control-'));
  const executable = join(dir, 'chromium');
  const requested = join(dir, 'requested');
  const stopped = join(dir, 'stopped');
  let child;
  try {
    const fixture = control === 'spawn-error' ? '#!/keep-nonexistent-interpreter\n' : `#!/usr/bin/env node
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const profile = process.argv.find(arg => arg.startsWith('--user-data-dir=')).split('=')[1];
const control = ${JSON.stringify(control)};
process.stderr.write('DISPOSABLE_PAGE_STDERR_SENTINEL');
process.on('SIGTERM', () => { fs.writeFileSync(${JSON.stringify(stopped)}, 'stopped'); process.exit(0); });
if (control === 'early-exit') process.exit(7);
if (control === 'never-ready') setInterval(() => {}, 1000);
else {
  const server = http.createServer((req, res) => {
    fs.writeFileSync(${JSON.stringify(requested)}, 'requested');
    // One page target without a socket URL: ready for discovery, fails at socket.
    res.setHeader('Content-Type', 'application/json'); res.end('[{"type":"page"}]');
  });
  server.listen(0, '127.0.0.1', () => {
    const portfile = path.join(profile, 'DevToolsActivePort');
    const complete = () => fs.writeFileSync(portfile, server.address().port + '\\n/browser');
    if (control === 'valid') complete();
    else { fs.writeFileSync(portfile, control === 'empty-to-valid' ? '' : '4'); setTimeout(complete, 200); }
  });
}
`;
    await writeFile(executable, fixture);
    await chmod(executable, 0o700);
    const started = performance.now();
    child = spawn(process.execPath, [checker], {env: {...process.env, CHROME_BIN: executable, TMPDIR: dir, KEEP_CHROMIUM_STARTUP_MS: '5000'}, stdio: ['pipe', 'pipe', 'pipe']});
    let output = '', errors = '';
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { errors += data; });
    child.stdin.end(JSON.stringify({plaintext: 'disposable-page-control', url: 'http://127.0.0.1/'}));
    let timer;
    const result = await Promise.race([
      new Promise((resolve, reject) => { child.once('error', reject); child.once('close', code => resolve(code)); }),
      new Promise((_, reject) => { timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('page control deadline')); }, 9000); })
    ]).finally(() => clearTimeout(timer));
    assert.notEqual(result, 0, 'stand-in never supplies a behavioral browser');
    assert.equal(output, '');
    assert(!errors.includes('DISPOSABLE_PAGE_STDERR_SENTINEL'), 'raw browser stderr is suppressed');
    const events = errors.split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line));
    const diagnostics = events.filter(row => row.event === 'chromium-startup-failed');
    const failures = events.filter(row => row.event === 'page-browser-failed');
    const readyEvents = events.filter(row => row.event === 'chromium-startup-ready');
    assert.equal(events.length, diagnostics.length + failures.length + readyEvents.length, 'only known diagnostic events');
    assert.equal(failures.length, 1, 'stand-in retains one page failure');
    const ready = ['empty-to-valid', 'numeric-partial-to-valid', 'valid'].includes(control);
    assert.deepEqual(failures[0], {event:'page-browser-failed', stage:ready ? 'socket' : 'readiness',
      error_class:ready ? 'SyntaxError' : 'AssertionError', code:ready ? 'other' : 'ERR_ASSERTION'});
    if (ready) {
      assert.equal(await readFile(requested, 'utf8'), 'requested', 'complete port reaches the real HTTP boundary');
      assert.equal(diagnostics.length, 0);
      assert.equal(readyEvents.length, 1, 'a successful start logs its elapsed time once');
      assert(!errors.includes('page browser: Chromium did not start'));
    } else {
      assert.equal(diagnostics.length, 1);
      assert.equal(diagnostics[0].event, 'chromium-startup-failed');
      assert.equal(diagnostics[0].spawn_error, control === 'spawn-error' ? 'ENOENT' : null);
      assert.equal(diagnostics[0].exit_code, control === 'early-exit' ? 7 : null);
      assert(errors.includes('page browser: Chromium did not start'));
      if (control === 'never-ready') assert(performance.now() - started >= 4900);
    }
    if (!['early-exit', 'spawn-error'].includes(control)) assert.equal(await readFile(stopped, 'utf8'), 'stopped');
    assert(!(await readdir(dir)).some(name => name.startsWith('keep-input-page-')), 'page profile is removed');
    // Only fixed safe summaries cross the test output boundary.
    console.log(JSON.stringify({control: 'page-' + control, passed: true}));
  } finally {
    if (child?.exitCode === null) child.kill('SIGKILL');
    await rm(dir, {recursive: true, force: true});
  }
}
// A close event without exit must not make page cleanup wait indefinitely.
const closedChild = new EventEmitter();
let kills = 0;
closedChild.kill = () => { kills++; };
const closedMonitor = monitorChromium(closedChild);
closedChild.emit('close');
await closedMonitor.cleanup();
assert.equal(kills, 0);
console.log(JSON.stringify({control: 'page-close-without-exit-cleanup', passed: true}));
// The CI startup control entry point also verifies owned teardown boundaries.
await import('./test_page_cleanup.mjs');
