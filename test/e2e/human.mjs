// The "human" of the W2 acceptance: open an input link in headless Chromium,
// type the value into the page and submit it. The fixture {url, plaintext}
// arrives on stdin; stdout carries only the completion metadata the page
// shows (version, fingerprint). Every failure has a fixed message: no page
// text, URL, console argument or value is ever printed.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {access, mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

let source = '';
for await (const chunk of process.stdin) source += chunk;
const input = JSON.parse(source);
source = '';

const candidates = [process.env.CHROME_BIN, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].filter(Boolean);
let chrome;
for (const path of candidates) { try { await access(path); chrome = path; break; } catch {} }
assert(chrome, 'human browser: Chromium is required; set CHROME_BIN');

const profile = await mkdtemp(join(tmpdir(), 'keep-e2e-human-'));
const flags = ['--headless=new', '--disable-gpu', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', `--user-data-dir=${profile}`];
if (process.env.KEEP_E2E_NO_SANDBOX === '1') flags.push('--no-sandbox');
const browser = spawn(chrome, [...flags, 'about:blank'], {stdio: 'ignore'});
const browserExit = new Promise(resolve => browser.once('exit', resolve));
let socket;
try {
  let port;
  for (let i = 0; i < 400; i++) {
    try { port = Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; }
    catch { await new Promise(resolve => setTimeout(resolve, 25)); }
  }
  assert(port, 'human browser: Chromium did not start');
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  socket = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, {once: true});
    socket.addEventListener('error', reject, {once: true});
  });
  let sequence = 0, loaded;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.method === 'Page.loadEventFired' && loaded) { loaded(); loaded = undefined; }
    if (message.id && pending.has(message.id)) {
      const {resolve, reject} = pending.get(message.id);
      pending.delete(message.id);
      message.error ? reject(new Error('human browser: CDP command failed')) : resolve(message.result);
    }
  });
  const cdp = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, {resolve, reject});
    socket.send(JSON.stringify({id, method, params}));
  });
  const evaluate = async expression => {
    const result = await cdp('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true});
    assert(!result.exceptionDetails, 'human browser: evaluation failed');
    return result.result?.value;
  };
  const waitFor = async (expression, phase) => {
    for (let i = 0; i < 400; i++) {
      if (await evaluate(expression)) return;
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert(false, 'human browser: expected page state was not reached (' + phase + ')');
  };
  await cdp('Page.enable'); await cdp('Runtime.enable');
  const ready = new Promise(resolve => { loaded = resolve; });
  await cdp('Page.navigate', {url: input.url});
  await Promise.race([ready, new Promise((_, reject) => setTimeout(() => reject(new assert.AssertionError({message: 'human browser: navigation timeout'})), 10000))]);
  await waitFor(`document.querySelector('#status')?.textContent === 'Ready for secure input.'`, 'ready');
  await evaluate(`document.querySelector('#secret').value = ${JSON.stringify(input.plaintext)}; document.querySelector('button').click()`);
  await waitFor(`document.querySelector('#status')?.dataset.state === 'success'`, 'save');
  const result = await evaluate(`({version:document.querySelector('#version').textContent,fingerprint:document.querySelector('#fingerprint').textContent})`);
  assert(result.version && result.fingerprint, 'human browser: completion metadata missing');
  process.stdout.write(JSON.stringify(result));
} finally {
  try { socket?.close(); } catch {}
  browser.kill();
  await Promise.race([browserExit, new Promise(resolve => setTimeout(resolve, 5000))]);
  // Chromium may still be flushing its profile; a leftover temp directory
  // is not a failure of the scenario.
  try { await rm(profile, {recursive: true, force: true, maxRetries: 20, retryDelay: 100}); } catch {}
}
process.exit(0);
