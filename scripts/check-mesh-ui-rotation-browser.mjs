// Drive the rotation run page (/mesh/ui/secrets/{id}/rotations/{run}) in
// Chromium: an active run refreshes itself in place every 3 s, turns into the
// finished run without a reload once the server ends it, and then stops
// asking. Fixtures arrive on stdin; the run prints only a fixed result line.
// Every failure carries a fixed message naming the step.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {access, appendFile, mkdir, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {monitorChromium, startupBudget} from './lib/chromium-startup.mjs';
import {withChromiumProfile} from './lib/chromium-profile.mjs';

const FLOW_MS = 15000;
const sleep = ms => new Promise(r => setTimeout(r, ms));
let step = 'setup';

async function main() {
  let source = '';
  for await (const chunk of process.stdin) source += chunk;
  const input = JSON.parse(source);
  const candidates = [process.env.CHROME_BIN, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].filter(Boolean);
  let chrome;
  for (const path of candidates) { try { await access(path); chrome = path; break; } catch {} }
  assert(chrome, 'rotation browser: Chromium is required');

  await withChromiumProfile('keep-mesh-ui-', async ({path: profile, diagnostic}) => {
    const browser = spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check',
      '--ignore-certificate-errors', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], {stdio: ['ignore', 'ignore', 'pipe']});
    const monitor = monitorChromium(browser, diagnostic, {startupBudgetMs: startupBudget()});
    let socket;
    try {
      step = 'browser';
      const port = await monitor.port(profile);
      assert(port, 'rotation browser: Chromium did not start');
      const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      socket = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
      await new Promise((res, rej) => { socket.addEventListener('open', res, {once: true}); socket.addEventListener('error', rej, {once: true}); });
      let seq = 0, loaded, loads = 0;
      const pending = new Map(), problems = [], refetches = [];
      socket.addEventListener('message', ev => {
        const m = JSON.parse(ev.data);
        if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error('rotation browser: CDP command failed')) : p.res(m.result); return; }
        if (m.method === 'Page.loadEventFired') { loads++; if (loaded) { loaded(); loaded = undefined; } }
        if (m.method === 'Runtime.exceptionThrown') problems.push('exception');
        if (m.method === 'Log.entryAdded' && /Content Security Policy|Refused to/.test(m.params.entry.text || '')) problems.push('policy');
        if (m.method === 'Network.requestWillBeSent' && m.params.type === 'Fetch') refetches.push(m.params.request.url);
      });
      const cdp = (method, params = {}) => new Promise((res, rej) => { const id = ++seq; pending.set(id, {res, rej}); socket.send(JSON.stringify({id, method, params})); });
      const page = async expr => {
        const r = await cdp('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true});
        assert(!r.exceptionDetails, 'rotation browser: evaluation failed');
        return r.result.value;
      };
      const waitFor = async (fn, what, ms = FLOW_MS) => {
        const until = performance.now() + ms;
        for (;;) {
          if (await fn()) return;
          if (performance.now() > until) assert.fail('rotation browser: not reached: ' + what);
          await sleep(50);
        }
      };
      const navigate = async url => {
        const ready = new Promise(r => { loaded = r; });
        await cdp('Page.navigate', {url});
        await Promise.race([ready, sleep(FLOW_MS).then(() => assert.fail('rotation browser: navigation timeout'))]);
      };
      const shot = async name => {
        if (!input.shots) return;
        await mkdir(input.shots, {recursive: true});
        const {data} = await cdp('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
        await writeFile(join(input.shots, name), Buffer.from(data, 'base64'));
      };
      const viewport = (width, height, mobile) => cdp('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile});
      const fits = () => page(`document.documentElement.scrollWidth <= innerWidth`);
      const dump = async () => {
        if (!input.domDump) return;
        const text = await page(`document.documentElement.outerHTML + '\\n' + document.body.innerText`);
        assert(typeof text === 'string' && text.length > 0, 'rotation browser: DOM dump is empty');
        await appendFile(input.domDump, text + '\n');
      };
      await cdp('Page.enable'); await cdp('Runtime.enable'); await cdp('Network.enable'); await cdp('Log.enable');
      await cdp('Network.setCookie', {name: input.cookieName, value: input.cookie, url: input.keep + '/mesh/ui', secure: true, httpOnly: true, sameSite: 'None'});

      // 1. The active run: marked live, its own script loaded under the policy.
      step = 'active';
      await viewport(1440, 900, false);
      await navigate(input.active);
      const before = await page(`({live: !!document.querySelector('[data-live][data-live-active]'), text: document.body.innerText})`);
      assert(before.live, 'rotation browser: the active run is not marked live');
      assert(/Rotation in progress/.test(before.text) && /Pending/.test(before.text), 'rotation browser: the active run does not show its progress');
      assert(await fits(), 'rotation browser: the active run overflows at 1440');
      await shot('mesh-rotation-run-active-1440.png');
      await viewport(393, 800, true);
      assert(await fits(), 'rotation browser: the active run overflows at 393');
      await shot('mesh-rotation-run-active-393.png');
      await dump();

      // 2. The page asks again by itself, in place: no reload.
      step = 'refresh';
      await page(`window.__keepMark = 1`);
      const loadsBefore = loads;
      await waitFor(async () => refetches.filter(u => u === input.active).length >= 2, 'two live refreshes', 9000);
      assert(await page(`window.__keepMark === 1`) && loads === loadsBefore, 'rotation browser: the live refresh reloaded the page');

      // 3. The server ends the run; the next refresh shows it done and the script stops.
      step = 'finish';
      assert((await fetch(input.release, {method: 'POST'})).ok, 'rotation browser: could not end the run');
      await waitFor(() => page(`/Rotation done/.test(document.body.innerText)`), 'the finished run in place', 12000);
      const after = await page(`({live: !!document.querySelector('[data-live]'), active: !!document.querySelector('[data-live-active]'), mark: window.__keepMark, text: document.body.innerText})`);
      assert(after.live && !after.active && after.mark === 1 && loads === loadsBefore, 'rotation browser: the finished run did not replace the live part in place');
      assert(!/Updates every 3 s/.test(after.text) && /Confirmed/.test(after.text), 'rotation browser: the finished run still reads as active');
      const asked = refetches.length;
      await sleep(4500);
      assert(refetches.length === asked, 'rotation browser: the script kept asking after the run ended');
      assert(await fits(), 'rotation browser: the finished run overflows at 393');
      await shot('mesh-rotation-run-done-393.png');
      await viewport(1440, 900, false);
      await shot('mesh-rotation-run-done-1440.png');
      await dump();

      // 4. A finished run opened fresh never asks; the run list opens it.
      step = 'finished-fresh';
      await navigate(input.active);
      const fresh = refetches.length;
      await sleep(3500);
      assert(refetches.length === fresh, 'rotation browser: a finished run page asks for updates');
      await navigate(input.list);
      assert(await page(`[...document.querySelectorAll('a.row-link')].some(a => a.href === ${JSON.stringify(input.active)})`), 'rotation browser: the run list does not open the run');
      await shot('mesh-rotations-1440.png');
      await viewport(393, 800, true);
      assert(await fits(), 'rotation browser: the run list overflows at 393');
      await shot('mesh-rotations-393.png');
      await dump();

      assert(problems.length === 0, 'rotation browser: a script error or a policy violation on the page');
      process.stdout.write(JSON.stringify({ok: true, steps: 4}) + '\n');
    } finally {
      try { socket?.close(); } catch {}
      await monitor.cleanup().catch(() => {});
    }
  });
}
main().catch(error => {
  if (process.env.MESH_UI_BROWSER_DEBUG) process.stderr.write(String(error && error.stack) + '\n');
  process.stderr.write(`FAIL step=${step}: ${error.code === 'ERR_ASSERTION' ? error.message : 'rotation browser: unexpected failure'}\n`);
  process.exitCode = 1;
});
