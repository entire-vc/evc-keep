// The real approval console, sessions and decisions are supplied by the Go
// fixture. Never print its input: it contains a disposable session cookie.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {access, appendFile, mkdir, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {monitorChromium, startupBudget} from './lib/chromium-startup.mjs';
import {withChromiumProfile} from './lib/chromium-profile.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let step = 'setup';
async function main() {
  let source = '';
  for await (const chunk of process.stdin) source += chunk;
  const input = JSON.parse(source);
  const candidates = [process.env.CHROME_BIN, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].filter(Boolean);
  let chrome;
  for (const path of candidates) { try { await access(path); chrome = path; break; } catch {} }
  assert(chrome, 'adoption browser: Chromium is required');
  await withChromiumProfile('keep-mesh-ui-', async ({path: profile, diagnostic}) => {
    const browser = spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check',
      '--ignore-certificate-errors', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], {stdio: ['ignore', 'ignore', 'pipe']});
    const monitor = monitorChromium(browser, diagnostic, {startupBudgetMs: startupBudget()});
    let socket;
    try {
      step = 'browser';
      const port = await monitor.port(profile);
      assert(port, 'adoption browser: Chromium did not start');
      const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      socket = new WebSocket(targets.find(target => target.type === 'page').webSocketDebuggerUrl);
      await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, {once: true}); socket.addEventListener('error', reject, {once: true}); });
      let seq = 0, loaded;
      const pending = new Map(), problems = [];
      socket.addEventListener('message', event => {
        const message = JSON.parse(event.data);
        if (message.id && pending.has(message.id)) {
          const p = pending.get(message.id); pending.delete(message.id);
          message.error ? p.reject(new Error('adoption browser: CDP command failed')) : p.resolve(message.result);
        }
        if (message.method === 'Page.loadEventFired' && loaded) { loaded(); loaded = undefined; }
        if (message.method === 'Runtime.exceptionThrown') problems.push('exception');
        if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') problems.push('console.error');
        if (message.method === 'Network.responseReceived' && message.params.response.status >= 500) problems.push('server error');
        if (message.method === 'Log.entryAdded' && /Content Security Policy|Refused to/.test(message.params.entry.text || '')) problems.push('policy');
      });
      const cdp = (method, params = {}) => new Promise((resolve, reject) => { const id = ++seq; pending.set(id, {resolve, reject}); socket.send(JSON.stringify({id, method, params})); });
      const page = async expression => {
        const result = await cdp('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true});
        assert(!result.exceptionDetails, 'adoption browser: evaluation failed');
        return result.result.value;
      };
      const navigation = async action => {
        const ready = new Promise(resolve => { loaded = resolve; });
        await action();
        await Promise.race([ready, sleep(15000).then(() => assert.fail('adoption browser: navigation timeout'))]);
      };
      const navigate = url => navigation(() => cdp('Page.navigate', {url}));
      const capture = async name => {
        assert(await page('document.documentElement.scrollWidth <= innerWidth'), 'adoption browser: horizontal overflow');
        if (input.shots) {
          await mkdir(input.shots, {recursive: true});
          const {data} = await cdp('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
          await writeFile(join(input.shots, name + '.png'), Buffer.from(data, 'base64'));
        }
        await appendFile(input.domDump, await page('document.documentElement.outerHTML') + '\n');
      };
      const sizes = async name => {
        for (const width of [1440, 393]) {
          await cdp('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: width === 393});
          await capture(name + '-' + width);
        }
      };
      await cdp('Page.enable'); await cdp('Runtime.enable'); await cdp('Network.enable'); await cdp('Log.enable');
      await cdp('Network.setCookie', {name: 'keep_console', value: input.cookie, url: input.keep + '/console', secure: true, httpOnly: true, sameSite: 'Strict'});
      for (const [i, decision] of ['approve', 'reject'].entries()) {
        step = decision;
        const card = input.keep + '/console/approvals/' + input.ids[i];
        await navigate(card);
        const text = await page('document.body.innerText');
        for (const expected of ['Read-only YAML adoption', 'Approve adoption', input.version, input.runner, input.path, input.field]) {
          assert(text.includes(expected), 'adoption browser: frozen destination is missing');
        }
        assert(await page(`!!document.querySelector('input[name="binding"][value]') && !!document.querySelector('input[name="csrf"][value]')`), 'adoption browser: bound form is missing');
        await sizes('yaml-adoption-' + decision + '-requested');
        if (decision === 'reject') await page(`document.querySelector('input[name="reason"]').value = 'Disposable probe rejected'`);
        await navigation(() => page(`document.querySelector('button[name="decision"][value="${decision}"]').click()`));
        assert(await page(`document.body.innerText.includes(${JSON.stringify('Status: ' + (decision === 'approve' ? 'approved' : 'rejected'))}) && !document.querySelector('button[name="decision"]')`), 'adoption browser: decision did not complete');
        await sizes('yaml-adoption-' + decision + '-decided');
      }
      step = 'list';
      await navigate(input.keep + '/console/approvals');
      assert(await page(`document.body.innerText.includes('Read-only adoption') && document.body.innerText.includes(${JSON.stringify(input.field)})`), 'adoption browser: list lost the adoption field');
      await sizes('yaml-adoption-list');
      assert(problems.length === 0, 'adoption browser: script or policy failure');
      process.stdout.write(JSON.stringify({ok: true, steps: 3}) + '\n');
    } finally {
      try { socket?.close(); } catch {}
      await monitor.cleanup().catch(() => {});
    }
  });
}
main().catch(error => {
  process.stderr.write(`FAIL step=${step}: ${error.code === 'ERR_ASSERTION' ? error.message : 'adoption browser: unexpected failure'}\n`);
  process.exitCode = 1;
});
