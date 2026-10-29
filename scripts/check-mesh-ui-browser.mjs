// Drive the real Mesh screen (/mesh/ui/*) in Chromium, framed by a stand-in
// Mesh page on another origin. Fixtures arrive on stdin; the run prints only a
// fixed result line. Every failure carries a fixed message naming the step.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
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
  const keep = input.keep, mesh = input.mesh;
  const candidates = [process.env.CHROME_BIN, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].filter(Boolean);
  let chrome;
  for (const path of candidates) { try { await access(path); chrome = path; break; } catch {} }
  assert(chrome, 'mesh ui browser: Chromium is required');

  await withChromiumProfile('keep-mesh-ui-', async ({path: profile, diagnostic, cleanup}) => {
    // The foreign page: embeds the screen directly, embeds the Mesh page that
    // embeds it, or opens it as a popup and posts at it.
    const evilSend = {token: '', body: '', popup: ''};
    const evil = createServer((req, res) => {
      res.setHeader('Content-Type', 'text/html');
      if (req.url.startsWith('/direct')) res.end(`<!doctype html><iframe id=k src="${keep}/mesh/ui/secrets"></iframe>`);
      else if (req.url.startsWith('/pop')) res.end(`<!doctype html><script>window.__w = null; function openIt() { window.__w = window.open(${JSON.stringify(evilSend.popup)}, 'k'); }</script>`);
      else res.end(`<!doctype html><iframe id=m src="${evilSend.body}"></iframe>`);
    });
    await new Promise(r => evil.listen(0, '127.0.0.1', r));
    const evilURL = `http://127.0.0.1:${evil.address().port}`;

    const browser = spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check',
      '--ignore-certificate-errors', '--disable-site-isolation-trials', '--disable-features=IsolateOrigins,site-per-process',
      '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], {stdio: ['ignore', 'ignore', 'pipe']});
    const monitor = monitorChromium(browser, diagnostic, {startupBudgetMs: startupBudget()});
    let socket;
    try {
      step = 'browser';
      const port = await monitor.port(profile);
      assert(port, 'mesh ui browser: Chromium did not start');
      const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      socket = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
      await new Promise((res, rej) => { socket.addEventListener('open', res, {once: true}); socket.addEventListener('error', rej, {once: true}); });
      let seq = 0, loaded;
      const pending = new Map(), violations = [], logs = [], posts = [];
      socket.addEventListener('message', ev => {
        const m = JSON.parse(ev.data);
        if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error('mesh ui browser: CDP command failed')) : p.res(m.result); return; }
        if (m.method === 'Page.loadEventFired' && loaded) { loaded(); loaded = undefined; }
        if (m.method === 'Runtime.exceptionThrown') violations.push('unhandled exception');
        if (m.method === 'Log.entryAdded') logs.push(m.params.entry);
        if (m.method === 'Network.requestWillBeSent' && m.params.request.method === 'POST') posts.push(new URL(m.params.request.url).pathname);
      });
      const cdp = (method, params = {}, sessionId) => new Promise((res, rej) => { const id = ++seq; pending.set(id, {res, rej}); socket.send(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})})); });
      const top = async expr => {
        const r = await cdp('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true});
        assert(!r.exceptionDetails, 'mesh ui browser: evaluation failed');
        return r.result.value;
      };
      const find = (t, pred) => { if (pred(t.frame)) return t.frame; for (const c of t.childFrames || []) { const f = find(c, pred); if (f) return f; } return null; };
      // Evaluate in the DOM of the frame whose URL starts with prefix (an
      // isolated world sees the DOM the screen script edits, across origins).
      // The frame may navigate between the lookup and the evaluation (after the
      // mesh.context sign-in the screen reloads itself), which destroys the
      // world: that is "not there yet" for the polling caller, like a missing frame.
      const inFrame = async (prefix, expr) => {
        const {frameTree} = await cdp('Page.getFrameTree');
        const fr = find(frameTree, f => f.url.startsWith(prefix));
        if (!fr) return undefined;
        let r;
        try {
          const {executionContextId} = await cdp('Page.createIsolatedWorld', {frameId: fr.id, worldName: 'mesh-ui-check'});
          r = await cdp('Runtime.evaluate', {contextId: executionContextId, expression: expr, returnByValue: true});
        } catch (error) {
          if (error.message === 'mesh ui browser: CDP command failed') return undefined;
          throw error;
        }
        return r.exceptionDetails ? undefined : r.result.value;
      };
      const waitFor = async (fn, what, ms = FLOW_MS) => {
        const until = performance.now() + ms;
        for (;;) {
          if (await fn()) return;
          if (performance.now() > until) assert.fail('mesh ui browser: not reached: ' + what);
          await sleep(50);
        }
      };
      const navigate = async url => {
        const ready = new Promise(r => { loaded = r; });
        await cdp('Page.navigate', {url});
        await Promise.race([ready, sleep(FLOW_MS).then(() => assert.fail('mesh ui browser: navigation timeout'))]);
      };
      const shot = async name => {
        if (!input.shots) return;
        await mkdir(input.shots, {recursive: true});
        const {data} = await cdp('Page.captureScreenshot', {format: 'png'});
        await writeFile(join(input.shots, name), Buffer.from(data, 'base64'));
      };
      const viewport = (width, height, mobile) => cdp('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile});
      // What the frames really hold after the screen script ran, for the Go side
      // to scan for the canary; never printed here.
      const dump = async (prefix, expr = `document.documentElement.outerHTML + '\\n' + document.body.innerText`) => {
        if (!input.domDump) return;
        const text = await inFrame(prefix, expr);
        assert(typeof text === 'string' && text.length > 0, 'mesh ui browser: frame DOM dump is empty');
        await appendFile(input.domDump, text + '\n');
      };
      const keepSecrets = keep + '/mesh/ui/secrets';
      const rowsShown = () => inFrame(keepSecrets, `document.querySelectorAll('tbody tr').length >= 3`);
      await cdp('Page.enable'); await cdp('Runtime.enable'); await cdp('Network.enable'); await cdp('Log.enable');

      // 1. Sidebar entry opens the screen in the frame, signed in by the Mesh token alone.
      step = 'sidebar-signin';
      await viewport(1440, 900, false);
      await navigate(`${mesh}/parent?sub=viewer`);
      assert(await top(`document.querySelector('#side [aria-current]').textContent === 'Keep'`), 'mesh ui browser: sidebar entry missing');
      await top(`document.getElementById('secrets-nav').click()`);
      await waitFor(rowsShown, 'secret rows in the frame');
      const page = await inFrame(keepSecrets, `({text: document.body.innerText, url: location.href, pw: document.querySelectorAll('input[type=password]').length,
        login: /Open this screen from Mesh|Signing in/.test(document.body.innerText), fp: /kfp1:/.test(document.body.innerText), button: document.querySelector('[data-mesh-workspace]')?.hidden})`);
      assert(page.pw === 0 && !page.login, 'mesh ui browser: a second login was shown');
      assert(!page.url.includes('token='), 'mesh ui browser: token left in the frame URL');
      assert(input.names.every(n => page.text.includes(n)) && page.fp, 'mesh ui browser: closed fields missing from the list');
      assert(!posts.includes('/mesh/ui/session'), 'mesh ui browser: URL token path used the session endpoint');
      await dump(keepSecrets);

      // 2. mesh.context reaches the screen from the parent; mesh.resize, mesh.navigate.
      step = 'context-resize-navigate';
      await waitFor(() => inFrame(keepSecrets, `document.querySelector('[data-mesh-workspace]').hidden === false`), 'workspace button after mesh.context');
      await waitFor(() => top(`window.__log.some(function (e) { return e.type === 'mesh.ready'; }) && window.__log.some(function (e) { return e.type === 'mesh.resize' && e.height > 0; })`), 'mesh.ready and mesh.resize at the parent');
      await sleep(300);
      const sizes = await top(`({h: parseInt(document.getElementById('keep').style.height, 10), last: window.__log.filter(function (e) { return e.type === 'mesh.resize'; }).pop().height})`);
      const inner = await inFrame(keepSecrets, `document.documentElement.scrollHeight`);
      assert(sizes.h === sizes.last && Math.abs(sizes.h - inner) <= 2, 'mesh ui browser: frame height does not follow the content');
      await shot('mesh-secrets-1440.png');
      await inFrame(keepSecrets, `document.querySelector('[data-mesh-workspace]').click()`);
      await waitFor(() => top(`document.getElementById('where').textContent === '/w/acme'`), 'mesh.navigate applied by the parent');
      assert(await top(`window.__log.some(function (e) { return e.type === 'mesh.navigate' && e.path === '/w/acme'; })`), 'mesh ui browser: navigate not logged');
      assert(await top(`window.__log.every(function (e) { return e.type !== 'foreign'; })`), 'mesh ui browser: parent got a foreign message');

      // 3. 393 px frame: no horizontal overflow, long name wraps.
      step = 'narrow';
      await viewport(393, 800, true);
      await navigate(`${mesh}/parent?sub=viewer`);
      await top(`document.getElementById('secrets-nav').click()`);
      await waitFor(rowsShown, 'secret rows at 393');
      await waitFor(() => inFrame(keepSecrets, `document.documentElement.scrollWidth <= document.documentElement.clientWidth`), 'no horizontal overflow at 393');
      await sleep(300);
      await shot('mesh-secrets-393.png');
      await viewport(1440, 900, false);

      // 4. The URL token has lapsed: the screen signs in through mesh.context, once.
      step = 'context-signin';
      const before = posts.filter(p => p === '/mesh/ui/session').length;
      await navigate(`${mesh}/parent?sub=viewer&expired=1`);
      await top(`document.getElementById('secrets-nav').click()`);
      await waitFor(rowsShown, 'rows after the mesh.context sign-in');
      assert(posts.filter(p => p === '/mesh/ui/session').length === before + 1, 'mesh ui browser: sign-in did not go through the session endpoint once');

      // 5. Key level: an admin changes it, the parent gets mesh.toast.
      step = 'key-level-toast';
      await navigate(`${mesh}/parent?sub=boss`);
      await top(`document.getElementById('secrets-nav').click()`);
      await waitFor(rowsShown, 'admin rows');
      await inFrame(keepSecrets, `document.querySelector('nav a[href="/mesh/ui/settings"]').click()`);
      await waitFor(() => inFrame(keep + '/mesh/ui/settings', `!!document.querySelector('select[name=level]')`), 'key level form');
      await inFrame(keep + '/mesh/ui/settings', `(function () { var f = document.querySelector('form[action$="key-level"]'); f.querySelector('select').value = 'organization'; f.querySelector('input[name=confirm_weakening]').checked = true; f.querySelector('button').click(); })()`);
      await waitFor(() => top(`document.getElementById('toast').textContent === 'Key level changed to organization' && document.getElementById('toast').dataset.level === 'success'`), 'mesh.toast at the parent');
      await dump(keep + '/mesh/ui/settings');
      await shot('mesh-settings-1440.png');

      // 5b. The same form at 393 px: reachable, inside the frame, no horizontal overflow.
      step = 'key-level-narrow';
      await viewport(393, 800, true);
      await navigate(`${mesh}/parent?sub=boss`);
      await top(`document.getElementById('secrets-nav').click()`);
      await waitFor(rowsShown, 'admin rows at 393');
      await inFrame(keepSecrets, `document.querySelector('nav a[href="/mesh/ui/settings"]').click()`);
      const settings = keep + '/mesh/ui/settings';
      await waitFor(() => inFrame(settings, `!!document.querySelector('select[name=level]')`), 'key level form at 393');
      await waitFor(() => inFrame(settings, `document.documentElement.scrollWidth <= document.documentElement.clientWidth`), 'no horizontal overflow of the key level form at 393');
      const controls = await inFrame(settings, `(function () { var w = document.documentElement.clientWidth; return ['select[name=level]', 'input[name=confirm_weakening]', 'form[action$="key-level"] button'].map(function (q) { var e = document.querySelector(q); if (!e) return q + ' missing'; var r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.left >= 0 && r.right <= w ? 'ok' : q + ' outside the frame'; }); })()`);
      assert(Array.isArray(controls) && controls.every(c => c === 'ok'), 'mesh ui browser: key level controls not reachable at 393: ' + JSON.stringify(controls));
      await sleep(300);
      await shot('mesh-settings-393.png');
      await viewport(1440, 900, false);

      // 6. Foreign origin, direct embed: refused by frame-ancestors.
      step = 'foreign-embed';
      logs.length = 0;
      await navigate(`${evilURL}/direct`);
      await waitFor(async () => (await cdp('Page.getFrameTree')).frameTree.childFrames?.length > 0 && logs.some(l => /frame-ancestors/.test(l.text)), 'frame-ancestors refusal logged');
      const {frameTree} = await cdp('Page.getFrameTree');
      const child = frameTree.childFrames[0].frame;
      assert(child.url.startsWith('chrome-error://') || child.unreachableUrl, 'mesh ui browser: foreign page framed the screen');
      // Read the tree, not the frame: inFrame treats a failed evaluation as absence.
      assert(!find(frameTree, f => f.url.startsWith(keepSecrets)), 'mesh ui browser: screen document present under a foreign page');

      // 7.
      step = 'foreign-chain';
      // The ancestor chain counts: the screen under Mesh under a foreign page is refused too.
      evilSend.body = `${mesh}/parent?sub=viewer&autoload=1`;
      logs.length = 0;
      await navigate(`${evilURL}/via`);
      await waitFor(() => logs.some(l => /frame-ancestors/.test(l.text)), 'frame-ancestors refusal for the nested screen');
      const nested = (await cdp('Page.getFrameTree')).frameTree.childFrames[0].childFrames?.[0]?.frame;
      assert(nested && (nested.url.startsWith('chrome-error://') || nested.unreachableUrl), 'mesh ui browser: screen loaded under a foreign ancestor');

      // 8. A window that is not the parent posting mesh.context (with a valid token)
      //    at the screen is ignored: once from a foreign origin, once from the
      //    Mesh origin itself (allowed origin, wrong window).
      evilSend.token = await (await fetch(`${mesh}/token?sub=viewer`)).text();
      const lapsed = (await (await fetch(`${mesh}/parent?sub=viewer&expired=1&autoload=1`)).text()).match(/<iframe[^>]* src="([^"]+)"/)[1].replaceAll('&amp;', '&');
      evilSend.popup = lapsed;
      for (const [label, pop] of [['foreign-origin-window', `${evilURL}/pop`], ['mesh-origin-other-window', `${mesh}/pop?u=${encodeURIComponent(lapsed)}`]]) {
        step = label;
        await cdp('Network.clearBrowserCookies');
        const sessionsBefore = posts.filter(p => p === '/mesh/ui/session').length;
        await navigate(pop);
        await cdp('Runtime.evaluate', {expression: 'openIt()', userGesture: true});
        let popup;
        await waitFor(async () => { popup = (await cdp('Target.getTargets')).targetInfos.find(t => t.type === 'page' && t.url.startsWith(keepSecrets)); return popup; }, 'popup with the screen');
        const {sessionId} = await cdp('Target.attachToTarget', {targetId: popup.targetId, flatten: true});
        const inPopup = async expr => (await cdp('Runtime.evaluate', {expression: expr, returnByValue: true}, sessionId)).result.value;
        await waitFor(() => inPopup(`/Signing in through Mesh/.test(document.body.innerText)`), 'the screen waits for mesh.context');
        assert(await top(`window.__w && !window.__w.closed`), 'mesh ui browser: control popup is not open');
        await top(`window.__w.postMessage({type:'mesh.context',version:1,workspace_slug:'evil',token:${JSON.stringify(evilSend.token)}}, '*')`);
        await sleep(1500);
        const waiting = await inPopup(`({rows: document.querySelectorAll('tbody tr').length, signing: /Signing in through Mesh/.test(document.body.innerText), button: !!document.querySelector('[data-mesh-workspace]')})`);
        assert(waiting.rows === 0 && waiting.signing && !waiting.button, 'mesh ui browser: foreign context signed the screen in');
        assert(posts.filter(p => p === '/mesh/ui/session').length === sessionsBefore, 'mesh ui browser: foreign context reached the session endpoint');
        await cdp('Target.closeTarget', {targetId: popup.targetId});
      }

      assert(violations.length === 0, 'mesh ui browser: unhandled exception in a frame');
      process.stdout.write(JSON.stringify({ok: true, steps: 9}) + '\n');
    } finally {
      try { socket?.close(); } catch {}
      await monitor.cleanup().catch(() => {});
      await new Promise(r => { evil.close(() => r()); evil.closeAllConnections(); });
      await cleanup();
    }
  });
}
main().catch(error => {
  if (process.env.MESH_UI_BROWSER_DEBUG) process.stderr.write(String(error && error.stack) + '\n');
  process.stderr.write(`FAIL step=${step}: ${error.code === 'ERR_ASSERTION' ? error.message : 'mesh ui browser: unexpected failure'}\n`);
  process.exitCode = 1;
});
