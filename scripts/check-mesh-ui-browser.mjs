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
      const pending = new Map(), violations = [], logs = [], posts = [], handed = [];
      const readback = {checked: 0, unavailable: 0};
      socket.addEventListener('message', ev => {
        const m = JSON.parse(ev.data);
        if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error('mesh ui browser: CDP command failed')) : p.res(m.result); return; }
        if (m.method === 'Page.loadEventFired' && loaded) { loaded(); loaded = undefined; }
        if (m.method === 'Runtime.exceptionThrown') violations.push('unhandled exception');
        if (m.method === 'Log.entryAdded') logs.push(m.params.entry);
        if (m.method === 'Runtime.bindingCalled' && m.params.name === '__keepClipboardHandoff') handed.push(m.params.payload);
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
      // Dispatch a real pointer click: focus and transient user activation
      // must match the ordinary path for popups and the clipboard fallback.
      const clickIn = async (prefix, selector) => {
        const {frameTree} = await cdp('Page.getFrameTree');
        const fr = find(frameTree, f => f.url.startsWith(prefix));
        assert(fr, 'mesh ui browser: frame to click in is missing');
        const {executionContextId} = await cdp('Page.createIsolatedWorld', {frameId: fr.id, worldName: 'mesh-ui-click'});
        const r = await cdp('Runtime.evaluate', {contextId: executionContextId, returnByValue: true,
          expression: `(function () { var e = document.querySelector(${JSON.stringify(selector)}); if (!e) return null; e.scrollIntoView({block: 'center'}); var r = e.getBoundingClientRect(); return {x: r.left + r.width / 2, y: r.top + r.height / 2}; })()`});
        assert(!r.exceptionDetails && r.result.value, 'mesh ui browser: nothing to click: ' + selector);
        const offset = await top(`(function () { var r = document.getElementById('keep').getBoundingClientRect(); return {x: r.left, y: r.top}; })()`);
        const x = offset.x + r.result.value.x, y = offset.y + r.result.value.y;
        await cdp('Input.dispatchMouseEvent', {type: 'mouseMoved', x, y});
        await cdp('Input.dispatchMouseEvent', {type: 'mousePressed', x, y, button: 'left', clickCount: 1});
        await cdp('Input.dispatchMouseEvent', {type: 'mouseReleased', x, y, button: 'left', clickCount: 1});
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
      const shot = async (name, prefix) => {
        if (!input.shots) return;
        if (prefix) await waitFor(() => inFrame(prefix, `document.fonts.status === 'loaded'`), 'fonts settled before the screenshot');
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
      assert(await inFrame(keepSecrets, `!!document.querySelector('.page-head a.btn[href="/mesh/ui/secrets/new"]')`), 'mesh ui browser: no Add secret above the list');
      await dump(keepSecrets);

      // 2. mesh.context reaches the screen from the parent; mesh.resize, mesh.navigate.
      step = 'context-resize-navigate';
      await waitFor(() => inFrame(keepSecrets, `document.querySelector('[data-mesh-workspace]').hidden === false`), 'workspace button after mesh.context');
      await waitFor(() => top(`window.__log.some(function (e) { return e.type === 'mesh.ready'; }) && window.__log.some(function (e) { return e.type === 'mesh.resize' && e.height > 0; })`), 'mesh.ready and mesh.resize at the parent');
      await sleep(300);
      const sizes = await top(`({h: parseInt(document.getElementById('keep').style.height, 10), last: window.__log.filter(function (e) { return e.type === 'mesh.resize'; }).pop().height})`);
      const inner = await inFrame(keepSecrets, `document.documentElement.scrollHeight`);
      assert(sizes.h === sizes.last && Math.abs(sizes.h - inner) <= 2, 'mesh ui browser: frame height does not follow the content');
      await shot('mesh-secrets-1440.png', keepSecrets);
      await inFrame(keepSecrets, `document.querySelector('[data-mesh-workspace]').click()`);
      await waitFor(() => top(`document.getElementById('where').textContent === '/w/acme'`), 'mesh.navigate applied by the parent');
      assert(await top(`window.__log.some(function (e) { return e.type === 'mesh.navigate' && e.path === '/w/acme'; })`), 'mesh ui browser: navigate not logged');
      assert(await top(`window.__log.every(function (e) { return e.type !== 'foreign'; })`), 'mesh ui browser: parent got a foreign message');

      // 2a. The embedded fonts load from the screen's own origin (font-src 'self').
      step = 'fonts';
      await waitFor(() => inFrame(keepSecrets, `(function () { var ok = {}; document.fonts.forEach(function (f) { if (f.status === 'loaded') { ok[f.family.replace(/"/g, '') + ' ' + f.weight] = 1; } }); return !!(ok['Inter 400'] && ok['Inter 500'] && ok['JetBrains Mono 400']); })()`), 'Inter and JetBrains Mono loaded in the frame');
      const fam = await inFrame(keepSecrets, `[getComputedStyle(document.body).fontFamily, getComputedStyle(document.querySelector('.mono')).fontFamily]`);
      assert(Array.isArray(fam) && /^"?Inter"?,/.test(fam[0]) && /^"?JetBrains Mono"?,/.test(fam[1]), 'mesh ui browser: the screen does not use the embedded fonts');

      // 2b. A row opens the page of the secret in the frame: carriers, versions,
      //     the stale banner; still no value, no password field.
      step = 'secret-page';
      const secretShown = () => inFrame(keepSecrets + '/', `document.querySelector('h1')?.textContent === 'deploy-token' && /Checked by fingerprint/.test(document.body.innerText)`);
      await inFrame(keepSecrets, `Array.from(document.querySelectorAll('a.row-link')).find(a => a.textContent === 'deploy-token').click()`);
      await waitFor(secretShown, 'the page of the secret');
      const detail = await inFrame(keepSecrets + '/', `({text: document.body.innerText, pw: document.querySelectorAll('input[type=password]').length,
        rows: document.querySelectorAll('tbody tr').length, banner: !!document.querySelector('.banner'), copy: !!document.querySelector('button[data-copy^="kfp1:"]')})`);
      assert(detail.pw === 0 && /kfp1:/.test(detail.text) && /web-1\.example\.test/.test(detail.text), 'mesh ui browser: closed fields missing from the secret page');
      assert(detail.rows >= 3 && detail.banner && detail.copy, 'mesh ui browser: carriers, versions or the stale banner missing from the secret page');
      await dump(keepSecrets + '/');
      await sleep(300);
      await shot('mesh-secret-1440.png', keepSecrets + '/');

      // 3. 393 px frame: no horizontal overflow, long name wraps.
      step = 'narrow';
      await viewport(393, 800, true);
      await navigate(`${mesh}/parent?sub=viewer`);
      await top(`document.getElementById('secrets-nav').click()`);
      await waitFor(rowsShown, 'secret rows at 393');
      await waitFor(() => inFrame(keepSecrets, `document.documentElement.scrollWidth <= document.documentElement.clientWidth`), 'no horizontal overflow at 393');
      await sleep(300);
      await shot('mesh-secrets-393.png', keepSecrets);
      step = 'secret-page-narrow';
      await inFrame(keepSecrets, `Array.from(document.querySelectorAll('a.row-link')).find(a => a.textContent === 'deploy-token').click()`);
      await waitFor(secretShown, 'the page of the secret at 393');
      await waitFor(() => inFrame(keepSecrets + '/', `document.documentElement.scrollWidth <= document.documentElement.clientWidth`), 'no horizontal overflow of the secret page at 393');
      await sleep(300);
      await shot('mesh-secret-393.png', keepSecrets + '/');

      // 3a. Before a record exists, a member who may add into their own
      //     scope gets the form right in the empty state (the disabled reason
      //     is checked by the handler tests). Never offer a terminal command
      //     that cannot work yet. The guidance, every field and the submit
      //     button must fit every phone width in light and dark themes.
      step = 'empty-narrow';
      const emptyBox = `(function () { var d = document.documentElement, empty = document.querySelector('.empty'); if (!empty) return null;
        var controls = ['p', 'small', '.add-form', '.add-form input[name="name"]', '.add-form select[name="scope"]', '.add-form input[name="class"]', '.add-form button[type="submit"]'].map(function (q) { var e = empty.querySelector(q); if (!e) return false; var r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.left >= 0 && r.right <= d.clientWidth; });
        return { command: /keep input-link /.test(empty.innerText), inside: controls.every(Boolean) && d.scrollWidth <= d.clientWidth, width: d.clientWidth }; })()`;

      {
        await viewport(393, 800, true);
        await navigate(`${mesh}/parent?sub=newcomer`);
        await top(`document.getElementById('secrets-nav').click()`);
        await waitFor(() => inFrame(keepSecrets, `/No secrets yet/.test(document.body.innerText) && !!document.querySelector('.empty form.add-form[action="/mesh/ui/secrets/new"]')`), 'the empty list at 393');
        await waitFor(() => inFrame(keepSecrets, `document.fonts.status === 'loaded'`), 'fonts settled on the empty list');
        const seen = await inFrame(keepSecrets, `document.documentElement.outerHTML`);
        assert(typeof seen === 'string' && input.names.every(n => !seen.includes(n)), 'mesh ui browser: a member without a grant sees a secret name');
        const bad = [];
        let widths = 0;
        for (let w = 393; w >= 320; w--) {
          await viewport(w, 800, true);
          let c;
          await waitFor(async () => { c = await inFrame(keepSecrets, emptyBox); return c && c.width === w; }, `the empty list laid out at ${w}`);
          assert(!c.command, 'mesh ui browser: the empty list shows a command before a record exists');
          widths++;
          if (!c.inside) bad.push(`${w}: outside the frame`);
        }
        assert(widths === 74, 'mesh ui browser: the empty list was not checked at every width');
        assert(bad.length === 0, 'mesh ui browser: the empty-state guidance is hidden or sticks out: ' + bad.slice(0, 4).join(', '));
        await viewport(393, 800, true);
        await waitFor(async () => (await inFrame(keepSecrets, emptyBox))?.width === 393, 'the empty list back at 393');
        await sleep(300);
        await shot('mesh-secrets-empty-393.png', keepSecrets);
      }
      // A command longer than the line (a long secret name in the empty
      // carriers block of its page) scrolls inside its own box: still one
      // line, the frame does not overflow.
      step = 'empty-long-narrow';
      const longName = 'a-very-long-secret-name-that-must-wrap-in-a-narrow-frame-without-overflow';
      await viewport(393, 800, true);
      await navigate(`${mesh}/parent?sub=viewer`);
      await top(`document.getElementById('secrets-nav').click()`);
      await waitFor(rowsShown, 'secret rows before the long name');
      await inFrame(keepSecrets, `Array.from(document.querySelectorAll('a.row-link')).find(a => a.textContent === ${JSON.stringify(longName)}).click()`);
      await waitFor(() => inFrame(keepSecrets + '/', `document.querySelector('h1')?.textContent === ${JSON.stringify(longName)} && !!document.querySelector('.empty code')`), 'the page of the long-named secret at 393');
      await waitFor(() => inFrame(keepSecrets + '/', `document.fonts.status === 'loaded'`), 'fonts settled on the long-named secret');
      const long = await inFrame(keepSecrets + '/', `(function () { var c = document.querySelector('.empty code'), r = c.getBoundingClientRect(), d = document.documentElement;
        return { text: c.textContent, rects: c.getClientRects().length, scrolls: c.scrollWidth > c.clientWidth, inside: r.left >= 0 && r.right <= d.clientWidth && d.scrollWidth <= d.clientWidth }; })()`);
      assert(long && long.text === 'keep deploy ' + longName, 'mesh ui browser: the empty carriers block does not show the deploy command');
      assert(long.rects === 1 && long.inside, 'mesh ui browser: the long empty-state command breaks or sticks out at 393');
      assert(long.scrolls, 'mesh ui browser: the long command fits the line, the check proves nothing');
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
      await waitFor(() => inFrame(keep + '/mesh/ui/settings', `!!document.querySelector('input[name=level][value=organization]')`), 'key level form');
      await inFrame(keep + '/mesh/ui/settings', `(function () { var f = document.querySelector('form[action$="key-level"]'); f.querySelector('input[name=level][value=organization]').checked = true; f.querySelector('input[name=confirm_weakening]').checked = true; f.querySelector('button').click(); })()`);
      await waitFor(() => top(`document.getElementById('toast').textContent === 'Key level changed to organization' && document.getElementById('toast').dataset.level === 'success'`), 'mesh.toast at the parent');
      await dump(keep + '/mesh/ui/settings');
      await shot('mesh-settings-1440.png', keep + '/mesh/ui/settings');

      // 5b. The same form at 393 px: reachable, inside the frame, no horizontal overflow.
      step = 'key-level-narrow';
      await viewport(393, 800, true);
      await navigate(`${mesh}/parent?sub=boss`);
      await top(`document.getElementById('secrets-nav').click()`);
      await waitFor(rowsShown, 'admin rows at 393');
      await inFrame(keepSecrets, `document.querySelector('nav a[href="/mesh/ui/settings"]').click()`);
      const settings = keep + '/mesh/ui/settings';
      await waitFor(() => inFrame(settings, `!!document.querySelector('input[name=level]')`), 'key level form at 393');
      await waitFor(() => inFrame(settings, `document.documentElement.scrollWidth <= document.documentElement.clientWidth`), 'no horizontal overflow of the key level form at 393');
      const controls = await inFrame(settings, `(function () { var w = document.documentElement.clientWidth; return ['input[name=level][value=user]', 'input[name=level][value=organization]', 'input[name=confirm_weakening]', 'form[action$="key-level"] button'].map(function (q) { var e = document.querySelector(q); if (!e) return q + ' missing'; var r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.left >= 0 && r.right <= w ? 'ok' : q + ' outside the frame'; }); })()`);
      assert(Array.isArray(controls) && controls.every(c => c === 'ok'), 'mesh ui browser: key level controls not reachable at 393: ' + JSON.stringify(controls));
      await sleep(300);
      await shot('mesh-settings-393.png', settings);
      await viewport(1440, 900, false);

      // 5c. The Mesh theme: dark tokens in mesh.context paint the screen on
      //     every page load, mesh.theme switches it live; a token of the wrong
      //     name or shape never reaches the style.
      step = 'theme-dark';
      const paint = prefix => inFrame(prefix, `(function () { var r = document.documentElement, cs = getComputedStyle(document.body); return { bg: cs.backgroundColor, scheme: getComputedStyle(r).colorScheme, card: getComputedStyle(document.querySelector('.card') || document.body).backgroundColor, warning: r.style.getPropertyValue('--warning'), font: r.style.getPropertyValue('--font-sans'), radius: r.style.getPropertyValue('--radius') }; })()`);
      const LIGHT = 'rgb(255, 255, 255)';
      const isDark = p => p && p.bg !== LIGHT && /^rgb\((\d+), (\d+), (\d+)\)$/.test(p.bg) && p.bg.match(/\d+/g).every(n => +n < 40) && p.scheme === 'dark';
      for (const [width, height, mobile, tag] of [[1440, 900, false, '1440'], [393, 800, true, '393']]) {
        await viewport(width, height, mobile);
        await navigate(`${mesh}/parent?sub=boss&theme=dark`);
        await top(`document.getElementById('secrets-nav').click()`);
        await waitFor(rowsShown, 'rows in the dark theme');
        await waitFor(async () => isDark(await paint(keepSecrets)), 'dark theme from mesh.context on the list');
        const p = await paint(keepSecrets);
        assert(p.warning === '' && p.font === '' && p.radius === '0.5rem', 'mesh ui browser: a theme token of the wrong name or shape reached the style');
        await shot(`mesh-secrets-${tag}-dark.png`, keepSecrets);
        await inFrame(keepSecrets, `document.querySelector('nav a[href="/mesh/ui/settings"]').click()`);
        await waitFor(() => inFrame(settings, `!!document.querySelector('input[name=level]')`), 'key level form in the dark theme');
        await waitFor(async () => isDark(await paint(settings)), 'dark theme from mesh.context on the key level page');
        await shot(`mesh-settings-${tag}-dark.png`, settings);
      }
      // Live switch without a reload: mesh.theme light, then dark again.
      await top(`window.__theme('light')`);
      await waitFor(async () => { const p = await paint(settings); return p && p.bg === LIGHT && p.scheme === 'light'; }, 'mesh.theme light applied live');
      await top(`window.__theme('dark')`);
      await waitFor(async () => isDark(await paint(settings)), 'mesh.theme dark applied live');

      // The empty list in the dark theme at 393: painted dark, guidance
      // and the add form stay visible inside the frame.
      await viewport(393, 800, true);
      await navigate(`${mesh}/parent?sub=newcomer&theme=dark`);
      await top(`document.getElementById('secrets-nav').click()`);
      await waitFor(() => inFrame(keepSecrets, `/No secrets yet/.test(document.body.innerText) && !!document.querySelector('.empty form.add-form[action="/mesh/ui/secrets/new"]')`), 'the empty list in the dark theme');
      await waitFor(async () => isDark(await paint(keepSecrets)), 'dark theme from mesh.context on the empty list');
      await waitFor(() => inFrame(keepSecrets, `document.fonts.status === 'loaded'`), 'fonts settled on the dark empty list');
      const darkEmpty = await inFrame(keepSecrets, emptyBox);
      assert(darkEmpty && !darkEmpty.command && darkEmpty.width === 393, 'mesh ui browser: the dark empty list shows a command before a record exists');
      assert(darkEmpty.inside, 'mesh ui browser: the empty-state guidance is hidden or sticks out in the dark theme');
      await sleep(300);
      await shot('mesh-secrets-empty-393-dark.png', keepSecrets);
      await viewport(1440, 900, false);

      // 5d. Add secret: a person with no secrets names one in the empty state,
      //     gets a one-time input link on the page itself, opens it in a new
      //     tab (outside Mesh's sandbox) and copies the link and the command.
      //     The link never reaches the frame URL, Mesh (postMessage) or a toast.
      // The clipboard is the browser's boundary: some headless builds resolve
      // writeText and still read back nothing. A recorder in Keep's frames
      // takes the exact text the page hands to the clipboard API; the read
      // back is checked too wherever the environment round-trips it.
      await cdp('Runtime.addBinding', {name: '__keepClipboardHandoff'});
      await cdp('Page.addScriptToEvaluateOnNewDocument', {source: `(function () { if (location.origin !== ${JSON.stringify(keep)} || !navigator.clipboard) return;
        var c = navigator.clipboard, w = c.writeText.bind(c);
        c.writeText = function (t) { try { __keepClipboardHandoff(String(t)); } catch (e) {} return w(t); }; })();`});
      for (const [width, height, mobile, tag, name] of [[1440, 900, false, '1440', 'stripe-key'], [393, 800, true, '393', 'stripe key 393']]) {
        step = 'add-secret-' + tag;
        await viewport(width, height, mobile);
        await cdp('Browser.grantPermissions', {origin: keep, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite']});
        await cdp('Browser.grantPermissions', {origin: mesh, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite']});
        await cdp('Emulation.setFocusEmulationEnabled', {enabled: true});
        await navigate(`${mesh}/parent?sub=adder`);
        await top(`document.getElementById('secrets-nav').click()`);
        const addForm = `!!document.querySelector('form[action="/mesh/ui/secrets/new"] input[name=name]')`;
        if (tag === '1440') {
          await waitFor(() => inFrame(keepSecrets, `/No secrets yet/.test(document.body.innerText) && ${addForm}`), 'the empty list with the add form');
          const fields = await inFrame(keepSecrets, `Array.from(document.querySelectorAll('form[action="/mesh/ui/secrets/new"] [name]')).map(function (e) { return e.name; }).sort().join(',')`);
          assert(fields === 'class,csrf,name,scope', 'mesh ui browser: the add form is not the closed field set: ' + fields);
          await sleep(300);
          await shot('mesh-secrets-empty-1440.png', keepSecrets);
        } else {
          await waitFor(() => inFrame(keepSecrets, `!!document.querySelector('.page-head a.btn[href="/mesh/ui/secrets/new"]')`), 'Add secret above the list at 393');
          await clickIn(keepSecrets, '.page-head a.btn[href="/mesh/ui/secrets/new"]');
          await waitFor(() => inFrame(keepSecrets + '/new', addForm), 'the Add secret page at 393');
        }
        const formFrame = tag === '1440' ? keepSecrets : keepSecrets + '/new';
        const logBefore = await top(`window.__log.length`);
        await inFrame(formFrame, `(function () { var f = document.querySelector('form[action="/mesh/ui/secrets/new"]'); f.querySelector('input[name=name]').value = ${JSON.stringify(name)}; f.requestSubmit(); })()`);
        const issued = keepSecrets + '/new';
        await waitFor(() => inFrame(issued, `!!document.getElementById('input-link')`), 'the result page with the input link');
        const res = await inFrame(issued, `({link: document.getElementById('input-link').value, cmd: document.getElementById('input-command').value, url: location.href,
          open: (function () { var a = Array.from(document.querySelectorAll('a')).find(function (a) { return a.textContent === 'Open input page'; }); return a ? [a.href, a.target, a.rel] : null; })(),
          readonly: document.getElementById('input-link').readOnly && document.getElementById('input-command').readOnly, text: document.body.innerText,
          fits: document.documentElement.scrollWidth <= document.documentElement.clientWidth })`);
        assert(res && res.link.startsWith(keep + '/input/') && res.readonly, 'mesh ui browser: no one-time link in a read-only field');
        assert(res.open && res.open[0] === res.link && res.open[1] === '_blank' && res.open[2] === 'noopener noreferrer', 'mesh ui browser: Open input page is not a new-tab link to the input page');
        assert(/One-time link/.test(res.text) && /Expires in/.test(res.text), 'mesh ui browser: the lifetime and the one-time note are missing');
        assert(res.cmd === 'keep input-link ' + (name.includes(' ') ? `'${name}'` : name), 'mesh ui browser: the terminal command is missing or not quoted');
        assert(res.url === issued && !res.url.includes('/input/'), 'mesh ui browser: the link reached the frame URL');
        assert(res.fits, 'mesh ui browser: the result page overflows the frame');
        const token = new URL(res.link).pathname.slice('/input/'.length);
        if (input.linkDump) await appendFile(input.linkDump, res.link + '\n');
        await waitFor(() => top(`document.getElementById('toast').textContent === 'Input link created'`), 'the fixed toast at the parent');
        await sleep(300);
        // Artifacts show the result layout without publishing its capability.
        await inFrame(issued, `document.getElementById('input-link').style.setProperty('-webkit-text-security', 'disc')`);
        try {
          await shot(`mesh-add-result-${tag}.png`, issued);
        } finally {
          await inFrame(issued, `document.getElementById('input-link').style.removeProperty('-webkit-text-security')`);
        }

        // Copy link, then Copy for the command: the clipboard holds each, the
        // parent gets a fixed toast.
        for (const [btn, want, toast] of [['link', res.link, 'Link copied'], ['command', res.cmd, 'Command copied']]) {
          // The environment must round-trip the clipboard before a copy is
          // judged. On failure, name what differs (states and lengths only:
          // the clipboard may hold an input link, which is never printed).
          const control = await top(`(function () {
            function state(name) { return navigator.permissions.query({name: name}).then(function (s) { return s.state; }, function (e) { return 'query:' + e.name; }); }
            function settle(p) { return p.then(function (v) { return {ok: true, v: v}; }, function (e) { return {ok: false, v: e.name}; }); }
            var out = {focus: document.hasFocus(), visibility: document.visibilityState, active: document.activeElement ? document.activeElement.tagName : 'none', secure: window.isSecureContext};
            return Promise.all([state('clipboard-read'), state('clipboard-write')]).then(function (p) {
              out.read = p[0]; out.write = p[1];
              return settle(navigator.clipboard.writeText('clipboard-positive-control'));
            }).then(function (w) {
              out.wrote = w.ok ? 'ok' : w.v;
              return settle(navigator.clipboard.readText());
            }).then(function (r) {
              out.match = r.ok && r.v === 'clipboard-positive-control';
              out.got = r.ok ? 'length ' + r.v.length : r.v;
              return out;
            });
          })()`);
          assert(control && control.wrote === 'ok', `mesh ui browser: clipboard writes refused before the ${btn} copy: ${JSON.stringify(control)}`);
          const handedBefore = handed.length;
          await top(`document.getElementById('toast').textContent = ''`);
          await clickIn(issued, `button[data-copy-from="input-${btn}"]`);
          await waitFor(() => top(`document.getElementById('toast').textContent === ${JSON.stringify(toast)}`), `${toast} at the parent`);
          const got = handed.slice(handedBefore);
          assert(got.length === 1 && got[0] === want, `mesh ui browser: the page did not hand the ${btn} to the clipboard (calls=${got.length}, expectedLength=${want.length}, lengths=${got.map(t => t.length).join('/')})`);
          if (control.match) {
            const clip = await top(`navigator.clipboard.readText()`);
            assert(clip === want, `mesh ui browser: the clipboard does not hold the ${btn} (empty=${clip === ''}, expectedLength=${want.length}, actualLength=${typeof clip === 'string' ? clip.length : 'missing'})`);
            readback.checked++;
          } else {
            readback.unavailable++;
          }
          assert(await inFrame(issued, `document.querySelector('[data-copy-status]').textContent === ${JSON.stringify(toast)}`), 'mesh ui browser: no copy feedback on the page');
        }

        // Open input page: a new tab on Keep's input page, outside the frame.
        const tabsBefore = new Set((await cdp('Target.getTargets')).targetInfos.map(t => t.targetId));
        await clickIn(issued, 'a[target=_blank]');
        let tab;
        await waitFor(async () => { tab = (await cdp('Target.getTargets')).targetInfos.find(t => t.type === 'page' && !tabsBefore.has(t.targetId) && t.url.startsWith(keep + '/input/')); return tab; }, 'the input page in a new tab');
        const {sessionId} = await cdp('Target.attachToTarget', {targetId: tab.targetId, flatten: true});
        const inTab = async expr => (await cdp('Runtime.evaluate', {expression: expr, returnByValue: true}, sessionId)).result.value;
        await waitFor(async () => (await inTab(`document.readyState === 'complete' && document.body.innerText.includes(${JSON.stringify(name)})`)) === true, 'the input page names the secret');
        assert(await inTab(`window.opener === null && document.referrer === ''`), 'mesh ui browser: the input tab keeps an opener or a referrer');
        await cdp('Target.closeTarget', {targetId: tab.targetId});

        // Nothing the screen sent Mesh carries the link.
        const sent = await top(`JSON.stringify(window.__log.slice(${logBefore}))`);
        assert(!sent.includes(token) && !sent.includes('/input/'), 'mesh ui browser: the input link reached Mesh');
        assert(await top(`window.__log.some(function (e) { return e.type === 'mesh.toast'; })`), 'mesh ui browser: positive control: no toast reached the parent');
      }
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
      assert(handed.length === 4 && readback.checked + readback.unavailable === 4, 'mesh ui browser: not every copy was checked');
      process.stdout.write(JSON.stringify({ok: true, steps: 13, clipboardHandoffs: handed.length, clipboardReadback: readback}) + '\n');
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
