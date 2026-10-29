// Drive the production Go page on a real HTTP server. Fixtures arrive through
// stdin; no capability, input value, browser diagnostics or request body is
// printed. Every failure has a fixed, surface-specific message.
import assert from 'node:assert/strict';
import {emitPageFailure, emitFixedAssertion, pageCleanup, cleanupPageResources, isRedirectTarget, postDestinationViolation, REDIRECT_TARGET_PATH} from './lib/page-failure.mjs';
import {spawn} from 'node:child_process';
import {CLEANUP_BUDGET_MS, monitorChromium, startupBudget} from './lib/chromium-startup.mjs';
import {withChromiumProfile} from './lib/chromium-profile.mjs';
import {access, writeFile, mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {createServer} from 'node:http';

let stage = 'setup';
async function main() {
let source = '';
for await (const chunk of process.stdin) source += chunk;
const input = JSON.parse(source);
source = '';
const plain = input.plaintext;
// Trim base64 boundary groups: neighboring bytes must not determine whether
// a leak matches. Exercise all alignments with unrelated prefix/suffix bytes.
const raw = Buffer.from(plain);
const variants = [plain, ...[0,1,2].flatMap(offset => {
  const b = Buffer.concat([Buffer.alloc(offset), raw]);
  const begin = 4 * Math.ceil(offset / 3), end = 4 * Math.floor(b.length / 3);
  return ['base64','base64url'].map(encoding => b.toString(encoding).slice(begin,end));
}), raw.toString('hex'), encodeURIComponent(plain), [...plain].reverse().join('')].map(v => v.toLowerCase());
const leaked = value => variants.some(v => String(value).toLowerCase().includes(v));
for (const prefix of ['', 'q', 'qr']) assert(leaked(Buffer.from(prefix + plain + 'tail').toString('base64')), 'page browser: canary detector control failed');
const candidates = [process.env.CHROME_BIN, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].filter(Boolean);
let chrome;
for (const path of candidates) { try { await access(path); chrome = path; break; } catch {} }
assert(chrome, 'page browser: Chromium is required');
await withChromiumProfile('keep-input-page-', async ({path:profile, diagnostic, cleanup}) => {
const origin = new URL(input.url).origin;
let outsideHits = 0;
const outside = createServer((req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.url === '/injected.js') {
    outsideHits++;
    res.setHeader('Content-Type', 'text/javascript');
    res.end('globalThis.injected = true;');
  } else {
    res.setHeader('Content-Type', 'text/html');
    res.end('<!doctype html><script src="/injected.js"></script><title>CSP control</title>');
  }
});
await new Promise(resolve => outside.listen(0, '127.0.0.1', resolve));
const outsideURL = `http://127.0.0.1:${outside.address().port}`;
const browser = spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
const browserMonitor = monitorChromium(browser, diagnostic, {startupBudgetMs: startupBudget(), group: true});
let socket, primary;
try {
  stage = 'readiness';
  const port = await browserMonitor.port(profile);
  assert(port, 'page browser: Chromium did not start');
  stage = 'discovery';
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  stage = 'socket';
  socket = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, {once: true});
    socket.addEventListener('error', reject, {once: true});
  });
  stage = 'page';
  let sequence = 0, posts = 0, logs = 0, exceptions = 0, cspLogs = 0;
  let expectedBlockedScript = false, checkingPage = false, redirectProbe = false;
  let redirectRequest, redirectResponses = 0;
  const violations = new Set(), pending = new Map();
  let loaded;
  const cdp = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, {resolve, reject});
    socket.send(JSON.stringify({id, method, params}));
  });
  const onMessage = event => {
    const message = JSON.parse(event.data);
    if (message.method === "Page.loadEventFired" && loaded) { loaded(); loaded = undefined; }
    if (checkingPage) {
      if (message.method === 'Runtime.consoleAPICalled') violations.add('page browser: console side effect');
      if (message.method === 'Runtime.exceptionThrown') { exceptions++; violations.add('page browser: unhandled exception'); }
      if (message.method === 'Log.entryAdded') {
        const entry = message.params.entry;
        // Permit only the deliberate CSP diagnostic and the network failure
        // of the exact redirected request. The real submission tolerates none.
        const redirectDiagnostic = Boolean(redirectRequest) && entry.source === 'network' && entry.level === 'error' && entry.networkRequestId === redirectRequest && entry.text.endsWith('net::ERR_FAILED');
        const expected = expectedBlockedScript && entry.source === 'security' && entry.level === 'error' && entry.text.includes(outsideURL + '/injected.js') && entry.text.includes('Content Security Policy');
        if (expected) cspLogs++; else if (!redirectDiagnostic) { logs++; violations.add(entry.text.includes('integrity') ? 'page browser: script integrity violation' : entry.text.includes('Content Security Policy') ? 'page browser: unexpected CSP diagnostic' : 'page browser: unexpected browser log'); }
        if (leaked(entry.text)) violations.add('page browser: input in browser log');
      }
      if (message.method === 'Network.requestWillBeSent') {
        const request = message.params.request;
        if (leaked(request.url) || (request.postData && leaked(request.postData))) violations.add('page browser: input in request');
        if (request.method === 'POST') {
          posts++;
          const destination = postDestinationViolation(request.url, input.url.split('#')[0], origin);
          if (destination) violations.add(destination);
          let envelope;
          try { envelope = JSON.parse(request.postData); } catch {}
          if (!envelope || Object.keys(envelope).sort().join(',') !== 'ciphertext,enc' || Buffer.from(envelope.enc || '', 'base64').length !== 32 || Buffer.from(envelope.ciphertext || '', 'base64').length <= 16) violations.add('page browser: non-envelope request');
          if (request.headers.Authorization || request.headers.Cookie || request.headers.Referer) violations.add('page browser: credential or referrer sent');
        }
      }
      if (message.method === 'Fetch.requestPaused') {
        const {request, requestId} = message.params;
        const u = new URL(request.url);
        const allowed = u.origin === origin && ((request.method === 'GET' && (u.pathname === new URL(input.url).pathname || u.pathname === '/input/assets.js')) || (request.method === 'POST' && request.url === input.url.split('#')[0]));
        if (isRedirectTarget(request.url, origin)) violations.add('page browser: redirect followed');
        else if (!allowed) violations.add('page browser: unexpected network side effect');
        if (request.method === 'POST') {
          if (Object.keys(request.headers).some(name => ['cookie','authorization','referer'].includes(name.toLowerCase()))) violations.add('page browser: credential or referrer sent');
          if (redirectProbe && allowed) {
            redirectResponses++; redirectRequest = message.params.networkId;
            void cdp('Fetch.fulfillRequest', {requestId, responseCode:307, responseHeaders:[{name:'Location',value:origin+REDIRECT_TARGET_PATH}]}).catch(() => violations.add('page browser: interception failed'));
            return;
          }
        }
        void cdp(allowed ? 'Fetch.continueRequest' : 'Fetch.failRequest', allowed ? {requestId} : {requestId, errorReason: 'BlockedByClient'}).catch(() => violations.add('page browser: interception failed'));
      }
      if (message.method === 'Network.webSocketCreated' || message.method === 'Network.webTransportCreated') violations.add('page browser: unexpected network side effect');
    }
    if (message.id && pending.has(message.id)) {
      const {resolve, reject} = pending.get(message.id);
      pending.delete(message.id);
      message.error ? reject(Object.assign(new Error('page browser: CDP command failed'), {code:'CDP_COMMAND_FAILED'})) : resolve(message.result);
    }
  };
  socket.addEventListener('message', onMessage);
  const evaluate = async expression => {
    const result = await cdp('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true});
    assert(!result.exceptionDetails, 'page browser: evaluation failed');
    return result.result?.value;
  };
  // Budgets. A healthy page reaches each state in well under a second; the
  // budget only matters when the shared runner is loaded. Whole page runs took
  // 10-15 s normally and 25-62 s under load, so the steps of the real flow get
  // 15 s. The tamper-variant loop keeps the short budget: there a mutant that
  // fails to reject is detected by the state never appearing, and a long wait
  // would be paid once per variant.
  const FLOW_BUDGET_MS = 15000, VARIANT_BUDGET_MS = 5000;
  const waitFor = async (expression, phase, budgetMs = VARIANT_BUDGET_MS) => {
    const until = performance.now() + budgetMs;
    for (;;) {
      if (await evaluate(expression)) return;
      if (performance.now() >= until) break;
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert(false, 'page browser: expected UI state was not reached (' + phase + '); ' + [...violations].join('; '));
  };
  // Page load on the local server is milliseconds when healthy; 15 s is for a
  // loaded runner (see the budgets above).
  const NAVIGATION_BUDGET_MS = 15000;
  const navigate = async (url, phase) => {
    const ready = new Promise(resolve => { loaded = resolve; });
    await cdp('Page.navigate', {url});
    let timer;
    try { await Promise.race([ready, new Promise((_,reject)=>{timer=setTimeout(()=>reject(new assert.AssertionError({message:"page browser: navigation timeout (" + phase + ")"})),NAVIGATION_BUDGET_MS);})]); } finally { clearTimeout(timer); }
  };
  await cdp('Page.enable'); await cdp('Runtime.enable'); await cdp('Network.enable'); await cdp('Log.enable');
  // Positive control: the planted external script really executes without CSP.
  await navigate(outsideURL, 'control');
  await waitFor('globalThis.injected === true', 'control', FLOW_BUDGET_MS);
  assert(outsideHits === 1, 'page browser: external script control did not execute');
  // Close the execution-control tab before watching the production page.
  // Its asynchronous favicon/network events must not race the page assertions.
  const oldSocket = socket;
  const oldTarget = targets.find(t => t.type === 'page').id;
  const {targetId} = await cdp('Target.createTarget', {url:'about:blank'});
  const freshTargets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  socket = new WebSocket(freshTargets.find(t => t.id === targetId).webSocketDebuggerUrl);
  await new Promise((resolve,reject) => { socket.addEventListener('open',resolve,{once:true}); socket.addEventListener('error',reject,{once:true}); });
  socket.addEventListener('message', onMessage);
  await cdp('Target.closeTarget', {targetId:oldTarget});
  oldSocket.removeEventListener('message', onMessage);
  oldSocket.close();
  await cdp('Page.enable'); await cdp('Runtime.enable'); await cdp('Network.enable'); await cdp('Log.enable');
  const cookieControl = await cdp('Network.setCookie', {url:input.url.split('#')[0], name:'keep_probe', value:'cookie-control', path:'/input/'});
  assert(cookieControl.success, 'page browser: cookie control was not seeded');
  await cdp('Page.addScriptToEvaluateOnNewDocument', {source: `
    globalThis.pageProbe = {verified:false, verifications:0, encryptions:0, earlyEncryption:0, storage:0, indexedDB:0, cookieWrites:0, policy:[]};
    const verify = crypto.subtle.verify.bind(crypto.subtle);
    crypto.subtle.verify = async (...args) => {
      pageProbe.verifications++;
      const result = await verify(...args);
      pageProbe.verified = result;
      return result;
    };
    const generate = crypto.subtle.generateKey.bind(crypto.subtle);
    crypto.subtle.generateKey = (...args) => {
      if (args[0] === 'X25519') { pageProbe.encryptions++; if (!pageProbe.verified) pageProbe.earlyEncryption++; }
      return generate(...args);
    };
    const cookie = Object.getOwnPropertyDescriptor(Document.prototype,'cookie');
    Object.defineProperty(Document.prototype,'cookie',{...cookie, set(value) { pageProbe.cookieWrites++; cookie.set.call(this,value); }});
    const store = Storage.prototype.setItem;
    Storage.prototype.setItem = function(...args) { pageProbe.storage++; return store.apply(this,args); };
    const open = indexedDB.open.bind(indexedDB);
    indexedDB.open = (...args) => { pageProbe.storage++; pageProbe.indexedDB++; return open(...args); };
    document.addEventListener('securitypolicyviolation', e => pageProbe.policy.push({directive:e.effectiveDirective, uri:e.blockedURI}));
  `});
  checkingPage = true;
  await cdp('Fetch.enable', {patterns: [{urlPattern: '*', requestStage: 'Request'}]});
  const quiet = async () => {
    await evaluate('new Promise(resolve => setTimeout(resolve,100))');
    // Inspect actual browser state as well as instrumented write calls. Only
    // counts and booleans cross the diagnostic boundary, never stored values.
    const persisted = await evaluate(`(async () => {
      const directory = await navigator.storage.getDirectory();
      let files = 0;
      for await (const entry of directory.keys()) files++;
      return {caches:(await caches.keys()).length, files,
        databases:(await indexedDB.databases()).length, indexedDB:pageProbe.indexedDB, unnamed:window.name === '',
        fields:document.querySelectorAll('input,textarea').length,
        imports:[...document.styleSheets].some(sheet =>
          [...sheet.cssRules].some(rule => rule.type === CSSRule.IMPORT_RULE))};
    })()`);
    assert(persisted.caches === 0, 'page browser: Cache Storage side effect');
    assert(persisted.files === 0, 'page browser: OPFS side effect');
    // A transient database write is still forbidden after its database is deleted.
    assert(persisted.databases === 0 && persisted.indexedDB === 0, 'page browser: IndexedDB side effect');
    assert(persisted.unnamed, 'page browser: window.name side effect');
    assert(persisted.fields === 1, 'page browser: unexpected input field');
    // CSP hashes intentionally follow the delivered CSS bytes. An import
    // must therefore be rejected independently of the hash comparison.
    assert(!persisted.imports, 'page browser: CSS import side effect');
    const privacy = await evaluate(`(() => {
      const field = document.querySelector('#secret');
      return {autocomplete:[field.getAttribute('autocomplete'),field.autocomplete],
        autocapitalize:[field.getAttribute('autocapitalize'),field.autocapitalize],
        autocorrect:[field.getAttribute('autocorrect')],
        spellcheck:[field.getAttribute('spellcheck'),field.spellcheck]};
    })()`);
    for (const [name, expected] of Object.entries({autocomplete:['off','off'], autocapitalize:['off','none'], autocorrect:['off'], spellcheck:['false',false]})) {
      assert(privacy[name].length === expected.length && privacy[name].every((value, i) => value === expected[i]), 'page browser: textarea privacy attribute ' + name);
    }
    const state = await evaluate(`({cookieWrites:pageProbe.cookieWrites, storage:pageProbe.storage, local:localStorage.length, session:sessionStorage.length, early:pageProbe.earlyEncryption, url:location.href, title:document.title, html:document.documentElement.outerHTML})`);
    const {cookies} = await cdp('Network.getCookies', {urls:[input.url.split('#')[0]]});
    assert(state.cookieWrites === 0 && cookies.length === 1 && cookies[0].name === 'keep_probe' && cookies[0].value === 'cookie-control', 'page browser: browser cookie side effect');
    assert(state.storage === 0 && state.local === 0 && state.session === 0, 'page browser: browser storage side effect');
    assert(state.early === 0, 'page browser: encryption before descriptor verification');
    assert(!leaked(state.url) && !leaked(state.title) && !leaked(state.html), 'page browser: input in URL, title or DOM');
    assert(violations.size === 0, [...violations].join('; '));
  };
  for (const variant of ['hidden-name', ...['SecretName', 'Scope', 'StoreName', 'Class', 'RequestedBy', 'Sponsor'].map(name => 'hidden-field-' + name), 'hidden-ancestor', 'extra-name', 'duplicate-name', 'nested-name', 'metadata-label', 'raw-row-text', 'raw-card-text', 'secret-name', 'legacy-v1', 'foreign-descriptor', 'signed-request', 'scope', 'store', 'class', 'requester', 'sponsor', 'public', 'request', 'signature', 'signer', 'missing-pin', 'wrong-pin', 'duplicate-pin', 'malformed-pin', 'wrong-request-pin', 'missing-request-pin', 'duplicate-request-pin', 'unknown-fragment', 'noncanonical-public', 'noncanonical-signature']) {
    const u = new URL(input.url);
    u.searchParams.set("case", variant);
    const signingPins = new URLSearchParams(u.hash.slice(1));
    if (variant === 'missing-pin') signingPins.delete('signing');
    else if (variant === 'wrong-pin') signingPins.set('signing', Buffer.alloc(32, 1).toString('base64url'));
    else if (variant === 'duplicate-pin') signingPins.append('signing', signingPins.get('signing'));
    else if (variant === 'malformed-pin') signingPins.set('signing', '%');
    u.hash = signingPins.toString();

    if (variant === 'wrong-request-pin') { const pins = new URLSearchParams(u.hash.slice(1)); pins.set('request', '019a0000-0000-7000-8000-000000000099'); u.hash = pins.toString(); }
    else if (variant === 'missing-request-pin') { const pins = new URLSearchParams(u.hash.slice(1)); pins.delete('request'); u.hash = pins.toString(); }
    else if (variant === 'duplicate-request-pin') u.hash += '&request=' + new URLSearchParams(u.hash.slice(1)).get('request');
    else if (variant === 'unknown-fragment') u.hash += '&extra=value';

    await navigate(u.href, variant);
    await waitFor(`document.querySelector('#status')?.dataset.state === 'error'`, variant);
    const state = await evaluate(`({disabled:document.querySelector('#secret').disabled && document.querySelector('button').disabled, encryptions:pageProbe.encryptions})`);
    assert(state.disabled && state.encryptions === 0, 'page browser: tampered descriptor accepted');
    await evaluate(`document.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
    await quiet();
    assert(posts === 0, 'page browser: tampered descriptor was sent');
  }
  await cdp('Emulation.setDeviceMetricsOverride', {width:1440, height:1050, deviceScaleFactor:1, mobile:false});
  await navigate(input.url, 'ready');
  await waitFor(`document.querySelector('#status')?.textContent === 'Ready for secure input.'`, 'ready', FLOW_BUDGET_MS);
  assert(await evaluate(`pageProbe.verifications === 1 && pageProbe.verified && !document.querySelector('#secret').disabled`), 'page browser: valid descriptor did not verify');
  const metadata = await evaluate(`Array.from(document.querySelectorAll('h2,dd,.card-top .badge'), node => node.textContent)`);
  for (const value of input.metadata) assert(metadata.includes(value), 'page browser: requester metadata missing');
  await quiet();
  if (process.env.KEEP_INTAKE_SCREENSHOTS) {
    await mkdir(process.env.KEEP_INTAKE_SCREENSHOTS, {recursive:true});
    for (const width of [1440,393]) {
      await cdp('Emulation.setDeviceMetricsOverride', {width, height:1050, deviceScaleFactor:1, mobile:width===393});
      assert(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'page browser: horizontal overflow');
      const screenshot = await cdp('Page.captureScreenshot', {format:'png', captureBeyondViewport:true});
      await writeFile(join(process.env.KEEP_INTAKE_SCREENSHOTS, `input-${width}.png`), Buffer.from(screenshot.data,'base64'));
    }
  }
  // Block one specific injected script, after proving its execution control.
  expectedBlockedScript = true;
  const blocked = await evaluate(`new Promise(resolve => {
    const node = document.createElement('script');
    node.src = ${JSON.stringify(outsideURL + '/injected.js')};
    node.onerror = () => resolve(true);
    node.onload = () => resolve(false);
    document.head.append(node);
  })`);
  await quiet();
  assert(blocked && outsideHits === 1 && cspLogs === 1, 'page browser: external script was not blocked by CSP');
  assert(await evaluate(`globalThis.injected !== true && pageProbe.policy.some(p=>p.directive==='script-src-elem' && p.uri===${JSON.stringify(outsideURL+'/injected.js')})`), 'page browser: external script CSP event missing');
  expectedBlockedScript = false;
  // A real HTTP 307 response must fail the fetch without following its target.
  const redirectPage = new URL(input.url);
  redirectPage.searchParams.set('case','redirect');
  await navigate(redirectPage.href, 'redirect');
  await waitFor(`document.querySelector('#status')?.textContent === 'Ready for secure input.'`, 'redirect-ready', FLOW_BUDGET_MS);
  assert(await evaluate(`document.cookie === 'keep_probe=cookie-control'`), 'page browser: cookie control is not visible');
  redirectProbe = true;
  await evaluate(`document.querySelector('#secret').value = ${JSON.stringify(plain)}; document.querySelector('button').click()`);
  await waitFor(`document.querySelector('#status')?.dataset.state === 'error'`, 'redirect-error', FLOW_BUDGET_MS);
  await quiet();
  assert(redirectResponses === 1 && posts === 1, 'page browser: redirect control did not run');
  redirectProbe = false;
  redirectRequest = undefined;
  // Fresh valid page: the real scenario has no tolerated diagnostic events.
  const fresh = new URL(input.url);
  fresh.searchParams.set('case', 'submit');
  await navigate(fresh.href, 'submit');
  await waitFor(`document.querySelector('#status')?.textContent === 'Ready for secure input.'`, 'ready', FLOW_BUDGET_MS);
  await evaluate(`document.querySelector('#secret').value = ${JSON.stringify(plain)}; document.querySelector('button').click()`);
  await waitFor(`document.querySelector('#status')?.dataset.state === 'success'`, 'save', FLOW_BUDGET_MS);
  await quiet();
  assert(posts === 2, 'page browser: expected redirect probe and one ciphertext submission');
  assert(await evaluate(`document.querySelector('#secret').value === '' && document.querySelector('form').hidden && pageProbe.encryptions === 1`), 'page browser: plaintext field not cleared after submission');
  const result = await evaluate(`({version:document.querySelector('#version').textContent,fingerprint:document.querySelector('#fingerprint').textContent})`);
  assert(!leaked(result.version) && !leaked(result.fingerprint) && result.version && result.fingerprint, 'page browser: invalid completion metadata');
  assert(logs === 0 && exceptions === 0, 'page browser: unexpected diagnostic output');
  process.stdout.write(JSON.stringify(result));
} catch (error) {
  primary = error;
  throw error;
} finally {
  if (!primary) stage = 'cleanup';
  await pageCleanup(primary, () => cleanupPageResources([
    ['CLEANUP_SOCKET', () => { socket?.close(); }, 100],
    ['CLEANUP_BROWSER', () => browserMonitor.cleanup(), CLEANUP_BUDGET_MS],
    ['CLEANUP_SERVER', () => new Promise((resolve, reject) => {
      outside.close(error => error ? reject(error) : resolve());
      outside.closeAllConnections();
    }), 1000],
    ['CLEANUP_PROFILE', cleanup, 2000]
  ]));
}
});
}
main().catch(error => { emitPageFailure(stage, error); emitFixedAssertion(error); process.exitCode = 1; });
