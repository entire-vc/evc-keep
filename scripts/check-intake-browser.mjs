import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {cleanupStep, monitorChromium, startupBudget} from './lib/chromium-startup.mjs';
import {withChromiumProfile} from './lib/chromium-profile.mjs';
import {boundedCleanup} from './lib/bounded-cleanup.mjs';
import {readFile, access} from 'node:fs/promises';
import {join, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createServer} from 'node:http';
import {createHash, randomBytes} from 'node:crypto';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
// Full object verified against the immutable TestVectors source cited by
// RFC 9180: cfrg/draft-irtf-cfrg-hpke@5f503c564da00b0687b3de75f1dfbdfc4079ad31.
const fixture = await readFile(join(root,'web/intake/testdata/rfc9180-x25519-aes256.json'));
assert.equal(createHash('sha256').update(fixture).digest('hex'),'29a4dc2c6be901468cf715cadfa7dd3d92b2f060b3c794ecb611fc37dbbfc2d0','RFC fixture hash mismatch');
const vector = JSON.parse(fixture);
let cross;
if(process.argv.includes('--cross')) {
 let input=''; for await (const chunk of process.stdin) input+=chunk;
 cross=JSON.parse(input);
}
const canary=randomBytes(32).toString('hex');
const script = await readFile(join(root,'web/intake/hpke.js'));
const candidates = [process.env.CHROME_BIN, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].filter(Boolean);
let chrome;
for (const path of candidates) { try { await access(path); chrome=path; break; } catch {} }
assert(chrome,'headless Chromium is required; set CHROME_BIN');
await withChromiumProfile('keep-intake-browser-', async ({path:profile, diagnostic, cleanup}) => {
const server = createServer((req,res)=>{
 res.setHeader('Cache-Control','no-store');
 res.setHeader('Content-Security-Policy',"img-src 'self'; script-src 'self'");
 if (req.url==='/hpke-limit.js') { res.setHeader('Content-Type','text/javascript'); res.end(script.toString().replace('let sequence=0n;','let sequence=(1n<<96n)-2n;')); }
 else if (req.url==='/hpke.js') { res.setHeader('Content-Type','text/javascript'); res.end(script); }
 else { res.setHeader('Content-Type','text/html'); res.end('<!doctype html><link rel="icon" href="/">'); }
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const browser = spawn(chrome,['--headless=new','--no-sandbox','--disable-gpu','--disable-background-networking','--disable-component-update','--no-first-run','--no-default-browser-check','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:['ignore','ignore','pipe'],detached:true});
const browserMonitor = monitorChromium(browser, diagnostic, {startupBudgetMs: startupBudget(), group: true});
let socket, primary;
try {
 const port = await browserMonitor.port(profile);
 assert(port,'Chromium did not start');
 const targets=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
 socket=new WebSocket(targets.find(t=>t.type==='page').webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
 let seq=0;
 const pending=new Map();
 const violations=new Set();
 const sideEffects=new Map(['localStorage','sessionStorage','IndexedDB','document title'].map(kind=>[kind,'browser '+kind+' side effect']));
 const url=`http://127.0.0.1:${server.address().port}`;
 const allowed=request=>request.method==='GET' && ['/', '/hpke.js', '/hpke-limit.js'].some(path=>request.url===url+path);
 socket.addEventListener('message',e=>{
  const m=JSON.parse(e.data);
  // Record classes only; never echo console arguments, request bodies or URLs.
  if(m.method==='Runtime.bindingCalled' && m.params.name==='intakeSideEffect') violations.add(sideEffects.get(m.params.payload)||'browser interception misuse');
  if(m.method==='Page.navigatedWithinDocument') violations.add('browser location hash side effect');
  if(m.method==='Log.entryAdded') violations.add('browser log side effect');
  if(m.method==='Runtime.exceptionThrown') violations.add('browser exception side effect');
  if(m.method==='Runtime.consoleAPICalled') violations.add('browser console side effect');
  if(m.method==='Network.requestWillBeSent' && !allowed(m.params.request)) violations.add('browser network side effect');
  if(m.method==='Network.webSocketCreated' || m.method==='Network.webTransportCreated') violations.add('browser network side effect');
  if(m.method==='Fetch.requestPaused') {
   const permitted=allowed(m.params.request);
   if(!permitted) violations.add('browser network side effect');
   void cdp(permitted?'Fetch.continueRequest':'Fetch.failRequest',permitted?{requestId:m.params.requestId}:{requestId:m.params.requestId,errorReason:'BlockedByClient'}).catch(()=>violations.add('browser interception failed'));
  }
  if(m.id&&pending.has(m.id)){const {resolve,reject}=pending.get(m.id);pending.delete(m.id);m.error?reject(new Error('CDP command failed')):resolve(m.result);}
 });
 const cdp=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
 const assertQuiet=async()=>{
  await cdp('Runtime.evaluate',{awaitPromise:true,expression:'new Promise(resolve=>setTimeout(resolve,50))'});
  assert.equal(violations.size,0,Array.from(violations).join('; '));
 };
 await cdp('Page.enable');
 await cdp('Runtime.enable');
 await cdp('Network.enable');
 await cdp('Log.enable');
 await cdp('Runtime.addBinding',{name:'intakeSideEffect'});
 await cdp('Page.addScriptToEvaluateOnNewDocument',{source:`(()=>{
  const report=kind=>globalThis.intakeSideEffect(kind);
  for(const name of ['localStorage','sessionStorage']) {
   const storage=globalThis[name];
   Object.defineProperty(globalThis,name,{value:new Proxy(storage,{
    get(target,key) {
     const value=Reflect.get(target,key,target);
     if(typeof value!=='function') return value;
     return (...args)=>{report(name);return value.apply(target,args);};
    },
    set(target,key,value) {report(name);return Reflect.set(target,key,value,target);},
    defineProperty(target,key,descriptor) {report(name);return Reflect.defineProperty(target,key,descriptor);},
    deleteProperty(target,key) {report(name);return Reflect.deleteProperty(target,key);}
   })});
  }
  for(const [proto,methods] of [
   [IDBFactory.prototype,['open','deleteDatabase']],
   [IDBObjectStore.prototype,['put','add','delete','clear']],
   [IDBCursor.prototype,['update','delete']]
  ]) for(const name of methods) {
   const original=proto[name];
   proto[name]=function(...args) {report('IndexedDB');return original.apply(this,args);};
  }
  const title=Object.getOwnPropertyDescriptor(Document.prototype,'title');
  Object.defineProperty(Document.prototype,'title',{...title,set(value) {report('document title');return title.set.call(this,value);}});
  new MutationObserver(records=>{
   if(records.some(r=>r.target.nodeName==='TITLE' || r.target.parentNode?.nodeName==='TITLE' ||
    [...r.addedNodes].some(n=>n.nodeName==='TITLE'))) report('document title');
  }).observe(document,{subtree:true,childList:true,characterData:true});
 })()`});
 await cdp('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]});
 await cdp('Page.navigate',{url});
 await new Promise(r=>setTimeout(r,250));
 if(cross) {
  const result=await cdp('Runtime.evaluate',{awaitPromise:true,returnByValue:true,expression:`(async()=>{
   const {setupSender,intakeInfo}=await import('/hpke.js');
   const from64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
   const to64=b=>btoa(String.fromCharCode(...b));
   const input=${JSON.stringify(cross)};
   const plaintext=from64(input.plaintext);
   try {
    const sender=await setupSender(from64(input.public_key),intakeInfo(input.request_id));
    const ct=await sender.seal(plaintext);
    return {enc:to64(sender.enc),ciphertext:to64(ct)};
   } finally { plaintext.fill(0); }
  })()`});
  await assertQuiet();
  const value=result.result?.value;
  assert(value?.ciphertext,'browser cross-encryption failed');
  console.log(JSON.stringify(value));
 } else {
 const result=await cdp('Runtime.evaluate',{awaitPromise:true,returnByValue:true,expression:`(async()=>{
  const module=await import('/hpke.js');
  const {setupSender,intakeInfo}=module;
  const v=${JSON.stringify(vector)};
  const fromHex=s=>Uint8Array.from(s.match(/../g)||[],b=>parseInt(b,16));
  const toHex=b=>Array.from(b,b=>b.toString(16).padStart(2,'0')).join('');
  try {
   const recipient=fromHex(v.pkRm),info=fromHex(v.info),plaintext=fromHex(v.encryptions[0].pt);
   const canary=new TextEncoder().encode(${JSON.stringify(canary)});
   try { await (await setupSender(recipient,info)).seal(canary); }
   finally { canary.fill(0); }
   const original=crypto.subtle.generateKey.bind(crypto.subtle);
   let generated=0;
   crypto.subtle.generateKey=async(...args)=>{
    if(args[0]!=='X25519' || args[1]!==false) throw new Error('extractable ephemeral key');
    const pair=await original(...args);
    if(pair.privateKey.extractable) throw new Error('extractable ephemeral key');
    generated++;
    return pair;
   };
   try {
    const a=await setupSender(recipient,info),b=await setupSender(recipient,info);
    if(toHex(a.enc)===toHex(b.enc) || toHex(await a.seal(plaintext))===toHex(await b.seal(plaintext))) return {ok:false,reason:'ephemeral freshness failed'};
    const fixed=fromHex(v.skEm);
    const c=await setupSender(recipient,info,fixed),d=await setupSender(recipient,info,fixed);
    fixed.fill(0);
    if(toHex(c.enc)===toHex(d.enc) || generated!==4) return {ok:false,reason:'production ephemeral override accepted'};
   } finally { crypto.subtle.generateKey=original; }
   for(const id of ['bad','019A0000-0000-7000-8000-000000000001','019a0000-0000-4000-8000-000000000001','019a0000-0000-7000-0000-000000000001','x019a0000-0000-7000-8000-000000000001','019a0000-0000-7000-8000-000000000001\\n']) {
    let rejected=false; try { intakeInfo(id); } catch { rejected=true; }
    if(!rejected) return {ok:false,reason:'invalid browser request accepted'};
   }
   intakeInfo('019a0000-0000-7000-8000-000000000001');
   let invalidWork=0;
   crypto.subtle.generateKey=async(...args)=>{invalidWork++;return original(...args);};
   for(const invalid of [recipient.slice(0,31),new Uint8Array(33),Array.from(recipient)]) {
    let rejected=false; try { await setupSender(invalid,info); } catch { rejected=true; }
    if(!rejected || invalidWork!==0) return {ok:false,reason:'invalid browser recipient accepted'};
   }
   crypto.subtle.generateKey=original;
   // Chromium's own low-order rejection is a positive control. Then
   // emulate a permissive primitive to exercise the sender's own check.
   const lowOrder=new Uint8Array(32); lowOrder[0]=1;
   let nativeRejected=false;
   try { await setupSender(lowOrder,info); } catch { nativeRejected=true; }
   if(!nativeRejected) return {ok:false,reason:'native low-order recipient accepted'};
   const derive=crypto.subtle.deriveBits.bind(crypto.subtle);
   let derived=0,kdfWork=0;
   const importKey=crypto.subtle.importKey.bind(crypto.subtle);
   crypto.subtle.importKey=async(...args)=>{
    if(args[2]?.name==='HMAC') kdfWork++;
    return importKey(...args);
   };
   await setupSender(recipient,info);
   if(kdfWork===0) return {ok:false,reason:'KDF order observer is blind'};
   kdfWork=0;
   crypto.subtle.deriveBits=async(...args)=>{
    if(args[0].name==='X25519') { derived++; return new ArrayBuffer(32); }
    return derive(...args);
   };
   let zeroRejected=false;
   try { await setupSender(lowOrder,info); }
   catch(e) { zeroRejected=e.message==='invalid HPKE shared secret'; }
   finally { crypto.subtle.deriveBits=derive; crypto.subtle.importKey=importKey; }
   if(kdfWork!==0) return {ok:false,reason:'zero-DH reached KDF before rejection'};
   if(!zeroRejected || derived!==1) return {ok:false,reason:'zero-DH sender guard missing'};
   const limited=await (await import('/hpke-limit.js')).setupSender(recipient,info);
   try { await limited.seal(plaintext); }
   catch { return {ok:false,reason:'last legal browser seal rejected'}; }
   for(let retry=0;retry<2;retry++) {
    let exhausted=false;try { await limited.seal(plaintext); } catch(e) { exhausted=e.message==='HPKE message limit reached'; }
    if(!exhausted) return {ok:false,reason:'browser message limit ignored'};
   }
   // Supply deterministic keys only in the harness. Production has no
   // parameter or export that can inject private key material.
   crypto.subtle.generateKey=async(...args)=>{
    if(args[0]!=='X25519' || args[1]!==false) throw new Error('extractable ephemeral key');
    const raw=fromHex(v.skEm);
    const prefix=new Uint8Array([48,46,2,1,0,48,5,6,3,43,101,110,4,34,4,32]);
    const encoded=new Uint8Array(prefix.length+raw.length);
    encoded.set(prefix); encoded.set(raw,prefix.length);
    try {
     const probe=await crypto.subtle.importKey('pkcs8',encoded,'X25519',true,['deriveBits']);
     const jwk=await crypto.subtle.exportKey('jwk',probe);
     const publicBytes=Uint8Array.from(atob(jwk.x.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
     return {
      privateKey:await crypto.subtle.importKey('pkcs8',encoded,'X25519',false,['deriveBits']),
      publicKey:await crypto.subtle.importKey('raw',publicBytes,'X25519',true,[])
     };
    } finally { raw.fill(0); encoded.fill(0); }
   };
   let sender;
   try { sender=await setupSender(recipient,info); }
   finally { crypto.subtle.generateKey=original; }
   if(toHex(sender.enc)!==v.enc) return {ok:false,reason:'encapsulation mismatch'};
   for(const e of v.encryptions) {
    const ct=await sender.seal(fromHex(e.pt),fromHex(e.aad));
    if(toHex(ct)!==e.ct) return {ok:false,reason:'ciphertext mismatch'};
   }
   return {ok:true,count:v.encryptions.length};
  } catch(e) { return {ok:false,reason:e.message==='extractable ephemeral key'?e.message:'sender rejected RFC vector'}; }
 })()`});
 await assertQuiet();
 const status=result.result?.value;
 assert(status?.ok,status?.reason||'browser vector test failed');
 console.log('PASS RFC 9180 sequence boundary: Seal(2^96-2) succeeds, Seal(2^96-1) rejects');
 console.log('PASS browser guards: ephemeral freshness, production API, non-extractable keys, request ID, recipient size, sequence limit');
 console.log('PASS browser side effects: only approved GET assets, no console, storage, hash, title, log or exception effects; zero-DH rejected before KDF');
 console.log(`PASS RFC 9180 base X25519/HKDF-SHA256/AES-256-GCM: ${status.count} messages in Chromium`);
 }
} catch (error) { primary = error; throw error;
} finally {
 try { socket?.close(); } catch {}
 // The browser step runs its own TERM/KILL waits; the shared 2 s deadline cut
 // them short on a loaded runner and failed a run whose checks had all passed.
 await boundedCleanup([cleanupStep(browserMonitor), () => new Promise(resolve => server.close(resolve)), () => cleanup()], {primary});
}
});
