import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {monitorChromium} from './lib/chromium-startup.mjs';
// DevTools stand-in listing one page target, so a complete port file is ready.
const devtools = createServer((req, res) => { res.setHeader('Content-Type', 'application/json'); res.end('[{"type":"page"}]'); });
await new Promise(resolve => devtools.listen(0, '127.0.0.1', resolve));
const PORT = devtools.address().port;
const secret = 'PRIVATE_SENTINEL_https://private.invalid/path?token=PRIVATE_SENTINEL';
async function check(name, script, setup, verify) {
  const profile = await mkdtemp(join(tmpdir(), 'startup-diagnostic-'));
  await setup?.(profile);
  const child = spawn(process.execPath, ['-e', script], {stdio: ['ignore','ignore','pipe']});
  const monitor = monitorChromium(child), lines = [], old = console.error;
  if (name === 'stream-error') child.stderr.destroy(new Error('PRIVATE_SENTINEL')); 
  console.error = line => lines.push(JSON.parse(line));
  try { const port = await monitor.port(profile); await verify(port, lines, child); }
  finally { console.error = old; await monitor.cleanup(); await rm(profile, {recursive:true,force:true}); }
  assert(!JSON.stringify(lines).includes(secret));
  assert(!JSON.stringify(lines).includes('private.invalid'));
  console.log(`PASS ${name}`);
}
await check('fragmented-private-stderr', `process.stderr.write(${JSON.stringify(secret)});process.stderr.write('No usable ');setTimeout(()=>{process.stderr.write('sandbox');setTimeout(()=>process.exit(7),40)},40)`, null, (p,l)=>{assert.equal(p,null);assert.deepEqual(l[0].stderr_signatures,['sandbox-refused']);assert.equal(l[0].exit_code,7)});
await check('hard-prefix-bound', "process.stderr.write('x'.repeat(9000)+'No usable sandbox');setTimeout(()=>process.exit(8),100)", null,(p,l)=>{assert.equal(p,null);assert.equal(l[0].stderr_truncated,true);assert.deepEqual(l[0].stderr_signatures,[])});
await check('read-error-class', 'setTimeout(()=>process.exit(9),200)', p=>mkdir(join(p,'DevToolsActivePort')), (p,l)=>{assert.equal(p,null);assert.equal(l[0].readiness_read_error,'EISDIR')});
await check('success-reports-elapsed-only', `process.stderr.write(${JSON.stringify(secret)});setInterval(()=>{},1000)`, p=>writeFile(join(p,'DevToolsActivePort'),`${PORT}\n`), (p,l)=>{assert.equal(p,PORT);assert.equal(l.length,1);assert.deepEqual(Object.keys(l[0]).sort(),['budget_seconds','elapsed_seconds','event','phase']);assert.equal(l[0].event,'chromium-startup-ready')});
await check('missing-readiness-live', 'setInterval(()=>{},1000)', null,(p,l)=>{assert.equal(p,null);assert.equal(l[0].child_alive_observed,true);assert.equal(l[0].readiness_read_error,'ENOENT')});
await check('stream-error', 'setTimeout(()=>process.exit(10),200)', null, (p,l)=>{assert.equal(p,null);assert.equal(l[0].exit_code,10);assert.equal(l[0].stderr_read_error,'stream-error')});
devtools.close();
