// Actual entrypoints with disposable Node children, never native Chromium/DB.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {chmod, mkdtemp, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';

for (const [name, script, setupError] of [
  ['standalone','check-intake-browser.mjs',false],
  ['page','check-intake-page.mjs',false],
  ['page-setup','check-intake-page.mjs',true]
]) {
  const dir=await mkdtemp(join(tmpdir(),'keep-profile-entrypoint-'));
  const browser=join(dir,'browser'), receipt=join(dir,'receipt');let child;
  try {
    await writeFile(browser, `#!/usr/bin/env node
const fs=require('node:fs');
const profile=process.argv.find(arg=>arg.startsWith('--user-data-dir=')).slice('--user-data-dir='.length);
fs.appendFileSync(${JSON.stringify(receipt)},JSON.stringify({mode:fs.statSync(profile).mode&511,prefix:require('node:path').basename(profile).split('-').slice(0,-1).join('-'),flags:process.argv.slice(2).filter(arg=>!arg.startsWith('--user-data-dir='))})+'\\n',{mode:384});
process.stderr.write('PRIVATE_DISPOSABLE_BROWSER_STDERR');process.exit(7);
`);await chmod(browser,0o700);
    const checker=fileURLToPath(new URL('./'+script,import.meta.url));
    child=spawn(process.execPath,[checker],{env:{...process.env,CHROME_BIN:browser,TMPDIR:dir,KEEP_CHROMIUM_PROFILE_ROOT:''},stdio:['pipe','pipe','pipe']});
    let output='',errors='';child.stdout.on('data',data=>{output+=data;});child.stderr.on('data',data=>{errors+=data;});
    child.stdin.end(script==='check-intake-page.mjs' ? JSON.stringify({plaintext:'disposable-profile-control',url:setupError?'invalid':'http://127.0.0.1/'}) : undefined);
    let timer;
    const code=await Promise.race([
      new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);}),
      new Promise((_,reject)=>{timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('profile entrypoint control deadline'));},5000);})
    ]).finally(()=>clearTimeout(timer));
    assert.notEqual(code,0);assert.equal(output,'');assert(!errors.includes('PRIVATE_DISPOSABLE_BROWSER_STDERR'));
    const expectedPrefix=script==='check-intake-page.mjs'?'keep-input-page-':'keep-intake-browser-';
    assert(!(await readdir(dir)).some(value=>value.startsWith(expectedPrefix)),'owned entrypoint profile removed');
    if (setupError) {
      await assert.rejects(readFile(receipt),error=>error.code==='ENOENT');
    } else {
      const rows=(await readFile(receipt,'utf8')).trim().split('\n').map(JSON.parse);
      assert.equal(rows.length,1,'sole browser spawn, no retry');assert.equal(rows[0].mode,0o700);
      assert.deepEqual(rows[0].flags,['--headless=new','--no-sandbox','--disable-gpu','--disable-background-networking','--disable-component-update','--no-first-run','--no-default-browser-check','--remote-debugging-port=0','about:blank']);
      const events=errors.split('\n').filter(line=>line.startsWith('{')).map(JSON.parse);
      const startup=events.find(value=>value.event==='chromium-startup-failed');
      assert.equal(startup.exit_code,7);assert.equal(startup.profile_allocation.placement,'fallback');
      assert.equal(startup.profile_allocation.reason,'not-configured');
      assert(!JSON.stringify(startup.profile_allocation).includes(dir));
    }
    console.log(JSON.stringify({control:'profile-entrypoint-'+name,passed:true,native_chromium_executed:false}));
  } finally {
    if(child && child.exitCode===null)child.kill('SIGKILL');await rm(dir,{recursive:true,force:true});
  }
}
