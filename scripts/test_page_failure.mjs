import assert from 'node:assert/strict';
import {emitPageFailure, emitFixedAssertion, pageCleanup, isRedirectTarget, postDestinationViolation, REDIRECT_TARGET_PATH} from './lib/page-failure.mjs';
const rows = [], emit = row => rows.push(row);
for (const [stage,error] of [['page',Object.assign(new Error('PRIVATE_SENTINEL'),{code:'CDP_COMMAND_FAILED'})], ['discovery',new SyntaxError('PRIVATE_SENTINEL')], ['setup',Object.assign(new Error('PRIVATE_SENTINEL'),{code:'ENOENT'})]]) emitPageFailure(stage,error,emit);
assert.equal(rows[0].code,'CDP_COMMAND_FAILED');
assert.equal(rows[1].error_class,'SyntaxError');
assert.equal(rows[2].code,'ENOENT');
const primary = new TypeError('PRIVATE_SENTINEL'), cleanup = new Error('PRIVATE_SENTINEL');
let caught;
try { try { throw primary; } finally { await pageCleanup(primary,async()=>{throw cleanup;},emit); } } catch(error) { caught = error; }
assert.equal(caught,primary);
assert.equal(rows.at(-1).stage,'cleanup');
await assert.rejects(pageCleanup(null,async()=>{throw cleanup;},emit),error=>error===cleanup);
emitPageFailure('PRIVATE_SENTINEL',{name:'PRIVATE_SENTINEL',code:'PRIVATE_SENTINEL',stack:'PRIVATE_SENTINEL'},emit);
assert.deepEqual(rows.at(-1),{event:'page-browser-failed',stage:'other',error_class:'other',code:'other'});
assert(!JSON.stringify(rows).includes('PRIVATE_SENTINEL'));
let successful = false;
await pageCleanup(null,async()=>{successful=true;},emit);
assert(successful);
console.log('PASS fixed failure classification, primary preservation, cleanup and privacy');

const lines=[];
emitFixedAssertion({name:'AssertionError',message:'page browser: navigation timeout (PRIVATE_SENTINEL)',actual:'PRIVATE_SENTINEL'},line=>lines.push(line));
assert.deepEqual(lines,['AssertionError [ERR_ASSERTION]: page browser: navigation timeout']);
emitFixedAssertion({name:'AssertionError',message:'PRIVATE_SENTINEL'},line=>lines.push(line));
assert.equal(lines.length,1);
assert(!JSON.stringify(lines).includes('PRIVATE_SENTINEL'));
const count=rows.length;
await assert.rejects(pageCleanup(null,async()=>{throw cleanup;},emit));
assert.equal(rows.length,count);

// Keep exact existing mutation witnesses; arbitrary suffixes stay private.
for (const reason of [
  'page browser: expected UI state was not reached (duplicate-pin)',
  'page browser: expected UI state was not reached (extra-name)',
  'page browser: expected UI state was not reached (hidden-field-SecretName)',
  'page browser: expected UI state was not reached (nested-name)',
  'page browser: expected UI state was not reached (noncanonical-public)',
  'page browser: expected UI state was not reached (raw-card-text)',
  'page browser: expected UI state was not reached (raw-row-text)',
  'page browser: expected UI state was not reached (secret-name)',
  'page browser: expected UI state was not reached (signed-request)',
  'page browser: expected UI state was not reached (signer)',
  'page browser: expected UI state was not reached (unknown-fragment)',
  'page browser: textarea privacy attribute autocomplete',
  'page browser: textarea privacy attribute autocapitalize',
  'page browser: textarea privacy attribute autocorrect',
  'page browser: textarea privacy attribute spellcheck',
]) {
  const witness=[];
  emitFixedAssertion({name:'AssertionError',message:reason+'; PRIVATE_SENTINEL'},line=>witness.push(line));
  assert.deepEqual(witness,['AssertionError [ERR_ASSERTION]: '+reason]);
  assert(!JSON.stringify(witness).includes('PRIVATE_SENTINEL'));
}
const unknown=[];
emitFixedAssertion({name:'AssertionError',message:'page browser: expected UI state was not reached (PRIVATE_SENTINEL)'},line=>unknown.push(line));
assert.deepEqual(unknown,['AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached']);
assert(!JSON.stringify(unknown).includes('PRIVATE_SENTINEL'));

for (const message of [
  'page browser: textarea privacy attribute PRIVATE_SENTINEL',
  'page browser: expected UI state was not reached (secret-name-PRIVATE_SENTINEL)'
]) {
  const rows=[];
  emitFixedAssertion({name:'AssertionError',message}, row=>rows.push(row));
  assert.equal(rows.length,1);
  assert(!JSON.stringify(rows).includes('PRIVATE_SENTINEL'));
  assert(!rows[0].includes('(secret-name)'));
}

console.log('PASS exact mutation witnesses and unknown/private suffix rejection');

// A followed redirect is seen by two CDP domains, in either order. Whichever
// records first, the single reason forwarded to the mutation witness must be
// "redirect followed"; it was "wrong ciphertext destination" whenever the
// Network hop was recorded before the paused Fetch request.
{
  const origin = 'http://127.0.0.1:4000', submit = origin + '/input/token';
  const hop = origin + REDIRECT_TARGET_PATH;
  assert.equal(postDestinationViolation(submit, submit, origin), null);
  assert.equal(postDestinationViolation(hop, submit, origin), 'page browser: redirect followed');
  assert(isRedirectTarget(hop, origin));
  // Other destinations stay a wrong destination: same host other path, other origin, junk.
  for (const other of [origin + '/input/other', 'http://127.0.0.1:4001' + REDIRECT_TARGET_PATH, 'http://evil.invalid/x', 'not a url', origin + '/input/token/']) {
    assert.equal(postDestinationViolation(other, submit, origin), 'page browser: wrong ciphertext destination', other);
  }
  const forwarded = order => {
    const violations = new Set(), lines = [];
    for (const source of order) {
      // Network observer reports the POST hop; Fetch observer reports the paused request.
      violations.add(source === 'network' ? postDestinationViolation(hop, submit, origin) : 'page browser: redirect followed');
    }
    emitFixedAssertion({name: 'AssertionError', message: [...violations].join('; ')}, line => lines.push(line));
    return lines;
  };
  const expected = ['AssertionError [ERR_ASSERTION]: page browser: redirect followed'];
  assert.deepEqual(forwarded(['network', 'fetch']), expected);
  assert.deepEqual(forwarded(['fetch', 'network']), expected);
  // Negative control: the previous classification reproduces the flake.
  const old = ['page browser: wrong ciphertext destination', 'page browser: redirect followed'];
  const stale = [];
  emitFixedAssertion({name: 'AssertionError', message: old.join('; ')}, line => stale.push(line));
  assert.deepEqual(stale, ['AssertionError [ERR_ASSERTION]: page browser: wrong ciphertext destination']);
  console.log('PASS followed redirect is named the same in either event order');
}
