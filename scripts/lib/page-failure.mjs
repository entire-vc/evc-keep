// Fixed diagnostic vocabulary only: never serialize an exception or its message.
const stages = new Set(['setup', 'readiness', 'discovery', 'socket', 'page', 'cleanup']);
const classes = new Set(['Error', 'TypeError', 'SyntaxError', 'AssertionError']);
const codes = new Set(['ERR_ASSERTION', 'ECONNREFUSED', 'ECONNRESET', 'ENOENT', 'EACCES', 'CDP_COMMAND_FAILED', 'CLEANUP_SOCKET', 'CLEANUP_BROWSER', 'CLEANUP_SERVER', 'CLEANUP_PROFILE']);
export function emitPageFailure(stage, error, emit = row => process.stderr.write(JSON.stringify(row) + '\n')) {
  emit({event:'page-browser-failed', stage:stages.has(stage) ? stage : 'other',
    error_class:classes.has(error?.name) ? error.name : 'other',
    code:codes.has(error?.code) ? error.code : 'other'});
}
export async function pageCleanup(primary, cleanup, emit) {
  try { await cleanup(); } catch (error) {
    if (primary) emitPageFailure('cleanup', error, emit);
    if (!primary) throw error;
  }
}

// Preserve only fixed source IDs required by the behavioral mutation witnesses.
const assertionReasons = [
  "page browser: expected UI state was not reached (duplicate-pin)",
  "page browser: expected UI state was not reached (extra-name)",
  "page browser: expected UI state was not reached (hidden-field-SecretName)",
  "page browser: expected UI state was not reached (nested-name)",
  "page browser: expected UI state was not reached (noncanonical-public)",
  "page browser: expected UI state was not reached (raw-card-text)",
  "page browser: expected UI state was not reached (raw-row-text)",
  "page browser: expected UI state was not reached (secret-name)",
  "page browser: expected UI state was not reached (signed-request)",
  "page browser: expected UI state was not reached (signer)",
  "page browser: expected UI state was not reached (unknown-fragment)",
  "page browser: textarea privacy attribute autocomplete",
  "page browser: textarea privacy attribute autocapitalize",
  "page browser: textarea privacy attribute autocorrect",
  "page browser: textarea privacy attribute spellcheck",

  "page browser: expected redirect probe and one ciphertext submission",
  "page browser: plaintext field not cleared after submission",
  "page browser: encryption before descriptor verification",
  "page browser: external script control did not execute",
  "page browser: external script was not blocked by CSP",
  "page browser: expected UI state was not reached",
  "page browser: external script CSP event missing",
  "page browser: valid descriptor did not verify",
  "page browser: canary detector control failed",
  "page browser: unexpected network side effect",
  "page browser: cookie control is not visible",
  "page browser: cookie control was not seeded",
  "page browser: redirect control did not run",
  "page browser: tampered descriptor accepted",
  "page browser: tampered descriptor was sent",
  "page browser: unexpected diagnostic output",
  "page browser: wrong ciphertext destination",
  "page browser: browser storage side effect",
  "page browser: credential or referrer sent",
  "page browser: invalid completion metadata",
  "page browser: browser cookie side effect",
  "page browser: input in URL, title or DOM",
  "page browser: requester metadata missing",
  "page browser: script integrity violation",
  "page browser: textarea privacy attribute",
  "page browser: Cache Storage side effect",
  "page browser: unexpected CSP diagnostic",
  "page browser: window.name side effect",
  "page browser: CSS import side effect",
  "page browser: Chromium did not start",
  "page browser: unexpected browser log",
  "page browser: unexpected input field",
  "page browser: IndexedDB side effect",
  "page browser: Chromium is required",
  "page browser: input in browser log",
  "page browser: non-envelope request",
  "page browser: console side effect",
  "page browser: horizontal overflow",
  "page browser: interception failed",
  "page browser: unhandled exception",
  "page browser: CDP command failed",
  "page browser: navigation timeout",
  "page browser: evaluation failed",
  "page browser: redirect followed",
  "page browser: OPFS side effect",
  "page browser: input in request"
];
export function emitFixedAssertion(error, write = line => process.stderr.write(line + "\n")) {
  if (error?.name !== "AssertionError") return;
  const reason = assertionReasons.find(reason => error.message === reason || (error.message?.startsWith(reason + " (") || error.message?.startsWith(reason + " ") || error.message?.startsWith(reason + "; ")));
  if (reason) write("AssertionError [ERR_ASSERTION]: " + reason);
}

// The redirect control answers the ciphertext POST with a 307 to this path. A
// browser that follows it replays the POST at the target.
export const REDIRECT_TARGET_PATH = '/input/redirect-target';
export function isRedirectTarget(rawUrl, origin) {
  try { const url = new URL(rawUrl); return url.origin === origin && url.pathname === REDIRECT_TARGET_PATH; } catch { return false; }
}
// Name the violation for a POST that is not the one submission. A followed
// redirect is observed twice: as a new hop on the Network domain and as a
// paused request on the Fetch domain. CDP does not order events across
// domains, and the first violation recorded picks the one reason forwarded to
// the mutation witness, so both observers must name the hop the same way.
// Any other destination stays "wrong ciphertext destination".
export function postDestinationViolation(rawUrl, expectedUrl, origin) {
  if (rawUrl === expectedUrl) return null;
  return isRedirectTarget(rawUrl, origin) ? 'page browser: redirect followed' : 'page browser: wrong ciphertext destination';
}

// Fixed named steps; every owned resource is attempted even after another fails.
export async function cleanupPageResources(steps) {
  let first;
  for (const [code, cleanup, budget] of steps) {
    let timer;
    try {
      await Promise.race([Promise.resolve().then(cleanup), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('cleanup deadline')), budget);
      })]);
    } catch (cause) { first ||= Object.assign(new Error('page cleanup incomplete', {cause}), {code}); }
    finally { clearTimeout(timer); }
  }
  if (first) throw first;
}
