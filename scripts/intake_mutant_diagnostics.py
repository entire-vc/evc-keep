"""Fixed diagnostics for rejected page mutants; never print raw child output."""
import json
from pathlib import Path
import re
import sys
import time

TESTS = frozenset(('TestIntakePageBrowserLifecycle', 'TestInputPage',
                   'TestRenderMetadataPreservesCRAndEscapesMarkup'))


# Only fixed harness assertions become public IDs; never forward their payload.
ASSERTION_MARKERS = (
    ('cdp-command-failed', 'page browser: CDP command failed'),
    ('css-import-side-effect', 'page browser: CSS import side effect'),
    ('cache-storage-side-effect', 'page browser: Cache Storage side effect'),
    ('chromium-did-not-start', 'page browser: Chromium did not start'),
    ('chromium-is-required', 'page browser: Chromium is required'),
    ('indexeddb-side-effect', 'page browser: IndexedDB side effect'),
    ('opfs-side-effect', 'page browser: OPFS side effect'),
    ('browser-cookie-side-effect', 'page browser: browser cookie side effect'),
    ('browser-storage-side-effect', 'page browser: browser storage side effect'),
    ('canary-detector-control-failed', 'page browser: canary detector control failed'),
    ('console-side-effect', 'page browser: console side effect'),
    ('cookie-control-is-not-visible', 'page browser: cookie control is not visible'),
    ('cookie-control-was-not-seeded', 'page browser: cookie control was not seeded'),
    ('credential-or-referrer-sent', 'page browser: credential or referrer sent'),
    ('encryption-before-descriptor-verification', 'page browser: encryption before descriptor verification'),
    ('evaluation-failed', 'page browser: evaluation failed'),
    ('expected-ui-state-was-not-reached', 'page browser: expected UI state was not reached'),
    ('expected-redirect-probe-and-one-ciphertext-submission', 'page browser: expected redirect probe and one ciphertext submission'),
    ('external-script-csp-event-missing', 'page browser: external script CSP event missing'),
    ('external-script-control-did-not-execute', 'page browser: external script control did not execute'),
    ('external-script-was-not-blocked-by-csp', 'page browser: external script was not blocked by CSP'),
    ('horizontal-overflow', 'page browser: horizontal overflow'),
    ('input-in-url-title-or-dom', 'page browser: input in URL, title or DOM'),
    ('input-in-browser-log', 'page browser: input in browser log'),
    ('input-in-request', 'page browser: input in request'),
    ('interception-failed', 'page browser: interception failed'),
    ('invalid-completion-metadata', 'page browser: invalid completion metadata'),
    ('navigation-timeout', 'page browser: navigation timeout'),
    ('non-envelope-request', 'page browser: non-envelope request'),
    ('plaintext-field-not-cleared-after-submission', 'page browser: plaintext field not cleared after submission'),
    ('redirect-control-did-not-run', 'page browser: redirect control did not run'),
    ('redirect-followed', 'page browser: redirect followed'),
    ('requester-metadata-missing', 'page browser: requester metadata missing'),
    ('script-integrity-violation', 'page browser: script integrity violation'),
    ('tampered-descriptor-accepted', 'page browser: tampered descriptor accepted'),
    ('tampered-descriptor-was-sent', 'page browser: tampered descriptor was sent'),
    ('textarea-privacy-attribute-autocapitalize', 'page browser: textarea privacy attribute autocapitalize'),
    ('textarea-privacy-attribute-autocomplete', 'page browser: textarea privacy attribute autocomplete'),
    ('textarea-privacy-attribute-autocorrect', 'page browser: textarea privacy attribute autocorrect'),
    ('textarea-privacy-attribute-spellcheck', 'page browser: textarea privacy attribute spellcheck'),
    ('unexpected-csp-diagnostic', 'page browser: unexpected CSP diagnostic'),
    ('unexpected-browser-log', 'page browser: unexpected browser log'),
    ('unexpected-diagnostic-output', 'page browser: unexpected diagnostic output'),
    ('unexpected-input-field', 'page browser: unexpected input field'),
    ('unexpected-network-side-effect', 'page browser: unexpected network side effect'),
    ('unhandled-exception', 'page browser: unhandled exception'),
    ('valid-descriptor-did-not-verify', 'page browser: valid descriptor did not verify'),
    ('window-name-side-effect', 'page browser: window.name side effect'),
    ('wrong-ciphertext-destination', 'page browser: wrong ciphertext destination'),
)

def assertion_marker_ids(output):
    # Go forwards the fixed assertion line; raw JS stack/source is excluded.
    payloads = re.findall(
        r'^\s*(?:[A-Za-z0-9_./-]+\.go:\d+: )?'
        r'AssertionError \[ERR_ASSERTION\]: ([^\r\n]*)$', output, re.M)
    found = sorted({marker_id for marker_id, marker in ASSERTION_MARKERS
                    if any(re.search(r'(?:^|; )' + re.escape(marker) +
                                     r'(?=$|; | \()', payload)
                           for payload in payloads)})
    return found or ['unknown']


def report(output, code, elapsed):
    if 'panic: test timed out' in output:
        reason = 'testtimeout'
    elif any(x in output for x in ('database operation deadline exceeded',
                                   'context deadline exceeded',
                                   'page browser: navigation timeout')):
        reason = 'deadline'
    elif any(x in output for x in ('page browser: Chromium did not start',
                                   'page browser: Chromium is required')):
        reason = 'browserlaunch'
    elif code == 0:
        reason = 'expectedwitnessmissing'
    elif re.search(r'^\s*--- FAIL: ', output, re.M):
        reason = 'testfailure'
    else:
        reason = 'unknown'
    ids = sorted(set(re.findall(r'^\s*(?:--- FAIL:|=== RUN) +(Test[A-Za-z0-9_]+)(?:\s|$)', output, re.M)) & TESTS)
    print(json.dumps({'event': 'rejected-page-mutant', 'classification': reason,
                      'exit_code': code, 'seconds': round(max(0, elapsed), 3),
                      'test_ids': ids, 'assertion_marker_ids': assertion_marker_ids(output)}, sort_keys=True), flush=True)


# Fixed IDs from the HPKE browser harness, never its assertion values or stack.
HPKE_MARKERS = (
    ('chromium-did-not-start', 'Chromium did not start'),
    ('chromium-is-required', 'headless Chromium is required; set CHROME_BIN'),
    ('fixture-hash-mismatch', 'RFC fixture hash mismatch'),
    ('ciphertext-mismatch', 'ciphertext mismatch'),
    ('encapsulation-mismatch', 'encapsulation mismatch'),
    ('sender-rejected-vector', 'sender rejected RFC vector'),
    ('ephemeral-freshness-failed', 'ephemeral freshness failed'),
    ('production-ephemeral-override-accepted', 'production ephemeral override accepted'),
    ('extractable-ephemeral-key', 'extractable ephemeral key'),
    ('invalid-browser-request-accepted', 'invalid browser request accepted'),
    ('invalid-browser-recipient-accepted', 'invalid browser recipient accepted'),
    ('native-low-order-recipient-accepted', 'native low-order recipient accepted'),
    ('kdf-order-observer-blind', 'KDF order observer is blind'),
    ('zero-dh-before-kdf-missing', 'zero-DH reached KDF before rejection'),
    ('zero-dh-sender-guard-missing', 'zero-DH sender guard missing'),
    ('last-legal-browser-seal-rejected', 'last legal browser seal rejected'),
    ('browser-message-limit-ignored', 'browser message limit ignored'),
    ('browser-vector-test-failed', 'browser vector test failed'),
    ('browser-cross-encryption-failed', 'browser cross-encryption failed'),
    ('location-hash-side-effect', 'browser location hash side effect'),
    ('document-title-side-effect', 'browser document title side effect'),
    ('log-side-effect', 'browser log side effect'),
    ('exception-side-effect', 'browser exception side effect'),
    ('local-storage-side-effect', 'browser localStorage side effect'),
    ('session-storage-side-effect', 'browser sessionStorage side effect'),
    ('indexeddb-side-effect', 'browser IndexedDB side effect'),
    ('network-side-effect', 'browser network side effect'),
    ('console-side-effect', 'browser console side effect'),
    ('interception-misuse', 'browser interception misuse'),
    ('interception-failed', 'browser interception failed'),
)


def hpke_report(output, code):
    payloads = re.findall(r'^AssertionError \[ERR_ASSERTION\]: ([^\r\n]*)$', output, re.M)
    markers = sorted({key for key, marker in HPKE_MARKERS
                      if any(re.search(r'(?:^|; )' + re.escape(marker) +
                                       r'(?=$|; | \()', value) for value in payloads)})
    error_types = sorted(set(re.findall(
        r'^(AssertionError \[ERR_ASSERTION\]|Error|TypeError|ReferenceError|SyntaxError|RangeError):',
        output, re.M)))
    error_types = ['AssertionError' if value.startswith('AssertionError') else value
                   for value in error_types]
    startup = []
    for line in output.splitlines():
        if not line.startswith('{') or len(line) > 4096:
            continue
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(value, dict) or value.get('event') != 'chromium-startup-failed':
            continue
        # Treat even diagnostic JSON as untrusted; project only bounded fields.
        entry = {}
        for key, allowed in (
            ('readiness', ('missing', 'empty', 'invalid')),
            ('spawn_error', (None, 'ENOENT', 'EACCES', 'ENOMEM', 'other')),
            ('signal', (None, 'SIGABRT', 'SIGBUS', 'SIGILL', 'SIGKILL', 'SIGSEGV', 'SIGTERM', 'SIGTRAP', 'other')),
            ('readiness_read_error', (None, 'ENOENT', 'EACCES', 'EIO', 'ENOTDIR', 'EISDIR', 'other')),
        ):
            if value.get(key) in allowed:
                entry[key] = value.get(key)
        exit_code = value.get('exit_code')
        if exit_code is None or type(exit_code) is int and 0 <= exit_code <= 255:
            entry['exit_code'] = exit_code
        signatures = value.get('stderr_signatures')
        if isinstance(signatures, list):
            entry['stderr_signatures'] = sorted({item for item in signatures if isinstance(item, str) and item in (
                'sandbox-refused', 'profile-in-use', 'shared-memory-failed', 'disk-full',
                'permission-denied', 'crashpad-required')})
        startup.append(entry)
        break
    if startup or set(markers) & {'chromium-did-not-start', 'chromium-is-required'}:
        reason = 'browserlaunch'
    elif re.search(r'^Error: CDP command failed$', output, re.M):
        reason = 'cdp-command-failed'
    elif code == 0:
        reason = 'expectedwitnessmissing'
    elif 'AssertionError' in error_types:
        reason = 'assertion-failure'
    elif error_types:
        reason = 'runtime-error'
    else:
        reason = 'unknown'
    print(json.dumps({'event': 'rejected-hpke-mutant', 'classification': reason,
                      'exit_code': code, 'error_types': error_types,
                      'assertion_marker_ids': markers or ['unknown'],
                      'startup': startup}, sort_keys=True), flush=True)


if __name__ == '__main__':
    if sys.argv[1] == '--hpke':
        with Path(sys.argv[2]).open(errors='replace') as stream:
            hpke_report(stream.read(1024 * 1024), int(sys.argv[3]))
    else:
        report(Path(sys.argv[1]).read_text(errors='replace'), int(sys.argv[2]),
               time.monotonic() - float(sys.argv[3]))
