The JSON fixture is the published RFC 9180 base-mode vector for
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM, including all
257 sequential encryption examples. Its keys and messages are public test
material, not credentials.

Source: https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json
Specification: https://www.rfc-editor.org/rfc/rfc9180

The complete fixture object matches mode=0, kem_id=32, kdf_id=1, aead_id=2
in that immutable source. The harness checks the entire local file's SHA-256:
`29a4dc2c6be901468cf715cadfa7dd3d92b2f060b3c794ecb611fc37dbbfc2d0`.
The source file's SHA-256 is
`61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`.

Run `node scripts/check-intake-browser.mjs` with Node 22 or newer and
Chromium (`CHROME_BIN` can select its executable). The harness uses CDP
and Node built-ins; it needs no npm modules. It compares every ciphertext
inside a headless browser and prints only a pass/fail result.

The harness also checks fresh encapsulations/ciphertexts, non-extractable
private keys, production input validation and the sequence limit. It supplies
the deterministic RFC key by intercepting WebCrypto in the test page only;
`setupSender` accepts only the recipient key and HPKE info.
