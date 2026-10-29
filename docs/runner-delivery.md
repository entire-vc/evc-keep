# Runner job delivery

The public result retains the runner's closed error class. Audit projects it
onto its existing closed taxonomy: target-write and health failures become
`target_error`; provider and unavailable-value failures become `provider_error`;
policy and rate-limit failures become `policy_denied`; identity, signature and
replay failures become `permission_denied`; expired or invalid jobs become
`invalid_argument`; other validated failures become `internal`. Env-file format
rejections produce the same class regardless of the rejected input's shape.

The following routes require the current runner mTLS certificate. Organization
and runner IDs come from that certificate, never from JSON. Registration binds
the X25519 recipient public key; requests cannot replace it.

| Route | Request | Success |
| --- | --- | --- |
| `GET /runners/jobs/next` | No body | `SignedJob`, or 204 after a 25-second long poll |
| `POST /runners/jobs/value` | `{"job_id":"<UUIDv7>"}` only | `ValueEnvelope` |
| `POST /runners/jobs/{job_id}/result` | Closed `runnerproto.Result` | 204 |

Unknown or duplicate JSON fields, alternate key spelling, trailing input and
free-form result errors are rejected. Responses from job handlers after
successful mTLS authentication use `Cache-Control: no-store`. This guarantee
does not cover responses from the mTLS middleware before job handling.
For material requests, missing, foreign, expired, replayed and terminal jobs
have the same 404 refusal. Result acknowledgements follow the retry rules below.
Certificate renewal and revocation are rechecked for every operation, including
each attempt inside a long poll. Polling holds no transaction while waiting.

A queued job contains an immutable canonical payload, nonce, expiry, catalog
version, provider reference and owner scope. Claiming it changes `queued` to
`issued`; signing uses the organization's sealed Ed25519 key inside the plaintext
zone. A failed signature leaves the job unclaimed. A lost successful response
requires a new deployment request when the old job expires.

Material issuance is one atomic, job-bound database transition. Exactly one
caller can receive the value and fingerprint-key envelopes. The claim commits
before opening material, so a lost response or subsequent backend error cannot
be retried with the same job. A fresh authorized deployment is required.

`ValueEnvelope` contains `job_id`, `sealed`, and `sealed_fingerprint_key`.
Each envelope is the 32-byte HPKE encapsulated key followed by ciphertext.
The suite is X25519/HKDF-SHA256/ChaCha20-Poly1305. Value encryption uses
`runnerproto.Info(job)`. Fingerprint-key encryption uses the bytes
`keep/fingerprint-key/v1\0` followed by the complete `Info(job)`; its plaintext
is exactly 32 key bytes. The key ID is bound by the job's expected fingerprint.
The envelopes cannot be substituted for one another. A runner must reject a
missing key envelope, verify the value's HMAC before writing, and wipe both
plaintext buffers after the job. There is no legacy envelope fallback.

The wired material issuer supports builtin stores. It rechecks the saved
catalog version, provider reference, store owner scope and active status before
resolving the exact version. Catalog rows remain locked through encryption so delivery cannot race
past an in-flight catalog revocation. All crypto lookups use the same held
connection; raw provider errors never leave the zone. The enabled path is builtin-only.
Admission records an `unsupported_provider` refusal when policy would otherwise
allow delivery from an unsupported store. Its deny and approval decisions retain
their existing precedence.

Migration `00017_deployment_result.sql` follows the admission queue in `00016`.
Downgrading to `00016` preserves existing result audit history while rejecting
new `deploy.result` records; upgrading enables that action again. Neither
transition changes the prerequisite queue, trust or catalog schema.

Terminal results commit with `deploy.result` in the audit journal, using the
original request ID. They cannot be overwritten. An exact repeat receives 204
without another audit record, including after the execution lease expires. A
late first result is accepted only for an issued job and the current live owner
certificate. Expiry still prevents polling or material issuance. A differing
terminal result or job-level ownership/state refusal receives 404.
Certificate rejection by the mTLS middleware (invalid, revoked or expired
credentials) receives 401 before job handling. This lets a runner retry a
durable metadata-only outbox after losing an acknowledgement; it must never
fetch material or execute the target again.
Successful results require
material issuance and the exact frozen fingerprint and version. Supplied
fingerprint/version fields on failures must also match the job. The audit record
contains identifiers and closed status classes, not target content or process
output.

## Runner side: `keep-runner run`

`keep-runner run -policy <file> -server <https url>` polls the three routes
above with the enrolled certificate (`-server-ca` pins the listener CA,
`-state-dir` holds the replay journal and the result outbox, `-once` runs at
most one job and fails if its Result could not be sent, leaving it in the
outbox). Per job, in this order:

1. Verify the organization signature, the runner's own identity (from its
   certificate), the time window and the replay journal. A bad signature or a
   replay is only logged; an identity or window failure is reported.
2. The job is recorded as `started` in the outbox immediately before the replay
   journal claims it, so a crash at any later point is reported on restart. A
   refused claim removes that entry again.
3. Check the job against the host policy and take a rate-limit slot. Only a
   `deploy` job is run. Nothing has been requested from the server yet. Then
   request the value once. A failed request is reported as
   `value_unavailable` and never repeated.
4. Open both HPKE envelopes with the delivery key, compute the value's
   fingerprint with the delivered key and compare it with the job's before
   `targets.Write`; wipe both plaintext buffers afterwards.
5. `deploy.Apply`, then close the Result in the outbox (`closed`) and send it.
   `204` or a `404` refusal removes the entry; any other failure keeps it and
   only the sending is retried, with backoff. The target is not written again.

If a job's outcome cannot be written to the outbox, `run` stops with an error
instead of polling on, and `-once` exits non-zero.

After a restart the outbox is sent before the first poll. A job left `started`
is reported as `internal` (what happened to its target is unknown) and is not
run again. The rate limiter is in memory and starts empty after a restart.
Rollback of a target is not part of the loop.

### Path prefixes must be real directories

The target writer opens every component of a target path with `O_NOFOLLOW`,
so a host policy prefix that passes through a symlink admits a job that is
then denied on every write. `keep-runner check` walks each `path_prefixes`
entry from `/` and fails, naming the rule, the prefix and the component, when
a component is a symlink or not a directory. A component that does not exist
yet is accepted; the writer still refuses a symlink created there later.
`keep-runner run` logs a warning with error class `policy_prefix_not_plain`
for such a policy and starts anyway, so the other rules keep working.

On macOS `/var`, `/tmp` and `/etc` are symlinks into `/private`. Write
prefixes by their real path, for example `/private/var/lib/app/ext` instead of
`/var/lib/app/ext`.
