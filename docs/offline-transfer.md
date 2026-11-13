# Moving one organization between two installations: `keep-server offline-transfer`

This copies one organization, with its builtin-store secrets, its CA and its
audit chain, from a source installation to an empty target installation over
files you carry yourself. Neither side needs a network path to the other. The
source is only read. Nothing here prints, logs or accepts a secret value, a
key, a database URL or a path in a receipt.

Scope: exactly one organization in Mesh store mode (one Mesh installation,
no extension mode), the builtin provider only, and the same schema version on
both sides. Two source shapes are accepted, told apart by the `profile_version`
in the bundle's manifest:

| Profile | Source shape | Canonical workspace (`--workspace`) |
|---|---|---|
| 1 | one tenancy workspace (`workspaces` has one row) | that workspace's id |
| 2 | native Mesh store mode: one Mesh installation, **no** tenancy workspace and no project | the `workspace_id` of the organization's one Mesh installation |

Mesh's own installation creates no tenancy workspace, so a native store-mode
organization is profile 2. Nothing is created to make it look like profile 1:
the target gets no synthetic workspace or project, and the source is never
written (it is read in one read-only repeatable-read transaction, and
the source database, SQL seed and installation are not repaired or altered by
this tool). The tool picks the profile from what the source holds; you pass the
canonical workspace id from the table, and any other value is refused as
`reason=pin`.

A source is refused, with no effect on either side, if it has two or more
tenancy workspaces, a project without a workspace, a second or foreign installation, extension mode, a non-builtin store, any
state the profile does not carry, or a key domain or sealed-secret scope that
names a workspace or project (with no tenancy workspace in the snapshot such a
scope would dangle, so it is refused rather than guessed). On import the
manifest's profile, not the rows, decides which shape is required; a profile-2
manifest over rows with a workspace, or the reverse, is refused as
`reason=manifest`, and every refusal leaves the target unchanged.

Compatibility: profile 1 bundles are unchanged byte for byte. A `keep-server`
build that predates profile 2 knows only profile 1: it refuses a profile-2
manifest (`profile_version` is not 1) and cannot export a profile-2 source (its
inventory finds no tenancy workspace), so a profile-2 bundle can never be
half-understood. Use the same build on both sides.

## What you need

- Two installations running the same `keep-server` build, the target freshly
  migrated and empty (no organization, no audit records).
- On each side: `KEEP_DATABASE_URL`, `KEEP_ROOT_KEY_FILE` and, if it is not
  `local-v1`, `KEEP_ROOT_KEY_ID`, set in the environment of the command. The
  two roots are independent; they never meet. Neither is ever an argument.
- A directory for carriers that you own and that is not group- or
  world-writable. Carrier files are created `0600`, never overwrite an
  existing name and never follow a symlink.
- Four identities, chosen by you before you start, all canonical lowercase
  UUIDs: `transfer`, `source`, `target`, `snapshot`. The organization and
  workspace UUIDs and the schema version (`--schema`, the current migration
  version) come from the source.

## Steps

1. **Target: create the recipient key.**

   ```
   keep-server offline-transfer recipient \
     --private-file /secure/recipient.key --public-file /secure/recipient.pub
   ```

   Receipt: `outcome=created recipient_fingerprint=<sha256 of the public key>`.
   The private key stays on the target. Carry `recipient.pub` to the source
   and tell the source operator the fingerprint by a second channel.

2. **Source: freeze writes to the organization**, by whatever means your
   installation has (stop the server, or cut the API at the proxy). The tool
   cannot freeze for you; `finalize` below proves the freeze held.

3. **Source: export.**

   ```
   keep-server offline-transfer export \
     --org <org> --workspace <ws> --transfer <t> --source <s> --target <g> \
     --snapshot <n> --schema <version> \
     --recipient-public-file /secure/recipient.pub \
     --expect-recipient-fingerprint <fingerprint from the target operator> \
     --bundle /secure/transfer.sealed --checkpoint /secure/checkpoint.json
   ```

   It reads one repeatable-read snapshot, verifies that it is one closed
   organization, and seals it to the recipient. Receipt fields: `rows`,
   `closure_digest`, `audit_head`, `ciphertext_checksum`.

4. **Source, still frozen: finalize.**

   ```
   keep-server offline-transfer finalize \
     --org <org> --checkpoint /secure/checkpoint.json --approval /secure/approval.json \
     --quiescence-confirmed true
   ```

   It re-reads the source and writes `approval.json` only if every copied row
   is exactly what was exported. Otherwise it refuses with
   `reason=source_changed`; repeat from step 2 with a new snapshot id. Keep the
   receipt: its `ciphertext_checksum` and its `approval_checksum` (the SHA-256
   of the exact `approval.json` bytes, issued only after the source compare
   passed and the file was written) are the two pins for step 5. Carry
   `approval.json` to the target together with the bundle, and send both
   pins over the same independently authenticated channel as the recipient
   fingerprint, never inside a carrier: step 5 refuses to start without them.
   The pin does not replace the freeze, which holds until the cutover is
   complete or aborted.

5. **Target: import.** Carry `transfer.sealed` across (all paths are absolute; the carrier directory is yours and private). Read the checksum from
   the source operator's receipt, never from the bundle. Carry the checksum, the `approval_checksum` and
   the recipient fingerprint over a channel that is separate from, and
   authenticated independently of, the bundle: HPKE does not authenticate the
   sender, so whoever can replace both the bundle and its checksum can plant
   an organisation.

   ```
   keep-server offline-transfer import \
     --bundle /secure/transfer.sealed --private-file /secure/recipient.key \
     --public-file /secure/recipient.pub --approval /secure/approval.json \
     --transfer <t> --source <s> --target <g> --snapshot <n> \
     --org <org> --workspace <ws> --schema <version> \
     --expect-checksum <ciphertext_checksum from the source receipt> \
     --expect-approval-checksum <approval_checksum from the source finalize receipt> \
     --expect-recipient-fingerprint <fingerprint from step 1>
   ```

   Everything is verified before the first write: the checksum, the
   recipient, the approval file (read once; its SHA-256 must equal
   `--expect-approval-checksum`, else `reason=approval_pin`; the bundle is opened first because the approval is bound to its digest, still before any target write) and the source's final approval (it must be `final` with the freeze
   asserted and name exactly this transfer, source, target, snapshot,
   organization, workspace, schema, checksum, closure digest and source audit
   head), the bundle under exactly these identities, the closure of the
   rows, the digest, the counts and the organization CA under the target
   root. Then one transaction inserts the rows, restarts the version sequence
   above the highest copied value, writes the ledger and a `transfer.imported`
   audit record, reads everything back and commits. Receipt:
   `outcome=imported transfer=<t> source=<s> target=<g>
   recipient_fingerprint=<fp> org=<org> snapshot=<n> rows=<n>
   ciphertext_checksum=<sum> audit_head_before=<h> audit_head_after=<h>
   recipient_key=destroyed`. `audit_head_before` equals the source `audit_head`.

6. **Afterwards**: a committed import overwrites and removes the recipient
   private key itself (`recipient_key=destroyed`; `retained` means it could
   not, so remove it by hand: with the bundle it opens every key without the
   target root). A refused import leaves the key in place so the step can be
   repeated. Delete the remaining carriers on both sides, and bring the target up. The next audit record continues the
   copied chain.

## Refusals

Every refusal is one line, `offline-transfer <op> failed: reason=<code>`, and
exits non-zero. A refused import changes nothing on the target.

| reason | meaning |
|---|---|
| `pin`, `identity` | a checksum, fingerprint, UUID or schema argument is malformed or not the expected one |
| `checksum`, `recipient` | the bundle or public key is not the one pinned |
| `root` | the root key file or id is unusable |
| `bundle` | cannot be opened under these identities, is damaged, or the target root is the source root (the same key material under any id; the bundle carries a probe wrapped by the source root that the target root must not open) |
| `approval_pin` | the approval file does not hash to the pin from the source's finalize receipt (a substituted or altered approval; a malformed pin is `pin`, an unreadable file `carrier_*`) |
| `approval` | the source's final approval is not final, lacks the asserted freeze, or describes another export |
| `pki` | the organization CA does not authenticate under the target root |
| `closure`, `counts`, `digest`, `manifest` | the rows are not one closed, unaltered organization |
| `profile` | the source organization is outside the supported profile, or the schema of the source or target is not exactly this binary's: the applied migration history differs, or the live catalog (columns, constraints, indexes, triggers and whether they are enabled, functions, sequences, row security) was altered by hand. Run `keep-server migrate up` with the same release on both sides and undo manual schema changes |
| `target_not_empty` | the target already has data; a second import is always refused |
| `source_changed`, `quiescence` | finalize: the source changed after export, or the freeze was not asserted |
| `carrier_*` | a carrier path or its permissions are unsafe |
| `database`, `insert`, `sequence`, `ledger`, `audit`, `readback`, `commit` | the target transaction failed and rolled back |

## Retry

Export and finalize never write to the source database. A failed export
leaves no bundle behind. Choose a new carrier name for each attempt. A failed
import rolled back completely: fix the cause and run the same command again.
An import that printed `outcome=imported` cannot be repeated.

## Rollback

The source is never modified by any step, so a transfer that goes wrong is
undone on the target only, and the source installation stays the system of
record until you decide otherwise.

- **Before the import commits** (any refusal, or a crash): nothing was
  written. Fix the cause and run the same command again.
- **After `outcome=imported`**: take a database backup of the empty target
  (`pg_dump` of the freshly migrated, empty database, or a snapshot of the
  volume) before step 5, and keep it until you accept the target. To roll
  back, stop the target, restore that backup (or drop and recreate the
  database and run `keep-server migrate up`), and start again from step 1
  with a new recipient and new carrier names. An import cannot be repeated on
  a target that already holds the organization, so restoring the empty
  target is the only way back to a state where it can run again. Do not
  restore the target root key file from the source: the two roots stay
  independent.
- **The source** keeps working throughout; remove the freeze only after you
  have accepted the target.
