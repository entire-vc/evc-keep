# Keep as a Mesh extension

Keep can be connected to a Mesh instance as an external extension. It is off by
default and changes nothing for a Keep that does not use it: set
`KEEP_MESH_EXTENSION=1` on the server to register the two routes below. Without
it they do not exist (404), and the rest of Keep behaves identically.

The manifest the Mesh side reads is [`mesh-extension.json`](../mesh-extension.json).

## Two extensions: `keep` and `keep-rotator`

Mesh gives an extension one actor per workspace, and the actor holds every
right its manifest declares. Rotating credentials is kept out of Keep's own
actor, so the repository carries two manifests:

| Extension | Manifest | Mesh token Keep holds | Used for |
|---|---|---|---|
| `keep` | [`mesh-extension.json`](../mesh-extension.json) | `extension_token`, sealed at the admin install | confirmations through a Mesh card, the mirror of the Mesh hierarchy, the secrets screen |
| `keep-rotator` | [`mesh-extension.keep-rotator.json`](../mesh-extension.keep-rotator.json) | `mesh-service-token`, sealed by the service-token store | rotating agent keys and its own token ([service account](mesh-service-account.md)) |

`keep-rotator` declares exactly `agent_keys:read`, `agent_key:rotate` and
`ext_token:self_rotate`, and nothing else: no events, no screens, no network
domains, no secrets. `keep` declares none of the rotation rights
(`agent_key:rotate`, `ext_token:self_rotate`, `agent_keys:write`), so a leaked
`extension_token` cannot issue or revoke a credential, and a leaked rotator
token cannot open a card, read the hierarchy or write a secret. The tests
`TestMeshManifestsSplitRotationRights` and `TestMeshRotatorManifestIsNarrow`
hold this split.

`keep-rotator` is an external extension pointing at the same `keep_url`, with
the paths of `keep`, because Mesh requires them of an external manifest. Keep
answers its install handshake with `401` (the handshake accepts only
`extension_id` `keep`) and writes nothing, so Mesh reports the rotator's
connection as not healthy; its token works regardless. Its first token is
issued in Mesh to the administrator and reaches Keep through
`KEEP_MESH_SVC_BOOTSTRAP_FILE`; Keep seals it as `mesh-service-token` and rotates
it from then on ([self-rotation](mesh-service-account.md)). The two extensions
are installed and connected separately, each with its own consent.

Mesh installs from a repository by reading `mesh-extension.json` at its root, so
`keep-rotator` is not installed from this repository's root at a ref the way
`keep` is; its manifest is published here so that the file installed is the one
the tests check.

The extension catalog likewise takes one extension per repository, so
`keep-rotator` is listed from its own repository, `evc-keep-rotator`. That
repository holds no code: only `mesh-extension.json`, a README and the license.
This repository is the source of truth for the manifest; the copy there must be
byte-for-byte equal to `mesh-extension.keep-rotator.json` at the same version.
To change it:

1. Change `mesh-extension.keep-rotator.json` here and raise its `version`; the
   manifest tests and `scripts/check-mesh-mutations.sh` run on this file.
2. Once merged, copy it to `evc-keep-rotator` as `mesh-extension.json`, check
   that `cmp` reports no difference against this file at `main`, and tag the
   same version there (a plain `X.Y.Z` tag, as the catalog expects).
3. Run the catalog validator in that clone, `mesh-ext validate . --tag X.Y.Z`,
   before the catalog entry is updated.

Mesh keeps the manifest it read at install time. A changed manifest (a new
sidebar title, a new version) reaches a running Mesh only through its update
path, by install source:

- installed from this repository at a branch: the instance administrator opens
  Extensions → Updates (`GET /api/v1/extensions/updates`) and applies the update
  (`POST /api/v1/extensions/keep/update`), or the instance auto-update does it on
  its next pass. Mesh sees a new commit on the branch head.
- installed at a tag: the same, once a higher `vX.Y.Z` tag exists; Mesh offers
  the highest semver tag.
- installed from the catalog: once the catalog entry carries the new version.

An update that adds no capability needs no new consent. Reloading the Mesh page
afterwards shows the new title in the sidebar.

## `POST /mesh/install`

The route serves two callers, told apart by the `Authorization` header:

- with `Authorization`: an organization admin connects a workspace and hands
  Keep the Mesh credentials directly (the admin install below);
- without it: Mesh's own install handshake, which Mesh sends when the extension
  is enabled in a workspace and repeats on every health check (the Mesh
  handshake below). It binds the workspace only inside a window an admin opened
  in Keep.

Both are served only over TLS.

### Admin install

Called by an organization admin (a human user token with the admin role) to
connect one Mesh workspace to the caller's organization.

Request body (unknown fields are refused):

| field | rule |
|---|---|
| `mesh_url` | absolute `https` URL; `http` only for a loopback host; no credentials, query or fragment. Keep does not call it during install |
| `workspace_id` | UUID of the Mesh workspace |
| `extension_token` | the Mesh actor token Keep will call Mesh with, at most 4096 bytes |
| `events_endpoint_secret` | the secret Mesh signs events with, 16 to 512 bytes |

Response `200`: `{"ok": true, "request_id": "...", "keep_secret": "..."}`.
`keep_secret` is Keep's own secret for this workspace. It is shown exactly once
in this response (`Cache-Control: no-store`) and is never readable again.

The token and both secrets are sealed with the built-in provider under
`mesh/<workspace_id>/...` in the organization's store. They never appear in a
log, error, audit record or any other response. Installing again from the same
organization replaces them (the old events secret stops working). A workspace
connected to another organization answers `409 already_exists`. A caller who is
not an admin gets `404`. Each install is audited as `mesh.install`.

### Mesh handshake

Mesh calls the route with no bearer token:

- `X-Mesh-Timestamp`: Unix seconds; more than five minutes away from Keep's
  clock is refused
- `X-Mesh-Signature`: lowercase hex of
  `HMAC-SHA256(signing_secret, "<timestamp>.<raw body>")`, no prefix
- body: `{"extension_id": "keep", "version": "...", "workspace_id": "...",
  "signing_secret": "...", "events": [...], "events_path": "/mesh/events"}`.
  Unknown fields are ignored; `signing_secret` is 32 to 512 bytes (Mesh
  generates 64 hex characters and keeps it as the workspace secret
  `EXT_KEEP_SIGNING_SECRET`)

The outcome:

- the workspace is not connected and an admin's window for it is open, with the
  SHA-256 of this `signing_secret` (compared over all 32 bytes): the secret is sealed as the workspace's
  events secret, the workspace is connected to the window's organization with
  the window's `mesh_url`, the window is spent, and `mesh.install` is audited
  with the admin who opened the window as the actor. Response
  `200 {"ok": true, "request_id": "..."}`; nothing secret is returned;
- the workspace is already connected and `signing_secret` is the bound events
  secret (Mesh repeats the handshake after a restart with the same secret):
  `200`, and nothing is written;
- anything else (no window, an expired or spent window, another digest, a
  bad or stale signature, another `extension_id`, another secret for a
  connected workspace): the same `401 unauthenticated`, and nothing is written.

An authenticated handshake (one of the two `200` cases) is limited per
workspace with the budget of `resolve` (`429` with `Retry-After`). A refused
one never spends it: the signature is keyed with the secret in the body, so
anyone can sign for any workspace id. Every unauthenticated Mesh call (the
handshake, `POST /mesh/events`, the signed secrets calls, `POST /mesh/token`,
`POST /mesh/session`)
spends instead the budget of its client address, 120 a minute with a burst of
30, before any storage call, and gets the token back once it authenticates;
see `KEEP_TRUSTED_PROXIES` in [deploy](deploy.md).

The handshake carries no Mesh actor token. Mesh delivers it separately, to
`POST /mesh/token` (below), once the workspace is connected and again on every
rotation. Until the first delivery the workspace has no `extension_token`: the
mirror of the Mesh hierarchy and the confirmation gate, which call Mesh with
that token, do not run for it.

### Token delivery: `POST /mesh/token`

Mesh hands Keep the extension actor token of a connected workspace, so the
token never passes through a person. No bearer token; TLS only.

Mesh calls this path only because the `keep` manifest names it in
`external.token_path`; an installation still on a manifest without it (before
0.6.4) gets no delivery, and its `rotate-token` returns the token to the caller
instead. Update the installation (see above) before rotating.

- `X-Mesh-Timestamp`: Unix seconds; more than five minutes away from Keep's
  clock is refused
- `X-Mesh-Signature`: lowercase hex of
  `HMAC-SHA256(events secret, "<timestamp>.<raw body>")`, no prefix. The key
  is the events secret already bound to the workspace (for a handshake
  install, `EXT_KEEP_SIGNING_SECRET`); nothing in the body is a key
- body: `{"extension_id": "keep", "workspace_id": "...", "extension_token": "..."}`.
  Unknown fields are ignored; the token is 1 to 4096 bytes

The outcome:

- the workspace is connected, the signature holds, and the timestamp is later
  than the one of the last accepted delivery: the token is sealed as a new
  version of `mesh/<workspace_id>/extension_token` in the organization's store,
  and the gate and the hierarchy mirror use it from their next call. Response
  `200 {"ok": true, "request_id": "..."}`; `mesh.token` is audited with the
  workspace as a service actor, the fingerprint and the length;
- a delivery signed at the same second as the last accepted one or earlier is
  a replay: it could put back a token Mesh has since rotated away. It gets
  `401`, writes no token and is audited as a refused `mesh.token`;
- anything else (not connected, a bad or stale signature, another
  `extension_id`, an empty or oversized token, a body over 64 KiB, the
  per-workspace budget it shares with the handshake spent): the same `401`,
  and nothing is written;
- the budget of the client address spent: `429` with `Retry-After`, before the
  body is read. It is keyed on the address alone, so it answers alike for any
  workspace and any signature; a delivery whose signature holds gets its
  token back.

A signed delivery Keep refuses (another `extension_id`, an empty or oversized
token, a replay) is audited as a refused `mesh.token`. If the journal cannot
record an accepted delivery or such a refusal, the answer is `503`. The timestamp of a delivery is spent once it
passes the replay check, even if sealing then fails (`503`): Mesh delivers
again with a newer timestamp. Deliveries for one workspace are applied one at
a time, so an older one never lands after a newer one.

### Install window: `POST /orgs/{org_id}/mesh/pending-installs`

An organization admin opens the window before enabling Keep in the Mesh
workspace. Bearer of an admin of `{org_id}`, TLS only; anyone else gets `404`.

Request body (unknown fields are refused):

| field | rule |
|---|---|
| `workspace_id` | UUID of the Mesh workspace |
| `mesh_url` | the Mesh address, same rule as in the admin install |
| `signing_secret_sha256` | the full SHA-256 of the signing secret `EXT_KEEP_SIGNING_SECRET`: exactly 64 lowercase hex characters, anything else is `400` |

Response `201 {"workspace_id": "...", "expires_at": "<RFC 3339>", "request_id": "..."}`.
The response never repeats the digest, and neither do the log and the audit
journal. The window lasts 15 minutes and is used once; it is deleted when the
handshake spends it and once it expires. There is one window per workspace:
opening it again replaces it. A workspace connected to another
organization, or holding a live window of another organization, answers
`409 already_exists`. Each window is audited as `mesh.install.pending`.

Connecting a workspace this way:

1. In Mesh, add the Keep extension to the workspace. Mesh creates
   `EXT_KEEP_SIGNING_SECRET` in the workspace secrets. Its first handshakes
   are refused until the window is open; Mesh retries.
2. Compute the digest without displaying the secret. Read the value from the
   Mesh secret store and pipe it straight into `sha256sum` (`shasum -a 256` on
   macOS); keep only the digest in a variable. Never `echo` the value, put it
   on a command line or in a shell variable, and keep it out of the shell
   history. `read-mesh-secret` below stands for whatever command your Mesh
   deployment uses to read a workspace secret to standard output; if it ends
   the value with a newline, the `tr` removes it:

   ```sh
   SHA=$(read-mesh-secret "$WORKSPACE_ID" EXT_KEEP_SIGNING_SECRET | tr -d '\n' | sha256sum | cut -d' ' -f1)
   ```

   The 8-character fingerprint that Mesh lists next to the secret is not
   enough and is refused: anyone who sees it can search offline for another
   secret with the same 8 characters.
3. Open the window in Keep with that digest:

   ```sh
   curl -sS -X POST "https://keep.example.com/orgs/$ORG_ID/mesh/pending-installs" \
     -H "Authorization: Bearer $KEEP_ADMIN_TOKEN" -H 'Content-Type: application/json' \
     -d '{"workspace_id": "'"$WORKSPACE_ID"'", "mesh_url": "https://mesh.example.com", "signing_secret_sha256": "'"$SHA"'"}'
   ```

4. Within 15 minutes Mesh's next health check repeats the handshake and the
   workspace is connected. To speed it up, run the extension health check in
   Mesh.


## `POST /mesh/events`

No bearer token: the request is authenticated by its signature.

Headers:

- `X-Mesh-Workspace`: the workspace UUID. Optional: Mesh itself does not send
  it, and Keep then takes `workspace_id` from the body (the signature covers the
  body)
- `X-Mesh-Event`: the event type of Mesh's flat body. The signature does not
  cover headers, so it is only a label: Keep never takes an id from a header
  (`X-Mesh-Delivery` is ignored), derives the id of a flat event from the signed
  body (a retry is the same body, a header edit cannot mint a new delivery),
  recognises a gate answer by its signed fields (`task_id` and `decision`)
  whatever the header says, and refuses `task.gate.decided` on a body that is not
  a gate answer
- `X-Mesh-Timestamp`: Unix seconds; a request more than five minutes away from
  Keep's clock is refused
- `X-Mesh-Signature`: the lowercase hex of
  `HMAC-SHA256(events_endpoint_secret, "<timestamp>.<raw body>")`, exactly 64
  characters, as Mesh sends it to extensions. The same hex after one `v1=` is
  also accepted (the form Keep documented first); it is the same MAC, so the
  prefix is only a label. Upper case, another length, a second prefix or
  surrounding spaces are refused with 401

Body: either Mesh's flat body (`workspace_id` plus the fields of the change,
for example `{"workspace_id": "...", "user_id": "...", "role": "member"}`) with
`X-Mesh-Event`, or the envelope
`{"id": "...", "type": "...", "workspace_id": "..."}`. `id` matches
`[A-Za-z0-9._:-]{1,128}`, `workspace_id` must equal the header, and `type` is
one of the manifest's events.

Every authentication failure (unknown workspace, stale timestamp, missing,
malformed or wrong signature) answers the same `401 unauthenticated`, so the
route is no oracle on which workspaces are connected. A valid event answers
`200 {"ok": true, "request_id": "..."}`. An event id is recorded once per
workspace: a repeat delivery is acknowledged and has no further effect.

## Confirmations through a Mesh card

A request that waits for a person (a deploy, an exec or a rotation approval)
can be shown in Mesh as a card with a human gate. The card is a pointer: it
names the secret, its class, the kind of request, the request id and the
request hash, and never a value. The card is created by the extension actor,
carries the hash as its write-once `external_hash`, and has a deadline equal to
the approval's own.

The person answers on the card; Mesh sends `task.gate.decided` to
`POST /mesh/events`. Keep applies the answer only when all of this holds, and
refuses it otherwise (a refusal is still acknowledged with `200`, so Mesh does
not retry it or mark the connection degraded; the reason goes to Keep's log as
a closed code):

- the decider is a person (`decided_by_type = user`), not an agent or the system;
- the decider is not the one who asked;
- `external_hash` equals the hash Keep bound to the request;
- the Mesh user is linked to a Keep user (`mesh_user_links`); an unlinked user is refused;
- the request is still pending and before its deadline.

The first word of the answer is the decision (`approve` or `reject`); any
other text is no decision. The rest of the text is never logged or stored, and
the journal gets a fixed reason. A repeated delivery, or a later answer to a
decided card, changes nothing. A failure to apply (for example, the database is
down) answers `503` and the event is forgotten, so the redelivery is applied
and not dropped as a repeat.

When the deadline passes, the request lapses and Keep cancels the card. Mesh
may refuse to cancel a card that has a gate; the card then stays marked and
the next sweep tries again.

Keep core talks to the tracker only through `pkg/gatecard`; the Mesh client is
in `plugins/mesh`, and Keep works without it.

### Configuration

The cards are on only when `KEEP_MESH_EXTENSION=1` and all of these are set;
a part of them stops the start with the name of the missing variable:

| Variable | Meaning |
|---|---|
| `KEEP_MESH_PROJECT_ID` | the Mesh project the cards are created in |
| `KEEP_MESH_URL` | the base address of Mesh |
| `KEEP_MESH_CANCEL_STATUS_ID` | the project's cancelled status, for lapsed requests |
| `KEEP_MESH_WORKSPACE_ID` or `KEEP_MESH_TOKEN_FILE` | where the extension actor's token comes from; exactly one of the two |

`KEEP_MESH_WORKSPACE_ID` names the installation whose actor token Keep sealed
at the admin install or at the last `POST /mesh/token` delivery. Keep unseals it for each call to Mesh, so the token a
later install or rotation seals is used next, without a restart; there is no
second copy of it on disk. The token is sent only to the Mesh the workspace
was installed from: `KEEP_MESH_URL` must have the same scheme, host and port as
the address recorded at install. A workspace with no installation, no token or
another Mesh address fails the request that needs a card as unavailable. `KEEP_MESH_TOKEN_FILE` is
for a setup without the install handshake: a file of mode `0600` that is read
on each call. `KEEP_MESH_SWEEP_INTERVAL` (default `1m`) sets how often lapsed
cards are cancelled. At start Keep logs which source is on, by name only.

## Mirror of the Mesh hierarchy

Keep mirrors the hierarchy of a connected workspace (members with roles,
projects, agents with their active keys and sponsor) so that tenancy can follow
Mesh. It is metadata only: no value, and no key material, not even the public key
prefix Mesh exports, is stored; a key is known by its id and label.

Two inputs keep the mirror current:

- **Events.** `POST /mesh/events` applies `workspace.member.added|removed`,
  `project.created|updated` and `agent.key.issued|revoked` in the same
  transaction that records the event id. The optional fields are `occurred_at`
  (RFC 3339; the moment of the fact in Mesh, never more than five minutes ahead
  of Keep's clock) and `data`:
  `user_id`, `role` (member events); `project_id`, `slug`, `name`, `is_archived`
  (project events); `agent_id`, `key_id`, `label`, `sponsor_user_id` (key
  events). A row only moves forward in time (times are kept to the microsecond; at the
  same instant a removal or revocation wins over an addition), so a repeated or
  reordered delivery changes nothing. Mesh's own flat events carry no
  `occurred_at`, so they only make the next reconciliation fetch a full
  snapshot. An event without `occurred_at` or without the
  fields it needs is still recorded but changes no row (Keep's receive time
  cannot order it); it makes the next reconciliation fetch a full snapshot.
- **Full reconciliation.** Every five minutes each connected workspace is read
  from `GET {mesh_url}/api/v1/workspaces/{id}/export/hierarchy` with the sealed
  actor token (unsealed only inside the plaintext zone, no redirect is followed).
  The ETag is the cursor: an unchanged snapshot costs one `304`. The cursor
  catches events Keep missed, but only changes on Mesh's side: a divergence
  that exists only in Keep's mirror (a row edited by hand, a partial restore)
  would survive every `304`. So once an hour after the last full snapshot it
  applied, the reconciliation of a workspace fetches without the ETag, and the
  full snapshot repairs the mirror (`last_full_sync_at` in `mesh_sync_state`).

**Nothing is deleted.** An entity Mesh no longer reports is marked `orphaned`
(a member removed by an event is `removed`, a revoked key `revoked`), so the
secrets and the access that hang off it survive a missed or mistaken event;
Mesh reporting it again revives it. Newly orphaned entities log a warning
(`mesh.orphaned`); the counts are in `mesh_sync_state`. A failed fetch changes
nothing and is recorded by class only (`unauthorized`, `not_found`, `server`,
`network`, `too_large`, `bad_status`, `unavailable`, `bad_snapshot`). For
`https` the fetch refuses a Mesh host that resolves to a private, loopback or
link-local address.

## `PUT /orgs/{org_id}/mesh/secrets/{ref}` and `POST /orgs/{org_id}/mesh/secrets/{ref}/resolve`

A Mesh workspace keeps the values of its own extension settings in Keep. Both
routes are served over TLS only. A user token is not accepted.

Authentication reuses the events secret of the install, with the headers of
`/mesh/events` plus `X-Mesh-Nonce`. The signature is
`v1=` + lowercase hex of `HMAC-SHA256(events_endpoint_secret, M)` where `M` is

```
keep-mesh-secret-v1\n<timestamp>\n<nonce>\n<METHOD>\n<request path>\n<hex sha256 of the raw body>
```

The request path is the path as sent (without the query), so the signature
binds one method, one path and one body, and cannot be turned into an event.
The window is five minutes. `X-Mesh-Nonce` is required: 16 to 64 characters of
base64url or hex without padding, unique per request. Keep records it once the
signature holds, and a repeat of a nonce is refused like a bad signature, so a
captured request cannot be replayed. A retry carries a new nonce. A missing or
malformed nonce is refused, and there is no compatibility mode. Every
authentication failure answers the same
`401`. Revoking the workspace is a reinstall with a new events secret: the old
signature stops working at once. The organization in the path must be the one
that owns the workspace's installation, otherwise `403`.

`{ref}` matches `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` and contains no `..`; a
workspace reads and writes only `mesh/<workspace_id>/secrets/<ref>` in its
organization's store. Another workspace's ref and a ref nobody wrote are the
same `404`.

- `PUT` body `{"value": "..."}` (1 byte to 32 KiB, no other field) stores a new
  version. Answer `{"ref", "version", "fingerprint"}`; the value is not returned.
- `POST .../resolve` has no body. Answer `{"value", "version"}` with
  `Cache-Control: no-store` and `Content-Type: application/json`. This is the
  one place Keep returns a value to a caller that is not a runner, narrowed to
  what the workspace itself wrote. It is limited per workspace (`429` with
  `Retry-After`).

Errors: `400` malformed ref or body, `401` not authenticated, `403` foreign
organization, `404` no such ref, `429` rate limit, `503` storage unavailable
(Mesh should treat Keep as degraded). Each call is audited as
`mesh.secret.put` or `mesh.secret.resolve` with the workspace, the ref, the
version, the fingerprint and the length, never the value; there is no answer to
a resolve without its audit record.

Signature headers (`X-Mesh-Signature`, `X-Mesh-Timestamp`) must never be written to a log or a trace: a leaked request is refused once its nonce is spent, but a request Keep has not yet seen could still be used inside the five-minute window.

Smoke: `TestMeshExtensionSmoke` (`cmd/keep-server/app/mesh_smoke_test.go`) drives
both routes over a real TLS connection against a throwaway PostgreSQL, with its
own organizations, workspaces, events secrets and a synthetic value, and prints
only the ref, version, fingerprint and length. Run it with
`KEEP_DATABASE_URL=<disposable server> go test -count=1 -run TestMeshExtensionSmoke -v ./cmd/keep-server/app`.
`scripts/check-mesh-mutations.sh` proves it goes red when a guard is off.

## The secrets screen in the Mesh iframe

The manifest declares one sidebar item, titled `Keep`, at `/mesh/ui/secrets`. The path stays as it is when the title changes: the session cookie and the frame policy are scoped to it. Mesh opens it as `/mesh/ui/secrets?token=<JWT>`; Keep verifies the token against the Mesh key set recorded at install (the same check as `/mesh/session`), opens its own session cookie `keep_mesh_ui` (`Path=/mesh/ui`, `HttpOnly`, `Secure`, `SameSite=None`, `Partitioned`) and redirects to the same path without the token. There is no second login.

| Path | What |
|---|---|
| `/mesh/ui/secrets` | secrets of the organization and of the signed-in user: name, scope, class, version, fingerprint, length, status. A value is never rendered. Filters `q` and `class`, first 200 rows |
| `/mesh/ui/settings` | organization key level (`user`, `project`, `workspace`, `organization`), who changed it and when |
| `/mesh/ui/settings/key-level` | `POST`, organization admins only, CSRF token and same-origin check; a coarser level needs the explicit confirmation box |

**Framing.** Every response carries `Content-Security-Policy: … frame-ancestors <origins>`, where the origins are the `mesh_url` values of the organization's install records. They never come from the request. With no session or no install record the value is `'none'`. `X-Frame-Options` is not sent (it cannot name an origin).

**postMessage.** The screen script acts on a message only if `event.source` is the parent window and `event.origin` is one of the recorded origins; anything else is ignored silently. It accepts `mesh.context` (version 1) and sends `mesh.ready`, `mesh.resize`, `mesh.navigate` (a path with a single leading `/`) and `mesh.toast` (text up to 300 characters) with the Mesh origin as `targetOrigin`, never `*`. The token field of `mesh.context` is named `token`, as in the Mesh implementation.

**Key level on this server.** The level is read from `keep_org_key_level`. Changing it is offered only when the server has a key-level changer wired in; the standard server wires it in when the Mesh extension is enabled, and a server built without one shows the page read-only.

Guards are proved by `scripts/check-mesh-ui-mutations.sh` (CI job `mesh-ui-mutations`).
