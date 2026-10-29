# Keep service account in Mesh

The Mesh rotation plugin (`plugins/mesh`) rotates agent keys through the Mesh
agent-keys API. It authenticates as a dedicated Mesh service account.

## What the account is

An extension actor of Mesh (token `ext_…`), not an agent: it has no agent keys
of its own. It is the actor of the `keep-rotator` extension
([`mesh-extension.keep-rotator.json`](../mesh-extension.keep-rotator.json)),
not of `keep`: Keep's own extension holds no rotation right (see
[two extensions](mesh-extension.md#two-extensions-keep-and-keep-rotator)). Every call carries the token as `Authorization: Bearer ext_…`; an
agent key (`agk_…`) is never a Bearer and is refused. It rotates the agent keys
of other agents.

## What the account may do

`agent_key:rotate`: `POST`, `GET` and `DELETE` `/api/v1/agents/{id}/keys` in
its own workspace; `ext_token:self_rotate`: rotating its own token (below);
and `agent_keys:read`. Nothing else: no creating or deleting agents, no reading
tasks, no events, not an owner.

## Where the token lives

In Keep, sealed, under its own secret name. Not in Mesh, not in a shared
environment file. `pkg/provider/svctoken.Store` keeps it in any
`provider.Provider` (the built-in store in production) and is both sides of the
plugin: `Store` is the `Sink` and `Store.Token` feeds `Config.TokenSource`
(`func(ctx) (mesh.Token, error)` wrapping it). The plugin never holds the token:
the source is asked on every call, so nothing is cached. A source error is not forwarded (class
`ErrUnavailable`). Treat the token as short-lived: rotate the account on a
schedule.

## Rotating the account itself

`mesh.RotateSelf(ctx, rotator, sink, hook, runID)`. `rotator` is a
`mesh.SelfRotator`: `*mesh.Provider` over the agent-keys API today, and the
implementation that calls Mesh's self-rotation capability for the `ext_` token
once its contract exists. It must authenticate with the token read at call time
(`PerCallToken`), otherwise `ErrConfig`:

1. exactly one active key must exist, otherwise `ErrNoCurrent` and nothing is issued;
2. a second key is issued, the old one stays valid;
3. `Sink.Stage` seals the new value in Keep; the plugin then checks at Mesh that the key is active;
4. `Sink.Activate` switches the token source to the new key;
5. the old key is revoked, authenticated by the new token;
6. the hook runs.

A failure up to step 4 revokes the new key and discards the staged value; the
old key stays in force. The issued value is wiped from the plugin's memory as
soon as the sink holds its own sealed copy. After step 4 the rotation is
forward-only: a failed revoke is returned with the `RotateResult`. Two keys are
now active, so a second `RotateSelf` answers `ErrNoCurrent`; call
`mesh.RevokeOld(ctx, rotator, hook, result)` instead. It ends the old key and
runs the hook, and refuses unless the new key is active at Mesh and is a
different key from the old one. A failed hook is reported in
`RotateResult.HookFailed` and does not undo it. Nobody sees the value: the
result, the journal and errors carry key ids, outcome class and lengths.

After a successful `Store.Activate` writes the new token, it drops the staged
copies of the key id: the builtin provider crypto-erases every staged version,
so the live token has one readable sealed copy. A provider without erasure gets
them disabled, except the last version of the name, which a provider refuses to
disable. Crypto-erasure is final only once the KEK is purged and dead rows, WAL
and backups age out (see `builtin.Provider.Erase`); at the default `user` key
level the KEK stays live.

The token is switched before this cleanup, so `Activate` succeeds even when the
cleanup does not: a provider error, or staged versions still there after 16
erased by a restarted Store (`ErrStagedLeft`), leaves copies behind. Failing
`Activate` would revoke the key the token now holds, so keep-server logs it
instead, as `mesh service token staged copy not erased` with
`error_class=staged_cleanup`; check the staged name before you treat it as clean.

A staged value of an abandoned rotation stays sealed under its staged name (a
provider cannot disable the last version of a name). `Store.Activate` refuses it
after `Discard`, and its key is already revoked in Mesh. A staged value kept for
recovery (a failed `Activate`, `ErrOrphaned`) is untouched until it is activated.

## The ext_ implementation of the rotator

`mesh.NewExtSelf` is the `SelfRotator` for the account as an extension actor
(capability `ext_token:self_rotate`). It needs `ExtConfig.TokenSource` and an
https (or loopback) base URL; `GraceSeconds` is 0 (Mesh's default, 300) up to
3600. Routes, authenticated only by the caller's token (no id in a path):

- `GET /api/v1/ext/me`: probe. `Current` probes the old token, `Verify` probes the new one.
- `POST /api/v1/ext/me/token/rotate`: `Issue`. The answer carries the new token once; the
  caller's token stays valid for the grace window. A repeat with the same token is safe.
- `DELETE /api/v1/ext/me/token/previous`: the revoke of the replaced token, always sent with the
  current (new) token; Mesh answers 409 to the previous one. A repeat is 204.

Order for Keep: POST, stage, probe with the new token, activate, DELETE previous, hook.
Mesh has no route that ends a freshly issued token and cannot issue the same one
twice, and the replaced token dies on its own after `grace_seconds`. So an
ext_ rotation that fails after the POST is not rolled back to the old token:
`RotateSelf` keeps the staged value (the sink's `Discard` is not called) and returns
`ErrOrphaned` joined with the cause. A failed `Stage` is retried (3 times, 500 ms apart,
on a context that survives cancellation) before the issued value is wiped, because
it is the only copy of the new token. If every retry fails the value is lost:
`RotateSelf` returns `errors.Join(ErrOrphaned, ErrSink)`. It calls neither `Revoke`
(Mesh cannot end a freshly issued extension token, so it would do nothing) nor the sink's
`Discard` (Stage may have committed and still failed, and a partly written copy can
be the only working one). The old token dies after the grace window (300 s by
default): re-run `RotateSelf` before it ends; otherwise use the manual
`rotate-mesh-agent-key.py`. For agent keys, which can be ended, a lost Stage ends the
new key and returns `ErrSink`; only if ending it fails is the result
`errors.Join(ErrOrphaned, ErrSink, revokeErr)`, to be cleared by an operator.
Recover in this order: run `RotateSelf` again before the grace window ends (the
old token still works, a new POST issues another token); if the window has
passed, activate the staged value named by `RotateResult.NewKeyID` through the
sink (`Store.Activate`), which is the only token that works. An abandoned
rotation never sends the DELETE (it would end the token in use). Tokens have no
ids in Mesh, so the key ids the sink and the hook see are local labels. A 403 means the capability is missing.

## Restart hook

A process that holds the old token in its environment must be relaunched after
step 4. That is an operator step outside Keep's core: `mesh.NewExecHook(argv)`
runs one absolute-path program with no shell and a closed environment
(`PATH`, `HOME`, `KEEP_AGENT_ID`, `KEEP_KEY_ID`). Its output is discarded.

## Background self-rotation in keep-server

The Mesh build of `keep-server` (`plugins/mesh/cmd/keep-server`) can rotate the
account's own `ext_` token on a timer. It is off unless `KEEP_MESH_SELF_ROTATE=1`;
the plain build refuses to start with that setting. It needs
`KEEP_MESH_EXTENSION=1` and:

| Variable | Meaning |
|---|---|
| `KEEP_MESH_SELF_ROTATE_URL` | base address of Mesh |
| `KEEP_MESH_SELF_ROTATE_ACCOUNT_ID` | actor id of the service account (UUID) |
| `KEEP_MESH_SELF_ROTATE_ORG_ID` | organisation whose sealed store holds the token (UUID) |
| `KEEP_MESH_SELF_ROTATE_INTERVAL` | period, at least `1s`, default `24h`; the first rotation runs one period after start |
| `KEEP_MESH_SELF_ROTATE_HOOK` | optional absolute path of the restart wrapper |
| `KEEP_MESH_SVC_BOOTSTRAP_FILE` | optional absolute path of the first token |

The token lives under the secret name `mesh-service-token` in that store
(`svctoken.Store`): `RotateSelf` stages, checks and activates the new value there.
A failed revoke of the old token is repeated once in the same run; a failure is
logged by class (`error_class=rotation`) and the next tick tries again.

Bootstrap: when the store holds no token and `KEEP_MESH_SVC_BOOTSTRAP_FILE` is
set, the file is read and sealed. It must be a regular file (not a symlink) of
mode `0600`, not empty and at most 4096 bytes, otherwise the server does not
start. The file is left in place and never replaces a token that is already
sealed, so a restart after a rotation keeps the rotated token. The log line
states `name`, `version`, `fingerprint` and `length`. The first rotation runs one
interval after start, so delete the file once that line appears: until then it is a
live token in plaintext. No API route is added.

The hook is started with no arguments and the closed environment above; the token
is never in its argv or environment. Run one server instance for the account:
two instances would both rotate it.

Limits to know about:

- A failed or orphaned rotation is retried up to four times, after a quarter of
  the interval (at most 30 s), then waits for the next tick. The timer restarts
  from zero when the server restarts.
- A crash between staging and activating a new token leaves a staged token and
  the old main token in place. The bootstrap file never replaces a sealed token,
  so if the main token is dead, reseal it by hand.
- The bootstrap file is checked for mode 0600, size and type, not for its owner.
- The sealed token's name is reserved: a catalog `provider_ref` under
  `builtin://mesh-service-token` is refused. The check runs when a ref is
  created, so before enabling self-rotation on an instance that predates it,
  confirm that no catalog ref already points under that prefix.

## Moving from `keep` 0.6.2

Up to `keep` 0.6.2 the rotation rights sat on the `keep` extension, so a token
sealed as `mesh-service-token` may be a `keep` actor token. From 0.6.3 that
token has no rotation right and every self-rotation tick fails with
`error_class=rotation`. Order of the move:

1. install and connect `keep-rotator` in the workspace and issue its token;
2. put that token into Keep as the service account's token: on a store that
   holds none, through `KEEP_MESH_SVC_BOOTSTRAP_FILE`; over a sealed `keep`
   actor token, reseal it by hand as for a dead main token (above);
3. update `keep` to 0.6.3.

Never put Keep's `extension_token` into the bootstrap file: it is the `keep`
actor and, after the update, rotates nothing.

## One actor, one owner

The self-rotation account and the Mesh gate (`KEEP_MESH_TOKEN_FILE` or
`KEEP_MESH_WORKSPACE_ID`, see `mesh-extension.md`) use different actors. Each
actor has one sealed copy of its token and one owner of its rotation:

- the self-rotation account (`KEEP_MESH_SELF_ROTATE_ACCOUNT_ID`) is its own
  actor with only `agent_key:rotate`, and only self-rotation replaces its token;
- the installation's actor, whose token the gate holds, is rotated only by the
  install handshake and by Mesh's `rotate-token` of that installation. Do not
  grant it `agent_key:rotate`.

One actor in both roles kills its own copies: a `rotate-token` of the gate
replaces the token, and the sealed `mesh-service-token` of the same actor stops
working; a self-rotation in turn ends the gate's token.

So the Mesh build of `keep-server` refuses to start when self-rotation is on (not
seal-only) and the gate is configured, and Mesh answers that the gate's token
belongs to the self-rotation account: before the rotation starts it calls
`GET /api/v1/ext/me` with the gate's token and compares `actor_id` with
`KEEP_MESH_SELF_ROTATE_ACCOUNT_ID`. The start then stops with
`self-rotation account is the gate's actor` and a log line with
`error_class=same_actor`; nothing was rotated. If Mesh cannot be asked (no
answer, a refused token, an answer without an actor id), the start goes on with
a warning by class (`mesh self-rotation actor check skipped`): the gate answers
503 in that state anyway. Neither the token nor the answer is logged. The check
runs once per start: an actor changed in Mesh later is found at the next start.

## Rollback

Disable the `keep-rotator` extension in the workspace (its token stops working), and
go back to rotating by hand with the manual rotation script. No Keep data
changes are involved.

## Issuing the role (operator, once)

Issue the account and its first token in Mesh, then seal the token into Keep
without printing it. Use name, version, fingerprint and length to confirm; never
echo the value.
