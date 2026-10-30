# Keep

Keep is open-source (Apache-2.0) storage and delivery of secrets for
people and software agents. It hands a secret to whoever needs it — a
human, a service, or an autonomous agent — without ever putting the
secret's *value* somewhere it can leak: not in a model's context, not
in a log, not in an API response, not in an error message.

It works standalone, and plugs into [Mesh](https://github.com/entire-vc/evc-mesh)
as an integration — Keep has no hard dependency on Mesh.

## Status: pre-alpha

The server and CLI support runner registration, renewal over mTLS, and
revocation. `keep-runner enroll` registers a host and pins its organization's
CA and job-signing key; `keep-runner check` verifies its local credential
and policy.

Runner job execution works end to end. `keep deploy` submits a deployment;
the server signs a job; `keep-runner run` polls for it over mTLS, verifies the
signature, its own identity, the time window and the replay journal, checks the
host policy, fetches the value once, verifies its fingerprint and writes the
target (`env-file`, `file`, `launchd-env`, `systemd-credential`, `mcp-config`,
`hermes-config`). It then reports a closed result; the value never appears in
the result. The wire contract is in `docs/runner-delivery.md`. Which
deployments run without a person's approval is the organization's deployment
policy, set by the operator with `keep-server set-deploy-policy`
(`docs/deploy-policy.md`).

Expect breaking changes while the interfaces stabilize.

## Goals

- Store secret references and metadata (never plaintext values) once,
  and hand them out to the people and agents that need them.
- Keep secret values out of logs, transcripts, and chat.
- Deliver a secret to a target host — a file, an environment, a
  systemd credential — through a runner that resolves the value on the
  host itself, not on the server or in a client's memory.
- Support pluggable storage providers: a built-in provider plus
  adapters for external secret managers (1Password, SOPS/age,
  Vault/OpenBao, and others), all conforming to one interface.
- Run on its own, or as a Mesh integration.

## Components

| Component | What it does |
|---|---|
| `cmd/keep` | CLI client, including `keep deploy` |
| `cmd/keep-server` | catalog, tenancy, policy, audit journal |
| `cmd/keep-runner` | on-host executor: `enroll`, `check`, `run` (executes signed deploy jobs) |
| `pkg/provider` | the storage-provider interface and conformance tests |

## Network

Keep makes no outbound connections except to endpoints the operator
configures:

- `keep-server` connects to its PostgreSQL database (`KEEP_DATABASE_URL`).
- With the Mesh integration enabled, `keep-server` calls the Mesh API at
  `KEEP_MESH_URL` (workspace and agent metadata, approval cards, token
  verification keys), and Mesh calls Keep at the configured `keep_url`.
  What each Mesh permission is used for is listed under
  [Permissions](#permissions).
- If `KEEP_TELEGRAM_BOT_TOKEN` and `KEEP_TELEGRAM_CHAT_ID` are set,
  `keep-server` sends approval notices to `api.telegram.org`. The notice
  carries the secret's name and class, never its value.
- `keep` and `keep-runner` connect only to the Keep server they are pointed
  at (`--server` / `KEEP_SERVER`), the runner over mTLS. A deploy job's
  optional HTTP health check is restricted to loopback addresses on the
  runner's host.
- The Mesh plugin's `keep-lane-poller` connects only to the Keep server at
  `KEEP_URL`.

## Permissions

What Keep does with each permission, event, domain and screen its Mesh
manifest ([`mesh-extension.json`](mesh-extension.json)) declares. Mesh
gives these to Keep's extension actor in a workspace where Keep is
installed. Keep itself sends no secret value to Mesh and puts none on a
card, comment or event: what Keep writes to Mesh or keeps from Mesh is
names, ids, versions, fingerprints and the hash that binds a confirmation
card to its request. The one exception is a read-back: a
Mesh workspace, authenticated by the install's signature, reads the value of
an extension setting it wrote itself with
`POST /orgs/{org_id}/mesh/secrets/{ref}/resolve`. It reaches only the refs
of its own prefix; each call is rate limited, journaled before the value is
released, and answered with `Cache-Control: no-store`. Details:
[docs/mesh-extension.md](docs/mesh-extension.md).

### API

| Permission | What Keep does with it | What it does not do |
|---|---|---|
| `workspaces:read` | Reads the workspace's hierarchy, `GET /api/v1/workspaces/{id}/export/hierarchy`, every five minutes (an unchanged snapshot is one `304`), to reconcile its mirror of the workspace. | Reads no other workspace. Changes nothing in Mesh. |
| `projects:read` | Takes the projects from that snapshot (id, slug, name, archived) and keeps them in its mirror. | Creates, edits or archives no project. Reads no task or document. |
| `members:read` | Takes the members from that snapshot (user id and role) and keeps them in its mirror; a member Mesh no longer reports is marked, not deleted. | Reads no email, name or profile. Invites or removes no one. A Mesh membership grants no right in Keep. |
| `agents:read` | Takes the agents from that snapshot (id, slug, sponsoring user) and keeps them in its mirror. | Creates, edits or deletes no agent. |
| `agent_keys:read` | Keeps the key id, label and state (active, revoked) of agent keys, from the snapshot's active keys and the `agent.key.*` events. Keep makes no call to the agent-keys API under this permission. | Never sees or stores a key's secret part. Issues, rotates or revokes no key: that is the separate `keep-rotator` extension ([service account](docs/mesh-service-account.md)). |
| `tasks:write` | When `KEEP_MESH_EXTENSION=1` and the card settings are configured, opens a confirmation card for a Keep request that needs a person's approval (`POST /api/v1/projects/{id}/tasks`), binds it to the request (`PUT /api/v1/tasks/{id}/external-ref`, request id and hash), arms its human gate, and moves it to cancelled when the request lapses. The card holds the secret's name and class, the target kind and the request id. | Puts no secret value, provider text or free text of the request on a card. Reads, edits or moves no other card. |
| `comments:write` | Declared, but not used: Keep writes no comment to Mesh. | Reads or writes no comment. |
| `secrets:write` | Declared, but Keep makes no call to Mesh under it. In the other direction, Mesh stores the values of its extension settings in Keep (`PUT` and `POST .../resolve` under `/orgs/{org_id}/mesh/secrets/{ref}`), signed with the install's events secret; Keep answers a write with `ref`, `version` and `fingerprint` only, and `resolve` with the stored value (the one exception above: rate limited, journaled before release, `Cache-Control: no-store`). | Pushes no secret value into Mesh on its own: a value leaves Keep for Mesh only as the answer to the workspace's signed `resolve` call. A workspace reaches only the refs it wrote itself. |

### Events

Keep receives events at `/mesh/events`, signed with the install's events
secret; each event is applied once.

| Event | What Keep does with it | What it does not do |
|---|---|---|
| `workspace.member.added` | Marks the member (user id, role) active in its mirror. | Creates no Keep user and grants no Keep role. |
| `workspace.member.removed` | Marks the member removed in its mirror. | Deletes no secret or access that hangs off the member. |
| `project.created` | Adds the project (id, slug, name, archived) to its mirror. | Creates nothing in Keep's catalog. |
| `project.updated` | Updates the project's slug, name or archived flag in its mirror. | Deletes no project or secret. |
| `agent.key.issued` | Records the agent and the key's id and label as active. | Never receives or stores the key's secret part. |
| `agent.key.revoked` | Marks the key revoked in its mirror. | Revokes nothing itself. |
| `task.gate.decided` | Applies the answer on a confirmation card it opened: approve or reject, only from a person, never the one who asked, only someone allowed to approve in the secret's scope, only for the request whose hash the card carries, only once. Any other answer changes nothing. | Keeps, logs or returns no free text of the decision. Acts on no card it did not open. |

### Network

`{settings.keep_url}` only: the Keep server's own API (install handshake,
events, the secrets screen, token exchange). Keep's extension declares no
other domain.

### UI

| Slot | What it shows | What it does not do |
|---|---|---|
| `sidebar.item` | The `Keep` item, opening `/mesh/ui/secrets` in a frame: secrets of the organization and of the signed-in user by name, scope, class, version, fingerprint, length and status. Organization admins can change the organization key level there. | Never renders a value. |
| `workspace.settings` | Mesh's settings form for the workspace setting `approvals_via_mesh`. Keep does not read this setting yet: confirmation cards are switched on by the server's own settings (`KEEP_MESH_*`). | Holds no secret value. |

## Accounts

Keep needs no third-party account. Access is through Keep's own
credentials: an organization administrator token, per-host runner
certificates issued at enrollment, and agent tokens. The Mesh integration
uses a Mesh service account in the workspace it is installed in; Telegram
notifications use a bot token supplied by the operator. Both are optional.

## Telemetry

None. Keep does not collect usage data or send anything to its authors.
Logs stay on the operator's hosts and never contain secret values.

## Runner registration

An organization administrator issues a token with `keep runner enroll-token
--host <hostname> --policy <policy.json> --uid-shared=false`. The administrator
must explicitly assert whether agents and consumers share a UID; use
`--uid-shared=true` when they do. Optional `--environment` and `--platform`
labels accept `development|staging|production` and `linux|darwin` respectively.
The token is bound to that host
and the exact policy file, expires within 15 minutes, and can be redeemed
once. Its issuance and use are audited. Only its hash is stored in the database.
The administrator CLI reads its bearer credential from `KEEP_ADMIN_TOKEN`.
Transfer the enrollment token through a private channel into
`keep-runner enroll`'s stdin; do not put it in command arguments or logs.

On the host, run `keep-runner enroll --host <hostname> --policy <policy.json>
--server https://<server>:8443 --server-ca <listener-ca.pem>` as the dedicated
`keep` account (`_keep` on macOS). The private key is generated on the host;
the server receives only a CSR. The server issues a 30-day client certificate.
`--server-ca` verifies the server listener during bootstrap; the organization
CA and job-signing public key returned at enrollment are pinned separately.
The runner generates a separate X25519 delivery key on the host. Its private
key is stored at mode 0600; enrollment sends only its public key. A legacy
runner without this key can still authenticate and renew, but cannot receive
a deployment value. An enrollment token without the UID assertion leaves the
host attributes unknown and cannot authorize a production deployment.
Both CLIs refuse HTTP URLs and redirects.

The server requires both `KEEP_SERVER_TLS_CERT_FILE` and
`KEEP_SERVER_TLS_KEY_FILE` for its runner listener. For local development only,
`KEEP_DEV_EPHEMERAL_TLS=1` permits a temporary self-signed listener
certificate and emits a warning. An incomplete certificate/key pair is always
rejected.

The authenticated organization CA cache is local to each server process. If
another instance enrolls a new organization, restart this instance to load
that CA before accepting its runner certificates.

Credential files are written atomically with mode 0600. Keep the local policy
at mode 0600 with the same owner, and run `keep-runner check --policy
<policy.json>` as that account before operating the host. It refuses symlinks,
broad permissions, another owner's files, or mismatched key/certificate pairs.
Use `--cred-dir` to select a credential directory in both runner commands.

`POST /runners/renew` uses the current client certificate to determine the
organization, runner, and host. `keep runner revoke <runner_id>` revokes a
runner immediately: its next mTLS request is refused. Request bodies and
headers cannot select another organization.

The server login role must be a member of `keep_app` so audit writes can
switch to the restricted journal role. If migrations run as a separate
administrator, grant `keep_app` to the server login role explicitly.

Configure a persistent root-key file using `KEEP_ROOT_KEY_FILE` and
`KEEP_ROOT_KEY_ID` on the server. The file holds 32 raw bytes or their standard
base64 encoding, is owned by the server account, and has mode 0600. A 32-character
file that is also valid base64 is ambiguous and refused; encode a 32-byte root
as standard base64 (44 characters) to make the format explicit. Serving requires this file;
an all-zero key is refused. Keep the key and its identifier stable across
restarts. Startup authenticates existing organization CA and job-signing
material before opening listeners. A damaged organization's CA is withheld
from runner authentication while healthy organizations continue serving. If
none of the existing CAs authenticate, startup refuses to serve. The v2
enrollment envelopes bind the entire public material;
unbound v1 envelopes from pre-release development instances are refused.

## Database requirements

`keep-server` needs PostgreSQL 17 and refuses to start unless the
database is set up so that nothing it does can end up in PostgreSQL's own
server log. That covers three independent things:

**Server-log settings.** With the defaults, a statement that violates a
constraint is logged with the full row (`DETAIL: Failing row contains
...`) and the statement text (`STATEMENT: ...`); a statement that runs
long, or one duration-sampled or transaction-sampled at random, is logged
with its parameter values regardless of whether it failed. Run once, as
a superuser:

```sql
ALTER DATABASE keep SET log_error_verbosity = terse;
ALTER DATABASE keep SET log_min_error_statement = panic;
ALTER DATABASE keep SET log_statement = 'none';   -- or 'ddl'
ALTER DATABASE keep SET log_min_duration_statement = -1;
ALTER DATABASE keep SET log_min_duration_sample = -1;
ALTER DATABASE keep SET log_transaction_sample_rate = 0;
ALTER DATABASE keep SET log_min_messages = 'panic';   -- or 'fatal'
ALTER DATABASE keep SET auto_explain.log_min_duration = -1;   -- if loaded
```

These settings do not cover the primary error message, which still
quotes a value PostgreSQL could not parse. Nor, on their own, do they
cover `debug_print_plan`/`debug_print_parse`/`debug_print_rewritten`:
those three are session-settable by any role, with no grant needed, so
checking they're off at startup only catches what's already set
database-wide. `log_min_messages` raised this high is the actual
defense — it suppresses all `LOG`-severity output, `debug_print_*`'s
included, no matter which session turns one on afterwards.

If the `auto_explain` extension is preloaded (a standard choice for
diagnosing slow queries — `shared_preload_libraries`), it writes a
statement's execution plan to the server log once `log_min_duration` is
crossed, with each bound parameter's value inlined as a literal by the
planner itself, before `auto_explain` ever prints it — independent of
every statement-logging setting above, since it hooks the
planner/executor directly, not PostgreSQL's own statement-logging path.
`auto_explain.log_parameter_max_length = 0` does not close this: it only
truncates the separate `Query Parameters:` line `auto_explain` also
prints, not the `Filter:`/similar line the value was already inlined
into. The `log_min_messages` requirement above is still the first
barrier here too — auto_explain's own output is filtered by the same
message severity, so `panic`/`fatal` already suppresses it. `keep-server`
additionally refuses to start if `auto_explain.log_min_duration` is set
to anything other than `-1` (its own default) as a second barrier, in
case `log_min_messages` is ever loosened; the extension not being loaded
at all is accepted, since there is then nothing to disable.

**Connection string.** `KEEP_DATABASE_URL` must not set
`default_query_exec_mode=simple_protocol` or `=exec`. Both hand pgx's
query parameters to the server as text inside the statement or bind
message instead of the extended protocol's typed wire format, which the
settings above cannot stop from reaching the log.

**Role.** `keep-server` must connect as a role without PostgreSQL
superuser rights, and without membership — direct, or reachable through
any chain of `pg_auth_members`, not only the roles usable right now via
`SET ROLE` or automatic inheritance — in a role that has them: a
superuser can run `SET` on its own session at any time, undoing every
setting above for the rest of that connection, and so can a role that
only reaches superuser rights through a membership chain, even one
granted `ADMIN` only, since `ADMIN OPTION` lets the holder re-grant
itself `SET`-capable membership and then `SET ROLE` straight through.
The same reachability applies to two further ways a role can undo the
settings above without `rolsuper` ever being set:

- Membership in the built-in roles `pg_execute_server_program` or
  `pg_write_server_files`, which let a role run an arbitrary program, or
  write an arbitrary file, as the operating-system user the server
  process itself runs as — opening its own admin connection to Postgres
  entirely outside SQL. Reported as a distinct error from a superuser
  rights refusal, since the two are undone differently.
  `pg_read_server_files` is deliberately not checked: it can read any
  file the server's OS user can, including `postgresql.auto.conf`,
  `pg_hba.conf` and the server log itself — a real disclosure risk, but
  not a way to reset a setting this check exists to protect.
- `GRANT SET ON PARAMETER` or `GRANT ALTER SYSTEM ON PARAMETER`
  (both PostgreSQL 15+) on any of the settings above: either lets a role
  change or reset the setting without ever holding superuser rights.

Migrations (`keep-server migrate up`) and any admin tooling may still use
a superuser; only the role the server itself serves as, and every role
reachable from it, must not.

All three checks run at startup only: restart `keep-server` after
changing any of them.

**Sessions.** `keep-server` holds PostgreSQL session advisory locks, so
it needs a session to the database: connect directly or through a pooler
in session mode, never in transaction mode. Besides its connection pool
each instance keeps one more connection open for the claims of key-level
changes; count it in `max_connections`. Several instances may share one
database.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the rules this project holds
non-negotiable, starting with: a secret's value never enters a log, a
test, an API response, or an error.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

### Input links

`keep input-link <secret> --ttl 30m` issues a single-use delivery capability
for a builtin secret. The server accepts only HPKE ciphertext at `POST
/input/{token}`; the authenticated issuer can read `{version,fingerprint}`
at `GET /v1/input-links/{request_id}`. Issuance requires rotation permission.
The default lifetime is 30 minutes, with a maximum of 24 hours. Consumed and
expired capabilities return 410. Tokens are stored as SHA-256 hashes; the
journal, sealed version and capability transition commit together.

Enable the intake backend with `KEEP_PUBLIC_URL` (HTTPS, or HTTP on loopback)
and `KEEP_ROOT_KEY_FILE`, a persistent 32-byte file owned by the server
user with mode 0600 (raw bytes or standard base64). The server loads this
one root once for both builtin values and organization PKI. PKI uses a
separate `pki:` KEK domain, isolated from value key-level changes and purge.
Without a public URL, intake issuance remains unavailable. Existing
root-key files must be preserved across restarts. Migration 00009 enforces
one builtin store per owner scope, including disabled stores; existing
namespace and envelope AAD stay unchanged. Migration 00010 adds the intake
capability table and audit actions. Downgrading past intake audit events is
refused so the journal cannot be erased.

The token travels in the URL path, so the front proxy must not log
`/input/*` request lines (access logs would otherwise retain live tokens).

The browser input page is a separate integration; this backend change does
not register a `GET /input/{token}` page yet.
