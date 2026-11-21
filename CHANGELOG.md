# Changelog

Notable changes of each Keep release. The GitLab release of a tag takes its
description from the section of that tag here (`scripts/changelog-section.sh`).
Releases before 0.7.0 are listed only by their tags.

## [0.7.0]

Keep is pre-alpha: interfaces can still change between minor releases. The
changes below are everything merged since 0.6.5.

### Breaking changes

- `keep-server` takes the lanes the restart queue accepts from
  `KEEP_RESTART_LANES` (comma-separated). There is no built-in list any more:
  unset or empty, every restart request is refused and the start logs one line
  naming the variable. Set it before rolling out this release
  ([docs/restart-queue.md](docs/restart-queue.md)).
- `keep` prints a fixed text for each error class instead of the server's
  message, and `keep --debug` prints only allow-listed HTTP header names, never
  header values. Scripts that parsed server messages from CLI output should
  read `error_class` instead.
- `keep-runner enroll` accepts only a canonical lowercase UUID as `runner_id`,
  exactly one JSON document in an answer, and at most 4096 bytes of token on
  stdin. `keep login` and `--token-file` cap their input at 4096 bytes too.
- Local files the CLI and the runner read (`--token-file`, `-policy`,
  `-server-ca`, runner credentials, outbox entries, the replay journal) must be
  regular files of bounded size: a FIFO, a device or an oversized file is
  refused instead of blocking or being truncated.

### Carriers

- Carrier discovery: `keep carriers discover --runner ID --store ID` asks one
  enrolled runner to scan its own host under its local host policy and compare
  what it finds with the carrier registry. Every finding is `match`, `stale`,
  `sprawl` or `unknown_find`, with path, name and a keyed fingerprint, never a
  value or its length. An `unknown_find`, and a `sprawl` holding a value the
  store issued, open an incident for a person; nothing is rotated by itself.
  Reports are read in pages (`GET /orgs/{org_id}/carriers/discover/{request_id}?offset=N`)
  ([docs/carrier-discovery.md](docs/carrier-discovery.md)).
- An `mcp-config` carrier is matched by the variable a scan reports.

### Rotation

- Two-phase rotation (the MCP `rotate` tool and `POST .../rotate`: lay the new
  version out on every carrier, check each carrier's fingerprint, then retire
  the old one) now rolls a failed run back: the previous version stays live, a
  Mesh agent key issued during the run is revoked, and the run's terminal
  answer carries `incident_opened: true` when it opened an incident for a
  person.
- Mesh agent keys as a rotation source (Mesh build): a secret bound to a Mesh
  agent is rotated by the ordinary `rotate` request (and the MCP `rotate`
  tool), which issues the new key through the Mesh agent-keys API and revokes
  the old one only after every carrier confirmed. Configured with
  `KEEP_MESH_ROTATE_URL`, `KEEP_MESH_ROTATE_TOKEN_FILE` and
  `KEEP_MESH_ROTATE_BINDINGS`, all or none ([docs/deploy.md](docs/deploy.md)).
- A `systemd-credential` carrier is verified under the unit of its last deploy.
- The keep-rotator service account connects through its own install window,
  bound separately from the `keep` installation and with its own rate-limit
  budgets ([docs/mesh-extension.md](docs/mesh-extension.md)).

### Mesh integration

- The embedded interface lists secrets with search, filters and carrier status.
  Each secret has a detail page with carriers, versions and recent rotations;
  the paginated rotation history links to each run's carrier phases and outcome.
  Active runs refresh in place until they finish. These pages show metadata only.
- Keep applies the workspace setting `approvals_via_mesh` per workspace: on
  (the default), a request that needs a person's approval opens a confirmation
  card in Mesh; off, it is approved in Keep's own console (with a Telegram
  notice for a deploy approval when one is configured) and no card is opened.
- The `keep` manifest no longer asks for `comments:write` and `secrets:write`:
  Keep makes no call to Mesh under either. Mesh storing its extension settings
  in Keep is Keep's own signed API and needs no right in Mesh.
- Metadata probe `GET /orgs/{org_id}/mesh/secrets/{ref}/metadata`: Mesh learns
  the version and length of a stored setting without the value; every verified
  call is journaled (`mesh.secret.metadata`).
- A same-organization store binding is upgraded to the extension on the Mesh
  handshake, keeping its events secret.

### Server and operations

- `keep-server offline-transfer` moves one organization (builtin-store secrets,
  CA, audit chain) between two installations over files, with KEKs rewrapped to
  the target's independent root ([docs/offline-transfer.md](docs/offline-transfer.md)).
- `keep-server issue-admin-token` issues a new admin token for an existing
  admin of an existing organization ([docs/bootstrap-org.md](docs/bootstrap-org.md)).
- `GET /input/{token}` serves the browser input page: the value is encrypted in
  the browser and only the ciphertext reaches the server.
- A quickstart for one Linux host ([docs/quickstart.md](docs/quickstart.md)),
  run verbatim by CI.
- Upgrade from 0.6.5 and rollback, as written in [docs/deploy.md](docs/deploy.md),
  run by CI.
- `keep deploy` and the MCP `deploy` tool validate the answer's version,
  approval metadata, `request_id` and health-check status before printing it.

### Extension manifest

- `mesh-extension.json` version 0.7.0. `mesh-extension.keep-rotator.json`
  stays at 0.1.0: its manifest is unchanged since that release.
