# Deploying keep-server

This runbook covers a production deployment, an upgrade and a rollback. It
names configuration variables only; values live in an env file on the host
and never in this repository, in a command line, or in a log.

## What you deploy

One binary, `keep-server`, built either as the container image from the
`Dockerfile` or installed at `/usr/local/bin/keep-server` and run by the
systemd unit `deploy/keep-server.service`. It needs PostgreSQL 17 prepared as
described under "Database requirements" in the README, and it listens on two
ports:

| Port | Serves | Who reaches it |
|---|---|---|
| `8080` (`KEEP_HTTP_ADDR`) | `/healthz`, `/readyz` only | the proxy, the orchestrator |
| `8443` (`KEEP_RUNNER_ADDR`) | the TLS listener for runners | runners |

The image has two variants, picked by the build argument `SERVER_VARIANT`:
`core` (the default, `cmd/keep-server`, no Mesh code) and `mesh`
(`plugins/mesh/cmd/keep-server`, the server with the Mesh plugin):

```bash
docker build -t keep-server .
docker build --build-arg SERVER_VARIANT=mesh -t keep-server:mesh .
```

### Sealing the Mesh service token without rotation (mesh build)

With `KEEP_MESH_EXTENSION` set to `1`, `KEEP_MESH_SVC_BOOTSTRAP_FILE` (absolute path,
regular file, mode `0600`) and `KEEP_MESH_SELF_ROTATE_ORG_ID`, and with
`KEEP_MESH_SELF_ROTATE` unset, the server seals the token from the file into
that organisation's store at start and does not rotate it: no call to Mesh, no
hook. The log line names the secret, its version, fingerprint and length. A
restart over a sealed token seals nothing new and no longer needs the file;
delete it once the line is logged. `KEEP_MESH_SELF_ROTATE_HOOK` and
`KEEP_MESH_SELF_ROTATE_INTERVAL` are refused in this mode. The core build
refuses to start with these variables.

### Rotating Mesh agent keys (mesh build)

By default `POST /orgs/{org}/secrets/{id}/rotate` with `mode: generate`
produces a random value. A secret that stands for a Mesh agent key is bound to
its agent instead, and the same request then issues a new key for that agent
through the Mesh agent-keys API, lays it out on the carriers, checks each
carrier's fingerprint, and revokes the old key only after every carrier
confirmed. A failed carrier keeps the old key and opens an incident.

Three variables, all or none (a part set stops the start):

| Variable | Meaning |
|---|---|
| `KEEP_MESH_ROTATE_URL` | base address of the Mesh whose agent keys are rotated (https, or http to loopback) |
| `KEEP_MESH_ROTATE_TOKEN_FILE` | absolute path, regular file, mode `0600`, holding the service token with the `agent_key:rotate` right; read on every call |
| `KEEP_MESH_ROTATE_BINDINGS` | regular file, JSON `{"<secret id>": "<agent id>"}`, canonical lowercase UUIDs only; read on every call |

A secret that is not in the bindings file keeps the generated value and is
never sent to Mesh. An unreadable bindings file fails the run closed. The core
build does not import the Mesh plugin and refuses to start, before it opens the
database, if any of the three variables is set.

TLS for clients is terminated by an external reverse proxy (for example
Caddy); `KEEP_PUBLIC_URL` is the https URL clients use through it. The
server's own TLS listener (`8443`) uses the certificate named by
`KEEP_SERVER_TLS_CERT_FILE` and `KEEP_SERVER_TLS_KEY_FILE`.

### The proxy must name the client

The Mesh calls that are not yet authenticated (`POST /mesh/events`, the signed
`/orgs/{org_id}/mesh/secrets/...` calls, the install handshake,
`POST /mesh/token` and `POST /mesh/session`) share a budget per client address: 120 a minute with a
burst of 30, and a call that authenticates gets its token back. The client is
the TCP peer, so behind a reverse proxy name the proxy:

```
KEEP_TRUSTED_PROXIES=127.0.0.1/32
```

From a peer in that list (comma-separated CIDR) the client is the rightmost
`X-Forwarded-For` address outside it; from any other peer the header is
ignored. Without it every caller arrives from the proxy's address and shares
one budget, so a flood of bad signatures refuses everyone, Mesh included; the
server logs a warning the first time a Mesh call comes from a loopback peer
while the list is empty. The proxy must append the peer to
`X-Forwarded-For` (Caddy and nginx with
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` do).

### The proxy must pass the original Host

Whatever the proxy forwards to either listener, it must send the client's own
`Host` header upstream, not the upstream's address. Every state-changing
browser request (the console's `POST /console/*`, the Mesh screen's
`POST /mesh/session` and `POST /mesh/ui/*`) is checked for same origin: an
`Origin` header that names a host must name the host in `Host`. The server
reads `Host` only; `X-Forwarded-Host` and `Forwarded` are ignored on purpose,
since a client can set them. A proxy that rewrites `Host` to its upstream
makes every request whose `Origin` names the public host fail with 403
(`permission_denied` from the JSON endpoints, an error page from the forms),
while pages still load and `/healthz` stays green. A request that arrives
with `Origin: null` and `Sec-Fetch-Site: same-origin` is judged without
`Host` and still passes, so the breakage can look partial.

An HTTPS upstream is where this usually goes wrong: proxy setups for TLS
upstreams commonly set `Host` to the upstream's address so the handshake and
the certificate name match. Keep `Host` as the client sent it, and name the
server certificate's host for the TLS handshake separately:

```caddyfile
keep.example.com {
	reverse_proxy /healthz 127.0.0.1:8080
	reverse_proxy /readyz 127.0.0.1:8080
	reverse_proxy https://127.0.0.1:8443 {
		header_up Host {host}
		transport http {
			tls_server_name keep.example.com
			tls_trusted_ca_certs /etc/caddy/keep-ca.pem
		}
	}
}
```

`tls_server_name` must match a name in the certificate from
`KEEP_SERVER_TLS_CERT_FILE`; `tls_trusted_ca_certs` is the CA that signed it.
Do not replace them with `tls_insecure_skip_verify`. The nginx equivalent:

```nginx
location / {
	proxy_pass https://127.0.0.1:8443;
	proxy_set_header Host $host;
	proxy_ssl_server_name on;
	proxy_ssl_name keep.example.com;
	proxy_ssl_verify on;
	proxy_ssl_trusted_certificate /etc/nginx/keep-ca.pem;
}
```

Without `proxy_ssl_server_name on` nginx sends no SNI, and without
`proxy_ssl_verify on` it does not check the certificate at all.

To check (mesh build), post an empty body from the public origin: the answer
must be 400 `invalid_argument`, not 403:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Origin: https://keep.example.com' -H 'Content-Type: application/json' \
  -d '{}' https://keep.example.com/mesh/session
```

## Configuration

The only configuration source is the environment. `deploy/keep-server.env.example`
lists every variable name with an empty value:

| Name | Required | Notes |
|---|---|---|
| `KEEP_DATABASE_URL` | yes | connection URL, carries the database password |
| `KEEP_ROOT_KEY_FILE` | to serve | path to the sealer root key file |
| `KEEP_ROOT_KEY_ID` | no | defaults to `local-v1`; do not change after first start |
| `KEEP_PUBLIC_URL` | yes in production | public https URL |
| `KEEP_SERVER_TLS_CERT_FILE`, `KEEP_SERVER_TLS_KEY_FILE` | yes | both, or the server refuses to start |
| `KEEP_HTTP_ADDR`, `KEEP_RUNNER_ADDR` | no | `:8080`, `:8443` |

Create the env file as root, mode `0600`, outside any repository. Generate the
root key on the host (32 random bytes) and store it as a regular file (not a
symlink) with mode exactly `0600`, owned by the user the server runs as. The
server refuses to start on any other mode or owner (`root key: builtin: local
root key unavailable or insecure`). In a container, the mounted file must be
owned by uid 10001.

**The root key lives outside the database and outside database backups.**
Keep it in a separate, access-controlled place with its own backup. Losing it
makes every sealed secret unrecoverable; storing it next to the database
backup defeats the sealing.

Never print the environment, the env file or the key file when debugging
(`env`, `cat`, `docker inspect`, `systemctl show -p Environment`). If a value
was printed anywhere, rotate it.

## First deployment

1. Prepare PostgreSQL per the README, create the database and a role
   without superuser rights (the server refuses to run as a superuser). The
   role that runs `migrate up` must be able to create roles: migration 00005
   creates the `keep_app` journal role and grants it to the migrating role,
   which the server later switches to. The tested setup is one non-superuser
   role with `CREATEROLE` that both migrates and serves.
2. Write the env file and the root key file.
3. Apply migrations. The server never migrates on its own:

   ```sh
   # container
   docker run --rm --env-file /etc/keep/keep-server.env keep-server migrate up
   # systemd: root reads the 0600 env file, then drops to the keep user
   sudo sh -c 'set -a; . /etc/keep/keep-server.env; exec setpriv --reuid=keep --regid=keep --clear-groups keep-server migrate up'
   ```

   `keep-server migrate status` shows the applied and required versions. A
   server whose schema is behind its binary exits at start with a pointer to
   `migrate up`.
4. Start it. Container:

   ```sh
   docker run -d --name keep-server --restart unless-stopped \
     --env-file /etc/keep/keep-server.env \
     -v /etc/keep/root.key:/etc/keep/root.key:ro \
     -v /etc/keep/tls:/etc/keep/tls:ro \
     -p 127.0.0.1:8080:8080 -p 8443:8443 keep-server
   ```

   `KEEP_ROOT_KEY_FILE` and the TLS variables then hold the in-container paths.
   Systemd: install the unit, `systemctl daemon-reload`,
   `systemctl enable --now keep-server`.
5. Point the proxy at `127.0.0.1:8080` for the public hostname.

## Health

- `GET /healthz` is 200 while the process is serving. It never touches the
  database. The image's `HEALTHCHECK` uses it.
- `GET /readyz` is 200 only while the database answers a ping, otherwise 503
  `{"error_class":"not_ready",...}`. Use it for proxy and orchestrator
  readiness. Do not use it to restart the process: a database outage is not
  fixed by a restart.
- `GET /version` is 200 with `{"commit": "<40-hex or unknown>", "build_time":
  "<RFC 3339 or empty>"}` and nothing else. It needs no credentials, never
  touches the database and is not cached. It tells you which commit is live.

The commit comes from the build, not from the environment. `make build` injects
it. When you build the image from a source archive (no `.git`), pass it in or
`/version` reports `unknown`:

```sh
docker build -t keep-server \
  --build-arg BUILD_COMMIT=<full 40-hex commit> \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) .
```

A value that is not a full lowercase 40-hex commit is reported as `unknown`
rather than echoed.

After a deploy, check both through the proxy and directly:

```sh
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/healthz
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/version
```

### The published Mesh image and its receipt

A push to the default branch that passes the whole pipeline and whose commit is
named by the protected variable `KEEP_MESH_IMAGE_WRITE_SHA` (see "Default is
auth-only" below; an ordinary push only verifies authorization and writes
nothing) publishes the Mesh variant (`SERVER_VARIANT=mesh`, linux/amd64) to the
project's private container registry, from that exact commit:

```
<registry>/entire-vc/evc-keep/keep-server-mesh:<full 40-hex commit>
```

The commit is the only tag; there is no `latest`. The publish job refuses to push when that tag already exists (the check and the push are one serialized job), so a published reference is never moved. Merge requests, schedules,
tags and manual pipelines never publish. The same pipeline pulls the image back
by its digest, takes the `keep-server` binary out of it, starts that binary
against a scratch database and compares `GET /version` with the commit. The job
`image-receipt-mesh` keeps `mesh-image-receipt.json` for a year:

```json
{"schema": "keep-mesh-image-receipt/1", "source_sha": "<commit>", "variant": "mesh",
 "platform": "linux/amd64", "pipeline_id": 0, "publish_job_id": 0, "pull_job_id": 0,
 "receipt_job_id": 0, "build_time": "<RFC 3339>",
 "image": {"repository": "...", "tag": "<commit>", "reference": "...:<commit>",
           "digest": "sha256:...", "by_digest": "...@sha256:..."},
 "elf": {"path": "usr/local/bin/keep-server", "sha256": "...",
         "main_package": "github.com/entire-vc/evc-keep/plugins/mesh/cmd/keep-server", "machine": "x86_64"},
 "runtime": {"commit": "<commit>", "build_time": "<RFC 3339>"}}
```

It holds names, ids and digests only; no configuration value reaches it.

Verify it yourself, with a registry login that can read the project
(`crane auth login`) and `crane` from go-containerregistry:

```sh
R=mesh-image-receipt.json
python3 scripts/mesh_image_receipt.py verify "$R" --source-sha <commit>   # consistency
ref=$(jq -r .image.by_digest "$R")
crane digest "$(jq -r .image.reference "$R")"                             # tag still -> the digest
crane manifest "$ref" | sha256sum                                         # equals the digest
crane export "$ref" - | tar -xO usr/local/bin/keep-server | sha256sum     # equals .elf.sha256
```

Pull and run the image by digest, never by tag: `docker pull "$ref"`.

Publish authorization. One probe, `scripts/registry_auth_probe.py`, runs in two
places. `image-publish-mesh` runs it as `allow` before the opt-in and before any
write; merge request pipelines run it as `deny` in `image-auth-deny-mesh`. It
asks the CI server who the job is (`/api/v4/job`: job name, pipeline source,
project, actor; the `CI_*` variables are only compared with it, never trusted)
and asks the registry token service for the scopes `pull`, `pull,push`,
`pull,delete` and `pull,*` on exactly the Mesh repository. Every token must keep
`pull` (the credential is accepted) and must not carry the wildcard. `allow`:
the server says this is `image-publish-mesh` of a push pipeline of this project
and push is granted; delete is only reported (it follows the native rights).
`deny`: the server says this is the merge request probe job and neither push nor
delete is granted. A failed, redirected, unauthenticated, malformed or foreign
answer is neither an allow nor a deny and fails the job. The probe writes
nothing and prints only the server-side context, repository and decisions,
never a token, header or raw answer. The publisher job runs on the pinned
python image with `crane` taken from `image-crane-mesh`, which copies it out of
the pinned crane image; the publisher checks its sha256 before use. This relies
on the registry-side policy that grants push only to the trusted publisher job
of the protected default-branch push pipeline.

Default is auth-only. After the authorization check the publish job stops with
success unless the protected project variable `KEEP_MESH_IMAGE_WRITE_SHA` equals
the full commit being published. Absent, empty, malformed or another commit's
value (a stale opt-in included) writes only `mesh-image-auth-only.json`: no
image, no digest, no receipt; the pull and receipt jobs then do nothing. To
publish a commit, set the variable to its full SHA and retry `image-publish-mesh`
in that commit's push pipeline. An auth-only run is not an image receipt.

Rollback: revert the commit that added the `image-publish-mesh`,
`image-pull-mesh` and `image-receipt-mesh` jobs, which stops new references from
being issued. An image that is already installed and its data are not touched.

## Upgrade

Every fenced block below that follows an `exec:` marker is run, as written, by
`scripts/check-upgrade-rollback.sh` in CI (0.6.5 to the current commit and
back, against a real PostgreSQL). If you change a step here, that job tells
you whether the new text still works.

The blocks are plain `sh`, and every step that must not run after a failure is
chained to the one before it with `&&`, so they stop at the first error whether
or not your shell runs with `set -e` or `pipefail`. libpq takes the URL as a
command-line argument, so the database password is visible in the process list
for the length of a `pg_dump` or `psql`; run them on a host where only the
service account can list processes, or use a role for backups that is not the
application role.

1. Back up the database (`pg_dump -Fc`) and note the current image tag or
   binary version. The root key is not part of this backup. The blocks below
   take the connection from the env file (`ENV_FILE`, default
   `/etc/keep/keep-server.env`) and hand `KEEP_DATABASE_URL` to libpq as it is,
   so a backup or a restore reaches the database the server uses and no other.
2. `keep-server migrate status` with the **new** binary. It exits 1 while the
   schema is behind the binary, which is what you expect before the upgrade.
3. `migrate up` with the new binary.
4. Replace the container or binary and restart; run the health checks.

<!-- exec:upgrade -->
```sh
BACKUP_DIR=${BACKUP_DIR:-/var/backups/keep}
ENV_FILE=${ENV_FILE:-/etc/keep/keep-server.env}
set -a; . "$ENV_FILE"; set +a   # the same 0600 env file the server runs with
# libpq reads KEEP_DATABASE_URL as it is (host, port, sslmode and every other
# option in it), so the dump reaches the database the server uses and no other.
# ${...:?} stops here if the URL is empty: without it libpq would fall back to
# its defaults and dump whatever database that is.
db=${KEEP_DATABASE_URL:?KEEP_DATABASE_URL is not set in the env file}
# Each step runs only if the one before it succeeded, in any shell.
pg_dump -Fc -d "$db" -f "$BACKUP_DIR/keep-pre-upgrade.dump" &&
  curl -fsS "${KEEP_LOCAL_URL:-http://127.0.0.1:8080}/version" &&   # the commit being replaced
  { keep-server migrate status || true; } &&   # new binary; exit 1 = behind, expected here
  keep-server migrate up &&
  systemctl restart keep-server        # or: replace the container and start it
```

Migrations are applied under a database lock, so running `migrate up` twice
at once is safe.

## Rollback

Decide before you upgrade which kind of rollback you can afford.

**Binary or image only.** Use this when the upgrade applied no migration.
Start the previous image tag or reinstall the previous binary and run the
health checks. If the upgrade did apply migrations, the older binary runs
against a newer schema; do that only if those migrations were additive and
you have confirmed the older release works with them, otherwise use the next
path.

**Binary and schema.** Roll the schema down to the version the older binary
requires, then start the older binary. `keep-server` has no `migrate down`
command; use the goose command-line tool against the migrations of the *newer*
release, because they hold the `Down` steps. Run it from a checkout of the
newer release tag (`git checkout <newer-release-tag>`), with the server
stopped:

<!-- exec:rollback -->
```sh
ENV_FILE=${ENV_FILE:-/etc/keep/keep-server.env}
go install github.com/pressly/goose/v3/cmd/goose@v3.27.0 &&   # once; put it on root's PATH
  systemctl stop keep-server &&
  sudo sh -c 'set -a; . "$1"; \
    GOOSE_DRIVER=postgres GOOSE_DBSTRING="$KEEP_DATABASE_URL" \
    exec goose -dir internal/store/migrations down-to "$2"' sh "$ENV_FILE" "$OLDER_SCHEMA_VERSION" &&
  # now install the older binary and start it
  systemctl start keep-server
```

`OLDER_SCHEMA_VERSION` is the schema version the older binary required (its
`migrate status` output). The connection URL carries the database password, so
it reaches goose through `GOOSE_DBSTRING` in its environment and never as a
command-line argument, where any local user could read it in the process list.

Rehearse the downgrade on a restored copy of the backup first: a downgrade
that drops a column drops its data.

**Restore.** If the downgrade is unsafe or fails, stop the server, restore the
`pg_dump` taken in step 1 of the upgrade into an empty schema (restoring over
the newer schema would leave the tables the newer release added), and start the
older binary or image. The SQL it writes (`restore.sql`, mode 0600) holds the
whole database: delete it when the restore is verified. Anything written after that backup is lost.

<!-- exec:restore -->
```sh
BACKUP_DIR=${BACKUP_DIR:-/var/backups/keep}
ENV_FILE=${ENV_FILE:-/etc/keep/keep-server.env}
set -a; . "$ENV_FILE"; set +a   # the same 0600 env file the server runs with
db=${KEEP_DATABASE_URL:?KEEP_DATABASE_URL is not set in the env file}   # see Upgrade
umask 077
# The archive is converted to SQL first: a damaged or unreadable dump stops the
# sequence here, before the server is stopped or anything is dropped. Each later
# step runs only if the one before it succeeded, in any shell.
pg_restore --no-owner -f "$BACKUP_DIR/restore.sql" "$BACKUP_DIR/keep-pre-upgrade.dump" &&
  systemctl stop keep-server &&
  # an empty schema first: --clean would leave the tables the newer release added
  psql -v ON_ERROR_STOP=1 -d "$db" -c 'DROP SCHEMA public CASCADE' -c 'CREATE SCHEMA public' &&
  psql -v ON_ERROR_STOP=1 -q -d "$db" -f "$BACKUP_DIR/restore.sql" &&
  # now install the older binary and start it
  systemctl start keep-server
```

After any rollback run the health checks and `keep-server migrate status`.

## Backup

`pg_dump -Fc` of the Keep database on a schedule, restored periodically into
a scratch database to prove it works. Back the root key file up separately.
A database backup without the root key restores the catalog but none of the
sealed values.
