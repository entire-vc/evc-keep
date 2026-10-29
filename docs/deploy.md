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

## Upgrade

1. Back up the database (`pg_dump -Fc`) and note the current image tag or
   binary version. The root key is not part of this backup.
2. `keep-server migrate status` with the **new** binary.
3. `migrate up` with the new binary.
4. Replace the container or binary and restart; run the health checks.

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
release, because they hold the `Down` steps:

```sh
git checkout <newer-release-tag>
go install github.com/pressly/goose/v3/cmd/goose@v3.27.0   # once; put it on root's PATH
sudo sh -c 'set -a; . /etc/keep/keep-server.env; \
  GOOSE_DRIVER=postgres GOOSE_DBSTRING="$KEEP_DATABASE_URL" \
  exec goose -dir internal/store/migrations down-to <version>'
```

The connection URL carries the database password, so it reaches goose through
`GOOSE_DBSTRING` in its environment and never as a command-line argument, where
any local user could read it in the process list.

`<version>` is the schema version the older binary required (its
`migrate status` output). Rehearse the downgrade on a restored copy of the
backup first: a downgrade that drops a column drops its data.

**Restore.** If the downgrade is unsafe or fails, stop the server, restore the
`pg_dump` taken in step 1 of the upgrade into the database, and start the
older binary or image. Anything written after that backup is lost.

After any rollback run the health checks and `keep-server migrate status`.

## Backup

`pg_dump -Fc` of the Keep database on a schedule, restored periodically into
a scratch database to prove it works. Back the root key file up separately.
A database backup without the root key restores the catalog but none of the
sealed values.
