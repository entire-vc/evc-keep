# Quickstart: from nothing to a secret delivered to a host

This page takes one Linux host from an empty directory to a working delivery:
Keep built from source, a database, a server, an organization, a secret whose
value a person types into a browser, and a runner that writes that value into
a file and checks the service that reads it. Nothing in it is a mock. It is
for trying Keep out; a production setup is in [deploy.md](deploy.md) and
[bootstrap-org.md](bootstrap-org.md).

**The page is executed by CI.** The job `quickstart` extracts every block
marked `<!-- quickstart: ... -->` and runs it, verbatim, in a clean container.
The only things the job adds are the person typing the value (a headless
browser) and checks of the result. If a command here stops working, that job
fails. Every `sh` block on this page carries a marker.

**A secret's value never appears in this walkthrough.** The value goes from the
browser to the server encrypted and from the server to the runner encrypted.
No command below prints it, and neither should you: do not `cat` the target
file in a terminal an agent or a chat can read. The steps show only the name,
version, fingerprint and length.

## What you need

- A Linux host with systemd, and a user that can run `sudo` (the last service
  is a system unit).
- Go 1.25, `make`, `git`.
- Docker, to run PostgreSQL 17 (any PostgreSQL 17 you can reach works; see
  "Database requirements" in the [README](../README.md#database-requirements)).
- `psql`, `jq`, `curl`, `openssl`, `python3`.
- A web browser, for the one step only a person does.

Run every command from the repository root, in the order given. Each block
loads `~/keep-quickstart/env.sh`, written in step 3, so it also works in a
fresh terminal.

## 1. Get the source and build

Keep is distributed as source. `make build` writes `bin/keep`,
`bin/keep-server` and `bin/keep-runner`.

<!-- quickstart: clone ci-skip -->
```sh
git clone https://github.com/entire-vc/evc-keep.git && cd evc-keep
```

<!-- quickstart: build -->
```sh
make build
```

## 2. Prepare PostgreSQL 17

A throwaway local database. Its administrator password is for this container
on the loopback interface only; everything Keep itself uses is generated below.

<!-- quickstart: database ci-skip -->
```sh
docker run -d --name keep-quickstart-db -p 127.0.0.1:5432:5432 \
  -e POSTGRES_PASSWORD=keep-quickstart postgres:17
```

(The CI job has no Docker inside its container; it starts the same image as a
job service and points `PGHOST` at it.)

## 3. Environment file for this walkthrough

Everything lives under `~/keep-quickstart`, mode `0700`. `env.sh` holds the
paths and is sourced by every step. The PostgreSQL administrator connection is in
a separate `pg-admin.env`, sourced only by the step that creates the role, so the
server, the runner and `keep mcp` never see the administrator password.

<!-- quickstart: env -->
```sh
export QS="$HOME/keep-quickstart"
umask 077
mkdir -p "$QS"
cat > "$QS/env.sh" <<EOF
export QS="$QS"
umask 077
export PATH="$PWD/bin:\$PATH"
export PGHOST="${PGHOST:-127.0.0.1}"
export KEEP_SERVER=http://127.0.0.1:8080
EOF
echo 'export PGUSER=postgres PGPASSWORD=keep-quickstart' > "$QS/pg-admin.env"
```

<!-- quickstart: db-wait -->
```sh
. "$HOME/keep-quickstart/env.sh"
until pg_isready -q; do sleep 1; done
```

## 4. Database role and settings

`keep-server` refuses to start unless the database is set up so that nothing it
does can reach PostgreSQL's own log (README, "Database requirements"). This
block creates a role without superuser rights, with a generated password, and
applies the settings the server checks. The password goes into a file, not onto
a command line.

<!-- quickstart: database-setup -->
```sh
. "$HOME/keep-quickstart/env.sh"
. "$QS/pg-admin.env"
openssl rand -hex 16 > "$QS/db.pw"
printf "CREATE ROLE keep LOGIN CREATEROLE PASSWORD '%s';\n" "$(cat "$QS/db.pw")" | psql -v ON_ERROR_STOP=1 -q
psql -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE keep OWNER keep"
psql -v ON_ERROR_STOP=1 -q -d keep <<'SQL'
ALTER DATABASE keep SET log_error_verbosity = terse;
ALTER DATABASE keep SET log_min_error_statement = panic;
ALTER DATABASE keep SET log_statement = 'none';
ALTER DATABASE keep SET log_min_duration_statement = -1;
ALTER DATABASE keep SET log_min_duration_sample = -1;
ALTER DATABASE keep SET log_transaction_sample_rate = 0;
ALTER DATABASE keep SET log_min_messages = 'panic';
SQL
```

## 5. Root key, listener certificate and server environment

The root key is 32 random bytes, standard base64, mode `0600`. Losing it makes
every sealed secret unrecoverable: in a real setup it lives outside the
database and outside the database backup. The runner listener needs a TLS
certificate; this one is self-signed for `127.0.0.1` and the runner is told to
trust exactly it.

<!-- quickstart: keys -->
```sh
. "$HOME/keep-quickstart/env.sh"
head -c 32 /dev/urandom | base64 > "$QS/root.key"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 \
  -subj /CN=keep-quickstart -addext "subjectAltName=IP:127.0.0.1" \
  -addext basicConstraints=critical,CA:TRUE \
  -keyout "$QS/listener-key.pem" -out "$QS/listener.pem" 2>/dev/null
```

The server reads only its environment. The file is written with `printf` and
`echo`, so the password is never printed.

<!-- quickstart: server-env -->
```sh
. "$HOME/keep-quickstart/env.sh"
{
  printf 'KEEP_DATABASE_URL="postgres://keep:%s@%s:5432/keep?sslmode=disable"\n' "$(cat "$QS/db.pw")" "$PGHOST"
  echo "KEEP_ROOT_KEY_FILE=$QS/root.key"
  echo "KEEP_HTTP_ADDR=127.0.0.1:8080"
  echo "KEEP_RUNNER_ADDR=127.0.0.1:8443"
  echo "KEEP_PUBLIC_URL=http://127.0.0.1:8080"
  echo "KEEP_SERVER_TLS_CERT_FILE=$QS/listener.pem"
  echo "KEEP_SERVER_TLS_KEY_FILE=$QS/listener-key.pem"
} > "$QS/keep-server.env"
```

## 6. Migrate and start the server

The server never migrates on its own.

<!-- quickstart: migrate -->
```sh
. "$HOME/keep-quickstart/env.sh"
set -a; . "$QS/keep-server.env"; set +a
keep-server migrate up
keep-server migrate status
```

<!-- quickstart: server-start -->
```sh
. "$HOME/keep-quickstart/env.sh"
set -a; . "$QS/keep-server.env"; set +a
nohup keep-server > "$QS/server.log" 2>&1 &
echo $! > "$QS/server.pid"
curl -fsS --retry 30 --retry-connrefused --retry-delay 1 --retry-all-errors http://127.0.0.1:8080/readyz
```

`/readyz` answers only while the database answers. The server logs to
`~/keep-quickstart/server.log`.

## 7. The first organization

`bootstrap-org` creates the organization, its certificate authority and
signing key, a built-in store named `default`, an administrator and a token for
that administrator. The token is written to a file, never to the terminal.

<!-- quickstart: bootstrap-org -->
```sh
. "$HOME/keep-quickstart/env.sh"
set -a; . "$QS/keep-server.env"; set +a
keep-server bootstrap-org --name quickstart --admin-email admin@example.test \
  --token-file "$QS/admin.token" --ttl 24h | tee "$QS/bootstrap.out"
echo "export KEEP_ORG=$(sed -n 's/^org_id=//p' "$QS/bootstrap.out")" >> "$QS/env.sh"
```

## 8. Log in and create a secret reference

`keep login` reads the token from standard input. `create-ref` creates the
secret's name and where it will live; there is no value yet.

<!-- quickstart: login -->
```sh
. "$HOME/keep-quickstart/env.sh"
keep login < "$QS/admin.token"
```

<!-- quickstart: create-ref -->
```sh
. "$HOME/keep-quickstart/env.sh"
keep create-ref DEMO_API_KEY --scope-level org --scope-id "$KEEP_ORG" \
  --class dev --type generic --provider-ref builtin://default/DEMO_API_KEY --json > "$QS/ref.json"
echo "export SECRET_ID=$(jq -r .id "$QS/ref.json")" >> "$QS/env.sh"
```

## 9. A person enters the value

`input-link` issues a single-use link, valid for 30 minutes. The server accepts
only ciphertext at that address. Treat the link itself as a capability: whoever
opens it first sets the value.

<!-- quickstart: input-link -->
```sh
. "$HOME/keep-quickstart/env.sh"
keep input-link DEMO_API_KEY --ttl 30m > "$QS/link.json"
```

**This step is the person's.** Open the address below in a browser and type the
value into the page. The page tells you the version and fingerprint it stored.
Do not type the value in the terminal and do not give it to an agent.

<!-- quickstart: open-link human -->
```sh
. "$HOME/keep-quickstart/env.sh"
jq -r .url "$QS/link.json"
```

(CI plays the person with a headless browser, `test/e2e/human.mjs`, which opens
this same address and types a random canary value into the same page.)

## 10. What the system shows about the secret

The command line shows names, versions, fingerprints and lengths, and never a
value: there is no command that returns one.

<!-- quickstart: list-meta -->
```sh
. "$HOME/keep-quickstart/env.sh"
keep list --scope-level org --scope-id "$KEEP_ORG"
keep version DEMO_API_KEY --scope-level org --scope-id "$KEEP_ORG"
```

`keep mcp` serves the same data to an agent over MCP on standard input and
output. Its tools take and return no value either:

<!-- quickstart: mcp -->
```sh
. "$HOME/keep-quickstart/env.sh"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"quickstart","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list_secrets\",\"arguments\":{\"scope_level\":\"org\",\"scope_id\":\"$KEEP_ORG\"}}}" \
  "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"get_secret_meta\",\"arguments\":{\"secret_id\":\"$SECRET_ID\"}}}" \
  | keep mcp --token-file "$QS/admin.token"
```

## 11. The consumer

Delivery ends by restarting the service that reads the file and asking it
whether it is healthy. The consumer here is a small web server. Its `/healthz`
on the loopback interface answers `200` only when it can read a non-empty
delivered file, and never returns a byte of it; before the delivery it answers
`503`. `/ready` answers `200` as soon as the server listens: the unit's
`ExecStartPost` waits for it, so `systemctl restart` returns only once the
server is up, because the runner checks health right after the restart
returns.

<!-- quickstart: consumer -->
```sh
. "$HOME/keep-quickstart/env.sh"
mkdir -p "$QS/consumer" "$QS/target"
cat > "$QS/consumer/server.py" <<'PY'
import http.server, sys

TARGET = sys.argv[1]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.path == "/ready"
        if self.path == "/healthz":
            try:
                with open(TARGET, "rb") as f:
                    ok = len(f.read(1)) == 1
            except OSError:
                ok = False
        body = b"keep-quickstart-ok\n" if ok else b"waiting for the delivered file\n"
        self.send_response(200 if ok else 503)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
PY
sudo tee /etc/systemd/system/keep-quickstart-consumer.service > /dev/null <<UNIT
[Service]
ExecStart=/usr/bin/python3 $QS/consumer/server.py $QS/target/demo.key
ExecStartPost=/usr/bin/curl --silent --retry 20 --retry-connrefused --retry-delay 1 --output /dev/null http://127.0.0.1:18080/ready
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now keep-quickstart-consumer
```

The runner runs as your own user, not as root, and calls
`systemctl restart <unit>` itself, without `sudo`. A system unit refuses that
unless the user is allowed to restart this one unit. The rule below allows
exactly that and nothing else (polkit 0.106 or newer; it grants the one verb
`restart` on the one unit to the one user):

<!-- quickstart: restart-permission -->
```sh
. "$HOME/keep-quickstart/env.sh"
sudo mkdir -p /etc/polkit-1/rules.d
sudo tee /etc/polkit-1/rules.d/49-keep-quickstart.rules > /dev/null <<RULE
polkit.addRule(function (action, subject) {
  if (action.id == "org.freedesktop.systemd1.manage-units" &&
      action.lookup("unit") == "keep-quickstart-consumer.service" &&
      action.lookup("verb") == "restart" &&
      subject.user == "$(id -un)") {
    return polkit.Result.YES;
  }
});
RULE
```

(CI runs as root with a stand-in for `systemctl`, so it writes this rule but
cannot show that polkit honours it. On a real host, check it with
`systemctl restart keep-quickstart-consumer` as your user, without `sudo`.)

## 12. The host policy and the runner

The host decides what it accepts, in a local file the server cannot change: a
target of kind `file` under one directory, the one service it may restart, and
the health check that decides whether the delivery worked. The check is a GET
to a loopback address that must answer `200` with a marker in the body.

<!-- quickstart: host-policy -->
```sh
. "$HOME/keep-quickstart/env.sh"
cat > "$QS/host-policy.json" <<POLICY
{"version": 1, "agent_uids": [], "agent_gids": [], "max_deploys_per_hour": 20,
 "targets": [{"kind": "file", "path_prefixes": ["$QS/target"],
   "units": ["systemd:keep-quickstart-consumer"],
   "health": {"kind": "http", "url": "http://127.0.0.1:18080/healthz",
              "expect_status": 200, "body_marker": "keep-quickstart-ok", "timeout_seconds": 5}}]}
POLICY
```

An administrator issues a one-time enrollment token bound to this host and this
exact policy file; the runner redeems it on standard input and prints its id.
`check` then verifies the local credential and policy.

<!-- quickstart: runner-enroll -->
```sh
. "$HOME/keep-quickstart/env.sh"
KEEP_ADMIN_TOKEN="$(cat "$QS/admin.token")" keep runner enroll-token --host "$(hostname)" \
  --policy "$QS/host-policy.json" --server https://127.0.0.1:8443 --server-ca "$QS/listener.pem" \
  --uid-shared=false --environment staging --platform linux > "$QS/enroll.token"
keep-runner enroll --host "$(hostname)" --server https://127.0.0.1:8443 --server-ca "$QS/listener.pem" \
  --policy "$QS/host-policy.json" --cred-dir "$QS/runner-cred" < "$QS/enroll.token"
keep-runner check --cred-dir "$QS/runner-cred" --policy "$QS/host-policy.json"
```

<!-- quickstart: runner-start -->
```sh
. "$HOME/keep-quickstart/env.sh"
nohup keep-runner run --cred-dir "$QS/runner-cred" --policy "$QS/host-policy.json" \
  --server https://127.0.0.1:8443 --server-ca "$QS/listener.pem" > "$QS/runner.log" 2>&1 &
echo $! > "$QS/runner.pid"
```

## 13. The server's deployment policy

A deployment runs without a person's approval only if the organization's
policy has a rule for that secret, that runner, that kind of target and that
directory ([deploy-policy.md](deploy-policy.md)). Anything else waits for
someone other than the requester.

<!-- quickstart: deploy-policy -->
```sh
. "$HOME/keep-quickstart/env.sh"
set -a; . "$QS/keep-server.env"; set +a
RUNNER_ID=$(PGPASSWORD="$(cat "$QS/db.pw")" psql -h "$PGHOST" -U keep -d keep -Atc "SELECT id FROM runners WHERE org_id = '$KEEP_ORG'")
echo "export RUNNER_ID=$RUNNER_ID" >> "$QS/env.sh"
jq -n --arg secret "$SECRET_ID" --arg runner "$RUNNER_ID" --arg dir "$QS/target" \
  '{rules: [{secret_id: $secret, runner_id: $runner, kind: "file", path_prefix: $dir}]}' > "$QS/deploy-policy.json"
keep-server set-deploy-policy --org-id "$KEEP_ORG" --policy-file "$QS/deploy-policy.json"
```

## 14. Deliver

`keep deploy` asks for the delivery and waits for the runner's answer. The
answer carries the version and fingerprint of what was written and the health
of the consumer, never the value.

<!-- quickstart: deploy -->
```sh
. "$HOME/keep-quickstart/env.sh"
keep deploy DEMO_API_KEY --runner "$RUNNER_ID" --kind file --target "$QS/target/demo.key" \
  --uid "$(id -u)" --gid "$(id -g)" --consumer systemd:keep-quickstart-consumer --wait 60s --json
```

`"ok": true` and `"healthcheck": {"status": "ok"}` mean the file is written, the
service restarted and it answered the check. The file holds only the value, with
mode `0600`; compare its size with the length from step 10 without reading it:

<!-- quickstart: target -->
```sh
. "$HOME/keep-quickstart/env.sh"
stat -c '%a %s %n' "$QS/target/demo.key"
```

## 15. The audit journal

Every step above wrote a record to a hash chain. `audit verify` checks the
chain end to end.

<!-- quickstart: audit -->
```sh
. "$HOME/keep-quickstart/env.sh"
keep audit verify
```

## Clean up

<!-- quickstart: cleanup -->
```sh
. "$HOME/keep-quickstart/env.sh"
kill "$(cat "$QS/runner.pid")" "$(cat "$QS/server.pid")"
sudo systemctl stop keep-quickstart-consumer
rm -f "$HOME/.config/keep/token"
```

<!-- quickstart: drop-database ci-skip -->
```sh
docker rm -f keep-quickstart-db
rm -rf ~/keep-quickstart
```

## Where next

- Run it for real: [deploy.md](deploy.md), then [bootstrap-org.md](bootstrap-org.md).
- Let agents ask for deliveries without a person each time:
  [deploy-policy.md](deploy-policy.md).
- How the runner treats a job: [runner-delivery.md](runner-delivery.md).
