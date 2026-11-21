# Rotation testbed

A local stand that runs the rotation path end to end on the built binaries:
`keep-server`, PostgreSQL, two hosts each with its own `keep-runner`, an agent
and five carriers with live consumers. It uses test credentials only and never
touches a real host, a real key or a real provider.

```
scripts/testbed/rotation.sh all
```

needs Docker with Compose v2 (Docker Desktop, or colima with the Docker CLI)
and about 4 GB of memory for the containers. The script runs on any bash 3.2 or
newer, including the system `/bin/bash` on macOS. A cold start builds six binaries
and four images (a few minutes); a warm run takes about a minute.

## Commands

| Command | What it does |
|---|---|
| `rotation.sh up` | Builds, starts the stand from nothing, delivers version 1 of one secret to all five carriers and registers them. |
| `rotation.sh rotate` | Starts a rotation of that secret in generate mode through the MCP `rotate` tool of `keep mcp`, then records the run. |
| `rotation.sh break-third` | Makes the consumer of the third carrier unable to start. The next `rotate` must fail there. |
| `rotation.sh tamper` | Changes carrier a1 behind Keep's back, asks the MCP `verify_carriers` tool, puts a1 back and asks again, and checks both answers (see "Tamper"). |
| `rotation.sh receipt` | Scans everything the stand produced for the secret's values and prints the receipt as JSON. |
| `rotation.sh down` | Removes the containers and their volumes. |
| `rotation.sh all` | `up`, `rotate`, `tamper`, `break-third`, `rotate`, the checks of both runs and of `tamper`, `receipt`. Fails if any property does not hold. `all --mesh` runs the same with the Mesh part. |
| `rotation.sh discover` | Carrier discovery on both hosts through `keep carriers discover`, before and after the hosts change behind Keep's back, and its checks (see "Discovery"). |
| `rotation.sh discover-all` | `up`, `discover`, its checks, `receipt`. |

Rotation is started only through the MCP tool, as an agent would do it. The
script adds no CLI to Keep and calls no internal function.

## What runs

```
operator ──────────────┐   keys, certificate, database access, the human at
                       │   the input page, the leak scanner
postgres ── keep-server ┼── agent (shares the server's network namespace; the
                       │   CLI sends plain HTTP to a loopback address only)
        ┌──────────────┴──────────────┐
      host-a                        host-b
 systemd, keep-runner          systemd, keep-runner
 consumer-a1  env-file         consumer-b1  env-file
 consumer-a2  mcp-config       consumer-b2  file
 consumer-a3  systemd-credential
```

* Each host is a Debian container with systemd as PID 1, its own hostname,
  machine id, filesystem and network, and its own runner enrolled under its
  own identity. The image ships an empty `/etc/machine-id`, so systemd gives
  each host its own at boot; `all` fails if the two hosts share one.
  The containers are privileged because systemd needs a private cgroup tree.
  The root mount is made shared before systemd starts, as on a booted
  machine; with Docker's default private propagation systemd would hand a
  unit an empty credentials directory.
  No host directory is mounted and no port is published.
* `keep-server` and PostgreSQL run in their own containers. PostgreSQL uses
  trust authentication on the stand's private network only.
* A consumer is a systemd unit running `consumer`, a small program that reads
  its credential from its carrier, refuses to start unless the credential has
  the expected shape, and then serves a fixed marker (an HTTP endpoint on
  loopback, or only the running state). It prints the credential's length and
  nothing else. The runner restarts it after each delivery and runs the
  health check the host policy defines: `http` for a1, a3 and b1,
  `unit-active` for a2 and b2.
* The third carrier, a3, is a systemd credential. The runner encrypts the
  value with the host's own `systemd-creds` (the binary of Debian's `systemd`
  package, not a stand-in) under the credential name `api_token`, and writes
  only the ciphertext to `/srv/app/a3/api_token.cred`. The consumer unit loads
  it with `LoadCredentialEncrypted=api_token:/srv/app/a3/api_token.cred`;
  systemd decrypts it into the unit's credentials directory before the
  service starts, so a file that does not decrypt under that name keeps the
  consumer from starting. The carrier is registered with its path only; when
  a rotation verifies it, the server takes the credential name from the last
  completed deploy of the secret to that path on that host.
* The first value is entered by a human at the one-time input link (the
  `humaninput` helper plays the human), so no tool in the stand ever carries a
  value. Later versions are generated on the Keep side.

## Scenarios

**1. Rotation succeeds.** `up` then `rotate`: `ok=true`, all five carriers
`state=ok` with one fingerprint, health `PASS` on all five consumers, one new
`current` version and the old one `disabled`.

**2. The third carrier refuses.** `break-third` then `rotate`: `ok=false`,
`error_class` is `deploy_failed` or `unhealthy`, the run is rolled back (the
version it created is `disabled` and the previous one is `current` again), the
answer carries `incident_opened=true`, and the server log has
`rotation incident opened` with the same `run_id`.

After a failed run `rotate` also records which version each carrier holds now.
It asks the MCP `verify_carriers` tool, so each runner reads its own carrier and
compares it with the version Keep names current. The fingerprint a runner
reported (the expected one on a match, the observed one on a mismatch, as the
server stored the verification) is named by the version it belongs to. The
value each carrier holds after the run is compared with the one it held before,
inside the operator's private needle directory. The receipt shows this as a
table for the run (`runs[].carrier_versions`):

| carrier | fingerprint | version | holds |
|---|---|---|---|
| a1 … b2 | the fingerprint the runner read | 2 | `previous` |

Scenario 2 requires all five rows to be `previous`: a `match` against version
2, version 2's fingerprint, and the value byte for byte the one from before the
run. That includes the broken a3 and the four carriers whose new value was
delivered and verified before a3 failed. The run is rolled back as a whole: the
engine puts version 2 back on every carrier it changed and disables version 3,
so no carrier is left on the new version.

## Tamper

`tamper` runs after scenario 1, while all five carriers hold version 2. It
checks that Keep sees a carrier that was changed behind its back.

1. a1's file is copied aside on host-a. A one-time wrong value of the same
   form (each letter and digit of the current value replaced by a random one of
   its class, every other character kept) is written in its place. The value
   is made on host-a and goes from there only to the operator's needle
   directory for the leak scan; it is never printed.
2. `verify_carriers` through `keep mcp`: a1 must be `mismatch` with
   `error_class=fingerprint_mismatch` and `fingerprint_match=false`, the other
   four `match`.
3. The saved copy is put back, and `verify_carriers` must answer `ok=true`
   with all five `match`.

If the first MCP request fails, the saved copy is restored before `tamper`
exits with an error. This includes a transport failure and a reply without a
result.

The receipt has both answers under `tamper` (`before`, `after`), by carrier
id, status, `fingerprint_match` and `error_class`; no value and no fingerprint
of the wrong value.

## Discovery

Each host's policy has a `discovery` section: host-a may scan `/srv/app` for
`API_TOKEN` in `*/app.env` and `GATEWAY_TOKEN` in `*/mcp.json`, host-b for
`SERVICE_TOKEN` in `*/app.env`; owners root and the consumers' user (2001),
agent uid 3001. Of the five carriers a1 (env-file), a2 (mcp-config) and b1
(env-file) are ones a scan can name; a3 (a systemd credential registered
without a field) and b2 (file) are outside discovery and never reported.

The administrator asks through the CLI, from a workstation of its own (the
`admin` container, the org admin's token, the server's loopback like the
agent):

```
keep carriers discover --runner RUNNER_ID --store STORE_ID --wait 2m --json
```

**Discovery 1.** Right after `up`: on host-a a1 and a2 are `match`, on host-b
b1 is `match`; no incident, exit 0.

**Discovery 2.** Then the hosts change without Keep: a1's line is copied to
`/srv/app/extra/app.env`, a2's file is moved out of `/srv/app`, b1 is rewritten
with a value Keep never issued. On host-a a1 is `match`, the copy is `sprawl`
with a1's fingerprint and an incident, a2 is `unknown_find` with an incident;
on host-b b1 is `stale`; exit 1 on both. The two incidents are open in the
report store, each scan's result is in the journal without a path or a
fingerprint, and no deployment job, rotation run, secret version or carrier
state changed: discovery reissues nothing.

The receipt then has a `discovery` part: the stand's carrier ids, every scan
(round, host, runner, request id, state, CLI exit code, findings with verdict,
carrier id, path, name, fingerprint, length and incident), what the server
stored (verdicts and incident states, journal lines) and the work counts before
and after. The rewritten b1 value is a needle of the leak scan, and the CLI's
answers are scanned with everything else.

## Receipt

`receipt` prints one JSON document (and leaves it in `scripts/testbed/out/` (a directory the stand owns: `TESTBED_OUT` must be new or empty, or a previous stand output directory; anything else is refused)):

* the commit the images were built from, whether the working tree was dirty and
  which paths made it so (`dirty_paths`, at most 50, names only);
* the versions of `keep`, `keep-runner` and `keep-server`, the SHA-256 of each
  binary as read inside the running containers, and the three image ids;
* the hosts (hostname, machine id, address, runner id), checked by `all` to
  be two hosts with distinct machine ids, addresses and runners;
* for each run: `run_id`, `ok`, `error_class`, `incident_opened`, whether the
  incident line is in the server log, the new version, the active and the
  disabled versions, every carrier (`id`, `host`, `kind`, rotation `state`,
  `fingerprint`), the run's own record of each carrier (deployed, verified,
  `error_class`: the answer marks every carrier of a failed run that was not
  confirmed as `stale`, this says which one failed) and the result of every
  consumer's health check; for a failed run, the table of what each carrier
  holds after it (`carrier_versions`: carrier, fingerprint, version, `holds`
  `new`/`previous`, `value_as_before_run`, see "Scenarios");
* `tamper`: the two `verify_carriers` answers before and after a1 was put back;
* for each systemd credential carrier: the `systemd-creds` version and the
  package that owns it (and that the binary is unchanged from that package),
  whether any value the stand knows is found in the raw
  file in any of the six encodings (it must not be: the file is ciphertext),
  and whether the file decrypts under its credential name and under another
  one (yes and no); `receipt` fails if any of these does not hold;
* the leak scan result.

Values never appear in it: only names, versions, fingerprints and lengths.

## The Mesh part (`--mesh`)

```
TESTBED_MESH_SRC=<a checkout of entire-vc/evc-mesh> scripts/testbed/rotation.sh up --mesh
scripts/testbed/rotation.sh rotate-mesh
scripts/testbed/rotation.sh break-third && scripts/testbed/rotation.sh rotate-mesh
```

The secret of the stand is then an agent key of a disposable Mesh, and the
rotation issues and revokes real keys in it. `up --mesh` adds, in the same
Compose project: a Mesh built from `TESTBED_MESH_SRC` (the API only, built with
Mesh's own `-tags e2eloopback`, which lets it reach Keep on loopback; no Mesh
source is changed), its own PostgreSQL and Redis, a `keep-server` of the mesh
build, and a stand-in for the extension catalog (`meshcatalog`) that serves the
manifest `mesh-extension.keep-rotator.json` signed with a key made at start.
Nothing here touches a real Mesh, agent, key or grant.

Mesh and `keep-server` share one network namespace, so each is `localhost` to
the other; that is the only way both accept the other's address (plain `http`
only on loopback) without weakening either. Setup goes through the public APIs:
the Mesh user and workspace, Keep's admin install of the workspace as a secret
store, `keep-rotator` installed from the signed catalog and connected (Keep
answers the real install handshake, over TLS, inside a window the stand opens),
the extension's service token written to the file `KEEP_MESH_ROTATE_TOKEN_FILE`
names, a test agent with one issued key (its original key is revoked: Keep
rotates issued keys), and `KEEP_MESH_ROTATE_BINDINGS` naming that agent for the
secret. The human at the input link enters that key as the secret's first value.

Each consumer then proves its credential at Mesh: it sends it in `X-Agent-Key`
to `GET /api/v1/agents/me` at start and on every health request, so a key Mesh
has revoked is an unhealthy consumer.

`rotate-mesh` is `rotate` plus questions to Mesh: the ids of the agent's active
keys before and after, the ids of its revoked keys after (`revoked_ids_after`),
the ids that appeared during the run (`issued_ids`, active or revoked: the key
the run issued), and the status Mesh gives to the old and the new key. Ids
only, never values.

**Mesh 1.** After `up --mesh` and `rotate-mesh`: `ok=true`, the active key ids
in Mesh changed, all five carriers `state=ok` with one fingerprint, health
`PASS` on all five consumers with the new key, the new key gets 200 and the old
key 401.

**Mesh 2.** After `break-third` and `rotate-mesh`: `ok=false`, `error_class` is
`deploy_failed` or `unhealthy`, the old key still gets 200, the previous version
is not disabled, `incident_opened=true` and the log line has the run id. In
Mesh exactly one key of the agent is active and it is the old one
(`key_ids_after == key_ids_before`), the run issued exactly one key and that key
is in `revoked_ids_after`, the run was rolled back (version 3 `disabled`,
version 2 `current`), and health is `PASS` on a1, a2, b1 and b2 (`FAIL` on
the broken a3). A tree where the failed run leaves the issued key active fails
on "the key issued in the failed run is revoked".

The receipt has a `mesh` part: the commits of Keep and of evc-mesh, the image
ids and the Mesh binary's SHA-256, `mesh_build_tags`, the catalog artifact's
SHA-256 and the catalog public key (both public), the agent id, and for each run
the key ids before and after, the revoked and issued ids (ids, never values)
with the old and new key's status. The leak scan adds the Mesh containers' logs and the stand's Mesh
values (the agent key, the service token, the signing and events secrets).

`scripts/testbed/check-mesh-mutation.sh` is the red run: in a copy of the tree
`rotationParts.provider` always returns the Generator, Mesh is never called, and
scenario 1 must fail on "the key ids in Mesh changed"; the untouched copy must
pass.

## Leak scan

Every value that exists in the stand (the one the human entered, the one
each carrier holds after each run, and every value a consumer started on, read
on its host straight into the operator's private directory) is searched, in the six encodings of
`internal/testutil/canary`, in: the script's output, every MCP reply, the
server log, both hosts' journals (runner and consumers), the audit journal and
the receipt. A copy of the server log with a value mixed in is scanned first
and must be caught; a scanner that cannot see its own needles aborts the run.

Each consumer unit has a stand-only `ExecStartPre=+` (`host/seen.sh`) that copies
its carrier, as root, into `/var/lib/testbed-seen` on its host before every
start. The harvest after each run turns those copies into needles and deletes
them. A failed run whose rollback put the old value back on every carrier
therefore still has its new value among the needles, and scenario 2 fails if
it does not (`new_value_scanned` in the receipt).

## Red run

`python3 scripts/testbed/check-tamper-restore.py` runs the real `tamper`
command with a failed Docker transport and a reply without an MCP result.
It uses disposable local carrier files, checks that a1 was changed before
the failure, then requires the original bytes back, a nonzero exit and no
value in captured output. It needs Bash, jq and Python 3, without a stand.

`scripts/testbed/check-testbed-mutation.sh` copies the tree twice, changes the
rotation engine of one copy so that the gates before the old version is revoked
no longer wait for the carriers, and runs the whole stand from each copy. The
unmodified copy must pass; the mutated one must fail scenario 2.

The same script also proves the systemd credential carrier:

* a third copy whose server verifies a systemd credential without the
  credential name of its last deploy must fail scenario 1 with `ok=false`,
  `error_class=verify_failed`, and a3 as the only carrier that failed;
* on the stand the unmodified copy leaves running, host-a's `systemd-creds`
  is changed by one byte, then a3's file is replaced by a ciphertext bound to
  no name, by one bound to another name, and by its plaintext, each put back
  afterwards: `receipt` must fail on the a3 line each time and report exactly
  the fields that were broken, the others as on a sound carrier;
* the two checks on a3 (its kind in scenario 1 and the sealed line of the
  receipt) are read from `rotation.sh` and must hold on the unmodified run's
  output and fail on it with any one of their terms made false;
* so is the rollback check of scenario 2: it must hold on the unmodified run's
  version list and fail when the old semantics come back (v2 `previous`, v3
  `current`), when only v3 is `current`, v2 `disabled` or `previous`, v1 not
  `disabled`, or v3 is missing; and the unmodified run must have printed its
  `PASS` line, so a scenario 2 that no longer runs it is red as well;
* so are the version table of scenario 2 (`ON_PREVIOUS`: a carrier that is a
  mismatch, on version 3, marked `new`, holds another value, or is missing)
  and the two tamper checks (`TAMPER_BEFORE`, `TAMPER_AFTER`); the unmodified
  run must have printed the version table's `PASS` line;
* two more copies change `rotation.sh` itself. In one, `tamper` writes a1's own
  value back instead of a wrong one: `all` must fail the tamper "before" check
  and still pass "after". In the other, the saved copy is never put back: `all`
  must fail "after" and still pass "before".

None of this runs in the project's CI (see Known limits); the consumer's own
test, `go test ./scripts/testbed/consumer`, does.

## Known limits

* A Mesh agent's original key is listed by Mesh as `primary`, not a UUID. Keep
  accepts that entry in the list, but rotates only issued keys, so the stand
  gives its agent an issued key and revokes the original one first.
* In CI the stand runs as two automatic jobs on the `keep-netns` runner, in a
  dind service: `rotation-testbed` (`all`) and `rotation-testbed-mesh`
  (`all --mesh`). The Mesh job builds Mesh from entire-vc/evc-mesh at the
  commit pinned in `TESTBED_MESH_SHA`, fetched with the job token, so the
  account that starts the pipeline must be able to read that project. Both
  upload only the receipt and the two scan logs. `scripts/test_ci_config.py`
  keeps trace switches (`set -x`, `GIT_TRACE`, `GIT_CURL_VERBOSE`,
  `CI_DEBUG_TRACE`) out of the Mesh job and its scripts: the job token is in
  the fetch URL.
