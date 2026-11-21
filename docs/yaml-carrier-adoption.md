# Read-only YAML carrier adoption

Status: implementation contract; rollout requires the reviewed server and runner
artifacts. An older runner rejects the new action or kind. Adopt reads a file
that already exists. It does not write the scalar, create a backup, restart the
consumer, run a healthcheck, or create a completed deployment.

## API and evidence

`POST /orgs/{org_id}/secrets/{secret_id}/carriers/adopt` accepts exactly:

```json
{
  "request_id": "yaml-adoption-probe-1",
  "runner_id": "<enrolled runner UUID>",
  "target": {
    "kind": "yaml-scalar",
    "path": "/srv/keep-yaml-probe/config.yaml",
    "field": "service.token"
  }
}
```

`request_id` is optional; the default is the response `X-Request-ID`. Reusing it
with the same actor, organization, secret, runner and exact destination returns
the original request. Changing that binding returns 409. A retry after the
catalog changes still names the original version; it cannot register a stale
attestation. There is no caller-supplied host, version, fingerprint, value,
consumer, healthcheck, mode, UID or GID. Unknown fields, including nested fields,
are 400. Only builtin-backed current enabled versions are supported.

`GET /orgs/{org_id}/secrets/{secret_id}/carriers/adopt/{request_id}` reads the
same request. Both routes require `adopt_carrier` in the secret's exact scope.
Admins have this right. Agents need an explicit grant and an admin sponsor;
default deploy permission grants no adoption. Missing/foreign/unauthorized
objects use the same 404. Responses are `Cache-Control: no-store`.

The closed response fields are `ok`, `request_id`, `status`, `version_id`,
optional `job_id`, `error_class`, and `approval: {id,status,url}`. Pending and
approval_required return 202; registered and failed return 200, with `ok` true
only for registered. Refusals use the existing closed Error schema: 400 invalid
input/provider, 403 denied policy/approval, 404 unavailable object, 409 changed
idempotency binding, 429 admission limit, 503 unavailable service. Approval
rejection/expiry is 403. No response contains an observed scalar or fingerprint.

Successful attestation atomically commits the runner result, an immutable
`carrier_adoption_receipts` row and the carrier. The receipt binds org, secret,
catalog version UUID and provider version, runner, enrolled host, path, field,
expected fingerprint and job ID. The canonical stored job binds the nonce,
request ID, signature and 15-minute expiry. Material issuance is one-use and
contains only the tenant fingerprint key, HPKE-sealed under the adopt domain
and the complete job. The enrolled runner verifies the organization signature,
identity, time window and durable replay journal before reading the scalar.

At acceptance the server rechecks live enrollment, certificate serial through
the dispatch principal, delivery key, host attributes, current version UUID,
fingerprint, frozen target, material issuance, expiry and bound approval.
Revoked trust, a new current version (even with the same fingerprint), foreign
runner/org, changed job and forged health cannot register a carrier. The exact
terminal Result may be acknowledged again while trust remains valid; it cannot
create a second receipt or rerun the job. A different replay is refused.
The host is the enrollment's stored host, reached through the same org/runner
identity as the signed job; the registry exposes no host rename operation.

`GET /orgs/{org_id}/secrets/{secret_id}/carriers` returns `org_id`, `secret_id`,
provider `version`, `host`, `runner_id`, `target: {kind,path,field}`,
`provenance: "adoption"`, `attestation_job_id`, registered status,
last_verified_at and fingerprint_match. Consumer/healthcheck are optional existing
metadata. The receipt describes registration evidence; later verify updates the
observed carrier version without rewriting that evidence. Adoption requests do
not appear on `/v1/deployments/{request_id}`. The existing POST carriers guard
still requires approved metadata and a confirmed deployment.

The optional target `field` is emitted only for `yaml-scalar`; existing kinds retain their previous target shape.

## Explicit policy and approval

The server deployment policy has a separate `adoption_rules` list (maximum
128); a deploy `rules` entry never authorizes adoption. A non-production request
may run without human approval only with this exact tuple:

```json
{"secret_id":"<secret UUID>","runner_id":"<runner UUID>","kind":"yaml-scalar","path":"/srv/keep-yaml-probe/config.yaml","field":"service.token"}
```

An unlisted tuple requires approval of that frozen request by another human
admin, using the existing approval flow. Production requires approval for every
request, even with an exact rule, and refuses unknown host attributes or shared
UIDs. Approval binds the version and exact destination; version/trust changes
are checked again when approving and accepting the result. Admission shares the
organization's deployment rate budget. Use `set-deploy-policy` with the current
complete policy and `--expect-revision`; preserve all other rules.

The trusted local runner policy independently needs BOTH a normal target read
rule and an exact `adoption_targets` entry. Add these to the existing policy:

```json
{
  "targets": [{"kind":"yaml-scalar","path_prefixes":["/srv/keep-yaml-probe"],"fields":["service.token"]}],
  "adoption_targets": [{"path":"/srv/keep-yaml-probe/config.yaml","field":"service.token"}]
}
```

This fragment is not a complete policy: retain version, agent identities and
other required fields. Agent-owned or agent-writable paths are refused. Adopt
also refuses consumer/unit fields. `yaml-scalar` supports adopt, verify and
discovery; deploy and rotation refuse it before writing or queueing a writer.

## YAML semantics and limits

`field` has 1–16 mapping-key segments, each `[A-Za-z0-9_-]+`, joined by dots,
with at most 256 bytes. Selection is exact and case-sensitive. No array indexing,
globs, escaped/literal-dot key selection or recursive search. The document must
be one mapping-root YAML document and the selected leaf a string scalar. Block
and quoted string decoding follows YAML semantics, including newline chomping;
the fingerprint covers decoded bytes. Plain YAML 1.1 boolean spellings
yes/no/y/n/on/off are refused; quote them when strings are intended.

The same reader serves adopt, verify and discovery. It bounds the file to 1 MiB,
the accepted tree to depth 32 and 16,384 nodes, and fields to 256 per read.
Duplicate mapping keys anywhere, complex keys, anchors, aliases, merge keys,
explicit/custom tags, multiple documents, malformed trailing content, and a
selected non-string or non-mapping intermediate fail closed. Unsupported input
returns fixed errors without parser diagnostics or partial findings. Missing
selected fields cannot produce a matching attestation.

Unix reads pin directory descriptors and refuse symlinks, hardlinks, nonregular
files and unsafe writable ancestors/files. Discovery additionally enforces its
trusted owner list and its own byte/file limits. Other platforms fail closed.
No file or .bak is written. Concurrent changes by an authorized owner remain a
snapshot limitation: an attestation proves the bytes read, not future contents.
The YAML decoder allocates immutable strings inside the value zone; Go cannot
guarantee their erasure before collection. Owned byte buffers and secret.Value
are wiped. Values, parser text and file-supplied names never enter API/log output.

Discovery needs an explicit local discovery rule, for example this rule under
the protected root `/srv/keep-yaml-probe` with trusted owner UIDs and byte/file
limits:

```json
{"glob":"config.yaml","kind":"yaml-scalar","names":["service.token"]}
```

The finding name and registered carrier field both remain `service.token`.
Another branch ending in `token` cannot collide with it. A matching read is
`match`; a changed value is `stale`, not a missing `unknown_find`.

## Disposable contract fixture

An existing workstation is not a supported adoption destination when its
enrolled reader has no ordinary access to the consumer-owned 0700 directory
and 0600 file, and the owner runs both the consumer and an agent. In that case,
privileged reading alone would not satisfy the agent-writable and shared-UID
guards. Preserve the current files, ownership, permissions, policy and consumer.
Changing the reader or isolating the consumer requires a separately agreed
product and threat-model contract, independent review and an authorized rollout.
The synthetic stand below does not establish applicability to such a destination.

With `KEEP_DATABASE_URL` pointing only to a disposable PostgreSQL database,
the following command creates a fresh migrated test database, builtin secret
and current version, enrolled runner with a generated delivery key, policy and
administrator. It exercises POST adoption, signed one-use key delivery, GET
carrier, verify match/mismatch/match, discovery match, retry, stale current
version and revoked trust, then drops the fixture database:

```sh
go test -p 1 ./cmd/keep-server/app \
  -run '^TestAdoptDispatchRealCryptoAndCarrierAPI$' -count=1 -v
```

This test starts at the authenticated dispatch-principal boundary and reads
generated YAML bytes with the shared parser. It does not claim to exercise
the TLS handshake, an installed runner process or protected host files.
File permissions, symlinks and unchanged YAML/.bak metadata are covered by
the targeted `YAML` tests in `internal/targets`, `internal/runner/loop` and
`internal/runner/discover`. The installed-path probe below remains required.

The `intake-browser` CI job also runs `TestMeshUIBrowserYAMLAdoption`: real
console sessions and bound approve/reject forms, with screenshots at 1440 and
393 pixels. The approved request creates one adopt job; rejection creates none.

## Operator probe after installation

Use a disposable current builtin secret and enrolled runner on the stand. The
same generated test value must already be in the named YAML scalar. Record
server `/version`, runner build SHA, prior artifacts for rollback and external
consumer health before running. Keep the authenticated curl configuration in a
protected file; do not print its contents or put credentials in command text.
The following variables contain identifiers/paths only: `KEEP_API`, `ORG_ID`,
`SECRET_ID`, `STORE_ID`, `RUNNER_ID`, `CARRIER_HOST`, `YAML_PATH`,
`KEEP_CURL_CONFIG`, expected catalog `VERSION_ID` and provider `VERSION`,
and fresh `ADOPT_REQUEST_ID`, `VERIFY_REQUEST_ID`,
`DISCOVER_REQUEST_ID`.

```sh
jq -n --arg request_id "$ADOPT_REQUEST_ID" --arg runner_id "$RUNNER_ID" \
  --arg path "$YAML_PATH" \
  '{request_id:$request_id,runner_id:$runner_id,target:{kind:"yaml-scalar",path:$path,field:"service.token"}}' > adopt-request.json
curl --config "$KEEP_CURL_CONFIG" --fail-with-body --silent --show-error \
  -H 'Content-Type: application/json' --data-binary @adopt-request.json \
  "$KEEP_API/orgs/$ORG_ID/secrets/$SECRET_ID/carriers/adopt" > adopt.json
jq -e '.status == "pending" or .status == "approval_required"' adopt.json
```

Resolve the returned approval when required. After the installed runner reports
the job, read the result; do not infer success from the initial 202:

```sh
curl --config "$KEEP_CURL_CONFIG" --fail-with-body --silent --show-error \
  "$KEEP_API/orgs/$ORG_ID/secrets/$SECRET_ID/carriers/adopt/$ADOPT_REQUEST_ID" > adopt-result.json
jq -e --arg version_id "$VERSION_ID" \
  '.ok and .status == "registered" and .version_id == $version_id and (.job_id | length > 0)' adopt-result.json
curl --config "$KEEP_CURL_CONFIG" --fail-with-body --silent --show-error \
  "$KEEP_API/orgs/$ORG_ID/secrets/$SECRET_ID/carriers" > carriers.json
jq -e --arg org "$ORG_ID" --arg secret "$SECRET_ID" --arg runner "$RUNNER_ID" \
  --arg host "$CARRIER_HOST" --arg path "$YAML_PATH" --arg version "$VERSION" --slurpfile result adopt-result.json \
  'length == 1 and all(.[]; .org_id == $org and .secret_id == $secret and
   .runner_id == $runner and .host == $host and .version == $version and .provenance == "adoption" and
   .target == {kind:"yaml-scalar",path:$path,field:"service.token"} and
   .status == "registered" and .fingerprint_match and
   .attestation_job_id == $result[0].job_id)' carriers.json
jq -n --arg request_id "$VERIFY_REQUEST_ID" '{request_id:$request_id}' > verify-request.json
curl --config "$KEEP_CURL_CONFIG" --fail-with-body --silent --show-error \
  -H 'Content-Type: application/json' --data-binary @verify-request.json \
  "$KEEP_API/orgs/$ORG_ID/secrets/$SECRET_ID/carriers/verify" > verify-submit.json
```

After the runner answers verify, read its bound status and submit discovery:

```sh
curl --config "$KEEP_CURL_CONFIG" --fail-with-body --silent --show-error \
  "$KEEP_API/orgs/$ORG_ID/secrets/$SECRET_ID/carriers/verify/$VERIFY_REQUEST_ID" > verify.json
jq -e '.ok and (.carriers | length == 1) and all(.carriers[]; .status == "match" and .fingerprint_match and .target.field == "service.token")' verify.json
jq -n --arg request_id "$DISCOVER_REQUEST_ID" --arg runner_id "$RUNNER_ID" --arg store_id "$STORE_ID" \
  '{request_id:$request_id,runner_id:$runner_id,store_id:$store_id}' > discovery-request.json
curl --config "$KEEP_CURL_CONFIG" --fail-with-body --silent --show-error \
  -H 'Content-Type: application/json' --data-binary @discovery-request.json \
  "$KEEP_API/orgs/$ORG_ID/carriers/discover" > discovery-submit.json
```

After the runner answers discovery, read the complete one-file probe report:

```sh
curl --config "$KEEP_CURL_CONFIG" --fail-with-body --silent --show-error \
  "$KEEP_API/orgs/$ORG_ID/carriers/discover/$DISCOVER_REQUEST_ID" > discovery.json
jq -e '.state == "completed" and any(.findings[]; .name == "service.token" and .verdict == "match") and
  (.total == (.findings | length)) and all(.findings[]; .verdict != "unknown_find")' discovery.json
```

Repeat the identical POST and assert the same job ID and one carrier. Compare
the carrier provider version with the enabled current entry from GET secret
versions. Verify `/v1/deployments/{request_id}` remains 404 and the database has
no action=deploy row for this request. Capture YAML/.bak SHA-256 and stat
(mode/UID/GID/size/mtime) before/after and compare; assert the existing external
consumer health, independently of adoption. Negative probes use fresh request
IDs and disposable files/runners only; verify no carrier was inserted. Change
the disposable scalar to test nonmatch, then restore it for discovery.

Rollback reinstalls the captured server and runner artifacts; do not down-migrate
away accepted receipts or authorization metadata. Migration 00059 refuses such
a destructive down migration. Before adoption state exists, downgrade only to
version 54 so the existing Mesh approvals setting remains installed. Existing
carrier files need no restoration after adoption because adoption never changes
them.
