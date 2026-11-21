#!/usr/bin/env bash
# The rotation testbed: five carriers on two isolated hosts, one documented
# command. See docs/rotation-testbed.md.
#
#   rotation.sh up           build, start the stand, deliver a secret to all five carriers
#   rotation.sh rotate       rotate the secret through the MCP rotate tool
#   rotation.sh break-third  make the third carrier's consumer unable to start
#   rotation.sh tamper       change a1 behind Keep's back: verify_carriers must see it; put it back
#   rotation.sh up --mesh    the same, plus a disposable Mesh whose agent key is the secret (docs/rotation-testbed.md)
#   rotation.sh rotate-mesh  rotate the secret that is a Mesh agent key; checks the key at Mesh itself
#   rotation.sh discover     carrier discovery on both hosts: match, then sprawl, stale and unknown_find
#   rotation.sh receipt      print the receipt of everything run so far (JSON)
#   rotation.sh down         remove the stand and its volumes
#   rotation.sh all          down, up, rotate, tamper, break-third, rotate, check both runs, receipt
#   rotation.sh discover-all down, up, discover, check it, receipt
#
# Rotation is started only through `keep mcp`, as an agent would. The script
# never prints, stores or passes a secret value: it handles names, ids,
# versions and fingerprints. The one value a human enters is made by the
# `humaninput` helper inside the operator container and is only ever written
# to the operator's own needle directory for the leak scan.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../.." && pwd)
OUT=${TESTBED_OUT:-$HERE/out}
SECRET_NAME=rotation-canary

# Everything this process writes to a terminal, stdout and stderr, is also
# kept in terminal.log and scanned: the stderr of keep mcp, the runner enroll
# and the helpers is the surface an agent's context would see.
# Raw replies hold a live one-time input link until the helper redeems it, so
# everything under $OUT is private to the running user whatever the caller's umask.
umask 077
# `up` clears $OUT, so the stand only touches a directory it owns: absent, empty,
# or carrying the marker an earlier run left. A foreign non-empty directory is
# refused before any chmod, write or cleanup.
MARK=.keep-testbed-out
if [ -e "$OUT" ] && [ ! -d "$OUT" ]; then echo "FAIL: TESTBED_OUT $OUT is not a directory" >&2; exit 1; fi
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT")" ] && [ ! -f "$OUT/$MARK" ]; then
  echo "FAIL: TESTBED_OUT $OUT is not empty and not a stand output directory; use an empty or new directory" >&2
  exit 1
fi
mkdir -p "$OUT"
chmod 700 "$OUT"
: >"$OUT/$MARK"
: >>"$OUT/terminal.log"; chmod 600 "$OUT/terminal.log"   # kept across runs: fix an older mode
# stdout stays stdout (receipt prints clean JSON there), stderr stays stderr.
# Two FIFOs and an explicit wait, so the last lines are flushed before exit.
FIFO=$(mktemp -d)
mkfifo "$FIFO/out" "$FIFO/err"
tee -a "$OUT/terminal.log" <"$FIFO/out" & TEE_OUT=$!
tee -a "$OUT/terminal.log" <"$FIFO/err" >&2 & TEE_ERR=$!
exec >"$FIFO/out" 2>"$FIFO/err"
trap 'exec >&- 2>&-; wait "$TEE_OUT" "$TEE_ERR"; find "$FIFO" -delete' EXIT

export TESTBED_SRC=$SRC
export TESTBED_COMMIT=${TESTBED_COMMIT:-$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)}
export TESTBED_BUILD_TIME=${TESTBED_BUILD_TIME:-$(git -C "$SRC" log -1 --format=%cI 2>/dev/null || echo unknown)}

# --mesh: the disposable Mesh, built from the evc-mesh source tree TESTBED_MESH_SRC,
# and a keep-server of the mesh build. Once a stand is up with it, later
# commands find it from the state file.
MESH=0
{ [ "${1:-}" = up ] || [ "${1:-}" = all ]; } && [ "${2:-}" = --mesh ] && MESH=1
[ ! -f "$OUT/state/mesh" ] || MESH=1
if [ "$MESH" = 1 ]; then
  export COMPOSE_PROFILES=mesh TESTBED_SERVER_VARIANT=mesh
  export TESTBED_COMMIT40=$TESTBED_COMMIT
  [ -n "${TESTBED_MESH_SRC:-}" ] && [ -d "$TESTBED_MESH_SRC/cmd/api" ] \
    || { echo "FAIL: --mesh needs TESTBED_MESH_SRC, a checkout of entire-vc/evc-mesh" >&2; exit 1; }
  TESTBED_MESH_SRC=$(cd "$TESTBED_MESH_SRC" && pwd); export TESTBED_MESH_SRC
fi

C() { docker compose --progress quiet -f "$HERE/compose.yaml" "$@"; }
# HX runs in a container with no stdin: inside a `while read` loop it must not eat the loop's input.
HX() { C exec -T "$@" </dev/null; }
OP() { C exec -T operator "$@"; }
say() { printf '%s\n' "$*" | tee -a "$OUT/script.log" >&2; }
die() { say "FAIL: $*"; exit 1; }
state() { cat "$OUT/state/$1"; }
AG() { C exec -T -e KEEP_SERVER=http://127.0.0.1:8080 -e "KEEP_ORG=$(state org)" agent "$@"; }
# ADM runs a command at the administrator's workstation, with the org admin's token.
ADM() { C exec -T -e KEEP_SERVER=http://127.0.0.1:8080 -e "KEEP_ORG=$(state org)" admin "$@"; }

# The carriers: id host kind path field unit-of-credential consumer
CARRIERS='a1 host-a env-file /srv/app/a1/app.env API_TOKEN - systemd:consumer-a1.service
a2 host-a mcp-config /srv/app/a2/mcp.json mcpServers.gateway.env.GATEWAY_TOKEN - systemd:consumer-a2.service
a3 host-a systemd-credential /srv/app/a3/api_token.cred - api_token systemd:consumer-a3.service
b1 host-b env-file /srv/app/b1/app.env SERVICE_TOKEN - systemd:consumer-b1.service
b2 host-b file /srv/app/b2/token - - systemd:consumer-b2.service'

# mcp TOOL ARGS-JSON: one MCP tools/call through the agent's `keep mcp`; the
# raw reply is kept for the leak scan, the structured result is printed.
mcp() {
  local n; n=$(find "$OUT/mcp" -type f | wc -l | tr -d ' ')
  local f="$OUT/mcp/$(printf '%03d' "$n")-$1.json"
  printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s}}\n' "$1" "$2" | AG keep mcp >"$f"
  jq -e '.result' "$f" >/dev/null || die "mcp $1 returned no result"
  # The tool's answer is JSON text in the first content item.
  jq -er '.result.content[0].text' "$f"
}

runner_of() { awk -v h="$1" '$1==h {print $2}' "$OUT/state/runners"; }
psql_op() { OP psql -h postgres -U keep -d keep -At -c "$1"; }

up() {
  COMPOSE_PROFILES=mesh C down -v --remove-orphans >/dev/null 2>&1 || true
  # terminal.log is the live copy of everything this process writes: it stays.
  find "$OUT" -mindepth 1 ! -name terminal.log ! -name "$MARK" -delete 2>/dev/null || true
  mkdir -p "$OUT/state" "$OUT/mcp" "$OUT/runs"
  : >"$OUT/script.log"
  say "== build"
  C build >/dev/null
  C up -d --wait postgres operator >/dev/null
  if [ "$MESH" = 1 ]; then OP stand-init.sh mesh >/dev/null; else OP stand-init.sh >/dev/null; fi
  C run --rm --no-deps keep-server migrate up >/dev/null
  C up -d --wait keep-server agent admin >/dev/null
  C up -d host-a host-b >/dev/null
  local h i
  for h in host-a host-b; do
    for i in $(seq 60); do
      C exec -T "$h" systemctl is-active testbed-init.service >/dev/null 2>&1 && break
      sleep 1
    done
    C exec -T "$h" systemctl is-active testbed-init.service >/dev/null 2>&1 || die "$h did not finish its first boot"
  done

  say "== organization, agent, token"
  local boot
  boot=$(C run --rm --no-deps keep-server bootstrap-org --name testbed --admin-email admin@stand.invalid --token-file /exchange/admin-token --ttl 2h)
  sed -n 's/^org_id=//p' <<<"$boot" >"$OUT/state/org"
  local org; org=$(state org)
  psql_op "WITH a AS (SELECT user_id FROM memberships WHERE org_id='$org' LIMIT 1),
     g AS (INSERT INTO agents(id,org_id,sponsor_user_id,name) SELECT gen_random_uuid(),'$org',user_id,'rotation-agent' FROM a RETURNING id)
     INSERT INTO agent_grants(id,org_id,agent_id,permission) SELECT gen_random_uuid(),'$org',id,'rotate' FROM g" >/dev/null
  psql_op "SELECT id FROM agents WHERE org_id='$org'" >"$OUT/state/agent"
  # The agent's token goes from the operator to the agent's own file; it is
  # never put in a variable or on a terminal.
  OP sh -c 'umask 077; mkdir -p /operator/needles; cp /exchange/admin-token /operator/needles/admin-token
    # the token body without its keep_<kind>_ prefix is as usable as the whole
    sed "s/^[^_]*_[^_]*_//" /exchange/admin-token >/operator/needles/admin-token-body
    printf "Authorization: Bearer %s\n" "$(cat /exchange/admin-token)" >/operator/hdr
    curl -fsS -H @/operator/hdr -H "Content-Type: application/json" \
      -d "{\"kind\":\"a\",\"principal_id\":\"'"$(state agent)"'\",\"scope\":\"org:'"$org"'\"}" \
      http://keep-server:8080/orgs/'"$org"'/tokens | jq -r .token | tr -d "\n" >/operator/needles/agent-token
    sed "s/^[^_]*_[^_]*_//" /operator/needles/agent-token >/operator/needles/agent-token-body'
  OP cat /operator/needles/agent-token \
    | AG sh -c 'umask 077; mkdir -p "$HOME/.config/keep"; tr -d "\n" >"$HOME/.config/keep/token"'
  OP cat /exchange/admin-token \
    | ADM sh -c 'umask 077; mkdir -p "$HOME/.config/keep"; tr -d "\n" >"$HOME/.config/keep/token"'

  [ "$MESH" = 0 ] || mesh_up "$org"
  say "== secret and its first value (entered by a human at the input link)"
  # The administrator defines the secret (a name and a locator, no value).
  OP sh -c 'curl -fsS -H @/operator/hdr -H "Content-Type: application/json" \
      -d "{\"scope_level\":\"org\",\"scope_id\":\"'"$org"'\",\"name\":\"'"$SECRET_NAME"'\",\"class\":\"dev\",\"type\":\"generic\",\"provider_ref\":\"builtin://default/'"$SECRET_NAME"'\"}" \
      http://keep-server:8080/orgs/'"$org"'/secrets | jq -r .id' >"$OUT/state/secret"
  [ "$MESH" = 0 ] || OP mesh-setup.sh bind "$(state secret)"
  local link
  link=$(mcp request_secret_input "{\"secret\":\"$SECRET_NAME\",\"ttl\":\"10m\"}" | jq -r .url)
  OP install -d -m 0700 /operator/needles
  # The page is served for the agent's loopback address; the operator reaches it by name.
  link=${link/127.0.0.1/keep-server}
  # In the Mesh stand the human types the test agent's first key, so the secret IS that key.
  # ${hv[@]+"${hv[@]}"}: Bash 3.2 (macOS /bin/bash) under set -u treats an empty
  # array as unbound; this form expands to nothing there, with no empty argument.
  local hv=(); [ "$MESH" = 0 ] || hv=(-e KEEP_HUMAN_VALUE_FILE=/operator/mesh/agent-key-1)
  C exec -T -e "KEEP_HUMAN_LINK=$link" -e KEEP_HUMAN_OUT=/operator/needles/canary-v1 ${hv[@]+"${hv[@]}"} operator \
    humaninput -test.run TestHumanEntersTheValue -test.count=1 | tee -a "$OUT/script.log"

  say "== runners: each host enrolls under its own identity"
  for h in host-a host-b; do
    OP sh -c 'KEEP_ADMIN_TOKEN=$(cat /exchange/admin-token) keep runner enroll-token -host '"$h"' \
        -policy /etc/keep-testbed/policy-'"$h"'.json -server https://keep-server:8443 -server-ca /pki/server-ca.pem \
        -ttl 5m -uid-shared=false -environment staging -platform linux' \
      | C exec -T "$h" keep-runner enroll -host "$h" -server https://keep-server:8443 \
          -policy /etc/keep/host-policy.json -cred-dir /var/lib/keep-runner/cred -server-ca /etc/keep/pki/server-ca.pem >/dev/null
    C exec -T "$h" systemctl start keep-runner
  done
  psql_op "SELECT host||' '||id FROM runners WHERE org_id='$org' ORDER BY host" >"$OUT/state/runners"

  say "== deployment policy: which secret may go where, without a person's approval"
  local rules="" id host kind path field unit consumer rid
  while read -r id host kind path _ _ _; do
    rid=$(runner_of "$host")
    rules+="{\"secret_id\":\"$(state secret)\",\"runner_id\":\"$rid\",\"kind\":\"$kind\",\"path_prefix\":\"$(dirname "$path")\"},"
  done <<<"$CARRIERS"
  printf '{"rules":[%s]}' "${rules%,}" | OP sh -c 'cat >/exchange/deploy-policy.json; chmod 0644 /exchange/deploy-policy.json'
  C run --rm --no-deps keep-server set-deploy-policy --org-id "$org" --policy-file /exchange/deploy-policy.json >/dev/null

  say "== five carriers: deploy the first version to each, then register it"
  while read -r id host kind path field unit consumer; do
    local t="{\"kind\":\"$kind\",\"path\":\"$path\",\"uid\":2001,\"gid\":2001,\"mode\":\"0600\",\"consumer\":\"$consumer\""
    [ "$field" = - ] || t+=",\"field\":\"$field\""
    [ "$unit" = - ] || t+=",\"unit\":\"$unit\""
    t+="}"
    local r ok
    r=$(mcp deploy "{\"secret\":\"$SECRET_NAME\",\"runner_id\":\"$(runner_of "$host")\",\"target\":$t,\"wait_seconds\":90}")
    ok=$(jq -r '.ok' <<<"$r")
    say "deploy $id: ok=$ok $(jq -c '{version,fingerprint,error_class,healthcheck}' <<<"$r")"
    [ "$ok" = true ] || die "deploy to $id failed"
    local reg="{\"secret_id\":\"$(state secret)\",\"version\":\"$(jq -r .version <<<"$r")\",\"host\":\"$host\",\"target_kind\":\"$kind\",\"target_path\":\"$path\",\"consumer\":\"$consumer\""
    [ "$field" = - ] || reg+=",\"target_field\":\"$field\""
    reg+="}"
    mcp register_carrier "$reg" | jq -c . | tee -a "$OUT/script.log"
  done <<<"$CARRIERS"
  harvest up
  [ "$MESH" = 0 ] || mesh_consumers
  build_info
  say "== stand is up: 5 carriers on 2 hosts hold version 1"
}

# mesh_up ORG: the disposable Mesh, its workspace linked to Keep, the rotator
# extension installed from the stand's signed catalog and connected, and one
# test agent. Order matters: Keep's install first, Mesh restarted to read it.
mesh_up() {
  say "== disposable Mesh: its own database, the stand's signed catalog, the keep-rotator extension"
  echo 1 >"$OUT/state/mesh"
  C up -d --wait mesh-postgres mesh-redis meshaux >/dev/null
  C up -d --wait mesh >/dev/null
  OP mesh-setup.sh link "$1"
  C up -d --force-recreate --no-deps --wait mesh >/dev/null
  OP mesh-setup.sh connect "$1"
  OP mesh-setup.sh token
  OP mesh-setup.sh agent
  OP cat /operator/mesh/agent-id >"$OUT/state/mesh-agent"
  say "mesh: agent $(state mesh-agent), extension $(OP jq -c '{id,enabled,connected,status}' /operator/mesh/rotator-state.json 2>/dev/null)"
}

# mesh_consumers: from now on each consumer proves its credential at Mesh, at
# start and on every health request (CONSUMER_VERIFY_URL), not by a marker.
mesh_consumers() {
  local id host kind path field unit consumer
  while read -r id host kind path field unit consumer; do
    unit=${consumer#systemd:}
    HX "$host" sh -c "install -d /etc/systemd/system/$unit.d
      printf '[Service]\nEnvironment=CONSUMER_VERIFY_URL=http://keep-server:8005/api/v1/agents/me\n' >/etc/systemd/system/$unit.d/verify.conf
      systemctl daemon-reload && systemctl restart $unit"
  done <<<"$CARRIERS"
  health up
  jq -e 'all(.[]; .health == "PASS")' "$OUT/runs/up-health.json" >/dev/null || die "a consumer did not accept the first Mesh key at Mesh"
}

# carrier_value HOST KIND PATH FIELD UNIT: the credential a carrier file holds, read
# on its host and written to stdout, which is always a pipe into the operator's
# needle directory, never a terminal.
carrier_value() {
  case "$2" in
    env-file|hermes-config) HX "$1" sed -n "s/^$4=//p" "$3" ;;
    mcp-config) HX "$1" jq -j ".$4 // empty" "$3" ;;
    file) HX "$1" cat "$3" ;;
    # Sealed to the host: decrypted there under its name UNIT, straight into the pipe.
    # Its diagnostics stay on the host: a failed decrypt is a short needle, a failure.
    systemd-credential) HX "$1" systemd-creds decrypt --name="$5" "$3" - 2>/dev/null ;;
  esac
}

# needle NAME: stdin, without newlines and quotes, becomes /operator/needles/NAME.
# A needle that came back empty or short would be skipped by the scan and leave
# the value unsearched: it is a failure here, not a quiet gap.
needle() {
  OP sh -c 'umask 077; tr -d "\n\"'"'"'" >/operator/needles/'"$1"'
    test "$(wc -c </operator/needles/'"$1"')" -ge 16'
}

# harvest TAG [PREV [ok|failed]]: the value each carrier holds goes from its host into the
# operator's needle directory (stand-only, never to a terminal), so the leak
# scan also looks for the values the stand itself generated. So does every
# value a consumer started on since the last harvest: each start leaves a copy of
# its carrier in the host's /var/lib/testbed-seen (host/seen.sh), so a value a
# failed run delivered and its rollback took off again is a needle too.
harvest() {
  local id host kind path field unit consumer f k
  while read -r id host kind path field unit consumer; do
    carrier_value "$host" "$kind" "$path" "$field" "$unit" | needle "carrier-$id-$1" || die "harvest: carrier $id holds no readable credential after $1"
    k=0
    for f in $(HX "$host" sh -c "find /var/lib/testbed-seen -maxdepth 1 -type f -name '$id.*' 2>/dev/null | sort"); do
      k=$((k + 1))
      carrier_value "$host" "$kind" "$f" "$field" "$unit" | needle "seen-$id-$1-$k" || die "harvest: the copy of carrier $id taken at a consumer start holds no readable credential"
      HX "$host" rm -f "$f"
    done
  done <<<"$CARRIERS"
  [ -z "${2:-}" ] || OP sh -c 'new=0
    for f in /operator/needles/carrier-*-'"$1"' /operator/needles/seen-*-'"$1"'-*; do
      [ -e "$f" ] || continue
      same=0
      for g in /operator/needles/carrier-*-'"$2"'; do cmp -s "$f" "$g" && same=1; done
      [ "$same" = 1 ] || new=1
    done
    exit $((1 - new))' || {
      # A successful run replaced every carrier's value, so none new is a harness fault.
      # A failed run may have stopped before any consumer started on it: say so, do not hide it.
      [ "${3:-}" = ok ] || { say "NOTE: after $1 neither a carrier nor a consumer start holds a value that $2 did not; the run's new value cannot be a needle"; : >"$OUT/state/unscanned-$1"; return 0; }
      die "harvest: no carrier holds a value that $2 did not: this run's new value is not among the needles"
    }
}

# snapshot N: what the server holds after run N, as the operator reads it.
# steps are the run's own per-carrier record: the rotate answer marks every
# carrier of a failed run that was not confirmed as stale, the steps say which
# one failed verification and with what class.
snapshot() {
  local sid rid; sid=$(state secret); rid=$(jq -r .request_id "$OUT/runs/$1-rotate.json")
  psql_op "SELECT json_build_object(
    'carriers', (SELECT json_agg(json_build_object('id',id,'host',host,'kind',target_kind,'path',target_path,'state',state,'version',version,'fingerprint',last_fp) ORDER BY created_at) FROM carriers WHERE secret_id='$sid'),
    'steps', (SELECT json_agg(json_build_object('carrier_id',st.carrier_id,'path',c.target_path,'deploy',st.deploy_state,'verify',st.verify_state,'error_class',st.error_class) ORDER BY c.created_at)
              FROM rotation_steps st JOIN carriers c ON c.id::text=st.carrier_id WHERE st.run_id::text='$rid'),
    'versions', (SELECT json_agg(json_build_object('version',provider_version,'fingerprint',fingerprint,'length',length,'disabled',disabled) ORDER BY seal_seq) FROM secret_versions WHERE secret_id='$sid'))" >"$OUT/runs/$1-state.json"
  mcp get_secret_meta "{\"secret_id\":\"$sid\"}" >"$OUT/runs/$1-meta.json"
}

# health N: the consumers, asked directly on their hosts: an http consumer
# must answer with its marker, the others must be running.
health() {
  local id host kind path field unit consumer u port out="[" st
  while read -r id host kind path field unit consumer; do
    u=${consumer#systemd:}
    case "$id" in a1) port=19101 ;; a2) port=19102 ;; a3) port=19103 ;; b1) port=19201 ;; b2) port=19202 ;; *) port= ;; esac
    if [ -n "$port" ]; then
      HX "$host" sh -c "curl -fsS --max-time 5 http://127.0.0.1:$port/ 2>/dev/null | grep -q consumer-ok:$id" && st=PASS || st=FAIL
    else
      HX "$host" systemctl is-active --quiet "$u" && st=PASS || st=FAIL
    fi
    out+="{\"carrier\":\"$id\",\"consumer\":\"$u\",\"health\":\"$st\"},"
  done <<<"$CARRIERS"
  printf '%s]' "${out%,}" | jq -c . >"$OUT/runs/$1-health.json"
  say "health: $(jq -c '[.[]|"\(.carrier)=\(.health)"]' "$OUT/runs/$1-health.json")"
}

rotate() {
  local n; n=$(find "$OUT/runs" -type f -name '*-rotate.json' | wc -l | tr -d ' ')
  local prev=up; [ "$n" -eq 0 ] || prev="run$(printf '%02d' "$n")"
  n=$(printf '%02d' "$((n + 1))")
  # The version current before the run: a failed run's carriers are named against it.
  psql_op "SELECT provider_version FROM secret_versions WHERE secret_id='$(state secret)' AND NOT disabled ORDER BY seal_seq DESC LIMIT 1" >"$OUT/runs/$n-before-version"
  mcp rotate "{\"secret_id\":\"$(state secret)\",\"mode\":\"generate\",\"wait_seconds\":120}" >"$OUT/runs/$n-rotate.json"
  say "rotate: $(jq -c . "$OUT/runs/$n-rotate.json")"
  C logs --no-color keep-server 2>&1 | grep 'rotation incident opened' | grep "$(jq -r .request_id "$OUT/runs/$n-rotate.json")" >"$OUT/runs/$n-incident.log" || true
  local result=ok; jq -e .ok "$OUT/runs/$n-rotate.json" >/dev/null || result=failed
  harvest "run$n" "$prev" "$result"
  snapshot "$n"
  health "$n"
  [ "$result" = ok ] || carrier_versions "$n" "$prev"
  jq -e . "$OUT/runs/$n-rotate.json" >/dev/null
}

# carrier_paths: the stand's carrier ids by registered path, as a JSON object.
carrier_paths() {
  awk 'BEGIN { printf "{" } { printf "%s\"%s\":\"%s\"", (NR > 1 ? "," : ""), $4, $1 } END { printf "}" }' <<<"$CARRIERS"
}

# carrier_versions N PREV: after the failed run N, which version each carrier
# holds. verify_carriers, through `keep mcp`, has each runner read its carrier
# and compare it with the version Keep names current now. The fingerprint the
# runner reported is taken from that verification (the expected one on a match,
# the observed one on a mismatch) and named by the version it belongs to: new
# (the version run N created), previous (the one current before run N) or other.
# value_as_before_run compares, inside the operator's needle directory, the
# value the carrier holds after the run with the one it held before it.
carrier_versions() {
  local n=$1 prev=$2 sid vid id host kind path _ same="{"
  sid=$(state secret)
  mcp verify_carriers "{\"secret\":\"$SECRET_NAME\",\"wait_seconds\":90}" >"$OUT/runs/$n-verify.json"
  vid=$(jq -r .request_id "$OUT/runs/$n-verify.json")
  psql_op "SELECT json_agg(json_build_object('path',c.target_path,'verify',x.state,'fingerprint',x.fp,
      'version',(SELECT sv.provider_version FROM secret_versions sv WHERE sv.secret_id=v.secret_id AND sv.fingerprint=x.fp)) ORDER BY c.created_at)
    FROM carrier_verifications v JOIN carrier_verification_items i ON i.verification_id=v.id JOIN carriers c ON c.id=i.carrier_id
    CROSS JOIN LATERAL (SELECT i.state, CASE WHEN i.state='match' THEN v.expected_fingerprint ELSE i.observed_fingerprint END AS fp) x
    WHERE v.request_id='$vid' AND v.secret_id='$sid'" >"$OUT/runs/$n-verify-items.json"
  while read -r id host kind path _; do
    # </dev/null: inside the loop OP must not eat the loop's input.
    if OP cmp -s "/operator/needles/carrier-$id-run$n" "/operator/needles/carrier-$id-$prev" </dev/null; then same+="\"$id\":true,"; else same+="\"$id\":false,"; fi
  done <<<"$CARRIERS"
  same="${same%,}}"
  local newest
  newest=$(psql_op "SELECT provider_version FROM secret_versions WHERE secret_id='$sid' ORDER BY seal_seq DESC LIMIT 1")
  jq -n --arg run "$n" --arg before "$(cat "$OUT/runs/$n-before-version")" --arg newest "$newest" \
    --argjson ids "$(carrier_paths)" --argjson same "$same" --slurpfile items "$OUT/runs/$n-verify-items.json" \
    --slurpfile vr "$OUT/runs/$n-verify.json" --slurpfile st "$OUT/runs/$n-state.json" \
    '($st[0].carriers | map({key:.path, value:{host, kind}}) | from_entries) as $where
     | {run:$run, previous_version:$before, new_version:(if $newest != $before then $newest else null end),
        verify_request_id:$vr[0].request_id, verify_ok:$vr[0].ok, current_version:($vr[0].version // null),
        carriers:[($items[0] // [])[] | . as $c | {carrier:$ids[$c.path], host:$where[$c.path].host, kind:$where[$c.path].kind, path:$c.path,
          verify:$c.verify, fingerprint:$c.fingerprint, version:$c.version,
          holds:(if $c.version == null then null elif $c.version == $before then "previous" elif $c.version == $newest then "new" else "other" end),
          value_as_before_run:$same[$ids[$c.path]]}]}' >"$OUT/runs/$n-carrier-versions.json"
  say "carrier versions after run $n: $(jq -c '[.carriers[]|"\(.carrier)=\(.version)/\(.holds)"]' "$OUT/runs/$n-carrier-versions.json")"
}

# tamper: a carrier changed behind Keep's back. a1's file is saved on host-a and
# a one-time wrong value of the same form (each letter and digit replaced by a
# random one of its class, every other character kept) is written in its place:
# verify_carriers through `keep mcp` must find a1 fingerprint_mismatch and the
# other four match. The saved copy is then put back and all five must match.
# The wrong value is made on host-a, goes from there into the operator's needle
# directory only, and is never printed.
TAMPER_A1=/srv/app/a1/app.env
TAMPER_SAVED=/root/a1-app.env.tamper
# tamper_back: a1's saved copy goes back in place (also after a failed change).
tamper_back() { HX host-a sh -c "rm -f $TAMPER_A1.new; cp -p $TAMPER_SAVED $TAMPER_A1 && rm -f $TAMPER_SAVED"; }
tamper() {
  HX host-a cp -p "$TAMPER_A1" "$TAMPER_SAVED"
  # No pipe in the seed: a failed od stops the change instead of an empty seed
  # that makes the same "random" value every time.
  C exec -T -e "F=$TAMPER_A1" host-a sh -s <<'EOF' || { tamper_back; die "tamper: a1 could not be changed on host-a"; }
set -e
umask 077
seed=$(od -An -N4 -tu4 /dev/urandom)
[ -n "$seed" ]
awk -v seed="$seed" '
  BEGIN { srand(seed); lo = "abcdefghijklmnopqrstuvwxyz"; up = toupper(lo); di = "0123456789" }
  /^API_TOKEN=/ {
    v = substr($0, 11); w = ""
    for (i = 1; i <= length(v); i++) {
      c = substr(v, i, 1)
      if (c ~ /[a-z]/) c = substr(lo, int(rand() * 26) + 1, 1)
      else if (c ~ /[A-Z]/) c = substr(up, int(rand() * 26) + 1, 1)
      else if (c ~ /[0-9]/) c = substr(di, int(rand() * 10) + 1, 1)
      w = w c
    }
    print "API_TOKEN=" w; next
  }
  { print }' "$F" >"$F.new"
chown --reference="$F" "$F.new"; chmod --reference="$F" "$F.new"; mv "$F.new" "$F"
EOF
  carrier_value host-a env-file "$TAMPER_A1" API_TOKEN - | needle tamper-a1 || { tamper_back; die "tamper: a1 holds no readable credential after the change"; }
  say "tamper: a1 on host-a now holds a one-time wrong value of the same form"
  # mcp can exit the shell for a malformed reply. Isolate that exit so every
  # failed verification restores a1 before the command reports failure.
  (mcp verify_carriers "{\"secret\":\"$SECRET_NAME\",\"wait_seconds\":90}") >"$OUT/runs/tamper-before.json" || {
    tamper_back
    die "tamper: verify_carriers failed while a1 was changed"
  }
  tamper_back
  say "tamper: a1's saved copy is back"
  mcp verify_carriers "{\"secret\":\"$SECRET_NAME\",\"wait_seconds\":90}" >"$OUT/runs/tamper-after.json"
  local row='{ok, request_id, version, fingerprint, carriers:([.carriers[]|{carrier:$ids[.target.path], status, fingerprint_match, error_class:(.error_class // null)}]|sort_by(.carrier))}'
  jq -n --argjson ids "$(carrier_paths)" --arg path "$TAMPER_A1" \
    --slurpfile b "$OUT/runs/tamper-before.json" --slurpfile a "$OUT/runs/tamper-after.json" \
    "{carrier:\"a1\", path:\$path, before:(\$b[0]|$row), after:(\$a[0]|$row)}" >"$OUT/runs/tamper.json"
  say "tamper: before $(jq -c '[.before.carriers[]|"\(.carrier)=\(.status)\(if .error_class then "/"+.error_class else "" end)"]' "$OUT/runs/tamper.json"), after $(jq -c '[.after.carriers[]|"\(.carrier)=\(.status)"]' "$OUT/runs/tamper.json")"
}

check_tamper() {
  local rc=0
  expect "tamper: before, a1 fingerprint_mismatch and the other four match" "$TAMPER_BEFORE" "$OUT/runs/tamper.json" || rc=1
  expect "tamper: after the copy is back, all five match"                 "$TAMPER_AFTER" "$OUT/runs/tamper.json" || rc=1
  return $rc
}

# rotate_mesh: rotate() with Mesh asked about the keys before and after: the
# ids it lists (ids only), and what the old and the new key get from GET
# /agents/me.
rotate_mesh() {
  [ "$MESH" = 1 ] || die "rotate-mesh needs a stand brought up with --mesh"
  local n; n=$(find "$OUT/runs" -type f -name '*-rotate.json' | wc -l | tr -d ' ')
  local prev=up; [ "$n" -eq 0 ] || prev="run$(printf '%02d' "$n")"
  n=$(printf '%02d' "$((n + 1))")
  local before old_before rev_before
  before=$(OP mesh-setup.sh keys)
  rev_before=$(OP mesh-setup.sh revoked)
  old_before=$(OP mesh-setup.sh probe "/operator/needles/carrier-a1-$prev")
  local rc=0; rotate || rc=$?
  local after rev_after old new=none
  after=$(OP mesh-setup.sh keys)
  rev_after=$(OP mesh-setup.sh revoked)
  old=$(OP mesh-setup.sh probe "/operator/needles/carrier-a1-$prev")
  if jq -e .ok "$OUT/runs/$n-rotate.json" >/dev/null; then new=$(OP mesh-setup.sh probe "/operator/needles/carrier-a1-run$n"); fi
  # issued_ids: the keys Mesh lists after the run and did not list before, active
  # or revoked: the key this run issued. revoked_ids_after: every revoked key of
  # the agent. Ids only, never values.
  jq -n --argjson b "$before" --argjson a "$after" --argjson rb "$rev_before" --argjson ra "$rev_after" \
    --arg ob "$old_before" --arg o "$old" --arg nw "$new" --arg agent "$(state mesh-agent)" \
    '{agent_id:$agent, key_ids_before:$b, key_ids_after:$a, key_id_changed:($b != $a),
      revoked_ids_after:$ra, issued_ids:((($a + $ra) | unique) - (($b + $rb) | unique)),
      old_key_http_before:($ob|tonumber), old_key_http_after:($o|tonumber), new_key_http:(if $nw == "none" then null else ($nw|tonumber) end)}' \
    >"$OUT/runs/$n-mesh.json"
  say "rotate-mesh: $(jq -c . "$OUT/runs/$n-mesh.json")"
  return $rc
}

# build_info: what is running, by hash, as read inside the running containers.
build_info() {
  # working_tree_dirty names what made the tree dirty: paths only, never contents.
  # Outside a git checkout (a copied tree) there is nothing to report and the
  # commit says unknown; awk reads to the end, so a long list breaks no pipe.
  local dirty=false st
  st=$(git -C "$SRC" status --porcelain 2>/dev/null) || st=
  st=$(printf '%s\n' "$st" | awk 'NR <= 50 && length($0) > 3 { print substr($0, 4) }')
  [ -z "$st" ] || dirty=true
  local img="${TESTBED_PROJECT:-keep-rotation-testbed}"
  jq -n --arg commit "$TESTBED_COMMIT" --argjson dirty "$dirty" \
    --argjson dirty_paths "$(printf '%s\n' "$st" | jq -Rsc 'split("\n") | map(select(length > 0))')" \
    --arg keep "$(HX operator keep -V)" --arg runner "$(HX host-a keep-runner version 2>&1 | head -1 | sed 's/: unknown command$//')" \
    --arg srv_sha "$(HX keep-server sha256sum /usr/local/bin/keep-server | cut -d' ' -f1)" \
    --arg keep_sha "$(HX operator sha256sum /usr/local/bin/keep | cut -d' ' -f1)" \
    --arg runner_a_sha "$(HX host-a sha256sum /usr/local/bin/keep-runner | cut -d' ' -f1)" \
    --arg runner_b_sha "$(HX host-b sha256sum /usr/local/bin/keep-runner | cut -d' ' -f1)" \
    --arg consumer_sha "$(HX host-a sha256sum /usr/local/bin/consumer | cut -d' ' -f1)" \
    --arg img_server "$(docker image inspect --format '{{.Id}}' "$img-server")" \
    --arg img_tools "$(docker image inspect --format '{{.Id}}' "$img-tools")" \
    --arg img_host "$(docker image inspect --format '{{.Id}}' "$img-host")" \
    --argjson srv_version "$(HX operator curl -fsS http://keep-server:8080/version)" \
    '{commit:$commit, working_tree_dirty:$dirty, dirty_paths:$dirty_paths,
      versions:{keep:$keep, keep_runner:$runner, keep_server:$srv_version},
      binaries_sha256:{"keep-server":$srv_sha, keep:$keep_sha, "keep-runner@host-a":$runner_a_sha, "keep-runner@host-b":$runner_b_sha, consumer:$consumer_sha},
      images:{server:$img_server, tools:$img_tools, host:$img_host}}' >"$OUT/state/build.json"
}

# scan: the six-encoding canary scan over everything the stand produced.
scan() {
  local d="$OUT/scan"; rm -rf "$d"; mkdir -p "$d"
  cat "$OUT"/mcp/*.json "$OUT"/runs/*.json >"$d/mcp-replies" 2>/dev/null || true
  cat "$OUT"/discover/*.json "$OUT"/discover/*.err >"$d/discover-replies" 2>/dev/null || true
  cp "$OUT/script.log" "$d/script-output"
  cp "$OUT/terminal.log" "$d/terminal"
  C logs --no-color agent admin operator postgres >"$d/container-logs" 2>&1
  C logs --no-color keep-server >"$d/server-log" 2>&1
  if [ "$MESH" != 0 ]; then
    C logs --no-color mesh meshaux mesh-postgres mesh-redis >"$d/mesh-logs" 2>&1 || die "could not read the Mesh containers' logs"
    # An empty log would scan clean for the wrong reason.
    [ "$(wc -c <"$d/mesh-logs")" -gt 200 ] || die "the Mesh containers' logs are empty: nothing to scan"
  fi
  HX host-a journalctl --no-pager >"$d/runner-a-log"
  HX host-b journalctl --no-pager >"$d/runner-b-log"
  psql_op "SELECT to_jsonb(a)::text FROM audit_records a ORDER BY org_seq" >"$d/journal"
  [ ! -f "$OUT/receipt.json" ] || cp "$OUT/receipt.json" "$d/receipt"
  tar -C "$d" -cf - . | OP sh -c 'rm -rf /operator/scan && mkdir -p /operator/scan && tar -x -C /operator/scan'
  # Positive control: a canary mixed into a copy of the server log must be caught.
  OP sh -c 'cat /operator/scan/server-log /operator/needles/canary-v1 >/operator/scan/control'
  local ctl="control=/operator/scan/control"
  if [ "$MESH" != 0 ]; then
    OP sh -c 'cat /operator/scan/mesh-logs /operator/needles/canary-v1 >/operator/scan/control-mesh'
    ctl="$ctl control-mesh=/operator/scan/control-mesh"
  fi
  local labels="" f
  for f in script-output terminal container-logs mcp-replies discover-replies server-log runner-a-log runner-b-log journal mesh-logs receipt; do
    [ -f "$d/$f" ] && labels+=" $f=/operator/scan/$f"
  done
  if OP leakscan -needles /operator/needles -control $ctl >"$OUT/scan.control" 2>&1; then
    die "the scanner did not catch a canary mixed into a log (positive control)"
  fi
  grep -q '^LEAK control' "$OUT/scan.control" || die "positive control gave no LEAK line"
  [ "$MESH" = 0 ] || grep -q '^LEAK control-mesh' "$OUT/scan.control" || die "positive control on the Mesh logs gave no LEAK line"
  say "scan control: a canary mixed into a log copy is caught ($(grep -c . "$OUT/scan.control") lines)"
  # shellcheck disable=SC2086
  OP leakscan -needles /operator/needles $labels | tee "$OUT/scan.result" >&2 || die "a secret value was found in the stand's output"
}

# mesh_receipt: what the Mesh part of a run stands on: the commits and images,
# the catalog artifact and its public key (both public), the agent, and for each
# run the key ids before and after (ids, never values) with what Mesh said of
# the old and the new key.
mesh_receipt() {
  local img="${TESTBED_PROJECT:-keep-rotation-testbed}" runs="[" f n
  for f in "$OUT"/runs/*-mesh.json; do
    [ -f "$f" ] || continue
    n=$(basename "$f" -mesh.json)
    runs+=$(jq -c --arg run "$n" '{run:$run} + .' "$f"),
  done
  jq -n --arg keep "$TESTBED_COMMIT" --arg mesh_sha "$(git -C "$TESTBED_MESH_SRC" rev-parse HEAD)" \
    --arg img_mesh "$(docker image inspect --format '{{.Id}}' "$img-mesh")" \
    --arg img_aux "$(docker image inspect --format '{{.Id}}' "$img-meshaux")" \
    --arg bin "$(HX mesh sha256sum /usr/local/bin/mesh-api 2>/dev/null | cut -d' ' -f1)" \
    --arg art "$(OP cat /exchange/catalog-artifact-sha256)" --arg pub "$(OP cat /exchange/catalog-public-key)" \
    --arg agent "$(state mesh-agent)" --argjson runs "${runs%,}]" \
    '{mesh_build_tags:"e2eloopback", commits:{keep:$keep, evc_mesh:$mesh_sha}, images:{mesh:$img_mesh, meshaux:$img_aux}, mesh_api_binary_sha256:$bin,
      catalog:{artifact_sha256:$art, public_key:$pub}, agent_id:$agent, runs:$runs}'
}

# sealed: each systemd-credential carrier, as its host holds it now. The tool is
# the distribution's own systemd-creds (not a stand-in); the file's raw bytes
# are scanned for every value the stand knows, in all six encodings (none may
# be there: the file is ciphertext); it decrypts under its credential name and
# is refused under another. Only booleans, the tool's version and the package
# that owns it leave the host.
# The two filters on the systemd credential carrier are kept on one line each:
# check-testbed-mutation.sh reads them from here and shows every term failing.
SEALED_OK='.sealed_carriers|length == 1 and all(.[]; .carrier == "a3" and .tool_package == "systemd" and .tool_as_shipped == true and (.tool|startswith("systemd ")) and .value_in_file == false and .decrypts_under_its_name == true and .decrypts_under_another_name == false)'
A3_KIND_OK='[.carriers[]|select(.path=="/srv/app/a3/api_token.cred")|.kind] == ["systemd-credential"]'
# Scenario 2: the failed run is rolled back. The version it created (3) is
# disabled and the previous one (2) is the only version not disabled, current
# again. One line, for the same reason as the two filters above.
ROLLED_BACK='[.versions[]|select(.status!="disabled")|.version] == ["2"] and [.versions[]|select(.version=="2")|.status] == ["current"] and [.versions[]|select(.version=="3")|.status] == ["disabled"]'
# Scenario 2, carrier by carrier: the run created version 3 and was rolled back,
# so every carrier, the broken a3 too, holds version 2 again: its runner reads a
# match against the current version 2, the fingerprint it reports is version 2's,
# and the value is byte for byte the one it held before the run.
ON_PREVIOUS='.previous_version == "2" and .new_version == "3" and .current_version == "2" and .verify_ok == true and ([.carriers[].carrier]|sort) == ["a1","a2","a3","b1","b2"] and all(.carriers[]; .verify == "match" and .version == "2" and .holds == "previous" and .value_as_before_run == true)'
# tamper (below): a1 changed behind Keep's back is a mismatch of class
# fingerprint_mismatch while the other four match; with its copy back, all match.
TAMPER_BEFORE='.carrier == "a1" and .before.ok == false and ([.before.carriers[]|select(.carrier == "a1")|"\(.status) \(.error_class) \(.fingerprint_match)"] == ["mismatch fingerprint_mismatch false"]) and ([.before.carriers[]|select(.carrier != "a1")|.carrier] == ["a2","a3","b1","b2"]) and all(.before.carriers[]|select(.carrier != "a1"); .status == "match")'
TAMPER_AFTER='.after.ok == true and ([.after.carriers[].carrier] == ["a1","a2","a3","b1","b2"]) and all(.after.carriers[]; .status == "match" and .fingerprint_match == true)'
sealed() {
  local out="[" id host kind path field unit consumer plain under other tool pkg unmod
  while read -r id host kind path field unit consumer; do
    [ "$kind" = systemd-credential ] || continue
    tool=$(HX "$host" systemd-creds --version | head -1)
    # Debian registers the merged-/usr binary under /bin; dpkg -V lists a file
    # of the package whose content no longer matches what the package shipped.
    pkg=$(HX "$host" dpkg -S /bin/systemd-creds | cut -d: -f1)
    if HX "$host" sh -c 'dpkg -V systemd | grep -q systemd-creds'; then unmod=false; else unmod=true; fi
    HX "$host" cat "$path" | OP sh -c 'umask 077; cat >/operator/sealed-'"$id"
    OP sh -c 'test -s /operator/sealed-'"$id" || die "sealed: carrier $id is empty on $host"
    if OP leakscan -needles /operator/needles -control "raw-$id=/operator/sealed-$id" >>"$OUT/sealed.scan" 2>&1; then plain=false
    else plain=true; fi
    grep -q "^clean raw-$id" "$OUT/sealed.scan" || plain=true
    HX "$host" systemd-creds decrypt --name="$unit" "$path" /dev/null >/dev/null 2>&1 && under=true || under=false
    HX "$host" systemd-creds decrypt --name="$unit-other" "$path" /dev/null >/dev/null 2>&1 && other=true || other=false
    out+=$(jq -nc --arg id "$id" --arg host "$host" --arg path "$path" --arg name "$unit" --arg tool "$tool" --arg pkg "$pkg" \
      --argjson unmod "$unmod" --argjson plain "$plain" --argjson under "$under" --argjson other "$other" \
      '{carrier:$id, host:$host, path:$path, credential_name:$name, tool:$tool, tool_package:$pkg, tool_as_shipped:$unmod,
        value_in_file:$plain, decrypts_under_its_name:$under, decrypts_under_another_name:$other}'),
  done <<<"$CARRIERS"
  printf '%s]' "${out%,}"
}

receipt() {
  scan
  local hosts="[" h
  for h in host-a host-b; do
    hosts+=$(jq -nc --arg h "$h" --arg mid "$(HX "$h" cat /etc/machine-id)" --arg ip "$(HX "$h" hostname -i)" --arg rid "$(runner_of "$h")" \
      '{host:$h, machine_id:$mid, address:$ip, runner_id:$rid}'),
  done
  local runs="[" f n
  for f in "$OUT"/runs/*-rotate.json; do
    [ -f "$f" ] || continue
    n=$(basename "$f" -rotate.json)
    runs+=$(jq -c --slurpfile r "$f" --slurpfile st "$OUT/runs/$n-state.json" --slurpfile m "$OUT/runs/$n-meta.json" \
      --slurpfile hl "$OUT/runs/$n-health.json" --argjson cv "$(cat "$OUT/runs/$n-carrier-versions.json" 2>/dev/null || echo null)" --arg inc "$(grep -c . "$OUT/runs/$n-incident.log" || true)" --argjson scanned "$([ -e "$OUT/state/unscanned-run$n" ] && echo false || echo true)" -n \
      '{run:"'"$n"'", run_id:$r[0].request_id, ok:$r[0].ok, error_class:($r[0].error_class // null), incident_opened:($r[0].incident_opened // false),
        incident_logged_with_run_id:(($inc|tonumber) > 0), new_value_scanned:$scanned,
        new_version:($r[0].version // null), carrier_progress:$r[0].carriers,
        carriers:[$st[0].carriers[] as $c | $c + ($r[0].carriers[]|select(.carrier_id==$c.id)|{state:.state, phase:.phase}) + {registered_state:$c.state}],
        steps:[$st[0].steps[]? | {path, deploy, verify, error_class}],
        versions:$m[0].versions,
        active_versions:[$m[0].versions[]|select(.status!="disabled")|.version],
        disabled_versions:[$m[0].versions[]|select(.status=="disabled")|.version],
        consumers:$hl[0]} + (if $cv == null then {} else {carrier_versions:$cv} end)'),
  done
  local mesh=null discovery=null tamper=null sealed_json
  [ "$MESH" = 0 ] || mesh=$(mesh_receipt)
  [ ! -f "$OUT/runs/tamper.json" ] || tamper=$(cat "$OUT/runs/tamper.json")
  [ ! -f "$OUT/discover/summary.json" ] || discovery=$(cat "$OUT/discover/summary.json")
  : >"$OUT/sealed.scan"
  sealed_json=$(sealed)
  jq -n --slurpfile b "$OUT/state/build.json" --argjson hosts "${hosts%,}]" --argjson runs "${runs%,}]" --argjson mesh "$mesh" --argjson sealed "$sealed_json" \
    --argjson discovery "$discovery" --argjson tamper "$tamper" --arg control "caught" --rawfile res "$OUT/scan.result" \
    '$b[0] + {hosts:$hosts, runs:$runs, sealed_carriers:$sealed} + (if $mesh == null then {} else {mesh:$mesh} end) + (if $discovery == null then {} else {discovery:$discovery} end) + (if $tamper == null then {} else {tamper:$tamper} end) + {leak_scan:{control:$control, result:($res|split("\n")|map(select(length>0)))}}' >"$OUT/receipt.json"
  # The receipt itself is scanned too; its own result is on stderr.
  OP sh -c 'rm -f /operator/scan/receipt'; tar -C "$OUT" -cf - receipt.json | OP tar -x -C /operator/scan
  OP leakscan -needles /operator/needles receipt=/operator/scan/receipt.json >&2 || die "a secret value was found in the receipt"
  # A credential carrier that holds its value in the clear, or opens under any
  # name, is not what the stand claims to run: the receipt says so and fails.
  expect "a3: sealed by the distribution's systemd-creds, no value in the file, bound to its name" "$SEALED_OK" \
    "$OUT/receipt.json" || die "the systemd credential carrier is not sealed as claimed (receipt.json: sealed_carriers)"
  cat "$OUT/receipt.json"
}

down() {
  C down -v --remove-orphans >/dev/null 2>&1 || true
  say "stand removed"
}

# check_ok / check_failed: the acceptance checks on a finished run, one
# line each, so a failed property is named.
expect() { # label jq-filter file
  if jq -e "$2" "$3" >/dev/null; then say "PASS $1"; else say "FAIL $1"; return 1; fi
}
check_ok() {
  local n=$1 rc=0
  expect "scenario 1: rotate returned ok=true"                       '.ok == true' "$OUT/runs/$n-rotate.json" || rc=1
  expect "scenario 1: all 5 carriers state=ok"                       '[.carriers[]|select(.state=="ok")]|length == 5' "$OUT/runs/$n-rotate.json" || rc=1
  expect "scenario 1: all carriers hold the new fingerprint"         '([.carriers[].fingerprint]|unique|length) == 1' "$OUT/runs/$n-state.json" || rc=1
  expect "scenario 1: carrier a3 is a systemd credential"            "$A3_KIND_OK" "$OUT/runs/$n-state.json" || rc=1
  expect "scenario 1: health PASS on all 5 consumers"                'length == 5 and all(.[]; .health == "PASS")' "$OUT/runs/$n-health.json" || rc=1
  expect "scenario 1: one new active version, the old one disabled"  '[.versions[]|select(.status!="disabled")|.version] == ["2"] and [.versions[]|select(.status=="disabled")|.version] == ["1"]' "$OUT/runs/$n-meta.json" || rc=1
  return $rc
}
check_failed() {
  local n=$1 rc=0
  expect "scenario 2: rotate returned ok=false"                      '.ok == false' "$OUT/runs/$n-rotate.json" || rc=1
  expect "scenario 2: error_class is deploy_failed or unhealthy"     '.error_class == "deploy_failed" or .error_class == "unhealthy"' "$OUT/runs/$n-rotate.json" || rc=1
  expect "scenario 2: rolled back: the new version disabled, the old one current" "$ROLLED_BACK" "$OUT/runs/$n-meta.json" || rc=1
  expect "scenario 2: incident_opened is true in the answer"         '.incident_opened == true' "$OUT/runs/$n-rotate.json" || rc=1
  [ -s "$OUT/runs/$n-incident.log" ] && say "PASS scenario 2: 'rotation incident opened' is in the server log with the run id" \
    || { say "FAIL scenario 2: no 'rotation incident opened' line with the run id"; rc=1; }
  # The new value reached the consumers before the run failed: it must be among
  # the leak scan's needles even when a rollback took it off every carrier.
  [ ! -e "$OUT/state/unscanned-run$n" ] && say "PASS scenario 2: the failed run's new value is a leak-scan needle" \
    || { say "FAIL scenario 2: the failed run's new value is not among the leak-scan needles"; rc=1; }
  expect "scenario 2: every carrier holds the previous version again (verify_carriers, fingerprint, value)" "$ON_PREVIOUS" "$OUT/runs/$n-carrier-versions.json" || rc=1
  return $rc
}

check_mesh_ok() {
  local n=$1 rc=0 f="$OUT/runs/$1-mesh.json"
  expect "mesh 1: the old key worked before the rotation"            '.old_key_http_before == 200' "$f" || rc=1
  expect "mesh 1: the key ids in Mesh changed"                       '.key_id_changed == true' "$f" || rc=1
  expect "mesh 1: the new key is accepted by Mesh"                   '.new_key_http == 200' "$f" || rc=1
  expect "mesh 1: the old key is revoked (401)"                      '.old_key_http_after == 401' "$f" || rc=1
  return $rc
}
check_mesh_failed() {
  local n=$1 rc=0 f="$OUT/runs/$1-mesh.json"
  expect "mesh 2: the old key is still alive (200) after the failure" '.old_key_http_after == 200' "$f" || rc=1
  expect "mesh 2: one active key, the old one (key ids unchanged)"    '(.key_ids_before|length) == 1 and .key_ids_after == .key_ids_before' "$f" || rc=1
  expect "mesh 2: the run issued exactly one key in Mesh"             '(.issued_ids|length) == 1' "$f" || rc=1
  expect "mesh 2: the key issued in the failed run is revoked"        '(.issued_ids|length) == 1 and (.issued_ids - .revoked_ids_after) == []' "$f" || rc=1
  expect "mesh 2: rolled back: the new version disabled, the old one current" '[.versions[]|select(.version=="3")|.status] == ["disabled"] and [.versions[]|select(.version=="2")|.status] == ["current"]' "$OUT/runs/$n-meta.json" || rc=1
  expect "mesh 2: health PASS on a1 a2 b1 b2, FAIL on the broken a3"  '([.[]|select(.health == "PASS")|.carrier]|sort) == ["a1","a2","b1","b2"] and ([.[]|select(.carrier == "a3")|.health] == ["FAIL"])' "$OUT/runs/$n-health.json" || rc=1
  return $rc
}

# all: the whole path, from nothing to a receipt, failing on the first broken property.
all() {
  up
  local r=rotate bad=0; [ "$MESH" = 0 ] || r=rotate_mesh
  $r
  check_ok 01 || bad=1
  if [ "$MESH" = 1 ]; then check_mesh_ok 01 || bad=1; fi
  tamper
  check_tamper || bad=1
  break_third
  $r || true
  check_failed 02 || bad=1
  if [ "$MESH" = 1 ]; then check_mesh_failed 02 || bad=1; fi
  receipt >"$OUT/receipt.out"
  jq -e '(.runs|length == 2) and .tamper.carrier == "a1" and (.runs[1].carrier_versions.carriers|length == 5)' "$OUT/receipt.out" >/dev/null || die "receipt stdout is not the clean JSON receipt"
  expect "hosts: two hosts with their own machine id, address and runner" \
    '.hosts|length == 2 and all(.[]; (.machine_id|test("^[0-9a-f]{32}$")) and (.runner_id|length > 0))
      and ([.[].machine_id]|unique|length) == 2 and ([.[].address]|unique|length) == 2 and ([.[].runner_id]|unique|length) == 2' \
    "$OUT/receipt.out" || bad=1
  # The raw replies kept for the scan hold a live input link until redeemed.
  local open; open=$(find "$OUT" \( -perm -040 -o -perm -020 -o -perm -010 -o -perm -004 -o -perm -002 -o -perm -001 \) | head -3)
  [ -z "$open" ] || die "FAIL out files are open to other users: $open"
  say "PASS out directory and files are private to the running user"
  [ "$bad" = 0 ] || die "a scenario property does not hold (the lines above name it)"
  say "all: scenarios 1 and 2 and tamper hold; receipt in $OUT/receipt.json"
}

# The third carrier is a3, on host-a: its consumer is made unable to start,
# so the runner's restart-and-check after a delivery fails there.
break_third() {
  C exec -T host-a sh -c 'install -d /etc/systemd/system/consumer-a3.service.d
    printf "[Service]\nExecStart=\nExecStart=/bin/false\n" >/etc/systemd/system/consumer-a3.service.d/break.conf
    systemctl daemon-reload'
  say "break-third: consumer-a3 on host-a can no longer start"
}

# ---- carrier discovery (docs/rotation-testbed.md, "Discovery") ----
# Each host's policy grants a scan of /srv/app: host-a for API_TOKEN in */app.env
# and GATEWAY_TOKEN in */mcp.json, host-b for SERVICE_TOKEN in */app.env. Of the
# five carriers a1 (env-file), a2 (mcp-config) and b1 (env-file) are ones a scan
# can name; a3 (systemd-credential, registered without a field) and b2 (file)
# are outside discovery.

# discover_one ROUND HOST: the admin asks HOST's runner, through the CLI, to scan
# and compare; the JSON answer and the CLI's exit code are kept.
discover_one() {
  local f="$OUT/discover/$1-$2" rc=0
  ADM keep carriers discover --runner "$(runner_of "$2")" --store "$(state store)" --wait 2m --json >"$f.json" 2>"$f.err" || rc=$?
  echo "$rc" >"$f.exit"
  jq -e '.request_id' "$f.json" >/dev/null || die "discover $1 $2: no report (exit $rc)"
  say "discover $1 $2: exit=$rc state=$(jq -r .state "$f.json") $(jq -c '[.findings[]|"\(.verdict):\(.path)\(if .incident then " incident" else "" end)"]' "$f.json")"
}

# work_counts: what would show a reissue or a delivery: jobs, rotation runs,
# secret versions, and every carrier's registered state and version.
work_counts() {
  psql_op "SELECT json_build_object(
    'deployment_jobs', (SELECT count(*) FROM deployment_jobs),
    'rotation_runs', (SELECT count(*) FROM rotation_runs),
    'secret_versions', (SELECT count(*) FROM secret_versions),
    'carriers', (SELECT json_agg(json_build_object('id',id,'state',state,'version',version,'fingerprint',last_fp) ORDER BY created_at) FROM carriers))"
}

discover() {
  find "$OUT/discover" -delete 2>/dev/null || true
  mkdir -p "$OUT/discover"
  psql_op "SELECT store_id FROM secrets WHERE id='$(state secret)'" >"$OUT/state/store"
  work_counts >"$OUT/discover/work-before.json"

  say "== discovery 1: the hosts as Keep left them"
  discover_one 1 host-a
  discover_one 1 host-b

  say "== the hosts change behind Keep's back"
  # sprawl: a1's line copied into a place no carrier is registered for.
  HX host-a sh -c 'install -d -o root -g root -m 0755 /srv/app/extra
    install -m 0600 -o 2001 -g 2001 /dev/null /srv/app/extra/app.env
    grep "^API_TOKEN=" /srv/app/a1/app.env >>/srv/app/extra/app.env'
  # unknown_find: a2's file is moved out of every scanned root.
  HX host-a mv /srv/app/a2/mcp.json /root/a2-mcp.json.moved
  # stale: b1 now holds a value Keep never issued; it goes to the needles only.
  HX host-b sh -c 'umask 077; V=$(head -c 24 /dev/urandom | base64 | tr -d "\n/+=") f=/srv/app/b1/app.env
    export V; awk "/^SERVICE_TOKEN=/ {print \"SERVICE_TOKEN=\" ENVIRON[\"V\"]; next} {print}" "$f" >"$f.new"
    chown --reference="$f" "$f.new"; chmod --reference="$f" "$f.new"; mv "$f.new" "$f"'
  HX host-b sed -n 's/^SERVICE_TOKEN=//p' /srv/app/b1/app.env \
    | OP sh -c 'umask 077; tr -d "\n\"'"'"'" >/operator/needles/discover-b1-stale'
  OP sh -c 'test "$(wc -c </operator/needles/discover-b1-stale)" -ge 16' || die "the stale value of b1 is not a needle"
  say "host-a: a1's line copied to /srv/app/extra/app.env, a2's file moved away; host-b: b1 rewritten"

  say "== discovery 2: the changed hosts"
  discover_one 2 host-a
  discover_one 2 host-b
  work_counts >"$OUT/discover/work-after.json"
  psql_op "SELECT json_build_object(
    'observations', (SELECT json_agg(json_build_object('verdict',verdict,'carrier_id',carrier_id,'incident_state',incident_state) ORDER BY created_at) FROM discovery_observations),
    'journal', (SELECT json_agg(json_build_object('action',action,'actor',actor_type,'status',result_status,'error_class',result_error_class,'target_path',target_path,'fingerprint',result_fingerprint) ORDER BY org_seq) FROM audit_records WHERE action='carrier.discover'))" >"$OUT/discover/server.json"
  discovery_summary
}

# carrier_id ID: the registered carrier of the stand's carrier ID (a1..b2).
carrier_id() {
  local path; path=$(awk -v c="$1" '$1==c {print $4}' <<<"$CARRIERS")
  psql_op "SELECT id FROM carriers WHERE target_path='$path'"
}

discovery_summary() {
  local d="$OUT/discover" scans="[" f n
  for f in "$d"/[12]-host-*.json; do
    n=$(basename "$f" .json)
    scans+=$(jq -c --arg n "$n" --arg rc "$(cat "$d/$n.exit")" \
      '{round:($n|split("-")[0]|tonumber), host, runner_id, request_id, state, ok, error_class:(.error_class // null), cli_exit:($rc|tonumber),
        reply_fields:(keys), finding_fields:[.findings[]|keys],
        findings:[.findings[]|{verdict, carrier_id:(.carrier_id // null), path, name, fingerprint:(.fingerprint // null), length, incident}]}' "$f"),
  done
  jq -n --argjson scans "${scans%,}]" --slurpfile before "$d/work-before.json" --slurpfile after "$d/work-after.json" \
    --slurpfile server "$d/server.json" \
    --arg a1 "$(carrier_id a1)" --arg a2 "$(carrier_id a2)" --arg b1 "$(carrier_id b1)" \
    '{carriers:{a1:$a1, a2:$a2, b1:$b1}, scans:$scans, work_before:$before[0], work_after:$after[0],
      observations:$server[0].observations, journal:$server[0].journal}' >"$d/summary.json"
}

check_discover() {
  local s="$OUT/discover/summary.json" rc=0
  local A1 A2 B1
  A1=$(jq -r .carriers.a1 "$s"); A2=$(jq -r .carriers.a2 "$s"); B1=$(jq -r .carriers.b1 "$s")
  # f ROUND HOST: the findings of one scan.
  local f='def f(r;h): [.scans[]|select(.round==r and .host==h)][0];'
  expect "discovery: all four scans completed without an error class"      '[.scans[]|select(.state=="completed" and .error_class == null)]|length == 4' "$s" || rc=1
  # ok is the report's "nothing to act on": true only when every line is a match.
  expect "discovery: ok is true in round 1 and false in round 2"             '[.scans[]|"\(.round) \(.ok)"]|sort == ["1 true","1 true","2 false","2 false"]' "$s" || rc=1
  expect "discovery 1: host-a a1 (env-file) and a2 (mcp-config) are match"   "$f"' f(1;"host-a")|[.findings[]|"\(.verdict) \(.carrier_id)"]|sort == (["match '"$A1"'","match '"$A2"'"]|sort)' "$s" || rc=1
  expect "discovery 1: host-b b1 is match"                                   "$f"' f(1;"host-b")|[.findings[]|"\(.verdict) \(.carrier_id)"] == ["match '"$B1"'"]' "$s" || rc=1
  expect "discovery 1: nothing to report, CLI exit 0 on both hosts"         "$f"' [f(1;"host-a"),f(1;"host-b")]|all(.cli_exit == 0 and all(.findings[]; .incident == false))' "$s" || rc=1
  expect "discovery 2: host-a a1 is still match"                             "$f"' f(2;"host-a")|[.findings[]|select(.carrier_id=="'"$A1"'")|.verdict] == ["match"]' "$s" || rc=1
  expect "discovery 2: host-a the copy is sprawl with an incident"           "$f"' f(2;"host-a")|[.findings[]|select(.verdict=="sprawl")|{path,name,incident,carrier_id}] == [{path:"/srv/app/extra/app.env",name:"API_TOKEN",incident:true,carrier_id:null}]' "$s" || rc=1
  expect "discovery 2: host-a the sprawl copy has a1's fingerprint"          "$f"' f(2;"host-a")|([.findings[]|select(.verdict=="sprawl")|.fingerprint] == [.findings[]|select(.carrier_id=="'"$A1"'")|.fingerprint])' "$s" || rc=1
  expect "discovery 2: host-a a2 is unknown_find with an incident"           "$f"' f(2;"host-a")|[.findings[]|select(.carrier_id=="'"$A2"'")|{verdict,incident}] == [{verdict:"unknown_find",incident:true}]' "$s" || rc=1
  expect "discovery 2: host-b b1 is stale"                                   "$f"' f(2;"host-b")|[.findings[]|"\(.verdict) \(.carrier_id)"] == ["stale '"$B1"'"]' "$s" || rc=1
  expect "discovery 2: the stale fingerprint differs from round 1"           "$f"' (f(2;"host-b").findings[0].fingerprint) != (f(1;"host-b").findings[0].fingerprint)' "$s" || rc=1
  expect "discovery 2: CLI exit 1 (findings) on both hosts"                  "$f"' [f(2;"host-a"),f(2;"host-b")]|all(.cli_exit == 1)' "$s" || rc=1
  expect "discovery: the two incidents are open in the report store"         '[.observations[]|select(.incident_state=="open")|.verdict]|sort == ["sprawl","unknown_find"]' "$s" || rc=1
  expect "discovery: every scan's result is in the journal"                 '[.journal[]|select(.actor=="runner" and .status=="ok")]|length == 4' "$s" || rc=1
  expect "discovery: the journal carries no path and no fingerprint"         'all(.journal[]; .target_path == "" and .fingerprint == "")' "$s" || rc=1
  expect "discovery: nothing reissued (no job, run, version or carrier change)" '.work_before == .work_after' "$s" || rc=1
  # The CLI's raw replies, not the summary's projection: the closed field lists
  # of a result (8) and a finding (7), nothing outside them and nothing always
  # present missing (error_class only on a failure, carrier_id not on a sprawl,
  # fingerprint not on an unknown_find).
  expect "discovery: every reply has only the result's closed fields"       'all(.scans[]; (.reply_fields - ["error_class","findings","host","ok","request_id","runner_id","state","store_id"]) == [])' "$s" || rc=1
  expect "discovery: every reply has the result's fixed fields"             'all(.scans[]; (["findings","host","ok","request_id","runner_id","state","store_id"] - .reply_fields) == [])' "$s" || rc=1
  expect "discovery: every finding has only the finding's closed fields"    'all(.scans[].finding_fields[]; (. - ["carrier_id","fingerprint","incident","length","name","path","verdict"]) == [])' "$s" || rc=1
  expect "discovery: every finding has the finding's fixed fields"          'all(.scans[].finding_fields[]; (["incident","length","name","path","verdict"] - .) == [])' "$s" || rc=1
  return $rc
}

discover_all() {
  up
  local bad=0
  discover
  check_discover || bad=1
  receipt >"$OUT/receipt.out"
  jq -e '.discovery.scans|length == 4' "$OUT/receipt.out" >/dev/null || die "receipt stdout is not the clean JSON receipt"
  [ "$bad" = 0 ] || die "a discovery property does not hold (the lines above name it)"
  say "discover-all: match, sprawl, stale and unknown_find hold on two hosts; receipt in $OUT/receipt.json"
}

case "${1:-}" in
  up) up ;;
  rotate-mesh) rotate_mesh ;;
  break-third) break_third ;;
  tamper) tamper; check_tamper ;;
  receipt) receipt ;;
  down) down ;;
  all) all ;;
  rotate) rotate ;;
  discover) discover; check_discover ;;
  discover-all) discover_all ;;
  *) echo "usage: $0 up[--mesh]|rotate|rotate-mesh|break-third|tamper|discover|receipt|down|all|discover-all" >&2; exit 2 ;;
esac
