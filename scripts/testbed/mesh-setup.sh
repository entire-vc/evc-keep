#!/bin/sh
# Runs in the operator container, for `rotation.sh up --mesh`. It sets up the
# disposable Mesh (its own user, workspace, agent and extension) through the
# public APIs of Mesh and Keep, in four steps:
#
#   link ORG       register the Mesh user, install the workspace in Keep as a
#                  secret store, and give Mesh the settings to reach Keep
#   connect ORG    install keep-rotator from the stand's signed catalog, open
#                  its window in Keep, connect it, take the service token
#   agent          register the test agent and put its first key in a file
#   bind SECRET    write the secret-to-agent bindings keep-server reads
#
# Every value made here is a test value of this stand. Values go to files
# (mode 0600, the needle directory the leak scan reads), never to a terminal,
# an argument or a variable.
set -eu
umask 077
M=http://keep-server:8005/api/v1
K=https://keep-server:8443
D=/operator/mesh
N=/operator/needles
install -d -m 0700 "$D" "$N"

mx() { curl -fsS -m 60 -H @"$D/hdr" -H 'Content-Type: application/json' "$@"; }
kp() { curl -fsS -m 60 --cacert /pki/server-ca.pem -H @/operator/hdr -H 'Content-Type: application/json' "$@"; }
rnd() { openssl rand -hex 32 | tr -d '\n' >"$1"; }

case "${1:?step}" in
link)
  org=$2
  # A password the policy accepts: the generated hex behind a fixed class prefix.
  { printf 'Aa1-'; openssl rand -hex 24 | tr -d '\n'; } >"$D/user-password"
  jq -n --rawfile p "$D/user-password" '{email:"operator@stand.invalid",password:$p,name:"operator"}' \
    | curl -fsS -m 30 -H 'Content-Type: application/json' -d @- "$M/auth/register" \
    | jq -j '.tokens.access_token' >"$D/jwt"
  printf 'Authorization: Bearer %s\n' "$(cat "$D/jwt")" >"$D/hdr"
  mx "$M/workspaces" | jq -j '.[0].id' >"$D/ws"
  rnd "$D/events-secret"; rnd "$D/store-token"
  jq -n --rawfile ws "$D/ws" --rawfile t "$D/store-token" --rawfile e "$D/events-secret" \
    '{mesh_url:"http://localhost:8005",workspace_id:$ws,extension_token:$t,events_endpoint_secret:$e,mode:"store"}' \
    | kp -X POST -d @- "$K/mesh/install" -o /dev/null
  {
    echo "export MESH_KEEP_URL=https://localhost:8443 MESH_KEEP_ORG_ID=$org MESH_KEEP_WORKSPACE_ID=$(cat "$D/ws")"
    echo "export MESH_KEEP_EVENTS_SECRET=$(cat "$D/events-secret")"
  } >>/meshconf/mesh.env
  # Mesh's own secrets and the operator's token are stand values too: the leak
  # scan looks for them (values read here, never printed).
  sed -n "s/^export JWT_SECRET='\(.*\)'\$/\1/p" /meshconf/mesh.env | tr -d '\n' >"$N/mesh-jwt-secret"
  sed -n "s/^export MESH_INTEGRATION_ENCRYPTION_KEY='\(.*\)'\$/\1/p" /meshconf/mesh.env | tr -d '\n' >"$N/mesh-integration-key"
  cp "$D/jwt" "$N/mesh-user-jwt"
  cp "$D/events-secret" "$N/mesh-events-secret"; cp "$D/store-token" "$N/mesh-store-token"; cp "$D/user-password" "$N/mesh-user-password"
  ;;
connect)
  org=$2; ws=$(cat "$D/ws")
  jq -n --rawfile k /exchange/catalog-public-key \
    '{settings:{spark_url:"http://localhost:8090",catalog_public_key:($k|rtrimstr("\n")),catalog_install_counter:false}}' \
    | mx -X PUT -d @- "$M/extensions/spark/instance-settings" -o /dev/null
  mx -X POST "$M/extensions/catalog/refresh" -o /dev/null
  mx -X POST -d '{"source":"catalog","id":"keep-rotator"}' "$M/extensions/install" -o /dev/null
  mx -X PUT -d '{"allowed":true}' "$M/extensions/keep-rotator/allowed" -o /dev/null
  mx -X PUT -d '{"settings":{"keep_url":"https://localhost:8443"}}' "$M/extensions/keep-rotator/instance-settings" -o /dev/null
  # Mesh makes the rotator's signing secret itself when it is absent; the stand
  # makes it first, so the digest Keep's window needs is known without ever
  # reading a secret back out of a store.
  rnd "$D/rotator-signing"
  jq -n --rawfile v "$D/rotator-signing" '{scope:"workspace",name:"EXT_KEEP_ROTATOR_SIGNING_SECRET",value:$v}' \
    | mx -X POST -d @- "$M/workspaces/$ws/secrets" -o /dev/null
  cp "$D/rotator-signing" "$N/mesh-rotator-signing"
  jq -n --arg ws "$ws" --arg sha "$(sha256sum <"$D/rotator-signing" | cut -d' ' -f1)" \
    '{extension_id:"keep-rotator",workspace_id:$ws,mesh_url:"http://localhost:8005",signing_secret_sha256:$sha}' \
    | kp -X POST -d @- "$K/orgs/$org/mesh/pending-installs" -o /dev/null
  mx -X POST -d '{"settings":{"keep_url":"https://localhost:8443"},"consent":{"capabilities":["api:agent_keys:read","api:agent_key:rotate","api:ext_token:self_rotate"]}}' \
    "$M/workspaces/$ws/extensions/keep-rotator/connect" -o "$D/connect.json"
  mx "$M/workspaces/$ws/extensions" >"$D/extensions.json"
  jq -r '[.. | objects | select(.id=="keep-rotator")][0] | del(.manifest)' "$D/extensions.json" >"$D/rotator-state.json"
  ;;
token)
  cid=$(jq -r '.connection.id' "$D/rotator-state.json")
  mx -X POST "$M/integrations/$cid/rotate-token" | jq -j '.extension_token' >"$D/svc-token"
  test "$(wc -c <"$D/svc-token")" -ge 16
  install -d -m 0755 /exchange/mesh
  cp "$D/svc-token" /exchange/mesh/rotate-token; chown 10001:10001 /exchange/mesh/rotate-token; chmod 0600 /exchange/mesh/rotate-token
  cp "$D/svc-token" "$N/mesh-service-token"
  ;;
agent)
  ws=$(cat "$D/ws")
  mx -X POST -d '{"name":"rotation-agent","agent_type":"custom"}' "$M/workspaces/$ws/agents" >"$D/agent.json"
  jq -r '[.. | objects | select(has("id") and has("name"))][0].id' "$D/agent.json" | tr -d '\n' >"$D/agent-id"
  # The agent is registered with an original key ("primary"). Keep rotates
  # issued keys, which have UUID ids, so the agent gets one such key first and
  # its original key is revoked: the issued key is the secret's first value.
  mx -X POST -d '{"label":"testbed"}' "$M/agents/$(cat "$D/agent-id")/keys" | jq -j '.api_key' >"$D/agent-key-1"
  test "$(wc -c <"$D/agent-key-1")" -ge 16
  mx -X DELETE "$M/agents/$(cat "$D/agent-id")/keys/primary" -o /dev/null
  # the agent's original key, revoked above, is still a value the scan must not see
  jq -j '.. | objects | select(has("api_key")) | .api_key' "$D/agent.json" | head -c 4096 >"$N/mesh-agent-primary-key"
  rm -f "$D/agent.json"
  ;;
bind)
  jq -n --arg s "$2" --rawfile a "$D/agent-id" '{($s):$a}' >/exchange/mesh/bindings.json
  chown 10001:10001 /exchange/mesh/bindings.json; chmod 0600 /exchange/mesh/bindings.json
  ;;
keys)
  # The ids of the agent's active keys (no revoked_at), as Mesh lists them: ids only.
  mx "$M/agents/$(cat "$D/agent-id")/keys" | jq -c '[.keys[] | select(.revoked_at == null) | .id] | sort'
  ;;
revoked)
  # The ids of the agent's revoked keys (revoked_at set), as Mesh lists them: ids only.
  mx "$M/agents/$(cat "$D/agent-id")/keys" | jq -c '[.keys[] | select(.revoked_at != null) | .id] | sort'
  ;;
probe)
  # probe FILE: the status of GET /agents/me with the key in FILE.
  { printf 'X-Agent-Key: '; cat "$2"; printf '\n'; } >"$D/probe-hdr"
  curl -sS -m 20 -o /dev/null -w '%{http_code}' -H @"$D/probe-hdr" "$M/agents/me"; rm -f "$D/probe-hdr"
  ;;
*) echo "unknown step" >&2; exit 2 ;;
esac
