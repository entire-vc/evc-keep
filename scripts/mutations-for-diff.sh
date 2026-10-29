#!/usr/bin/env bash
# Prints the mutation scripts a diff needs locally, one per line.
#
#   scripts/mutations-for-diff.sh [base-ref]     (default: origin/main)
#   scripts/mutations-for-diff.sh --all          every script (what CI runs)
#
# Locally you run only the printed scripts; the full set runs once in CI.
# A change to a shared file (go.mod, the helpers, the linter config, CI
# config) selects every script. A script changed in the diff selects itself.
set -euo pipefail
cd "$(dirname "$0")/.."

# script-suffix : space-separated path prefixes whose change selects it
table='
audit: internal/audit cmd/keep-server internal/obs internal/store/migrations
builtin: internal/builtin
deployment: internal/deployment internal/store/migrations/00016_deployment.sql
carrier-verify: internal/deployment internal/dispatch internal/api internal/audit internal/store/migrations/00022_carrier_verify.sql test/security
approvals: internal/deployment internal/identity internal/notify internal/api internal/audit internal/store/migrations/00018_approvals.sql cmd/keep-server
carriers: internal/carriers internal/store/migrations
rotation: internal/rotation internal/store/migrations
rotate-audit: internal/rotation internal/api internal/audit internal/store/migrations
rotation-wiring: cmd/keep-server internal/rotation internal/intake internal/api internal/store/migrations internal/deployment/verify.go
mesh-plugin: plugins/mesh pkg/rotation cmd/keep-server/app internal/config pkg/provider
mesh-rotation-e2e: plugins/mesh internal/rotation
lanepoller: plugins/mesh/lanepoller plugins/mesh/cmd/keep-lane-poller
dispatch: internal/dispatch internal/api internal/builtin/delivery internal/builtin/local_delivery internal/builtin/orgpki internal/builtin/store.go internal/builtin/sealer internal/registry internal/mtls internal/audit internal/deployment internal/store/migrations internal/store/deployment_result_migration_test.go pkg/runnerproto pkg/fingerprint pkg/secret cmd/keep-server
discovery: internal/runner/discover
deploy: internal/runner/deploy
deploy-api: internal/api internal/deployment cmd/keep/ cmd/keep-runner cmd/keep-server
mcp: internal/mcp internal/api cmd/keep/
bootstrap-org: cmd/keep-server internal/tenancy internal/identity internal/audit internal/builtin/orgpki internal/catalog internal/store/migrations
keylevel-reconcile: cmd/keep-server internal/builtin internal/reqid internal/audit internal/store/migrations
mesh-hierarchy: cmd/keep-server internal/api internal/meshext internal/builtin internal/store/migrations
resolve-callers: scripts/check-resolve-callers.sh internal/api cmd/keep-server internal/builtin/mesh_vault.go
mesh: cmd/keep-server internal/api internal/meshext internal/builtin pkg/fingerprint internal/store/migrations mesh-extension.json mesh-extension.keep-rotator.json
mesh-ui: internal/api cmd/keep-server internal/meshext
mesh-ui-browser: internal/api cmd/keep-server internal/meshext internal/testutil/meshfake
meshgate: internal/meshgate pkg/gatecard internal/deployment internal/api cmd/keep-server plugins/mesh internal/store/migrations
loop: internal/runner/loop internal/builtin/delivery.go cmd/keep-runner pkg/runnerproto
execpolicy: pkg/execpolicy
execrun: internal/runner/execrun pkg/execpolicy
fingerprint: pkg/fingerprint
health: internal/runner/health
identity: internal/identity internal/obs internal/reqid internal/tokenshape
identity-attack: internal/identity internal/obs internal/testutil/canary test/security
intake-browser: internal/builtin
intake-page: web/intake internal/api internal/builtin
intake-receiver: internal/builtin
intake-service: internal/builtin internal/intake internal/api internal/config internal/catalog internal/store internal/metatext internal/tenancy scripts/metadata-mutations.sh cmd/keep-server cmd/keep/
keep-cli: cmd/keep/
netns: internal/runner/execrun
loghygiene: internal/store internal/obs cmd/keep-server
public-hygiene: scripts/check-public-hygiene
providertest: pkg/provider
pgscratch: internal/testutil/pgscratch test/security
runnerproto: pkg/runnerproto
runner-enroll: internal/builtin internal/registry internal/enrolltoken internal/runner internal/mtls internal/api internal/config internal/store cmd/keep-server cmd/keep-runner cmd/keep/
sealer: internal/builtin/sealer
targets: internal/targets pkg/runnerproto
tenancy: internal/tenancy internal/catalog internal/identity
'

all=()
for f in scripts/check-*-mutations.sh; do all+=("$f"); done

if [ "${1:-}" = "--all" ]; then printf '%s\n' "${all[@]}"; exit 0; fi

base="${1:-origin/main}"
changed="$(git diff --name-only "$base"...HEAD; git diff --name-only HEAD)"

if grep -Eq '^(go\.mod|go\.sum|\.golangci\.yml|\.gitlab-ci\.yml|\.gitlab/ci/|scripts/(mutation-helpers|check-mutation-[a-z]+)\.sh|internal/zonecheck/)' <<<"$changed"; then
	printf '%s\n' "${all[@]}"; exit 0
fi

while IFS=: read -r name prefixes; do
	[ -n "$name" ] || continue
	script="scripts/check-$name-mutations.sh"
	[ -f "$script" ] || { echo "mutations-for-diff: table names missing $script" >&2; exit 2; }
	pick=0
	grep -qx "$script" <<<"$changed" && pick=1
	for p in $prefixes; do grep -q "^$p" <<<"$changed" && pick=1; done
	[ "$pick" = 1 ] && echo "$script"
done <<<"$table" | sort -u

# Every mutation script must be in the table, or it would never run locally.
for s in "${all[@]}"; do
	n="${s#scripts/check-}"; n="${n%-mutations.sh}"
	grep -q "^$n:" <<<"$table" || { echo "mutations-for-diff: $s has no table entry" >&2; exit 2; }
done
