#!/bin/sh
# Proves the tenancy and catalog tests can fail: in a scratch copy of the
# tree, switch off one property at a time and require the tests of
# internal/tenancy and internal/catalog to go red. A property whose removal
# leaves the tests green is not tested.
#
# Both packages' tests need a real PostgreSQL (no mocking, CONTRIBUTING.md)
# and reset the schema themselves, so KEEP_DATABASE_URL must point at a
# database of its own; they run one package at a time (-p 1) because they
# share it.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
mutation_shard_init

# Private per-run build cache: on a shared host running several
# clones' go test/build concurrently, a shared $GOCACHE can serve one
# process a build-cache entry another process is evicting mid-write,
# producing a spurious build failure unrelated to any code change
# (seen as "could not import internal/chacha8rand ... no such file").
# Scoping the cache to each run removes the sharing, not just the
# symptom. Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace

if ! mutation_apply_only && [ -z "${KEEP_DATABASE_URL:-}" ]; then
	echo "FAIL check-tenancy-mutations: KEEP_DATABASE_URL is not set — the tests would skip, not fail, which this script must never report as red"
	exit 1
fi

fail=0
# edit SRC FROM TO: print SRC with the first literal occurrence of FROM
# replaced by TO; exit 1 if FROM is not there.
edit() {
	awk -v from="$2" -v to="$3" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$1"
}

pkgs="./internal/tenancy/ ./internal/catalog/"

# Every shard proves, BEFORE its first mutant, that tests ran in each
# unmutated target package with no SKIP: a red or skipped baseline makes every
# "red" below meaningless, so the run stops here, in seconds, naming the
# package, instead of after the whole inventory.
rm -rf "$work/tree"
mutation_snapshot "$work/tree"
for baseline_pkg in $pkgs; do
	mutation_apply_only && break
	if (cd "$work/tree" && go test -timeout 600s -count=1 -p 1 -v "$baseline_pkg" >"$work/out" 2>&1) &&
		! grep -q -- '--- SKIP' "$work/out" && grep -q -- '^--- PASS: Test' "$work/out"; then
		echo "ok   baseline: $baseline_pkg tests green on the real code (0 SKIP)"
	else
		echo "FAIL baseline: $baseline_pkg tests did not run successfully (or skipped) on the real code"
		grep -E -- '^(--- FAIL|FAIL|panic)' "$work/out" | head -20 || true
		echo "FAIL baseline is red: no mutant was run"
		exit 1
	fi
done


# mutate NAME FILE FROM TO WANT: FILE is relative to the repo root. WANT
# is a space-separated list of `--- FAIL: ` prefixes that MUST
# all appear in the red run — a mutant is not proven to isolate the property
# it claims to just because *some* test went red; the wrong test catching it
# (a different, unrelated check that happened to also depend on the mutated
# line) proves nothing about the property WANT names. Mirrors the
# `--- FAIL: WANT` check in check-identity-attack-mutations.sh.
mutate() {
	mutation_selected || return 0
	name=$1 src=$2 from=$3 to=$4 want=${5:?expected test witness required}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! edit "$root/$src" "$from" "$to" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	# Run each whole witness parent (including every subtest), with literal
	# ASCII names only. The original WANT checks still require every named red.
	run_tests=""
	for w in $want; do
		top=${w%%/*}
		case "$top" in
			Test[A-Z0-9_]*) ;;
			*) echo "FAIL $name: unsupported witness"; fail=1; return ;;
		esac
		case "$top" in
			*[!A-Za-z0-9_]*) echo "FAIL $name: unsupported witness"; fail=1; return ;;
		esac
		run_tests="${run_tests:+$run_tests|}$top"
	done
	# shellcheck disable=SC2086
	if (cd "$work/tree" && go test -timeout 600s -count=1 -p 1 -v -run "^($run_tests)$" $pkgs >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
		return
	else
		test_status=$?
	fi
	# A named failure cannot rescue an incomplete run, a broken build, or SKIP.
	# go test -v emits one terminal summary per package. Either package may be
	# green for a particular mutant, but both must finish and at least one of
	# the target packages must be red.
	if [ "$test_status" -ne 1 ] ||
		! awk '
			$3 ~ /^[0-9]+([.][0-9]+)?s$/ {
				if ($2 == "github.com/entire-vc/evc-keep/internal/tenancy" && ($1 == "ok" || $1 == "FAIL")) tenancy=1
				if ($2 == "github.com/entire-vc/evc-keep/internal/catalog" && ($1 == "ok" || $1 == "FAIL")) catalog=1
				if ($1 == "FAIL" && $2 ~ /^github.com\/entire-vc\/evc-keep\/internal\/(tenancy|catalog)$/) red=1
			}
			END { exit !(tenancy && catalog && red) }
		' "$work/out" ||
		grep -q -E '^panic:|^fatal error:|signal: killed|\[build failed\]|\[setup failed\]|--- SKIP|SQLSTATE 42' "$work/out"; then
		echo "FAIL $name: invalid test run (incomplete process, timeout, build/setup failure, or skip; exit $test_status)"
		fail=1
		return
	fi
	if mutation_infrastructure_failed "$work/out"; then
		exit 1
	fi
	if ! grep -q -- '--- FAIL' "$work/out"; then
		# Red because the mutant does not build, or every test skipped, is
		# not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error, or a silent skip?)"
		fail=1
		return
	fi
	missing=""
	for w in $want; do
		grep -q -F -- "--- FAIL: $w" "$work/out" || missing="$missing $w"
	done
	if [ -n "$missing" ]; then
		echo "FAIL $name: red, but not on:$missing (the wrong test/subtest caught it):"
		fail=1
		return
	fi
	echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)${want:+, confirmed on: $want}"
}

# RemoveUser stops filtering by org: one organisation could remove another's
# user, and with it every sponsored agent's access.
mutate remove-user-any-org internal/tenancy/repo.go \
	"WHERE org_id = \$1 AND id = \$2 AND status = 'active'" \
	"WHERE \$1::uuid IS NOT NULL AND id = \$2 AND status = 'active'" 'TestEveryTenancyQueryFiltersByOrg'

# The not-found text goes back to naming the levels the server searched, so
# an OverrideLock's position shows in the message.
mutate not-found-names-search-chain internal/tenancy/resolve.go \
	'return SecretRef{}, NotFoundError(name, levels)' \
	'return SecretRef{}, NotFoundError(name, append(searchChain, levels[len(levels):]...))' 'TestResolve_NotFoundTextIsContextOnly'
# ... or the levels are not the request's own.
mutate not-found-fixed-levels internal/tenancy/resolve.go \
	'levels := []Level{LevelOrg}' \
	'levels := []Level{LevelOrg, LevelWorkspace}' 'TestResolve_NotFoundTextIsContextOnly'
# A removed sponsor's agent stops failing closed.
mutate sponsor-gone-resolves internal/tenancy/resolve.go \
	'if sponsorGone {' \
	'if false && sponsorGone {' 'TestScenarios/C4_SponsorRemovedAgentFailsClosed'
# A removed sponsor is answered with a text of its own (the old behaviour:
# only the org level was named).
mutate sponsor-gone-own-text internal/tenancy/resolve.go \
	'return SecretRef{}, NotFoundError(name, CheckedLevels(tc))' \
	'return SecretRef{}, NotFoundError(name, []Level{LevelOrg})' 'TestResolve_NotFoundTextIsContextOnly'

# A removed sponsor's agent skips the ambiguity check and so answers
# differently from an active one when the workspace is omitted.
mutate sponsor-gone-skips-ambiguity internal/tenancy/resolve.go \
	'if tc.Workspace == uuid.Nil && effectiveUser != uuid.Nil {' \
	'if tc.Workspace == uuid.Nil && effectiveUser != uuid.Nil && !sponsorGone {' 'TestResolve_RemovedSponsorAgentSeesSameAmbiguity'
# The not-found text is cut at the position of a lock below the org.
mutate not-found-cut-at-lower-lock internal/tenancy/resolve.go \
	'levels := CheckedLevels(tc)' \
	'levels := CheckedLevels(tc); if lockIdx >= 0 { levels = levels[:lockIdx+1] }' 'TestResolve_NotFoundTextIgnoresLockDepth'

# An explicitly chosen store is no longer checked at all.
mutate explicit-store-unchecked internal/catalog/catalog.go \
	'if in.StoreID != uuid.Nil {' \
	'if false {' 'TestCreateRef_ExplicitStore'
# ... or a disabled store passes.
mutate explicit-store-disabled-ok internal/catalog/store.go \
	'if status != "active" {' \
	'if false {' 'TestCreateRef_ExplicitStore'
# ... or a store owned outside the target scope's chain passes.
mutate explicit-store-outside-chain internal/catalog/store.go \
	'if s == owner {' \
	'if s == owner || true {' 'TestCreateRef_ExplicitStore'
# ... or the store lookup stops filtering by org.
mutate explicit-store-any-org internal/catalog/store.go \
	'FROM stores WHERE org_id = $1 AND id = $2' \
	'FROM stores WHERE $1::uuid IS NOT NULL AND id = $2' 'TestEveryQueryFiltersByOrg'

# A StoreBinding to an unusable store (someone else's, disabled) is accepted.
mutate binding-store-unchecked internal/catalog/store.go \
	'if err := requireUsableStore(ctx, tx, org, chain, storeID); err != nil {' \
	'if err := requireUsableStore(ctx, tx, org, chain, storeID); false && err != nil {' 'TestCreateStoreBinding_RefusesUnusableStores'
# The store found by the binding walk is used without a re-check.
mutate implicit-store-unchecked internal/catalog/catalog.go \
	'if err := requireUsableStore(ctx, tx, in.Org, chain, storeID); err != nil {' \
	'if err := requireUsableStore(ctx, tx, in.Org, chain, storeID); false && err != nil {' 'TestCreateRef_ImplicitStoreDisabledSinceBinding'

# mode=store enforcement removed: a store the lock does not allow is accepted.
mutate store-lock-off internal/catalog/catalog.go \
	'lk.Mode == ModeStore && lk.SelectorClass' \
	'false && lk.SelectorClass' 'TestScenarios/C5_ForbiddenOverride'
# secretAt stops filtering by org.
mutate secret-at-any-org internal/tenancy/catalog_reads.go \
	'WHERE org_id = $1 AND scope_level = $2 AND scope_id = $3 AND name = $4' \
	'WHERE $1::uuid IS NOT NULL AND scope_level = $2 AND scope_id = $3 AND name = $4' 'TestSecretAt_RejectsMismatchedOrg'

# --- Tenancy model §3 step 5: principal rights on a resolved secret ---

# The context gate switched off entirely: a principal with no rights at
# all in ANY level tc names still reaches Resolve, and (since it is the
# only remaining check) resolves whatever it finds. Isolates
# principalCanReachContext as a whole — see ResolveAuthorized's doc for why
# the found-scope check after it is never independently observable and so
# gets no mutation of its own.
# WANT pins b and c: those are the cases where the found scope, and the
# principal's rights there, are unchanged by the mutation (NAME is defined
# at org, the principal has a role at org, the post-Resolve check alone
# would let both through) — only the context gate itself can catch them.
# Case d/e failing too is fine; b/c not failing means the gate's own
# necessity, not just its presence, went unproven.
mutate authz-context-gate-off internal/catalog/authz.go \
	'if !reachable {' \
	'if !reachable && false {' \
	'TestResolveAuthorized_MultiLevelExistenceOracle/b: TestResolveAuthorized_MultiLevelExistenceOracle/c:'
# The user branch stops checking the role at the level being gated —
# every user is treated as if they held every permission at every level of
# tc. Isolates §3 step 5's role check for a plain user (not an agent).
mutate authz-user-role-check-off internal/catalog/authz.go \
	'return ir.UserPermissions(ctx, tc.Org, tc.Principal.ID, scope.String())' \
	'return identity.PermissionsForRole(identity.RoleAdmin), nil' 'TestResolveAuthorized_UserRoleGatesResolve'
# The agent branch stops checking the sponsor's rights at the level being
# gated — every agent is treated as if its sponsor held every permission
# there, regardless of the sponsor's actual (or absent) role. Isolates §3
# step 5's sponsor-intersection for an agent, at the layer this card wires
# it into (internal/identity's own equivalent property, the intersection
# inside identity.AgentPermissions, is not observable through this boolean
# gate: every role this package defines already grants PermReadMetadata, so
# the only way an agent's rights actually differ from "everything" here is
# when the sponsor has NO role at all — and that case short-circuits in
# Repo.EffectiveAgentPermissions before AgentPermissions is ever called,
# per its own doc).
mutate authz-agent-sponsor-check-off internal/catalog/authz.go \
	'return ir.EffectiveAgentPermissions(ctx, p, scope.String())' \
	'_ = p; return identity.PermissionsForRole(identity.RoleAdmin), nil' 'TestResolveAuthorized_AgentPermissionsNeverExceedSponsor'

# --- catalog: CreateRef/CreateStoreBinding transaction + classification ---

# CreateRef stops taking the advisory scope lock on each ancestor before
# reading its locks: the TOCTOU window against a concurrent
# CreateOverrideLock reopens. Caught by the deterministic concurrency test,
# not the race detector — the mutant is built and run without -race. Skips
# the loop body via an empty range rather than neutralizing the if-condition
# in place: the latter leaves anc unused by the compiler's static check
# (the call it guards is the only reference to anc left in the loop), so it
# fails to build rather than proving anything about the property.
mutate createref-no-scope-lock internal/catalog/catalog.go \
	'for _, anc := range ancestors {' \
	'for _, anc := range []tenancy.Scope{} {' 'TestCreateRef_OverrideLockRace'
# CreateOverrideLock stops taking the same lock on its own target scope
# before inserting: same TOCTOU window, from the other side.
mutate createoverridelock-no-scope-lock internal/catalog/lock.go \
	'if err := lockScope(ctx, tx, org, scope); err != nil {' \
	'if err := error(nil); err != nil {' 'TestCreateRef_OverrideLockRace'
# A race on secrets' own (org_id, scope_level, scope_id, name) UNIQUE stops
# being classified: the loser of the race gets a raw, unclassified error
# instead of apperr.ClassAlreadyExists.
mutate createref-unique-unclassified internal/catalog/catalog.go \
	'if uniqueViolation(err) {' \
	'if false && uniqueViolation(err) {' 'TestCreateRef_DuplicateName'
# Same, for store_bindings' one-binding-per-scope UNIQUE.
mutate storebinding-unique-unclassified internal/catalog/store.go \
	'return StoreBinding{}, alreadyBoundError()' \
	'return StoreBinding{}, fmt.Errorf("catalog: create store binding: %w", err)' 'TestCreateStoreBinding_DuplicateBinding'
# CreateOverrideLock's scope gate is removed: an invalid scope now falls
# through to the table's own keep_validate_scope CHECK, unclassified.
mutate overridelock-scope-gate-off internal/catalog/lock.go \
	'WHERE keep_validate_scope($2, $3, $4)' \
	'WHERE TRUE' 'TestCreateOverrideLock_InvalidScope'
# Same, for CreateStore's owner scope.
mutate store-scope-gate-off internal/catalog/store.go \
	'WHERE keep_validate_scope($2, $5, $6)' \
	'WHERE TRUE' 'TestCreateStore_InvalidScope'
# A class-mode OverrideLock goes back to blocking only a same-level
# definition of the name it covers, not a lower one (tenancy model v3 §3
# step 2, Calvin's follow-up on this card).
mutate classlock-same-level-only internal/tenancy/resolve.go \
	'candidate, candidateFound, err = r.deepestDefinition(ctx, org, chain, scopeIDs, name, i)' \
	'candidate, candidateFound, err = r.deepestDefinition(ctx, org, chain[i:i+1], scopeIDs[i:i+1], name, 0)' 'TestResolve_OverrideLocks'

mutation_shard_finish
exit "$fail"
