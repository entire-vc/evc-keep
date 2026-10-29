#!/bin/sh
# Proves the Mesh hierarchy sync guards can fail (tenancy model section 2,
# threat model 4.1): in a scratch copy of the tree, switch off one property of
# the event application or the full reconciliation at a time and require the
# named test to go red. A build
# error, a skip or an unrelated failure is not evidence. Needs a real
# PostgreSQL: KEEP_DATABASE_URL.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
mutation_apply_only || : "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must name disposable PostgreSQL}"
# A run takes the whole list unless MUTATION_SHARD_TOTAL splits it; the shard
# line states how many mutants this run selected.
mutation_shard_init

fail=0
pkg=./cmd/keep-server/app
# mutate NAME FILE FROM TO TEST: replace one literal FROM with TO in FILE and
# require TEST (in package $pkg, ./cmd/keep-server/app unless set otherwise)
# to fail with a real --- FAIL.
mutate() {
	mutation_selected || return 0
	name=$1 file=$2 from=$3 to=$4 test=$5
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! python3 - "$work/tree/$file" "$from" "$to" "${6:-}" "${7:-}" "${8:-}" <<'PY'
import sys
p, a, b, f2, a2, b2 = sys.argv[1:]
s = open(p).read()
if s.count(a) < 1:
    sys.exit(1)
open(p, 'w').write(s.replace(a, b, 1))
if f2:
    q = p.rsplit('/tree/', 1)[0] + '/tree/' + f2
    t = open(q).read()
    if t.count(a2) < 1:
        sys.exit(1)
    open(q, 'w').write(t.replace(a2, b2, 1))
PY
	then
		echo "FAIL $name: mutation did not apply, the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -count=1 -p 1 -timeout 240s -run "$test" "$pkg" >"$work/out" 2>&1); then
		echo "FAIL $name: $test stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

H=internal/meshext/hierarchy.go
V=internal/builtin/mesh_vault.go
O=TestMeshReconcileOrphansWhatMeshNoLongerReports
# Orphan, never delete: each entity kind must be marked, and a DELETE in place of the mark must fail.
mutate orphan-members-off  $H 'AND state_at <= $3 AND user_id <> ALL($2::uuid[])' 'AND state_at <= $3 AND false AND user_id <> ALL($2::uuid[])' $O
mutate orphan-projects-off $H 'AND state_at <= $3 AND project_id <> ALL($2::uuid[])' 'AND state_at <= $3 AND false AND project_id <> ALL($2::uuid[])' $O
mutate orphan-agents-off   $H 'AND state_at <= $3 AND agent_id <> ALL($2::uuid[])' 'AND state_at <= $3 AND false AND agent_id <> ALL($2::uuid[])' $O
mutate orphan-keys-off     $H 'AND k.state_at <= $4
   AND NOT EXISTS' 'AND k.state_at <= $4 AND false
   AND NOT EXISTS' $O
mutate orphan-is-delete    $H "UPDATE mesh_members SET status = 'orphaned', orphaned_at = \$3, state_at = \$3, updated_at = now()
 WHERE workspace_id = \$1 AND status = 'active' AND state_at <= \$3 AND user_id" "DELETE FROM mesh_members WHERE \$3::timestamptz IS NOT NULL AND workspace_id = \$1 AND status = 'active' AND state_at <= \$3 AND user_id" $O
mutate reconcile-noop-call $H 'orphaned, err := r.applySnapshot(ctx, workspace, snap, started, cursorOut, dirtySeq, etag == "")' 'orphaned, err := 0, error(nil); _, _, _ = snap, started, got' $O
mutate revive-off          $H 'THEN $4 ELSE mesh_members.status END' 'THEN mesh_members.status ELSE mesh_members.status END' $O
mutate snapshot-ws-unchecked $H 'snap.Workspace.ID != workspace ||' '' TestMeshFailedFetchChangesNothing
# Cursor and dirty flag.
mutate cursor-ignored      $H '	etag := cursor' '	etag := ""; _ = cursor' TestMeshReconcileUsesCursorAndEventsForceFullFetch
mutate dirty-ignored       $H '	if dirtySeq > syncedSeq || fullDue {' '	if fullDue {' TestMeshReconcileUsesCursorAndEventsForceFullFetch
# The hourly full fetch repairs a divergence only on Keep's side; only an
# applied snapshot fetched without the cursor restarts the hour.
pkg=./internal/meshext
F=TestReconcileFullFetchRepairsKeepSideDivergence
mutate full-sync-ignored   $H '	if dirtySeq > syncedSeq || fullDue {' '	if dirtySeq > syncedSeq {' $F
mutate full-sync-never-recorded $H 'last_full_sync_at = CASE WHEN $5::bool THEN now() ELSE mesh_sync_state.last_full_sync_at END' 'last_full_sync_at = mesh_sync_state.last_full_sync_at' $F $H 'CASE WHEN $5::bool THEN now() END)' 'CASE WHEN $5::bool THEN NULL::timestamptz END)'
mutate full-sync-on-304    $H "SET last_sync_at = now(), last_result = 'not_modified'," "SET last_full_sync_at = now(), last_sync_at = now(), last_result = 'not_modified'," TestReconcileKeepsCursorWhileFullSyncIsFresh
pkg=./cmd/keep-server/app
mutate dirty-never-marked  $H '	if d == nil || !ev.Timed {
		return markDirty(ctx, tx, ws)
	}' '	if d == nil || !ev.Timed {
		return nil
	}' TestMeshReconcileUsesCursorAndEventsForceFullFetch
mutate dirty-never-cleared $H "SET cursor = \$2, synced_seq = GREATEST(mesh_sync_state.synced_seq, \$3)," "SET cursor = \$2," TestMeshReconcileUsesCursorAndEventsForceFullFetch
# Events: ordering, replay, bounds, application.
mutate member-order-off    $H 'status = CASE WHEN mesh_members.state_at < $5 OR (mesh_members.state_at = $5 AND mesh_members.status < $4)' 'status = CASE WHEN true OR (mesh_members.state_at = $5 AND mesh_members.status < $4)' TestMeshEventsApplyIdempotentlyAndInAnyOrder
mutate member-order-tie-off    $H 'status = CASE WHEN mesh_members.state_at < $5 OR (mesh_members.state_at = $5 AND mesh_members.status < $4)' 'status = CASE WHEN mesh_members.state_at < $5' TestMeshSubMicrosecondFactsAreOrderIndependent
mutate key-order-off    $H 'status = CASE WHEN mesh_agent_keys.state_at < $6 OR (mesh_agent_keys.state_at = $6 AND mesh_agent_keys.status < $5)' 'status = CASE WHEN true OR (mesh_agent_keys.state_at = $6 AND mesh_agent_keys.status < $5)' TestMeshEventsApplyIdempotentlyAndInAnyOrder
mutate key-order-tie-off    $H 'status = CASE WHEN mesh_agent_keys.state_at < $6 OR (mesh_agent_keys.state_at = $6 AND mesh_agent_keys.status < $5)' 'status = CASE WHEN mesh_agent_keys.state_at < $6' TestMeshSubMicrosecondFactsAreOrderIndependent
mutate flat-type-header-off $H '		w.Type = headerType' '		_ = headerType' TestMeshAcceptsMeshsOwnFlatDelivery
mutate flat-ws-body-off     internal/api/mesh.go '		wsRaw = peek.WorkspaceID' '		_ = peek' TestMeshAcceptsMeshsOwnFlatDelivery
mutate dedup-off           $H 'VALUES ($1, $2, $3)
ON CONFLICT (workspace_id, event_id) DO NOTHING`, workspace, ev.ID' 'VALUES ($1, $2 || gen_random_uuid()::text, $3)
ON CONFLICT (workspace_id, event_id) DO NOTHING`, workspace, ev.ID' TestMeshEventsApplyIdempotentlyAndInAnyOrder
mutate event-apply-noop    $H '	if err := applyEvent(ctx, tx, workspace, ev); err != nil {' '	if err := error(nil); err != nil {' TestMeshEventsApplyIdempotentlyAndInAnyOrder
mutate event-untimed-applied $H '	if d == nil || !ev.Timed {' '	if d == nil {' TestMeshIncompleteEventsForceFullFetch
mutate event-future-ok     $H 'if at.After(now.Add(maxFuture)) {' 'if false {' TestMeshEventsApplyIdempotentlyAndInAnyOrder
mutate event-keyid-open    $H '(d.KeyID != "" && !ValidEventID(d.KeyID))' 'false' TestMeshEventsApplyIdempotentlyAndInAnyOrder
mutate event-role-len-off  $H 'len(d.Role) > 64 ||' '' TestMeshEventsApplyIdempotentlyAndInAnyOrder
mutate api-uses-record     internal/api/mesh.go 'm.deps.Repo.Accept(r.Context(), ws, ev)' 'm.deps.Repo.Record(r.Context(), ws, ev.ID, ev.Type)' TestMeshEventsApplyIdempotentlyAndInAnyOrder
# Failed fetch changes nothing; the token reaches only the installed URL.
mutate fetch-error-ignored $H '	if ferr != nil {' '	if ferr != nil && false {' TestMeshFailedFetchChangesNothing
mutate bearer-not-sent     $V '	secret.Expose(v, func(b []byte) { req.Header.Set("Authorization", "Bearer "+string(b)) })' '	_ = secret.Expose' $O
mutate redirect-followed   $V '	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },' '' TestMeshFetchDoesNotFollowRedirectsWithToken
# Leaks: each plants the token or key material on a different surface.
mutate leak-class-from-body $V 'case resp.StatusCode >= 500:
		return MeshFetched{}, &MeshFetchError{class: "server"}' 'case resp.StatusCode >= 500:
		b, _ := io.ReadAll(resp.Body)
		return MeshFetched{}, &MeshFetchError{class: string(b)}' TestMeshHierarchySyncNeverLeaksTokenOrKeys $H 'if s := c.Class(); s != "" && len(s) <= 64 && !strings.ContainsAny(s, " \t\r\n") {' 'if s := c.Class(); s != "" {'
mutate leak-key-prefix-stored $H 'Label string `json:"label"`
		} `json:"active_keys"`' 'Label string `json:"key_prefix"`
		} `json:"active_keys"`' TestMeshHierarchySyncNeverLeaksTokenOrKeys
# Poisonous values and non-public hosts.
mutate nul-event-open      $H '!cleanText(d.Role, d.Slug, d.Name, d.Label)' 'false' TestMeshPoisonousValuesDoNotFreezeTheMirror
mutate nul-snapshot-open   $H '	if !snap.clean() {' '	if false {' TestMeshPoisonousValuesDoNotFreezeTheMirror
mutate long-etag-stored    $H 'if len(cursorOut) > 128 ||' 'if false ||' TestMeshPoisonousValuesDoNotFreezeTheMirror
mutate ssrf-guard-off      $V '	if scheme == "https" {' '	if false {' TestMeshFetchRefusesNonPublicHTTPSHosts
# A snapshot never overrides a newer fact; events of every kind are ordered; incomplete events and failures.
N=TestMeshSnapshotNeverOverridesNewerEvents
mutate members-newer-orphaned  $H 'AND state_at <= $3 AND user_id <> ALL($2::uuid[])' 'AND user_id <> ALL($2::uuid[])' $N
mutate projects-newer-orphaned $H 'AND state_at <= $3 AND project_id <> ALL($2::uuid[])' 'AND project_id <> ALL($2::uuid[])' $N
mutate agents-newer-orphaned   $H 'AND state_at <= $3 AND agent_id <> ALL($2::uuid[])' 'AND agent_id <> ALL($2::uuid[])' $N
mutate keys-newer-orphaned     $H 'AND k.state_at <= $4
   AND NOT EXISTS' '
   AND NOT EXISTS' $N
mutate snap-member-ignores-ts  $H 'status = CASE WHEN mesh_members.state_at < $5 OR (mesh_members.state_at = $5 AND mesh_members.status < $4)' 'status = CASE WHEN true OR (mesh_members.state_at = $5 AND mesh_members.status < $4)' $N
mutate snap-agent-ignores-ts   $H 'status = CASE WHEN mesh_agents.state_at <= $5 THEN' 'status = CASE WHEN true THEN' TestMeshStaleEventDoesNotReviveOrphanedEntities
mutate snap-key-ignores-ts     $H 'status = CASE WHEN mesh_agent_keys.state_at < $6 OR (mesh_agent_keys.state_at = $6 AND mesh_agent_keys.status < $5)' 'status = CASE WHEN true OR (mesh_agent_keys.state_at = $6 AND mesh_agent_keys.status < $5)' $N
mutate snap-project-overrides-newer $H 'p.IsArchived, at, true, true, true' 'p.IsArchived, at.Add(time.Hour), true, true, true' $N
mutate project-slug-clock-off $H '$7 AND (mesh_projects.slug_at < $6 OR (mesh_projects.slug_at = $6 AND mesh_projects.slug < left($3,128)))' '$7' TestMeshSeededPartialProjectConverges
mutate project-slug-tie-off $H '$7 AND (mesh_projects.slug_at < $6 OR (mesh_projects.slug_at = $6 AND mesh_projects.slug < left($3,128)))' '$7 AND (mesh_projects.slug_at < $6)' TestMeshSeededPartialProjectConverges
mutate project-name-clock-off $H '$8 AND (mesh_projects.name_at < $6 OR (mesh_projects.name_at = $6 AND mesh_projects.name < left($4,256)))' '$8' TestMeshSeededPartialProjectConverges
mutate project-name-tie-off $H '$8 AND (mesh_projects.name_at < $6 OR (mesh_projects.name_at = $6 AND mesh_projects.name < left($4,256)))' '$8 AND (mesh_projects.name_at < $6)' TestMeshSeededPartialProjectConverges
mutate project-archived-clock-off $H '$9 AND (mesh_projects.archived_at < $6 OR (mesh_projects.archived_at = $6 AND mesh_projects.is_archived < $5::boolean))' '$9' TestMeshSeededPartialProjectConverges
mutate project-archived-tie-off $H '$9 AND (mesh_projects.archived_at < $6 OR (mesh_projects.archived_at = $6 AND mesh_projects.is_archived < $5::boolean))' '$9 AND (mesh_projects.archived_at < $6)' TestMeshSeededPartialProjectConverges
mutate project-stale-revives $H "WHEN mesh_projects.state_at <= \$6 THEN 'active'" "WHEN true THEN 'active'" TestMeshStaleEventDoesNotReviveOrphanedProject
mutate project-fields-ignore-flag $H 'CASE WHEN $7 AND (mesh_projects.slug_at' 'CASE WHEN true AND (mesh_projects.slug_at' TestMeshSeededPartialProjectConverges
mutate agent-event-order-off   $H 'status = CASE WHEN mesh_agents.state_at <= $5 THEN' 'status = CASE WHEN true THEN' TestMeshStaleEventDoesNotReviveOrphanedEntities
mutate partial-not-dirty       $H '	if !applied {
		return markDirty(ctx, tx, ws)
	}' '	if !applied {
		return nil
	}' TestMeshIncompleteEventsForceFullFetch
mutate key-orphan-agent-unmatched $H 'WHERE s.a = k.agent_id AND s.kid = k.key_id' 'WHERE s.kid = k.key_id' TestMeshKeysAreScopedToTheirAgentAndFailuresKeepTheCursor
mutate failed-fetch-moves-cursor $H "INSERT INTO mesh_sync_state (workspace_id, last_sync_at, last_result, last_error_class)
VALUES (\$1, now(), 'failed', \$2)
ON CONFLICT (workspace_id) DO UPDATE SET last_sync_at = now(), last_result = 'failed', last_error_class = \$2" "INSERT INTO mesh_sync_state (workspace_id, last_sync_at, last_result, last_error_class)
VALUES (\$1, now(), 'failed', \$2)
ON CONFLICT (workspace_id) DO UPDATE SET last_sync_at = now(), last_result = 'failed', last_error_class = \$2, cursor = '', synced_seq = mesh_sync_state.dirty_seq" TestMeshKeysAreScopedToTheirAgentAndFailuresKeepTheCursor
mutate leak-class-network  $V 'return MeshFetched{}, &MeshFetchError{class: "network"}
	}
	defer func() { _ = resp.Body.Close() }()' 'return MeshFetched{}, &MeshFetchError{class: "network:" + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()' TestMeshNetworkFailureLeaksNothing

pkg=./internal/builtin
mutate ssrf-private-ok     $V '|| ip.IsPrivate() {' '{' TestPublicDialAddress
mutate ssrf-global-off     $V '!ok || !ip.IsGlobalUnicast() ||' '!ok ||' TestPublicDialAddress
mutate ssrf-unmap-off      $V '	return ip.Unmap(), true' '	return ip, true' TestPublicDialAddress
mutate ssrf-list-ignored   $V '		if p.Contains(ip) {' '		if false && p.Contains(ip) {' TestPublicDialAddress
mutate ssrf-cgnat-off      $V '	netip.MustParsePrefix("100.64.0.0/10"),
' '' TestPublicDialAddress
mutate ssrf-nat64-off      $V '	netip.MustParsePrefix("64:ff9b::/96"),
' '' TestPublicDialAddress
mutate ssrf-6to4-off       $V '	netip.MustParsePrefix("2002::/16"),
' '' TestPublicDialAddress
mutate ssrf-compat-off     $V '	netip.MustParsePrefix("::/96"),
' '' TestPublicDialAddress
mutate ssrf-cgnat-narrow   $V 'netip.MustParsePrefix("100.64.0.0/10")' 'netip.MustParsePrefix("100.64.0.0/16")' TestPublicDialAddress
mutate http-dial-open      $V '	return ok && ip.IsLoopback()' '	_ = ip; return ok' TestLoopbackDialAddress
pkg=./cmd/keep-server/app
mutate fetch-limit-off     $V 'if len(body) > meshFetchLimit {' 'if false {' TestMeshFailedFetchChangesNothing
mutate class-unauth-lost   $V '&MeshFetchError{class: "unauthorized"}' '&MeshFetchError{class: "network"}' TestMeshFailedFetchChangesNothing
mutate http-dial-unguarded $V '	allowed := loopbackDialAddress
' '	allowed := publicDialAddress
	_ = loopbackDialAddress
' TestMeshReconcileOrphansWhatMeshNoLongerReports
# Optional fields of member, agent and key events order on their own clocks, not on the row's status clock.
T=TestMeshPartialMemberAgentKeyConverges
mutate role-shares-status-clock    $H 'CASE WHEN $6 AND (mesh_members.role_at < $5 OR' 'CASE WHEN $6 AND (mesh_members.state_at < $5 OR' $T
mutate sponsor-shares-status-clock $H 'CASE WHEN $7 AND (mesh_agents.sponsor_at < $5 OR' 'CASE WHEN $7 AND (mesh_agents.state_at < $5 OR' $T
mutate label-shares-status-clock   $H 'CASE WHEN $7 AND (mesh_agent_keys.label_at < $6 OR' 'CASE WHEN $7 AND (mesh_agent_keys.state_at < $6 OR' $T
mutate absent-role-is-a-fact       $H 'ev.At, d.Role != "")' 'ev.At, true)' $T
mutate absent-label-is-a-fact      $H 'ev.At, d.Label != "")' 'ev.At, true)' $T
# X-Mesh-Event and X-Mesh-Delivery are not signed. The id of a flat hierarchy
# event covers both (Mesh sends added and removed with one body; a retry keeps
# the delivery id), so a flat hierarchy event must never apply; a gate answer
# is recognised by its signed fields and keyed on them alone, and a hierarchy
# body cannot be relabelled as a gate answer.
mutate flat-id-body-only       $H '[]string{headerType, headerDelivery}' '[]string{}' TestMeshFlatRemovedThenAddedSameBodyBothRecorded
mutate flat-id-random          $H 'w.ID = "flat:" + hex.EncodeToString(h.Sum(nil)[:20])' 'w.ID = "flat:" + hex.EncodeToString(h.Sum(nil)[:20]) + now.String()' TestMeshFlatRemovedThenAddedSameBodyBothRecorded
mutate flat-timed              $H '			w.OccurredAt = nil
' '' TestMeshFlatHeadersAreNotTrusted
mutate gate-shape-ignored      $H 'case w.TaskID != "" && w.Decision != "":' 'case false:' TestMeshFlatHeadersAreNotTrusted
mutate gate-header-accepted    $H 'case headerType != GateDecided:' 'case true:' TestMeshFlatHeadersAreNotTrusted
pkg=./internal/meshext
mutate flat-id-no-delivery     $H '[]string{headerType, headerDelivery}' '[]string{headerType}' TestParseEventFlatIDSeparatesEvents
mutate flat-id-no-type         $H '[]string{headerType, headerDelivery}' '[]string{headerDelivery}' TestParseEventFlatIDSeparatesEvents
mutate gate-id-takes-delivery  $H '			w.Type = GateDecided
' '			w.Type = GateDecided
			h.Write([]byte(headerDelivery))
' TestParseEventFlatGateIDIgnoresHeaders
# Schema: closed sets and a downgrade that really undoes.
pkg=./internal/store
M=internal/store/migrations/00035_mesh_hierarchy.sql
mutate member-status-open  $M "CHECK (status IN ('active','removed','orphaned'))" "CHECK (true)" TestMeshHierarchyMigrationDowngradeAndUpgrade
mutate key-id-shape-open   $M "CHECK (key_id ~ '^[A-Za-z0-9._:-]{1,128}\$')" "CHECK (true)" TestMeshHierarchyMigrationDowngradeAndUpgrade
mutate down-leaves-table   $M 'DROP TABLE mesh_sync_state;' '' TestMeshHierarchyMigrationDowngradeAndUpgrade
mutate down-drops-events   $M 'DROP TABLE mesh_members;' 'DROP TABLE mesh_members; DROP TABLE mesh_events;' TestMeshHierarchyMigrationDowngradeAndUpgrade

# The unmutated tree is green with nothing skipped.
if mutation_apply_only; then
	:
elif (cd "$root" && go test -count=1 -p 1 -v -run 'TestMeshReconcile|TestMeshFailedFetch|TestMeshEventsApply|TestMeshHierarchy|TestMeshFetchDoesNot|TestMeshPoisonous|TestMeshFetchRefuses|TestMeshSnapshotNever|TestMeshProjectAndAgent|TestMeshIncomplete|TestMeshKeysAreScoped|TestMeshNetworkFailure|TestMeshPartialMemberAgentKey|TestMeshStaleEventDoesNotReviveOrphanedEntities|TestMeshFlat|TestMeshAcceptsMeshsOwnFlatDelivery' ./cmd/keep-server/app >"$work/base" 2>&1) &&
	(cd "$root" && go test -count=1 -p 1 -v -run 'TestParseEventFlat|TestReconcile' ./internal/meshext >>"$work/base" 2>&1) && ! grep -q -- '--- SKIP' "$work/base" && [ "$(grep -c -- '--- PASS' "$work/base")" -ge 23 ]; then
	echo "ok   baseline: hierarchy tests green on the real code, none skipped"
else
	echo "FAIL baseline: hierarchy tests red or skipped on the real code"
	fail=1
fi
mutation_shard_finish
exit $fail
