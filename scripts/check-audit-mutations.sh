#!/bin/sh
# Proves the R-AUD-1 journal's tests can fail (threat model §4.2 and a
# review round on this package): in a scratch copy of the tree, switch
# off one property of the audit journal at a time and require `go test
# ./internal/audit/...` to go red. Seven families of property, each
# mutating a different source of truth:
#
#   1. hash-field  — one Record field (or nested-struct field group) is
#      neutralized inside canonicalJSON's input before it's hashed. Caught
#      by TestCanonicalJSON_EveryFieldChangesOutput, which changes exactly
#      that field off a fixed baseline and requires canonicalJSON's output
#      to differ — a superuser-bypass tamper of the matching DB column
#      would otherwise go undetected by Verify with nobody noticing.
#   2. keep-app-grant-* — the append-only guarantee is a database GRANT
#      (internal/store/migrations/00005_audit.sql), not application logic;
#      each mutation adds back one of the three privileges keep_app must
#      NOT have. Caught by rights_test.go.
#   3. org-scope — Verify's WHERE org_id = $1 clause is what actually keeps
#      one organization's chain walk from seeing another's rows; caught by
#      TestVerify_OrgFilterIsEnforced.
#
#   3b. keep-app-grant-column-update / append-set-local-role — a column-level
#      UPDATE grant, and Append not actually running as keep_app (the pool's
#      login role is a superuser, so only a trigger probe notices).
#   3c. verify-* / append-* / hash-no-prev-prefix — each Verify check, the
#      Append -> database -> Verify column mapping and time normalization,
#      and the pinned hash format, switched off one at a time.
#   4. closed-field-* — Record.validate refuses free text in every closed
#      enumeration, the fingerprint and the action name (a backend's error
#      text must never reach an append-only table). One mutant per field
#      turns that field's refusal into an accept; caught by
#      TestAppend_ClosedFieldsRefuseArbitraryText.
#   4b. action-registry-* / utf8-* — Action is a closed registry (the one
#      record field the service log line carries), enforced by validate and
#      by the migration's CHECK, with the two lists kept equal by a test;
#      free-text fields must be valid UTF-8, one mutant per field.
#   4c. log-extra-key-* — the append log line carries exactly id, action and
#      request_id: one mutant adds each kind of record field that
#      internal/obs would let through (a "*_id" / "*_name" key, error_class).
#   5. check-* — the migration's CHECK constraints repeat the same rules as
#      a second barrier against a writer that skips validate; one mutant per
#      constraint makes it vacuous; caught by
#      TestAuditRecordsRejectFreeTextInClosedColumns.
#
# Needs a real, disposable PostgreSQL — KEEP_DATABASE_URL, same convention
# as the rest of this package (CONTRIBUTING.md; the database layer is never
# mocked). Exits 0 only if every mutation is caught and the real code is
# green with zero SKIPs.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"

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

mutation_apply_only || : "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must point at a throwaway Postgres instance — see CONTRIBUTING.md / the keep-local-ci skill}"

fail=0

# mutate NAME FILE FROM TO WANT: FILE is repo-root-relative (not pkg-relative
# — unlike the other check-*-mutations.sh scripts, this one's mutations span
# internal/audit AND internal/store/migrations). Replaces the first literal
# occurrence of FROM with TO and requires the test(s) named by WANT (an
# anchored `go test -run` regexp) to go red. Naming the test is the point:
# a mutant that turns some unrelated test red proves nothing about the guard
# it is meant to exercise, and running only WANT keeps each mutant to
# seconds instead of a full package run. A WANT that matches nothing, or
# whose test SKIPs, is a failure too, not a pass.
mutate() {
	name=$1 src=$2 from=$3 to=$4 want=$5 pkg=${6:-./internal/audit/...}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$src" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && KEEP_DATABASE_URL="$KEEP_DATABASE_URL" go test -timeout 120s -count=1 -run "$want" -v "$pkg" >"$work/out" 2>&1); then
		echo "FAIL $name: $want stayed green with the property switched off"
		fail=1
	elif grep -q -- '--- SKIP' "$work/out"; then
		echo "FAIL $name: $want SKIPped (KEEP_DATABASE_URL not propagating?)"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '^--- FAIL' "$work/out"; then
		# Red because the mutant does not build is not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: $want went red ($(grep -c -- '^--- FAIL' "$work/out") failing)"
	fi
}

canon=internal/audit/canonicaljson.go
verify=internal/audit/verify.go
migration=internal/store/migrations/00005_audit.sql
# migration_action: the test setup drops and recreates the schema and runs
# every migration in order (testhelpers_test.go), so audit_records_action_closed
# is whatever the LAST migration that touches it declares — a later migration
# always re-adds its own full closed list on top of an earlier one, healing
# any mutation made only to that earlier migration's copy. Point the action-
# CHECK mutations at whichever migration is currently last to touch it; when
# a future migration adds another action, this must move again.
migration_action=internal/store/migrations/00044_mesh_token_delivery.sql
# The downgrade test goes down to version 37, so the Down CHECK it exercises
# last is 00038's: a mutation of a later migration's Down is healed by it.
migration_action_down=internal/store/migrations/00038_audit_key_level_requested.sql
anchor='var buf bytes.Buffer'
# The pointer above goes stale silently: a newer migration re-adding the CHECK
# heals every mutant made to an older copy. Fail loudly instead.
last_action_migration=$(grep -l 'audit_records_action_closed' "$root"/internal/store/migrations/*.sql | sort | tail -1)
if [ "${last_action_migration#"$root"/}" != "$migration_action" ]; then
	echo "FAIL migration_action: points at $migration_action but the last migration touching audit_records_action_closed is ${last_action_migration#"$root"/}"
	exit 1
fi

# 1. Per-field hash coverage — one mutate() per top-level Record field.
# Deleting a container field (actor/intent/secret/target/policy/approval/
# result) drops every nested column that field owns in one shot; the
# corresponding subtest(s) of TestCanonicalJSON_EveryFieldChangesOutput go
# red for each of them, not just one — this script only requires the field
# name's own line to fire, but the leaf-level test does the finer-grained
# accounting (recordJSONKeysAtEveryLevel's completeness check).
mutate hash-field-id         "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "id"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-ts         "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "ts"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-request_id "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "request_id"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-org_id     "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "org_id"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-scope      "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "scope"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-actor      "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "actor"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-intent     "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "intent"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-action     "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "action"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-secret     "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "secret"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-target     "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "target"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-policy     "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "policy"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-approval   "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "approval"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-result     "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "result"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'
mutate hash-field-prev_hash  "$canon" "$anchor" 'delete(generic.(map[string]interface{}), "prev_hash"); '"$anchor" '^TestCanonicalJSON_EveryFieldChangesOutput$'

# 2. keep_app must not gain UPDATE, DELETE, or TRUNCATE on audit_records —
# see rights_test.go's own doc for why these are proven live against
# Postgres rather than read off the migration file.
mutate keep-app-grant-update   "$migration" 'GRANT SELECT, INSERT ON audit_records TO keep_app;' 'GRANT SELECT, INSERT, UPDATE ON audit_records TO keep_app;' '^TestAppRoleCannotUpdateOrDeleteAuditRecords$'
mutate keep-app-grant-delete   "$migration" 'GRANT SELECT, INSERT ON audit_records TO keep_app;' 'GRANT SELECT, INSERT, DELETE ON audit_records TO keep_app;' '^TestAppRoleCannotUpdateOrDeleteAuditRecords$'
mutate keep-app-grant-truncate "$migration" 'GRANT SELECT, INSERT ON audit_records TO keep_app;' 'GRANT SELECT, INSERT, TRUNCATE ON audit_records TO keep_app;' '^TestAppRoleCannotTruncateAuditRecords$'
mutate keep-app-grant-column-update "$migration" 'GRANT SELECT, INSERT ON audit_records TO keep_app;' 'GRANT SELECT, INSERT ON audit_records TO keep_app; GRANT UPDATE (scope) ON audit_records TO keep_app;' '^TestAppRoleHasNoUpdatePrivilegeOnAnyAuditRecordsColumn$'

# 2b. Append must really run as keep_app: the pool's login role is a
# superuser in CI, so nothing but the trigger probe notices the switch gone.
mutate append-set-local-role internal/audit/journal.go 'tx.Exec(ctx, "SET LOCAL ROLE keep_app")' 'tx.Exec(ctx, "SELECT 1")' '^TestAppendRunsAsKeepApp$'

# 3. Verify must never let one organization's chain walk see another
# organization's rows — "OR true" (rather than dropping the clause outright)
# keeps the query's own parameter count intact, so the mutant fails on the
# actual property instead of on an unrelated "expected N arguments" error.
mutate org-scope "$verify" 'WHERE org_id = $1' 'WHERE org_id = $1 OR true' '^TestVerify_OrgFilterIsEnforced$'

# 4. Record.validate — every closed field's refusal, one mutant each. The
# field name is the argument of invalidField, so the FROM string is unique.
record=internal/audit/record.go
for field in actor.type actor.via policy.decision result.status result.health \
	result.error_class result.fingerprint action request_id; do
	mutate "closed-field-$field" "$record" "return invalidField(\"$field\")" 'return nil' '^TestAppend_ClosedFieldsRefuseArbitraryText$'
done
mutate closed-field-result.length internal/audit/record.go 'return invalidField("result.length")' 'return nil' '^TestAppend_NegativeLengthIsRefused$'
# The bounds (length caps) and the raw-error rule, each with the test that
# alone can see them: the closed-field tests use free text with spaces, which
# the shape checks refuse before any length check is reached.
mutate closed-field-intent.reason "$record" 'return invalidField("intent.reason")' 'return nil' '^TestAppend_BoundsAreEnforced$'
mutate db-error-carries-raw-pgerror internal/audit/journal.go 'database error (SQLSTATE %s)", op, pgErr.Code)' 'database error (SQLSTATE %s): %w", op, pgErr.Code, err)' '^TestAppendErrorsCarryOnlySQLState$'
mutate closed-field-validate-not-called internal/audit/journal.go 'if err := r.validate(); err != nil {' 'if err := r.validate(); false && err != nil {' '^TestAppend_ClosedFieldsRefuseArbitraryText$'

# 5. The migration's CHECK constraints — one mutant each ("true OR" keeps
# the DDL valid, so the mutant fails on the property, not on a syntax error).
mutate check-actor_type         "$migration" 'CHECK (actor_type IN'         'CHECK (true OR actor_type IN' '^TestAuditRecordsRejectFreeTextInClosedColumns$'
mutate check-actor_via          "$migration" 'CHECK (actor_via IN'          'CHECK (true OR actor_via IN' '^TestAuditRecordsRejectFreeTextInClosedColumns$'
mutate check-policy_decision    "$migration" 'CHECK (policy_decision IN'    'CHECK (true OR policy_decision IN' '^TestAuditRecordsRejectFreeTextInClosedColumns$'
mutate check-result_status      "$migration" 'CHECK (result_status IN'      'CHECK (true OR result_status IN' '^TestAuditRecordsRejectFreeTextInClosedColumns$'
mutate check-result_health      "$migration" 'CHECK (result_health IN'      'CHECK (true OR result_health IN' '^TestAuditRecordsRejectFreeTextInClosedColumns$'
mutate check-result_error_class "$migration" 'CHECK (result_error_class IN' 'CHECK (true OR result_error_class IN' '^TestAuditRecordsRejectFreeTextInClosedColumns$'
mutate check-result_fingerprint "$migration" "CHECK (result_fingerprint = ''" "CHECK (true OR result_fingerprint = ''" '^TestAuditRecordsRejectFreeTextInClosedColumns$'
mutate check-request_id         "$migration" 'CHECK (request_id ='         'CHECK (true OR request_id =' '^TestAuditRecordsRejectFreeTextInClosedColumns$'
mutate check-result_length      "$migration" 'CHECK (result_length >= 0)'  'CHECK (true OR result_length >= 0)' '^TestAuditRecordsRejectOutOfBoundsValues$'
mutate check-intent_reason      "$migration" 'CHECK (char_length(intent_reason) <= 200)' 'CHECK (true OR char_length(intent_reason) <= 200)' '^TestAuditRecordsRejectOutOfBoundsValues$'
mutate check-action             "$migration_action" 'CHECK (action IN'             'CHECK (true OR action IN' '^TestAuditRecordsRejectFreeTextInClosedColumns$'

# 4b. Action registry. The Go check accepts any non-empty name, then the
# validate call is switched off; the migration's CHECK is widened to any
# dotted name (the shape-only rule this replaced), then made vacuous; each
# list is made to disagree with the other. "vault.read", "secret.rotate.*" and
# "secret." + hex(canary) all have the right shape, so only the registry
# refuses them.
mutate action-registry-open        "$record" 'if a == k {' 'if a == k || len(a) > 0 {' '^TestAppend_ActionOutsideRegistryIsRefused$'
mutate action-registry-not-checked "$record" 'return invalidField("action")' 'return nil' '^TestAppend_ActionOutsideRegistryIsRefused$'
mutate check-action-shape-only     "$migration_action" 'CHECK (action IN' "CHECK (action LIKE '%.%' OR action IN" '^TestAuditRecordsRejectActionOutsideRegistry$'
mutate check-action-vacuous        "$migration_action" 'CHECK (action IN' 'CHECK (true OR action IN' '^TestAuditRecordsRejectActionOutsideRegistry$'
mutate action-list-drift-database  "$migration_action" "'kek.purge'" "'kek.purge_x'" '^TestActionRegistryMatchesMigrationCheck$'
mutate action-list-drift-go        "$record" 'ActionKEKPurge,' 'ActionKEKPurge, "kek.extra",' '^TestActionRegistryMatchesMigrationCheck$'
# The Mesh secret actions must survive in the last migration's Up CHECK (the
# registry test sees the drift) and in its Down CHECK (the downgrade test
# inserts both after the downgrade; that test lives in internal/store).
mutate action-mesh-put-dropped-up   "$migration_action" "'secret.rotate','mesh.secret.put','mesh.secret.resolve','org.bootstrap','mesh.install.pending'," "'secret.rotate','mesh.secret.resolve','org.bootstrap','mesh.install.pending'," '^TestActionRegistryMatchesMigrationCheck$'
mutate action-mesh-resolve-dropped-up "$migration_action" "'mesh.secret.put','mesh.secret.resolve','org.bootstrap','mesh.install.pending'," "'mesh.secret.put','org.bootstrap','mesh.install.pending'," '^TestActionRegistryMatchesMigrationCheck$'
mutate action-mesh-pending-dropped-up "$migration_action" "'org.bootstrap','mesh.install.pending'," "'org.bootstrap'," '^TestActionRegistryMatchesMigrationCheck$'
mutate action-store-bind-default-dropped-up "$migration_action" "'store.bind_default','deploy.policy_set','mesh.token'));" "'deploy.policy_set','mesh.token'));" '^TestActionRegistryMatchesMigrationCheck$'
mutate action-deploy-policy-set-dropped-up "$migration_action" "'store.bind_default','deploy.policy_set','mesh.token'));" "'store.bind_default','mesh.token'));" '^TestActionRegistryMatchesMigrationCheck$'
mutate action-mesh-token-dropped-up "$migration_action" "'store.bind_default','deploy.policy_set','mesh.token'));" "'store.bind_default','deploy.policy_set'));" '^TestActionRegistryMatchesMigrationCheck$'
mutate action-mesh-put-dropped-down "$migration_action_down" "'mesh.secret.put','mesh.secret.resolve')) NOT VALID" "'mesh.secret.resolve')) NOT VALID" '^TestKeyLevelAuditMigration_DowngradeKeepsHistory$' ./internal/store/...
mutate action-mesh-resolve-dropped-down "$migration_action_down" "'mesh.secret.resolve')) NOT VALID" "'mesh.secret.put')) NOT VALID" '^TestKeyLevelAuditMigration_DowngradeKeepsHistory$' ./internal/store/...

# Free text must be valid UTF-8, field by field: the field's value in
# validate's list is replaced by "" so that one field is never looked at.
while read -r field expr; do
	mutate "utf8-$field" "$record" "{\"$field\", $expr}," "{\"$field\", \"\"}," '^TestAppend_InvalidUTF8InFreeTextIsRefused$' </dev/null
done <<'FIELDS'
org_id r.OrgID
scope r.Scope
actor.id r.Actor.ID
actor.sponsor_id r.Actor.SponsorID
intent.task_ref r.Intent.TaskRef
intent.session_ref r.Intent.SessionRef
intent.reason r.Intent.Reason
secret.id r.Secret.ID
secret.name r.Secret.Name
secret.version r.Secret.Version
target.runner_id r.Target.RunnerID
target.host r.Target.Host
target.kind r.Target.Kind
target.path r.Target.Path
policy.rule_id r.Policy.RuleID
approval.id r.Approval.ID
approval.approver_id r.Approval.ApproverID
FIELDS

# 4c. The append log line: one extra attribute of each kind internal/obs
# passes ("*_id", "*_name", error_class) and the line must be caught.
logline='slog.String("request_id", r.RequestID),'
mutate log-extra-key-reason_id   internal/audit/journal.go "$logline" "$logline"' slog.String("reason_id", r.Intent.Reason),' '^TestAppend_ServiceLogCarriesOnlyIDActionRequestID$'
mutate log-extra-key-org_id      internal/audit/journal.go "$logline" "$logline"' slog.String("org_id", r.OrgID),' '^TestAppend_ServiceLogCarriesOnlyIDActionRequestID$'
mutate log-extra-key-secret_name internal/audit/journal.go "$logline" "$logline"' slog.String("secret_name", r.Secret.Name),' '^TestAppend_ServiceLogCarriesOnlyIDActionRequestID$'
mutate log-extra-key-error_class internal/audit/journal.go "$logline" "$logline"' slog.String("error_class", string(r.Result.ErrorClass)),' '^TestAppend_ServiceLogCarriesOnlyIDActionRequestID$'
mutate log-extra-key-actor_id    internal/audit/journal.go "$logline" "$logline"' slog.String("actor_id", r.Actor.ID),' '^TestAppend_ServiceLogCarriesOnlyIDActionRequestID$'
mutate log-drops-action          internal/audit/journal.go 'slog.String("action", string(r.Action)),' '' '^TestAppend_ServiceLogCarriesOnlyIDActionRequestID$'

# 6. Verify's own checks and the hashed format. Each check is switched off on
# its own; the named test forges a chain that is consistent everywhere else
# (see rechain in verify_hardening_test.go), so only that check can see it.
mutate verify-sequence-check   "$verify" 'if seq != walked {'                       'if false && seq != walked {' '^TestVerify_DetectsSequenceGap$'
mutate verify-hash-check       "$verify" 'if recomputed != storedHash {'            'if false && recomputed != storedHash {' '^TestVerify_DetectsInPlaceTamper$'
mutate verify-link-check       "$verify" 'if rec.PrevHash != expectedPrev {'        'if false && rec.PrevHash != expectedPrev {' '^TestVerify_DetectsForgedMiddleLink$'
mutate verify-genesis-check    "$verify" 'if rec.PrevHash != expectedPrev {'        'if walked > 1 && rec.PrevHash != expectedPrev {' '^TestVerify_DetectsFirstRecordNotChainedFromGenesis$'
mutate verify-head-position    "$verify" 'if headPos != walked || headHash != expectedPrev {' 'if false && headPos != walked || headHash != expectedPrev {' '^TestVerify_DetectsStaleHeadPosition$'
mutate verify-head-hash        "$verify" 'if headPos != walked || headHash != expectedPrev {' 'if headPos != walked {' '^TestVerify_DetectsStaleHeadHash$'
mutate verify-head-row-missing "$verify" 'if walked > 0 {'                          'if false && walked > 0 {' '^TestVerify_DetectsDeletedHeadRow$'
mutate verify-ts-utc           "$verify" 'rec.TS = rec.TS.UTC()'                    'rec.TS = rec.TS' '^TestVerify_RoundTripsEveryColumnUnderNonUTCLocalTime$'
mutate verify-approval-utc     "$verify" 'rec.Approval.DecidedAt = approvalDecAt.Time.UTC()' 'rec.Approval.DecidedAt = approvalDecAt.Time' '^TestVerify_RoundTripsEveryColumnUnderNonUTCLocalTime$'
mutate verify-scan-swap-target "$verify" '&rec.Target.Host, &rec.Target.Kind,'      '&rec.Target.Kind, &rec.Target.Host,' '^TestVerify_RoundTripsEveryColumnUnderNonUTCLocalTime$'
mutate verify-scan-swap-approval "$verify" '&rec.Approval.ID, &rec.Approval.ApproverID,' '&rec.Approval.ApproverID, &rec.Approval.ID,' '^TestVerify_RoundTripsEveryColumnUnderNonUTCLocalTime$'
journal=internal/audit/journal.go
mutate append-ts-truncate       "$journal" 'r.TS = j.now().UTC().Truncate(time.Microsecond)' 'r.TS = j.now().UTC()' '^TestVerify_RoundTripsEveryColumnUnderNonUTCLocalTime$'
mutate append-approval-truncate "$journal" 'r.Approval.DecidedAt = r.Approval.DecidedAt.UTC().Truncate(time.Microsecond)' 'r.Approval.DecidedAt = r.Approval.DecidedAt.UTC()' '^TestVerify_RoundTripsEveryColumnUnderNonUTCLocalTime$'
mutate insert-drop-target-path  "$journal" 'r.Target.RunnerID, r.Target.Host, r.Target.Kind, r.Target.Path,' 'r.Target.RunnerID, r.Target.Host, r.Target.Kind, "",' '^TestVerify_RoundTripsEveryColumnUnderNonUTCLocalTime$'
mutate head-no-advance          "$journal" 'UPDATE audit_chain_heads SET position = $2, hash = $3 WHERE org_id = $1' 'UPDATE audit_chain_heads SET position = $2, hash = $3 WHERE org_id = $1 AND false' '^TestVerify_DetectsTruncatedTail$'
mutate hash-no-prev-prefix internal/audit/hash.go 'h.Write([]byte(prevHash))' '' '^TestHashFormatIsPinned$'

# 7. Output barriers: a record id from the database is returned only in its
# ULID shape, and dbErr keeps only the SQLSTATE and the context sentinels.
mutate verify-broken-id-raw "$verify" 'BrokenID: safeRecordID(rec.ID)' 'BrokenID: rec.ID' '^TestVerify_NeverReturnsAMalformedRecordID$'
mutate db-error-default-raw     "$journal" 'database error (unclassified)", op)' '%w", op, err)' '^TestDbErrKeepsOnlySQLStateAndContextSentinels$'
mutate db-error-canceled-lost   "$journal" 'case errors.Is(err, context.Canceled):' 'case false && errors.Is(err, context.Canceled):' '^TestDbErrKeepsOnlySQLStateAndContextSentinels$'
mutate db-error-deadline-lost   "$journal" 'case errors.Is(err, context.DeadlineExceeded):' 'case false && errors.Is(err, context.DeadlineExceeded):' '^TestDbErrKeepsOnlySQLStateAndContextSentinels$'
mutate check-id "$migration" "CHECK (id ~ " "CHECK (true OR id ~ " '^TestAuditRecordsRejectFreeTextInClosedColumns$'

if mutation_apply_only; then
	:
elif (cd "$root" && KEEP_DATABASE_URL="$KEEP_DATABASE_URL" go test -timeout 120s -count=1 ./internal/audit/... >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
