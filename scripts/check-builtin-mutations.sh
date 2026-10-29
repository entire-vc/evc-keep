#!/bin/sh
# Proves the built-in provider's PostgreSQL persistence tests can fail: in a
# scratch copy of the tree, switch off one property of internal/builtin at a
# time and require `go test ./internal/builtin/` to go red. A property whose
# removal leaves the tests green is not tested. Needs a real database —
# KEEP_DATABASE_URL, same as the "test" CI job (skill keep-local-ci).
#
# A few of these cover the acceptance criteria directly:
#   dek-stored-unwrapped  — the DEK itself ends up in wrapped_dek, not wrapped
#   erase-keeps-dek       — crypto-erasure stops deleting the wrapped DEK
#   erase-keeps-kek-ref   — crypto-erasure stops clearing kek_id, so the KEK
#                           it used can never actually be purged
#   shared-kek-any-domain — the active-KEK lookup ignores which domain asked
#                           (C6: a shared KEK across users at the "user" level)
#   level-not-persisted   — an organisation's key level stops surviving a
#                           restart or being shared across processes
set -eu

# Without a database this script cannot run a single mutation — that is not
# "nothing to report", it is every property below going unverified. A SKIP
# here used to exit 0, which is indistinguishable from every mutation
# having actually been caught; treat it as a failure instead (see
# check-no-silent-skip.sh for the same principle applied to `go test`).
# Apply-only mode runs no test, so it needs no database.
if [ -z "${KEEP_DATABASE_URL:-}" ] && [ "${MUTATION_APPLY_ONLY:-}" != 1 ]; then
	echo "FAIL: KEEP_DATABASE_URL not set — see CONTRIBUTING.md / skill keep-local-ci" >&2
	echo "no mutation below ran; this is not a pass" >&2
	exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"

# Private per-run build cache: on a shared host running several
# clones' go test/build concurrently, a shared $GOCACHE can serve one
# process a build-cache entry another process is evicting mid-write,
# producing a spurious build failure unrelated to any code change
# (seen as "could not import internal/chacha8rand ... no such file").
# Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
pkg=internal/builtin

fail=0
# mutate NAME FILE FROM TO WITNESS: require the named test itself to fail.
# Files under internal/ are repo-relative; other paths are builtin-relative.
mutate() {
	name=$1
	if [ "$#" -ne 5 ] || [ -z "$5" ]; then
		echo "FAIL $name: a designated witness is required"
		fail=1
		return
	fi
	from=$3 to=$4 want=$5
	# Anchor each component separately so a subtest does not select siblings.
	witness_run="^$(printf '%s' "$want" | sed 's|/|$/^|g')$"
	case "$2" in
		internal/*) src=$2 ;;
		*) src=$pkg/$2 ;;
	esac
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
	if (cd "$work/tree" && KEEP_DATABASE_URL="$KEEP_DATABASE_URL" go test -timeout 120s -count=1 -p 1 -v -run "$witness_run" ./$pkg/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif grep -q -F -e '[build failed]' -e '[setup failed]' -e '--- SKIP' "$work/out"; then
		echo "FAIL $name: mutant failed to build or skipped its witness"
		fail=1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	elif ! grep -q -F -- "--- FAIL: $want (" "$work/out"; then
		echo "FAIL $name: red, but not on designated witness $want"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing), confirmed on: $want"
	fi
}

# SQL corruption/substitution must name the blocking version, authenticate
# already-current envelopes, and never carry the value into error/log/audit.
mutate rewrap-missing-blocker sealer/sealer.go 'secretID, version = ref.SecretID, ref.Version' 'secretID, version = "", ""' TestChangeLevel_CorruptEnvelopeIdentifiesVersionAndEraseRecovers
mutate rewrap-missing-audit-ids sealer/sealer.go 'SecretID: secretID, Version: version,' '' TestChangeLevel_CorruptEnvelopeIdentifiesVersionAndEraseRecovers
mutate rewrap-missing-error-ids sealer/sealer.go 'return res, fmt.Errorf("%w: secret_id=%q version=%q: %w", ErrRewrapIncomplete, secretID, version, err)' 'return res, fmt.Errorf("%w: %w", ErrRewrapIncomplete, err)' TestChangeLevel_CorruptEnvelopeIdentifiesVersionAndEraseRecovers
mutate rewrap-skips-current-auth sealer/sealer.go 'dek, err := ls.unwrapDEK(ctx, ref, e)' 'if e.KEKID == t.ID { return e, nil }; dek, err := ls.unwrapDEK(ctx, ref, e)' TestChangeLevel_CorruptEnvelopeIdentifiesVersionAndEraseRecovers

mutate rewrap-audit-envelope-bytes sealer/sealer.go 'secretID, version = ref.SecretID, ref.Version' 'secretID, version = string(e.Ciphertext), ref.Version' TestChangeLevel_CorruptEnvelopeIdentifiesVersionAndEraseRecovers

# AC red run (1): the DEK itself, not wrapped under any KEK, ends up in the
# column meant to hold only a wrapped DEK — TestWrappedDEKIsActuallyWrapped
# checks the exact 32+28-byte length a real wrap always has and that the
# stored bytes do not themselves work as a raw AES-256-GCM key on the
# value's ciphertext. Targets sealer.go, not provider.go: the DEK is
# generated and wrapped entirely inside Seal, so this is where "wrap it"
# actually happens — provider.go only ever sees the Envelope Seal returns.
mutate dek-stored-unwrapped sealer/sealer.go \
	'w, err := seal(ka, dek, dekAAD(ref, k.ID))' \
	'w, err := dek, error(nil); _ = ka' \
	TestWrappedDEKIsActuallyWrapped

# A new nullable column is still an unreviewed place to leak a value. The
# witness migrates a scratch database using this altered embedded SQL.
mutate database-unreviewed-column internal/store/migrations/00007_builtin_provider.sql \
	'    ciphertext       BYTEA NOT NULL,' \
	'    ciphertext       BYTEA NOT NULL, note TEXT,' \
	TestNoCanaryInDatabase

mutate kek-stored-unwrapped sealer/sealer.go \
	'want.Wrapped = wrapped' \
	'want.Wrapped = append([]byte(nil), b...); _ = wrapped' \
	TestWrappedKEKIsActuallyWrapped

mutate fpkey-stored-unwrapped fpkey.go \
	'inserted, err := txStore.insertIfAbsent' \
	'fingerprint.ExposeKey(k, func(b []byte) { env.Ciphertext = append([]byte(nil), b...) }); inserted, err := txStore.insertIfAbsent' \
	TestNoRawFingerprintKeyInDatabase

mutate fpkey-stored-hex fpkey.go \
	'inserted, err := txStore.insertIfAbsent' \
	'fingerprint.ExposeKey(k, func(b []byte) { env.Ciphertext = []byte(hex.EncodeToString(b)) }); inserted, err := txStore.insertIfAbsent' \
	TestNoRawFingerprintKeyInDatabase

# AC red run (2): crypto-erasure stops deleting the wrapped DEK.
mutate erase-keeps-dek store.go \
	"SET wrapped_dek = NULL, kek_id = NULL, status = 'erased'" \
	"SET status = 'erased'" \
	TestErase_DeletesWrappedDEK_KeepsCiphertext

# Crypto-erasure stops clearing kek_id (wrapped_dek alone still cleared): the
# row no longer decrypts, but the KEK it used stays "referenced" forever in
# Each's scan, so Purge can never actually destroy it —
# TestPurge_ReclaimsKEKThatOnlyProtectedErasedVersions.
mutate erase-keeps-kek-ref store.go \
	"SET wrapped_dek = NULL, kek_id = NULL, status = 'erased'" \
	"SET wrapped_dek = NULL, status = 'erased'" \
	TestPurge_ReclaimsKEKThatOnlyProtectedErasedVersions

# Purge must never delete an active KEK, even if its id is on the list —
# TestKEKStore_Purge_RefusesAStillActiveID.
mutate purge-active-too store.go \
	"WHERE org_id = \$1 AND id = ANY(\$2) AND state = 'retired'" \
	"WHERE org_id = \$1 AND id = ANY(\$2)" \
	TestKEKStore_Purge_RefusesAStillActiveID

# Retire/Purge must stay inside the org passed in —
# TestKEKStore_Retire_DoesNotCrossOrgBoundary,
# TestKEKStore_Purge_DoesNotCrossOrgBoundary.
mutate retire-any-org store.go \
	"SET state = 'retired' WHERE org_id = \$1 AND id = ANY(\$2)" \
	"SET state = 'retired' WHERE id = ANY(\$2)" \
	TestKEKStore_Retire_DoesNotCrossOrgBoundary
mutate purge-any-org store.go \
	"DELETE FROM keep_kek WHERE org_id = \$1 AND id = ANY(\$2)" \
	"DELETE FROM keep_kek WHERE id = ANY(\$2)" \
	TestKEKStore_Purge_DoesNotCrossOrgBoundary

# AC red run (3) / C6: the active-KEK lookup ignores domainKey, so every
# store of an organisation converges on whichever KEK was created first —
# isolation between users breaks even though the level is still "user".
mutate shared-kek-any-domain store.go \
	'domain_key = $2 AND state' \
	'($2 = $2) AND state' \
	TestC6_UserKEKIsolation_ThenLevelRoundTrip

# Org boundary on a KEK id: Get must not resolve another organisation's KEK
# — see TestGet_DoesNotCrossOrgBoundary and its doc comment for why this
# check lives here now instead of in sealer's own mutation script.
mutate get-crosses-org store.go \
	'FROM keep_kek WHERE org_id = $1 AND id = $2' \
	'FROM keep_kek WHERE id = $2' \
	TestGet_DoesNotCrossOrgBoundary

# Resolve must reject a disabled/erased version even when it is named
# explicitly (Version does not — see lookup's doc comment).
mutate resolve-ignores-status provider.go \
	"if row.status != \"active\" {" \
	"if false {" \
	TestConformance/disable_two_phase

# checkAvailable's two guards (cancelled context, forced-outage test lever).
# "err != nil" -> "false" (not the whole if-statement) keeps err declared —
# the body below still names it, so a bare "if false {" would not build.
mutate ignore-cancelled-context provider.go \
	'if err := ctx.Err(); err != nil {' \
	'if err := ctx.Err(); false {' \
	TestCheckAvailable_ClassifiesBothOutageReasons
mutate ignore-forced-outage provider.go \
	'if p.unavailable.Load() {' \
	'if false {' \
	TestCheckAvailable_ClassifiesBothOutageReasons

# Every Provider method must refuse the store's reserved fingerprint-key id
# before it ever reaches a lookup — TestReservedSecretID_RejectedByProvider.
mutate reserved-guard-off fpkey.go \
	'func isReservedSecretID(path string) bool { return path == fpKeySecretID || path == intakeKeySecretID }' \
	'func isReservedSecretID(path string) bool { return path == intakeKeySecretID }' \
	TestReservedSecretID_RejectedByProvider

# An organisation's key level must actually persist: a fresh Sealer over the
# same database (a restart, or a second server process) must see the level
# a previous ChangeLevel set, not silently fall back to the default —
# TestLevel_PersistsAcrossRestart, TestLevel_SharedAcrossProcesses. Breaking
# the write itself (rather than the read) also fails every other test that
# calls ChangeLevel more than once against the same database, since the
# INSERT this targets errors at the SQL level (no such relation) instead of
# silently doing nothing.
mutate level-not-persisted store.go \
	'INSERT INTO keep_org_key_level (org_id, level, updated_by, updated_at)' \
	'INSERT INTO keep_org_key_level_disabled (org_id, level, updated_by, updated_at)' \
	TestLevel_PersistsAcrossRestart

# ChangeLevel's exclusive lock must be held for its whole operation —
# reading the level, deciding, persisting it, Rewrap and retire — not only
# around the level row's own read/write. Releasing it right after
# acquisition (instead of at the end of the call, via defer) reopens the
# race TestChangeLevel_LockCoversRewrap_NotJustTheLevelRow guards: a
# concurrent Write can then read the old level and commit its envelope
# after Rewrap already took its snapshot, permanently missing it. Rebind
# to the original pool-backed store after release: querying the released
# lock connection would panic before reaching this concurrency assertion.
mutate level-lock-released-early sealer/sealer.go \
	'defer func() { _ = release(ctx) }()' \
	'_ = release(ctx); locked = s.store' \
	TestChangeLevel_LockCoversRewrap_NotJustTheLevelRow

# Rewrap's per-row UPDATE must refuse a row a concurrent Erase has since
# marked 'erased' — otherwise it writes the re-wrap it computed from the
# row's pre-erase envelope straight back over the NULLs Erase just set,
# undoing a crypto-erasure that is supposed to be permanent —
# TestRewrap_DoesNotResurrectConcurrentlyErasedRow.
mutate rewrap-resurrects-erased store.go \
	"version = \$8 AND status <> 'erased'" \
	'version = $8' \
	TestRewrap_DoesNotResurrectConcurrentlyErasedRow

# store.Lock's key must be scoped per organisation — otherwise a
# ChangeLevel/Write for one org would contend with, and block behind, a
# completely unrelated org's lock — TestLevelLock_DoesNotCrossOrgBoundary.
mutate level-lock-any-org store.go \
	'func levelLockKey(org string) string { return "keep_org_key_level:" + org }' \
	'func levelLockKey(org string) string { return "keep_org_key_level" }' \
	TestLevelLock_DoesNotCrossOrgBoundary

# Write and FingerprintKey must actually take the org's shared key-level
# lock before reading the level and persisting — a no-op in its place would
# let either race a concurrent ChangeLevel exactly as before the lock
# existed. "SELECT $1::text" keeps the query's parameter count intact (an
# earlier version of this mutation used "SELECT 1", which drops the
# argument entirely — pgx then rejects the call outright with "mismatched
# param and argument count" before the query ever runs, so every test that
# calls Write/FingerprintKey at all fails for a reason that has nothing to
# do with the lock; that is a vacuous mutation the same way a mutant that
# fails to build is, see mutate()'s own doc comment) while granting
# nothing: TestChangeLevel_LockCoversRewrap_NotJustTheLevelRow (Write) and
# its FingerprintKey-side counterpart below are what actually catch the
# lock being gone.
mutate write-lock-is-noop provider.go \
	'SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))' \
	'SELECT $1::text' \
	TestChangeLevel_LockCoversRewrap_NotJustTheLevelRow
mutate fpkey-lock-is-noop fpkey.go \
	'SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))' \
	'SELECT $1::text' \
	TestChangeLevel_LockCoversRewrap_FingerprintKey

# Disable's UPDATE must not overwrite a row a concurrent Erase already moved
# to 'erased' — Erase takes no secret lock, so it can land between Disable's
# status read and its UPDATE, and the UPDATE's own status = 'active' guard is
# what keeps crypto-erasure final — TestDisable_DoesNotOverwriteConcurrentErase.
mutate disable-overwrites-erased store.go \
	"AND secret_id = \$5 AND version = \$6 AND status = 'active'\`," \
	"AND secret_id = \$5 AND version = \$6\`," \
	TestDisable_DoesNotOverwriteConcurrentErase

# ChangeLevel must run its envelope scan and updates on the connection its
# lock is held on. Off that connection Rewrap borrows a second one from the
# pool, which writers waiting for the lock can exhaust — a deadlock only a
# context deadline ends — TestChangeLevel_NeedsOnlyItsLockConnection.
mutate rewrap-off-lock-connection sealer/sealer.go \
	'if lb, ok := st.(LockBound); ok {' \
	'if lb, ok := st.(LockBound); ok && false {' \
	TestChangeLevel_NeedsOnlyItsLockConnection

# A database error reaches the caller as provider.ErrUnavailable with its
# SQLSTATE only — the driver's own text can quote the failing row, which for
# keep_envelope is a wrapped DEK and ciphertext —
# TestUnavailable_DropsPgErrorRowText.
mutate pgerror-wrapped provider.go \
	'return fmt.Errorf("%w: %s: sqlstate %s", provider.ErrUnavailable, what, pgErr.Code)' \
	'return fmt.Errorf("%w: %s: %w", provider.ErrUnavailable, what, err)' \
	TestUnavailable_DropsPgErrorRowText

# Admin returns the sealer's and the store's errors to its caller; a database
# error in that chain (a constraint violation's Detail quotes the failing row)
# is cut down to its SQLSTATE — TestAdminChangeLevel_DatabaseErrorCarriesSQLSTATEOnly.
# Write drops the seal error (a KEK INSERT's constraint Detail quotes the
# wrapped KEK) — TestWrite_SealDatabaseErrorIsNotChained.
mutate seal-error-raw provider.go \
	'return provider.Meta{}, fmt.Errorf("%w: seal failed", provider.ErrUnavailable)' \
	'return provider.Meta{}, fmt.Errorf("%w: seal failed: %w", provider.ErrUnavailable, err)' \
	TestWrite_SealDatabaseErrorIsNotChained

mutate purge-error-raw admin.go \
	'return n, scrubDB("purge", err)' \
	'return n, err' \
	TestAdminPurge_DatabaseErrorCarriesSQLSTATEOnly

mutate fpkey-open-error-raw fpkey.go \
	'return fingerprint.Key{}, scrubDB("open fingerprint key", fmt.Errorf("builtin: open fingerprint key: %w", err))' \
	'return fingerprint.Key{}, fmt.Errorf("builtin: open fingerprint key: %w", err)' \
	TestFingerprintKey_OpenDatabaseErrorCarriesSQLSTATEOnly

mutate admin-error-raw admin.go \
	'return res, scrubDB("change level", err)' \
	'return res, err' \
	TestAdminChangeLevel_DatabaseErrorCarriesSQLSTATEOnly

# The transactions that take the shared key-level lock must not inherit the
# server's default isolation: under REPEATABLE READ their snapshot predates
# the lock, and a Write that waited for a level change seals under the old
# KEK — TestKeyLevelLock_HoldsUnderRepeatableRead.
mutate default-isolation provider.go \
	'var readCommitted = pgx.TxOptions{IsoLevel: pgx.ReadCommitted}' \
	'var readCommitted = pgx.TxOptions{}' \
	TestKeyLevelLock_HoldsUnderRepeatableRead

# Write's log line carries names and versions, never the value — the log
# capture in the leak test must see a planted value.
mutate write-logs-value provider.go \
	'p.log.Info("write", "secret_id", loggableID(ref.Path), "version_id", versionString(version))' \
	'secret.Expose(v, func(b []byte) { p.log.Info("write", "secret_id", loggableID(ref.Path), "version_id", string(b)) })' \
	TestLeakInLogs_BuiltinSurfaces

# Disable's count-then-update stops being atomic: the per-secret lock goes
# away, so parallel Disable calls of different versions each see "more than
# one active" and disable their own, leaving none —
# TestDisable_ConcurrentNeverLeavesZeroActive.
mutate disable-not-atomic store.go \
	'if err := lockSecret(ctx, tx, scope, secretID); err != nil { // serialise against parallel Disable' \
	'if err := error(nil); err != nil { // serialise against parallel Disable' \
	TestDisable_ConcurrentNeverLeavesZeroActive

# Disable stops refusing the last active version (provider.ErrLastVersion).
# "active <= 0" keeps the active variable referenced (count(*) is never
# negative) — a bare "if false" would delete its only use and fail to build.
mutate disable-last-version store.go \
	'if active <= 1 {' \
	'if active <= 0 {' \
	TestConformance/disable_two_phase

. "$root/scripts/lib/baseline-diag.sh"
baseline_rc=0
mutation_apply_only || (cd "$root" && KEEP_DATABASE_URL="$KEEP_DATABASE_URL" go test -timeout 120s -count=1 -p 1 -v ./$pkg/ >"$work/baseline" 2>&1) || baseline_rc=$?
if mutation_apply_only; then
	:
elif [ "$baseline_rc" -eq 0 ] && ! grep -q -- '--- SKIP' "$work/baseline"; then
	echo "ok   baseline: tests green on the real code, zero SKIPs"
else
	echo "FAIL baseline: tests are red or skipped on the real code"
	baseline_diagnose "$work/baseline" "$baseline_rc"
	fail=1
fi

exit $fail
