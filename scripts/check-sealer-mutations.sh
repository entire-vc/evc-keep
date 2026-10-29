#!/bin/sh
# Proves the key-hierarchy tests can fail: in a scratch copy of the tree,
# switch off one property of internal/builtin/sealer at a time and require
# `go test ./internal/builtin/sealer/` to go red. A property whose removal
# leaves the tests green is not tested. Exits 0 only if every mutation is
# caught and the real code is green.
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
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace
pkg=internal/builtin/sealer

fail=0
# mutate NAME FILE FROM TO [WITNESS]: replace the first literal occurrence of FROM with TO.
mutate() {
	name=$1 src=$pkg/$2 from=$3 to=$4 witness=${5:-.}
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
	if (cd "$work/tree" && go test -timeout 120s -count=1 -run "$witness" ./$pkg/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		# Red because the mutant does not build is not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	elif [ "$witness" != . ] && ! grep -Fq -- "--- FAIL: $witness (" "$work/out"; then
		echo "FAIL $name: designated witness $witness did not fail"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

# A file-backed root must not be the known all-zero key, and a KEK's
# recorded root identifier must match even if two configured keys share bytes.
mutate root-nonzero rootkey.go 'if nonzero == 0 {' 'if false {' TestRootKeyRejectsZero
mutate root-identity sealer.go 'if rec.RootKeyID != s.root.ID() {' 'if false {'

# PKI has its own organization domain, independent of value levels/purge.
mutate pki-namespace level.go 'return "pki:" + lp(s.Org)' 'return "org:" + lp(s.Org)'
mutate pki-level level.go '		return s' '		return Scope{Org: s.Org}'
mutate pki-scope level.go 'case s.PKI && (s.Workspace != "" || s.Project != "" || s.User != ""):' 'case false && (s.Workspace != "" || s.Project != "" || s.User != ""):'
mutate pki-purge sealer.go '!k.Domain.PKI && !used[k.ID]' '!used[k.ID]'


# Early guards and their audit records have separate witnesses: deleting the
# whole guard/audit call must be caught, not just weakening its condition.
mutate change-invalid-level-guard sealer.go 'if !c.To.Valid() {' 'if false {' TestEarlyRefusalsAreAudited
mutate change-empty-org-guard sealer.go 'if c.Org == "" {' 'if false {' TestEarlyRefusalsAreAudited
mutate change-no-actor-guard sealer.go 'if c.Actor == "" {' 'if false {' TestEarlyRefusalsAreAudited
mutate purge-empty-org-guard sealer.go 'if org == "" {' 'if false {' TestEarlyRefusalsAreAudited
mutate purge-no-actor-guard sealer.go 'if actor == "" {' 'if false {' TestEarlyRefusalsAreAudited
mutate change-invalid-level-audit sealer.go 's.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "invalid_level"})' '_ = (Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "invalid_level"})' TestEarlyRefusalsAreAudited
mutate change-empty-org-audit sealer.go 's.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "invalid_scope"})' '_ = (Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "invalid_scope"})' TestEarlyRefusalsAreAudited
mutate change-no-actor-audit sealer.go 's.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "no_actor"})' '_ = (Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "no_actor"})' TestEarlyRefusalsAreAudited
mutate purge-early-audit sealer.go 's.audit.Record(Event{Action: "kek_purge_failed", Org: org, Actor: actor, Reason: reason})' '_ = (Event{Action: "kek_purge_failed", Org: org, Actor: actor, Reason: reason})' TestEarlyRefusalsAreAudited

mutate rewrap-missing-blocker sealer.go 'secretID, version = ref.SecretID, ref.Version' 'secretID, version = "", ""' TestRewrapFailureNamesOnlyBlockingIdentifiers
mutate rewrap-missing-audit-ids sealer.go 'SecretID: secretID, Version: version,' '' TestRewrapFailureNamesOnlyBlockingIdentifiers
mutate rewrap-current-auth sealer.go 'dek, err := ls.unwrapDEK(ctx, ref, e)' 'if e.KEKID == t.ID { return e, nil }; dek, err := ls.unwrapDEK(ctx, ref, e)' TestRewrapFailureNamesOnlyBlockingIdentifiers

# per-user KEK isolation
mutate domain-always-org   level.go  'org := Scope{Org: s.Org}' 'org := Scope{Org: s.Org}; if true { return org }'
mutate user-shares-org-kek level.go  'if l == LevelUser {' 'if false {'
# level change
mutate no-confirmation     sealer.go 'if from.Weakens(c.To) && !c.ConfirmWeakening {' 'if false {'
mutate no-rewrap           sealer.go 'if e.KEKID == t.ID {' 'if true {'
mutate no-retire           sealer.go 'if Domain(k.Domain, l) != k.Domain {' 'if false {'
mutate purge-referenced    sealer.go '!used[k.ID]' 'true'
mutate no-change-audit     sealer.go 's.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_changed"' '_ = (Event{RequestID: c.RequestID, Action: "key_level_changed"'
mutate no-denied-audit     sealer.go 's.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, From: from' '_ = (Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, From: from'
mutate no-failed-audit     sealer.go 's.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, SecretID: secretID, Version: version, From: from, To: c.To, Rewrapped' '_ = (Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, SecretID: secretID, Version: version, From: from, To: c.To, Rewrapped'
# a change that fails before Rewrap (lock, level read, level write) is audited
# too — TestChangeLevel_PersistenceFailuresAreAudited.
mutate no-lock-failed-audit  sealer.go 's.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "lock_failed"})' '_ = (Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "lock_failed"})'
mutate no-level-read-failed-audit sealer.go 's.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "level_read_failed"})' '_ = (Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "level_read_failed"})'
mutate no-level-write-failed-audit sealer.go 's.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, From: from, To: c.To, Reason: "level_write_failed"})' '_ = (Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, From: from, To: c.To, Reason: "level_write_failed"})'
# bindings
# kek-any-org used to live here (org-scoping of an unwrapDEK lookup on the
# in-memory kek map); the map is gone — a KEK's org is now enforced by the
# store's Get query (WHERE org_id = $1 AND id = $2), so that mutation moved
# to scripts/check-builtin-mutations.sh, which mutates the real query.
mutate dek-unbound         sealer.go 'return aad("keep/dek/v1", r.Store.key(), r.SecretID, r.Version, kekID)' 'return aad("keep/dek/v1", kekID)'
mutate aad-no-length       rootkey.go 'b = binary.BigEndian.AppendUint32(b, uint32(n))' 'b = binary.BigEndian.AppendUint32(b, uint32(n))[:len(b)]'
mutate default-org-level   level.go  'const DefaultLevel = LevelUser' 'const DefaultLevel = LevelOrg'

# activeKEK must refuse a KEK record whose own Domain does not match the
# domain it was looked up for (a store-level domain_key corruption) instead
# of unwrapping and using it — TestActiveKEK_RejectsDomainMismatch.
mutate active-kek-domain-unchecked sealer.go 'if rec.Org != d.Org || rec.Domain != d {' 'if false {'

# The store key that the DEK's AAD carries must not be ambiguous: without a
# length prefix on each id, two different scopes render the same key and one
# store's envelope opens as the other's — TestScopeKeyIsUnambiguous.
mutate scope-key-unprefixed level.go 'func lp(id string) string { return strconv.Itoa(len(id)) + ":" + id }' 'func lp(id string) string { _ = strconv.Itoa; return id }'
# Partial versions of the same mutation: one field without its length prefix
# is already enough to make two scopes render alike —
# TestScopeKeyRoundTripsForAdversarialIDs reads every key back.
mutate scope-key-ws-unprefixed level.go '"/ws:" + lp(s.Workspace) + "/proj:"' '"/ws:" + s.Workspace + "/proj:"'
mutate scope-key-org-unprefixed level.go '"org:" + lp(s.Org) + "/user:"' '"org:" + s.Org + "/user:"'
mutate scope-key-proj-unprefixed level.go '"/proj:" + lp(s.Project)' '"/proj:" + s.Project'
mutate scope-key-no-separator level.go 'func lp(id string) string { return strconv.Itoa(len(id)) + ":" + id }' 'func lp(id string) string { return strconv.Itoa(len(id)) + id }'

# A purge that fails part-way is journaled, and needs an actor —
# TestPurge_FailureIsAuditedAndNeedsActor.
mutate no-purge-failed-audit sealer.go 's.audit.Record(Event{Action: "kek_purge_failed", Org: org, Actor: actor, Reason: reason})' '_ = (Event{Action: "kek_purge_failed", Org: org, Actor: actor, Reason: reason})'
mutate purge-no-actor-check  sealer.go 'if actor == "" {' 'if false {'
# Each failing step of Purge has its own journaled reason —
# TestPurge_EachFailureStepIsAudited.
mutate purge-list-unaudited  sealer.go 'return failed("list_failed", err)' 'return 0, err'
mutate purge-store-unaudited sealer.go 'return failed("purge_failed", err)' 'return 0, err'

# The request hook runs once, under the level lock, before the change is
# decided, with a bounded deadline, and its failure stops the change.
mutate onlocked-after-decision sealer.go 'if c.OnLocked != nil {' 'if c.OnLocked != nil && c.ConfirmWeakening {' TestChangeLevel_OnLockedRunsBeforeTheChangeIsDecided
mutate onlocked-never-called   sealer.go 'if c.OnLocked != nil {' 'if false && c.OnLocked != nil {' TestChangeLevel_OnLockedRunsOnceUnderTheLockBeforeAnyWrite
mutate onlocked-no-deadline    sealer.go 'hctx, cancel := context.WithTimeout(ctx, OnLockedTimeout)' 'hctx, cancel := context.WithCancel(ctx)' TestChangeLevel_OnLockedRunsOnceUnderTheLockBeforeAnyWrite
mutate onlocked-long-deadline  sealer.go 'const OnLockedTimeout = 15 * time.Second' 'const OnLockedTimeout = time.Hour' TestChangeLevel_OnLockedRunsOnceUnderTheLockBeforeAnyWrite
mutate onlocked-error-ignored  sealer.go 'if herr != nil {' 'if false && herr != nil {' TestChangeLevel_OnLockedFailureStopsBeforeAnyWrite
mutate onlocked-text-forwarded sealer.go 'return ChangeResult{}, ErrOnLocked' 'return ChangeResult{}, fmt.Errorf("%w: %w", ErrOnLocked, herr)' TestChangeLevel_OnLockedFailureStopsBeforeAnyWrite

if mutation_apply_only; then
	:
elif (cd "$root" && go test -timeout 120s -count=1 ./$pkg/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
