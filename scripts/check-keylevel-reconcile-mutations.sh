#!/bin/sh
# Proves the guards of the key-level reconcile can fail: in a scratch copy of
# the tree, switch off one property of the reconcile at start (pairing by
# request id, the grace, the level lock, the order lock then request, the alias
# read, the request claim, one outcome per request, the clock of the age, the reconcile's actor) and
# require the named test to go red with a real --- FAIL. A build error, a skip
# or an unrelated failure is not evidence. Needs a real PostgreSQL:
# KEEP_DATABASE_URL.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
mutation_apply_only || : "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must name disposable PostgreSQL}"

fail=0
pkg=./cmd/keep-server/app
# mutate NAME FILE FROM TO TEST: replace one literal FROM with TO in FILE and
# require a test matching TEST to fail with a real --- FAIL. Optional 6-8:
# a second FILE FROM TO edited in the same mutant (a guard with two layers).
mutate() {
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

R=cmd/keep-server/app/keylevel_reconcile.go
K=internal/builtin/keylevel.go
A=cmd/keep-server/app/keylevel.go
C=cmd/keep-server/app/keylevel_claim.go
M=cmd/keep-server/app/main.go
# Pairing: an outcome closes only the request of its own id.
mutate pair-delete-off      $R '				delete(open, k)' '				_ = k' 'TestDanglingRequestsPairing|TestReconcileLeavesFinishedChangeAlone'
mutate pair-one-slot-per-org $R '			k := key{r.org, r.reqID}
			open[k] = append(open[k], r)' '			k := key{r.org, ""}
			open[k] = append(open[k], r)' 'TestDanglingRequestsPairByRequestID'
# A repeated id: the later request is the one an outcome closes, the earlier stays open.
mutate pair-repeat-overwrites $R '			open[k] = append(open[k], r)' '			open[k] = []keyLevelRecord{r}' 'TestDanglingRequestsSurviveARepeatedClientRequestID'
mutate outcome-keeps-id     $R '			RequestID: p.reqID,' '' 'TestReconcileIsIdempotent|TestReconcileGivesInterruptedRequestItsOutcome'
# Grace: a request younger than minAge may belong to a live change.
mutate grace-off            $R '		if p.age < minAge || !held[p.reqID] {' '		if !held[p.reqID] {' 'TestReconcileLeavesAFreshRequestAlone' $R '		if r.age >= minAge {' '		if true {'
# Level lock: the same lock a change holds, tried without waiting.
mutate lock-skip-off        $R '		if !ok {' '		if !ok && false {' 'TestReconcileSkipsOrgWhileAChangeHoldsTheLevelLock'
mutate lock-never-taken     $K 'SELECT pg_try_advisory_lock(hashtextextended($1, 0))' 'SELECT true WHERE $1 <> '"''"'' 'TestReconcileSkipsOrgWhileAChangeHoldsTheLevelLock'
mutate lock-other-key       $K '`SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, levelLockKey(org))' '`SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, "x"+levelLockKey(org))' 'TestReconcileSkipsOrgWhileAChangeHoldsTheLevelLock'
# A request journaled under the level lock: a stall after it holds the lock.
# A live handler also holds its claim: with the claim read switched off too,
# the level lock is the only guard left.
mutate lock-held-ignored    $K 'SELECT pg_try_advisory_lock(hashtextextended($1, 0))' 'SELECT true WHERE $1 <> '"''"'' 'TestReconcileLeavesAWaitingHandlerAlone' $C 'WHERE pg_try_advisory_xact_lock(hashtextextended(k.key, 0))' 'WHERE true OR pg_try_advisory_xact_lock(hashtextextended(k.key, 0))'
# Order lock -> request: a request journaled before the lock is open over the
# handler's wait for a connection, and the reconcile closes a live change.
mutate request-before-lock  $A '	res, err := builtin.NewAdmin(k.pool, k.local.Sealer(), org.String(), k.log).ChangeLevelByName(ctx, to, actor.String(), confirmWeakening, request)' '	if rerr := request(ctx); rerr != nil {
		return api.KeyLevelChange{}, errors.New("key level change refused: audit journal unavailable")
	}
	res, err := builtin.NewAdmin(k.pool, k.local.Sealer(), org.String(), k.log).ChangeLevelByName(ctx, to, actor.String(), confirmWeakening, nil)' 'TestReconcileLeavesAHandlerWaitingForAConnectionAlone' $C 'WHERE pg_try_advisory_xact_lock(hashtextextended(k.key, 0))' 'WHERE true OR pg_try_advisory_xact_lock(hashtextextended(k.key, 0))'
# Claim: a request whose claim is held, by any instance, has its outcome on the
# way; the reconcile reads the claim from the database, never from its process.
mutate claim-unread         $R '		if p.age < minAge || !held[p.reqID] {' '		_ = held
		if p.age < minAge {' 'TestReconcileOfAnotherInstanceLeavesAPendingOutcomeAlone|TestReconcileSkipsARequestWhoseClaimIsHeld' $R '		if len(free) == 0 {' '		if false {'
# One outcome per request: the reconcile writes only under the claim key it
# holds in its own transaction, never by the first look before the level lock;
# the writer appends under its claim and only when the request has no outcome.
mutate reconcile-no-claim-xact-lock $R '		if p.age < minAge || !held[p.reqID] {' '		_ = held
		if p.age < minAge || !free[p.reqID] {' 'TestReconcileOrgFencesAClaimTakenAgainAfterTheFirstLook'
mutate writer-no-outcome-check $C '	if answered {' '	if answered && false {' 'TestReconcileOverALostClaimLeavesOneOutcome'
mutate writer-off-claim-conn $A '	if a.claims == nil || !ok ||' '	if true || a.claims == nil || !ok ||' 'TestReconcileOverALostClaimLeavesOneOutcome'
mutate claim-always-free    $C 'WHERE pg_try_advisory_xact_lock(hashtextextended(k.key, 0))' 'WHERE true OR pg_try_advisory_xact_lock(hashtextextended(k.key, 0))' 'TestReconcileSkipsARequestWhoseClaimIsHeld|TestReconcileOfAnotherInstanceLeavesAPendingOutcomeAlone'
mutate claim-other-key      $C '	key := keyLevelClaimKey(org, id)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keyLevelClaimIOTimeout)' '	key := "x" + keyLevelClaimKey(org, id)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keyLevelClaimIOTimeout)' 'TestReconcileSkipsARequestWhoseClaimIsHeld'
# The change claims its request before it journals it; no claim, no change.
mutate change-claims-nothing $A '	if err := k.outcomes.claim(ctx, org.String(), id); err != nil {
		k.log.Error("key level change refused", "error_class", "claim", "org_id", org.String())
		return api.KeyLevelChange{}, errors.New("key level change refused: request claim unavailable")
	}
	defer k.outcomes.settle(org.String(), id)
' '' 'TestReconcileOfAnotherInstanceLeavesAPendingOutcomeAlone|TestKeyLevelChangeRefusedWithoutAClaim'
mutate claim-refusal-ignored $A '	if err := k.outcomes.claim(ctx, org.String(), id); err != nil {' '	if err := k.outcomes.claim(ctx, org.String(), id); err != nil && false {' 'TestKeyLevelChangeRefusedWithoutAClaim'
# The claim goes only once the outcomes queued before it are journaled.
mutate claim-released-at-settle $A '	a.pend = append(a.pend, pendingOutcome{org: org, id: id})' '	a.claims.release(org, id)' 'TestKeyLevelClaimHeldUntilItsOutcomeIsJournaled|TestReconcileOfAnotherInstanceLeavesAPendingOutcomeAlone'
mutate claim-never-released $A '			a.claims.release(p.org, p.id)
			continue' '			continue' 'TestKeyLevelClaimReleasedWhenNoOutcomeFollows|TestKeyLevelClaimHeldUntilItsOutcomeIsJournaled'
mutate claim-freed-at-stop  $A '	a.mu.Lock()
	a.pend = append(a.pend, pendingOutcome{org: org, id: id})' '	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		a.claims.release(org, id)
		return
	}
	a.pend = append(a.pend, pendingOutcome{org: org, id: id})' 'TestKeyLevelClaimKeptAfterStopUntilClose'
# A claim lost with its session is taken again: by the periodic check, and by
# the writer before each outcome; a live-looking dead session is pinged.
mutate claim-keeper-off     $C '		case <-t.C:
			c.ensure()' '		case <-t.C:' 'TestKeyLevelClaimKeptAfterItsSessionBroke'
mutate claim-no-ping        $C '	if c.conn != nil && c.conn.Ping(ctx) != nil {' '	if false {' 'TestKeyLevelClaimKeptAfterItsSessionBroke|TestKeyLevelOutcomeWriteTakesALostClaimAgain'
mutate write-no-ensure      $A '		a.claims.ensure()
' '' 'TestKeyLevelOutcomeWriteTakesALostClaimAgain'
mutate claim-on-request-ctx $C 'context.WithTimeout(context.WithoutCancel(ctx), keyLevelClaimIOTimeout)' 'context.WithTimeout(ctx, keyLevelClaimIOTimeout)' 'TestKeyLevelClaimIgnoresTheRequestCancel'
mutate claim-not-retaken    $C '	for key := range c.held {' '	for key := range map[string]struct{}{} {' 'TestKeyLevelClaimTakenAgainAfterItsConnectionBroke'
# Production wiring: the sink holds the claims, the change service has the sink.
mutate wire-no-claims       $M 'auditor := newKeyLevelAuditor(journal, logger, claims)' 'auditor := newKeyLevelAuditor(journal, logger, nil)' 'TestServeWiresTheClaimsIntoTheChange'
mutate wire-no-outcomes     $M 'meshDeps(cfg, pool, local, auditor, gates, journal, logger)' 'meshDeps(cfg, pool, local, nil, gates, journal, logger)' 'TestServeWiresTheClaimsIntoTheChange'
mutate start-no-reconcile   $M '	if _, err := reconcileKeyLevels(ctx, pool, journal, logger, keyLevelReconcileGrace); err != nil {' '	if err := error(nil); err != nil {' 'TestServeReconcilesBeforeItListens'
# Clock: the age comes from the clock that stamped the request, not from the database host.
mutate age-from-db-clock    $R '		r.age = keyLevelClock().Sub(ts)' '		r.age = time.Since(ts)' 'TestReconcileAgeFollowsTheAppClockNotTheDatabase'
mutate journal-clock-ignored internal/audit/journal.go '	c.now = now' '	_ = now' 'TestReconcileAgeFollowsTheAppClockNotTheDatabase'
# The reconciled outcome is the server's own.
mutate actor-is-requester   $R 'audit.ActorSystem, ID: keyLevelReconcileActor' 'audit.ActorUser, ID: p.actor' 'TestReconcileOutcomeIsASystemActor'
mutate actor-id-is-requester $R 'ID: keyLevelReconcileActor' 'ID: p.actor' 'TestReconcileOutcomeIsASystemActor'
# Alias: "org" and "organization" are one level.
mutate alias-unresolved     $K '	return l.String(), true
}' '	_ = l
	return name, true
}' 'TestReconcileSeesAliasAndCanonicalLevelAsOne|TestReconcileReadsRequestedAliasAsTheCanonicalLevel'
# The request is journaled with the id its outcome will carry.
mutate request-id-dropped   $A '		RequestID: id,' '' 'TestKeyLevelChangeIssuesItsOwnRequestID'
# The id is the server's own: the client's repeatable X-Request-Id never keys the pair,
# and never reaches the journal.
mutate request-id-from-client $A '	id := reqid.New()
' '	id := reqid.FromContext(ctx)
' 'TestKeyLevelChangeIssuesItsOwnRequestID'
mutate client-id-in-reason $A '	id := reqid.New()
' '	cid := reqid.FromContext(ctx)
	id := reqid.New()
' 'TestKeyLevelChangeKeepsClientRequestIDOutOfJournal' $A 'confirm_weakening=%t", to, confirmWeakening)' 'confirm_weakening=%t", to, confirmWeakening) + cid'

# The request hook runs under the level lock, on the lock connection, and its
# failure means the change does not start.
H=internal/builtin/store.go
S=internal/builtin/sealer/sealer.go
mutate pool-not-lockconn    $A '	if !ok || !tok {' '	if _, _ = ok, tok; true {' 'TestKeyLevelRequestNeedsNoSecondPoolConnection'
mutate lockconn-empty       $H '		return context.WithValue(ctx, lockConnKey{}, c)' '		_ = c
		return ctx' 'TestKeyLevelRequestNeedsNoSecondPoolConnection'
mutate sealer-no-lockconn   $S '			hctx = lc.WithLockConn(hctx)' '			_ = lc' 'TestKeyLevelRequestNeedsNoSecondPoolConnection'
mutate hook-err-swallowed   $A '			k.log.Error("key level change refused", "error_class", "audit_write", "org_id", org.String())
		}
		return err' '			k.log.Error("key level change refused", "error_class", "audit_write", "org_id", org.String())
		}
		return nil' 'TestKeyLevelChangeRefusedWhenJournalUnavailable|TestKeyLevelHookFailureLeaksNoValue'
mutate errlevelrequest-unmapped $A '	case errors.Is(err, builtin.ErrLevelRequest):' '	case false:' 'TestKeyLevelChangeRefusedWhenJournalUnavailable|TestKeyLevelHookFailureLeaksNoValue'
mutate builtin-map-dropped  $K '	if errors.Is(err, sealer.ErrOnLocked) {' '	if false {' 'TestKeyLevelChangeRefusedWhenJournalUnavailable|TestKeyLevelHookFailureLeaksNoValue'
# The stalled change also holds its claim: with the claim read switched off,
# the level lock is the only guard left.
mutate journal-before-lock  $A '	res, err := builtin.NewAdmin(k.pool, k.local.Sealer(), org.String(), k.log).ChangeLevelByName(ctx, to, actor.String(), confirmWeakening, request)' '	if rerr := request(ctx); rerr != nil {
		return api.KeyLevelChange{}, errors.New("key level change refused: audit journal unavailable")
	}
	res, err := builtin.NewAdmin(k.pool, k.local.Sealer(), org.String(), k.log).ChangeLevelByName(ctx, to, actor.String(), confirmWeakening, nil)' 'TestKeyLevelStalledChangeGetsOneOutcome' $C 'WHERE pg_try_advisory_xact_lock(hashtextextended(k.key, 0))' 'WHERE true OR pg_try_advisory_xact_lock(hashtextextended(k.key, 0))'
# Reconcile works under the level lock on the lock's own connection: a second
# pool connection taken there starves behind queued writers.
mutate reconcile-second-conn $K '	return context.WithValue(ctx, lockConnKey{}, conn), func(c context.Context) {' '	return func() context.Context {
		c2, e := pool.Acquire(ctx)
		if e != nil {
			return ctx
		}
		return context.WithValue(ctx, lockConnKey{}, c2)
	}(), func(c context.Context) {' 'TestReconcileNeedsNoSecondPoolConnection'
mutate reconcile-append-on-pool $R '		r, err := j.AppendTx(ctx, tx, audit.Record{' '		r, err := j.Append(ctx, audit.Record{' 'TestReconcileNeedsNoSecondPoolConnection|TestReconcileWritesAnOrgsOutcomesTogether'
mutate reconcile-lock-kept  $R '		release(ctx)' '		_ = release' 'TestReconcileNeedsNoSecondPoolConnection'
mutate reconcile-commit-each $R 'audit journal unavailable")
		}
		out = append(out, r)' 'audit journal unavailable")
		}
		out = append(out, r)
		_ = tx.Commit(ctx)' 'TestReconcileWritesAnOrgsOutcomesTogether'
mutate reconcile-lockconn-empty $K '	return context.WithValue(ctx, lockConnKey{}, conn), func(c context.Context) {' '	return ctx, func(c context.Context) {' 'TestReconcileNeedsNoSecondPoolConnection|TestReconcileGivesInterruptedRequestItsOutcome'
mutate reconcile-not-logged $R '		j.LogCommitted(ctx, r)' '		_ = r' 'TestReconcileNeedsNoSecondPoolConnection'
mutate reconcile-no-commit  $R '	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit reconciled outcomes: database error")
	}' '' 'TestReconcileGivesInterruptedRequestItsOutcome|TestReconcileIsIdempotent'
mutate no-logcommitted      $A '	tj.LogCommitted(ctx, out)' '' 'TestKeyLevelHookFailureLeaksNoValue|TestKeyLevelStalledChangeGetsOneOutcome|TestKeyLevelChangeIssuesItsOwnRequestID'

# The hook leak scan sees each surface it claims to search: a capture that
# misses the log, the journal or the error would pass the canary scan.
T=cmd/keep-server/app/keylevel_hook_test.go
mutate log-capture-off      cmd/keep-server/app/mesh_test.go '	logger := obs.New(&buf)' '	logger := obs.New(new(bytes.Buffer))' 'TestKeyLevelHookFailureLeaksNoValue'
mutate refusal-log-dropped  $A '			k.log.Error("key level change refused", "error_class", "audit_write", "org_id", org.String())' '			_ = org' 'TestKeyLevelHookFailureLeaksNoValue'
mutate journal-dump-blind   $T 'FROM audit_records a WHERE org_id = $1`' 'FROM audit_records a WHERE org_id = $1 AND false`' 'TestKeyLevelHookFailureLeaksNoValue'
mutate error-surface-dropped $T '	for e := error(err); e != nil;' '	for e := error(nil); e != nil;' 'TestKeyLevelHookFailureLeaksNoValue'

# The unmutated tree is green, nothing skipped: a skip is not a pass.
rm -rf "$work/tree"
mutation_snapshot "$work/tree"
if mutation_apply_only; then
	:
elif ! (cd "$work/tree" && go test -count=1 -p 1 -timeout 240s -v -run 'Reconcile|Dangling|KeyLevelClaim|OutcomeUnderAHeldClaimIsTheOnlyOne|KeyLevelChangeRefusedWithoutAClaim|ServeWiresTheClaims|KeyLevelAuditor|IssuesItsOwnRequestID|KeepsClientRequestIDOutOfJournal|TestKeyLevelRequestNeedsNoSecondPoolConnection|TestKeyLevelHookFailureLeaksNoValue|TestKeyLevelChangeRefusedWhenJournalUnavailable|TestKeyLevelStalledChangeGetsOneOutcome' "$pkg" >"$work/out" 2>&1); then
	echo "FAIL baseline: the real code is not green"
	fail=1
elif grep -q -- '--- SKIP' "$work/out"; then
	echo "FAIL baseline: a reconcile test was skipped (is KEEP_DATABASE_URL reachable?)"
	fail=1
else
	echo "ok   baseline: green, nothing skipped"
fi
exit "$fail"
