#!/bin/sh
# Proves the Mesh confirmation guards can fail (threat model 4.1, 4.3): in a
# scratch copy of the tree, switch off one property of the task.gate.decided
# path, the card text or the plugin client at a time and require the named test
# to go red. A build error, a skip or an unrelated failure is not evidence.
# Needs a real PostgreSQL: KEEP_DATABASE_URL.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
mutation_apply_only || : "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must name disposable PostgreSQL}"

fail=0
pkg=./internal/deployment
dir=.
# mutate NAME FILE FROM TO TEST: replace one literal FROM with TO in FILE and
# require TEST (package $pkg, run in $dir) to fail with a real --- FAIL.
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
	if (cd "$work/tree/$dir" && go test -count=1 -p 1 -timeout 240s -run "$test" "$pkg" >"$work/out" 2>&1); then
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

M=internal/meshgate/meshgate.go
# Who may answer, and on what.
mutate agent-answer-accepted  $M 'if d.DecidedByType != "user" {' 'if false {'                                   TestGateRefusesWhatInvariantsForbid
mutate hash-compare-noop      $M 'subtle.ConstantTimeCompare(shown, g.Hash[:]) != 1' 'subtle.ConstantTimeCompare(shown[:0], shown[:0]) != 1' TestGateRefusesWhatInvariantsForbid
mutate initiator-check-off    $M 'g.InitiatorRef != "" && strings.EqualFold(g.InitiatorRef, by.String())' 'false'  TestGateRefusesInitiator
mutate unlinked-user-accepted $M '		if !linked {' '		if linked && false {'                                TestGateRefusesWhatInvariantsForbid
# A link names who answered; only the approve role in the secret's scope decides.
mutate approver-check-off     $M '		if !may {' '		if may && false {'                                    TestGateDecidesOnlyByRole
mutate approver-check-noop    $M '		may, perr := s.approvers.CanApprove(ctx, g.Org, keepUser, a.Scope)' '		may, perr := true, error(nil)
		_ = a'                                                                                                     TestGateDecidesOnlyByRole
mutate approver-unset-allowed $M '		if s.approvers == nil {
			return Settlement{}, ErrUnavailable
		}' ''                                                                                                       TestGateWithoutRoleCheckDecidesNothing
mutate approver-error-ignored $M '		if perr != nil {
			return Settlement{}, ErrUnavailable
		}' '		_ = perr'                                                                                         TestGateWithoutRoleCheckDecidesNothing
mutate approver-scope-dropped internal/deployment/meshgate.go 'RequestID: a.RequestID, Scope: a.Scope}' 'RequestID: a.RequestID}'          TestGateDecidesOnlyByRole
mutate removed-user-linked    internal/meshgate/pgstore.go " AND u.status='active'" ''                                  TestGateDecidesOnlyByRole
mutate expiry-check-off       $M '		if !s.now().Before(g.ExpiresAt) {' '		if false {'                   TestGateTimeoutCancelsCardAndRequest
mutate decision-word-guessed  $M '	if !ok {
		return refuse(ReasonNoDecision)' '	if ok && false {
		return refuse(ReasonNoDecision)'                                                                          TestGateRefusesWhatInvariantsForbid
# A repeat and a race apply once.
mutate repeat-status-ignored  $M '		case g.Status != "pending":' '		case false:'                    TestGateRepeatedEventIsIdempotent internal/deployment/approval.go '	if status != "requested" {' '	if false {'
mutate exactly-once-off        $M '		case g.Status != "pending":' '		case false:' TestGateConcurrentAnswersApplyOnce internal/deployment/approval.go '	if status != "requested" {' '	if false {'
# Answers waiting for one gate lock never take the connection its holder needs.
mutate settle-slots-unbounded internal/meshgate/pgstore.go 'settleSlots: make(chan struct{}, n)}' 'settleSlots: make(chan struct{}, n+64)}' TestGateConcurrentAnswersApplyOnce
mutate one-conn-pool-accepted internal/meshgate/pgstore.go '	n := 0
	if pool != nil {' '	n := 1
	if pool != nil {' TestGateStoreRefusesAOneConnectionPool
mutate one-conn-check-dropped internal/meshgate/pgstore.go '	if cap(p.settleSlots) == 0 {
		return ErrPoolTooSmall
	}' '' TestGateStoreRefusesAOneConnectionPool
mutate settle-slot-skipped    internal/meshgate/pgstore.go '	case p.settleSlots <- struct{}{}:' '	default:' TestGateConcurrentAnswersApplyOnce internal/meshgate/pgstore.go '	defer func() { <-p.settleSlots }()' ''
# Timeout.
mutate sweep-skips-cancel     $M 's.cards.Cancel(ctx, g.TaskID.String(), "request expired"); err != nil' 'error(nil); err != nil' TestGateTimeoutCancelsCardAndRequest
mutate sweep-lapse-off        internal/meshgate/pgstore.go "WHERE status='pending' AND expires_at <= \$1" "WHERE status='pending' AND expires_at <= \$1 AND false" TestGateTimeoutCancelsCardAndRequest
mutate open-lapsed-accepted   $M '	if a.Status != "requested" || !a.ExpiresAt.After(s.now()) {' '	if a.Status != "requested" {' TestGateOpenRefusesLapsedApproval
mutate gate-not-reconciled     $M '			if gerr == nil && (cur.Status == "approved" || cur.Status == "rejected") {' '			if gerr == nil && false {' TestGateDecidedElsewhereSettlesGateNotExpired
mutate link-org-unbound       internal/meshgate/pgstore.go 'AND l.org_id=$3`' 'AND $3::uuid IS NOT NULL`' TestGateLinkIsBoundToOrg
mutate refusal-key-dropped    $M 'slog.String("kind", string(r))' 'slog.String("reason", string(r))' TestGateRefusesWhatInvariantsForbid
mutate gate-org-unbound        $M '		case g.Org != org:' '		case false:' TestGateIsBoundToOrgAndWorkspace
mutate link-workspace-unbound internal/meshgate/pgstore.go 'WHERE l.workspace_id=$1 AND l.mesh_user_id=$2 AND l.org_id=$3`' 'WHERE $1::uuid IS NOT NULL AND l.mesh_user_id=$2 AND l.org_id=$3`' TestGateIsBoundToOrgAndWorkspace
mutate orphan-card-kept        $M '		_ = s.cards.Cancel(context.WithoutCancel(ctx), id, "request not registered")' '		_ = id' TestGateOpenCancelsCardItCannotRegister
mutate sweep-unrecorded-counted $M '		if s.store.CardCancelled(ctx, g.Workspace, g.TaskID) != nil {' '		if false {' TestGateSweepDoesNotCountUnrecordedCancel
mutate card-body-extra         $M '"\nAnswer with the word approve or reject first."' '"\nExtra: " + a.SecretName + "\nAnswer with the word approve or reject first."' TestGateCardBodyIsClosedSet
# Leaks: each plants a leak on a different surface; the canary tests must see it.
mutate card-hash-unbound      $M '		RequestHash: a.BindingHash,' '		RequestHash: "",'                  TestGateCardCarriesPointerNotValue
mutate card-ref-unbound       $M '		ExternalRef: "keep:approval/" + a.ID.String(),' '		ExternalRef: "",'  TestGateCardCarriesPointerNotValue
mutate leak-text-in-log       $M 'slog.String("kind", string(r)))
		return Outcome{Kind: Refused, Reason: r}, nil' 'slog.String("kind", string(r)), slog.String("name", d.Decision))
		return Outcome{Kind: Refused, Reason: r}, nil'                                                          TestGateLeakDecisionTextNeverStored
# The events route: a failed apply is retried, a refusal is acknowledged once.
# Signing in through Mesh links the Mesh user, and only a Mesh user id.
pkg=./internal/meshext
F=internal/meshext/federation.go
mutate signin-link-dropped    $F '	if err := f.link(ctx, ws, meshUser, org, user); err != nil {' '	if err := error(nil); err != nil && meshUser == org {' TestSignInLinksTheMeshUser
mutate signin-subject-unparsed $F '	meshUser, err := uuid.Parse(claims.Subject)
	if err != nil {' '	meshUser, _ := uuid.Parse(claims.Subject)
	if false {'                                                                                                    TestSignInRefusesASubjectThatIsNotAnID
mutate signin-link-error-ignored $F '		return fmt.Errorf("meshext: link mesh user: database error")' '		return nil'              TestSignInFailsClosedWhenTheLinkIsNotWritten
pkg=./cmd/keep-server/app
mutate approvers-not-approve  cmd/keep-server/app/meshgate.go '	return perms[identity.PermApprove], nil' '	return perms[identity.PermDeploy], nil' TestMeshGateApproversAreTheConsoleRole
mutate forget-removed         internal/api/mesh.go '			_ = m.deps.Repo.Forget(fctx, ws, ev.ID)' '			_, _ = fctx, ws' TestMeshGateEventNotAppliedIsRetriedNotDropped
mutate gate-type-unchecked    internal/api/mesh.go 'if inserted && ev.Type == meshGateDecided && m.deps.Gates != nil {' 'if inserted && m.deps.Gates != nil {' TestMeshGateEventOnlyForGateType
mutate repeat-reapplied       internal/api/mesh.go 'if inserted && ev.Type == meshGateDecided && m.deps.Gates != nil {' 'if (inserted || true) && ev.Type == meshGateDecided && m.deps.Gates != nil {' TestMeshGateEventIsAppliedOnceAndRefusalIsAcknowledged
mutate leak-text-in-header    internal/api/mesh.go '	ev, err := meshext.ParseEvent(' '	w.Header().Set("X-Echo", string(body))
	ev, err := meshext.ParseEvent('                                                                                       TestMeshGateAnswerTextNeverLeaks
mutate route-type-forced       internal/api/mesh.go 'DecidedByType: ev.DecidedByType' 'DecidedByType: "user"' TestMeshGateEventPassesEveryFieldUnchanged
mutate route-hash-dropped      internal/api/mesh.go 'ExternalHash: ev.ExternalHash' 'ExternalHash: ""' TestMeshGateEventPassesEveryFieldUnchanged
mutate route-decision-forced   internal/api/mesh.go 'Decision: ev.Decision' 'Decision: "approve"' TestMeshGateEventPassesEveryFieldUnchanged
mutate route-decider-swapped   internal/api/mesh.go 'DecidedBy: ev.DecidedBy,' 'DecidedBy: ev.TaskID,' TestMeshGateEventPassesEveryFieldUnchanged
mutate route-nil-backend       internal/api/mesh.go 'if inserted && ev.Type == meshGateDecided && m.deps.Gates != nil {' 'if inserted && ev.Type == meshGateDecided {' TestMeshGateEventWithoutBackendIsAcknowledged
# The wiring: every new approval gets its card in the same transaction, a bad or
# half configuration stops the start, and the timer cancels lapsed cards.
pkg=./internal/deployment
mutate confirm-dropped-deploy  internal/deployment/repo.go '	if out.ApprovalID != uuid.Nil && r.confirm != nil {' '	if false {' TestConfirmerCreatesTheCardWithTheApproval
mutate confirm-error-ignored   internal/deployment/repo.go 'BindingHash: requestHash, ExpiresAt: approvalExpires}); err != nil {' 'BindingHash: requestHash, ExpiresAt: approvalExpires}); false {' TestConfirmerRefusalLeavesNoApproval
mutate undo-skipped-deploy     internal/deployment/repo.go '			undo(ctx)' '			_ = undo' TestConfirmerUndoesTheCardWhenTheCommitFails
mutate ambiguous-workspace-ok  internal/meshgate/opentx.go '	if len(ws) != 1 {' '	if len(ws) < 1 {' TestConfirmerRefusesAnAmbiguousWorkspace
mutate no-installation-ok      internal/meshgate/opentx.go '	if len(ws) != 1 {' '	if len(ws) > 1 {' TestConfirmerRefusesOrganizationsWithoutMesh
pkg=./cmd/keep-server/app
mutate confirm-dropped-rotate  internal/rotation/approval.go '	if s.confirm != nil {' '	if false {' TestRotationApprovalAsksMeshInTheSameTransaction
mutate undo-skipped-rotate     internal/rotation/approval.go '			undo(ctx)' '			_ = undo' TestRotationApprovalUndoesTheCardWhenTheCommitFails
mutate deploy-confirmer-unwired cmd/keep-server/app/meshgate.go '	dep.WithConfirmer(conf)' '	_ = dep' TestMeshGateWiringReachesDeploymentsAndRotations
mutate rotate-confirmer-unwired cmd/keep-server/app/meshgate.go '		svc.WithConfirmer(conf)' '		_ = svc' TestMeshGateWiringReachesDeploymentsAndRotations
mutate sweep-timer-not-started cmd/keep-server/app/meshgate.go '	go runMeshSweep(ctx, gates, every, logger)' '	_ = every' TestMeshGateSweepTimerCancelsTheCardOfALapsedRequest
mutate sweep-stops-on-error    cmd/keep-server/app/meshgate.go '		case <-t.C:
			sweep()' '		case <-t.C:
			if _, err := s.Sweep(ctx); err != nil {
				return
			}' TestMeshGateSweepLoopKeepsGoingOnErrorsAndStopsWithContext
mutate sweep-ignores-ctx       cmd/keep-server/app/meshgate.go '		case <-ctx.Done():
			return
		case <-t.C:' '		case <-t.C:' TestMeshGateSweepLoopKeepsGoingOnErrorsAndStopsWithContext
mutate no-plugin-accepted      cmd/keep-server/app/meshgate.go '		if opts.Cards == nil {' '		if false && opts.Cards == nil {' TestMeshGateConfiguredWithoutPluginOrWithRefusalStopsStart
mutate off-wires-gate          cmd/keep-server/app/meshgate.go '	if !cfg.MeshExtension {
		return nil, nil
	}' '	if false {
		return nil, nil
	}' TestMeshGateOffKeepsTheCoreWithoutMesh
mutate rotate-card-hash-unbound internal/rotation/approval.go 'BindingHash: hash, ExpiresAt: expires}' 'BindingHash: [32]byte{}, ExpiresAt: expires}' TestRotationApprovalAsksMeshInTheSameTransaction
mutate rotate-card-expiry-unbound internal/rotation/approval.go 'BindingHash: hash, ExpiresAt: expires}' 'BindingHash: hash, ExpiresAt: time.Time{}}' TestRotationApprovalAsksMeshInTheSameTransaction
mutate foreign-rotation-accepted cmd/keep-server/app/meshgate.go '	if rot != nil && !ok {' '	if false {' TestMeshGateRefusesARotationServiceItCannotWire
mutate sweep-first-run-dropped cmd/keep-server/app/meshgate.go '	sweep()
	t := time.NewTicker(every)' '	t := time.NewTicker(every)' TestMeshGateSweepRunsAtOnce
mutate sweep-error-text-logged cmd/keep-server/app/meshgate.go 'logger.Warn("mesh gate sweep failed", "error_class", "unavailable")' 'logger.Warn("mesh gate sweep failed: "+err.Error(), "error_class", "unavailable")' TestMeshGateSweepLogsOnlyTheClass
pkg=./internal/config
mutate url-host-unchecked      internal/config/meshgate.go 'err != nil || u.Host == "" || u.Hostname() == ""' 'err != nil || u.Host == ""' TestMeshGatePartialOrBadConfigFailsWithoutValues
mutate interval-alone-is-off   internal/config/meshgate.go ' && interval == "" {' ' {' TestMeshGatePartialOrBadConfigFailsWithoutValues
mutate token-mode-unchecked    internal/config/meshgate.go '	case fi.Mode().Perm() != 0o600:' '	case false:' TestMeshGatePartialOrBadConfigFailsWithoutValues
mutate token-mode-not-exact    internal/config/meshgate.go '	case fi.Mode().Perm() != 0o600:' '	case fi.Mode().Perm()&0o077 != 0:' TestMeshGatePartialOrBadConfigFailsWithoutValues
mutate token-empty-accepted    internal/config/meshgate.go '	case fi.Size() == 0:' '	case false:' TestMeshGatePartialOrBadConfigFailsWithoutValues
pkg=./cmd/keep-server/app
mutate startup-partial-accepted internal/config/meshgate.go '		if v.val == "" {' '		if false {' TestServeMeshGateStartup
# The plugin client (its own module).
pkg=./...
dir=plugins/mesh
mutate unarmed-card-kept      plugins/mesh/gate.go '		_ = g.Cancel(context.WithoutCancel(ctx), id, "request not bound")' '		_ = id' TestGatesCreateCancelsCardThatCannotBeArmed
mutate hash-not-bound         plugins/mesh/gate.go '"external_hash": s.RequestHash' '"external_hash": ""'  TestGatesCreateBindsHashAndArmsGate
mutate redirect-followed      plugins/mesh/gate.go '	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }' '	_ = hc' TestGatesRedirectIsNotFollowed
mutate refusal-misclassed     plugins/mesh/gate.go 'case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusBadRequest:' 'case http.StatusUnauthorized, http.StatusNotFound:' TestGatesRefusalsAreClassed
mutate plain-http-remote      plugins/mesh/gate.go '(u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname())))' 'false' TestGatesConfigIsStrict
mutate leak-body-in-error     plugins/mesh/gate.go '		return nil, gatecard.ErrRefused' '		return nil, &url.Error{Op: "x", URL: string(body), Err: gatecard.ErrRefused}' TestGatesNothingFromMeshSurfaces
mutate gate-class-soft         plugins/mesh/gate.go '"class":  "hard"' '"class":  "soft"' TestGatesBodiesCarryDeadlineClassAndStatus
mutate gate-deadline-dropped   plugins/mesh/gate.go '"deadline": s.Deadline.UTC().Format(time.RFC3339)' '"deadline": time.Time{}.UTC().Format(time.RFC3339)' TestGatesBodiesCarryDeadlineClassAndStatus
mutate gate-default-dropped   plugins/mesh/gate.go '	"recommended_default": "reject",
' '' TestGatesBodiesCarryDeadlineClassAndStatus
mutate gate-predicate-thin     plugins/mesh/gate.go '"credential_exists":false,"credential_reason":"only a linked person may decide; Keep refuses an answer from an agent",' '' TestGatesBodiesCarryDeadlineClassAndStatus
mutate gate-asker-holds-decision plugins/mesh/gate.go '"credential_exists":false,' '"credential_exists":true,' TestGatesBodiesCarryDeadlineClassAndStatus
mutate cancel-status-missing   plugins/mesh/gate.go 'map[string]string{"status_id": g.cancelled, "reason": reason}' 'map[string]string{"reason": reason}' TestGatesBodiesCarryDeadlineClassAndStatus
mutate card-id-unchecked       plugins/mesh/gate.go '	if !validUUID(id) {' '	if false {' TestGatesBadAnswerAndFailingDependencies
mutate cancel-status-unset-sent plugins/mesh/gate.go 'if !validUUID(cardID) || g.cancelled == "" {' 'if !validUUID(cardID) {' TestGatesBadAnswerAndFailingDependencies
mutate token-error-forwarded   plugins/mesh/gate.go '	if terr != nil || tok == "" {' '	if tok == "" {
		return nil, terr
	}
	if terr != nil {' TestGatesBadAnswerAndFailingDependencies
mutate transport-error-forwarded plugins/mesh/gate.go '	resp, err := g.hc.Do(r)
	if err != nil {' '	resp, err := g.hc.Do(r)
	if err != nil {
		return nil, err' TestGatesBadAnswerAndFailingDependencies
mutate token-file-mode-unchecked plugins/mesh/cmd/keep-server/cards.go ' || fi.Mode().Perm() != 0o600 {' ' {' TestTokenFileProblemsAreUnavailableAndNameNothing
mutate token-file-mode-not-exact plugins/mesh/cmd/keep-server/cards.go ' || fi.Mode().Perm() != 0o600 {' ' || fi.Mode().Perm()&0o077 != 0 {' TestTokenFileProblemsAreUnavailableAndNameNothing
mutate token-size-unbounded    plugins/mesh/cmd/keep-server/cards.go '|| len(raw) > maxTokenFile {' '{' TestTokenFileProblemsAreUnavailableAndNameNothing
mutate token-fifo-hangs        plugins/mesh/cmd/keep-server/cards.go 'os.O_RDONLY|syscall.O_NONBLOCK' 'os.O_RDONLY|syscall.O_NONBLOCK*0' TestTokenFileProblemsAreUnavailableAndNameNothing
mutate plugin-binary-without-cards plugins/mesh/cmd/keep-server/main.go 'app.Options{Cards: newCards, SelfRotate: newSelfRotate,' 'app.Options{SelfRotate: newSelfRotate,' TestPluginBinaryProvidesTheMeshCards
mutate plugin-binary-without-selfrotate plugins/mesh/cmd/keep-server/main.go 'app.Options{Cards: newCards, SelfRotate: newSelfRotate,' 'app.Options{Cards: newCards,' TestPluginBinaryProvidesTheMeshCards
mutate cards-ignore-vault-source plugins/mesh/cmd/keep-server/cards.go '	if tokens != nil {' '	if false {' TestCardsAskTheVaultSourceOnEveryCall
mutate cards-vault-token-cached plugins/mesh/cmd/keep-server/cards.go '	return func(ctx context.Context) (mesh.Token, error) {
		tok, err := tokens.Token(ctx)' '	tok, err := tokens.Token(context.Background())
	return func(ctx context.Context) (mesh.Token, error) {' TestCardsAskTheVaultSourceOnEveryCall
mutate cards-source-cause-forwarded plugins/mesh/cmd/keep-server/cards.go '		if err != nil || tok == "" {
			return "", errToken' '		if err != nil || tok == "" {
			return "", errors.Join(errToken, err)' TestTokenFromSourceRefusalIsOpaque
dir=.

# The actor token sealed at install: read anew on each call, refusals opaque,
# and handed to the plugin only for KEEP_MESH_WORKSPACE_ID.
pkg=./cmd/keep-server/app
T=cmd/keep-server/app/meshgate_token.go
mutate gate-token-cached       $T 'func (s vaultGateToken) Token(ctx context.Context) (string, error) {' 'var gateTokenMemo string

func (s vaultGateToken) Token(ctx context.Context) (string, error) {
	if gateTokenMemo != "" {
		return gateTokenMemo, nil
	}
	defer func() { gateTokenMemo = "x" + gateTokenMemo }()' TestGateTokenFromVaultIsReadAnewOnEveryCall
mutate gate-token-cause-forwarded $T '	if err != nil || !ok {
		return "", ErrGateToken' '	if err != nil || !ok {
		return "", errors.Join(ErrGateToken, err)' TestGateTokenRefusalsAreUnavailableAndNameNothing
mutate gate-token-org-unchecked $T '	if err != nil || !ok {' '	if _ = ok; err != nil {' TestGateTokenRefusalsAreUnavailableAndNameNothing
mutate gate-token-any-mesh-url $T '	if !sameOrigin(s.meshURL, installedFrom) {' '	if _ = installedFrom; false {' TestGateTokenRefusalsAreUnavailableAndNameNothing
mutate gate-token-origin-host-only $T 'strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)' 'strings.EqualFold(ua.Hostname(), ub.Hostname())' TestGateTokenRefusalsAreUnavailableAndNameNothing
mutate gate-token-empty-accepted $T '	if err != nil || tok == "" {' '	if err != nil {' TestGateTokenRefusalsAreUnavailableAndNameNothing
mutate gate-vault-source-not-wired cmd/keep-server/app/meshgate.go '	return vaultGateToken{installs: meshext.NewRepo(pool), vault: vault, workspace: ws, meshURL: gate.URL}, nil' '	_, _ = ws, meshext.NewRepo; return nil, nil' TestMeshGateHandsThePluginTheVaultSourceOnlyForAWorkspace
mutate gate-start-log-silent   cmd/keep-server/app/meshgate.go '			logger.Info("mesh gate on: actor token from " + from)' '			_ = from' TestMeshGateHandsThePluginTheVaultSourceOnlyForAWorkspace
pkg=./internal/builtin
mutate vault-token-cause-forwarded internal/builtin/mesh_vault.go '	v, _, err := m.local.Provider(org, "", "", "").Resolve(ctx, provider.Ref{Path: path})
	if err != nil {
		return "", errMeshVault' '	v, _, err := m.local.Provider(org, "", "", "").Resolve(ctx, provider.Ref{Path: path})
	if err != nil {
		return "", errors.Join(errMeshVault, errors.New(path))' TestMeshExtensionTokenRefusalsNameNothing
pkg=./internal/config
mutate gate-file-and-workspace-both internal/config/meshgate.go '	case g.TokenFile != "" && g.WorkspaceID != "":' '	case false:' TestMeshGatePartialOrBadConfigFailsWithoutValues
mutate gate-workspace-not-checked internal/config/meshgate.go '	if g.WorkspaceID != "" && !canonicalUUID(g.WorkspaceID) {' '	if false {' TestMeshGatePartialOrBadConfigFailsWithoutValues
pkg=./internal/deployment

# The unmutated tree is green with nothing skipped.
mutation_apply_only && exit "$fail"
for spec in './internal/deployment:TestGate:16' './cmd/keep-server/app:TestMeshGate:7' './internal/meshext:TestSignIn:3' './cmd/keep-server/app:TestGateToken:2' './internal/builtin:TestMeshExtensionToken:2'; do
	p=${spec%%:*} rest=${spec#*:}; run=${rest%%:*} min=${rest#*:}
	if (cd "$root" && go test -count=1 -p 1 -v -run "$run" "$p" >"$work/base" 2>&1) && ! grep -q -- '--- SKIP' "$work/base" && [ "$(grep -c -- '--- PASS' "$work/base")" -ge "$min" ]; then
		echo "ok   baseline: $run green on the real code in $p, none skipped"
	else
		echo "FAIL baseline: $run red or skipped in $p"
		fail=1
	fi
done
if (cd "$root/plugins/mesh" && go test -count=1 -v -run 'TestGates' ./... >"$work/base" 2>&1) && ! grep -q -- '--- SKIP' "$work/base" && [ "$(grep -c -- '--- PASS' "$work/base")" -ge 8 ]; then
	echo "ok   baseline: TestGates green on the real code, none skipped"
else
	echo "FAIL baseline: TestGates red or skipped"
	fail=1
fi
exit $fail
