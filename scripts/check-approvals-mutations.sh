#!/bin/sh
# Every guard of the approval flow must fail its own behavioral test when it
# is switched off in a scratch copy of the tree. A build error, a skip or an
# unrelated failure is not evidence: the designated test must report FAIL.
# Tests use isolated PostgreSQL databases (KEEP_DATABASE_URL).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
mutation_apply_only || : "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must name disposable PostgreSQL}"
# The tests need the real schema; applying it here makes the script correct
# on any database, not only one the CI job happened to migrate first.
mutation_apply_only || (cd "$root" && go run ./cmd/keep-server migrate up)
mutation_snapshot "$work/tree"
python3 - "$root" "$work" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys

root, work = map(Path, sys.argv[1:])
D, A, N, M = 'internal/deployment', 'internal/api', 'internal/notify', 'internal/store/migrations/00028_rotate_audit_approval.sql'
M18 = 'internal/store/migrations/00018_approvals.sql'
# The approval trigger lives in 00028 (Up and Down both carry it); the
# snippets below end in the Up-only column list so each target is unique.
UPTAIL = "NEW.rotation_run_id) THEN\n        RAISE EXCEPTION 'approval request content is immutable';\n"

# (name, file, before, after, designated test, package)
I = 'internal/identity'
mutations = [
    ('ttl', D + '/approval.go', '\tif expired {\n', '\tif false {\n', 'TestDecideAfterTTLIsRefused', D),
    ('self-approval', D + '/approval.go', 'if rtype == string(audit.ActorUser) && rid == in.ApproverID.String() {', 'if false {', 'TestDecideRefusesAgentAndSelf', D),
    ('agent-approver', D + '/approval.go', '\tif !in.ApproverIsUser {\n', '\tif false {\n', 'TestDecideRefusesAgentAndSelf', D),
    ('already-decided', D + '/approval.go', '\tif status != "requested" {\n', '\tif false {\n', 'TestDecideApproveCreatesExactlyTheShownJob', D),
    ('shown-hash', D + '/approval.go', '!equalHash(stored, shown) || ', '', 'TestApprovalBoundToHashTargetSwapRunsNothing', D),
    ('recomputed-hash', D + '/approval.go', ' || !equalHash(stored, recomputed[:])', ' || false && !equalHash(stored, recomputed[:])', 'TestApprovalBoundToHashTargetSwapRunsNothing', D),
    ('policy-recheck', D + '/approval.go', 'perr != nil || secret.provider', 'false && perr != nil || secret.provider', 'TestDecideApproveRechecksPolicyAndHost', D),
    ('frozen-approval-status', M, UPTAIL + "    END IF;\n    IF OLD.status <> 'requested' THEN", UPTAIL + "    END IF;\n    IF FALSE THEN", 'TestApprovalRowIsFrozenAfterDecision', D),
    ('frozen-approval-content', M, UPTAIL, "NEW.rotation_run_id) THEN\n        NULL;\n", 'TestApprovalContentIsImmutable', D),
    ('frozen-deployment-request', M18, "RAISE EXCEPTION 'deployment request is immutable';", 'RETURN NEW;', 'TestApprovalBoundToHashTargetSwapRunsNothing', D),
    ('console-csrf', A + '/console.go', 'subtle.ConstantTimeCompare([]byte(got), []byte(s.CSRF)) == 1', 'subtle.ConstantTimeCompare([]byte(got), []byte(s.CSRF)) == 1 || true', 'TestConsoleDecisionNeedsCSRFAndSameOrigin', A),
    ('console-foreign-site', A + '/console.go', 'if site != "" && site != "same-origin" {', 'if false {', 'TestConsoleDecisionNeedsCSRFAndSameOrigin', A),
    ('console-foreign-origin', A + '/console.go', 'return err == nil && u.Host != "" && u.Host == r.Host', 'return err == nil && u.Host != "" && u.Host == r.Host || true', 'TestConsoleDecisionNeedsCSRFAndSameOrigin', A),
    ('console-null-origin-needs-site', A + '/console.go', 'if origin == "" || origin == "null" {\n\t\treturn site == "same-origin"', 'if origin == "" || origin == "null" {\n\t\treturn true', 'TestConsoleDecisionNeedsCSRFAndSameOrigin', A),
    ('console-null-origin-refused', A + '/console.go', 'if origin == "" || origin == "null" {', 'if origin == "" {', 'TestConsoleDecisionNeedsCSRFAndSameOrigin', A),
    ('console-agent', A + '/console.go', '\tif s.Principal.Kind != identity.KindUser {\n', '\tif false {\n', 'TestConsoleAgentAndSelfApprovalAre403', A),
    ('console-self', A + '/console.go', '\tif isRequester(a, s.Principal) {\n\t\tc.fail(', '\tif false {\n\t\tc.fail(', 'TestConsoleAgentAndSelfApprovalAre403', A),
    ('console-scope', A + '/console.go', 'return perms[identity.PermApprove], nil', 'return perms[identity.PermApprove] || true, nil', 'TestConsoleListShowsOnlyApprovableScopes', A),
    ('console-exec-card', A + '/console.go', 'if e := a.Exec; e != nil {', 'if e := a.Exec; e != nil && false {', 'TestConsoleExecCardShowsTemplateModeAndParameterNames', A),
    ('console-csp', A + '/console.go', 'h.Set("Content-Security-Policy", consoleCSP)', '_ = consoleCSP', 'TestConsoleCardShowsRequestWithStrictHeadersAndNoScripts', A),
    ('console-httponly', A + '/console.go', 'Path: consolePath, HttpOnly: true, Secure: c.secure,\n\t\tSameSite: http.SameSiteStrictMode, MaxAge: int(', 'Path: consolePath, Secure: c.secure,\n\t\tSameSite: http.SameSiteStrictMode, MaxAge: int(', 'TestConsoleLoginCookieFlagsAndBadToken', A),
    ('console-reject-reason', A + '/console.go', '(decision == "reject" && reason == "")', 'false', 'TestConsoleDecisionPassesWhatWasShown', A),
    ('console-network-warning', A + '/console.go', 'v.NetWarning = networkWarning', 'v.NetWarning = ""', 'TestConsoleNetworkTemplateShowsDestinationsAndPinningWarning', A),
    ('console-no-session-check', A + '/console.go', '\tif !ok {\n\t\thttp.Redirect(w, r, "/console/login", http.StatusSeeOther)', '\tif !ok && false {\n\t\thttp.Redirect(w, r, "/console/login", http.StatusSeeOther)', 'TestConsoleNeedsSession', A),
    ('notify-once', A + '/deployments.go', 'out.ApprovalID == uuid.Nil || !out.Created', 'out.ApprovalID == uuid.Nil', 'TestDeployments_ReplayAndNotifierFailureDoNotChangeTheAnswer', A),
    ('notify-control-chars', N + '/telegram.go', 'unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) && r != \' \'', 'false && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) && r != \' \')', 'TestHostileNameCannotBreakTheMessage', N),
    ('notify-link-chars', N + '/telegram.go', "if r == '.' || r == '/' || r == ':' || r == '@' {", 'if false {', 'TestHostileNameCannotBreakTheMessage', N),
    ('notify-error-detail', N + '/telegram.go', 'resp, err := t.client.Do(req)\n\tif err != nil {\n\t\treturn ErrSend', 'resp, err := t.client.Do(req)\n\tif err != nil {\n\t\treturn err', 'TestFailureNeverReturnsTheTokenOrURL', N),
    ('notify-extra-field', N + '/telegram.go', 'TargetKind    string\n}', 'TargetKind    string\n\tReason        string\n}', 'TestNoticeFieldsAreAClosedList', N),
    ('session-expiry', I + '/session.go', '!sessionExpires.After(now) || ', 'false && !sessionExpires.After(now) || ', 'TestSessionExpires', I),
    ('session-token-revoked', I + '/session.go', '|| tokenRevoked != nil ||', '|| false && tokenRevoked != nil ||', 'TestSessionRefusesInvalidTokenAndEndsWithToken', I),
    ('session-token-expiry', I + '/session.go', '(tokenExpireAt != nil && !tokenExpireAt.After(now))', '(false && tokenExpireAt != nil && !tokenExpireAt.After(now))', 'TestSessionDiesWithItsExpiredToken', I),
    ('console-canary-view', A + '/console.go', 'RequestID: a.RequestID, Secret:', 'RequestID: a.RequestID + string(a.Requester.Via), Secret:', 'TestConsoleNeverRendersACanary', A),
    ('decide-rate-limit', D + '/approval.go', '\t\tif limited {\n', '\t\tif limited && false {\n', 'TestDecideApproveKeepsTheRateLimit', D),
    ('decide-provider', D + '/approval.go', ' || secret.provider != runnerproto.ProviderBuiltin {', ' || secret.provider != runnerproto.ProviderBuiltin && false {', 'TestDecideApproveRefusesProviderTheRunnerCannotUse', D),
    ('decide-audit-actor', D + '/approval.go', 'Actor:  audit.Actor{Type: audit.ActorUser, ID: in.ApproverID.String(), Via: audit.ViaConsole}', 'Actor:  audit.Actor{Type: audit.ActorUser, ID: in.OrgID.String(), Via: audit.ViaConsole}', 'TestDecideApproveCreatesExactlyTheShownJob', D),
    ('console-token-scope', A + '/console.go', 'if p.Scope != "" && p.Scope != scope.String()', 'if false && p.Scope != scope.String()', 'TestConsoleNarrowTokenDoesNotReachOtherScope', A),
    ('session-principal', I + '/session.go', 'p, err := r.livePrincipal(ctx, Kind(kind), org, principal, scope)', 'p, err := Principal{Kind: Kind(kind), ID: principal, OrgID: org, Scope: scope}, error(nil)', 'TestSessionDiesWithItsPrincipal', I),
    ('requested-journal-hash', D + '/repo.go', 'base.Policy.RuleID = "approval-binding:" + hex.EncodeToString(requestHash[:])', 'base.Policy.RuleID = hex.EncodeToString(requestHash[:])[:0]', 'TestApprovalShowsWhatWillRun', D),
]
env = os.environ.copy()
bad = 0
apply_only = os.environ.get('MUTATION_APPLY_ONLY') == '1'
# Baseline first: with the schema missing every mutant is "red" for the wrong
# reason, so mutants run only after the real code is green.
# One go test per package, each with its own budget: on a slow runner with a
# cold cache the four packages together outgrew a single -timeout.
if not apply_only:
    failed = False
    ev = []
    for pkg in ('./' + D, './' + A, './' + N, './internal/identity'):
        try:
            base = subprocess.run(['go', 'test', '-json', '-count=1', '-p', '1', '-timeout=300s', pkg],
                                  cwd=work / 'tree', env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=420)
            out, code = base.stdout, base.returncode
        except subprocess.TimeoutExpired as exc:
            out, code = exc.stdout or b'', None
            ev.append({'Action': 'timeout', 'Package': 'github.com/entire-vc/evc-keep/' + pkg[2:], 'Elapsed': 420})
        failed = failed or code != 0
        for line in out.splitlines():
            try:
                ev.append(json.loads(line))
            except ValueError:
                pass
    if failed or any(e.get('Action') == 'skip' for e in ev):
        print('FAIL baseline: red or skipped on the real code')
        sys.path.insert(0, str(root / 'scripts'))
        from approvals_baseline_diagnostics import report
        report(ev, root)
        print('FAIL: baseline is not green; mutant results would prove nothing, stopping before them')
        sys.exit(1)
    print('ok   baseline: green, nothing skipped')
for name, rel, before, after, test, pkg in mutations:
    src = (root / rel).read_text()
    if src.count(before) != 1:
        print('FAIL ' + name + ': mutation target is not unique or moved', flush=True)
        bad += 1
        continue
    target = work / 'tree' / rel
    target.write_text(src.replace(before, after, 1))
    try:
        if apply_only:
            print('ok   ' + name + ': applies', flush=True)
            continue
        run = subprocess.run(['go', 'test', '-json', '-count=1', '-p', '1', '-timeout=180s', '-run=^' + test + '$', './' + pkg],
                             cwd=work / 'tree', env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    finally:
        target.write_text(src)
    events = []
    for line in run.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    designated = any(e.get('Test') == test and e.get('Action') == 'fail' for e in events)
    skipped = any(e.get('Action') == 'skip' for e in events)
    built = any(e.get('Action') == 'build-fail' or '[build failed]' in str(e.get('Output', '')) or '[setup failed]' in str(e.get('Output', '')) for e in events)
    if run.returncode == 0 or not designated or skipped or built:
        print('FAIL ' + name + ': ' + test + ' did not reject the mutant', flush=True)
        bad += 1
    else:
        print('ok   ' + name + ': ' + test + ' red', flush=True)
sys.exit(1 if bad else 0)
PY
