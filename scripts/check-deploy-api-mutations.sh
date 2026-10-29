#!/bin/sh
# Proves the deploy surface guards can fail (threat model 4.1-4.4): in a
# scratch copy of the tree, switch off one property of POST /v1/deployments,
# GET /v1/deployments/{id} or `keep deploy` at a time and require the named
# test to go red. A build error, a skip or an unrelated failure is not
# evidence. Needs a real PostgreSQL: KEEP_DATABASE_URL.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
mutation_apply_only || : "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must name disposable PostgreSQL}"
mutation_snapshot "$work/tree"
python3 - "$root" "$work" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys

root, work = map(Path, sys.argv[1:])
env = os.environ.copy()
apply_only = os.environ.get('MUTATION_APPLY_ONLY') == '1'


def run_test(package, test, cwd, race=False):
    cmd = ['go', 'test', '-json', '-count=1', '-p', '1', '-timeout=240s', '-run=' + test, './' + package]
    if race:
        cmd.insert(2, '-race')
    run = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=400)
    events = []
    for line in run.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    return run.returncode, events


def diagnose(code, events):
    # Same helper as the other mutation checks: class, test names and
    # file:line only, never message text.
    log = work / 'unmutated.log'
    log.write_text(''.join(str(e.get('Output', '')) for e in events))
    helper = '. "$1/scripts/lib/baseline-diag.sh"; baseline_diagnose "$2" "$3"'
    subprocess.run(['sh', '-c', helper, 'sh', str(root), str(log), str(code)], check=False)


def broken_build(events):
    return any(e.get('Action') == 'build-fail' or '[build failed]' in str(e.get('Output', '')) or '[setup failed]' in str(e.get('Output', '')) for e in events)


# (name, file, before, after, package, designated test)
mutations = [
    ('body-reader-unbounded', 'internal/api/body_limit.go', 'io.ReadAll(http.MaxBytesReader(w, r.Body, limit))', 'io.ReadAll(r.Body)', 'internal/api', 'TestBodyLimit_StreamWithoutContentLengthStopsAtLimit'),
    ('secret-body-unlimited', 'internal/api/secrets.go', 'readBoundedBody(w, r, maxSecretBodyBytes, requestID)', 'readBoundedBody(w, r, 1<<40, requestID)', 'internal/api', 'TestBodyLimit_ExactLimitPassesOneOverIs413'),
    ('token-body-unlimited', 'internal/api/tokens.go', 'readBoundedBody(w, r, maxTokenBodyBytes, requestID)', 'readBoundedBody(w, r, 1<<40, requestID)', 'internal/api', 'TestBodyLimit_ExactLimitPassesOneOverIs413'),
    ('trailing-json-accepted', 'internal/api/body_limit.go', 'if _, err := d.Token(); !errors.Is(err, io.EOF) {', 'if _, err := d.Token(); false && !errors.Is(err, io.EOF) {', 'internal/api', 'TestBodyLimit_MalformedAndMultipleJSONAreInvalid'),
    ('body-413-as-400', 'internal/api/body_limit.go', 'writeError(w, http.StatusRequestEntityTooLarge, apperr.ClassPayloadTooLarge,', 'writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument,', 'internal/api', 'TestBodyLimit_ExactLimitPassesOneOverIs413'),
    ('deploy-right', 'internal/api/deployments.go', 'perms[identity.PermDeploy] && (', '(perms[identity.PermDeploy] || true) && (', 'internal/api', 'TestDeployments_RightsAndShape'),
    ('status-right', 'internal/api/deployments.go', 'err == nil && !ok {', 'err == nil && !ok && false {', 'internal/api', 'TestDeployments_StatusRightsAndReplayPin'),
    ('replay-pin', 'internal/api/deployments.go', 'prior.SecretID == ref.ID {', 'prior.SecretID == uuid.Nil {', 'internal/api', 'TestDeployments_StatusRightsAndReplayPin'),
    ('no-deploy-masks', 'internal/api/deployments.go', 'tenancy.NotFoundError(body.Secret, tenancy.CheckedLevels(tc))', 'catalog.NotFoundByID(ref.ID)', 'internal/api', 'TestDeployments_NoDeployRightAnswersLikeMissing'),
    ('header-key-pin', 'internal/api/deployments.go', 'prior, perr := d.svc.Report(r.Context(), p.OrgID, requestID)', 'prior, perr := d.svc.Report(r.Context(), p.OrgID, body.RequestID)', 'internal/api', 'TestDeployments_HeaderKeyPinsAndRejectKeepsForeignKey'),
    ('reject-foreign-key', 'internal/api/deployments.go', 'case err == nil:\n\t\twriteError(w, http.StatusConflict,', 'case err == nil && false:\n\t\twriteError(w, http.StatusConflict,', 'internal/api', 'TestDeployments_HeaderKeyPinsAndRejectKeepsForeignKey'),
    ('closed-kind', 'internal/api/deployments.go', '\treturn "unknown"\n}', '\treturn k\n}', 'internal/api', 'TestDeployments_ClosedKindVersionAndHeaders'),
    ('refusal-audit', 'internal/api/deployments.go', 'if d.aud != nil {\n\t\tif _, err := d.aud.Append(', 'if false {\n\t\tif _, err := d.aud.Append(', 'internal/api', 'TestDeployments_FormatRefusalsAreByteIdentical'),
    ('no-store', 'internal/api/deployments.go', 'w.Header().Set("Cache-Control", "no-store")', '_ = w', 'internal/api', 'TestDeployments_ClosedKindVersionAndHeaders'),
    ('disabled-version', 'internal/api/deployments.go', 'if version == nil && !versions[i].Disabled {', 'if version == nil {', 'internal/api', 'TestDeployments_ClosedKindVersionAndHeaders'),
    ('pending-shape', 'internal/api/deployments.go', 'writeJSON(w, http.StatusAccepted, DeployResult{RequestID: requestID})', 'writeJSON(w, http.StatusOK, DeployResult{RequestID: requestID})', 'internal/api', 'TestDeployments_ResultShapes'),
    ('cli-strict-decode', 'cmd/keep/deploy.go', 'd.DisallowUnknownFields()', '_ = d', 'cmd/keep', 'TestDeployCLIRefusesAnswerWithExtraField'),
    ('cli-require-runner', 'cmd/keep/deploy.go', '*runner == "" ||', 'false ||', 'cmd/keep', 'TestDeployCLIRequiresItsArguments'),
    ('cli-require-target', 'cmd/keep/deploy.go', '*target == "" ||', 'false ||', 'cmd/keep', 'TestDeployCLIRequiresItsArguments'),
    ('cli-require-uid', 'cmd/keep/deploy.go', '*uid < 0 ||', 'false ||', 'cmd/keep', 'TestDeployCLIRequiresItsArguments'),
    ('cli-require-gid', 'cmd/keep/deploy.go', '*gid < 0 ||', 'false ||', 'cmd/keep', 'TestDeployCLIRequiresItsArguments'),
    ('cli-exit-approval', 'cmd/keep/deploy.go', 'case res.Approval != nil:\n\t\treturn exitDeployApproval', 'case res.Approval != nil:\n\t\treturn 0', 'cmd/keep', 'TestDeployCLIExitCodes'),
    ('health-extra-field-api', 'internal/api/deployments.go', 'Status    string    `json:"status"`', 'Status    string    `json:"status"`\n\tKind      string    `json:"kind"`', 'internal/api', 'TestDeployments_HealthcheckHasOnlyStatusAndCheckedAt'),
    ('health-extra-field-cli', 'cmd/keep/deploy.go', 'Status    string    `json:"status"`', 'Status    string    `json:"status"`\n\tKind      string    `json:"kind"`', 'cmd/keep', 'TestDeployCLIHealthcheckIsExactlyStatusAndCheckedAt'),
    ('rate-limit-class-folded', 'internal/api/deployments.go', 'http.StatusTooManyRequests, apperr.ClassRateLimited,', 'http.StatusTooManyRequests, apperr.ClassPermissionDenied,', 'internal/api', 'TestDeployments_EleventhDeployIsRateLimited'),
    ('reject-storage-error-as-refusal', 'internal/api/deployments.go', 'case !errors.Is(err, deployment.ErrNotFound):', 'case false:', 'internal/api', 'TestDeployments_RejectDistinguishesStorageErrorFromNotFound'),
    ('reject-storage-error-audited', 'internal/api/deployments.go', 'case !errors.Is(err, deployment.ErrNotFound):\n\t\twriteError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)\n\t\treturn', 'case !errors.Is(err, deployment.ErrNotFound):\n\t\twriteError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "deployment service unavailable", rid)', 'internal/api', 'TestDeployments_RejectDistinguishesStorageErrorFromNotFound'),
    ('cli-rate-limited-unknown', 'internal/apperr/apperr.go', 'ClassPermissionDenied, ClassRateLimited,', 'ClassPermissionDenied,', 'cmd/keep', 'TestDeployCLIPrintsRateLimited'),
    ('e2e-fingerprint', 'internal/api/deployments.go', 'Fingerprint: rep.Result.Fingerprint, Version: rep.Result.Version,', 'Fingerprint: rep.Result.Fingerprint, Version: "",', 'cmd/keep-runner', 'TestKeepDeployEndToEnd'),
    ('carrier-rights', 'internal/api/carriers.go', ' || (p.Scope != "" && p.Scope != found.Scope.String())', '', 'internal/api', 'TestCarrierRoutes_TokenOfAnotherScopeAnswersLikeMissing'),
    ('carrier-strict-body', 'internal/api/carriers.go', 'if decodeInput(w, r, 8192, &body) != nil {', 'if decodeInput(w, r, 8192, &body); false {', 'internal/api', 'TestCarrierRoutes_RefusesAnyFieldOutsideTheMetadata'),
    ('carrier-kind-open', 'internal/api/carriers.go', 'if !known || ', 'if false || ', 'internal/api', 'TestCarrierRoutes_RefusesMalformedMetadata'),
    ('carrier-refusal-class-folded', 'internal/api/carriers.go', 'http.StatusForbidden, apperr.ClassMetadataNotApproved,', 'http.StatusForbidden, apperr.ClassPermissionDenied,', 'internal/api', 'TestCarrierRoutes_ServiceRefusalsAreClosedAndQuoteNothing'),
    ('carrier-runner-id-dropped', 'internal/api/carriers.go', 'RunnerID: runner,', 'RunnerID: runner[:0],', 'internal/api', 'TestCarrierRoutes_RegisterAnswersTheClosedRow'),
    ('carrier-refusal-quotes', 'internal/api/carriers.go', 'apperr.ClassInternal, "internal error", rid)', 'apperr.ClassInternal, err.Error(), rid)', 'internal/api', 'TestCarrierRoutes_ServiceRefusalsAreClosedAndQuoteNothing'),
    ('carrier-match-always', 'internal/api/carriers.go', 'FingerprintMatch: current != "" && c.LastFP == current}', 'FingerprintMatch: true}', 'internal/api', 'TestCarrierRoutes_ListShowsClosedRowsAndFingerprintMatch'),
    ('carrier-row-opens', 'internal/api/carriers.go', 'FingerprintMatch bool          `json:"fingerprint_match"`', 'FingerprintMatch bool          `json:"fingerprint_match"`\n\tValue            string        `json:"value"`', 'internal/api', 'TestResponseFieldsAreClosed'),
    ('carrier-unavailable', 'internal/api/carriers.go', 'if ok && c.svc == nil {', 'if false {', 'internal/api', 'TestCarrierRoutes_UnavailableServiceAnswersNotReady'),
    ('carrier-register-right', 'internal/api/carriers.go', 'c.secretFor(w, r, identity.PermDeploy)', 'c.secretFor(w, r, identity.PermReadMetadata)', 'internal/api', 'TestCarrierRoutes_RegisterNeedsTheRightToDeploy'),
    ('carrier-list-org', 'internal/api/carriers.go', 'c.svc.List(r.Context(), p.OrgID, id)', 'c.svc.List(r.Context(), uuid.Nil, id)', 'internal/api', 'TestCarrierRoutes_ListUsesTheCallersOrgAndNoStore'),
    ('carrier-list-no-store', 'internal/api/carriers.go', 'func (c *carrierRoutes) list(w http.ResponseWriter, r *http.Request) {\n\tdeployHeaders(w)', 'func (c *carrierRoutes) list(w http.ResponseWriter, r *http.Request) {', 'internal/api', 'TestCarrierRoutes_ListUsesTheCallersOrgAndNoStore'),
    ('carrier-host-limit', 'internal/api/carriers.go', 'cleanText(b.Host, 253, false)', 'cleanText(b.Host, 5000, false)', 'internal/api', 'TestCarrierRoutes_LimitsOfTheRequest'),
    ('carrier-body-limit', 'internal/api/carriers.go', 'decodeInput(w, r, 8192, &body)', 'decodeInput(w, r, 1<<20, &body)', 'internal/api', 'TestCarrierRoutes_LimitsOfTheRequest'),
    ('carrier-disabled-current', 'internal/api/carriers.go', 'if !v.Disabled {', 'if true {', 'internal/api', 'TestCarrierRoutes_DisabledVersionIsNotCurrent'),
    ('catalog-limit-off', 'internal/api/ratelimit.go', 'if !allowed {', 'if !allowed && false {', 'internal/api', 'TestCatalogLimit_BoundaryAndRefill'),
    ('catalog-limit-no-refill', 'internal/api/ratelimit.go', 'b.tokens = math.Min(l.burst, b.tokens+el*l.rate)', 'b.tokens = b.tokens', 'internal/api', 'TestCatalogLimit_BoundaryAndRefill'),
    ('catalog-limit-retry-after', 'internal/api/ratelimit.go', 'w.Header().Set("Retry-After", strconv.Itoa(wait))', 'w.Header().Set("Retry-After", strconv.Itoa(wait*0+1))', 'internal/api', 'TestCatalogLimit_BoundaryAndRefill'),
    ('catalog-limit-shared-budget', 'internal/api/ratelimit.go', 'kind: p.Kind, id: p.ID}', 'kind: p.Kind}', 'internal/api', 'TestCatalogLimit_IsPerPrincipalAndTenant'),
    ('catalog-limit-burst-uncapped', 'internal/api/ratelimit.go', 'b.tokens = math.Min(l.burst, b.tokens+el*l.rate)', 'b.tokens = b.tokens + el*l.rate', 'internal/api', 'TestCatalogLimit_Defaults'),
    ('catalog-limit-default-burst', 'internal/api/ratelimit.go', 'defaultCatalogBurst     = 20', 'defaultCatalogBurst     = 21', 'internal/api', 'TestCatalogLimit_Defaults'),
    ('catalog-limit-default-rate', 'internal/api/ratelimit.go', 'defaultCatalogPerMinute = 60', 'defaultCatalogPerMinute = 30', 'internal/api', 'TestCatalogLimit_Defaults'),
    ('catalog-limit-one-route', 'internal/api/router.go', 'strings.HasPrefix(pattern, "/orgs/{org_id}/secrets") ||', 'pattern == "/orgs/{org_id}/secrets/{secret_id}" ||', 'internal/api', 'TestCatalogLimit_CoversEveryCatalogRouteAndRefusal'),
    ('catalog-limit-no-deployments', 'internal/api/router.go', 'strings.HasPrefix(pattern, "/v1/deployments") ||', 'false ||', 'internal/api', 'TestCatalogLimit_CoversEveryCatalogRouteAndRefusal'),
    ('catalog-limit-no-input-links', 'internal/api/router.go', 'strings.HasPrefix(pattern, "/v1/input-links")\n', 'false\n', 'internal/api', 'TestCatalogLimit_CoversEveryCatalogRouteAndRefusal'),
    ('catalog-limit-refusal-unlogged', 'internal/api/ratelimit.go', 'logger.Info("http_request",', 'logger.Debug("dropped",', 'internal/api', 'TestCatalogLimit_RefusalIsLogged'),
    ('catalog-limit-fails-open', 'internal/api/ratelimit.go', 'writeError(w, http.StatusUnauthorized, apperr.ClassUnauthenticated, "authentication required", requestID)\n\t\t\t\treturn', 'next.ServeHTTP(w, r)\n\t\t\t\treturn', 'internal/api', 'TestLimitMiddlewareFailsClosed'),
    ('catalog-limit-no-hard-cap', 'internal/api/ratelimit.go', '\t\t\t\tl.evictOldest()', '\t\t\t\t_ = l.evictOldest', 'internal/api', 'TestLimiterHardCap'),
    ('catalog-limit-inside-org-match', 'internal/api/router.go', '\t\t\t\thandler = identity.RequireOrgMatch("org_id")(handler)\n\t\t\t}\n\t\t\t// Inside authentication, outside the tenant check: a probe of a\n\t\t\t// foreign tenant or a missing id spends the budget too.\n\t\t\tif limitedRoute(e.Pattern) {\n\t\t\t\thandler = limitMiddleware(catalogLimiter, logger, e.Pattern)(handler)\n\t\t\t}\n', '\t\t\t}\n\t\t\tif limitedRoute(e.Pattern) {\n\t\t\t\thandler = limitMiddleware(catalogLimiter, logger, e.Pattern)(handler)\n\t\t\t}\n\t\t\tif strings.Contains(e.Pattern, "{org_id}") {\n\t\t\t\thandler = identity.RequireOrgMatch("org_id")(handler)\n\t\t\t}\n', 'internal/api', 'TestCatalogLimit_CoversEveryCatalogRouteAndRefusal'),
    ('catalog-limit-no-eviction', 'internal/api/ratelimit.go', '>= l.burst {', '>= l.burst*1e9 {', 'internal/api', 'TestLimiterDropsIdleBuckets'),
    ('catalog-limit-noop-middleware', 'internal/api/router.go', 'handler = limitMiddleware(catalogLimiter, logger, e.Pattern)(handler)', '_ = catalogLimiter', 'internal/api', 'TestCatalogLimit_BoundaryAndRefill'),
    ('catalog-limit-e2e-noop', 'internal/api/router.go', 'handler = limitMiddleware(catalogLimiter, logger, e.Pattern)(handler)', '_ = catalogLimiter', 'test/security', 'TestCatalogEnumerationLimit'),
    ('catalog-limit-env-unwired', 'cmd/keep-server/app/main.go', 'Catalog:     api.CatalogLimit{PerMinute: cfg.CatalogRatePerMinute, Burst: cfg.CatalogBurst},', '', 'test/security', 'TestCatalogProcessAudit'),
    ('catalog-limit-env-zero', 'internal/config/config.go', 'err != nil || n < 1 {', 'err != nil || n < 0 {', 'internal/config', 'TestCatalogLimitFromEnv'),
    ('catalog-limit-env-rate-unwired', 'cmd/keep-server/app/main.go', 'api.CatalogLimit{PerMinute: cfg.CatalogRatePerMinute, Burst: cfg.CatalogBurst}', 'api.CatalogLimit{Burst: cfg.CatalogBurst}', 'test/security', 'TestCatalogLimitEnvWiring'),
    ('catalog-limit-env-burst-unwired', 'cmd/keep-server/app/main.go', 'api.CatalogLimit{PerMinute: cfg.CatalogRatePerMinute, Burst: cfg.CatalogBurst}', 'api.CatalogLimit{PerMinute: cfg.CatalogRatePerMinute}', 'test/security', 'TestCatalogLimitEnvWiring'),
    ('catalog-limit-evicts-newest', 'internal/api/ratelimit.go', 'b.last.Before(at)', 'b.last.After(at)', 'internal/api', 'TestLimiterHardCapEvictsTheOldestBucket'),
    ('catalog-limit-retry-after-floor', 'internal/api/ratelimit.go', 'math.Ceil((1 - b.tokens) / l.rate)', 'math.Floor((1 - b.tokens) / l.rate)', 'internal/api', 'TestLimiterRetryAfterRoundsUp'),
    ('rotate-right-off', 'internal/api/rotate.go', '!perms[identity.PermRotate] ||', '!(perms[identity.PermRotate] || true) ||', 'internal/api', 'TestRotate_RefusalsAndRights'),
    ('rotate-token-scope-off', 'internal/api/rotate.go', '(p.Scope != "" && p.Scope != found.Scope.String())', 'false', 'internal/api', 'TestRotate_RefusalsAndRights'),
    ('rotate-revoke-pending-unmapped', 'internal/api/rotate.go', 'writeAppError(w, rotationAppError(err), rid)', 'writeAppError(w, err, rid)', 'internal/api', 'TestRotate_RevokePendingIs409OverHTTP'),
    ('rotate-body-takes-a-value', 'internal/api/rotate.go', 'Mode string `json:"mode"`\n\t}', 'Mode  string `json:"mode"`\n\t\tValue string `json:"value"`\n\t}', 'internal/api', 'TestRotate_BodyIsModeOnlyAndNeverEchoed'),
    ('rotate-mode-open', 'internal/api/rotate.go', '(body.Mode != rotateGenerate && body.Mode != rotateHumanInput)', 'false', 'internal/api', 'TestRotate_BodyIsModeOnlyAndNeverEchoed'),
    ('rotate-start-no-store', 'internal/api/rotate.go', 'func (ro *rotateRoutes) start(w http.ResponseWriter, r *http.Request) {\n\tdeployHeaders(w)', 'func (ro *rotateRoutes) start(w http.ResponseWriter, r *http.Request) {', 'internal/api', 'TestRotate_StartAnswers202WithOnlyTheRequestID'),
    ('rotate-start-reports-version', 'internal/api/rotate.go', 'writeJSON(w, http.StatusAccepted, RotateResult{RequestID: started.RunID.String(), Approval: ro.approval(started.Approval)})', 'writeJSON(w, http.StatusAccepted, RotateResult{RequestID: started.RunID.String(), Approval: ro.approval(started.Approval), Version: "2"})', 'internal/api', 'TestRotate_StartAnswers202WithOnlyTheRequestID'),
    ('rotate-version-before-done', 'internal/api/rotate.go', '\tif rep.Done {\n\t\tout.Version, out.Fingerprint = rep.Version, rep.Fingerprint\n\t}', '\tout.Version, out.Fingerprint = rep.Version, rep.Fingerprint', 'internal/api', 'TestRotate_StatusNeverReportsAVersionBeforeDone'),
    ('rotate-class-passthrough', 'internal/api/rotate.go', '\t\t\treturn string(c)\n\t\t}\n\t}\n\treturn string(apperr.ClassInternal)', '\t\t\treturn string(c)\n\t\t}\n\t}\n\treturn string(c)', 'internal/api', 'TestRotate_StatusShapes'),
    ('rotate-conflict-as-503', 'internal/api/rotate.go', 'case errors.Is(err, rotation.ErrConflict):', 'case errors.Is(err, rotation.ErrConflict) && false:', 'internal/api', 'TestRotate_ConflictAndUnavailable'),
    ('rotate-status-foreign-secret', 'internal/api/rotate.go', 'rep, err := ro.svc.Report(r.Context(), ref, run)', 'rep, err := ro.svc.Report(r.Context(), rotation.Ref{OrgID: ref.OrgID}, run)', 'internal/api', 'TestRotate_StartAnswers202WithOnlyTheRequestID'),
    ('rotate-human-input-link-no-store', 'internal/api/rotate.go', '\tinputHeaders(w)\n\twriteJSON(w, http.StatusAccepted, link)', '\twriteJSON(w, http.StatusAccepted, link)', 'internal/api', 'TestRotate_HumanInputIssuesTheLink'),
    ('rotate-result-type-opens', 'internal/api/rotate.go', 'ErrorClass  string          `json:"error_class,omitempty"`', 'ErrorClass  string          `json:"error_class,omitempty"`\n\tValue       string          `json:"value,omitempty"`', 'internal/api', 'TestResponseFieldsAreClosed'),
    ('rotate-carrier-type-opens', 'internal/api/rotate.go', 'State     string `json:"state"`', 'State     string `json:"state"`\n\tValue     string `json:"value,omitempty"`', 'internal/api', 'TestResponseFieldsAreClosed'),
    ('rotate-failed-carrier-activates', 'internal/rotation/service.go', 'if runFailed && cs.State != CarrierOK {', 'if false {', 'internal/api', 'TestRotate_OneFailedCarrierActivatesNothing'),
    ('rotate-refusal-echoes-mode', 'internal/api/rotate.go', 'rotateMessage("request invalid"), rid)', 'rotateMessage("request invalid "+body.Mode), rid)', 'internal/api', 'TestRotate_BodyIsModeOnlyAndNeverEchoed'),
    ('rotate-done-answers-202', 'internal/api/rotate.go', '\t\tcode = http.StatusOK', '\t\tcode = http.StatusAccepted', 'internal/api', 'TestRotate_StatusShapes'),
]
failed = False
for name, rel, before, after, package, test in mutations:
    path = work / 'tree' / rel
    original = (root / rel).read_text()
    if original.count(before) != 1:
        print('FAIL ' + name + ': mutation target is not unique - the source changed, update this script')
        failed = True
        continue
    path.write_text(original.replace(before, after, 1))
    try:
        if apply_only:
            print('ok   ' + name + ': applies', flush=True)
            continue
        # Without the mutation the same test must be green, with no skip.
        code, events = run_test(package, '^' + test + '$', root)
        if code != 0 or any(e.get('Action') == 'skip' for e in events):
            print('FAIL ' + name + ': designated test is not green without the mutation', flush=True)
            diagnose(code, events)
            failed = True
            continue
        code, events = run_test(package, '^' + test + '$', work / 'tree')
        pkg = 'github.com/entire-vc/evc-keep/' + package
        designated = any(e.get('Package') == pkg and e.get('Test') == test and e.get('Action') == 'fail' for e in events)
        if code == 0 or not designated or broken_build(events) or any(e.get('Action') == 'skip' for e in events):
            print('FAIL ' + name + ': ' + test + ' did not reject the mutant')
            failed = True
        else:
            print('ok   ' + name + ': ' + test + ' red', flush=True)
    finally:
        path.write_text(original)
sys.exit(1 if failed else 0)
PY
