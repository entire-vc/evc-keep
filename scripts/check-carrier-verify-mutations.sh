#!/bin/sh
# Prove the carrier verification guards with named behavioral failures, never
# compiler errors: each mutant must turn its designated test red.
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
mutations = [
    ('verify-match-needs-key', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyMatchWithoutTheKeyIsRefusedButARefusalIsNot', "OR material_issued_at IS NOT NULL) FOR UPDATE", "OR material_issued_at IS NOT NULL OR action='verify') FOR UPDATE"),
    ('verify-mismatch-only-for-verify', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyMismatchMayNameObservedFingerprintOnlyForVerify', 'job.Action == runnerproto.ActionVerify && !result.OK', '!result.OK'),
    ('verify-audit-action', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyJobNeedsNoValueAndReportsAfterTheKey', 'action = audit.ActionCarrierVerify', 'action = audit.ActionDeployResult'),
    ('verify-result-applied', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyJobNeedsNoValueAndReportsAfterTheKey', 'deployment.ApplyVerifyResultTx(ctx, tx, p.OrgID, snap.Job, result)', 'func() (deployment.VerifyState, bool, error) { return "", false, nil }()'),
    ('verify-current-catalog-only', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyResultIgnoredForSupersededCatalogVersion', 'LIMIT 1)=$3`', 'LIMIT 1) IS NOT NULL`'),
    ('verify-observed-key-binding', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyAnswerOfAnotherKeyIsNotStored', 'expected.KeyID == got.KeyID', '(expected.KeyID == got.KeyID || true)'),
    ('verify-runner-live', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyRunnerMustBeLiveAndOnTheCarrierHost', 'AND revoked_at IS NULL AND cert_not_after>clock_timestamp()', ''),
    ('verify-runner-host', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyRunnerMustBeLiveAndOnTheCarrierHost', 'AND host=$2 AND revoked_at', 'AND ($2::text IS NOT NULL) AND revoked_at'),
    ('verify-request-binding', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifySubmitIsIdempotentAndBound', 'if !equalHash(stored, hash[:]) {', 'if !equalHash(stored, hash[:]) && false {'),
    ('verify-hourly-cap', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyLimits', 'recent >= MaxVerifiesPerHour', 'recent >= MaxVerifiesPerHour*1000'),
    ('verify-carrier-cap', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyLimits', 'len(out) > MaxVerifyCarriers', 'len(out) > MaxVerifyCarriers*1000'),
    ('verify-structure-guard', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyCarrierWithBrokenTargetIsFailedNotDispatched', 'c.target.Validate() != nil || networkTarget(c.target)', 'false'),
    ('verify-expiry-derived', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyPendingPastDeadlineReadsAsUnreachable', 'AND j.expires_at<clock_timestamp() THEN', 'AND false THEN'),
    ('verify-org-isolation', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyIsolatedByOrganization', 'WHERE org_id=$1 AND request_id=$2`, org, requestID)', 'WHERE request_id=$2 AND $1::uuid IS NOT NULL`, org, requestID)'),
    ('deploy-allowance-excludes-verify', 'internal/deployment/repo.go', 'internal/deployment', 'TestVerifyLimits', "AND action<>'verify' AND created_at", 'AND created_at'),
    ('no-consumer-in-verify-target', 'internal/deployment/verify.go', 'test/security', 'TestW5_CarrierVerify_NoValueOnAnySurface', 'Mode: 0o600}', 'Mode: 0o600, Consumer: "systemd:" + path}'),
    ('leak-carrier-metadata-in-answer', 'internal/deployment/verify.go', 'test/security', 'TestW5_CarrierVerify_NoValueOnAnySurface', 'SELECT i.carrier_id,i.runner_id,c.host,', 'SELECT i.carrier_id,i.runner_id,c.consumer,'),
    ('api-metadata-permission', 'internal/api/carriers_verify.go', 'internal/api', 'TestCarrierVerify_RequiresAuthenticationAndMetadataRead', 'return perms[identity.PermReadMetadata] && (p.Scope == "" || p.Scope == scope.String()), nil', 'return perms[identity.PermReadMetadata] || true, nil'),
    ('api-ok-only-on-match', 'internal/api/carriers_verify.go', 'internal/api', 'TestCarrierVerify_PendingThenDone', 'if it.State != deployment.VerifyMatch {', 'if it.State == deployment.VerifyFailed {'),
    ('api-pending-is-202', 'internal/api/carriers_verify.go', 'internal/api', 'TestCarrierVerify_PendingThenDone', 'if !rep.Done() {', 'if false {'),
    ('api-closed-fields', 'internal/api/carriers_verify.go', 'internal/api', 'TestResponseFieldsAreClosed', 'ErrorClass       string        `json:"error_class,omitempty"`', 'ErrorClass       string        `json:"error_class,omitempty"`\n\tPath             string        `json:"path"`'),
    ('api-error-class-closed-set', 'internal/api/carriers_verify.go', 'internal/api', 'TestCarrierVerify_ErrorClassIsClosed', 'if class != "" && !class.Valid() {', 'if false {'),
    ('api-carrier-row-extra-field', 'internal/api/carriers_verify.go', 'internal/api', 'TestResponseFieldsAreClosed', 'ErrorClass       string        `json:"error_class,omitempty"`', 'ErrorClass       string        `json:"error_class,omitempty"`\n\tMessage          string        `json:"message,omitempty"`'),
    ('guard-carriers-on-other-object', 'internal/api/closed_fields_test.go', 'internal/api', 'TestVerifyResultExceptionsAreBound', 'allowed: deployHealthFields}', 'allowed: fieldSet("status", "checked_at", "carriers")}'),
    ('guard-error-class-in-standalone-carrier', 'internal/api/closed_fields_test.go', 'internal/api', 'TestVerifyResultExceptionsAreBound', 'name:    verifyRowSchema,', 'name:    "CarrierRead",'),
    ('guard-standalone-carrier-fields', 'internal/api/closed_fields_test.go', 'internal/api', 'TestVerifyResultExceptionsAreBound', 'carrierFields       = fieldSet("id", "host", "runner_id", "target", "status", "last_verified_at", "fingerprint_match")', 'carrierFields       = fieldSet("id", "host", "runner_id", "target", "status", "last_verified_at", "fingerprint_match", "error_class")'),
    ('runnerproto-class-valid', 'pkg/runnerproto/result.go', 'pkg/runnerproto', 'TestErrorClassValid', 'func (c ErrorClass) Valid() bool { return errorClasses[c] }', 'func (c ErrorClass) Valid() bool { return true }'),
    ('api-error-class-closed-set-no-db', 'internal/api/carriers_verify.go', 'internal/api', 'TestCarrierVerifyWrite_ClassNeverCarriesText', 'if class != "" && !class.Valid() {', 'if false {'),
    ('guard-carrier-row-by-overlap', 'internal/api/closed_fields_test.go', 'internal/api', 'TestVerifyResultExceptions_RedRun', 'return n >= 3', 'return set["host"]'),
    ('guard-nested-sets-checked', 'internal/api/closed_fields_test.go', 'internal/api', 'TestVerifyResultExceptions_RedRun', 'for field, set := range e.nested {', 'for field, set := range map[string]map[string]bool{} {'),
    ('guard-name-bound-to-type', 'internal/api/closed_fields_test.go', 'internal/api', 'TestVerifyResultExceptions_RedRun', 'ok && e.typ != want {', 'ok && e.typ != want && false {'),
    ('migration-down-verify-jobs', 'internal/store/migrations/00022_carrier_verify.sql', 'internal/deployment', 'TestVerifyMigrationDownKeepsDeploymentsAndAuditHistory', "WHERE action = 'verify' RETURNING", 'WHERE false RETURNING'),
    ('migration-down-audit-registry', 'internal/store/migrations/00022_carrier_verify.sql', 'internal/deployment', 'TestVerifyMigrationDownKeepsDeploymentsAndAuditHistory', "'approval.requested','approval.decided')) NOT VALID;", "'approval.requested','approval.decided','carrier.verify')) NOT VALID;"),
    ('migration-down-trigger', 'internal/store/migrations/00022_carrier_verify.sql', 'internal/deployment', 'TestVerifyMigrationDownKeepsDeploymentsAndAuditHistory', 'OLD.job_payload,OLD.nonce,OLD.expires_at,OLD.created_at)\n       IS DISTINCT FROM\n       ROW(NEW.id,', 'OLD.job_payload,OLD.expires_at,OLD.created_at)\n       IS DISTINCT FROM\n       ROW(NEW.id,'),
    ('migration-up-trigger-freezes-action', 'internal/store/migrations/00022_carrier_verify.sql', 'internal/deployment', 'TestVerifyJobActionIsFrozen', 'IF ROW(OLD.action,OLD.id,', 'IF ROW(NEW.action,OLD.id,'),
    ('verify-key-gate', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyJobNeedsNoValueAndReportsAfterTheKey', '(!snap.Job.NeedsValue() && !snap.Job.NeedsFingerprintKey())', '!snap.Job.NeedsValue()'),
    ('verify-key-single-use', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyJobNeedsNoValueAndReportsAfterTheKey', 'AND status=\'issued\' AND material_issued_at IS NULL AND expires_at>clock_timestamp()', 'AND status=\'issued\' AND expires_at>clock_timestamp()'),
    ('verify-key-expiry', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyKeyIsRefusedAfterExpiry', 'AND status=\'issued\' AND material_issued_at IS NULL AND expires_at>clock_timestamp()', 'AND status=\'issued\' AND material_issued_at IS NULL'),
    ('verify-mismatch-class-only', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyMismatchMayNameObservedFingerprintOnlyForVerify', '!result.OK && result.ErrorClass == runnerproto.ErrClassFingerprintMismatch {', '!result.OK {'),
    ('verify-mismatch-not-expected', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyMismatchMayNameObservedFingerprintOnlyForVerify', 'return result.Fingerprint != job.ExpectedFingerprint && (', 'return ('),
    ('verify-journal-no-observed', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyMismatchMayNameObservedFingerprintOnlyForVerify', 'auditFingerprint = ""', '_ = auditFingerprint'),
    ('verify-delivery-trust', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyRunnerWithoutDeliveryTrustIsUnreachableAtOnce', 'terr != nil {', 'false && terr != nil {'),
    ('verify-row-hidden-from-deployments', 'internal/deployment/report.go', 'internal/deployment', 'TestVerifyRequestRowIsNotADeploymentReport', "\n\t AND NOT EXISTS (SELECT 1 FROM deployment_jobs j WHERE j.org_id=r.org_id AND j.deployment_request_id=r.id AND j.action='verify')", ''),
    ('verify-match-needs-current', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyMatchOnSupersededVersionDoesNotRegister', 'WHERE c.org_id=$1 AND c.id=$2`+current,\n\t\t\torg, carrierID, job.ExpectedFingerprint, job.ExpectedVersion)', 'WHERE c.org_id=$1 AND c.id=$2`,\n\t\t\torg, carrierID, job.ExpectedFingerprint, job.ExpectedVersion)'),
    ('verify-latest-enabled-version', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyExpectsLatestEnabledVersion', 'AND NOT disabled ORDER BY seal_seq DESC LIMIT 1`, in.OrgID, in.SecretID).Scan(&versionID)', 'ORDER BY seal_seq DESC LIMIT 1`, in.OrgID, in.SecretID).Scan(&versionID)'),
    ('verify-network-target', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyNetworkLookingTargetIsFailed', ' || networkTarget(c.target)', ''),
    ('verify-fixed-target-owner', 'internal/deployment/verify.go', 'internal/dispatch', 'TestVerifyJobNeedsNoValueAndReportsAfterTheKey', 'Mode: 0o600}', 'Mode: 0o600, UID: 1001}'),
    ('api-error-template', 'internal/api/carriers_verify.go', 'internal/api', 'TestCarrierVerify_Refusals', 'writeError(w, http.StatusNotFound, apperr.ClassNotFound, verifyMessage("unavailable"), rid)\n\tcase errors.Is(err, deployment.ErrConflict)', 'writeError(w, http.StatusNotFound, apperr.ClassNotFound, err.Error(), rid)\n\tcase errors.Is(err, deployment.ErrConflict)'),
    ('api-no-store', 'internal/api/carriers_verify.go', 'internal/api', 'TestCarrierVerify_NoStoreAndBodyCap', 'func (c *carrierVerifyRoutes) submit(w http.ResponseWriter, r *http.Request) {\n\tdeployHeaders(w)\n', 'func (c *carrierVerifyRoutes) submit(w http.ResponseWriter, r *http.Request) {\n'),
    ('api-body-cap', 'internal/api/carriers_verify.go', 'internal/api', 'TestCarrierVerify_NoStoreAndBodyCap', 'decodeInput(w, r, 4096, &body)', 'decodeInput(w, r, 1<<20, &body)'),
    ('org-status-bound-to-secret', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_StatusOfAnotherSecretIsNotFound', '(rep.SecretID != id || rep.Scope != scope)', '(rep.SecretID != id && id == uuid.Nil || rep.Scope != scope)'),
    ('org-body-closed', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_RefusesAnythingButTheRequestID', 'decodeInput(w, r, 512, &body) != nil || ', ''),
    ('org-permission-checked', 'internal/api/carriers.go', 'internal/api', 'TestOrgCarrierVerify_ForeignUnauthorizedAndUnknownAnswerLikeMissing', 'if !perms[perm] || (p.Scope', 'if !(perms[perm] || true) || (p.Scope'),
    ('org-token-scope-pinned', 'internal/api/carriers.go', 'internal/api', 'TestOrgCarrierVerify_ForeignUnauthorizedAndUnknownAnswerLikeMissing', '(p.Scope != "" && p.Scope != found.Scope.String())', 'false'),
    ('org-no-store', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_AcceptsThenReportsOnTheSecretOfThePath', 'func (c *carrierVerifyRoutes) submitOrg(w http.ResponseWriter, r *http.Request) {\n\tdeployHeaders(w)\n', 'func (c *carrierVerifyRoutes) submitOrg(w http.ResponseWriter, r *http.Request) {\n'),
    ('org-secret-from-path', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_AcceptsThenReportsOnTheSecretOfThePath', 'Scope: scope, SecretID: id,', 'Scope: scope, SecretID: func() uuid.UUID { _ = id; return uuid.New() }(),'),
    ('org-scope-from-secret', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_AcceptsThenReportsOnTheSecretOfThePath', 'Scope: scope, SecretID: id,', 'Scope: func() tenancy.Scope { _ = scope; return tenancy.Scope{} }(), SecretID: id,'),
    ('org-status-bound-to-scope', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_StatusOfAnotherScopeIsNotFound', '(rep.SecretID != id || rep.Scope != scope)', '(rep.SecretID != id || scope == tenancy.Scope{})'),
    ('org-request-id-passed', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_ViewerMaySubmitAndTheServiceGetsKeyAndActor', 'Scope: scope, SecretID: id, RequestID: requestID,', 'Scope: scope, SecretID: id, RequestID: rid,'),
    ('org-actor-passed', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_ViewerMaySubmitAndTheServiceGetsKeyAndActor', 'actor := audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI}\n\tif p.SponsorUserID != nil {\n\t\tactor.SponsorID = p.SponsorUserID.String()\n\t}\n\trep, err := c.svc.SubmitVerify(r.Context(), deployment.VerifyRequest{OrgID: p.OrgID, Scope: scope', 'actor := audit.Actor{}\n\trep, err := c.svc.SubmitVerify(r.Context(), deployment.VerifyRequest{OrgID: p.OrgID, Scope: scope'),
    ('org-read-right-too-strict', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_ViewerMaySubmitAndTheServiceGetsKeyAndActor', 'id, scope, p, ok := secretByID(w, r, c.sec, identity.PermReadMetadata)', 'id, scope, p, ok := secretByID(w, r, c.sec, identity.PermDeploy)'),
    ('org-body-cap', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_BodyIsCapped', 'decodeInput(w, r, 512, &body)', 'decodeInput(w, r, 1<<20, &body)'),
    ('org-service-required', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_WithoutAServiceAnswersNotReady', 'if c.svc == nil {', 'if c.svc == nil && false {'),
    ('org-class-closed-canary', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_NoCanaryInAnswerHeadersOrLog', 'if class != "" && !class.Valid() {', 'if false {'),
    ('org-error-quotes-service', 'internal/api/carriers_verify.go', 'internal/api', 'TestOrgCarrierVerify_ServiceRefusalsAreClosedAndQuoteNothing', 'writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, verifyMessage("unavailable"), rid)\n\t}\n\treturn true', 'writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, err.Error(), rid)\n\t}\n\treturn true'),
    ('migration-verify-pair-check', 'internal/store/migrations/00022_carrier_verify.sql', 'internal/deployment', 'TestVerifyTablesRejectInvalidRows', '    CHECK ((job_id IS NULL) = (runner_id IS NULL))\n', '    CHECK (true)\n'),
    ('migration-verify-unique-request', 'internal/store/migrations/00022_carrier_verify.sql', 'internal/deployment', 'TestVerifyTablesRejectInvalidRows', '    UNIQUE (org_id,request_id),\n', '    UNIQUE (org_id,id,request_id),\n'),
    ('migration-verify-state-check', 'internal/store/migrations/00022_carrier_verify.sql', 'internal/deployment', 'TestVerifyTablesRejectInvalidRows', "CHECK ((state = 'pending') = (completed_at IS NULL))", 'CHECK (true)'),
    ('migration-verify-fingerprint-shape', 'internal/store/migrations/00022_carrier_verify.sql', 'internal/deployment', 'TestVerifyTablesRejectInvalidRows', "expected_fingerprint TEXT NOT NULL CHECK (expected_fingerprint ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),", 'expected_fingerprint TEXT NOT NULL,'),
]
env = os.environ.copy()
apply_only = os.environ.get('MUTATION_APPLY_ONLY') == '1'
def events(output):
    result=[]
    for line in output.splitlines():
        try: result.append(json.loads(line))
        except ValueError: pass
    return result
for name, filename, directory, test, before, after in mutations:
    source=(root/filename).read_text()
    target=work/'tree'/filename
    if before not in source:
        raise SystemExit('FAIL '+name+': mutation target missing')
    target.write_text(source.replace(before,after))
    try:
        if apply_only:
            print('ok   '+name+': applies',flush=True)
            continue
        run=subprocess.run(['go','test','-json','-count=1','-timeout=120s','-run=^'+test+'$','./'+directory],cwd=work/'tree',env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
        ev=events(run.stdout)
        designated=any(e.get('Test')==test and e.get('Action')=='fail' for e in ev)
        skipped=any(e.get('Action')=='skip' for e in ev)
        build_failed=any(e.get('Action')=='build-fail' or '[build failed]' in str(e.get('Output','')) or '[setup failed]' in str(e.get('Output','')) for e in ev)
        infrastructure_failed = any(any(marker in str(e.get('Output', '')) for marker in (
            'panic: test timed out', 'database operation deadline exceeded',
            'create scratch database failed', 'open admin pool on scratch database failed',
            'connection failed (unclassified)')) for e in ev)
        if run.returncode==0 or not designated or skipped or build_failed or infrastructure_failed:
            raise SystemExit('FAIL '+name+': designated behavioral assertion did not reject mutant')
        print('ok   '+name+': '+test+' red',flush=True)
    finally:
        target.write_text(source)
if apply_only:
    sys.exit(0)
run=subprocess.run(['go','test','-json','-race','-p','1','-count=1','-timeout=300s','-run=^(TestVerify|TestCarrierVerify|TestW5_CarrierVerify|TestResponseFieldsAreClosed|TestErrorClassValid|TestCarrierVerifyWrite|TestOrgCarrierVerify)', './internal/deployment','./internal/dispatch','./internal/api','./pkg/runnerproto','./test/security'],cwd=work/'tree',env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=420)
if run.returncode or any(e.get('Action')=='skip' for e in events(run.stdout)):
    raise SystemExit('FAIL baseline: carrier verify tests failed or skipped')
print('ok   baseline: carrier verify race tests green, no skips',flush=True)
PY
