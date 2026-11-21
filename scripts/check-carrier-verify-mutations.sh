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
import sys
sys.path.insert(0, str(root / 'scripts/lib'))
from mutation_edit import named_edit as mutation_edit
# Every migration that adds an audit action redefines the closed registry
# (audit_records_action_closed), and the tests run on the latest definition: a
# mutant on an older one changes nothing. Edit the latest one; its first
# occurrence is the goose Up section.
audit_registry = sorted(
    p for p in (root / 'internal/store/migrations').glob('*.sql')
    if 'ADD CONSTRAINT audit_records_action_closed' in p.read_text()
)[-1].relative_to(root).as_posix()
mutations = [
    ('verify-match-needs-key', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyMatchWithoutTheKeyIsRefusedButARefusalIsNot', "OR material_issued_at IS NOT NULL) FOR UPDATE", "OR material_issued_at IS NOT NULL OR action='verify') FOR UPDATE"),
    ('verify-mismatch-only-for-verify', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyMismatchMayNameObservedFingerprintOnlyForVerify', '(job.Action == runnerproto.ActionVerify || job.Action == runnerproto.ActionAdopt) && !result.OK', '!result.OK'),
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
    ('verify-journal-no-observed', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestVerifyMismatchMayNameObservedFingerprintOnlyForVerify', 'action = audit.ActionCarrierVerify\n\t\tif !result.OK {\n\t\t\tauditFingerprint = ""', 'action = audit.ActionCarrierVerify\n\t\tif !result.OK {\n\t\t\t_ = auditFingerprint'),
    ('verify-delivery-trust', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyRunnerWithoutDeliveryTrustIsUnreachableAtOnce', 'terr != nil {', 'false && terr != nil {'),
    ('verify-row-hidden-from-deployments', 'internal/deployment/report.go', 'internal/deployment', 'TestVerifyRequestRowIsNotADeploymentReport', "\n\t AND NOT EXISTS (SELECT 1 FROM deployment_jobs j WHERE j.org_id=r.org_id AND j.deployment_request_id=r.id AND j.action='verify')", ''),
    ('verify-match-needs-current', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyMatchOnSupersededVersionDoesNotRegister', 'WHERE c.org_id=$1 AND c.id=$2`+current,\n\t\t\torg, carrierID, job.ExpectedFingerprint, job.ExpectedVersion)', 'WHERE c.org_id=$1 AND c.id=$2`,\n\t\t\torg, carrierID, job.ExpectedFingerprint, job.ExpectedVersion)'),
    ('verify-latest-enabled-version', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyExpectsLatestEnabledVersion', 'AND NOT disabled AND ($3=\'\' OR provider_version=$3) ORDER BY seal_seq DESC LIMIT 1`', 'AND ($3=\'\' OR provider_version=$3) ORDER BY seal_seq DESC LIMIT 1`'),
    ('verify-pin-version', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyPinnedVersionIsTheOneExpected', "AND ($3='' OR provider_version=$3) ORDER BY", "AND ($3='' OR true) ORDER BY"),
    ('verify-pin-bound-to-request', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyPinnedVersionIsTheOneExpected', 'hashed = append(hashed, in.ProviderVersion)', 'hashed = append(hashed)'),
    ('rollback-headroom-lost', 'internal/deployment/repo.go', 'internal/deployment', 'TestSubmitRollbackHasHeadroomAboveTheLimitButNotWithout', 'return 2 * limit', 'return limit'),
    ('rollback-headroom-unbounded', 'internal/deployment/repo.go', 'internal/deployment', 'TestSubmitRollbackHasHeadroomAboveTheLimitButNotWithout', 'return 2 * limit', 'return 1000000'),
    ('rollback-flag-ignored', 'internal/deployment/repo.go', 'internal/deployment', 'TestSubmitRollbackHasHeadroomAboveTheLimitButNotWithout', 'rollbackAllowance(limit, in.Rollback)', 'rollbackAllowance(limit, false)'),
    ('rollback-flag-never-sent', 'internal/rotation/rotwire/rotwire.go', 'internal/rotation/rotwire', 'TestDeployRequestMarksOnlyTheRollbackLayout', 'Rollback: rotation.IsRollback(ctx)}', 'Rollback: false}'),
    ('rollback-flag-always-sent', 'internal/rotation/rotwire/rotwire.go', 'internal/rotation/rotwire', 'TestDeployRequestMarksOnlyTheRollbackLayout', 'Rollback: rotation.IsRollback(ctx)}', 'Rollback: true}'),
    ('rollback-deploy-own-request-id', 'internal/rotation/rotwire/rotwire.go', 'internal/rotation/rotwire', 'TestRollbackDeployIsARequestOfItsOwn', 'return uuid.NewSHA1(runID, []byte("rollback-deploy/"+carrier)).String()', 'return uuid.NewSHA1(runID, []byte("deploy/"+carrier)).String()'),
    ('rollback-deploy-marker-ignored', 'internal/rotation/rotwire/rotwire.go', 'internal/rotation/rotwire', 'TestRollbackDeployIsARequestOfItsOwn', 'func deployRequestID(ctx context.Context, runID uuid.UUID, carrier string) string {\n\tif rotation.IsRollback(ctx) {', 'func deployRequestID(ctx context.Context, runID uuid.UUID, carrier string) string {\n\tif false {'),
    ('rollback-verify-unpinned', 'internal/rotation/rotwire/rotwire.go', 'internal/rotation/rotwire', 'TestRollbackVerifyIsPinnedToTheVersionPutBack', 'return uuid.NewSHA1(runID, []byte("rollback-verify")).String(), version', 'return uuid.NewSHA1(runID, []byte("rollback-verify")).String(), ""'),
    ('rollback-verify-marker-ignored', 'internal/rotation/rotwire/rotwire.go', 'internal/rotation/rotwire', 'TestRollbackVerifyIsPinnedToTheVersionPutBack', 'func verifyRequestID(ctx context.Context, runID uuid.UUID, version string) (id, pin string) {\n\tif rotation.IsRollback(ctx) {', 'func verifyRequestID(ctx context.Context, runID uuid.UUID, version string) (id, pin string) {\n\tif false {'),
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
    ('credential-observe-refused', 'internal/targets/observe.go', 'internal/targets', 'TestObserveSystemdCredentialMatchesOnlyUnderItsName', 'h, ok := kindHandlers[t.Kind]', 'if t.Kind == runnerproto.TargetSystemdCredential {\n\t\treturn "", false, denied("target kind cannot be verified")\n\t}\n\th, ok := kindHandlers[t.Kind]'),
    ('credential-observe-swallows-policy', 'internal/targets/observe.go', 'internal/targets', 'TestObserveSystemdCredentialUntrustedToolIsPolicy', 'if errors.Is(err, ErrPolicy) {\n\t\t\treturn "", false, err', 'if false {\n\t\t\treturn "", false, err'),
    ('credential-verify-without-unit', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyCredentialCarrierNamesTheUnitOfItsLastDeploy', 'c.target.Unit = last.Unit', '_ = last'),
    ('credential-verify-unnamed-dispatched', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyCredentialCarrierWithoutDeployFailsBeforeAnyJob', 'if c.target.Unit == "" {', 'if false {'),
    ('credential-verify-any-destination', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyCredentialCarrierWithoutDeployFailsBeforeAnyJob', "AND j.status='completed' AND dr.target @> $4::jsonb", "AND j.status='completed'"),
    ('credential-verify-incomplete-deploy', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyCredentialCarrierTakesTheNewestCompletedDeployOnly', "AND j.action='deploy' AND j.status='completed' AND", "AND j.action='deploy' AND"),
    ('credential-verify-oldest-deploy', 'internal/deployment/verify.go', 'internal/deployment', 'TestVerifyCredentialCarrierTakesTheNewestCompletedDeployOnly', 'ORDER BY j.created_at DESC, j.id DESC LIMIT 1`, org, secretID', 'ORDER BY j.created_at ASC, j.id ASC LIMIT 1`, org, secretID'),
    ('discover-key-single-use', 'internal/dispatch/discover.go', 'internal/dispatch', 'TestDiscoverJobIsDeliveredOnceAndKeyIsIssuedOnce', "AND status='issued' AND material_issued_at IS NULL AND expires_at>clock_timestamp()", "AND status='issued' AND expires_at>clock_timestamp()"),
    ('discover-success-needs-key', 'internal/dispatch/discover.go', 'internal/dispatch', 'TestDiscoverResultRoutesByJobAndKeepsShapes', '(NOT $4 OR material_issued_at IS NOT NULL)', '(NOT $4 OR true)'),
    ('discover-result-routed-by-job', 'internal/dispatch/discover.go', 'internal/dispatch', 'TestDiscoverResultRoutesByJobAndKeepsShapes', 'SELECT EXISTS(SELECT 1 FROM discovery_jobs WHERE id=$1', 'SELECT false AND EXISTS(SELECT 1 FROM discovery_jobs WHERE id=$1'),
    ('discover-deploy-body-cap', 'internal/dispatch/discover.go', 'internal/dispatch', 'TestDiscoverResultRoutesByJobAndKeepsShapes', 'len(body) > MaxResultBody', 'len(body) > MaxResultBody*1000'),
    ('discover-terminal-retry-exact', 'internal/dispatch/discover.go', 'internal/dispatch', 'TestDiscoverResultRoutesByJobAndKeepsShapes', 'subtle.ConstantTimeCompare(again, encoded) != 1', 'subtle.ConstantTimeCompare(again, encoded) != 1 && false'),
    ('discover-journal-action', 'internal/dispatch/discover.go', 'internal/dispatch', 'TestDiscoverResultRoutesByJobAndKeepsShapes', 'Action: audit.ActionCarrierDiscover,', 'Action: audit.ActionDeployResult,'),
    ('discover-foreign-key-is-failed-scan', 'internal/dispatch/discover.go', 'internal/dispatch', 'TestDiscoverReportUnderForeignKeyIsFailedScanWithNoLines', 'errors.Is(err, deployment.ErrDiscoverRejected)', 'false'),
    ('discover-submit-binding', 'internal/deployment/discover.go', 'internal/deployment', 'TestSubmitDiscoverIdempotentBusyAndScoped', 'if !equalHash(stored, hash[:]) {', 'if !equalHash(stored, hash[:]) && false {'),
    ('discover-one-at-a-time', 'internal/deployment/discover.go', 'internal/deployment', 'TestSubmitDiscoverIdempotentBusyAndScoped', 'if busy {', 'if busy && false {'),
    ('discover-hourly-cap', 'internal/deployment/discover.go', 'internal/deployment', 'TestSubmitDiscoverRateLimit', 'recent >= MaxDiscoversPerHour', 'recent >= MaxDiscoversPerHour*1000'),
    ('discover-runner-live', 'internal/deployment/discover.go', 'internal/deployment', 'TestSubmitDiscoverInvalidAndUnknownRunner', 'AND revoked_at IS NULL AND cert_not_after>clock_timestamp()', ''),
    ('discover-store-org-owned', 'internal/deployment/discover.go', 'internal/deployment', 'TestSubmitDiscoverInvalidAndUnknownRunner', 'ownerLevel != string(tenancy.LevelOrg) || ownerID != in.OrgID', 'false'),
    ('discover-seal-before-mark', 'internal/dispatch/discover.go', 'internal/dispatch', 'TestDiscoverFailedSealLeavesNoIssuanceMark', "env, err := s.issuer.SealMaterial(ctx, Snapshot{Job: job}, recipient)\n\tif err != nil {\n\t\treturn runnerproto.ValueEnvelope{}, true, ErrUnavailable\n\t}\n\tif err := tx.Commit(ctx); err != nil {\n\t\treturn runnerproto.ValueEnvelope{}, true, ErrUnavailable\n\t}", "if err := tx.Commit(ctx); err != nil {\n\t\treturn runnerproto.ValueEnvelope{}, true, ErrUnavailable\n\t}\n\tenv, err := s.issuer.SealMaterial(ctx, Snapshot{Job: job}, recipient)\n\tif err != nil {\n\t\treturn runnerproto.ValueEnvelope{}, true, ErrUnavailable\n\t}"),
    ('discover-key-id-nonempty', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverRejectsForeignKeyAndStoresNothing', 'if err != nil || !keyIDs[p.KeyID] {', 'if err != nil || (len(keyIDs) > 0 && !keyIDs[p.KeyID]) {'),
    ('discover-store-active-builtin', 'internal/deployment/discover.go', 'internal/deployment', 'TestSubmitDiscoverInvalidAndUnknownRunner', 'storeStatus != "active" || provider != string(runnerproto.ProviderBuiltin)', 'false'),
    ('discover-expiry-derived', 'internal/deployment/discover.go', 'internal/deployment', 'TestDiscoverReportExpiresUnansweredJob', "WHEN j.expires_at<clock_timestamp() THEN 'expired'", "WHEN false THEN 'expired'"),
    ('discover-expired-frees-runner', 'internal/deployment/discover.go', 'internal/deployment', 'TestDiscoverReportExpiresUnansweredJob', 'AND expires_at<=clock_timestamp()`', 'AND false`'),
    ('discover-org-isolation', 'internal/deployment/discover.go', 'internal/deployment', 'TestSubmitDiscoverIdempotentBusyAndScoped', 'WHERE j.org_id=$1 AND j.request_id=$2`, org, requestID)', 'WHERE j.request_id=$2 AND $1::uuid IS NOT NULL`, org, requestID)'),
    ('discover-failed-scan-no-compare', 'internal/deployment/discover.go', 'internal/deployment', 'TestFailedScanProvesNothingAboutAbsence', 'if !res.OK {', 'if false {'),
    ('discover-key-id-binding', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverRejectsForeignKeyAndStoresNothing', 'if err != nil || !keyIDs[p.KeyID] {', 'if err != nil || (!keyIDs[p.KeyID] && false) {'),
    ('discover-job-action-checked', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverRejectsForeignKeyAndStoresNothing', 'job.Action != runnerproto.ActionDiscover || res.Validate() != nil', 'res.Validate() != nil'),
    ('discover-incident-known-value-only', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverComparesAndNeverQueuesWork', 'it.Incident = versionFPs[f.Fingerprint]', 'it.Incident = true'),
    ('discover-match-compares-value', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverComparesAndNeverQueuesWork', 'if equalString(k.fingerprint, f.Fingerprint) {', 'if true {'),
    ('discover-unknown-find-reported', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverComparesAndNeverQueuesWork', 'if !seen[k.path+"\\x00"+k.scanName] {', 'if false {'),
    ('discover-fieldless-carrier-skipped', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverComparesAndNeverQueuesWork', "WHERE c.org_id=$1 AND c.target_field<>'' AND", 'WHERE c.org_id=$1 AND'),
    ('discover-registry-by-store', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverComparesAndNeverQueuesWork', 'AND s.store_id=$2 AND', 'AND $2::uuid IS NOT NULL AND'),
    ('discover-registry-by-host', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverComparesAndNeverQueuesWork', 'AND r.host=c.host', ''),
    ('discover-registry-active-secrets', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverComparesAndNeverQueuesWork', "AND s.status='active'", ''),
    ('discover-newest-enabled-version', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverComparesWithTheNewestEnabledVersion', 'AND NOT v.disabled ORDER BY v.seal_seq DESC', 'AND NOT v.disabled ORDER BY v.seal_seq ASC'),
    ('discover-lines-idempotent', 'internal/deployment/discover.go', 'internal/deployment', 'TestApplyDiscoverIsIdempotent', 'SELECT verdict,path,name FROM discovery_observations WHERE org_id=$1 AND job_id=$2`', 'SELECT verdict,path,name FROM discovery_observations WHERE false AND org_id=$1 AND job_id=$2`'),
    ('discover-page-limit', 'internal/deployment/discover.go', 'internal/deployment', 'TestDiscoverReportReadsWorstReportInPages', 'org, id, DiscoverPageSize, offset)', 'org, id, 1<<31-1, offset)'),
    ('discover-page-tiebreak', 'internal/deployment/discover.go', 'internal/deployment', 'TestDiscoverReportPagesAreStableWhenPathAndNameRepeat', 'ORDER BY path,name,id LIMIT $3', 'ORDER BY path,name LIMIT $3'),
    ('discover-ok-whole-report', 'internal/deployment/discover.go', 'internal/deployment', 'TestDiscoverReportReadsWorstReportInPages', "count(*) FILTER (WHERE verdict<>'match')", 'count(*) FILTER (WHERE false)'),
    ('discover-offset-past-total', 'internal/deployment/discover.go', 'internal/deployment', 'TestDiscoverReportReadsWorstReportInPages', 'if offset < 0 || offset > rep.Total {', 'if offset < 0 {'),
    ('discover-offset-on-pending', 'internal/deployment/discover.go', 'internal/deployment', 'TestDiscoverReportReadsWorstReportInPages', '\t\tif offset != 0 {\n\t\t\treturn DiscoverReport{}, ErrInvalidArgument', '\t\tif false {\n\t\t\treturn DiscoverReport{}, ErrInvalidArgument'),
    ('discover-api-ok-per-page', 'internal/api/carriers_discover.go', 'internal/api', 'TestCarrierDiscover_PagesCarryOffsetTotalAndTheWholeReportsOK', 'rep.State == deployment.DiscoverCompleted && rep.AllMatch', 'rep.State == deployment.DiscoverCompleted && func() bool { for _, it := range rep.Items { if it.Verdict != deployment.VerdictMatch { return false } }; return true }()'),
    ('discover-api-offset-leading-zero', 'internal/api/carriers_discover.go', 'internal/api', 'TestCarrierDiscover_OffsetIsParsedStrictly', "(len(v) > 1 && v[0] == '0')", 'false'),
    ('discover-api-offset-repeated', 'internal/api/carriers_discover.go', 'internal/api', 'TestCarrierDiscover_OffsetIsParsedStrictly', 'if len(vals) != 1 {', 'if len(vals) == 0 {'),
    ('discover-api-offset-sign', 'internal/api/carriers_discover.go', 'internal/api', 'TestCarrierDiscover_OffsetIsParsedStrictly', "if v[i] < '0' || v[i] > '9' {", 'if false {'),
    ('discover-api-offset-int32', 'internal/api/carriers_discover.go', 'internal/api', 'TestCarrierDiscover_OffsetIsParsedStrictly', 'n > 1<<31-1', 'false'),
    ('discover-api-length-closed-list', 'internal/api/carriers_discover.go', 'internal/api', 'TestResponseFieldsAreClosed', '\tIncident    bool   ', '\tLength      int    `json:"length"`\n\tIncident    bool   '),
    ('discover-api-length-on-wire', 'internal/api/carriers_discover.go', 'internal/api', 'TestCarrierDiscover_NoCanaryAndNoLengthOnAnyPage', '\tIncident    bool   ', '\tLength      int    `json:"length"`\n\tIncident    bool   '),
    ('discover-key-from-store', 'internal/builtin/local_delivery.go', 'internal/builtin', 'TestLocalSealMaterialDiscoverIssuesTheStoreKeyOnly', "WHERE org_id=$1 AND id=$2 AND provider='builtin' AND status='active' FOR SHARE", 'WHERE org_id=$1 AND $2::uuid IS NOT NULL AND provider=\'builtin\' FOR SHARE'),
    ('discover-key-store-active', 'internal/builtin/local_delivery.go', 'internal/builtin', 'TestLocalSealMaterialDiscoverIssuesTheStoreKeyOnly', "AND provider='builtin' AND status='active' FOR SHARE", "AND provider='builtin' FOR SHARE"),
    ('discover-api-invalid-body', 'internal/api/jobs.go', 'internal/api', 'TestRunnerJobHTTPClosedRequestsAndErrorLeak', 'if errors.Is(err, dispatch.ErrInvalidBody) {', 'if false {'),
    ('discover-api-body-cap', 'internal/api/jobs.go', 'internal/api', 'TestRunnerJobResultBodyIsCappedAtTheLargestReport', 'dispatch.MaxDiscoverBody))', 'dispatch.MaxDiscoverBody*100))'),
    ('migration-discover-one-active', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', "    WHERE status IN ('queued','issued');", '    WHERE false;'),
    ('migration-discover-incident-verdicts', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', "CHECK (incident_state IS NULL OR verdict IN ('sprawl','unknown_find')),", 'CHECK (true),'),
    ('migration-discover-unknown-find-empty', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', "CHECK (verdict <> 'unknown_find' OR (fingerprint = '' AND length = 0)),", 'CHECK (true),'),
    ('migration-discover-carrier-required', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', "CHECK (verdict = 'sprawl' OR carrier_id IS NOT NULL)", 'CHECK (true)'),
    ('migration-discover-fingerprint-shape', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', "CHECK (fingerprint = '' OR fingerprint ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$')", 'CHECK (true)'),
    ('migration-discover-payload-frozen', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', 'IF ROW(OLD.id,OLD.org_id,OLD.runner_id,OLD.request_id,OLD.request_hash,OLD.store_id,\n           OLD.job_payload,', 'IF ROW(OLD.id,OLD.org_id,OLD.runner_id,OLD.request_id,OLD.request_hash,OLD.store_id,\n           NEW.job_payload,'),
    ('migration-discover-path-unbounded', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', "CHECK (path <> '' AND char_length(path) <= 4096 AND path !~ '[[:cntrl:]]')", 'CHECK (true)'),
    ('migration-discover-path-in-bytes', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', "CHECK (path <> '' AND char_length(path) <= 4096 AND path !~ '[[:cntrl:]]')", "CHECK (path <> '' AND octet_length(path) <= 1024)"),
    ('migration-discover-name-unbounded', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', "CHECK (name <> '' AND char_length(name) <= 256 AND name !~ '[[:cntrl:]]')", 'CHECK (true)'),
    ('migration-discover-name-env-only', 'internal/store/migrations/00052_carrier_discovery.sql', 'internal/deployment', 'TestDiscoveryTablesRefuseWhatContractForbids', "CHECK (name <> '' AND char_length(name) <= 256 AND name !~ '[[:cntrl:]]')", "CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$')"),
    ('migration-discover-audit-action', audit_registry, 'internal/deployment', 'TestSubmitDiscoverIdempotentBusyAndScoped', "'carrier.discover'", "'carrier.verify'"),
    ('audit-discover-registered', 'internal/audit/record.go', 'internal/deployment', 'TestSubmitDiscoverIdempotentBusyAndScoped', 'ActionDeployResult, ActionCarrierVerify, ActionCarrierDiscover, ActionSecretRotate,', 'ActionDeployResult, ActionCarrierVerify, ActionSecretRotate,'),
]
env = os.environ.copy()
apply_only = os.environ.get('MUTATION_APPLY_ONLY') == '1'
def events(output):
    result=[]
    for line in output.splitlines():
        try: result.append(json.loads(line))
        except ValueError: pass
    return result
# Preserve the former replace-all mutants with explicit descending occurrences.
mutation_occurrences = {'verify-expiry-derived': (2, 1), 'org-read-right-too-strict': (2, 1), 'org-service-required': (4, 3, 2, 1), 'discover-registry-by-store': (2, 1), 'discover-registry-active-secrets': (2, 1), 'migration-discover-audit-action': (1,)}
for name, filename, directory, test, before, after in mutations:
    source=(root/filename).read_text()
    target=work/'tree'/filename
    changed = source
    for occurrence in mutation_occurrences.get(name, (None,)):
        changed = mutation_edit(name, changed, before, after, occurrence, filename)
    target.write_text(changed)
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
run=subprocess.run(['go','test','-json','-race','-p','1','-count=1','-timeout=300s','-run=^(TestVerify|TestCarrierVerify|TestCarrierDiscover|TestW5_CarrierVerify|TestResponseFieldsAreClosed|TestErrorClassValid|TestCarrierVerifyWrite|TestOrgCarrierVerify|TestObserve|TestDiscover|TestSubmitDiscover|TestApplyDiscover|TestFailedScan|TestLocalSealMaterialDiscover|TestRunnerJob)', './internal/targets','./internal/deployment','./internal/dispatch','./internal/api','./internal/builtin','./pkg/runnerproto','./test/security'],cwd=work/'tree',env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=420)
if run.returncode or any(e.get('Action')=='skip' for e in events(run.stdout)):
    raise SystemExit('FAIL baseline: carrier verify tests failed or skipped')
print('ok   baseline: carrier verify and discover race tests green, no skips',flush=True)
PY
