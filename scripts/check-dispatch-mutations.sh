#!/bin/sh
# Prove dispatch guards with named behavioral failures, never compiler errors.
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
import re
import subprocess
import sys

root, work = map(Path, sys.argv[1:])
mutations = [
    ('poll-claim', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestPollClaimsOnceAndHonorsCancellation', "AND status='queued' AND expires_at", "AND expires_at"),
    ('poll-cancellation', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestPollClaimsOnceAndHonorsCancellation', 'if err := ctx.Err(); err != nil {', 'if err := ctx.Err(); false && err != nil {'),
    ('http-tls', 'internal/api/router.go', 'internal/api', 'TestRunnerJobHTTPRejectsUntrustedPeer', 'jobMTLS := chain(requireTLS, mtls.RequireMTLS(deps.CA, deps.Runners, logger))', 'jobMTLS := chain()'),
    ('signing-error-leak', 'internal/builtin/orgpki/sign_job.go', 'internal/builtin/orgpki', 'TestSignJobRejectsCorruptionAndNeverEchoesInput', 'if org == uuid.Nil || j.OrgID != org.String() || j.Validate() != nil {\n\t\treturn runnerproto.SignedJob{}, ErrJobSigning', 'if org == uuid.Nil || j.OrgID != org.String() || j.Validate() != nil {\n\t\treturn runnerproto.SignedJob{}, errors.New(j.Secret.Name)'),
    ('key-scope-binding', 'pkg/runnerproto/value.go', 'internal/builtin', 'TestRunnerMaterialRoundTripAndBinding', 'e.str(tagSecretScope, j.Secret.Scope)', 'e.str(tagSecretScope, "")'),
    ('key-provider-binding', 'pkg/runnerproto/value.go', 'internal/builtin', 'TestRunnerMaterialRoundTripAndBinding', 'e.str(tagProvider, j.Secret.Provider)', 'e.str(tagProvider, "")'),
    ('key-domain-exact', 'pkg/runnerproto/value.go', 'pkg/runnerproto', 'TestFingerprintEnvelopeDomain', 'keep/fingerprint-key/v1', 'keep/fingerprint-key/v0'),
    ('signing-id-compat', 'pkg/runnerproto/sign.go', 'pkg/runnerproto', 'TestSigningKeyIDEnrollmentCompatibility', '^[a-z0-9][a-z0-9_-]{0,63}$', '^[a-z0-9][a-z0-9-]{0,63}$'),
    ('signing-id-invalid', 'pkg/runnerproto/sign.go', 'pkg/runnerproto', 'TestSigningKeyIDEnrollmentCompatibility', '!signingKeyIDRe.MatchString(s.KeyID)', '(false && !signingKeyIDRe.MatchString(s.KeyID))'),
    ('registered-recipient', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestMaterialUsesRegisteredRecipient', 'return tx, d.HPKEPublicKey, nil', '_ = d; return tx, make([]byte, 32), nil'),
    ('result-migration-up', 'internal/store/migrations/00017_deployment_result.sql', 'internal/store', 'TestDeploymentResultMigrationPreservesHistory', "'deploy.policy_decision','deploy.result'", "'deploy.policy_decision'"),
    ('result-migration-history', 'internal/store/migrations/00017_deployment_result.sql', 'internal/store', 'TestDeploymentResultMigrationPreservesHistory', ')) NOT VALID;', '));'),
    ('result-migration-down', 'internal/store/migrations/00017_deployment_result.sql', 'internal/store', 'TestDeploymentResultMigrationPreservesHistory', "'deploy.requested','deploy.policy_decision')) NOT VALID", "'deploy.requested','deploy.policy_decision','deploy.result')) NOT VALID"),
    ('audit-failure-category', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestResultAuditKeepsClosedFailureCategory', 'errorClass := auditFailureClass(result.ErrorClass)', 'errorClass := audit.ErrClassTargetError'),
    ('late-result', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestResultRetriesAfterLeaseExpiryWithoutSecondAudit', 'result.OK), p, true)', 'result.OK), p, false)'),
    ('result-retry-equality', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestResultRetriesAfterLeaseExpiryWithoutSecondAudit', '!bytes.Equal(canonical, encoded)', '(!bytes.Equal(canonical, encoded) && false)'),
    ('signing-pool', 'internal/builtin/orgpki/sign_job.go', 'internal/builtin/orgpki', 'TestSignJobUsesHeldConnection', 'loadRecordFrom(ctx, tx, org)', 'r.loadRecord(ctx, org)'),
    ('signing-sealer-pool', 'internal/builtin/orgpki/sign_job.go', 'internal/builtin/orgpki', 'TestSignJobUsesHeldConnection', 'r.sealer.WithStore(builtin.NewTransactionKeyStore(tx)).Open(', 'r.sealer.WithStore(builtin.NewKeyStore(r.db)).Open('),
    ('catalog-revocation', 'internal/builtin/local_delivery.go', 'internal/builtin', 'TestLocalDeliveryUsesFrozenReference', 'FOR SHARE OF s,st,v', ''),
    ('audit-atomic', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestResultAuditFailureRollsBackWithoutLeak', 'if err != nil { // result audit must commit with the state', 'if false { // result audit must commit with the state'),
    ('result-binding', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestResultRejectsUnboundMetadata', 'if !resultMatchesJob(result, snap.Job) {', 'if false {'),
    ('key-domain', 'pkg/runnerproto/value.go', 'pkg/runnerproto', 'TestFingerprintEnvelopeCannotSwapWithValue', 'return append([]byte("keep/fingerprint-key/v1\\x00"), Info(j)...)', 'return Info(j)'),
    ('closed-request', 'pkg/runnerproto/value_request.go', 'pkg/runnerproto', 'TestDecodeValueRequestIsClosed', 'if !exactKeys(', 'if false && !exactKeys('),
    ('org-signing', 'internal/builtin/orgpki/sign_job.go', 'internal/builtin/orgpki', 'TestSignJobUsesOrganizationKey', 'j.OrgID != org.String()', '(j.OrgID != org.String() && false)'),
    ('plaintext-envelope', 'internal/builtin/delivery.go', 'internal/builtin', 'TestRunnerMaterialNeverLeaks', 'return append(enc, cipher...), nil', '_ = enc; _ = cipher; return append([]byte(nil), plain...), nil'),
    ('fingerprint-check', 'internal/builtin/delivery.go', 'internal/builtin', 'TestRunnerMaterialRejectsInvalidInputs', 'actual != j.ExpectedFingerprint', '(actual != j.ExpectedFingerprint && false)'),
    ('key-liveness', 'internal/builtin/delivery.go', 'internal/builtin', 'TestExternalRunnerMaterialHasKeyOnly', 'if _, err := fingerprint.Compute(key, secret.Value{}); err != nil {', 'if _, err := fingerprint.Compute(key, secret.Value{}); false && err != nil {'),
    ('frozen-owner', 'internal/builtin/local_delivery.go', 'internal/builtin', 'TestLocalDeliveryUsesFrozenReference', 'owner != s.OwnerScope', '(owner != s.OwnerScope && false)'),
    ('one-issuance', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestMaterialConcurrentOneWinner', 'AND material_issued_at IS NULL', ''),
    ('current-certificate', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestMaterialRejectsWrongPeerAndState', 'cert_serial=$3', '($3::text IS NOT NULL)'),
    ('job-expiry', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestMaterialExpiredJobAndBackendFailure', 'AND expires_at>clock_timestamp()', ''),
    ('terminal-result', 'internal/dispatch/dispatch.go', 'internal/dispatch', 'TestTerminalResultIsImmutable',  'if state == "completed" || state == "failed" { // terminal results only acknowledge exact retries', 'if false { // terminal results only acknowledge exact retries' ),
    ('http-error', 'internal/api/jobs.go', 'internal/api', 'TestRunnerJobHTTPClosedRequestsAndErrorLeak', '"runner job service unavailable", reqid.FromContext', 'err.Error(), reqid.FromContext'),
    ('response-deadline', 'internal/api/middleware.go', 'internal/api', 'TestStatusRecorderPreservesResponseDeadlines', 'func (r *statusRecorder) Unwrap() http.ResponseWriter', 'func (r *statusRecorder) hiddenUnwrap() http.ResponseWriter'),
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
baseline_run = '^Test(DeploymentResultMigration|RunnerMaterial|ExternalRunnerMaterial|LocalDelivery|SignJob|FingerprintEnvelope|SigningKeyID|DecodeValueRequest|PollClaims|MaterialUses|MaterialConcurrent|MaterialRejects|MaterialExpired|TerminalResult|ResultAudit|ResultRejects|ResultRetries|RunnerJobHTTP|StatusRecorder)'
baseline_packages = ['./internal/store', './internal/dispatch', './internal/builtin', './internal/builtin/orgpki', './internal/api', './pkg/runnerproto']

def baseline_failure(package, cls, ev, names):
    # Class, package and test names, then only the file:line locations of the
    # test output. Message text is never printed: a test may interpolate a
    # value into its message, and a CI log is not a place for one.
    print('FAIL baseline: dispatch tests ' + cls + ' in ' + package, flush=True)
    for n in sorted(names):
        print('  test: ' + n, flush=True)
    lines = [str(e.get('Output', '')).strip() for e in ev if e.get('Action') in ('output', 'build-output')]
    where = []
    for l in lines:
        m = re.match(r'^([A-Za-z0-9_./-]+\.go:[0-9]+(?::[0-9]+)?): ', l)
        if not m:
            # A go timeout dumps stacks: `<abs path>.go:N +0x..` lines hold only
            # paths and offsets. Keep those under the mutation tree, which
            # leaves the test's own frames and drops the runtime's.
            m = re.match(r'^' + re.escape(str(work / 'tree')) + r'/([A-Za-z0-9_./-]+\.go:[0-9]+)(?: \+0x[0-9a-f]+)?$', l)
        if m and m.group(1) not in where:
            where.append(m.group(1))
    for w in where[-12:]:
        print('  at ' + w, flush=True)
    raise SystemExit(1)

# One package per run: a failure names its package, and the wall-clock limit
# of the wrapper (compile included) applies to that package alone. The test
# deadline stays 180 s of test run time, as before.
for package in baseline_packages:
    try:
        run = subprocess.run(['go', 'test', '-json', '-race', '-p', '1', '-count=1', '-timeout=180s', '-run=' + baseline_run, package], cwd=work/'tree', env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    except subprocess.TimeoutExpired:
        print('FAIL baseline: dispatch tests timeout (wrapper limit 600 s, compile included) in ' + package, flush=True)
        raise SystemExit(1)
    ev = events(run.stdout)
    skipped = {str(e.get('Test')) for e in ev if e.get('Action') == 'skip'}
    failed = {str(e.get('Test')) for e in ev if e.get('Action') == 'fail' and e.get('Test')}
    timed_out = any('panic: test timed out' in str(e.get('Output', '')) for e in ev)
    build_failed = any(e.get('Action') == 'build-fail' or '[build failed]' in str(e.get('Output', '')) or '[setup failed]' in str(e.get('Output', '')) for e in ev)
    if timed_out:
        # A real timeout gives the hung test no `fail` event: go attributes the
        # runtime's own panic line to it, so take the names from that line.
        hung = {str(e.get('Test')) for e in ev if e.get('Test') and str(e.get('Output', '')).startswith('panic: test timed out')}
        baseline_failure(package, 'timeout (go test deadline 180 s)', ev, failed | hung)
    if build_failed:
        baseline_failure(package, 'build-fail', ev, failed)
    if skipped:
        baseline_failure(package, 'skip', ev, skipped)
    if failed:
        baseline_failure(package, 'fail', ev, failed)
    if run.returncode:
        baseline_failure(package, 'fail (exit ' + str(run.returncode) + ', no named test)', ev, failed)
print('ok   baseline: dispatch race tests green, no skips',flush=True)
PY
