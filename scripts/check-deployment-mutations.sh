#!/bin/sh
# Each security decision below must fail its own behavioral test when the
# corresponding guard is removed. A build error, skip or unrelated failure
# is not evidence. Tests use isolated PostgreSQL databases.
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
source = (root / 'internal/deployment/repo.go').read_text()
target = work / 'tree/internal/deployment/repo.go'
mutations = [
    ('approval', 'decision == Allow', 'decision != Allow', 'TestSubmitApprovalAndIdempotency'),
    ('idempotency', 'if !equalHash(stored, hash) {', 'if false {', 'TestSubmitApprovalAndIdempotency'),
    ('target-binding', 'in.RunnerID.String(), string(targetJSON))', 'in.RunnerID.String())', 'TestSubmitProductionApprovalBindingAndSharedHost'),
    ('secret-binding', 'bindHash("keep/deploy/target/v1", in.OrgID.String(), in.SecretID.String(),', 'bindHash("keep/deploy/target/v1", in.OrgID.String(),', 'TestSubmitProductionApprovalBindingAndSharedHost'),
    ('registry-required', 'if err != nil {\n\t\t\treturn Host{}, err\n\t\t}', 'if err != nil {\n\t\t\treturn Host{AttributesKnown: true}, nil\n\t\t}', 'TestSubmitUsesEnrolledRegistryTrust'),
    ('registry-prod-attrs', 'AttributesKnown: d.AttrsKnown, UIDShared: d.UIDShared', 'AttributesKnown: true, UIDShared: false', 'TestSubmitUsesEnrolledRegistryTrust'),
    ('rate-limit', 'return used >= limit, nil', 'return used > limit, nil', 'TestSubmitAtomicRateLimitAndTenantIsolation'),
    ('provider-capability', 'if status == Queued && secret.provider != runnerproto.ProviderBuiltin {', 'if false {', 'TestUnsupportedProviderNeverQueuesMaterialClaim'),
    ('provider-policy-precedence', 'if status == Queued && secret.provider != runnerproto.ProviderBuiltin {', 'if secret.provider != runnerproto.ProviderBuiltin {', 'TestSubmitUnsupportedProviderPreservesPolicyDecisions'),
    ('tenant-scope', 'if s.secretScopeLevel != string(in.Scope.Level) || s.secretScopeID != in.Scope.ID {', 'if false {', 'TestSubmitAtomicRateLimitAndTenantIsolation'),
    ('audit-atomic', 'second, err := r.journal.AppendTx(ctx, tx, base)\n\tif err != nil {', 'second, err := r.journal.AppendTx(ctx, tx, base)\n\tif false {', 'TestSubmitRollsBackOnAuditFailureAndNoCanary'),
]
env = os.environ.copy()
apply_only = os.environ.get('MUTATION_APPLY_ONLY') == '1'
def check_mutation(name, before, after, test, original, mutated, test_package='internal/deployment', expect=None):
    if original.count(before) != 1:
        raise SystemExit('FAIL ' + name + ': mutation target is not unique')
    mutated.write_text(original.replace(before, after, 1))
    try:
        if apply_only:
            print('ok   ' + name + ': applies', flush=True)
            return
        run = subprocess.run(
            ['go', 'test', '-json', '-count=1', '-timeout=180s', '-run=^' + test + '$', './' + test_package],
            cwd=work / 'tree', env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
        events = []
        for line in run.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
        package = 'github.com/entire-vc/evc-keep/' + test_package
        designated = any(e.get('Package') == package and e.get('Test') == test and e.get('Action') == 'fail' for e in events)
        skipped = any(e.get('Action') == 'skip' for e in events)
        build_failed = any(e.get('Action') == 'build-fail' or '[build failed]' in str(e.get('Output', '')) or '[setup failed]' in str(e.get('Output', '')) for e in events)
        if run.returncode == 0 or not designated or skipped or build_failed:
            raise SystemExit('FAIL ' + name + ': designated behavioral assertion did not reject mutant')
        if expect:
            seen = [str(e.get('Output', '')).strip() for e in events if expect in str(e.get('Output', ''))]
            if not seen:
                raise SystemExit('FAIL ' + name + ': test went red but not with ' + repr(expect))
            print('     evidence: ' + seen[0], flush=True)
        print('ok   ' + name + ': ' + test + ' red', flush=True)
    finally:
        mutated.write_text(original)
for name, before, after, test in mutations:
    check_mutation(name, before, after, test, source, target)
policy_file = 'internal/deployment/policy.go'
check_mutation('secret-template-binding', 'if rule.SecretID != secretID {', 'if false {',
               'TestReviewSecretPolicyIsolation', (root / policy_file).read_text(),
               work / 'tree' / policy_file)
check_mutation('exec-rule-template', 'rule.SecretID != secretID || rule.TemplateID != templateID {', 'rule.SecretID != secretID {',
               'TestExecNoneTemplateWithoutAMatchingRuleWaitsForApproval', (root / policy_file).read_text(),
               work / 'tree' / policy_file)
check_mutation('exec-rule-secret', 'rule.SecretID != secretID || rule.TemplateID != templateID {', 'rule.TemplateID != templateID {',
               'TestExecRuleIsBoundToItsSecret', (root / policy_file).read_text(),
               work / 'tree' / policy_file)
# The job-frozen trigger function is recreated by every later migration that
# changes the columns it guards, so the mutation must hit the last definition.
for name, before, after, test, mig in [
    ('frozen-job', 'IF ROW(OLD.action,OLD.id,', 'IF FALSE AND ROW(OLD.action,OLD.id,', 'TestQueuedJobMetadataCannotBeRewritten', '00022_carrier_verify.sql'),
    ('terminal-result', "CHECK ((result IS NOT NULL) = (status IN ('completed','failed')))",
     'CHECK (true)', 'TestQueuedJobMetadataCannotBeRewritten', '00016_deployment.sql'),
]:
    check_mutation(name, before, after, test, (root / 'internal/store/migrations' / mig).read_text(),
                   work / 'tree/internal/store/migrations' / mig)
# exec_with_secret on the server: the network gate, the approval binding and the
# journal's closed fields. Each guard is switched off in the scratch tree.
exec_file = 'internal/deployment/exec.go'
exec_source = (root / exec_file).read_text()
exec_target = work / 'tree' / exec_file
for name, before, after, test in [
    ('exec-network-needs-approval', 'case lt.decision.RequiresApproval || secret.class == "prod":', 'case secret.class == "prod":',
     'TestExecNetworkTemplateCreatesNoJobBeforeApproval'),
    ('exec-prod-needs-approval', 'case lt.decision.RequiresApproval || secret.class == "prod":', 'case lt.decision.RequiresApproval:',
     'TestExecProductionSecretWaitsEvenWithNetworkNone'),
    ('exec-binding-destinations', '\tvals = append(vals, s.Destinations...)\n', '',
     'TestExecApprovalRefusedWhenDestinationsChange'),
    ('exec-binding-params', '\t\tvals = append(vals, k, s.Params[k])\n', '\t\t_ = k\n',
     'TestExecApprovalRefusedWhenDestinationsChange'),
    ('exec-rule-required', '\tcase !ExecAllowed(p, host, secretID, templateID):', '\tcase false:',
     'TestExecNoneTemplateWithoutAMatchingRuleWaitsForApproval'),
    ('exec-template-org-scope', 'WHERE org_id=$1 AND template_id=$2`, org, id)',
     'WHERE template_id=$2 AND $1::uuid IS NOT NULL`, org, id)',
     'TestExecTemplateIsScopedToItsOrganization'),
    ('exec-binding-template-id', 's.TemplateID, s.Digest, s.Mode,',
     's.Digest, s.Mode,',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-digest', 's.TemplateID, s.Digest, s.Mode,',
     's.TemplateID, s.Mode,',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-mode', 's.TemplateID, s.Digest, s.Mode, strconv',
     's.TemplateID, s.Digest, strconv',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-org', 'vals := []string{org.String(), secretID.String(),', 'vals := []string{secretID.String(),',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-secret', 'vals := []string{org.String(), secretID.String(), versionID.String(),', 'vals := []string{org.String(), versionID.String(),',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-version', 'secretID.String(), versionID.String(), runnerID.String(), scope,', 'secretID.String(), runnerID.String(), scope,',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-scope', 'versionID.String(), runnerID.String(), scope, s.TemplateID', 'versionID.String(), runnerID.String(), s.TemplateID',
     'TestExecBindingCoversEveryField'),
    ('exec-identity-org', 'if c.OrgID == uuid.Nil || c.SecretID', 'if c.SecretID',
     'TestExecSubmitRefusesIncompleteIdentity'),
    ('exec-identity-scope', 'c.RunnerID == uuid.Nil || c.Scope.ID == uuid.Nil ||', 'c.RunnerID == uuid.Nil ||',
     'TestExecSubmitRefusesIncompleteIdentity'),
    ('exec-identity-actor', '!reqid.Valid(c.RequestID) || c.Actor.ID == "" || !knownActor(c.Actor) {', '!reqid.Valid(c.RequestID) || c.Actor.ID == "" {',
     'TestExecSubmitRefusesIncompleteIdentity'),
    ('exec-identity-actor-id', 'c.Actor.ID == "" || !knownActor', '!knownActor',
     'TestExecSubmitRefusesIncompleteIdentity'),
    ('exec-stored-template-id', 'json.Unmarshal(body, &t) != nil || t.ID != id {', 'json.Unmarshal(body, &t) != nil {',
     'TestExecStoredTemplateIsRevalidated'),
    ('exec-stored-template-validate', 'dec, err := execpolicy.Validate(tpl)\n\tif err != nil {\n\t\treturn loadedTemplate{}, ErrTemplateUnknown', 'dec, _ := execpolicy.Validate(tpl)\n\tif false {\n\t\treturn loadedTemplate{}, ErrTemplateUnknown',
     'TestExecStoredTemplateIsRevalidated'),
    ('exec-binding-runner', 'versionID.String(), runnerID.String(), scope,',
     'versionID.String(), scope,',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-destination-count', 's.Mode, strconv.Itoa(len(s.Destinations))}',
     's.Mode}',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-requester', 'vals = append(vals, rtype, rid, rsponsor, rvia)',
     'vals = append(vals, rtype, rsponsor, rvia)',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-requester-type', 'vals = append(vals, rtype, rid, rsponsor, rvia)',
     'vals = append(vals, rid, rsponsor, rvia)',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-sponsor', 'vals = append(vals, rtype, rid, rsponsor, rvia)',
     'vals = append(vals, rtype, rid, rvia)',
     'TestExecBindingCoversEveryField'),
    ('exec-binding-via', 'vals = append(vals, rtype, rid, rsponsor, rvia)',
     'vals = append(vals, rtype, rid, rsponsor)',
     'TestExecBindingCoversEveryField'),
    ('exec-denied-prod-host', 'case secret.class == "prod" && (!host.AttributesKnown || host.UIDShared):',
     'case false:',
     'TestExecRequestTimePolicyChecks'),
    ('exec-unsupported-provider', 'case secret.provider != runnerproto.ProviderBuiltin:',
     'case false:',
     'TestExecRequestTimePolicyChecks'),
    ('exec-rate-limit', 'if limited {\n\t\t\tstatus = RateLimited',
     'if limited && false {\n\t\t\tstatus = RateLimited',
     'TestExecRequestTimePolicyChecks'),
    ('exec-runner-trust', 'host, err := r.trust(ctx, tx, c.OrgID, c.RunnerID)\n\tif err != nil {',
     'host, err := r.trust(ctx, tx, c.OrgID, c.RunnerID)\n\tif false {',
     'TestExecRequestTimePolicyChecks'),
    ('exec-snapshot-mode', 's.Mode = "allowlist"',
     's.Mode = "none"',
     'TestExecSnapshotModeAndKinds'),
    ('exec-snapshot-destinations', 'for _, d := range lt.decision.Destinations {',
     'for _, d := range []execpolicy.Destination(nil) {',
     'TestExecSnapshotModeAndKinds'),
    ('exec-param-keyset', 'if len(in.Params) != len(lt.tpl.Params) {', 'if false {',
     'TestExecRequestIsIdempotentAndRefusesBadInput'),
    ('exec-param-patterns', 'if _, err = execpolicy.Expand(lt.tpl, in.Params); err != nil {', 'if false {',
     'TestExecRequestIsIdempotentAndRefusesBadInput'),
    ('exec-template-validation', 'if _, err = execpolicy.Validate(tpl); err != nil {', 'if false {',
     'TestExecRequestIsIdempotentAndRefusesBadInput'),
]:
    check_mutation(name, before, after, test, exec_source, exec_target)
approval_file = 'internal/deployment/approval.go'
for name, before, after in [
    ('exec-decide-provider', 'lt.digest != snap.Digest || secret.provider != runnerproto.ProviderBuiltin ||', 'lt.digest != snap.Digest ||'),
    ('exec-decide-prod-host', '(secret.class == "prod" && (!host.AttributesKnown || host.UIDShared)) {', 'false {'),
    ('exec-decide-rate-limit', '\t\tif limited {\n\t\t\treturn DecideResult{}, ErrRefused', '\t\tif limited && !isExec {\n\t\t\treturn DecideResult{}, ErrRefused'),
    ('exec-decide-journal-kind', 'rec.Target.Kind = "exec"', '_ = rec'),
]:
    check_mutation(name, before, after, 'TestExecDecisionRechecksPolicyAndJournalsKind', (root / approval_file).read_text(), work / 'tree' / approval_file)
for name, before, after in [
    ('exec-card-param-names', 'a.Exec.ParamNames = append(a.Exec.ParamNames, k)', '_ = k'),
    ('exec-card-param-order', 'sort.Strings(a.Exec.ParamNames)', '_ = sort.Strings'),
]:
    check_mutation(name, before, after, 'TestExecApprovalListsParameterNamesSorted', (root / approval_file).read_text(), work / 'tree' / approval_file)
check_mutation('exec-template-recheck-at-approval', 'terr != nil || lt.digest != snap.Digest || ', 'terr != nil || lt.digest != lt.digest || ',
               'TestExecApprovalRefusedWhenDestinationsChange', (root / approval_file).read_text(), work / 'tree' / approval_file)
# Dropping the organization lock from PutExecTemplate keeps the code compiling
# (the locked id is simply unused) and must show the replacement racing past
# Decide's template read: the job is inserted with the old snapshot.
check_mutation('exec-put-template-org-lock',
               'if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, org).Scan(&lockedOrg); err != nil {',
               '_ = lockedOrg\n\tif err = error(nil); err != nil {',
               'TestExecTemplateReplacementDuringApprove', (root / exec_file).read_text(), work / 'tree' / exec_file,
               expect='RACE: replacement committed after template read')
check_mutation('exec-kind-only-for-exec', 'if execJSON != nil {\n\t\treturn "exec"', 'if true {\n\t\treturn "exec"',
               'TestExecSnapshotModeAndKinds', source, target)
check_mutation('exec-journal-kind', 'Kind: targetKind(f.execJSON)}', 'Kind: ""}',
               'TestExecLeaksNothingBeyondTheClosedFields', source, target)
check_mutation('exec-params-in-journal', 'Policy: audit.Policy{Decision: policyDecision},', 'Policy: audit.Policy{Decision: policyDecision, RuleID: string(f.execJSON)},',
               'TestExecLeaksNothingBeyondTheClosedFields', source, target)
migration_test = 'internal/store/deployment_migration_test.go'
check_mutation('migration-neighbors', 'provider.DownTo(pgscratch.Context(t), 15)', 'provider.DownTo(pgscratch.Context(t), 12)',
               'TestDeploymentMigrationDowngradeAndUpgrade', (root / migration_test).read_text(),
               work / 'tree' / migration_test, 'internal/store')
check_mutation('migration-carriers-neighbor', 'provider.DownTo(pgscratch.Context(t), 15)', 'provider.DownTo(pgscratch.Context(t), 14)',
               'TestDeploymentMigrationDowngradeAndUpgrade', (root / migration_test).read_text(),
               work / 'tree' / migration_test, 'internal/store')
if apply_only:
    sys.exit(0)
run = subprocess.run(
    ['go', 'test', '-json', '-race', '-count=1', '-timeout=180s', '-run=^Test(Exec|Submit|QueuedJob|UnsupportedProvider|Policy|Production|Trusted|Invalid|ReviewSecretPolicyIsolation)', './internal/deployment'],
    cwd=work / 'tree', env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
events = []
for line in run.stdout.splitlines():
    try:
        events.append(json.loads(line))
    except ValueError:
        pass
if run.returncode or any(e.get('Action') == 'skip' for e in events):
    raise SystemExit('FAIL baseline: deployment tests failed or skipped')
print('ok   baseline: deployment race tests green, no skips', flush=True)
PY
