#!/bin/sh
# Proves the keep-server bootstrap-org tests can fail: in a scratch copy of the
# tree, switch off one property of cmd/keep-server/app/bootstrap.go (or of
# tenancy.CreateOrganizationUniqueName, identity.WriteTokenFile or
# catalog.EnsureDefaultBuiltinStore, which it uses, of bind-default-store, or
# of set-deploy-policy and deployment.SetPolicy behind it)
# at a time and require the designated test to go red. Needs a PostgreSQL
# (KEEP_DATABASE_URL): without one the tests would skip, which is not red.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace
pkg=cmd/keep-server/app
src=$pkg/bootstrap.go

if ! mutation_apply_only && [ -z "${KEEP_DATABASE_URL:-}" ]; then
	echo "FAIL check-bootstrap-org-mutations: KEEP_DATABASE_URL is not set — the tests would skip, not fail"
	exit 1
fi

fail=0
# edit FROM TO: $src with the first literal occurrence of FROM replaced.
edit() {
	awk -v from="$1" -v to="$2" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }'
}

# mutate NAME FROM TO WITNESS [FROM2 TO2]: replace the first literal occurrence
# of FROM (and of FROM2) in $src with TO (TO2); WITNESS in $pkg must fail.
mutate() {
	name=$1 from=$2 to=$3 witness=$4
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	# No pipe: its status would be the last edit's only, hiding a first
	# FROM that no longer matches.
	if ! edit "$from" "$to" <"$root/$src" >"$work/edit1" ||
		! if [ -n "${5:-}" ]; then edit "$5" "$6" <"$work/edit1"; else cat "$work/edit1"; fi >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 180s -count=1 -run "^${witness}\$" ./$pkg/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -Fq -- "--- FAIL: $witness (" "$work/out"; then
		echo "FAIL $name: designated witness $witness did not fail (build error?)"
		fail=1
	else
		echo "ok   $name: $witness went red"
	fi
}

leak=TestBootstrapOrg_TokenOnlyInFile
full=TestBootstrapOrg_CreatesOrgCAAdminAndJournal

# the token in stdout / the journal record gone / wrong action / failed status
# (a token pushed into the log is blanked by obs's own scrubber, so that
# surface has no mutant here: it is guarded by internal/obs's mutations)
mutate token-in-stdout ', org.ID, dest)' ', org.ID, dest+identity.Reveal(issued.Token))' $leak
mutate audit-wrong-action 'Action: audit.ActionOrgBootstrap,' 'Action: audit.ActionTokenIssue,' $full
mutate audit-failed-status 'Result: audit.Result{Status: audit.StatusOK},' 'Result: audit.Result{Status: audit.StatusFailed},' $full
mutate audit-dropped 'journal.Append(ctx, audit.Record{' 'bootstrapNoop(ctx, journal, audit.Record{' $full 'func bootstrapFail(' 'func bootstrapNoop(_ context.Context, _ *audit.Journal, r audit.Record) (audit.Record, error) { return r, nil }\n\nfunc bootstrapFail('

mutate existing-file-precheck 'if _, err := os.Lstat(dest); err == nil {' 'if false {' TestBootstrapOrg_ExistingTokenFileKeptAndNoOrg
mutate relative-path 'if !filepath.IsAbs(*tokenFile) {' 'if false {' TestBootstrapOrg_RelativeTokenFileRefused
mutate no-admin-role 'string(identity.RoleAdmin)' 'string(identity.RoleViewer)' $full
mutate admin-email-ignored 'tn.CreateUser(ctx, org.ID, *email)' 'tn.CreateUser(ctx, org.ID, "x@y.test")' $full
mutate audit-scope-empty 'Scope:  scope.String(),' 'Scope:  "",' $full
mutate ttl-missing-accepted 'ttl <= 0 || ' '' TestBootstrapOrg_TTLRequiredAndBounded
mutate ttl-over-limit-accepted 'ttl > bootstrapMaxTTL' 'ttl > 100*bootstrapMaxTTL' TestBootstrapOrg_TTLRequiredAndBounded
mutate ttl-malformed-accepted 'if err != nil || ttl <= 0' 'if ttl < 0' TestBootstrapOrg_TTLRequiredAndBounded
mutate ttl-not-applied 'ExpiresAt: &expiresAt,' '' $full 'expiresAt := time.Now().UTC().Add(ttl)' '_ = time.Now().UTC().Add(ttl)'
mutate undelivered-not-revoked 'if ids.Revoke(context.WithoutCancel(ctx), identity.Principal{OrgID: org.ID}, issued.TokenID) != nil {' 'if false {' TestBootstrapOrg_UndeliveredTokenRevoked

# tenancy.CreateOrganizationUniqueName: the name check and its table lock
src=internal/tenancy/repo.go
mutate repeat-name 'if taken {' 'if false {' TestBootstrapOrg_RepeatedNameRefused
mutate no-table-lock '`LOCK TABLE organizations IN SHARE ROW EXCLUSIVE MODE`' '`SELECT 1`' TestBootstrapOrg_ConcurrentSameNameRefused

# identity.WriteTokenFile: mode, no temp left behind (through the command) and
# never overwriting (its own test: the command's pre-check hides that one)
src=internal/identity/tokenfile.go
mutate file-mode 'tmp.Chmod(0o600)' 'tmp.Chmod(0o644)' TestBootstrapOrg_FileMode0600
mutate temp-left-behind 'defer func() { _ = os.Remove(tmp.Name()) }()' '_ = os.Remove' $leak
pkg=internal/identity
mutate overwrite 'os.Link(tmp.Name(), dest)' 'os.Rename(tmp.Name(), dest)' TestWriteTokenFile
pkg=cmd/keep-server/app

# the default store: bootstrap-org binds one, bind-default-store does the same
# for an existing org, catalog.EnsureDefaultBuiltinStore does it atomically,
# once, under the org row's lock
src=cmd/keep-server/app/bootstrap.go
mutate no-default-store 'if _, _, err := catalog.New(d.pool).EnsureDefaultBuiltinStore(ctx, org.ID); err != nil {' 'if _ = catalog.New; false {' TestBootstrapOrg_FirstSecretCreatable
src=cmd/keep-server/app/binddefault.go
mutate bind-audit-dropped 'journal.Append(ctx, audit.Record{' 'bindNoop(ctx, journal, audit.Record{' TestBindDefaultStore_ExistingOrgThenRepeat 'func bindDefaultStoreFail(' 'func bindNoop(_ context.Context, _ *audit.Journal, r audit.Record) (audit.Record, error) { return r, nil }\n\nfunc bindDefaultStoreFail('
mutate bind-reports-created 'binding := "exists"' 'binding := "created"' TestBindDefaultStore_ExistingOrgThenRepeat
src=internal/catalog/store.go
pkg=internal/catalog
mutate binding-dropped '`INSERT INTO store_bindings (id, org_id, scope_level, scope_id, store_id) VALUES ($1, $2, $3, $4, $5)`,' '`SELECT $1::uuid, $2::uuid, $3::text, $4::uuid, $5::uuid`,' TestEnsureDefaultBuiltinStore_BindsOnceAndIsIdempotent
mutate store-outside-tx 'insertStoreTx(ctx, tx, id, org,' 'insertStoreTx(ctx, c.pool, id, org,' TestEnsureDefaultBuiltinStore_StoreAndBindingAtomic
mutate no-org-lock 'FROM organizations WHERE id = $1 FOR NO KEY UPDATE`' 'FROM organizations WHERE id = $1`' TestEnsureDefaultBuiltinStore_ConcurrentCallsSerialized
mutate existing-binding-ignored 'return bound, false, nil' '_ = bound' TestEnsureDefaultBuiltinStore_KeepsExistingBinding
mutate created-not-reported 'return storeID, true, nil' 'return storeID, false, nil' TestEnsureDefaultBuiltinStore_BindsOnceAndIsIdempotent
mutate disabled-store-bound 'requireUsableStore(ctx, tx, org, []tenancy.Scope{scope}, storeID); err != nil' 'error(nil); err != nil' TestEnsureDefaultBuiltinStore_BindsExistingDefault
mutate unknown-org-unclassified 'apperr.New(apperr.ClassNotFound, "organization not found")' 'fmt.Errorf("catalog: organization")' TestEnsureDefaultBuiltinStore_UnknownOrg
pkg=cmd/keep-server/app

# set-deploy-policy: the rules are stored and turn approval into a job, rules
# naming another organization's objects are refused, the revision check, the
# dry run, the journal record, the org lock, the strict decoder and the
# bounded journal reason
src=internal/deployment/policyset.go
policy=TestSetDeployPolicy_RuleTurnsApprovalIntoJob
refusals=TestSetDeployPolicy_Refusals
mutate policy-rules-not-stored 'VALUES($1,$2,$3,1)' "VALUES(\$1,'{\"rules\":[]}'::jsonb||(\$2::jsonb-'rules'),\$3,1)" $policy 'SET rules=EXCLUDED.rules,' 'SET '
mutate policy-foreign-secret 'return policyErr("%s.secret_id is not a secret of this organization", field)' '_ = field' $policy
mutate policy-foreign-runner 'return policyErr("%s.runner_id is not a runner of this organization", field)' '_ = field' $refusals
mutate policy-nil-secret 'if rule.SecretID == uuid.Nil {' 'if false && rule.SecretID == uuid.Nil {' $refusals
mutate policy-expect-ignored 'if c.ExpectRevision >= 0 && c.ExpectRevision != res.PrevRevision {' 'if false {' TestSetDeployPolicy_ExpectRevisionAndDryRun
mutate policy-dry-run-writes 'if c.DryRun {' 'if false {' TestSetDeployPolicy_ExpectRevisionAndDryRun
mutate policy-audit-dropped 'rec, err := r.journal.AppendTx(ctx, tx, audit.Record{' 'rec, err := policyNoop(ctx, tx, audit.Record{' $policy '// checkPolicyRefs requires every' 'func policyNoop(_ context.Context, _ pgx.Tx, r audit.Record) (audit.Record, error) { return r, nil }\n\n// checkPolicyRefs requires every'
mutate policy-audit-wrong-action 'Action: audit.ActionDeployPolicySet,' 'Action: audit.ActionStoreBindDefault,' $policy
mutate policy-unknown-field 'dec.DisallowUnknownFields()' '_ = dec' $refusals
pkg=internal/deployment
mutate policy-no-org-lock '`SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, c.OrgID' '`SELECT id FROM organizations WHERE id=$1`, c.OrgID' TestSetPolicyConcurrentFirstWriteOneWinner
mutate policy-null-accepted "len(trimmed) == 0 || trimmed[0] != '{' {" "len(trimmed) == 0 {" TestDecodePolicyIsStrict
mutate policy-trailing-data 'if err := dec.Decode(&rest); !errors.Is(err, io.EOF) {' 'if err := dec.Decode(&rest); false && !errors.Is(err, io.EOF) {' TestDecodePolicyIsStrict
mutate policy-reason-unbounded 'if utf8.RuneCountInString(out+item+more) > limit {' 'if false && utf8.RuneCountInString(out+item+more) > limit {' TestPolicyChangeReasonBoundedWithCount
pkg=cmd/keep-server/app
src=cmd/keep-server/app/setdeploypolicy.go
# This mutant prints the raw error of the deliberately unreachable database,
# whose text is the infrastructure classifier's connection signature. For it
# alone a connection failure counts as the mutant, once a database witness has
# shown the real database answers.
mutation_db_witness -run '^TestSetDeployPolicy_RuleTurnsApprovalIntoJob$' ./cmd/keep-server/app/
mutation_connect_faults_are_mutants=1
mutate policy-startup-raw 'return setDeployPolicyFail(stderr, apperr.ClassNotReady, "cannot open the database")' 'return setDeployPolicyFail(stderr, apperr.ClassNotReady, err.Error())' TestSetDeployPolicy_StartupFailuresFormatted
mutation_connect_faults_are_mutants=0
mutate policy-limit-unchecked 'if maxSet && (*maxPerHour < 1 || *maxPerHour > 1000) {' 'if false && maxSet {' $refusals

if mutation_apply_only; then
	:
elif (cd "$root" && go test -timeout 180s -count=1 -run 'TestBootstrapOrg|TestBindDefaultStore|TestWriteTokenFile|TestEnsureDefaultBuiltinStore|TestSetDeployPolicy|TestSetPolicy|TestDecodePolicy|TestPolicyChangeReason' ./cmd/keep-server/app/ ./internal/identity/ ./internal/catalog/ ./internal/deployment/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi
exit $fail
