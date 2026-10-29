#!/bin/sh
# Proves the runner protocol guards can fail: in a scratch copy of the tree,
# switch off one check of pkg/runnerproto at a time and require the named
# test to go red. A check whose removal leaves that test green is not
# tested. Exits 0 only if every mutation is caught.
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
dir=pkg/runnerproto

fail=0
# caught_by_crash TEST OUT: the run died with a runtime fatal error or panic
# raised from TEST's own goroutines. A race mutant can end this way instead of
# with "--- FAIL: TEST" (e.g. "fatal error: concurrent map writes"): the
# check is still caught, just by the runtime before the race detector.
caught_by_crash() {
	grep -q -E '^(fatal error|panic): ' "$2" && grep -q -E "runnerproto\.$1(\.func[0-9]+)?\(" "$2"
}

mutation_witness_failed() {
	if [ "${FAIL_LINE_ONLY:-0}" = 1 ] && grep -q -E '\[build failed\]|\[setup failed\]|^panic:|^fatal error:' "$2"; then
		return 1
	fi
	if grep -q -- "--- FAIL: $1 " "$2"; then
		return 0
	fi
	[ "${FAIL_LINE_ONLY:-0}" != 1 ] && caught_by_crash "$1" "$2"
}

mutation_witness_supported() {
	case "$1" in Test?*) ;; *) return 1 ;; esac
	case "$1" in *[!A-Za-z0-9_]*) return 1 ;; esac
}

# mutate NAME FILE TEST FROM TO: replace the first literal occurrence of FROM
# with TO in FILE; TEST must be among the failing tests.
mutate() {
	name=$1 file=$dir/$2 test=$3 from=$4 to=$5
	if ! mutation_witness_supported "$test"; then
		echo "FAIL $name: unsupported mutation witness"
		fail=1
		return
	fi
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$file" >"$work/tree/$file"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 120s -count=1 ${RACE:+-race} -run "^${test}$" ./$dir/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the check switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! mutation_witness_failed "$test" "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?):"
		head -20 "$work/out"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

# Exercise the real mutation verdict with controlled subprocess output. A
# strict witness must fail as a test; a panic or compiler failure is not proof.
failure_classifier_selftest() (
	mkdir -p "$work/fake-bin"
	cat >"$work/fake-bin/go" <<'EOF'
#!/bin/sh
printf '%s\n' "$MUTATION_SELFTEST_OUTPUT"
exit 1
EOF
	chmod +x "$work/fake-bin/go"
	PATH="$work/fake-bin:$PATH"
	export PATH
	for selftest_case in crash build mixed panicmixed wrong failure; do
		case "$selftest_case" in
			crash) MUTATION_SELFTEST_OUTPUT='panic: synthetic failure
runnerproto.TestInfoHPKEBindsSecret.func1()'; expected=1 ;;
			build) MUTATION_SELFTEST_OUTPUT='FAIL package [build failed]'; expected=1 ;;
			mixed) MUTATION_SELFTEST_OUTPUT='--- FAIL: TestInfoHPKEBindsSecret (0.00s)
FAIL package [build failed]'; expected=1 ;;
			panicmixed) MUTATION_SELFTEST_OUTPUT='--- FAIL: TestInfoHPKEBindsSecret (0.00s)
panic: synthetic failure'; expected=1 ;;
			wrong) MUTATION_SELFTEST_OUTPUT='--- FAIL: TestOther (0.00s)'; expected=1 ;;
			failure) MUTATION_SELFTEST_OUTPUT='--- FAIL: TestInfoHPKEBindsSecret (0.00s)'; expected=0 ;;
		esac
		export MUTATION_SELFTEST_OUTPUT
		fail=0
		FAIL_LINE_ONLY=1 mutate selftest value.go TestInfoHPKEBindsSecret \
			'e.str(tagSecretScope, j.Secret.Scope)' '' >"$work/selftest-verdict"
		if [ "$fail" != "$expected" ]; then
			echo "FAIL strict failure classifier: $selftest_case"
			exit 1
		fi
	done
	echo 'ok   strict failure classifier: crash/build/wrong-test rejected, named failure accepted'
)
# The classifier selftest runs a stub, not a mutant: nothing to anchor.
mutation_apply_only || failure_classifier_selftest || exit 1
if [ "${1:-}" = --selftest ]; then exit 0; fi
# apply1 FILE FROM TO: mutate's single substitution, applied to the tree
# mutateN already copied — lets mutateN chain several onto one scratch tree.
apply1() {
	file=$dir/$1 from=$2 to=$3
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$work/tree/$file" >"$work/tree/$file.new"; then
		return 1
	fi
	mv "$work/tree/$file.new" "$work/tree/$file"
}

# mutateN NAME TEST FILE FROM TO [FILE FROM TO ...]: like mutate, but applies
# several single-line substitutions before running TEST. Needed when a
# mutation cannot be expressed as one from/to pair — e.g. moving a line
# rather than editing it where it sits.
mutateN() {
	name=$1 test=$2
	if ! mutation_witness_supported "$test"; then
		echo "FAIL $name: unsupported mutation witness"
		fail=1
		return
	fi
	shift 2
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	while [ $# -gt 0 ]; do
		if ! apply1 "$1" "$2" "$3"; then
			echo "FAIL $name: mutation did not apply — the source changed, update this script"
			fail=1
			return
		fi
		shift 3
	done
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 120s -count=1 ${RACE:+-race} -run "^${test}$" ./$dir/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the checks switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! mutation_witness_failed "$test" "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?):"
		head -20 "$work/out"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

# Signed job: every field covered, signature checked, identity, time, replay.
mutate field-not-signed    canonical.go TestTamperAnyFieldRejected 'e.str(tagExpectedVersion, j.ExpectedVersion)' ''
mutate path-not-signed     canonical.go TestTamperAnyFieldRejected 'e.str(tagTargetPath, j.Target.Path)' ''
mutate no-signature-check  sign.go      TestTamperAnyFieldRejected '|| !ed25519.Verify(pub, sj.Payload, sj.Sig)' ''
mutate no-runner-check     sign.go      TestWrongOrgRunnerAndTime  'j.OrgID != me.OrgID || j.RunnerID != me.RunnerID' 'j.OrgID != me.OrgID'
mutate hermes-field-unchecked job.go   TestHermesConfigFieldIsEnvName 'case TargetEnvFile, TargetLaunchdEnv, TargetHermesConfig:' 'case TargetEnvFile, TargetLaunchdEnv:'
mutate no-org-check        sign.go      TestWrongOrgRunnerAndTime  'j.OrgID != me.OrgID || j.RunnerID != me.RunnerID' 'j.RunnerID != me.RunnerID'
mutate no-expiry           sign.go      TestWrongOrgRunnerAndTime  '|| !now.Before(j.NotAfter.Add(ClockSkew))' ''
mutate no-replay-check     sign.go      TestReplayRejected         'if err := journal.Claim(j.JobID, j.NotAfter, now); err != nil {' 'if err := error(nil); err != nil {'
RACE=1 mutate replay-not-atomic journal.go TestReplayConcurrent 'return m.claimLocked(jobID, notAfter, now)' 'm.mu.Unlock(); defer m.mu.Lock(); return m.claimLocked(jobID, notAfter, now)'
mutate journal-not-durable journal.go   TestReplaySurvivesRestart  'mem.seen[id] = t' '_ = id'
mutate journal-torn-fatal  journal.go   TestJournalTornTail        'range lines[:len(lines)-1] {' 'range lines {'
mutate journal-skips-damage journal.go  TestJournalTornTail        'return nil, errors.New("runnerproto: replay journal is corrupt")' 'continue'
mutate tmp-not-synced      journal.go   TestJournalDurable         'if err := syncFile(f); err != nil {' 'if err := error(nil); err != nil {'
mutate dir-not-synced      journal.go   TestJournalDurable         'return syncFile(d)' 'return nil'
mutate claim-not-synced    journal.go   TestJournalDurable         'if err := syncFile(j.f); err != nil {' 'if err := error(nil); err != nil {'
mutate broken-ignored      journal.go   TestJournalBrokenAfterFailedSync 'if j.broken {' 'if false {'
mutate claim-before-checks sign.go      TestRejectedJobDoesNotClaim 'j, err := DecodeJob(sj.Payload)' 'j, err := DecodeJob(sj.Payload); if err == nil { _ = journal.Claim(j.JobID, j.NotAfter, now) }'
mutate non-canonical-ok    canonical.go TestNonCanonicalRejected   'if !bytes.Equal(encodeJob(j), b) {' 'if false {'
mutate long-lifetime       job.go       TestInvalidJobs            'case j.NotAfter.Sub(j.IssuedAt) > MaxJobTTL:' 'case false:'
# tagTargetConsumer must stay appended after tagNonce, never inserted between
# existing tags (see the tag block's doc comment for the incident this
# guards): re-inserting it between tagTargetUnit and tagTargetMode — one
# `mutate` from/to can't express a line moving, hence mutateN — must break
# decoding of a job encoded by the previous binary.
mutateN canonical-tag-reordered TestDecodeJobAcceptsPreConsumerWireFormat \
	canonical.go '\ttagTargetConsumer' '' \
	canonical.go '\ttagTargetUnit' '\ttagTargetUnit\n\ttagTargetConsumer'

# Same rule, caught from the other direction: the encode CALL for Consumer
# moved back to right after Unit (before Mode/UID/GID/Nonce) instead of
# after Nonce — a mid-list insertion of the emitted byte order, not the tag
# constant this time. The decoder's own ascending-tag check already refuses
# the result, but nothing asserted that refusal before TestConsumerRoundTrip.
mutateN consumer-out-of-order TestConsumerRoundTrip \
	canonical.go 'e.opt(tagTargetConsumer, j.Target.Consumer)' '' \
	canonical.go 'e.opt(tagTargetUnit, j.Target.Unit)' 'e.opt(tagTargetUnit, j.Target.Unit)\n\te.opt(tagTargetConsumer, j.Target.Consumer)'

# Decoder silently drops a field it recognizes the tag for: caught today only
# by the one-encoding re-check (the decoded job, missing Consumer, re-encodes
# to different bytes than the signed payload), not by any assertion that the
# field itself made it into the decoded Job.
mutate consumer-not-decoded canonical.go TestConsumerRoundTrip 'j.Target.Consumer = s' '_ = s'

# Host policy: a compromised server's signed job cannot widen what the host
# actually does — deploy target allowlist, agent ownership, and the
# consumer unit a deploy job may ask the runner to restart.
mutate no-consumer-allowlist policy.go   TestConsumerUnitMustBeAllowlisted 'if t.Consumer != "" && !consumerAllowed(p, t) {' 'if false {'
# Check's own ActionVerify branch returns before the allowlist check above
# ever runs, so a verify job naming a consumer has nothing there to catch
# it — Job.Validate is the only gate. Without it, no-consumer-allowlist
# above would prove nothing for a verify job with a Consumer set.
mutate verify-consumer-unchecked job.go  TestVerifyJobRejectsConsumer 'if j.Action == ActionVerify && j.Target.Consumer != "" {' 'if false {'
# A launchd restart is bound to the job's uid: drop the uid check, or flip
# its deny-by-default (empty unit_uids permitting any uid), and the pair is
# no longer what the host authorised.
mutate launchd-uid-unchecked  policy.go TestLaunchdConsumerBoundToUID 'return slices.Contains(r.UnitUIDs, t.UID)' 'return true'
mutate launchd-uid-default-open policy.go TestPolicyWithoutUnitUIDsDeniesLaunchd 'return slices.Contains(r.UnitUIDs, t.UID)' 'return len(r.UnitUIDs) == 0 || slices.Contains(r.UnitUIDs, t.UID)'
mutate unit-uid-range-unchecked policy.go TestPolicyWithoutUnitUIDsDeniesLaunchd 'if uid < 0 || uid > 1<<31-1 {' 'if false {'
mutate unit-uid-upper-unchecked policy.go TestPolicyWithoutUnitUIDsDeniesLaunchd 'if uid < 0 || uid > 1<<31-1 {' 'if uid < 0 {'
mutate health-non-loopback-ok policy.go  TestHostPolicyRefusesNonLoopbackHealthCheck ' || !loopbackHTTPHosts[u.Hostname()]' ''
mutate health-no-marker-required policy.go TestHealthCheckValidate 'h.BodyMarker == "" || len(h.BodyMarker) > maxHealthMarkerLen' 'false'

# Value delivery: bound to the job, released once, only to its runner.
mutate verify-key-domain     value.go     TestVerifyKeyInfoIsItsOwnDomainBoundToNonceAndWindow 'keep/fingerprint-key/verify/v1' 'keep/fingerprint-key/v1'
mutate verify-key-nonce-unbound value.go  TestVerifyKeyInfoIsItsOwnDomainBoundToNonceAndWindow 'e.field(tagNonce, j.Nonce)' ''
mutate verify-key-issued-unbound value.go TestVerifyKeyInfoIsItsOwnDomainBoundToNonceAndWindow 'e.i64(tagIssuedAt, j.IssuedAt.Unix())' ''
mutate verify-key-window-unbound value.go TestVerifyKeyInfoIsItsOwnDomainBoundToNonceAndWindow 'e.i64(tagNotAfter, j.NotAfter.Unix())' ''
mutate info-unbound        value.go     TestInfoBindsJob           'e.str(tagRunnerID, j.RunnerID)' ''
FAIL_LINE_ONLY=1 mutate info-scope-unbound value.go TestInfoHPKEBindsSecret 'e.str(tagSecretScope, j.Secret.Scope)' ''
FAIL_LINE_ONLY=1 mutate info-provider-unbound value.go TestInfoHPKEBindsSecret 'e.str(tagProvider, j.Secret.Provider)' ''
# A tag inserted between two existing ones (not appended at the end)
# renumbers every following tag; Info's byte output for a fixed job then
# changes even though none of that job's fields did.
mutate tag-inserted-mid-list canonical.go TestInfoHistoricalWireFormat 'tagOrgID' 'tagInsertedForTest; tagOrgID'
# Info doesn't use any tag after tagExpectedFingerprint, so an insertion
# there leaves Info's pin green — only the Job/ExecJob pins would notice.
mutate tag-inserted-before-action canonical.go TestJobHistoricalWireFormat 'tagAction' 'tagInsertedForTest2; tagAction'
mutate tag-inserted-before-execdigest canonical.go TestExecJobHistoricalWireFormat 'tagExecDigest' 'tagInsertedForTest3; tagExecDigest'
# A binary tag missing from binaryTag's switch is wrongly UTF-8-checked; a
# nonce that happens not to be valid UTF-8 is then rejected instead of
# accepted.
mutate binarytag-forgot-nonce canonical.go TestNonUTF8NonceRoundTrips 'case tagNonce, tagExecParams, tagTargetMode, tagTargetUID, tagTargetGID, tagIssuedAt, tagNotAfter:' 'case tagExecParams, tagTargetMode, tagTargetUID, tagTargetGID, tagIssuedAt, tagNotAfter:'
mutate release-any-runner  value.go     TestCheckRelease           'job.OrgID != peer.OrgID || job.RunnerID != peer.RunnerID' 'false'
mutate release-twice       value.go     TestCheckRelease           'case released:' 'case false:'
mutate release-verify      value.go     TestCheckRelease           '!job.NeedsValue() || job.Secret.Provider != ProviderBuiltin' 'job.Secret.Provider != ProviderBuiltin'

# Result: closed list, strict decoding.
mutate result-extra-field  result.go    TestResultClosedList       'ErrorClass  ErrorClass   `json:"error_class,omitempty"`' 'ErrorClass  ErrorClass   `json:"error_class,omitempty"`; Stdout string `json:"stdout,omitempty"`'
mutate result-byte-field   result.go    TestNoValueCarrier         'ErrorClass  ErrorClass   `json:"error_class,omitempty"`' 'ErrorClass  ErrorClass   `json:"error_class,omitempty"`; Raw []byte `json:"-"`'
mutate case-insensitive    result.go    TestDecodeResult           'if !exactKeys(b, resultKeys) {' 'if false {'
mutate nested-case         result.go    TestDecodeResult           '&& !exactKeys(raw, healthcheckKeys)' '&& false'
mutate result-trailing-ok  result.go    TestDecodeResult           'if !atEOF(dec) {' 'if dec.More() {'
mutate free-error-class    result.go    TestDecodeResult           'case !r.OK && !errorClasses[r.ErrorClass]:' 'case !r.OK && r.ErrorClass == "":'
# The canary detector itself: a job that does carry the canary (here in the
# target path, as a stand-in for any future field) must be caught.
mutate canary-detector     runnerproto_test.go TestCanaryNeverInProtocol 'j.ExpectedFingerprint = fp' 'j.ExpectedFingerprint = fp; j.Target.Path = "/etc/keep/" + val'
# The same at an offset inside base64 (the value's first byte is not the
# first byte of a base64 group).
mutate canary-shifted      runnerproto_test.go TestCanaryNeverInProtocol 'j.ExpectedFingerprint = fp' 'j.ExpectedFingerprint = fp; j.Target.Path = "/etc/keep/" + base64.RawURLEncoding.EncodeToString([]byte("x"+val))'

# Host policy: independent of the server, deny by default.
mutate any-path            policy.go    TestHostPolicyOverridesServer 'if under(t.Path, pre) && r.allowsField(t) {' 'if (under(t.Path, pre) || true) && r.allowsField(t) {'
mutate prefix-lookalike    policy.go    TestHostPolicyOverridesServer 'return strings.HasPrefix(p, prefix+"/")' 'return strings.HasPrefix(p, prefix)'
mutate agent-owner-ok      policy.go    TestHostPolicyOverridesServer 'if contains(p.AgentUIDs, t.UID) {' 'if false {'
mutate world-readable-ok   policy.go    TestHostPolicyOverridesServer 'case t.Mode&0o007 != 0:' 'case false:'
mutate uid-shared-prod-ok  policy.go    TestHostPolicyOverridesServer 'if p.UIDShared && j.Secret.Scope == ProdScope && j.NeedsValue() {' 'if false {'
mutate exec-allowed        policy.go    TestHostPolicyOverridesServer 'if !p.AllowExec {' 'if false {'
mutate no-clean-path       policy.go    TestInvalidJobs            'case path.Clean(p) != p:' 'case path.Clean(p) == "":'
mutate relative-path-ok    policy.go    TestInvalidJobs            'case !strings.HasPrefix(p, "/"):' 'case false:'
mutate policy-trailing-ok  policy.go    TestParseHostPolicy        'if !atEOF(dec) {' 'if dec.More() {'
mutate policy-lenient      policy.go    TestParseHostPolicy        'dec.DisallowUnknownFields()' ''
# Field names (threat model 7.1): allowed per rule, echo names never.
mutate field-any           policy.go    TestHostPolicyOverridesServer 'if under(t.Path, pre) && r.allowsField(t) {' 'if under(t.Path, pre) {'
mutate field-any-name      policy.go    TestHostPolicyOverridesServer 'if f == t.Field {' 'if f != "" {'
mutate echo-allowed        policy.go    TestHostPolicyFieldRules   'if echoField(f) {' 'if false {'
mutate echo-case-sensitive policy.go    TestHostPolicyFieldRules   'name := strings.ToUpper(field[strings.LastIndex(field, ".")+1:])' 'name := field[strings.LastIndex(field, ".")+1:]'
mutate echo-whole-key      policy.go    TestHostPolicyFieldRules   'name := strings.ToUpper(field[strings.LastIndex(field, ".")+1:])' 'name := strings.ToUpper(field)'
mutate echo-no-names       policy.go    TestHostPolicyFieldRules   'if echoNames[name] {' 'if echoNames[name] && false {'
mutate echo-no-prefixes    policy.go    TestHostPolicyFieldRules   'if strings.HasPrefix(name, p) {' 'if strings.HasPrefix(name, p) && false {'
mutate echo-no-suffix      policy.go    TestHostPolicyFieldRules   'if strings.HasSuffix(name, s) {' 'if strings.HasSuffix(name, s) && false {'
mutate echo-no-round4-suffixes policy.go TestHostPolicyFieldRules '"_OPTS", "_OPTIONS", "_ARGS", "_OPT",' '"_OPTS",'
mutate echo-no-ccc         policy.go    TestHostPolicyFieldRules   '"CCC_",' ''
mutate echo-no-make-vars   policy.go    TestHostPolicyFieldRules   '"TARGET_ARCH": true, "LDLIBS": true, "LOADLIBES": true,' ''
mutate echo-no-toolchain   policy.go    TestHostPolicyFieldRules   '"SDKROOT": true, "DEVELOPER_DIR": true, "LIBRARY_PATH": true,' ''
mutate echo-exception-none policy.go    TestHostPolicyFieldRules   'if credentialNames[name] {' 'if false {'
mutate echo-exception-wide policy.go    TestHostPolicyFieldRules   'if credentialNames[name] {' 'if credentialNames[name] || strings.HasPrefix(name, "GIT_") || strings.HasPrefix(name, "NODE_") {'
# Field name shape (threat model 7.1, card e1f0d8e5): credential-shaped names
# by default, anything else only on the rule's explicit opt-in, reported by
# Warnings; the echo list stays as the second layer.
T=TestHostPolicyCredentialShapedFields
mutate shape-off           policy.go    $T 'if !r.AllowNonCredentialName && !credentialShaped(f) {' 'if false {'
mutate shape-optin-ignored policy.go    $T 'if !r.AllowNonCredentialName && !credentialShaped(f) {' 'if !credentialShaped(f) {'
mutate shape-no-underscore policy.go    $T '`^[A-Z0-9_]*_(TOKEN|KEY|SECRET|PASSWORD|API_KEY|CREDENTIAL)$`' '`^[A-Z0-9_]*(TOKEN|KEY|SECRET|PASSWORD|API_KEY|CREDENTIAL)$`'
mutate shape-no-end-anchor policy.go    $T '|CREDENTIAL)$`' '|CREDENTIAL)`'
mutate shape-no-start-anchor policy.go $T '`^[A-Z0-9_]*_(TOKEN' '`[A-Z0-9_]*_(TOKEN'
mutate shape-first-segment policy.go    $T 'last := field[strings.LastIndex(field, ".")+1:]' 'last := field'
mutate warnings-none       policy.go    $T 'if !r.AllowNonCredentialName {' 'if true {'
mutate warnings-all        policy.go    $T 'if !credentialShaped(f) {' 'if true {'
mutate echo-no-review-names policy.go   $T '"LINT": true, "MAKE": true, "MAKE_COMMAND": true, "RSYNC_RSH": true,' ''
mutate echo-no-key-path-suffixes policy.go $T '"_CLIENT_KEY", "_TLS_KEY", "_SSL_KEY"}' '"_PROXY"}'
mutate echo-no-tf-var      policy.go    $T '"TF_VAR_",' ''
mutate echo-no-etcdctl-key policy.go    $T '"ETCDCTL_KEY": true,' ''
mutate echo-no-review-prefixes policy.go $T '"COMPOSE_", "RUBY_", "OBJCPLUS_", "TF_CLI_ARGS", "CMAKE_",' ''
mutate echo-exception-prefix policy.go  TestHostPolicyFieldRules   'if credentialNames[name] {' 'if credentialNames[name] || strings.HasPrefix(name, "GIT_TOKEN") {'
mutate echo-exception-case policy.go    TestHostPolicyFieldRules   'if credentialNames[name] {' 'if credentialNames[field[strings.LastIndex(field, ".")+1:]] {'
mutate mcp-key-any-shape  policy.go    TestHostPolicyFieldRules   'if r.Kind == TargetMCPConfig && !mcpEnvKeyRe.MatchString(f) {' 'if false {'
mutate go-settings-off     policy.go    TestHostPolicyFieldRules   'if strings.HasPrefix(name, "GO") && !strings.Contains(name, "_") {' 'if false {'
mutate go-settings-any     policy.go    TestHostPolicyFieldRules   'if strings.HasPrefix(name, "GO") && !strings.Contains(name, "_") {' 'if strings.HasPrefix(name, "GO") {'
mutate fileless-rule-kind  policy.go    TestHostPolicyFieldRules   'if !kindHasField(r.Kind) {' 'if false {'
mutate fileless-job-kind   policy.go    TestHostPolicyOverridesServer 'if !kindHasField(t.Kind) {' 'if true {'
mutate mcp-kind-no-field   job.go       TestHostPolicyFieldRules   'case TargetEnvFile, TargetLaunchdEnv, TargetMCPConfig, TargetHermesConfig:' 'case TargetEnvFile, TargetLaunchdEnv, TargetHermesConfig:'
mutate field-malformed-ok  policy.go    TestHostPolicyFieldRules   'if err := (Target{Kind: r.Kind, Field: f}).validateField(); err != nil {' 'if err := error(nil); err != nil {'
mutate rule-without-fields policy.go    TestHostPolicyFieldRules   'if len(r.Fields) == 0 {' 'if false {'
mutate fields-on-fileless  policy.go    TestHostPolicyFieldRules   'if len(r.Fields) != 0 {' 'if false {'
mutate policy-any-owner    policy_unix.go TestLoadHostPolicyFile   'case !ok || int64(st.Uid) != int64(ownerUID):' 'case !ok || st == nil:'
mutate policy-any-mode     policy_unix.go TestLoadHostPolicyFile   'case fi.Mode().Perm()&0o077 != 0:' 'case false:'
mutate policy-symlink      policy_unix.go TestLoadHostPolicyFile   'os.O_RDONLY|syscall.O_NOFOLLOW' 'os.O_RDONLY'
mutate prefix-symlink-ok   policy_unix.go TestCheckPrefixesOnHost  'case fi.Mode()&fs.ModeSymlink != 0:' 'case false:'
mutate prefix-file-ok      policy_unix.go TestCheckPrefixesOnHost  'case !fi.IsDir():' 'case false:'
mutate prefix-check-noop   policy_unix.go TestCheckPrefixesOnHost  'if err := checkPrefixOnHost(pre); err != nil {' 'if err := error(nil); err != nil {'
mutate prefix-missing-fails policy_unix.go TestCheckPrefixesOnHost 'case errors.Is(err, fs.ErrNotExist):' 'case false:'
mutate no-rate-limit       policy.go    TestLimiter                'if len(l.times) >= l.max {' 'if false {'

# And the unmutated tree must be green, or every "red" above means nothing.
if mutation_apply_only; then
	:
elif (cd "$root" && go test -timeout 120s -count=1 ./$dir/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
