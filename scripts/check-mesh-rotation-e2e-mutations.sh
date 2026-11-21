#!/bin/sh
# Proves the Mesh key rotation e2e (plugins/mesh/e2e_test.go) can fail: in a
# scratch copy of the tree, switch off one property of the engine, the
# adapters or the plugin at a time and require the e2e to go red, naming the
# scenario that has to catch it. Needs KEEP_DATABASE_URL: without a database
# the e2e is SKIPPED, and a skipped run proves nothing, so that is a failure
# here. Exits 0 only if the baseline is green and every mutation is caught.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
mutation_apply_only || [ -n "${KEEP_DATABASE_URL:-}" ] || { echo "FAIL KEEP_DATABASE_URL is not set: the e2e would skip" >&2; exit 1; }
. "$root/scripts/temp-workspace.sh"
temp_workspace

fail=0
# mutate NAME EXPECT FILE PYTHON: PYTHON edits the string t (a copy of the
# source s of FILE); EXPECT is the test that must be among the failing ones.
# LEAKMSG, when set in the environment, must also appear in the failure output:
# a leak mutant has to be caught by the leak scan, not by a build or state error.
mutate() {
	name=$1 expect=$2 src=$3 prog=$4
	mutation_snapshot "$work/tree"
	if ! SRC="$work/tree/$src" PROG="$prog" NAME="$name" LIB="$root/scripts/lib" python3 -I -c '
import os, sys
sys.path.insert(0, os.environ["LIB"])
from mutation_edit import named_edit
p = os.environ["SRC"]
def edit(text, old, new, occurrence=None):
    return named_edit(os.environ["NAME"], text, old, new, occurrence, p)
s = open(p).read()
t = s
exec(os.environ["PROG"])
if t == s:
    raise SystemExit(1)
open(p, "w").write(t)'; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree/plugins/mesh" && go test -timeout 180s -count=1 -run TestE2E ./... >"$work/out" 2>&1); then
		echo "FAIL $name: e2e stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- "--- FAIL: $expect" "$work/out"; then
		echo "FAIL $name: $expect did not go red (build error, or another test caught it):"
		"$root/scripts/test-result-names.sh" "$work/tree" <"$work/out" ||
			echo "FAIL diagnostics: test-result-names.sh exited $?"
		fail=1
	elif [ -n "${leakmsg:-}" ] && ! grep -q -- "$leakmsg" "$work/out"; then
		echo "FAIL $name: red, but not by the leak scan ($leakmsg missing):"
		"$root/scripts/test-result-names.sh" "$work/tree" <"$work/out" ||
			echo "FAIL diagnostics: test-result-names.sh exited $?"
		fail=1
	else
		echo "ok   $name: $expect went red ($(grep -c -- '--- FAIL' "$work/out" | awk '{print ($1 > 40 ? "40+" : $1)}') failing)"
	fi
}

# The unmutated e2e must be green and must not skip, or every red below proves nothing.
if ! mutation_apply_only; then
(cd "$root/plugins/mesh" && go test -timeout 180s -count=1 -v -run TestE2E ./... >"$work/base" 2>&1) || {
	echo "FAIL baseline is red"
	"$root/scripts/test-result-names.sh" "$root" <"$work/base" ||
		echo "FAIL diagnostics: test-result-names.sh exited $?"
	exit 1
}
if grep -q -- '--- SKIP' "$work/base"; then echo "FAIL baseline skipped a scenario"; exit 1; fi
[ "$(grep -c -- '^--- PASS: TestE2E' "$work/base")" -ge 10 ] || { echo "FAIL baseline ran fewer scenarios than expected"; exit 1; }
fi

leakmsg=
E=internal/rotation/engine.go
P=internal/rotation/provider.go
M=plugins/mesh/mesh.go
# AC mutation: Revoke before the carriers were confirmed. The state machine
# skips verify and the revoke gate is removed with it.
mutate revoke-before-verify TestE2EDualKeyBadCarrierDoesNotActivate $E 't=edit(edit(edit(s, "StateDeploying, StateVerifying, ClassNone", "StateDeploying, StateRevokingOld, ClassNone"), "return StateVerifying, nil", "return StateRevokingOld, nil"), "ok, err := e.store.allVerified(ctx, run.ID)", "ok, err := true, error(nil)")'
mutate verify-ignores-fingerprint TestE2EDualKeyBadCarrierDoesNotActivate $E 't=edit(s, "|| rep.Fingerprint != run.ExpectedFP", "")'
mutate forward-only-no-layout-retry TestE2EForwardOnlyFailureAfterIssue $E 't=edit(s, "attempts = opts.DeployAttempts", "attempts = 1")'
mutate revoke-call-noop TestE2EDualKeyAllCarriersOK $P 't=edit(s, "if err := r.d.Provider.Revoke(ctx, k); err != nil {", "if err := error(nil); err != nil {")'
mutate revoke-and-check-noop TestE2EDualKeyAllCarriersOK $P 't=edit(edit(s, "if err := r.d.Provider.Revoke(ctx, k); err != nil {", "if err := error(nil); err != nil {"), "if st, err := r.d.Provider.Check(ctx, k); err != nil || st.Active {", "_ = k\n\t\t\tif false {")'
# AC mutation: the engine never resolves the "old key alive" incident after a successful retry.
mutate resolve-not-called TestE2EDualKeyRevokeFailureOpensIncident $E 't=edit(s, "if err := e.resolveIncident(sctx, ctx, run); err != nil {", "if err := error(nil); err != nil {")' # pragma: allowlist secret
# An agent with only its original key "primary": the run names it by the alias
# and ends it; without the alias it stays alive behind an incident.
mutate legacy-primary-not-current TestE2EDualKeyLegacyPrimaryIsRevoked $M 't=edit(s, "		if id == primaryKeyID {\n			id = p.alias\n		}", "		if id == primaryKeyID {\n			return \"\", false, nil\n		}")'
mutate legacy-primary-revoke-unmapped TestE2EDualKeyLegacyPrimaryIsRevoked $M 't=edit(s, "\"/\"+p.meshID(keyID)", "\"/\"+keyID")'
mutate resume-issues-again TestE2EResumeAfterCrashDoesNotIssueAgain $P 't=edit(s, "} else if ok {", "} else if ok && false {")'
leakmsg='surfaced in journal' mutate plugin-logs-issue-body TestE2EDualKeyAllCarriersOK $M 't=edit(s, "	var a issueAnswer", "	p.log.Debug(string(body))\n	var a issueAnswer")'
# One mutant per scan surface: each puts the key where the scan has to see it.
leakmsg='surfaced in stdout+stderr' mutate plugin-writes-stderr TestE2EDualKeyAllCarriersOK $M 't=edit(edit(s, "	var a issueAnswer", "	_, _ = os.Stderr.WriteString(string(body))\n	var a issueAnswer"), "\"net/url\"", "\"net/url\"\n\t\"os\"")'
leakmsg='surfaced in stdout+stderr' mutate plugin-writes-fd2 TestE2EDualKeyAllCarriersOK $M 't=edit(edit(s, "	var a issueAnswer", "	_, _ = syscall.Write(2, body)\n	var a issueAnswer"), "\"net/url\"", "\"net/url\"\n\t\"syscall\"")'
leakmsg='surfaced in stdout+stderr' mutate plugin-default-log TestE2EDualKeyAllCarriersOK $M 't=edit(edit(s, "	var a issueAnswer", "	log.Print(string(body))\n	var a issueAnswer"), "\"log/slog\"", "\"log\"\n\t\"log/slog\"")'
leakmsg='surfaced in database' mutate adapter-stores-value-in-db TestE2EDualKeyAllCarriersOK $P 't=edit(s, "	return Version{Old: old, New: meta.Version, Fingerprint: fp, Length: iss.Value.Len()}, nil\n}", "	_, _ = v.d.Ledger.pool.Exec(ctx, \"CREATE TABLE IF NOT EXISTS rotation_zz(x text)\")\n	_, _ = v.d.Ledger.pool.Exec(ctx, \"INSERT INTO rotation_zz VALUES ($1)\", string(leakOf(iss.Value)))\n	return Version{Old: old, New: meta.Version, Fingerprint: fp, Length: iss.Value.Len()}, nil\n}\nfunc leakOf(v secret.Value) []byte {\n	var b []byte\n	secret.Expose(v, func(x []byte) { b = append(b, x...) })\n	return b\n}"); t=edit(t, "\"github.com/entire-vc/evc-keep/pkg/fingerprint\"", "\"github.com/entire-vc/evc-keep/pkg/fingerprint\"\n\t\"github.com/entire-vc/evc-keep/pkg/secret\"")'

leakmsg=
# Revoke retry (R-ROT-3 §3a): a refused Revoke must leave the run retryable.
mutate revoke-failure-terminal TestE2EDualKeyRevokeFailureOpensIncident $E 't=edit(s, "return e.revokePending(ctx, run)", "return e.fail(ctx, run, ClassRevokeFailed)")' # pragma: allowlist secret
mutate revoking-old-not-claimable TestE2EDualKeyRevokeFailureOpensIncident internal/rotation/store.go 't=edit(s, "WHERE id=$1 AND (state NOT IN (\x27done\x27,\x27failed\x27) OR", "WHERE id=$1 AND (state NOT IN (\x27done\x27,\x27failed\x27,\x27revoking_old\x27) OR")' # pragma: allowlist secret
mutate check-after-revoke-ignored TestE2EDualKeyRevokeNotConfirmed $P 't=edit(s, "if st, err := r.d.Provider.Check(ctx, k); err != nil || st.Active {", "if false {")'
mutate healthy-ignored TestE2EDualKeyBadCarrierDoesNotActivate $E 't=edit(s, "case !rep.Healthy:", "case false:")'
mutate dual-key-retries-layout TestE2EDualKeyBadCarrierDoesNotActivate $E 't=edit(s, "	if e.forwardOnly() {\n		attempts", "	if true {\n		attempts")'
mutate forward-only-revokes TestE2EForwardOnlyTwoRotations $P 't=edit(s, "	if r.d.Provider.Capabilities().DualKey {\n		oldKey", "	if true {\n		oldKey")'
# The plugin binary's start refuses a self-rotation account that is the gate's
# actor: the call in runServe and the plugin's option are both needed.
mutate runserve-actor-check-dropped TestE2ESameActorRefusesStart cmd/keep-server/app/main.go 't=edit(s, "	if err := checkSelfRotateActor(expiryCtx, cfg, opts, pool, local.MeshVault(), logger); err != nil {", "	if err := error(nil); err != nil {")'
mutate plugin-actor-option-dropped TestE2ESameActorRefusesStart plugins/mesh/cmd/keep-server/main.go 't=edit(s, ", SelfRotateActor: checkSelfRotateActor}", "}")'
exit $fail
