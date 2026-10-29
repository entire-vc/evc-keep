#!/bin/sh
# Proves the discovery tests can fail: in a scratch copy of the
# tree, switch off one property at a time and require the tests of
# internal/runner/discover to go red. A property whose removal
# leaves the tests green is not tested.
#
# Tests use only generated temporary files, never host configuration.
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
. "$root/scripts/temp-workspace.sh"
temp_workspace

fail=0
# edit SRC FROM TO: print SRC with the first literal occurrence of FROM
# replaced by TO; exit 1 if FROM is not there.
edit() {
	python3 - "$1" "$2" "$3" "${4:-1}" <<'PYEDIT'
import pathlib
import sys
source = pathlib.Path(sys.argv[1]).read_text()
old, new, nth = sys.argv[2], sys.argv[3], int(sys.argv[4])
position = -1
for _ in range(nth):
    position = source.find(old, position + 1)
    if position < 0:
        raise SystemExit(1)
sys.stdout.write(source[:position] + new + source[position + len(old):])
PYEDIT
}

pkgs="./internal/runner/discover/"

# mutate NAME FILE FROM TO [WANT]: FILE is relative to the repo root. WANT,
# when given, is a space-separated list of exact failing test/subtest names that MUST
# all appear in the red run — a mutant is not proven to isolate the property
# it claims to just because *some* test went red; the wrong test catching it
# (a different, unrelated check that happened to also depend on the mutated
# line) proves nothing about the property WANT names. Mirrors the
# `--- FAIL: WANT` check in check-identity-attack-mutations.sh.
mutate() {
	name=$1 src=$2 from=$3 to=$4 want=${5:-} occurrence=${6:-1}
	rm -rf "$work/tree"
	mkdir -p "$work/tree"
	(cd "$root" && tar --exclude=.git --exclude=.gocache --exclude=.gomodcache --exclude=.lintcache -cf - .) | (cd "$work/tree" && tar -xf -)
	python3 "$root/scripts/instrument-discovery-wipes.py" "$work/tree"
	if ! edit "$work/tree/$src" "$from" "$to" "$occurrence" >"$work/edited"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mv "$work/edited" "$work/tree/$src"
	mutation_applied "$name" && return
	# shellcheck disable=SC2086
	if (cd "$work/tree" && go test -tags=discover_wipecheck -timeout 90s -count=1 -p 1 -v $pkgs >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
		return
	fi
	if grep -q -E 'panic: test timed out|\[build failed\]|\[setup failed\]|--- SKIP' "$work/out"; then
		echo "FAIL $name: invalid test run (timeout, build/setup failure, or skip)"
		fail=1
		return
	fi
	if ! grep -q -- '--- FAIL' "$work/out"; then
		# Red because the mutant does not build, or every test skipped, is
		# not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error, or a silent skip?)"
		fail=1
		return
	fi
	missing=""
	for w in $want; do
		grep -q -F -- "--- FAIL: $w (" "$work/out" || missing="$missing $w"
	done
	if [ -n "$missing" ]; then
		echo "FAIL $name: red, but not on:$missing (the wrong test/subtest caught it):"
		grep -- '--- FAIL' "$work/out" | head -5
		fail=1
		return
	fi
	echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)${want:+, confirmed on: $want}"
}

# Turn off independently observable tenant guards and require the isolation
# test itself (not an unrelated schema failure) to catch each mutation.
mutate plaintext-in-finding internal/runner/discover/scan.go \
 'Fingerprint: fp' 'Fingerprint: string(raw)' 'TestCanarySurfaces TestBinaryPlist'
mutate unknown-reissue internal/runner/discover/scan.go \
 'Verdict: UnknownFind' 'Verdict: Verdict("reissue")' 'TestMissingActiveIsUnknownFind'
mutate symlink-followed internal/runner/discover/read_unix.go \
 'const noFollow = unix.O_NOFOLLOW' 'const noFollow = 0' 'TestPolicyAndSymlinks'
mutate size-preflight-off internal/runner/discover/read_unix.go \
 'if info.Size() > limit {' 'if false && info.Size() > limit {' 'TestSizeLimitNoRead'
mutate writable-root-accepted internal/runner/discover/read_unix.go \
 'info.Mode().Perm()&0o022 != 0' '(false && info.Mode().Perm()&0o022 != 0)' 'TestWritableRootRefused'
mutate writable-root-ancestor-accepted internal/runner/discover/read_unix.go \
 'parentInfo.Mode().Perm()&0o022 != 0' '(false && parentInfo.Mode().Perm()&0o022 != 0)' 'TestWritableRootAncestorRefused'
mutate inactive-missing-classified internal/runner/discover/scan.go \
 'if k.Active && !seen[' 'if !seen[' 'TestMissingInactiveCarrierIgnored'
mutate untrusted-owner-admitted internal/runner/discover/read_unix.go \
 'st.Uid == uid' 'st.Uid == uid || len(owners) > 0' 'TestTrustedOwnersRequired'
mutate unmatched-enumeration-unbounded internal/runner/discover/read_unix.go \
 'if examined > limit*64 {' 'if false && examined > limit*64 {' 'TestUnmatchedDirectoryEntriesBounded'
mutate hardlink-accepted internal/runner/discover/read_unix.go \
 'st.Nlink != 1' '(false && st.Nlink != 1)' 'TestHardlinksPermissionsAndAtomicFailure'
mutate writable-accepted internal/runner/discover/read_unix.go \
 'if err != nil || info.Mode().Perm()&0o022 != 0 || !ownerAllowed(info, owners) || (i < len(parts)-1 || directory) && !info.IsDir() {' 'if err != nil || (false && info.Mode().Perm()&0o022 != 0) || !ownerAllowed(info, owners) || (i < len(parts)-1 || directory) && !info.IsDir() {' 'TestHardlinksPermissionsAndAtomicFailure'
mutate stale-as-match internal/runner/discover/scan.go \
 'subtle.ConstantTimeCompare([]byte(f.Fingerprint), []byte(k.Fingerprint)) == 1' 'subtle.ConstantTimeCompare([]byte(f.Fingerprint), []byte(k.Fingerprint)) >= 0' 'TestClassification TestFullFingerprintAndTenantKeys'
mutate sprawl-as-match internal/runner/discover/scan.go \
 'verdict := Sprawl' 'verdict := Match' 'TestClassification'
mutate foreign-key-accepted internal/runner/discover/scan.go \
 'return p.KeyID == keyID' 'return p.KeyID == keyID || len(keyID) > 0' 'TestFullFingerprintAndTenantKeys TestConsistentlyForeignKeyRejected'
mutate old-buffer-not-wiped internal/runner/discover/scan.go \
 'wipe(dst)' '_ = dst' 'TestBufferGrowthWipesOldCopy'

mutate names-casefold internal/runner/discover/parse.go \
 'bytes.Equal(e.name, []byte(name))' 'bytes.EqualFold(e.name, []byte(name))' 'TestNamesExactAdmission'
mutate names-prefix internal/runner/discover/parse.go \
 'bytes.Equal(e.name, []byte(name))' 'bytes.HasPrefix(e.name, []byte(name))' 'TestNamesExactAdmission'
mutate env-double-escape-unchecked internal/runner/discover/parse.go \
 '&& !doubleEscape {' '&& false && !doubleEscape {' 'TestEnvDoubleQuotedEscapes'
mutate binary-plist-error-leak internal/runner/discover/parse.go \
 'return nil, ErrParse' 'return nil, xml.UnmarshalError(string(data))' 'TestBinaryPlist'
mutate fingerprint-suffix-ignored internal/runner/discover/scan.go \
 '[]byte(f.Fingerprint), []byte(k.Fingerprint)' '[]byte(f.Fingerprint[:len(f.Fingerprint)-2]), []byte(k.Fingerprint[:len(k.Fingerprint)-2])' 'TestFingerprintLastByte'
mutate malformed-pair-accepted internal/runner/discover/scan.go \
 'p, err := fingerprint.Parse(fp)' 'p, err := fingerprint.Parse(fp); if err != nil { p.KeyID = keyID; err = nil }' 'TestMalformedPairRejected'
mutate scan-key-precheck-off internal/runner/discover/scan.go \
 'if _, err := fingerprint.Compute(key, secret.Value{}); err != nil {' 'if _, err := fingerprint.Compute(key, secret.Value{}); false && err != nil {' 'TestInvalidScanKeyOnEmptyRoot'
mutate json-duplicates-accepted internal/runner/discover/json.go \
 'if bytes.Equal(old, k) {' 'if false && bytes.Equal(old, k) {' 'TestJSONStructuralDuplicatesAndKeyLimit'
mutate json-key-unbounded internal/runner/discover/json.go \
 'len(k) > 256' 'len(k) > 100000' 'TestJSONStructuralDuplicatesAndKeyLimit'
mutate read-growth-unbounded internal/runner/discover/read_unix.go \
 'make([]byte, limit+1)' 'make([]byte, limit)' 'TestWipeReadErrors/growth'
mutate parse-values-not-wiped internal/runner/discover/parse.go \
 'wipe(e.value)' '_ = e.value' 'TestWipeLifecycle/env'
mutate scan-input-not-wiped internal/runner/discover/scan.go \
 'wipe(data)' '_ = data' 'TestWipeLifecycle/env TestWipeLifecycle/env-error-word'
mutate secret-copy-not-wiped internal/runner/discover/scan.go \
 'defer v.Wipe()' '_ = v' 'TestWipeLifecycle/env'
mutate word-growth-not-wiped internal/runner/discover/parse.go \
 'appendWiped(out, []byte{c})' 'append(out, []byte{c}...)' 'TestWipeLifecycle/env'
mutate json-growth-not-wiped internal/runner/discover/json.go \
 'appendWiped(out, []byte{c})' 'append(out, []byte{c}...)' 'TestWipeLifecycle/json'
mutate xml-tree-not-wiped internal/runner/discover/parse.go \
 'defer root.destroy()' '_ = root' 'TestWipeLifecycle/xml'
mutate json-tree-not-wiped internal/runner/discover/json.go \
 'defer root.destroy()' '_ = root' 'TestWipeLifecycle/json'
mutate env-error-word-not-wiped internal/runner/discover/parse.go \
 'wipe(value)' '_ = value' 'TestWipeLifecycle/env-error-word'
mutate read-growth-buffer-not-wiped internal/runner/discover/read_unix.go \
 'wipe(buffer)' '_ = buffer' 'TestWipeReadErrors/growth'

mutate env-error-tail-not-wiped internal/runner/discover/parse.go \
 'wipe(value)' '_ = value' 'TestWipeLifecycle/env-error-tail' 2
mutate unit-error-word-not-wiped internal/runner/discover/parse.go \
 'wipe(value)' '_ = value' 'TestWipeLifecycle/unit-error-word' 3
mutate unit-error-name-not-wiped internal/runner/discover/parse.go \
 'wipe(value)' '_ = value' 'TestWipeLifecycle/unit-error-name' 4
mutate read-short-buffer-not-wiped internal/runner/discover/read_unix.go \
 'wipe(buffer)' '_ = buffer' 'TestWipeReadErrors/short' 2
mutate bplist-top-name-not-wiped internal/runner/discover/bplist.go \
 'wipe(name)' '_ = name' 'TestWipeLifecycle/bplist' 1
mutate bplist-invalid-name-not-wiped internal/runner/discover/bplist.go \
 'wipe(name)' '_ = name' 'TestWipeLifecycle/bplist-error-name' 2
mutate bplist-invalid-value-not-wiped internal/runner/discover/bplist.go \
 'wipe(value)' '_ = value' 'TestWipeLifecycle/bplist-error-name' 1
mutate bplist-budget-name-not-wiped internal/runner/discover/bplist.go \
 'wipe(name)' '_ = name' 'TestWipeLifecycle/bplist-error-budget' 3
mutate bplist-budget-value-not-wiped internal/runner/discover/bplist.go \
 'wipe(value)' '_ = value' 'TestWipeLifecycle/bplist-error-budget' 2
mutate bplist-utf16-error-not-wiped internal/runner/discover/bplist.go \
 'wipe(out)' '_ = out' 'TestWipeLifecycle/bplist-error-utf16' 1

mutate xml-text-not-wiped internal/runner/discover/parse.go \
 'wipe(n.text)' '_ = n.text' 'TestWipeLifecycle/xml'
mutate json-text-not-wiped internal/runner/discover/json.go \
 'wipe(n.text)' '_ = n.text' 'TestWipeLifecycle/json'
mutate json-keys-not-wiped internal/runner/discover/json.go \
 'wipe(k)' '_ = k' 'TestWipeLifecycle/json'
mutate json-encoded-not-wiped internal/runner/discover/json.go \
 'wipe(encoded[:])' '_ = encoded' 'TestWipeLifecycle/json'

mutate compare-key-precheck-off internal/runner/discover/scan.go \
 'if _, err := fingerprint.Compute(key, secret.Value{}); err != nil {' 'if _, err := fingerprint.Compute(key, secret.Value{}); false && err != nil {' 'TestCompareKeyRequired' 2
mutate bplist-encoded-not-wiped internal/runner/discover/bplist.go \
 'wipe(encoded[:])' '_ = encoded' 'TestWipeLifecycle/bplist-error-utf16'

# Regression witnesses for policy, tenant binding, file type, and temporary copies.
mutate policy-root-slash internal/runner/discover/scan.go \
 'filepath.Clean(p.Root) == string(filepath.Separator)' 'false' 'TestPolicyAdmissionBounds/root-slash'
mutate policy-root-relative internal/runner/discover/scan.go \
 '!filepath.IsAbs(p.Root)' 'false' 'TestPolicyAdmissionBounds/root-relative'
mutate policy-files-unbounded internal/runner/discover/scan.go \
 'p.MaxFiles > 4096' 'false' 'TestPolicyAdmissionBounds/files-over-limit'
mutate policy-owners-unbounded internal/runner/discover/scan.go \
 'len(p.TrustedUIDs) > 32' 'false' 'TestPolicyAdmissionBounds/owners-over-limit'
mutate tenant-key-prefix internal/runner/discover/scan.go \
 'return p.KeyID == keyID' 'return strings.HasPrefix(p.KeyID, keyID)' 'TestTenantKeyPrefixRejected/finding TestTenantKeyPrefixRejected/known TestTenantKeyPrefixRejected/both TestTenantKeyPrefixRejected/known-only'
mutate known-key-unchecked internal/runner/discover/scan.go \
 '!validName(k.Name) || !check(k.Fingerprint)' '!validName(k.Name)' 'TestTenantKeyPrefixRejected/known TestTenantKeyPrefixRejected/known-only'
mutate nonregular-admitted internal/runner/discover/read_unix.go \
 '!info.Mode().IsRegular() || !ok' '!ok' 'TestNonRegularFilesRefused/fifo TestNonRegularFilesRefused/device'
mutate bplist-low-surrogate-not-wiped internal/runner/discover/bplist.go \
 'wipe(out)' '_ = out' 'TestWipeGrowthBoundaries/bplist-error-low-surrogate' 2
mutate bplist-utf16-growth-not-wiped internal/runner/discover/bplist.go \
 'appendWiped(out, encoded[:n])' 'append(out, encoded[:n]...)' 'TestWipeGrowthBoundaries/bplist-growth'
mutate xml-growth-not-wiped internal/runner/discover/parse.go \
 'appendWiped(parent.text, token)' 'append(parent.text, token...)' 'TestWipeGrowthBoundaries/xml-growth'
mutate json-escape-growth-not-wiped internal/runner/discover/json.go \
 'appendWiped(out, []byte{c})' 'append(out, []byte{c}...)' 'TestWipeGrowthBoundaries/json-quote TestWipeGrowthBoundaries/json-backslash TestWipeGrowthBoundaries/json-slash' 2
mutate json-unicode-growth-not-wiped internal/runner/discover/json.go \
 'appendWiped(out, encoded[:count])' 'append(out, encoded[:count]...)' 'TestWipeGrowthBoundaries/json-unicode'
mutate json-backspace-growth-not-wiped internal/runner/discover/json.go \
 'appendWiped(out, []byte{'\''\b'\''})' 'append(out, []byte{'\''\b'\''}...)' 'TestWipeGrowthBoundaries/json-backspace'
mutate json-formfeed-growth-not-wiped internal/runner/discover/json.go \
 'appendWiped(out, []byte{'\''\f'\''})' 'append(out, []byte{'\''\f'\''}...)' 'TestWipeGrowthBoundaries/json-formfeed'
mutate json-newline-growth-not-wiped internal/runner/discover/json.go \
 'appendWiped(out, []byte{'\''\n'\''})' 'append(out, []byte{'\''\n'\''}...)' 'TestWipeGrowthBoundaries/json-newline'
mutate json-return-growth-not-wiped internal/runner/discover/json.go \
 'appendWiped(out, []byte{'\''\r'\''})' 'append(out, []byte{'\''\r'\''}...)' 'TestWipeGrowthBoundaries/json-return'
mutate json-tab-growth-not-wiped internal/runner/discover/json.go \
 'appendWiped(out, []byte{'\''\t'\''})' 'append(out, []byte{'\''\t'\''}...)' 'TestWipeGrowthBoundaries/json-tab'

# The unmutated tree is green: a script whose baseline is red proves nothing.
mutation_apply_only && exit "$fail"
rm -rf "$work/tree"
mkdir -p "$work/tree"
	(cd "$root" && tar --exclude=.git --exclude=.gocache --exclude=.gomodcache --exclude=.lintcache -cf - .) | (cd "$work/tree" && tar -xf -)
python3 "$root/scripts/instrument-discovery-wipes.py" "$work/tree"
# shellcheck disable=SC2086
if (cd "$work/tree" && go test -race -tags=discover_wipecheck -timeout 90s -count=1 -p 1 -v $pkgs >"$work/out" 2>&1); then
	if grep -q -- '--- SKIP' "$work/out"; then
        echo "FAIL baseline: skipped tests"
        fail=1
    else
        echo "ok   baseline: tests green on the real code (0 SKIP)"
    fi
else
	echo "FAIL baseline: tests are red on the real code"
	grep -A3 -- "--- FAIL" "$work/out" || tail -20 "$work/out"
	fail=1
fi

exit "$fail"
