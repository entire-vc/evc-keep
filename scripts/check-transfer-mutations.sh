#!/bin/sh
# Proves the offline-transfer crypto tests can fail: in a scratch copy of the
# tree, switch off one property of the HPKE transport, the KEK rewrap, the
# manifest binding, the root checks or the org CA authentication at a time and
# require `go test -run Transfer` over internal/builtin, orgpki and transfercarrier to go red.
# A property whose removal leaves the tests green is not tested. Exits 0 only
# if every mutation is caught and the real code is green. Needs no database.
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
pkgs="./internal/builtin/ ./internal/builtin/orgpki/ ./internal/transfercarrier/"
run='Transfer|IsOrgPKIKEK|Destroy'

fail=0
# mutate NAME FILE FROM TO: replace the first literal occurrence of FROM with TO.
mutate() {
	name=$1 src=$2 from=$3 to=$4
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$src" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 120s -count=1 -run "$run" $pkgs >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		# Red because the mutant does not build is not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

T=internal/builtin/transfer_transport.go
B=internal/builtin/transfer_bundle.go
W=internal/builtin/transfer_rewrap.go
# the HPKE info/AAD binds every context field, length-prefixed
mutate ctx-drop-workspace   $T 'c.Org, c.Workspace} {' 'c.Org} {'
mutate ctx-drop-transfer    $T '[]string{c.Protocol, c.Transfer,' '[]string{c.Protocol,'
mutate ctx-drop-schema      $T 'put(schema[:])' '_ = schema'
mutate ctx-no-length-prefix $T 'out = append(out, n[:]...)' '_ = n'
# (Open's own recipient-key comparison repeats what HPKE already binds into
# the key schedule, so no mutation of it can be killed)
mutate seal-no-pub-check    $T '|| !bytes.Equal(recipientPub, tc.RecipientPub) {' '{'
# the bundle is strict and bound to the pinned identities
mutate manifest-no-workspace $B 'm.OrgID == tc.Org && m.WorkspaceID == tc.Workspace &&' 'm.OrgID == tc.Org &&'
mutate unknown-fields       $B 'dec.DisallowUnknownFields()' '_ = dec'
mutate trailing-data        $B 'if _, err := dec.Token(); !errors.Is(err, io.EOF) {' 'if _, err := dec.Token(); !errors.Is(err, io.EOF) && false {'
# (the root id and org checks in rewrapKEKRows repeat what RewrapKEK
# authenticates; they are defence in depth and no mutation can be killed there)
# the KEK rewrap really moves the key to an independent root
mutate same-root-accepted   $W 'return opensProbe(target, wrapped)' 'return opensProbe(target, wrapped) && false'
mutate domain-key-unchecked $W 'return sc, r.DomainKey == want' 'return sc, r.DomainKey == want || true'
# the target must not be the SOURCE key material (each hop compares only with
# the one-shot transport root): a probe wrapped by the source root travels in
# the bundle and the importer's root must not open it
mutate probe-check-noop      $B 'if len(b.Probe) == 0 || opensProbe(target.k, b.Probe) {' 'if false {'
mutate probe-open-ignored    $B 'if len(b.Probe) == 0 || opensProbe(target.k, b.Probe) {' 'if len(b.Probe) == 0 {'
mutate probe-absence-allowed $B 'if len(b.Probe) == 0 || opensProbe(target.k, b.Probe) {' 'if opensProbe(target.k, b.Probe) {'
mutate probe-wrapped-by-transport $B 'wrappedProbe, err := source.k.Wrap(probe, []byte(rootIndependenceAAD))' 'wrappedProbe, err := troot.Wrap(probe, []byte(rootIndependenceAAD))'
mutate probe-aad-unbound     $W 'plain, err := root.Unwrap(wrapped, []byte(rootIndependenceAAD))' 'plain, err := root.Unwrap(wrapped, []byte("x"))'
mutate probe-build-aad      $B 'wrappedProbe, err := source.k.Wrap(probe, []byte(rootIndependenceAAD))' 'wrappedProbe, err := source.k.Wrap(probe, []byte("x"))'
# the org CA is authenticated under the target root, from the org's own PKI KEKs
mutate pki-kek-any-domain   internal/builtin/orgpki/transfer_authenticate.go 'strings.HasPrefix(k.DomainKey, "pki:") &&' '(strings.HasPrefix(k.DomainKey, "pki:") || true) &&'
mutate pki-many-cas         internal/builtin/orgpki/transfer_authenticate.go 'len(rows.OrgCAs) != 1 || ' ''
# a committed import destroys the recipient key: zero it, then remove it, never through a symlink
C=internal/transfercarrier/carrier.go
mutate destroy-no-zero      $C 'f.Write(zeros[:n])' 'f.Write(zeros[:0])'
mutate destroy-no-remove    $C 'if os.Remove(path) != nil {' 'if false && os.Remove(path) != nil {'
mutate destroy-follows-link $C 'syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK' 'syscall.O_WRONLY|syscall.O_NONBLOCK'

# the approval carrier is accepted only under the pin the source operator
# handed over: hashing the very bytes that are parsed, never a pin from the
# carrier, never absent. These tests need no database.
pkgs=./cmd/keep-server/app/
run='TestVerifyApprovalNeedsTheIndependentPin|TestApprovalMatchesOnlyTheSameTransfer'
A=cmd/keep-server/app/offline_transfer_import_cmd.go
mutate approval-pin-noop    $A 'if !hex64.MatchString(pin) || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pin)) != 1 {' 'if sum[0] == 0 && false {'
mutate approval-pin-bundle-sum $A 'subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pin)) != 1 {' 'subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pin)) != 1 && pin != b.Checksum {'
mutate approval-fields-skipped $A 'if !approvalMatches(raw, b) {' 'if false {'

# (The call-site mutation, dropping the verifyApproval call from the import,
# needs a real database; it lives in check-audit-mutations.sh.)

if mutation_apply_only; then
	:
elif (cd "$root" && go test -timeout 120s -count=1 -run 'Transfer|IsOrgPKIKEK|Destroy' ./internal/builtin/ ./internal/builtin/orgpki/ ./internal/transfercarrier/ >/dev/null 2>&1 && go test -timeout 120s -count=1 -run "$run" $pkgs >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
