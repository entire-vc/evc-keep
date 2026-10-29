#!/bin/sh
# Red runs of scripts/check-mutant-anchors.sh and the apply-only mode of
# scripts/mutation-helpers.sh, on stub suites in a scratch repository: a
# stranded anchor, a forgotten go or node run, a silent suite, a FAIL line
# behind exit 0 and a crash after applied mutants must each fail the driver;
# a clean suite must pass.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/keep-anchors-selftest.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
repo=$work/repo
mkdir -p "$repo/scripts/lib"
cp "$root/go.mod" "$repo/"
cp "$root/scripts/check-mutant-anchors.sh" "$root/scripts/mutation-helpers.sh" "$repo/scripts/"
cp -R "$root/scripts/lib/apply-only" "$repo/scripts/lib/"

suite() {
	cat >"$repo/scripts/check-$1-mutations.sh" <<SUITE
#!/bin/sh
set -eu
root=\$(cd "\$(dirname "\$0")/.." && pwd)
. "\$root/scripts/mutation-helpers.sh"
fail=0
mutate() {
	if [ "\$2" != applies ]; then
		echo "FAIL \$1: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "\$1" && return
	echo "ok   \$1: tests went red"
}
$2
exit \$fail
SUITE
	chmod +x "$repo/scripts/check-$1-mutations.sh"
}

suite clean 'mutation_apply_only || go test ./...
mutate a applies
mutate b applies'
suite stale 'mutate a applies
mutate b stale'
suite forgot-go 'go test ./... || true
mutate a applies'
suite forgot-node 'node x.js || true
mutate a applies'
suite silent 'true'
suite hidden-fail 'echo "FAIL a: mutation target is not unique or moved"
mutate b applies'
suite crash 'mutate a applies
exit 3'
suite inputs 'echo "ok   apply-only: no source anchors (fixtures only)"'

expect() {
	want=$1
	shift
	if "$repo/scripts/check-mutant-anchors.sh" "$@" >"$work/out" 2>&1; then got=0; else got=1; fi
	if [ "$got" != "$want" ]; then
		echo "FAIL driver $*: exit $got, want $want"
		cat "$work/out"
		exit 1
	fi
	echo "ok   driver $*: exit $got"
}
expect 0 clean
expect 0 inputs
expect 1 stale
expect 1 forgot-go
expect 1 forgot-node
expect 1 silent
expect 1 hidden-fail
expect 1 crash
expect 1 clean stale
expect 1 no-such-suite
expect 1 'bad id'
"$repo/scripts/check-mutant-anchors.sh" forgot-go >"$work/out" 2>&1 || true
grep -q '^FAIL forgot-go: ran go test' "$work/out" || { echo 'FAIL driver: trap mark not reported'; exit 1; }
echo 'ok   driver: forgotten go test is named'

# The helper itself: off by default, refuses anything but 1/0/unset.
(
	. "$repo/scripts/mutation-helpers.sh"
	if mutation_applied x >/dev/null; then echo 'FAIL helper: apply-only on without the variable'; exit 1; fi
) || exit 1
echo 'ok   helper: off without MUTATION_APPLY_ONLY'
if (MUTATION_APPLY_ONLY=yes root=$repo sh -c '. "$root/scripts/mutation-helpers.sh"') >/dev/null 2>&1; then
	echo 'FAIL helper: MUTATION_APPLY_ONLY=yes accepted'
	exit 1
fi
echo 'ok   helper: refuses MUTATION_APPLY_ONLY=yes'
if (MUTATION_APPLY_ONLY=1 root=$repo sh -c '. "$root/scripts/mutation-helpers.sh"; go version' >/dev/null 2>&1) && command -v go >/dev/null; then
	echo 'ok   helper: go version still reaches the real toolchain'
elif command -v go >/dev/null; then
	echo 'FAIL helper: go version blocked in apply-only mode'
	exit 1
fi
