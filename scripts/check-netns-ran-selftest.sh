#!/bin/sh
# Proves check-netns-ran.sh can fail: a complete log passes; a SKIP, a missing
# test, a longer name standing in for the real one, a FAIL and an empty log
# must each exit non-zero.
set -u
here=$(dirname "$0")
guard="$here/check-netns-ran.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
printf '%s\n' 'TestNetnsNoneIsolates why' 'TestRunWithRealIsolatorNone why' 'TestOther why' >"$work/allow"
pass() { printf -- '--- PASS: %s (0.1s)\n' "$@"; }
pass TestNetnsNoneIsolates TestRunWithRealIsolatorNone >"$work/good"
"$guard" "$work/good" "$work/allow" >/dev/null 2>&1 || { echo "selftest: complete log must pass" >&2; exit 1; }
red() {
	if "$guard" "$work/$1" "$work/allow" >/dev/null 2>&1; then
		echo "selftest: $2 must fail" >&2
		exit 1
	fi
}
{ cat "$work/good"; echo '    --- SKIP: TestNetnsNoneIsolates/sub (0.00s)'; } >"$work/skip"; red skip "a SKIP next to every PASS"
pass TestNetnsNoneIsolates >"$work/missing"; red missing "a missing test"
pass TestNetnsNoneIsolates TestRunWithRealIsolatorNoneExtra >"$work/prefix"; red prefix "a longer name"
{ cat "$work/good"; echo '--- FAIL: TestOther (0.1s)'; } >"$work/fail"; red fail "a FAIL next to every PASS"
: >"$work/empty"; red empty "an empty log"
echo "check-netns-ran-selftest: complete log green; SKIP, missing, prefix, FAIL, empty red"
