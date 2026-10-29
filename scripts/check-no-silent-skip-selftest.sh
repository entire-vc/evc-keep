#!/bin/sh
# Proves check-no-silent-skip.sh can fail: a fake `go` reports one allowed
# and one unknown SKIP, the guard must exit non-zero naming only the unknown
# one; with the unknown one allowlisted, or absent, it must pass.
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir "$work/bin"
cat >"$work/bin/go" <<'FAKE'
#!/bin/sh
echo "=== RUN   TestControl"
echo "--- PASS: TestControl (0.00s)"
echo "--- SKIP: TestDemoBrokenStubThroughRun (0.00s)"
[ -n "${FAKE_UNKNOWN_SKIP:-}" ] && echo "--- SKIP: $FAKE_UNKNOWN_SKIP (0.00s)"
[ -n "${FAKE_SUBTEST_SKIP:-}" ] && echo "    --- SKIP: $FAKE_SUBTEST_SKIP (0.00s)"
echo "ok  	fake	0.01s"
exit 0
FAKE
chmod +x "$work/bin/go"
run() { PATH="$work/bin:$PATH" KEEP_DATABASE_URL=selftest "$@" "$root/scripts/check-no-silent-skip.sh" ./... >"$work/out" 2>&1; }
fail=0

run env FAKE_UNKNOWN_SKIP=TestUnexpectedMissingDependency
if [ $? -eq 0 ] || ! grep -q 'TestUnexpectedMissingDependency' "$work/out"; then echo "selftest: an unlisted SKIP passed" >&2; fail=1; fi

run env FAKE_SUBTEST_SKIP=TestUnexpectedParent/sub
if [ $? -eq 0 ]; then echo "selftest: an unlisted subtest SKIP passed" >&2; fail=1; fi

run env FAKE_UNKNOWN_SKIP=TestUnexpectedMissingDependency KEEP_SKIP_ALLOWLIST="$work/nope"
if [ $? -eq 0 ]; then echo "selftest: a missing allowlist passed" >&2; fail=1; fi

run env
if [ $? -ne 0 ]; then echo "selftest: only allowlisted SKIPs, yet the guard failed" >&2; cat "$work/out" >&2; fail=1; fi

printf 'TestUnexpectedMissingDependency reason\n' >"$work/allow"
cat "$root/scripts/allowed-skips.txt" >>"$work/allow"
run env FAKE_UNKNOWN_SKIP=TestUnexpectedMissingDependency KEEP_SKIP_ALLOWLIST="$work/allow"
if [ $? -ne 0 ]; then echo "selftest: an allowlisted SKIP failed" >&2; fail=1; fi

[ "$fail" -eq 0 ] && echo "check-no-silent-skip-selftest: unknown SKIP red, allowlisted SKIP green"
exit "$fail"
