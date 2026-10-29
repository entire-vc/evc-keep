#!/bin/sh
# Exercise the exact full-history scanner used for first pushes in CI.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
scanner=${1:-$root/scripts/scan-secret-history.sh}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cd "$work"
git init -q -b main
git config user.email 'secret-scan-selftest@localhost'
git config user.name 'secret-scan-selftest'
cp "$root/.gitleaks.toml" .gitleaks.toml
printf 'clean base\n' > clean.txt
git add .gitleaks.toml clean.txt
git commit -q -m 'selftest: clean base'
base=$(git rev-parse HEAD)

# Generate a fake AWS key with 16 distinct base32 characters. This avoids
# both the published-example allowlist and nondeterministic entropy misses.
raw=$(head -c 2048 /dev/urandom | tr -dc 'A-Z2-7')
body=''
while [ -n "$raw" ] && [ "${#body}" -lt 16 ]; do
    c=${raw%"${raw#?}"}; raw=${raw#?}
    case "$body" in *"$c"*) ;; *) body=$body$c ;; esac
done
if [ "${#body}" -ne 16 ]; then
    echo 'FAIL secret-scan-scope: insufficient distinct entropy characters'
    exit 1
fi
seed() { printf 'aws_access_key_id = "AKIA%s"\n' "$body" > credential.txt; }
assert_scan() {
    label=$1; expected=$2; shift 2
    if "$@" > scan.log 2>&1; then result=0; else result=$?; fi
    # Only counters are printed; never print finding fields or seeded bytes.
    echo "secret-scan-scope $label: exit $result (expected $expected)"
    sed -n '/commits scanned/p; /scanned ~.* bytes/p; /leaks found/p' scan.log
    if [ "$result" -ne "$expected" ]; then
        echo "FAIL secret-scan-scope $label: unexpected scanner exit"
        exit 1
    fi
    if ! grep -Eq '[1-9][0-9]* commits scanned' scan.log ||
       ! grep -Eq 'scanned ~[1-9][0-9]* bytes' scan.log; then
        echo "FAIL secret-scan-scope $label: scanner did not inspect history"
        exit 1
    fi
    if [ "$expected" -eq 1 ]; then
        if ! grep -Eq 'leaks found: 1([^0-9]|$)' scan.log; then
            echo "FAIL secret-scan-scope $label: expected one seeded finding"
            exit 1
        fi
    elif ! grep -q 'no leaks found' scan.log; then
        echo "FAIL secret-scan-scope $label: missing clean-scan evidence"
        exit 1
    fi
    echo "ok   secret-scan-scope $label"
}

git switch -q -c sibling
seed
git add credential.txt
git commit -q -m 'selftest: fake credential on sibling'
git switch -q main
printf 'clean tip\n' >> clean.txt
git commit -q -am 'selftest: clean tip'
tip=$(git rev-parse HEAD)
assert_scan sibling-only 0 env CI_COMMIT_SHA="$tip" "$scanner"
assert_scan mr-diff 0 gitleaks detect --source . --log-opts="$base..$tip" --redact --exit-code 1 -v

seed
git add credential.txt
git commit -q -m 'selftest: fake credential on scanned branch'
tip=$(git rev-parse HEAD)
assert_scan current-tip 1 env CI_COMMIT_SHA="$tip" "$scanner"
assert_scan mr-diff-leak 1 gitleaks detect --source . --log-opts="$base..$tip" --redact --exit-code 1 -v
git rm -q credential.txt
git commit -q -m 'selftest: remove fake credential'
tip=$(git rev-parse HEAD)
assert_scan ancestor-leak 1 env CI_COMMIT_SHA="$tip" "$scanner"
before=$tip
printf 'clean push\n' >> clean.txt
git commit -q -am 'selftest: later clean push'
tip=$(git rev-parse HEAD)
assert_scan push-diff 0 gitleaks detect --source . --log-opts="$before..$tip" --redact --exit-code 1 -v
echo 'secret-scan-scope OK: sibling excluded, current and ancestor leaks detected, diff scans intact'
