#!/bin/sh
# Selftest of scripts/scan-branch-secrets.sh, the scanner the schedule
# pipeline's branch-secret-scan job runs. It drives that same file against a
# throwaway origin whose clone holds only the default branch, so the scanner
# has to fetch the other heads itself:
#   - a branch (never fetched by the clone) with a seeded fake credential: exit != 0;
#   - the same branch without it: exit 0;
#   - a fake credential that lives only on the default branch: not scanned,
#     so the clean case also proves the default branch is excluded;
#   - an empty or missing default branch name: refused, not a green scan;
#   - the finding is printed redacted: the seeded value never reaches the log.
# Only counters are printed, never finding fields or seeded bytes.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
scanner=${1:-$root/scripts/scan-branch-secrets.sh}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

# A fake AWS key with 16 distinct base32 characters: matches the stock
# aws-access-token rule every time (see check-secret-scan-selftest.sh).
fake_key() {
    raw=$(head -c 2048 /dev/urandom | LC_ALL=C tr -dc 'A-Z2-7')
    body=''
    while [ -n "$raw" ] && [ "${#body}" -lt 16 ]; do
        c=${raw%"${raw#?}"}; raw=${raw#?}
        case "$body" in *"$c"*) ;; *) body=$body$c ;; esac
    done
    if [ "${#body}" -ne 16 ]; then
        echo 'FAIL branch-secret-scan: insufficient distinct entropy characters' >&2
        exit 1
    fi
    printf 'AKIA%s' "$body"
}

origin="$work/origin"
git init -q -b main "$origin"
git -C "$origin" config user.email 'branch-secret-scan-selftest@localhost'
git -C "$origin" config user.name 'branch-secret-scan-selftest'
cp "$root/.gitleaks.toml" "$origin/.gitleaks.toml"
printf 'clean base\n' > "$origin/clean.txt"
git -C "$origin" add .gitleaks.toml clean.txt
git -C "$origin" commit -q -m 'selftest: clean base'
# Already on the default branch: its own pipelines scan it, this scan must not.
printf 'aws_access_key_id = "%s"\n' "$(fake_key)" > "$origin/main-credential.txt"
git -C "$origin" add main-credential.txt
git -C "$origin" commit -q -m 'selftest: fake credential on the default branch'
# Branches with a slash in the name, as every topic branch here has.
git -C "$origin" switch -q -c topic/clean
printf 'clean topic\n' >> "$origin/clean.txt"
git -C "$origin" commit -q -am 'selftest: clean topic commit'
git -C "$origin" switch -q -c topic/leak
branch_key=$(fake_key)
printf 'aws_access_key_id = "%s"\n' "$branch_key" > "$origin/credential.txt"
git -C "$origin" add credential.txt
git -C "$origin" commit -q -m 'selftest: fake credential on a branch without an MR'
git -C "$origin" switch -q main

clone="$work/clone"
git clone -q --single-branch --branch main "$origin" "$clone"

assert_scan() {
    label=$1; expected=$2; default=$3
    if (cd "$clone" && CI_DEFAULT_BRANCH=$default "$scanner") > "$work/scan.log" 2>&1; then
        result=0
    else
        result=$?
    fi
    echo "branch-secret-scan $label: exit $result (expected $expected)"
    sed -n '/^branch-secret-scan:/p; /commits scanned/p; /leaks found/p' "$work/scan.log"
    case "$expected" in
        nonzero) [ "$result" -ne 0 ] ;;
        *) [ "$result" -eq "$expected" ] ;;
    esac || { echo "FAIL branch-secret-scan $label: unexpected scanner exit"; exit 1; }
}

# Both topic branches exist only on the origin: without the fetch nothing is scanned.
assert_scan leak-on-branch 1 main
grep -Eq '2 branches outside main, 2 commits not reachable from main' "$work/scan.log" ||
    { echo 'FAIL branch-secret-scan leak-on-branch: branch heads were not fetched'; exit 1; }
grep -Eq '^.*2 commits scanned' "$work/scan.log" ||
    { echo 'FAIL branch-secret-scan leak-on-branch: scanner did not read the branch commits'; exit 1; }
grep -Eq 'leaks found: 1([^0-9]|$)' "$work/scan.log" ||
    { echo 'FAIL branch-secret-scan leak-on-branch: expected exactly the branch finding'; exit 1; }
# The job log is public to project members: the finding must be printed redacted.
if grep -qF "$branch_key" "$work/scan.log"; then
    echo 'FAIL branch-secret-scan leak-on-branch: the seeded value reached the log unredacted'; exit 1
fi

# The same branch, its credential commit gone: green. The default branch still
# carries its own fake credential, so a scan that reads main goes red here.
git -C "$origin" branch -q -f topic/leak topic/clean
assert_scan clean-branch 0 main
grep -Eq '2 branches outside main, 1 commits not reachable from main' "$work/scan.log" ||
    { echo 'FAIL branch-secret-scan clean-branch: stale branch head kept after the fetch'; exit 1; }
grep -Eq '^.*1 commits scanned' "$work/scan.log" && grep -q 'no leaks found' "$work/scan.log" ||
    { echo 'FAIL branch-secret-scan clean-branch: missing clean-scan evidence'; exit 1; }

# A missing default branch name is refused, never read as "scan everything" or "nothing".
# Each refusal must come from the scanner's own check, not from a later git error.
assert_scan empty-default nonzero ''
grep -q 'CI_DEFAULT_BRANCH is required' "$work/scan.log" ||
    { echo 'FAIL branch-secret-scan empty-default: refused for another reason'; exit 1; }
assert_scan unknown-default nonzero no-such-branch
grep -q 'refs/remotes/origin/no-such-branch not found after the fetch' "$work/scan.log" ||
    { echo 'FAIL branch-secret-scan unknown-default: refused for another reason'; exit 1; }
if grep -q 'commits scanned' "$work/scan.log"; then
    echo 'FAIL branch-secret-scan unknown-default: scanned without a base'; exit 1
fi
echo 'branch-secret-scan OK: unfetched branch leak detected and redacted, clean branch green, default branch excluded, missing base refused'
