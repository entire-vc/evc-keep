#!/bin/sh
# Daily secret scan of every branch outside the default branch.
#
# A push to a non-default branch creates no pipeline (see workflow:rules in
# .gitlab-ci.yml), so a commit pushed to a branch without an MR is scanned
# here, once a day, in the schedule pipeline. The default branch is excluded:
# its own pipelines scan every commit that reaches it, and every MR pipeline
# scans its whole range. Run from the repository root; the job and
# check-branch-secret-scan-selftest.sh call this same file.
#
# Exit 0: no finding. Any other exit (a finding, a failed fetch, a gitleaks
# error, a missing default branch) fails the job. gitleaks prints findings
# with --redact; this script prints only ref names and counters.
set -eu
remote=${KEEP_BRANCH_SCAN_REMOTE:-origin}
default=${CI_DEFAULT_BRANCH:?CI_DEFAULT_BRANCH is required}
base="refs/remotes/$remote/$default"

# The runner fetches only the pipeline's own ref: take every branch head.
git fetch --quiet --prune "$remote" "+refs/heads/*:refs/remotes/$remote/*"
git rev-parse --verify --quiet "$base^{commit}" > /dev/null || {
    echo "branch-secret-scan: $base not found after the fetch" >&2
    exit 1
}
branches=$(git for-each-ref --format='%(refname)' "refs/remotes/$remote/" |
    grep -v -x -e "$base" -e "refs/remotes/$remote/HEAD" | wc -l | tr -d ' ')
commits=$(git rev-list --count --remotes="$remote" "^$base")
echo "branch-secret-scan: $branches branches outside $default, $commits commits not reachable from $default"
if [ "$commits" -eq 0 ]; then
    echo "branch-secret-scan: nothing to scan"
    exit 0
fi
# gitleaks splits --log-opts on spaces and passes the words to `git log`.
gitleaks detect --source . --config .gitleaks.toml \
    --log-opts="--remotes=$remote ^$base" --redact --exit-code 1 -v
