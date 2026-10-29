#!/bin/sh
# Required stage of the security-hygiene CI job.
set -eu
# gitleaks `detect` with no --log-opts scans every ref gitleaks can
# see, not just the current one (confirmed locally: scanning while
# checked out to a clean branch still flagged a secret that only
# existed on a sibling branch). Scope both diffs and full-history
# scans explicitly, independent of which refs the runner fetched.
if [ "${CI_PIPELINE_SOURCE:-}" = "merge_request_event" ]; then
  RANGE="${CI_MERGE_REQUEST_DIFF_BASE_SHA}..${CI_COMMIT_SHA}"
  echo "scanning MR diff: $RANGE"
  gitleaks detect --source . --log-opts="$RANGE" --redact --exit-code 1 -v
elif [ -z "${CI_COMMIT_BEFORE_SHA:-}" ] || [ "${CI_COMMIT_BEFORE_SHA}" = "0000000000000000000000000000000000000000" ]; then
  echo "no previous SHA (first push or force-push) — scanning full history on $CI_COMMIT_REF_NAME"
  ./scripts/scan-secret-history.sh
else
  RANGE="${CI_COMMIT_BEFORE_SHA}..${CI_COMMIT_SHA}"
  echo "scanning push diff: $RANGE"
  gitleaks detect --source . --log-opts="$RANGE" --redact --exit-code 1 -v
fi
