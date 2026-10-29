#!/bin/sh
# Required stage of the security-hygiene CI job.
set -eu
if [ "${CI_PIPELINE_SOURCE:-}" = "merge_request_event" ]; then
  export HYGIENE_RANGE="${CI_MERGE_REQUEST_DIFF_BASE_SHA}..${CI_COMMIT_SHA}"
fi
./scripts/check-public-hygiene.sh
