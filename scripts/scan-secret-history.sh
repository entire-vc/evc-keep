#!/bin/sh
# Scan every ancestor of the pipeline commit, excluding unrelated refs.
# Shared with check-secret-scan-scope.sh so CI tests the production command.
set -eu
gitleaks detect --source . --log-opts="${CI_COMMIT_SHA:?CI_COMMIT_SHA is required}" --redact --exit-code 1 -v
