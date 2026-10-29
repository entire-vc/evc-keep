#!/bin/sh
# Required browser checks: RFC vectors and a fresh browser-to-Go exchange.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
go test -timeout 90s -count=1 -v -run '^TestInputLinkCacheHeaders$|^TestInputPage' ./internal/api
node scripts/check-intake-browser.mjs
go test -timeout 90s -tags intake_browser -count=1 -v -run '^TestIntakeBrowserInteroperatesWithGo$|^TestCrossFailureClassIsFixed$' ./internal/builtin

if [ -n "${KEEP_DATABASE_URL:-}" ]; then
 go test -race -timeout 240s -tags intake_browser -count=1 -v -run '^TestIntakeBrowserDeliveryToSealedStore$|^TestIntakePageBrowserLifecycle$' ./internal/builtin
else
 echo 'FAIL browser delivery: PostgreSQL is required for the full page lifecycle'
 exit 1
fi
