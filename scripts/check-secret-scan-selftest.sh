#!/bin/sh
# Required stage of the security-hygiene CI job.
set -eu
set -eu
workdir="$(mktemp -d)"
cd "$workdir"
git init -q -b main
git config user.email "secret-scan-selftest@localhost"
git config user.name "secret-scan-selftest"
# The fake key must match gitleaks' aws-access-token rule, whose key
# body is base32 (A-Z2-7), not A-Z0-9. A draw with any of 0, 1, 8, 9
# fell through to the generic-api-key rule and its higher entropy bar,
# and missed about 1 run in 14 (3/40 against the pinned image). So:
# draw from A-Z2-7 and keep 16 DISTINCT characters, which also fixes
# the entropy of the body at 4 bits per character. 60/60 caught.
# Reading a fixed amount from the device first keeps tr reading to EOF:
# `tr ... < /dev/urandom | head -c N` died with SIGPIPE in this runner.
raw="$(head -c 2048 /dev/urandom | tr -dc 'A-Z2-7')"
body=""
while [ -n "$raw" ] && [ "${#body}" -lt 16 ]; do
  c="${raw%"${raw#?}"}"; raw="${raw#?}"
  case "$body" in *"$c"*) ;; *) body="$body$c" ;; esac
done
if [ "${#body}" -ne 16 ]; then
  echo "secret-scan-selftest FAILED: entropy source produced too few distinct characters (${#body})"
  exit 1
fi
fake_key="AKIA$body"
printf 'const demoFakeAWSKey = "%s"\n' "$fake_key" > leaked.go
git add leaked.go
git commit -q -m "selftest: seed a fake credential"
set +e
gitleaks detect --source . --redact --exit-code 1 -v > gitleaks-selftest.log 2>&1
status=$?
set -e
cat gitleaks-selftest.log
# Exit code 1 alone doesn't prove the scanner fired: gitleaks also
# exits 1 on its own fatal errors (bad --config, unreadable repo),
# with no leak ever found — confirmed locally by pointing this same
# command at a nonexistent --config file: exit 1, but the log carries
# only a "FTL unable to load gitleaks config" line, never "leaks
# found". A selftest that only checked the exit code would print OK
# on that failure too. Require the finding-evidence line as well.
# (Redirect, not a pipe into `tee`: this job's shell is busybox ash,
# which has no PIPESTATUS — piping would silently check tee's exit
# code instead of gitleaks'.)
if [ "$status" -ne 1 ]; then
  echo "secret-scan-selftest FAILED: gitleaks exited $status on a seeded fake credential, expected 1 — the scanner did not fire"
  exit 1
fi
if ! grep -q 'leaks found: 1' gitleaks-selftest.log; then
  echo "secret-scan-selftest FAILED: gitleaks exited 1 but never reported finding the seeded leak — exit 1 alone doesn't prove the scanner fired (e.g. a broken --config also exits 1)"
  exit 1
fi
echo "secret-scan-selftest OK: gitleaks correctly flagged the seeded fake credential (exit 1, leaks found: 1)"
