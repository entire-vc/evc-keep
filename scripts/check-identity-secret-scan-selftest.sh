#!/bin/sh
# Required stage of the security-hygiene CI job.
set -eu
set -eu
for kind in a s u; do
  # A bounded read from /dev/urandom first, tr filters it after, so
  # nothing closes the pipe early (same lesson as secret-scan-selftest
  # above). 1024 bytes, not 512: this alphabet is 32 characters wide
  # (vs. the AWS selftest's 36), and 52 characters are needed (vs.
  # 16), so the smaller job's buffer would leave too thin a margin.
  raw="$(head -c 1024 /dev/urandom | tr -dc 'a-z2-7')"
  if [ "${#raw}" -lt 52 ]; then
    echo "identity-secret-scan-selftest FAILED: entropy source produced too few candidate characters (${#raw})"
    exit 1
  fi
  token="keep_${kind}_$(printf '%s' "$raw" | cut -c 1-52)"

  workdir="$(mktemp -d)"
  cd "$workdir"
  git init -q -b main
  git config user.email "identity-secret-scan-selftest@localhost"
  git config user.name "identity-secret-scan-selftest"
  printf 'const leakedKeepToken = "%s"\n' "$token" > leaked.go
  git add leaked.go
  git commit -q -m "selftest: seed a real-format Keep token of kind $kind"

  set +e
  gitleaks detect --source . --config "$CI_PROJECT_DIR/.gitleaks.toml" --redact --exit-code 1 -v > "gitleaks-identity-selftest-$kind.log" 2>&1
  status=$?
  set -e
  cat "gitleaks-identity-selftest-$kind.log"
  if [ "$status" -ne 1 ]; then
    echo "identity-secret-scan-selftest FAILED: gitleaks exited $status on a seeded kind-$kind Keep token, expected 1 — the scanner did not fire"
    exit 1
  fi
  if ! grep -q 'keep-identity-token' "gitleaks-identity-selftest-$kind.log"; then
    echo "identity-secret-scan-selftest FAILED: gitleaks exited 1 on a kind-$kind token but not via the keep-identity-token rule — some other rule may have caught it instead"
    exit 1
  fi
  echo "identity-secret-scan-selftest OK: keep-identity-token flagged a generated kind-$kind token"
  cd "$CI_PROJECT_DIR"
done

./scripts/check-intake-scan-allowlist.sh
