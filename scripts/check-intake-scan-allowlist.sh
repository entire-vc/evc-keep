#!/bin/sh
# Published RFC vectors may silence generic-api-key only at their exact path.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
config=${GITLEAKS_CONFIG:-$root/.gitleaks.toml}
fixture=web/intake/testdata/rfc9180-x25519-aes256.json
mkdir -p "$work/tree/$(dirname "$fixture")"
cp "$root/$fixture" "$work/tree/$fixture"
scan() {
 rm -f "$work/report.json"
 (cd "$work/tree" && gitleaks dir --config "$config" --redact --exit-code 1 --report-format json --report-path "$work/report.json" . > "$work/result" 2>&1)
}
if scan; then
 echo 'ok   published vectors: exact fixture passed'
else
 echo 'FAIL published vectors: exact fixture was not allowed'; exit 1
fi
seed() {
 rm -rf "$work/tree"
 mkdir -p "$work/tree/$(dirname "$1")"
 case "$2" in
  private-key)
   { printf '%s%s%s\n' '-----BEGIN ' 'PRIVATE KEY' '-----'
     printf '%080d\n' 0
     printf '%s%s%s\n' '-----END ' 'PRIVATE KEY' '-----'
   } > "$work/tree/$1" ;;
  generic-api-key) cp "$root/$fixture" "$work/tree/$1" ;;
  keep-identity-token)
   body=$(head -c 2048 /dev/urandom | tr -dc 'a-z2-7' | cut -c 1-52)
   test "${#body}" -eq 52
   printf 'token = "keep_a_%s"\n' "$body" > "$work/tree/$1" ;;
 esac
 if scan; then
  echo "FAIL $2 at $1: seeded finding was suppressed"; exit 1
 else
  status=$?
 fi
 if [ "$status" -ne 1 ] || ! grep -q "\"RuleID\": \"$2\"" "$work/report.json"; then
  echo "FAIL $2 at $1: scanner did not reach the expected rule"; exit 1
 fi
 echo "ok   $2 at $1: seeded finding detected"
}
seed "$fixture" private-key
seed "$fixture" keep-identity-token
seed "$fixture.bak" generic-api-key
seed "web/intake/testdata/rfc9180-x25519-aes256xjson" generic-api-key
seed "x/$fixture" generic-api-key
seed "x/$fixture.bak" private-key
