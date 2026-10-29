#!/bin/sh
# Reject behavioral failures in the production page, not startup/compiler errors.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
if ! mutation_apply_only && [ -z "${KEEP_DATABASE_URL:-}" ]; then
 echo 'FAIL: a migrated PostgreSQL database is required' >&2
 exit 2
fi
behavioral_failure() {
 log=$1 test=$2 marker=$3
 if mutation_infrastructure_failed "$log" >/dev/null || grep -Eq 'panic:|fatal error:|\[build failed\]|\[setup failed\]|--- SKIP' "$log"; then return 1; fi
 grep -q -- "--- FAIL: $test" "$log" && grep -Fq "$marker" "$log"
}
# Reset the witness for each fault: an earlier fault must not mask a later one.
for fault in 'panic: test timed out' 'database operation deadline exceeded' 'connection failed (unclassified)' '[build failed]' '[setup failed]' 'panic: runtime error' '--- SKIP: TestProbe'; do
 printf '%s\n' '--- FAIL: TestProbe' 'behavioral witness' "$fault" >"$work/self-test"
 if behavioral_failure "$work/self-test" TestProbe 'behavioral witness'; then
  echo 'FAIL page mutation checker accepted an infrastructure fault'; exit 1
 fi
done
printf '%s\n' '--- FAIL: TestProbe' 'behavioral witness' >"$work/self-test"
behavioral_failure "$work/self-test" TestProbe 'behavioral witness'
echo 'ok   checker: behavioral witness required; infrastructure faults rejected'
mutation_apply_only || (cd "$root" && go test -timeout 180s -tags intake_browser -count=1 -run '^TestIntakePageBrowserLifecycle$' ./internal/builtin >"$work/baseline" 2>&1) || {
 baseline_status=$?
 python3 "$root/scripts/intake_baseline_diagnostics.py" "$work/baseline" "$baseline_status" 2>/dev/null ||
  echo '{"baseline":"page","event":"diagnostics-unavailable"}'
 echo 'FAIL page mutation baseline'; exit 1;
}
mkdir "$work/tree"
(cd "$root" && tar --exclude=.git --exclude=.gocache --exclude=.gomodcache -cf - .) | (cd "$work/tree" && tar -xf -)
mutate() {
 name=$1 file=$2 from=$3 to=$4 expected=$5
 cp "$root/$file" "$work/tree/$file"
 python3 - "$work/tree/$file" "$from" "$to" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
if s.count(sys.argv[2])!=1: raise SystemExit('FAIL page mutation: target is not unique')
p.write_text(s.replace(sys.argv[2],sys.argv[3],1))
PY
 if [ "$name" = descriptor-metadata ]; then
  # Model a protocol downgrade on both peers, so an honest link still works
  # and the test must reject a changed visible field rather than fail startup.
  python3 - "$work/tree/internal/intake/descriptor/message.go" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
fields=', m.SecretName, m.Scope, m.StoreName, m.Class, m.RequestedBy, m.Sponsor'
if s.count(fields)!=1: raise SystemExit('FAIL metadata mutation: target is not unique')
p.write_text(s.replace(fields,'',1))
PY
 fi
 if mutation_apply_only; then
  echo "ok   $name: applies"
  cp "$root/$file" "$work/tree/$file"
  cp "$root/internal/intake/descriptor/message.go" "$work/tree/internal/intake/descriptor/message.go"
  return
 fi
 case "$file" in
  web/intake/app.js|web/intake/hpke.js) pkg=./internal/builtin; test=TestIntakePageBrowserLifecycle; tags=intake_browser ;;
  *) pkg=./internal/api; test='TestInputPage'; tags='' ;;
 esac
 if [ "$name" = metadata-cr ]; then pkg=./web/intake; test=TestRenderMetadataPreservesCRAndEscapesMarkup; tags=''; fi
 case "$name" in
  csp-external|extra-input|css-import) pkg=./internal/builtin; test=TestIntakePageBrowserLifecycle; tags=intake_browser ;;
 esac
 # The browser lifecycle test is allowed 120 s of its own (see the test); the
 # go test limit must stay above that. Other packages keep the short limit.
 test_timeout=90s
 [ "$tags" = intake_browser ] && test_timeout=180s
 mutant_started=$(python3 -c 'import time; print(time.monotonic())')
 if (cd "$work/tree" && go test -timeout "$test_timeout" -tags "$tags" -count=1 -v -run "^$test" "$pkg" > "$work/result" 2>&1); then
  python3 "$root/scripts/intake_mutant_diagnostics.py" "$work/result" 0 "$mutant_started"
  echo "FAIL $name: page accepted mutant"; exit 1
 else
  mutant_status=$?
 fi
 if ! behavioral_failure "$work/result" "$test" "$expected"; then
  python3 "$root/scripts/intake_mutant_diagnostics.py" "$work/result" "$mutant_status" "$mutant_started"
  echo "FAIL $name: did not reach the intended behavioral assertion"; exit 1
 fi
 echo "ok   $name: page assertion rejected mutant"
 cp "$root/$file" "$work/tree/$file"
 cp "$root/internal/intake/descriptor/message.go" "$work/tree/internal/intake/descriptor/message.go"
}
mutate signature web/intake/app.js "if (!verified)" "if (false)" 'expected UI state was not reached (secret-name)'
mutate metadata-visible web/intake/app.js "!visible(node)" "false" 'expected UI state was not reached (hidden-field-SecretName)'
mutate metadata-structure web/intake/app.js "validateMetadataStructure(nodes);" "" 'expected UI state was not reached (extra-name)'
mutate metadata-leaf web/intake/app.js "node.children.length !== 0 || " "" 'expected UI state was not reached (nested-name)'
mutate metadata-row-text web/intake/app.js "validateStructureText(row);" "" 'expected UI state was not reached (raw-row-text)'
mutate metadata-card-text web/intake/app.js "validateStructureText(card);" "" 'expected UI state was not reached (raw-card-text)'
mutate metadata-cr web/intake/assets.go 'strings.ReplaceAll(template.HTMLEscapeString(text), "\r", "&#13;")' 'template.HTMLEscapeString(text)' 'visible metadata did not preserve CR through escaped text'
mutate signing-cardinality web/intake/app.js "pins.length !== 1 || " "" 'expected UI state was not reached (duplicate-pin)'
mutate signer-pin web/intake/app.js "const signing = from64(pin.replaceAll('-', '+').replaceAll('_', '/') + '=');" 'const signing = from64(form.dataset.signing);' 'expected UI state was not reached (signer)'
mutate descriptor-metadata web/intake/app.js "const fields = [utf8.encode(form.dataset.request), publicKey, ...metadata.map(value => utf8.encode(value))];" "const fields = [utf8.encode(form.dataset.request), publicKey];" 'expected UI state was not reached (secret-name)'
mutate request-pin web/intake/app.js "if (requests.length !== 1 || requests[0] !== form.dataset.request) throw new Error('untrusted request');" '' 'expected UI state was not reached (signed-request)'
mutate fragment-fields web/intake/app.js "if ([...fragment.keys()].some(name => name !== 'request' && name !== 'signing')) throw new Error('untrusted fragment');" '' 'expected UI state was not reached (unknown-fragment)'
mutate canonical-base64 web/intake/app.js "if (to64(bytes) !== s) throw new Error('noncanonical encoding');" '' 'expected UI state was not reached (noncanonical-public)'
mutate early-encryption web/intake/app.js "const pins =" "await setupSender(from64(form.dataset.public), intakeInfo(form.dataset.request)); const pins =" 'tampered descriptor accepted'
mutate console web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); console.log(field.value);" 'console side effect'
mutate cookie-write web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); document.cookie='s='+field.value;" 'browser cookie side effect'
mutate credentials web/intake/app.js "credentials: 'omit'" "credentials: 'include'" 'credential or referrer sent'
mutate redirect web/intake/app.js ", redirect: 'error'" '' 'redirect followed'
mutate local-storage web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); localStorage.setItem('input',field.value);" 'browser storage side effect'
mutate session-storage web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); sessionStorage.setItem('input',field.value);" 'browser storage side effect'
mutate indexed-db web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); await new Promise(resolve => { const request = indexedDB.open('input'); request.onsuccess = () => { request.result.close(); resolve(); }; });" 'IndexedDB side effect'
mutate cache-api web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); await (await caches.open('input')).put('/input/probe', new Response(field.value));" 'Cache Storage side effect'
mutate opfs web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); const dir = await navigator.storage.getDirectory(); const file = await dir.getFileHandle('input', {create:true}); const writer = await file.createWritable(); await writer.write(field.value); await writer.close();" 'OPFS side effect'
mutate window-name web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); window.name = field.value;" 'window.name side effect'
mutate extra-input web/intake/page.html '<label for="secret">' '<input name="extra"><label for="secret">' 'unexpected input field'
mutate css-import web/intake/style.css '*{box-sizing:border-box}' '@import url(https://outside.example.invalid/probe.css);*{box-sizing:border-box}' 'CSS import side effect'
mutate token-in-log internal/api/middleware.go 'logger.Info("http_request",' 'logger.Info(r.PathValue("token"),' 'page capability escaped into response or log'
mutate title web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); document.title=field.value;" 'input in URL, title or DOM'
mutate title-base64-shift web/intake/app.js "const plain = utf8.encode(field.value);" "const plain = utf8.encode(field.value); document.title=btoa('prefix:'+field.value+':suffix');" 'input in URL, title or DOM'
mutate field-clearing web/intake/app.js "field.value = '';" "void field.value;" 'plaintext field not cleared after submission'
mutate plaintext-request web/intake/app.js 'ciphertext: to64(await sender.seal(plain))' 'ciphertext: to64(plain)' 'input in request'
mutate csp-connect-wide web/intake/assets.go "connect-src 'self'" "connect-src 'self' https: http:" 'CSP does not match exact policy'
mutate csp-script-wide web/intake/assets.go "'; style-src '" "' https:; style-src '" 'CSP does not match exact policy'
mutate csp-frame-wide web/intake/assets.go "frame-ancestors 'none'" "frame-ancestors 'none' *" 'CSP does not match exact policy'
mutate csp web/intake/assets.go "script-src '" "script-src 'self' '" 'CSP does not match exact policy'
mutate csp-external web/intake/assets.go "script-src '" "script-src http: '" 'unexpected network side effect'
mutate no-referrer internal/api/intake.go 'w.Header().Set("Referrer-Policy", "no-referrer")' 'w.Header().Del("Referrer-Policy")' 'missing page header Referrer-Policy'
mutate autocomplete web/intake/page.html 'autocomplete="off"' '' 'missing textarea privacy attribute autocomplete'
mutate autocapitalize web/intake/page.html 'autocapitalize="off"' '' 'missing textarea privacy attribute autocapitalize'
mutate spellcheck web/intake/page.html 'spellcheck="false"' '' 'missing textarea privacy attribute spellcheck'
mutate autocorrect web/intake/page.html 'autocorrect="off"' '' 'missing textarea privacy attribute autocorrect'
mutate duplicate-autocomplete web/intake/page.html 'autocomplete="off"' 'autocomplete="on" autocomplete="off"' 'duplicate textarea privacy attribute autocomplete'
mutate runtime-autocomplete web/intake/app.js 'field.disabled = false;' "field.setAttribute('autocomplete','on'); field.disabled = false;" 'textarea privacy attribute autocomplete'
mutate runtime-spellcheck web/intake/app.js 'field.disabled = false;' 'field.spellcheck = true; field.disabled = false;' 'textarea privacy attribute spellcheck'
mutate sri web/intake/page.html 'integrity="{{.Integrity}}"' '' 'script integrity does not match'
mutate capability-response internal/api/intake.go 'io.WriteString(w, page.String())' 'io.WriteString(w, page.String()+r.PathValue("token"))' 'page capability escaped'
if ! mutation_apply_only; then
(cd "$root" && go test -timeout 180s -tags intake_browser -count=1 -v -run '^TestIntakePageBrowserLifecycle$' ./internal/builtin)
echo 'ok   baseline: production page lifecycle passed'
fi
