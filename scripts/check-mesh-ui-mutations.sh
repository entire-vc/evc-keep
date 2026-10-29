#!/bin/sh
# Proves the guards of the Mesh screen (/mesh/ui/*) can fail (threat model 4.1,
# 4.3): in a scratch copy of the tree, switch off one property at a time and
# require the named test to go red with a real --- FAIL. A build error, a skip
# or an unrelated failure is not evidence. Needs a real PostgreSQL:
# KEEP_DATABASE_URL. The script tests need node.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
mutation_apply_only || : "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must name disposable PostgreSQL}"

fail=0
pkg=./cmd/keep-server/app
# mutate NAME FILE FROM TO TEST [WANT]: replace one literal FROM with TO in FILE
# and require TEST (in $pkg) to fail with a real --- FAIL, naming WANT when given.
mutate() {
	name=$1 file=$2 from=$3 to=$4 test=$5 want=${6:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! python3 - "$work/tree/$file" "$from" "$to" <<'PY'
import sys
p, a, b = sys.argv[1:]
s = open(p).read()
if s.count(a) < 1:
    sys.exit(1)
open(p, 'w').write(s.replace(a, b, 1))
PY
	then
		echo "FAIL $name: mutation did not apply, the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -count=1 -p 1 -timeout 240s -run "$test" "$pkg" >"$work/out" 2>&1); then
		echo "FAIL $name: $test stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	elif [ -n "$want" ] && ! grep -q -- "$want" "$work/out"; then
		echo "FAIL $name: $test went red for another reason (wanted: $want)"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

U=internal/api/mesh_ui.go
S=internal/api/mesh_ui_assets.go
T=cmd/keep-server/app/mesh_ui_test.go
# CSP: the policy source, the 'none' fallback, the script source, the injection filter.
mutate csp-ancestors-widened $U '		anc = strings.Join(origins, " ")' '		anc = strings.Join(origins, " ") + " *"' TestMeshUIFrameAncestorsAreOnlyTheInstalledMesh
mutate csp-ancestors-default $U '	anc := "'"'"'none'"'"'"' '	anc := "*"' TestMeshUIRefusesWithoutAValidContext
mutate csp-script-inline     $U "script-src 'self';" "script-src 'self' 'unsafe-inline';" TestMeshUIFrameAncestorsAreOnlyTheInstalledMesh
mutate csp-headers-noop      $U '	meshUIHeaders(w, origins)
	rows, truncated' '	_ = origins
	rows, truncated' TestMeshUIFrameAncestorsAreOnlyTheInstalledMesh
pkg=./internal/api
mutate csp-origin-filter-off $U 'if strings.ContainsAny(o, " ;,'"'"'\"\r\n\t*") {' 'if false {' TestMeshUIFrameOrigin
# Entry: token exchange, redirect that drops it, cookie attributes, TLS only.
pkg=./cmd/keep-server/app
mutate token-kept-in-url     $U 'http.Redirect(w, r, "/mesh/ui/secrets", http.StatusSeeOther)' 'http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)' TestMeshUI
mutate cookie-not-httponly   $U 'Path: meshUIPath, HttpOnly: true,' 'Path: meshUIPath, HttpOnly: false,' TestMeshUI
mutate cookie-not-secure     $U 'HttpOnly: true, Secure: true,' 'HttpOnly: true, Secure: false,' TestMeshUI
mutate cookie-samesite-lax   $U 'SameSite: http.SameSiteNoneMode, Partitioned: true' 'SameSite: http.SameSiteLaxMode, Partitioned: true' TestMeshUI
mutate cookie-not-partitioned $U 'SameSite: http.SameSiteNoneMode, Partitioned: true' 'SameSite: http.SameSiteNoneMode, Partitioned: false' TestMeshUI
mutate tls-wrap-removed      $U 'logged(e.pattern, logger, requireTLS(e.h).ServeHTTP)' 'logged(e.pattern, logger, e.h)' TestMeshUIAbsentWhenExtensionOffOrPlainHTTP
mutate session-origin-off    $U '	if !sameOrigin(r) || !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {' '	if false {' TestMeshUISessionRouteRefusesForeignOriginAndPlainHTTP
mutate session-unknown-field $U '	dec.DisallowUnknownFields()' '	_ = dec' TestMeshUISessionRouteRefusesForeignOriginAndPlainHTTP
mutate signedout-always-ok   $U '	u.render(w, http.StatusUnauthorized, "signedout"' '	u.render(w, http.StatusOK, "signedout"' TestMeshUIRefusesWithoutAValidContext
mutate signedout-heading     $S '{{template "head" .}}<h1>Keep</h1>' '{{template "head" .}}<h1>Secrets</h1>' TestMeshUIRefusesWithoutAValidContext
mutate router-not-registered internal/api/router.go '			registerMeshUI(mux, logger, mr, catalog.New(pool))' '			_ = catalog.New(pool)' TestMeshUIFrameAncestorsAreOnlyTheInstalledMesh
# Data: read rights, closed fields.
mutate list-rights-off       $U '		if !perms[identity.PermReadMetadata] {
			continue
		}' '		_ = perms' TestMeshUIListsOnlyTheClosedFieldsAndNeverTheValue 'no role saw the catalog'
mutate list-filter-off       $U '(q != "" && !strings.Contains(strings.ToLower(ref.Name), q))' 'false' TestMeshUIListsOnlyTheClosedFieldsAndNeverTheValue 'name filter'
# Leak red run: a catalog row whose fingerprint carries the value reaches the page; the canary check must see it.
mutate leak-on-the-page      $T '"kfp1:k1:ABCDEFGHIJKLMNOP", len(value)' '"kfp1:k1:ABCDEFGHIJKLMNOP"+value, len(value)' TestMeshUIListsOnlyTheClosedFieldsAndNeverTheValue 'canary on the'
# Escaping: a secret named like markup must reach the page escaped.
mutate names-unescaped       $U '	"html/template"' '	"text/template"' TestMeshUIListsOnlyTheClosedFieldsAndNeverTheValue 'not escaped'
# Settings: CSRF, same origin, admin, weakening confirmation.
mutate settings-csrf-off     $U '!csrfValue(r.PostForm.Get("csrf"), s)' 'false' TestMeshUIKeyLevelSettings
mutate settings-origin-off   $U '	if !sameOrigin(r) || r.ParseForm() != nil' '	if r.ParseForm() != nil' TestMeshUIKeyLevelSettings
mutate settings-admin-off    $U '	if !v.IsAdmin {
		v.Error,' '	if false {
		v.Error,' TestMeshUIKeyLevelSettings
mutate settings-admin-perm   $U 'return perms[identity.PermManageRunners], nil' 'return perms[identity.PermReadMetadata], nil' TestMeshUIKeyLevelSettings
mutate settings-weaken-map   $U 'case errors.Is(err, ErrKeyLevelWeakening):' 'case false:' TestMeshUIKeyLevelSettings
mutate settings-form-for-all $U 'v.CanChange = can && admin' 'v.CanChange = can' TestMeshUIKeyLevelSettings
mutate settings-reread-off   $U '	v.ChangedAt, v.ChangedBy = "", ""
	if st, err := u.m.deps.KeyLevels.Get(r.Context(), s.Principal.OrgID); err == nil && !st.ChangedAt.IsZero() {
		v.ChangedAt, v.ChangedBy = when(st.ChangedAt), st.ChangedBy
	}' '	_ = s' TestMeshUIKeyLevelSettings 'previous change'
mutate settings-reread-actor-only $U 'v.ChangedAt, v.ChangedBy = when(st.ChangedAt), st.ChangedBy
	}
	u.render(w, http.StatusOK' 'v.ChangedBy = st.ChangedBy
	}
	u.render(w, http.StatusOK' TestMeshUIKeyLevelSettings 'previous change'
# Script: origin, source window, version, navigate path, toast length, target, login only without a session.
pkg=./internal/api
mutate js-origin-check-off   $S '!allowed(ev.origin)' 'false' TestMeshUIScriptPostMessageProtocol
mutate js-origin-prefix      $S 'return origins.indexOf(o) !== -1;' 'return typeof o === "string" && origins.some(function (x) { return o.indexOf(x) === 0; });' TestMeshUIScriptPostMessageProtocol
mutate js-origin-empty-ok    $S 'return origins.indexOf(o) !== -1;' 'return !o || origins.indexOf(o) !== -1;' TestMeshUIScriptPostMessageProtocol
mutate js-source-check-off   $S 'ev.source !== env.parent || ' '' TestMeshUIScriptPostMessageProtocol
mutate js-type-check-off     $S "d.type !== 'mesh.context' || " '' TestMeshUIScriptPostMessageProtocol
mutate js-navigate-any       $S "p.charAt(1) !== '/' && " '' TestMeshUIScriptPostMessageProtocol
mutate js-navigate-noop      $S 'function path(p) { return typeof p' 'function path(p) { return true || typeof p' TestMeshUIScriptPostMessageProtocol
mutate js-toast-untruncated  $S '.slice(0, 300)' '.slice(0)' TestMeshUIScriptPostMessageProtocol
mutate js-target-any         $S 'function send(msg) { if (target) {' 'function send(msg) { if (true) {' TestMeshUIScriptPostMessageProtocol
mutate js-target-star        $S 'env.parent.postMessage(msg, target)' 'env.parent.postMessage(msg, "*")' TestMeshUIScriptPostMessageProtocol
mutate js-login-always       $S 'if (env.needLogin && typeof d.token' 'if (typeof d.token' TestMeshUIScriptPostMessageProtocol
exit $fail
