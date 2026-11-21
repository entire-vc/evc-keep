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
# mutate NAME FILES FROM TO TEST [WANT]: replace one literal FROM with TO in each
# space-separated file, then require TEST (in $pkg) to fail with a real --- FAIL,
# naming WANT when given. Shared template clones must use the same template type.
mutate() {
	mutation_take_occurrences
	name=$1 files=$2 from=$3 to=$4 test=$5 want=${6:-}
	mutation_snapshot "$work/tree"
	for file in $files; do
		if ! { mutation_edit "$work/tree/$file" "$from" "$to" "${mutation_occurrence:-}" >"$work/edited" &&
			mv "$work/edited" "$work/tree/$file"; }
		then
			echo "FAIL $name: mutation did not apply, the source changed, update this script"
			fail=1
			return
		fi
	done
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

# A red baseline or a skipped database test cannot prove a guard.
mutation_baseline -p 1 -timeout 240s -run '^TestMeshUI' ./internal/api ./cmd/keep-server/app || exit 1
if ! mutation_apply_only && grep -q '"Action":"skip"' "$work/baseline"; then
	echo "FAIL baseline: skipped tests"
	exit 1
fi

U=internal/api/mesh_ui.go
R=internal/api/mesh_ui_rotation_pages.go
L=internal/api/mesh_ui_secrets.go
S=internal/api/mesh_ui_assets.go
T=cmd/keep-server/app/mesh_ui_test.go
# CSP: the policy source, the 'none' fallback, the script source, the injection filter.
mutate csp-ancestors-widened $U '		anc = strings.Join(origins, " ")' '		anc = strings.Join(origins, " ") + " *"' TestMeshUIFrameAncestorsAreOnlyTheInstalledMesh
mutate csp-ancestors-default $U '	anc := "'"'"'none'"'"'"' '	anc := "*"' TestMeshUIRefusesWithoutAValidContext
mutate csp-script-inline     $U "script-src 'self';" "script-src 'self' 'unsafe-inline';" TestMeshUIFrameAncestorsAreOnlyTheInstalledMesh
mutate csp-headers-noop      $U '	meshUIHeaders(w, origins)
	u.secretsPage' '	u.secretsPage' TestMeshUIFrameAncestorsAreOnlyTheInstalledMesh
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
mutate signedout-heading     $U 'NeedLogin: len(origins) > 0, Title: "Keep"}' 'NeedLogin: len(origins) > 0, Title: "Secrets"}' TestMeshUIRefusesWithoutAValidContext
mutate router-not-registered internal/api/router.go '			u := registerMeshUI(mux, logger, mr, catalog.New(pool), meshUIDeps{Carriers: meshUICarriersOf(deps.Carriers), Rotations: runs, Input: deps.Input})' '			u := &meshUI{m: mr, logger: logger, deps: meshUIDeps{Rotations: runs}}; _ = catalog.New(pool)' TestMeshUIFrameAncestorsAreOnlyTheInstalledMesh
# Data: read rights, closed fields.
mutate list-rights-off       $L 'if perms[identity.PermReadMetadata] {' 'if _ = perms; true {' TestMeshUIListsOnlyTheClosedFieldsAndNeverTheValue 'no role saw the catalog'
mutate list-filter-off       $L '(needle != "" && !strings.Contains(strings.ToLower(ref.Name), needle))' '(needle != "" && false)' TestMeshUIListsOnlyTheClosedFieldsAndNeverTheValue 'name filter'
# Leak red run: a catalog row whose fingerprint carries the value reaches the page; the canary check must see it.
mutate leak-on-the-page      $T '"kfp1:k1:ABCDEFGHIJKLMNOP", len(value)' '"kfp1:k1:ABCDEFGHIJKLMNOP"+value, len(value)' TestMeshUIListsOnlyTheClosedFieldsAndNeverTheValue 'canary on the'
# Escaping: a secret named like markup must reach the page escaped.
mutate names-unescaped       "$U $R" '	"html/template"' '	"text/template"' TestMeshUIListsOnlyTheClosedFieldsAndNeverTheValue 'not escaped'
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
# Secrets: the value boundary, state filters/order, pagination and one missing answer.
H=internal/api/mesh_ui_secrets_html.go
mutate secret-value-rendered $L 'v.Banner = secretBanner(v, current, stale, last)' 'v.Banner = secretBanner(v, current, stale, last)
	leaked, _, _ := u.m.deps.Vault.ResolveSecret(ctx, "", "", "")
	_, _ = w.Write(leaked)' TestMeshUISecretPagesLeak 'canary on'
mutate secret-value-header $L 'v.Banner = secretBanner(v, current, stale, last)' 'v.Banner = secretBanner(v, current, stale, last)
	leaked, _, _ := u.m.deps.Vault.ResolveSecret(ctx, "", "", "")
	w.Header().Set("X-Leak", string(leaked))' TestMeshUISecretPagesLeak 'canary on'
mutate secret-value-logged $L 'v.Banner = secretBanner(v, current, stale, last)' 'v.Banner = secretBanner(v, current, stale, last)
	leaked, _, _ := u.m.deps.Vault.ResolveSecret(ctx, "", "", "")
	u.logger.Info(string(leaked))' TestMeshUISecretPagesLeak 'canary in the log'
mutate secret-value-read $L 'v.Banner = secretBanner(v, current, stale, last)' 'v.Banner = secretBanner(v, current, stale, last)
	_, _, _ = u.m.deps.Vault.ResolveSecret(ctx, "", "", "")' TestMeshUISecretPagesLeak 'the screens read a value'
mutate secret-attention-off $L '(q.state == "attention" && !row.State.attention)' 'false' TestMeshUIStateFilters
mutate secret-rotating-off $L '(q.state == "rotating" && !row.State.rotating)' 'false' TestMeshUIStateFilters
mutate secret-class-off $L '(q.class != "" && ref.Class != q.class)' 'false' TestMeshUIStateFilters
mutate secret-scope-off $L '(q.scope != "" && string(ref.Scope.Level) != q.scope)' 'false' TestMeshUIStateFilters
mutate secret-rotated-sort-reversed $L 'return a.rotatedAt.After(b.rotatedAt)' 'return a.rotatedAt.Before(b.rotatedAt)' TestMeshUIStateFilters
mutate secret-failed-priority-off $L 'case run != nil && run.State == "failed":' 'case false:' TestMeshUIStateFilters
mutate secret-state-sort-reversed $L 'return a.State.rank < b.State.rank' 'return a.State.rank > b.State.rank' TestMeshUIStateFilters
mutate secret-page-offset-off $L 'from := (q.page - 1) * meshUIPageSize' 'from := 0' TestMeshUIListPages
mutate secret-page-query-lost $L 'set("q", q.q)' 'set("q", "")' TestMeshUIListPages
mutate secret-malformed-different $L 'id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		u.secretMissing(w, base)' 'id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		u.render(w, http.StatusServiceUnavailable, "unavailable", base)' TestMeshUISecretNotFoundIsOneAnswer
mutate secret-six-runs $L 'meshUIRecentRuns = 5' 'meshUIRecentRuns = 6' TestMeshUISecretPageBlocks
mutate secret-stale-banner-off $L 'case len(stale) > 0:' 'case false:' TestMeshUISecretPageBlocks
mutate secret-failed-banner-off $L 'case last != nil && last.State == "failed":' 'case false:' TestMeshUISecretPageBlocks
mutate secret-no-carriers-banner-off $L 'case v.ShowCarriers && len(v.Carriers) == 0 && current != "":' 'case false:' TestMeshUISecretPageBlocks
mutate secret-old-version-in-sync $L 'case c.Version != current:' 'case false:' TestMeshUISecretPageBlocks
mutate secret-drift-as-old-version $L 'case c.Version != current:' 'case c.Version != current || c.State == carriers.Stale:' TestMeshUISecretPageDrift
mutate secret-drift-branch-off $L 'case c.State == carriers.Stale:' 'case false:' TestMeshUISecretPageDrift
mutate secret-drift-held-lookup-off $L 'if held, ok := byFP[c.LastFP]; ok && c.LastFP != "" && held != current {' 'if held, ok := "", false; ok {' TestMeshUISecretPageDrift
mutate secret-unknown-carrier-off $L 'case c.State == carriers.Unknown:' 'case false:' TestMeshUISecretPageBlocks
mutate secret-nil-carriers-shown $H '{{if .ShowCarriers}}<div class="section">' '{{if true}}<div class="section">' TestMeshUISecretPageBlocks
mutate secret-nil-rotations-shown $H '{{if .ShowRotations}}<div class="section">' '{{if true}}<div class="section">' TestMeshUISecretPageBlocks
mutate secret-empty-state-off $H 'No secrets yet' 'Empty' TestMeshUISecretsEmptyAndEscaped
mutate secret-names-unescaped "$U $R" '	"html/template"' '	"text/template"' TestMeshUISecretsEmptyAndEscaped
mutate secret-long-runs-unbroken $L 'const wrapRun = 16' 'const wrapRun = 160' TestMeshUIWrapTextBreaksLongRuns
mutate secret-version-prefix-off $L 'return "v" + v' 'return v' TestMeshUIVersionLabel
pkg=./cmd/keep-server/app
mutate secret-read-right-noop $L 'if perms[identity.PermReadMetadata] {' 'if _ = perms; true {' TestMeshUISecretPageLeakOnRealStore
pkg=./internal/api
# The list and the page of a secret read rotation runs through the closed
# vocabulary of the rotation screens: bypassed at the router or turned into
# a pass-through, a hostile run history reaches those pages.
R=internal/api/mesh_ui_rotation_pages.go
mutate runs-closed-bypassed  internal/api/router.go 'runs := meshUIClosedRuns(deps.Mesh.Rotations)' 'runs := deps.Mesh.Rotations; _ = meshUIClosedRuns' TestMeshUIRotationLeak_HostileSources 'canary from a hostile source'
mutate runs-closed-noop      $R '	return closedRuns{r: r}' '	return r' TestMeshUIRotationLeak_HostileSources 'canary from a hostile source'
# The rotation screens check access with the same reader as the page of a secret.
mutate rotation-read-right-noop $L 'if perms[identity.PermReadMetadata] {' 'if _ = perms; true {' TestMeshUIRotationRequiresReadMetadata 'expected the common 404'
# Live refresh reads the body only of a text/html answer: the media type
# exactly, not a prefix of it (text/htmlx), and never any type.
V=internal/api/mesh_ui_rotation_assets.go
mutate live-type-prefix      $V "t === 'text/html'" "t.indexOf('text/html') === 0" TestMeshUIRotationLiveScriptRejectsNonHTMLResponses 'html-suffix: response body read'
mutate live-type-off         $V "r.ok && t === 'text/html'" 'r.ok' TestMeshUIRotationLiveScriptRejectsNonHTMLResponses 'json: response body read'
mutate js-origin-check-off   $S '!allowed(ev.origin)' 'false' TestMeshUIScriptPostMessageProtocol
mutate js-origin-prefix      $S 'return origins.indexOf(o) !== -1;' 'return typeof o === "string" && origins.some(function (x) { return o.indexOf(x) === 0; });' TestMeshUIScriptPostMessageProtocol
mutate js-origin-empty-ok    $S 'return origins.indexOf(o) !== -1;' 'return !o || origins.indexOf(o) !== -1;' TestMeshUIScriptPostMessageProtocol
mutate js-source-check-off   $S 'ev.source !== env.parent || ' '' TestMeshUIScriptPostMessageProtocol
mutate js-type-check-off     $S "if (d.type !== 'mesh.context') { return; }" '' TestMeshUIScriptPostMessageProtocol
mutate js-version-any        $S '(d.version !== 1 && d.version !== 2)' 'false' TestMeshUIScriptPostMessageProtocol
mutate js-navigate-any       $S "p.charAt(1) !== '/' && " '' TestMeshUIScriptPostMessageProtocol
mutate js-navigate-noop      $S 'function path(p) { return typeof p' 'function path(p) { return true || typeof p' TestMeshUIScriptPostMessageProtocol
mutate js-toast-untruncated  $S '.slice(0, 300)' '.slice(0)' TestMeshUIScriptPostMessageProtocol
mutate js-target-any         $S 'function send(msg) { if (target) {' 'function send(msg) { if (true) {' TestMeshUIScriptPostMessageProtocol
mutate js-target-star        $S 'env.parent.postMessage(msg, target)' 'env.parent.postMessage(msg, "*")' TestMeshUIScriptPostMessageProtocol
mutate js-login-always       $S 'if (env.needLogin && typeof d.token' 'if (typeof d.token' TestMeshUIScriptPostMessageProtocol
# Theme: only listed names with values of the token's shape reach the root
# style, from mesh.context (1 and 2) and mesh.theme; mode is light or dark.
th=TestMeshUIScriptAppliesOnlyValidThemeTokens
mutate js-theme-value-off    $S ' && /^[0-9. %]{1,32}$/.test(v)' '' $th 'invalid token name or value'
mutate js-theme-value-loose  $S '/^[0-9. %]{1,32}$/' '/^[^;]{1,64}$/' $th 'invalid token name or value'
mutate js-theme-name-off     $S 'THEME.indexOf(n) !== -1 && ' '' $th 'invalid token name or value'
mutate js-theme-radius-off   $S '/^[0-9.]{1,6}rem$/.test(v)' 'true' $th 'invalid radius'
mutate js-theme-type-off     $S "if (typeof v !== 'string') { return false; }" '' $th 'invalid token name or value'
mutate js-theme-mode-any     $S "if (t.mode === 'light' || t.mode === 'dark') {" 'if (t.mode) {' $th 'invalid token or mode'
mutate js-theme-noop         $S "if (tokenOK(n, tokens[k])) { st.setProperty('--' + n, tokens[k]); }" 'void 0;' $th
mutate js-theme-ctx-off      $S '      applyMeshTheme(d.theme);' '' $th
mutate js-theme-msg-off      $S "if (d.type === 'mesh.theme') { applyMeshTheme(d); return; }" "if (d.type === 'mesh.theme') { return; }" $th
mutate js-theme-v2-off       $S '(d.version !== 1 && d.version !== 2)' 'd.version !== 1' $th
mutate js-v2-no-signin       $S '(d.version !== 1 && d.version !== 2)' 'd.version !== 1' TestMeshUIScriptPostMessageProtocol 'protocol 2 context did not sign in'
mutate js-theme-before-check $S "      if (!ev || ev.source !== env.parent || !allowed(ev.origin)) { return; }" "      if (ev && ev.data && ev.data.type === 'mesh.theme') { applyMeshTheme(ev.data); }
      if (!ev || ev.source !== env.parent || !allowed(ev.origin)) { return; }" $th 'foreign origin'
# Style: Mesh tokens only, with the Mesh light theme as the fallback.
st=TestMeshUIStyleUsesOnlyMeshTokens
mutate css-own-dark-mode     $S 'color-scheme:light}' 'color-scheme:light}@media (prefers-color-scheme:dark){:root{--background:0 0% 0%}}' $st 'prefers-color-scheme'
mutate css-system-font       $S '--font-sans:"Inter",ui-sans-serif,sans-serif;' '--font-sans:system-ui,sans-serif;' $st 'system-ui'
mutate css-own-colour        $S 'a{color:inherit}' 'a{color:#2457d6}' $st 'hex colour'
mutate css-fallback-missing  $S '--radius:0.5rem;' '' $st 'no fallback for --radius'
mutate js-theme-list-wider    $S "var THEME = ['background', " "var THEME = ['sidebar-background', 'background', " $st 'the script accepts'
mutate css-foreign-token     $S 'body{font:400 14px/20px var(--font-sans);' 'body{font:400 14px/20px var(--font-sans);outline-color:var(--accent-2);' $st 'not a Mesh theme token'
# Fonts: font-src 'self' only; the route serves only the built-in files.
mutate csp-font-src-off      $U "font-src 'self'; " '' TestMeshUICSPShape "font-src"
mutate csp-font-src-wide     $U "font-src 'self';" "font-src 'self' https:;" TestMeshUICSPShape "font-src"
mutate font-allowlist-off    internal/api/mesh_ui_fonts.go '	if !ok || !strings.HasSuffix(name, ".woff2") {' '	if (!ok && false) || !strings.HasSuffix(name, ".woff2") {' TestMeshUIFontsRoute 'want 404'
mutate font-type-wrong       internal/api/mesh_ui_fonts.go '"font/woff2")' '"application/octet-stream")' TestMeshUIFontsRoute
mutate font-corp-off         internal/api/mesh_ui_fonts.go 'h.Set("Cross-Origin-Resource-Policy", "same-origin")' '_ = h' TestMeshUIFontsRoute 'Cross-Origin-Resource-Policy'
mutate font-cache-off        internal/api/mesh_ui_fonts.go 'h.Set("Cache-Control", "public, max-age=604800")' '_ = h' TestMeshUIFontsRoute 'Cache-Control'
mutate font-route-missing    $U '		{"GET", "/mesh/ui/fonts/{name}", u.font},
' '' TestMeshUIFontsRoute
mutate font-tls-off          $U 'logged(e.pattern, logger, requireTLS(e.h).ServeHTTP)' 'logged(e.pattern, logger, e.h)' TestMeshUIFontsRoute 'plain HTTP served a font'
# Add secret: a closed form behind the session's CSRF token and same-origin
# check, a scope from a closed list, the one-time link on the page only (the
# toast Mesh receives is fixed text), a new tab without opener or referrer.
A=internal/api/mesh_ui_add.go
mutate add-csrf-off          $A ' || !csrfValue(r.PostForm.Get("csrf"), s) {' ' {' TestMeshUIAddSecretCSRF
mutate add-origin-off        $A '	if !sameOrigin(r) || r.ParseForm() != nil' '	if r.ParseForm() != nil' TestMeshUIAddSecretCSRF
mutate add-fields-open       $A '		if !known || len(vs) != 1 {' '		if _ = vs; false {' TestMeshUIAddSecretFormIsClosed
mutate add-scope-any         $A '	default:
		u.secretMissing(w, base)
		return
	}' '	default:
		scope = tenancy.Scope{Level: tenancy.LevelUser, ID: s.Principal.ID}
	}' TestMeshUIAddSecretRefusals
mutate add-name-check-off    $A 'if msg := checkAddName(name, class); msg != "" {' 'if msg := checkAddName(name, class); msg == "x" {' TestMeshUIAddSecretRefusals
mutate add-link-in-log       internal/api/mesh_ui_add_test.go 'if h.logbuf.Len() == 0 {' 'h.logbuf.WriteString(add.token); if h.logbuf.Len() == 0 {' TestMeshUIAddSecretLinkStaysOnThePage 'token in the log'
mutate add-link-in-toast     $A 'base.Toast, base.ToastLvl = "Input link created", "success"' 'base.Toast, base.ToastLvl = "Input link created "+res.Link.URL, "success"' TestMeshUIAddSecretLinkStaysOnThePage 'fixed text'
mutate add-exists-unmapped   $A '	case errors.As(err, &exists):' '	case false:' TestMeshUIAddSecretRefusals
mutate add-shell-quote-off   $A '	if shellSafe.MatchString(name) {' '	if true {' TestMeshUIShellQuote
H=internal/api/mesh_ui_secrets_html.go
mutate add-open-same-tab     $H ' target="_blank" rel="noopener noreferrer">Open input page' '>Open input page' TestMeshUIAddSecretLinkStaysOnThePage
mutate add-opener-kept       $H 'rel="noopener noreferrer">Open input page' 'rel="opener">Open input page' TestMeshUIAddSecretLinkStaysOnThePage
mutate add-premature-command $H 'The value goes straight to Keep, never through Mesh or chat.</small>' 'The value goes straight to Keep, never through Mesh or chat. <code>keep input-link NAME</code></small>' TestMeshUIAddSecretFormIsClosed 'before a record exists'
mutate add-value-field       $H '<button class="btn" type="submit">Create input link</button></form>{{end}}' '<input type="password" name="value"><button class="btn" type="submit">Create input link</button></form>{{end}}' TestMeshUIAddSecretFormIsClosed
mutate add-reason-hidden     $H '<span class="muted" id="add-why">{{.Add.Reason}}</span>' '<span class="muted" id="add-why"></span>' TestMeshUIAddSecretRefusals
mutate add-link-form-for-all $L '		v.LinkReason = add.Reason
' '		v.LinkReason, v.CanLink = add.Reason, true
' TestMeshUISecretPageInputLink
# Copy never fails silently: clipboard API, then select + execCommand, then
# the field left selected for the keyboard.
cp=TestMeshUIScriptCopyNeverSilent
mutate copy-exec-off         $S 'if (sel) { try { ok = env.exec() === true; }' 'if (false) { try { ok = env.exec() === true; }' $cp 'fallback'
mutate copy-reselect-off     $S 'if (sel) { try { env.select(); }' 'if (false) { try { env.select(); }' $cp 'left selected'
mutate copy-reject-silent    $S "function () { return fallback(); });" "function () { return ''; });" $cp
mutate copy-manual-empty     $S "if (how === 'manual') { return { level: 'info', text: MANUAL }; }" "if (how === 'manual') { return { level: 'info', text: '' }; }" $cp 'fail silently'
# On a real store: rights, the built-in store before the record, a random
# locator, the audit record.
pkg=./cmd/keep-server/app
# Keep got and pm in use: a bare `if false {` leaves them unused and the
# mutant dies at compile time, which proves nothing about the rights check.
mutate add-rights-off        $A '		if !got[pm] {' '		if false && !got[pm] {' TestMeshUIAddSecretOnRealStore 'own scope only'
mutate add-store-check-off   $A '	if st.Provider != "builtin" || st.Status != "active" {' '	if st.Status != "active" {' TestMeshUIAddSecretRefusesNonBuiltinStore
mutate add-locator-is-name   $A 'path := "builtin://" + st.Name + "/" + loc.String()' 'path := "builtin://" + st.Name + "/" + strings.ReplaceAll(in.Name, " ", "-") + loc.String()[:0]' TestMeshUIAddSecretOnRealStore 'provider_ref'
mutate add-audit-off         $A '	a.journal(ctx, p, audit.SecretRef{ID: created.ID.String(), Name: created.Name}, audit.StatusOK, audit.ErrClassNone)' '' TestMeshUIAddSecretOnRealStore 'create_ref audit'
mutate add-link-in-audit     $A 'return meshUIIssued{SecretID: ref.ID, Name: ref.Name, Scope: ref.Scope.Level, Link: link}, nil' 'a.journal(ctx, p, audit.SecretRef{ID: ref.ID.String(), Name: link.URL}, audit.StatusOK, audit.ErrClassNone); return meshUIIssued{SecretID: ref.ID, Name: ref.Name, Scope: ref.Scope.Level, Link: link}, nil' TestMeshUIAddSecretOnRealStore 'token reached the log or the journal'
mutate add-input-off-reason  $A 'reasonInputOff     = "Input links are not set up on this server."' 'reasonInputOff     = ""' TestMeshUIAddSecretOffWithoutInputLinks 'no reason without input links'
pkg=./internal/api
exit $fail
