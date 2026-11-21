#!/bin/sh
# Proves the browser scenario of the Mesh screen can fail: in a scratch copy of
# the tree, switch off one property of the screen (its script, its policy, its
# cookie) at a time and require TestMeshUIBrowserScenario to go red at the named
# step of scripts/check-mesh-ui-browser.mjs. A build error, a skip or a failure
# at another step is not evidence. Needs Chromium and a real PostgreSQL:
# KEEP_DATABASE_URL.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace
mutation_apply_only || : "${KEEP_DATABASE_URL:?KEEP_DATABASE_URL must name disposable PostgreSQL}"

shots_sum() { [ -n "${KEEP_MESH_UI_SHOTS:-}" ] && [ -d "$KEEP_MESH_UI_SHOTS" ] && (cd "$KEEP_MESH_UI_SHOTS" && cksum *.png 2>/dev/null) || true; }
shots_before=$(shots_sum)

fail=0
test=TestMeshUIBrowserScenario
# The screenshot directory belongs to the baseline run of the CI job; a mutant
# must not write there, or the artifact would show a red tree.
run() { (cd "$1" && env -u KEEP_MESH_UI_SHOTS go test -tags mesh_ui_browser -count=1 -p 1 -timeout 240s -run "^$test\$" -v ./cmd/keep-server/app >"$2" 2>&1); }

# Baseline: the scenario passes untouched and nothing is skipped.
if ! mutation_apply_only; then
	if ! run "$root" "$work/base" || grep -q -- '--- SKIP' "$work/base" || ! grep -q -- '--- PASS' "$work/base"; then
		echo "FAIL baseline: the browser scenario is not green on the unmodified tree"
		"$root/scripts/test-result-names.sh" "$root" <"$work/base" ||
			echo "FAIL diagnostics: test-result-names.sh exited $?"
		exit 1
	fi
	echo "ok   baseline: $test passes, no skip"
fi

# mutate NAME FILE FROM TO STEP: replace one literal FROM with TO in FILE and
# require the scenario to fail at STEP (a name without spaces) or with the
# literal message STEP (a text with spaces).
mutate() {
	mutation_take_occurrences
	name=$1 file=$2 from=$3 to=$4 step=$5
	mutation_snapshot "$work/tree"
	if ! { mutation_edit "$work/tree/$file" "$from" "$to" "${mutation_occurrence:-}" >"$work/edited" &&
		mv "$work/edited" "$work/tree/$file"; }
	then
		echo "FAIL $name: mutation did not apply, the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if run "$work/tree" "$work/out"; then
		echo "FAIL $name: the scenario stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	elif case "$step" in *" "*) ! grep -qF -- "$step" "$work/out" ;; *) ! grep -q -- "FAIL step=$step:" "$work/out" ;; esac; then
		echo "FAIL $name: the scenario went red at another step (wanted $step)"
		"$root/scripts/test-result-names.sh" "$work/tree" <"$work/out" ||
			echo "FAIL diagnostics: test-result-names.sh exited $?"
		fail=1
	else
		echo "ok   $name: red at step $step"
	fi
}

U=internal/api/mesh_ui.go
S=internal/api/mesh_ui_assets.go
# Script: window and origin checks, each alone, and every message the screen speaks.
mutate js-source-check-off    $S 'ev.source !== env.parent || ' '' mesh-origin-other-window
# The origin check alone cannot be separated in a browser: a message from the
# parent window itself arrives with an allowed origin or not at all. It is
# killed alone by TestMeshUIScriptPostMessageProtocol (check-mesh-ui-mutations.sh);
# here both checks go together and the foreign window must get through.
mutate js-both-checks-off     $S 'if (!ev || ev.source !== env.parent || !allowed(ev.origin)) { return; }' 'if (!ev) { return; }' foreign-origin-window
mutate js-login-noop          $S 'env.login(d.token).then(function (ok) { if (ok) { env.reload(); } }, function () {});' 'void 0;' context-signin
mutate js-workspace-noop      $S 'env.workspace(d.workspace_slug);' 'void 0;' context-resize-navigate
mutate js-resize-noop         $S "if (typeof h === 'number' && h > 0) {" "if (false) {" context-resize-navigate
mutate js-navigate-noop       $S 'function path(p) { return typeof p' 'function path(p) { return false && typeof p' context-resize-navigate
mutate js-toast-noop          $S 'toast: function (level, message) { send(' 'toast: function (level, message) { void(' key-level-toast
mutate js-ready-noop          $S "ready: function () { send({ type: 'mesh.ready' }); }" "ready: function () {}" context-resize-navigate
# Policy: the frame must be refused for a foreign ancestor and open for Mesh.
mutate csp-ancestors-widened  $U '		anc = strings.Join(origins, " ")' '		anc = strings.Join(origins, " ") + " *"' foreign-embed
mutate csp-ancestors-none     $U '		anc = strings.Join(origins, " ")' '		_ = origins' sidebar-signin
# The sidebar entry Mesh draws comes from the manifest title.
mutate manifest-sidebar-title mesh-extension.json '"title": "Keep"' '"title": "Secrets"' sidebar-signin
mutate toast-attr-dropped     $S '{{if .Toast}} data-toast="{{.Toast}}" data-toast-level="{{.ToastLvl}}"{{end}}' '' key-level-toast
mutate narrow-frame-overflow  $S '.row-link{font-weight:500;text-decoration:none;color:hsl(var(--foreground));overflow-wrap:anywhere}' '.row-link{font-weight:500;text-decoration:none;color:hsl(var(--foreground));white-space:nowrap}' narrow
mutate settings-form-overflow    $S '.levels{display:grid;gap:8px;margin:12px 0 16px;padding:0;border:0;min-width:0}' '.levels{display:grid;gap:8px;margin:12px 0 16px;padding:0;border:0;min-width:600px}' key-level-narrow
mutate settings-form-hidden      $S '.levels{display:grid;gap:8px;margin:12px 0 16px;padding:0;border:0;min-width:0}' '.levels{display:none}' key-level-narrow
# Empty-list guidance and the add form stay visible within the frame;
# an existing record's long terminal command scrolls inside its own box.
mutate empty-guidance-hidden $S '.empty small{display:block;' '.empty small{display:none;' empty-narrow
mutate empty-guidance-overflow $S '.empty small{display:block;' '.empty small{display:block;min-width:600px;' empty-narrow
mutate empty-form-hidden     $S '.add-form{display:flex;' '.add-form{display:none;' empty-narrow
mutate empty-form-overflow   $S '.add-form{display:flex;' '.add-form{display:flex;min-width:600px;' empty-narrow
mutate empty-command-unbounded $S '.empty code{display:inline-block;max-width:100%;overflow-x:auto;' '.empty code{display:inline-block;' empty-long-narrow
# Fonts: the policy must let the embedded fonts load, and the style must use them.
mutate csp-font-src-dropped   $U "font-src 'self'; " '' fonts
mutate font-face-broken       $S 'src:url(/mesh/ui/fonts/inter-latin-500-normal.woff2)' 'src:url(/mesh/ui/fonts/inter-latin-500-missing.woff2)' fonts
# Theme: dark tokens from mesh.context on every page load, mesh.theme live; a
# token of the wrong name or shape never reaches the style.
mutate theme-noop             $S "if (tokenOK(n, tokens[k])) { st.setProperty('--' + n, tokens[k]); }" 'void 0;' theme-dark
mutate theme-context-off      $S '      applyMeshTheme(d.theme);' '' theme-dark
mutate theme-message-off      $S "if (d.type === 'mesh.theme') { applyMeshTheme(d); return; }" "if (d.type === 'mesh.theme') { return; }" theme-dark
mutate theme-check-off        $S "if (tokenOK(n, tokens[k])) {" "if (true) {" theme-dark
mutate theme-scheme-off       $S "st.setProperty('color-scheme', t.mode);" 'void 0;' theme-dark
mutate theme-var-unused       $S 'body{font:400 14px/20px var(--font-sans);color:hsl(var(--foreground));background:hsl(var(--background));' 'body{font:400 14px/20px var(--font-sans);color:hsl(var(--foreground));background:hsl(0 0% 100%);' theme-dark
# The page of one secret: a row opens it, it fits a 393 px frame, and its DOM
# is part of the leak scan.
B=internal/api/mesh_ui_secrets.go
H=internal/api/mesh_ui_secrets_html.go
mutate secret-row-link-dead   $B 'Href: "/mesh/ui/secrets/" + ref.ID.String(), Name:' 'Href: "/mesh/ui/secrets", Name:' secret-page
mutate secret-wrap-dropped    $H '{{if $i}}<wbr>{{end}}' '' secret-page-narrow
mutate secret-dom-not-scanned scripts/check-mesh-ui-browser.mjs "await dump(keepSecrets + '/');" 'void 0;' 'the DOM dump is missing'
mutate list-dom-not-scanned   scripts/check-mesh-ui-browser.mjs "await dump(keepSecrets);" 'void 0;' 'the DOM dump is missing'
mutate settings-dom-not-scanned scripts/check-mesh-ui-browser.mjs "await dump(keep + '/mesh/ui/settings');" 'void 0;' 'the DOM dump is missing'
# Leak red run: the fingerprint of a catalog row carries the value, so the
# browser renders it; the scan of the real DOM must see it.
mutate leak-in-the-dom        cmd/keep-server/app/mesh_ui_test.go '"kfp1:k1:ABCDEFGHIJKLMNOP", len(value)' '"kfp1:k1:ABCDEFGHIJKLMNOP"+value, len(value)' 'canary in the browser DOM'
# Add secret: the button above the list, the form in the empty state, the
# link opens in a new tab outside Mesh's sandbox, Copy fills the clipboard,
# and the links the run saw reach the server-log scan.
mutate add-button-gone        $H '{{if .Total}}{{template "add-button" .}}{{end}}' '' sidebar-signin
# Without the input service the screen offers no Add secret link at all: the
# disabled button replaces it above the list, so the first step goes red.
mutate add-input-unwired      $U '	if deps.Input != nil {' '	if false {' 'no Add secret above the list'
mutate add-copy-noop          $S 'if (cp) { copyFrom(cp); }' 'void 0;' add-secret-1440
mutate add-copy-truncated     $S "var text = field ? field.value : btn.getAttribute('data-copy');" "var text = field ? field.value.slice(0, -1) : btn.getAttribute('data-copy');" 'did not hand the link to the clipboard'
mutate clipboard-recorder-off scripts/check-mesh-ui-browser.mjs "try { __keepClipboardHandoff(String(t)); } catch (e) {}" 'void 0;' 'did not hand the link to the clipboard'
mutate add-popups-blocked     cmd/keep-server/app/mesh_ui_browser_test.go ' allow-popups allow-popups-to-escape-sandbox"' '"' add-secret-1440
mutate add-links-not-scanned  scripts/check-mesh-ui-browser.mjs "if (input.linkDump) await appendFile(input.linkDump, res.link + '\n');" 'void 0;' 'no input links were recorded'
mutate add-link-in-server-log cmd/keep-server/app/mesh_ui_browser_test.go 'if tok == "" || tok == l || strings.Contains(f.logbuf.String(), tok) || f.logbuf.Len() == 0 {' 'f.logbuf.WriteString(tok); if tok == "" || tok == l || strings.Contains(f.logbuf.String(), tok) || f.logbuf.Len() == 0 {' 'token reached the server log'
# The baseline screenshots must be byte-identical after every mutant ran.
if [ "$(shots_sum)" != "$shots_before" ]; then
	echo "FAIL screenshots: a mutant rewrote the baseline PNG files"
	fail=1
fi
exit $fail
