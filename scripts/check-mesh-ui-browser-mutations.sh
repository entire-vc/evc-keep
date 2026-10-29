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
		tail -n 15 "$work/base"
		exit 1
	fi
	echo "ok   baseline: $test passes, no skip"
fi

# mutate NAME FILE FROM TO STEP: replace one literal FROM with TO in FILE and
# require the scenario to fail at STEP (a name without spaces) or with the
# literal message STEP (a text with spaces).
mutate() {
	name=$1 file=$2 from=$3 to=$4 step=$5
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
		grep -- 'FAIL step=' "$work/out" | head -n 2
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
mutate narrow-frame-overflow  $S 'min-width:0;text-align:right;overflow-wrap:anywhere}' 'min-width:0;text-align:right;white-space:nowrap}' narrow
mutate settings-form-overflow    $S '.stack{display:flex;flex-direction:column;gap:12px;max-width:420px}' '.stack{display:flex;flex-direction:column;gap:12px;min-width:600px}' key-level-narrow
mutate settings-form-hidden      $S '.stack{display:flex;flex-direction:column;gap:12px;max-width:420px}' '.stack{display:none}' key-level-narrow
# Leak red run: the fingerprint of a catalog row carries the value, so the
# browser renders it; the scan of the real DOM must see it.
mutate leak-in-the-dom        cmd/keep-server/app/mesh_ui_test.go '"kfp1:k1:ABCDEFGHIJKLMNOP", len(value)' '"kfp1:k1:ABCDEFGHIJKLMNOP"+value, len(value)' 'canary in the browser DOM'
# The baseline screenshots must be byte-identical after every mutant ran.
if [ "$(shots_sum)" != "$shots_before" ]; then
	echo "FAIL screenshots: a mutant rewrote the baseline PNG files"
	fail=1
fi
exit $fail
