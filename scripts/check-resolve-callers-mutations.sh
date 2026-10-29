#!/bin/sh
# Proves scripts/check-resolve-callers.sh can fail: in a scratch copy of the
# tree, add a second reader of ResolveSecret in each shape (another function,
# a method value, a package-level closure, another package, a renamed handler)
# and require the guard to exit 1 naming it; the clean tree, a comment and a
# test file must pass. No Go build is needed: the guard reads source.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/lib/gocache.sh"
. "$root/scripts/temp-workspace.sh"
. "$root/scripts/mutation-helpers.sh"
temp_workspace

fail=0
tree=$work/tree
fresh() {
	rm -rf "$tree"
	mutation_snapshot "$tree"
}
# expect_red NAME: the guard must fail and name FORBIDDEN or the missing caller.
expect_red() {
	if "$root/scripts/check-resolve-callers.sh" "$tree" >"$work/out" 2>&1; then
		echo "FAIL $1: guard stayed green with a second reader"
		fail=1
	elif ! grep -q -e 'ResolveSecret' "$work/out"; then
		echo "FAIL $1: guard failed for another reason"
		cat "$work/out"
		fail=1
	else
		echo "ok   $1: guard went red"
	fi
}
expect_green() {
	if "$root/scripts/check-resolve-callers.sh" "$tree" >"$work/out" 2>&1; then
		echo "ok   $1: guard stayed green"
	else
		echo "FAIL $1: guard refused a permitted tree"
		cat "$work/out"
		fail=1
	fi
}

# The one probe that edits real source; the rest plant new files. It renames
# the declaration in FILE and refuses (exit 1) unless exactly one line starts
# with the original declaration: sed matching nothing, a source already renamed
# or a reformatted signature with either name in a comment would otherwise
# leave the guard nothing to catch while the probe reported it applied.
handler_decl='func (m \*meshRoutes) handleResolveSecret(w http.ResponseWriter'
rename_handler() {
	[ "$(grep -c "^$handler_decl" "$1")" = 1 ] || return 1
	sed "s/^$handler_decl/func (m *meshRoutes) handleResolveSecretRenamed(w http.ResponseWriter/" "$1" >"$1.new"
	mv "$1.new" "$1"
}

# rename_handler must refuse a source it cannot really change, in both modes.
# The inputs are built from a fixed declaration, not from mesh.go, so they
# stay meaningful whatever the source looks like; the declaration itself must
# be accepted and renamed.
decl='func (m *meshRoutes) handleResolveSecret(w http.ResponseWriter, r *http.Request) {'
renamed='func (m *meshRoutes) handleResolveSecretRenamed(w http.ResponseWriter, r *http.Request) {'
spaced='func (m *meshRoutes) handleResolveSecret( w http.ResponseWriter, r *http.Request) {'
refuse_rename() {
	if rename_handler "$work/stale.go"; then
		echo "FAIL rename-check $1: an unapplied rename counted as applied"
		exit 1
	fi
	echo "ok   rename-check $1: refused"
}
printf 'package api\n\n%s\n}\n' "$decl" >"$work/stale.go"
if ! rename_handler "$work/stale.go" || [ "$(grep -cxF "$renamed" "$work/stale.go")" != 1 ]; then
	echo "FAIL rename-check: the original declaration was not renamed"
	exit 1
fi
echo "ok   rename-check original declaration: renamed"
printf 'package api\n\n%s\n}\n' "$renamed" >"$work/stale.go"
refuse_rename "already renamed"
printf 'package api\n\n// %s\n%s\n}\n' "$renamed" "$spaced" >"$work/stale.go"
refuse_rename "reformatted, new name in a comment"
printf 'package api\n\n// %s\n%s\n}\n' "$decl" "$spaced" >"$work/stale.go"
refuse_rename "reformatted, old name in a comment"
printf 'package api\n\n%s\n}\n%s\n}\n' "$decl" "$decl" >"$work/stale.go"
refuse_rename "declaration on two lines"

if mutation_apply_only; then
	fresh
	if rename_handler "$tree/internal/api/mesh.go"; then
		echo "ok   handler-renamed: applies"
		exit 0
	fi
	echo "FAIL handler-renamed: mutation did not apply, the source changed, update this script"
	exit 1
fi

fresh
expect_green "clean tree"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

/* a quote " inside a block comment */ const probeMarker = "safe"

func probeQuoteInComment(v MeshVault) {
	_, _, _ = v.ResolveSecret(nil, "", "", "")
}
GO
expect_red "quote inside a block comment before a forbidden call"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

const probeRaw = `
// not a comment, and a quote " here
`

func probeAfterRaw(v MeshVault) {
	_, _, _ = v.ResolveSecret(nil, "", "", "")
}
GO
expect_red "multi-line raw string before a forbidden call"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

func probeSecondReader(v MeshVault) {
	_, _, _ = v.ResolveSecret(nil, "", "", "")
}
GO
expect_red "second function in internal/api"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

func probeSplit(m *meshRoutes) {
	_, _, _ = m.deps.Vault.
		// a comment between the dot and the name
		ResolveSecret(nil, "o", "w", "r")
}
GO
expect_red "selector split across lines"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

func probeInlineBlock(v MeshVault) {
	_, _, _ = v. /* probe */ ResolveSecret(nil, "", "", "")
}
GO
expect_red "inline block comment inside the selector"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

func probeMultiBlock(v MeshVault) {
	_, _, _ = v. /* a
	b */ ResolveSecret(nil, "", "", "")
}
GO
expect_red "block comment spanning lines inside the selector"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

func probeSpaced(v MeshVault) {
	_, _, _ = v.   ResolveSecret(nil, "", "", "")
}
GO
expect_red "spaces after the dot"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

func probeString(m *meshRoutes) {
	u := "http://x"; _, _, _ = m.deps.Vault.ResolveSecret(nil, u, "w", "r")
}
GO
expect_red "call after a // inside a string literal"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

func (m *meshRoutes) handleResolveSecret() {
	_, _, _ = m.deps.Vault.ResolveSecret(nil, "o", "w", "r")
}
GO
expect_red "duplicate handler declaration in another file"

fresh
cat >"$tree/cmd/keep-server/app/zz_probe.go" <<'GO'
package app

func (v meshVault) ResolveSecret() {
	_, _, _ = v.x.ResolveSecret(nil, "o", "w", "r")
}
GO
expect_red "second adapter declaration"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

var probeMethodValue = (MeshVault).ResolveSecret
GO
expect_red "method value at package level"

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

func probeAfterHandler() {}

var probeClosure = func(v MeshVault) {
	_, _, _ = v.ResolveSecret(nil, "", "", "")
}
GO
expect_red "package-level closure"

fresh
cat >>"$tree/cmd/keep-server/app/main.go" <<'GO'

func probeOtherPackage(v meshVault) {
	_, _, _ = v.MeshVault.ResolveSecret(nil, "", "", "")
}
GO
expect_red "caller in cmd/keep-server/app outside the adapter"

fresh
if rename_handler "$tree/internal/api/mesh.go"; then
	expect_red "handler renamed away from the guarded name"
else
	echo "FAIL handler-renamed: mutation did not apply, the source changed, update this script"
	fail=1
fi

fresh
cat >"$tree/internal/api/zz_probe.go" <<'GO'
package api

// v.ResolveSecret(ctx, org, ws, ref) is described here, not called.
/* v. ResolveSecret(ctx, org, ws, ref)
   is described here too */
func probeComment() {}
GO
cat >"$tree/internal/api/zz_probe_test.go" <<'GO'
package api

func probeInTest(v MeshVault) { _, _, _ = v.ResolveSecret(nil, "", "", "") }
GO
expect_green "a comment and a test file"

exit $fail
