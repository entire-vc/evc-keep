#!/bin/sh
# Proves the offline-transfer store-mode profile (profile 2: a native Mesh
# store-mode organization with one installation and no tenancy workspace) is
# guarded by tests that can fail. In a scratch copy of the tree one guard at a
# time is replaced by a no-op, or its input is removed, and the profile,
# manifest, closure, inventory, import and end-to-end tests must go red.
# Needs a real PostgreSQL (KEEP_DATABASE_URL), like check-audit-mutations.sh.
#
# Guards with no entry here are defence in depth that another guard repeats
# (for example a project without a workspace is also a dangling reference), so
# no mutation of them can be killed.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace

pkgs="./internal/scopedtransfer/ ./internal/transferverify/ ./internal/store/ ./cmd/keep-server/app/"
run='StoreMode|Manifest|Profile|ClosureStoreMode|ImportTransferStoreMode|ImportTransferRefusals|TestOfflineTransferEndToEnd'

fail=0
# mutate NAME FILE FROM TO: replace the first literal occurrence of FROM with TO.
mutate() {
	name=$1 src=$2 from=$3 to=$4
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$src" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if [ -z "${KEEP_DATABASE_URL:-}" ]; then
		echo "FAIL $name: KEEP_DATABASE_URL is not set — the database tests would SKIP, not fail"
		fail=1
		return
	fi
	if (cd "$work/tree" && go test -timeout 300s -count=1 -run "$run" $pkgs >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the guard switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

P=internal/scopedtransfer/profile.go
M=internal/scopedtransfer/manifest.go
Z=internal/transferverify/closure.go
I=cmd/keep-server/app/offline_transfer_import.go
E=cmd/keep-server/app/offline_transfer_export_cmd.go
S=internal/store/transfer_inventory.go

# the canonical workspace of profile 2 is the single installation's
mutate profile2-workspace-not-installation $P 'if in.MeshWorkspaceID != "" && in.MeshWorkspaceID == in.WorkspaceID {' 'if in.WorkspaceID != "" {'
mutate profile2-projects-allowed           $P '(profile == ProfileVersionStoreMode && counts["projects"] != 0) ||' ''
mutate profile-workspace-rows-unbound      $P 'counts["workspaces"] != wantWorkspaces' 'counts["workspaces"] > 1 || wantWorkspaces < 0'
mutate profile-installation-count-unbound  $P 'counts["mesh_installations"] != 1' 'counts["mesh_installations"] > 1'
# the manifest's profile version selects the shape and the counts prove it
mutate manifest-profile2-as-profile1       $M 'in.MeshWorkspaceID = m.WorkspaceID' 'in.WorkspaceIDs = []string{m.WorkspaceID}'
# closure: no key domain or envelope scope may name a workspace that is not in the snapshot
mutate closure-kek-workspace-scope         $Z 'if noWorkspace && (v.DomainWorkspace != "" || v.DomainProject != "") {' 'if false {'
mutate closure-envelope-workspace-scope    $Z 'if noWorkspace && (v.StoreWorkspace != "" || v.StoreProject != "") {' 'if false {'
mutate closure-single-installation         $Z 'len(r.MeshInstallations) != 1' 'len(r.MeshInstallations) > 1'
mutate closure-many-workspaces             $Z 'len(r.Workspaces) > 1 ||' 'false ||'
# import: the copied workspace shape is the manifest's profile, pinned to the manifest's workspace
mutate import-profile2-tenancy-rows        $I 'return len(rows.Workspaces) == 0 && len(rows.Projects) == 0 &&' 'return true &&'
mutate import-profile2-workspace-pin       $I 'rows.MeshInstallations[0].WorkspaceID.String() == m.WorkspaceID' 'true'
mutate import-profile2-store-mode            $I 'rows.MeshInstallations[0].Mode == "store" &&' ''
mutate import-profile1-workspace-pin       $I 'return len(rows.Workspaces) == 1 && rows.Workspaces[0].ID.String() == m.WorkspaceID' 'return len(rows.Workspaces) == 1'
mutate import-workspace-check-noop         $I 'if !workspaceMatchesProfile(m, rows) {' 'if false {'
# export writes the profile the source really is; inventory reads the installation's workspace
mutate export-always-profile1              $E 'ProfileVersion: plan.ProfileVersion(),' 'ProfileVersion: scopedtransfer.ProfileVersion,'
mutate inventory-no-installation-workspace $S 'in.WorkspaceID = in.MeshWorkspaceID' 'in.WorkspaceID = ""'
mutate inventory-ambiguous-installation    $S 'if len(mesh) == 1 {' 'if len(mesh) >= 1 {'

if mutation_apply_only; then
	:
elif [ -z "${KEEP_DATABASE_URL:-}" ]; then
	echo "FAIL baseline: KEEP_DATABASE_URL is not set"
	fail=1
elif (cd "$root" && go test -timeout 300s -count=1 -run "$run" $pkgs >"$work/base.out" 2>&1) && ! grep -q -- '--- SKIP' "$work/base.out"; then
	echo "ok   baseline: tests green on the real code, none skipped"
else
	echo "FAIL baseline: tests are red or skipped on the real code"
	fail=1
fi

exit $fail
