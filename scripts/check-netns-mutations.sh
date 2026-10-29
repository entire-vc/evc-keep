#!/bin/sh
# Proves the Linux network isolation can fail: in a scratch copy of the tree,
# switch off one part of internal/runner/execrun/netns_linux.go at a time and
# require the isolation tests to go red. Needs a privileged Linux host with
# ip, nft and setpriv (the keep-netns CI job); anywhere else it FAILS, because
# a mutation run that could not run proves nothing. A check whose removal leaves the
# tests green is not tested. Exits 0 only if every mutation is caught.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"

if ! mutation_apply_only && { [ "$(uname -s)" != Linux ] || [ "${KEEP_NETNS_TESTS:-}" != 1 ] || [ "$(id -u)" != 0 ]; }; then
	echo "FAIL needs a privileged Linux host with KEEP_NETNS_TESTS=1 (see the keep-netns job)" >&2
	exit 1
fi

# Private per-run build cache: on a shared host running several
# clones' go test/build concurrently, a shared $GOCACHE can serve one
# process a build-cache entry another process is evicting mid-write,
# producing a spurious build failure unrelated to any code change
# (seen as "could not import internal/chacha8rand ... no such file").
# Scoping the cache to each run removes the sharing, not just the
# symptom. Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace
src=""

fail=0
# mutate FILE NAME FROM TO: replace the first literal occurrence of FROM with TO.
mutate() {
	src=$1 name=$2 from=$3 to=$4
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
	run_mutant "$name"
}

# mutate_sed FILE NAME SED-EXPR: apply a sed edit to every line of the source.
mutate_sed() {
	src=$1 name=$2 expr=$3
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	sed -e "$expr" "$root/$src" >"$work/tree/$src"
	if cmp -s "$root/$src" "$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	run_mutant "$name"
}

# run_mutant NAME: the scratch tree must go red in a test, not in the build.
run_mutant() {
	name=$1
	if (cd "$work/tree" && go test -timeout 300s -count=1 -run "Netns|RealIsolator" ./internal/runner/execrun/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the check switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		# Red because the mutant does not build is not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

mutate internal/runner/execrun/netns_linux.go no-inside-firewall 'n.cmd(ctx, []byte(inside), n.ip, "netns", "exec", name, n.nft, "-f", "-")' 'n.cmd(ctx, []byte(inside), n.ip, "netns", "exec", name, "true")'
mutate internal/runner/execrun/netns_linux.go inside-output-accepts 'type filter hook output priority 0; policy drop;' 'type filter hook output priority 0; policy accept;'
mutate internal/runner/execrun/netns_linux.go no-pinned-port 'fmt.Sprintf("%s . %d", p.Addr.Addr(), p.Addr.Port())' 'p.Addr.Addr().String() + " . 1-65535"'
mutate internal/runner/execrun/netns_linux.go no-masquerade 'ip saddr %[4]s oifname != "%[2]s" masquerade' 'ip saddr %[4]s oifname != "%[2]s" accept'
mutate internal/runner/execrun/netns_linux.go no-ip-forward 'if err := os.WriteFile(ipForwardPath, []byte("1\\n"), 0o644);' 'if err := error(nil);'
mutate internal/runner/execrun/netns_linux.go ip-forward-not-restored '_ = os.WriteFile(ipForwardPath, fwd.prior, 0o644)' '_ = fwd.prior'
mutate internal/runner/execrun/netns_linux.go host-input-open 'iifname "%[2]s" counter drop' 'iifname "%[2]s" counter accept'
mutate internal/runner/execrun/netns_linux.go no-hosts-pin 'hosts += p.Addr.Addr().String() + " " + p.Host + "\\n"' '_ = p'
mutate internal/runner/execrun/netns_linux.go keeps-privileges '"--clear-groups", "--no-new-privs", "--bounding-set", "-all", "--inh-caps", "-all",' '"--clear-groups",'
mutate internal/runner/execrun/netns_linux.go no-core-limit '"--", n.lim, "--core=0:0", "--"}' '"--"}'
mutate internal/runner/execrun/netns_linux.go no-no-new-privs '"--clear-groups", "--no-new-privs",' '"--clear-groups",'
mutate internal/runner/execrun/netns_linux.go child-stays-root '"--reuid", strconv.FormatUint(uint64(n.ChildUID), 10),' '"--reuid", "0",'
mutate internal/runner/execrun/netns_linux.go no-ipv6-refusal 'if !p.Addr.Addr().Is4() {' 'if false && !p.Addr.Addr().Is4() {'
mutate internal/runner/execrun/netns_linux.go no-ns-delete '_ = n.cmd(c, nil, n.ip, "netns", "del", name)' '_ = c'
mutate internal/runner/execrun/netns_linux.go no-etc-cleanup 'undo = append(undo, func() { _ = os.RemoveAll(etc) })' '_ = etc'
mutate internal/runner/execrun/netns_linux.go no-host-table-delete '_ = n.cmd(c, nil, n.nft, "delete", "table", "ip", table)' '_ = c'
mutate internal/runner/execrun/netns_linux.go no-sweep 'if strings.HasPrefix(e.Name(), "keep-") {' 'if false {'
mutate internal/runner/execrun/netns_linux.go root-child-allowed 'n.ChildUID == 0 || n.ChildGID == 0 ||' 'false ||'
mutate internal/runner/execrun/run.go no-account-sweep 'homeErr := errors.Join(sweepAccount(d.ChildUID), removeChildDir(home))' 'homeErr := errors.Join(removeChildDir(home))'
mutate internal/runner/execrun/sweep_linux.go no-account-kill '_ = syscall.Kill(pid, syscall.SIGKILL)' '_ = pid'
mutate internal/runner/execrun/sweep_linux.go no-tmp-clean 'err = errors.Join(err, removeOwned(dir, uid))' '_ = dir'
mutate internal/runner/execrun/run_unix.go no-credential-drop 'cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}' '_, _ = uid, gid'
mutate internal/runner/execrun/run_unix.go keeps-supplementary-groups 'Groups: []uint32{}}' 'NoSetGroups: true}'
mutate internal/runner/execrun/run.go no-account-precheck 'if err := accountClear(d.ChildUID); err != nil {' 'if err := error(nil); err != nil {'
mutate internal/runner/execrun/sweep_linux.go no-nested-sweep 'if fi.IsDir() {' 'if false {'

mutation_apply_only && exit "$fail"

# And the unmutated tree must be green, or every "red" above means nothing.
if (cd "$root" && go test -timeout 300s -count=1 -run "Netns|RealIsolator" ./internal/runner/execrun/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
