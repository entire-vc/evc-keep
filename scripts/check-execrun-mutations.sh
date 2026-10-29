#!/bin/sh
# Proves the runner-side exec_with_secret guards can fail: in a scratch copy of
# the tree, switch off one check of internal/runner/execrun at a time and
# require `go test ./internal/runner/execrun/` to go red. A check whose removal leaves the
# tests green is not tested. Exits 0 only if every mutation is caught.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"

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
	if (cd "$work/tree" && go test -timeout 120s -count=1 ./internal/runner/execrun/ >"$work/out" 2>&1); then
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

mutate internal/runner/execrun/plan.go no-digest 'if execpolicy.Digest(tpl) != j.Exec.Digest {' 'if false {'
mutate internal/runner/execrun/plan.go no-param-count 'if len(j.Exec.Params) != len(tpl.Params) {' 'if false {'
mutate internal/runner/execrun/plan.go no-resolved-revalidate 'if _, err := execpolicy.Validate(again); err != nil {' 'if false {'
mutate internal/runner/execrun/plan.go no-bindir 'if !inside {' 'if false && !inside {'
mutate internal/runner/execrun/plan.go bindir-prefix-loose 'strings.TrimRight(rd, "/")+"/")' 'strings.TrimRight(rd, "/"))'
mutate internal/runner/execrun/plan.go no-regular '!fi.Mode().IsRegular()' 'false'
mutate internal/runner/execrun/plan.go no-exec-bit 'if fi.Mode().Perm()&0o111 == 0 {' 'if false {'
mutate internal/runner/execrun/plan.go no-suid-check 'if fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {' 'if false {'
mutate internal/runner/execrun/plan.go no-symlink-eval 'real, err := filepath.EvalSymlinks(bin)' 'real, err := bin, error(nil)'
mutate internal/runner/execrun/run.go allowlist-unenforced 'case pl.Mode == execpolicy.NetAllowlist:' 'case false:'
mutate internal/runner/execrun/run.go ignore-unenforced-flag 'case !p.ExecNetUnenforced:' 'case false:'
mutate internal/runner/execrun/run.go no-loopback-filter 'ip.IsLoopback() ||' 'false ||'
mutate internal/runner/execrun/run.go no-linklocal-filter 'ip.IsLinkLocalUnicast() ||' 'false ||'
mutate internal/runner/execrun/run.go no-unmap 'ip = ip.Unmap()' '_ = ip'
mutate internal/runner/execrun/run.go inherit-env 'cmd.Env = []string{"PATH=" + path, "HOME=" + home, "TMPDIR=" + home}' 'cmd.Env = exec.Command("x").Environ()'
mutate internal/runner/execrun/run.go no-output-cap 'if room := w.limit - w.buf.Len(); room > 0 {' 'if room := len(b); room > 0 {'
mutate internal/runner/execrun/run.go no-scrub 'res.Stdout, truncOut = sc.Scrub(stdout.buf.Bytes(), stdout.total > keep, max)' 'res.Stdout, truncOut = stdout.buf.String(), false'
mutate internal/runner/execrun/run.go no-timeout 'ctx, cancel := context.WithTimeout(ctx, timeout)' 'ctx, cancel := context.WithTimeout(ctx, 1000*time.Hour)'
mutate internal/runner/execrun/run.go log-output '"status", "exit_"+strconv.Itoa(out.ExitCode))' '"status", "exit_"+strconv.Itoa(out.ExitCode)+out.Stdout)'
mutate internal/runner/execrun/scrub.go no-trim 'keep := len(res) - (s.maxNeedle() - 1 + 8)' 'keep := len(res)'
mutate internal/runner/execrun/scrub.go no-wrapped-base64 'if s.hiddenByBreaks(res) {' 'if false {'
mutate internal/runner/execrun/run.go no-kill-group '	killGroup(cmd)' '	_ = cmd'
mutate internal/runner/execrun/scrub.go no-base64-alignment 'for offset := 0; offset <= 2; offset++ {' 'for offset := 0; offset <= 0; offset++ {'
mutate internal/runner/execrun/scrub.go no-reverse 'add(rev)' ''
mutate internal/runner/execrun/scrub.go no-hex-upper 'add([]byte(string(bytes.ToUpper([]byte(lower)))))' ''
mutate internal/runner/execrun/scrub.go no-urlenc 'add([]byte(url.QueryEscape(string(raw))))' ''
mutate internal/runner/execrun/scrub.go shortest-first 'return len(s.needles[i]) > len(s.needles[j])' 'return len(s.needles[i]) < len(s.needles[j])'
mutate internal/runner/execrun/home.go home-shared-between-runs '	return dir, nil' '	return root, nil'
mutate internal/runner/execrun/home.go home-not-private 'os.Chmod(dir, 0o700)' 'os.Chmod(dir, 0o755)'
mutate internal/runner/execrun/home.go home-not-given-to-child 'if err := chown(dir, int(uid), int(gid)); err != nil {' 'if err := error(nil); err != nil {'
mutate internal/runner/execrun/home.go home-chown-error-ignored 'if err := chown(dir, int(uid), int(gid)); err != nil {' 'if _ = chown(dir, int(uid), int(gid)); false {'
mutate internal/runner/execrun/run.go home-root-leftover-ignored 'if !homeRootEmpty(d.HomeRoot) {' 'if false {'
mutate internal/runner/execrun/home.go home-root-always-empty 'names, err := f.Readdirnames(1)' 'names, err := []string(nil), io.EOF'
mutate internal/runner/execrun/run.go no-home-remove-report 'homeErr := errors.Join(sweepAccount(d.ChildUID), removeChildDir(home))' 'var homeErr error'
mutate internal/runner/execrun/run.go no-home-remove-on-early-exit '		cerr := removeChildDir(home)' '		var cerr error'
mutate internal/runner/execrun/run.go home-clean-error-ignored 'if homeErr != nil {' 'if false {'
mutate internal/runner/execrun/run.go early-exit-clean-error-ignored '		if rclass != runnerproto.ErrClassInternal {' '		if false {'
mutate internal/runner/execrun/run.go early-exit-clean-error-dropped '		cerr := removeChildDir(home)' '		cerr := error(removeChildDir(home)); cerr = nil'
mutate internal/runner/execrun/run.go no-more-flag-stdout 'stdout.total > keep' 'false'
mutate internal/runner/execrun/run.go no-more-flag-stderr 'stderr.total > keep' 'false'
mutate internal/runner/execrun/scrub.go no-raw-form 'add(raw)' ''
mutate internal/runner/execrun/scrub.go no-b64-std 'base64.RawStdEncoding, base64.RawURLEncoding}' 'base64.RawURLEncoding}'
mutate internal/runner/execrun/scrub.go no-b64-url 'base64.RawStdEncoding, base64.RawURLEncoding}' 'base64.RawStdEncoding}'
mutate internal/runner/execrun/scrub.go b64-tail-group 'end := (offset + len(raw)) / 3' 'end := (offset+len(raw))/3 - 1'
mutate internal/runner/execrun/plan.go no-hardlink-check 'if fi.Mode().IsRegular() && linkCount(fi) != 1 {' 'if false {'
mutate internal/runner/execrun/plan.go no-writable-check 'di.Mode().Perm()&0o022 != 0 &&' 'di == nil &&'
mutate internal/runner/execrun/plan.go no-agent-owner 'ownerUID(di); !ok || containsInt64(p.AgentUIDs, uid)' 'ownerUID(di); !ok || containsInt64(nil, uid)'
mutate internal/runner/execrun/plan.go no-ancestor-walk 'if parent := filepath.Dir(d); parent == d {' 'if true {'
mutate internal/runner/execrun/scrub.go no-edge-groups 'res = replaceWithEdges(res, n)' 'res = bytes.ReplaceAll(res, n, []byte(redacted))'
mutate internal/runner/execrun/scrub.go no-trailing-edge 'for k := 0; k < 4 && end < len(b)' 'for k := 0; k < 0 && end < len(b)'
mutate internal/runner/execrun/scrub.go no-leading-edge 'for k := 0; k < 4 && start > 0' 'for k := 0; k < 0 && start > 0'
mutate internal/runner/execrun/run.go no-child-account 'if d.ChildUID == 0 || d.ChildGID == 0 {' 'if false {'
mutate internal/runner/execrun/run.go no-account-drop-nonroot-refusal 'dropAccount(cmd, d.ChildUID, d.ChildGID); err != nil {' 'error(nil); err != nil {'
mutate internal/runner/execrun/run_unix.go no-core-limit '_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})' '_ = syscall.Getrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})'
mutate internal/runner/execrun/run_unix.go no-root-refusal 'if geteuid() != 0 {' 'if geteuid() != 0 && false {'
mutate internal/runner/execrun/run.go cwd-not-set 'cmd.Dir = home' '_ = home'
mutate internal/runner/execrun/run.go stdin-open 'cmd.Stdin = nil' 'cmd.Stdin = strings.NewReader("x")'
mutate internal/runner/execrun/run.go no-runner-account-check 'int64(d.ChildUID) == int64(geteuid()) ||' 'int64(geteuid()) < 0 ||'
mutate internal/runner/execrun/run.go no-agent-account-check '|| containsInt64(p.AgentUIDs, int64(d.ChildUID)) {' '|| false {'
mutate internal/runner/execrun/run.go no-core-handler-check 'if piped() {' 'if false && piped() {'
mutate internal/runner/execrun/run.go no-wrapper-check 'if len(wrap) == 0 {' 'if false {'
mutate internal/runner/execrun/run.go resolve-outside-timeout 'resolveAll(ctx, pl.Dests, d)' 'resolveAll(context.Background(), pl.Dests, d)'

mutation_apply_only && exit "$fail"

# And the unmutated tree must be green, or every "red" above means nothing.
if (cd "$root" && go test -timeout 120s -count=1 ./internal/runner/execrun/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
