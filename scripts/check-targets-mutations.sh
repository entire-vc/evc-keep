#!/bin/sh
# Proves the internal/targets guards can fail: in a scratch copy of the tree,
# switch off one check at a time and require the named test to go red. A
# check whose removal leaves that test green is not tested. Exits 0 only if
# every mutation is caught. Unix-only, same as the package.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
mutation_shard_init

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
dir=internal/targets

fail=0

# Shards jointly form one suite. Run the full baseline once, on shard 1,
# so splitting the inventory does not multiply expensive unmutated attacks.
# It runs BEFORE the first mutant: a red baseline makes every "red" below
# meaningless, so it stops here, within the baseline's own run time, with the
# failing test names, instead of after the whole inventory.
if [ "$mutation_index" -eq 1 ] && ! mutation_apply_only; then
	MUTATION_BASELINE_DIAG_TESTS='TestConsumeEnvFileDeadlineFiresOnAStuckShell'
	export MUTATION_BASELINE_DIAG_TESTS
	if ! mutation_baseline -timeout 600s ${RACE:+-race} ./$dir/...; then
		echo "FAIL baseline is red: no mutant was run"
		exit 1
	fi
fi

# mutate NAME FILE TEST FROM TO [N]: replace the Nth (default first) literal
# occurrence of FROM with TO in FILE; TEST must be among the failing tests.
mutate() {
	mutation_selected || return 0
	name=$1 file=$dir/$2 test=$3 from=$4 to=$5 nth=${6:-1}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" -v nth="$nth" '
		!done && (i = index($0, from)) && ++seen == nth { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$file" >"$work/tree/$file"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 600s -count=1 ${RACE:+-race} -run "^${test}\$" ./$dir/... >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the check switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- "--- FAIL: $test" "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?):"
		head -20 "$work/out"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

# apply1 FILE FROM TO: like mutate's single replacement, but writes straight
# into $work/tree (already checked out) instead of building a fresh copy —
# used by mutate2 to stack two independent replacements before testing.
apply1() {
	file=$dir/$1 from=$2 to=$3
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$work/tree/$file" >"$work/tree/$file.new"; then
		return 1
	fi
	mv "$work/tree/$file.new" "$work/tree/$file"
}

# mutate2 NAME TEST FILE1 FROM1 TO1 FILE2 FROM2 TO2: switches off two
# independent checks at once and requires TEST to go red — for a property
# two redundant layers both catch, where disabling either one alone leaves
# the other still catching it (itself a good sign, not a gap: proving that
# needs both switched off together).
mutate2() {
	mutation_selected || return 0
	name=$1 test=$2 file1=$3 from1=$4 to1=$5 file2=$6 from2=$7 to2=$8
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! apply1 "$file1" "$from1" "$to1" || ! apply1 "$file2" "$from2" "$to2"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 600s -count=1 ${RACE:+-race} -run "^${test}\$" ./$dir/... >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with both checks switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- "--- FAIL: $test" "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?):"
		head -20 "$work/out"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

# mutateN NAME TEST FILE FROM TO [FILE FROM TO ...]: switches off several
# independent things at once and requires TEST to go red — for a property
# that redundant layers all catch (only all together prove any of them), or
# a mutant that needs a helper declared alongside the change.
mutateN() {
	mutation_selected || return 0
	name=$1 test=$2
	shift 2
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	while [ $# -gt 0 ]; do
		if ! apply1 "$1" "$2" "$3"; then
			echo "FAIL $name: mutation did not apply — the source changed, update this script"
			fail=1
			return
		fi
		shift 3
	done
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 600s -count=1 ${RACE:+-race} -run "^${test}\$" ./$dir/... >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the checks switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- "--- FAIL: $test" "$work/out"; then
		echo "FAIL $name: $test did not fail (build error or wrong test?):"
		head -20 "$work/out"
		fail=1
	else
		echo "ok   $name: $test went red"
	fi
}

# assert_still_green NAME FILE TEST FROM TO [N]: the inverse of mutate — for
# a check that claims to be defense in depth for an earlier one, switching
# off the earlier check ALONE must leave TEST green, because the later check
# in the same call path still catches it. FAILs loudly if TEST goes red
# (the "depth" was load-bearing, i.e. the two are one check, not two) or if
# the mutation cannot be applied. This is the positive-control counterpart
# to a mutateN that switches both off together and expects red.
assert_still_green() {
	mutation_selected || return 0
	name=$1 file=$dir/$2 test=$3 from=$4 to=$5 nth=${6:-1}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" -v nth="$nth" '
		!done && (i = index($0, from)) && ++seen == nth { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$file" >"$work/tree/$file"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	# -v: unlike "--- FAIL: $test", "--- PASS: $test" is only printed with -v,
	# and this function needs it to tell "the test ran and passed" apart from
	# "nothing matched -run" (both exit 0).
	if (cd "$work/tree" && go test -timeout 600s -count=1 -v ${RACE:+-race} -run "^${test}\$" ./$dir/... >"$work/out" 2>&1); then
		if grep -q -- "--- PASS: $test" "$work/out"; then
			echo "ok   $name: $test stayed green with only that layer off (the deeper layer caught it)"
		else
			echo "FAIL $name: exit 0 but $test never ran (typo'd test name or nothing matched -run):"
			head -20 "$work/out"
			fail=1
		fi
	elif grep -q -- "--- FAIL: $test" "$work/out"; then
		echo "FAIL $name: $test went red with only one layer off — the layers are not independent:"
		head -20 "$work/out"
		fail=1
	else
		echo "FAIL $name: $test did not fail cleanly (build error or wrong test?):"
		head -20 "$work/out"
		fail=1
	fi
}

# The Linux ACL mutations only mean anything where the Linux ACL code and its
# tests are compiled. On another OS they are reported as not run — loudly,
# never as passed — and CI (alpine) runs them.
goos=$(go env GOOS)
linux_only() {
	# Apply-only runs no tests, so every anchor is checked on every OS.
	mutation_apply_only && return 0
	if [ "$goos" != linux ]; then
		echo "skip $1: linux-only mutation, GOOS=$goos (runs in CI)"
		return 1
	fi
}

darwin_only() {
	mutation_apply_only && return 0
	if [ "$goos" != darwin ]; then
		echo "skip $1: darwin-only mutation, GOOS=$goos"
		return 1
	fi
}

# shell_lists SHELL NAME: SHELL is installed and reports NAME as one of its
# own variables (the same listing the tests use).
shell_lists() {
	mutation_apply_only && return 0
	case $1 in
	bash) list='compgen -v' ;;
	ksh) list='typeset +' ;;
	zsh) list='print -l ${(k)parameters}' ;;
	esac
	command -v "$1" >/dev/null 2>&1 && env -i PATH="$PATH" HOME=/nonexistent "$1" -c "$list" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"
}

# Symlink-safe walk: any component that is not a plain directory (a
# symlink, most often) must be refused, not opened.
mutate no-symlink-check     securewrite_unix.go TestSymlinkInMiddleOfPathRefused \
	'unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)' 'unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)'
# Same line, proved from outside by a hostile process that keeps flipping the
# real directory to a symlink and back under a running Write loop, instead of
# a single fixed symlink component (MR !31 review: the walk's own O_NOFOLLOW
# had no attack-test ratchet, only the fixed-symlink unit test above).
mutate no-symlink-check-live-flip securewrite_unix.go TestTargetsAttack_LiveSymlinkFlipNeverEscapes \
	'unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)' 'unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)'
# The existing target is read through the same walk's descriptor: a symlink at
# its name must be refused, not followed into another file's content.
mutate no-symlink-target-check securewrite_unix.go TestSymlinkedTargetContentNotMerged \
	'unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)' 'unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)'
# Every later operation goes through the held directory descriptor. The mutant
# renames by the directory's path instead (mutantDir is what an
# implementation that kept the path around would use): after the directory is
# swapped for a symlink, the rename no longer finds the temporary file.
mutateN rename-by-path TestParentDirSwappedForSymlinkAfterWalkWritesToWalkedDir \
	securewrite_unix.go 'unix.Renameat(parentFD, tmp, parentFD, base)' 'unix.Rename(mutantDir+"/"+tmp, mutantDir+"/"+base)' \
	securewrite_unix.go 'segs := strings.Split(absPath[1:], "/")' 'mutantDir = path.Dir(absPath); segs := strings.Split(absPath[1:], "/")' \
	securewrite_unix.go 'var fsyncFD = unix.Fsync' 'var fsyncFD = unix.Fsync; var mutantDir string'
# ".." is refused three times over: pkg/runnerproto.ValidatePath (proven by
# that package's own mutation script), and, inside walkToParent itself,
# once syntactically up front and once again per path segment during the
# walk. TestWalkToParentRejectsDotDot calls walkToParent directly, bypassing
# ValidatePath, so only walkToParent's own two checks are in play here —
# and since either alone still leaves the other catching it, both must go
# together to prove either one is doing anything.
mutate2 no-dotdot-check TestWalkToParentRejectsDotDot \
	securewrite_unix.go 'path.Clean(absPath) != absPath' 'false' \
	securewrite_unix.go 'seg == "" || seg == "." || seg == ".."' 'seg == "does-not-match-anything"'

# Hardlink/race defense: O_CREAT|O_EXCL already refuses a pre-existing name;
# the nlink check is what catches a link created in the instant after. It runs
# once, as late as possible — after Fchown/Fchmod, right before the first byte
# — so both windows (right after creation, and after chmod, the one a sticky
# directory leaves open) are covered by the same line; the two tests inject the
# link at the two points.
mutate no-nlink-check        securewrite_unix.go TestHardlinkRaceAfterTmpCreateRefused \
	'case st.Nlink != 1:' 'case false:'
mutate no-nlink-check-late   securewrite_unix.go TestHardlinkRaceAfterChmodRefused \
	'case st.Nlink != 1:' 'case false:'
# A concurrent write's own cleanupStaleTmp can unlink this exact temporary
# file out from under us; checkTmpFile names that cause instead of falling
# through to the unrelated "more than one link" wording below it.
mutate no-concurrent-unlink-check securewrite_unix.go TestTmpFileUnlinkedConcurrentlyRefusedWithCorrectMessage \
	'case st.Nlink == 0:' 'case false:'
# An existing target with several links (an agent's hardlink to another
# service's secret file, macOS has no protected_hardlinks) or a foreign owner
# must not be read and re-emitted into this target.
mutate no-existing-nlink-check securewrite_unix.go TestExistingTargetHardlinkedToForeignSecretRefused \
	'if st.Nlink != 1 {' 'if false {'
mutate no-existing-owner-check securewrite_unix.go TestExistingTargetForeignOwnerRefused \
	'if !slices.Contains(owners, int64(st.Uid)) {' 'if false && !slices.Contains(owners, int64(st.Uid)) {'
# The owner and mode the consumer needs are applied, and read back from the
# inode before the value is written. Either layer alone still catches a
# missing chown (Fchown's return value; the readback), so the combined mutant
# is the proof of the pair; each alone must also go red.
mutate no-fchown             securewrite_unix.go TestWriteAppliesOwnerGroupAndMode \
	'if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {' 'if err := error(nil); err != nil {'
mutate no-fchmod             securewrite_unix.go TestFileTargetModeAndOwnerApplied \
	'if err := unix.Fchmod(fd, mode); err != nil {' 'if err := error(nil); err != nil {'
mutateN no-owner-apply-or-verify TestWriteAppliesOwnerGroupAndMode \
	securewrite_unix.go 'if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {' 'if err := error(nil); err != nil {' \
	securewrite_unix.go 'case int64(st.Uid) != uid:' 'case false:'

# Write validates the target's own fields before touching anything.
mutate no-target-validate    write.go TestWriteRejectsXMLInjectionInLaunchdField \
	'if err := t.Validate(); err != nil {' 'if err := t.Validate(); false && err != nil {'
mutate no-target-validate-env write.go TestWriteRejectsNewlineInEnvFileField \
	'if err := t.Validate(); err != nil {' 'if err := t.Validate(); false && err != nil {'

# Agent-reach defense: a directory an agent can write or read/traverse, or
# a target mode/owner an agent could read, must be refused.
mutate no-agent-write-group agents.go TestAgentWritableDirRefused \
	'mode&0o020 != 0 && a.groupIsAgents(int64(st.Gid))' 'mode&0o020 != 0 && false'
mutate no-write-anyone      agents.go TestWorldWritableDirRefused \
	'mode&0o002 != 0 {' 'mode&0o002 != 0 && false {'
mutate no-agent-read-group  agents.go TestAgentReadableParentDirRefused \
	'(mode>>3)&dirReachBits != 0 && a.groupIsAgents(int64(st.Gid))' '(mode>>3)&dirReachBits != 0 && false'
mutate no-target-world-mode securewrite_unix.go TestWorldReadableModeRefused \
	'case mode&0o007 != 0:' 'case false:'
mutate no-target-agent-uid  securewrite_unix.go TestValidateTargetPermUIDDirect \
	'if ag.hasUID(uid) {' 'if false {'
mutate no-target-agent-gid  securewrite_unix.go TestAgentGroupReadableTargetModeRefused \
	'if mode&0o070 != 0 && ag.groupIsAgents(gid) {' 'if false {'

# The existing target is read only if it is a regular file of bounded size.
mutate no-regular-file-check   securewrite_unix.go TestFIFOAtTargetDoesNotBlockWrite \
	'if st.Mode&unix.S_IFMT != unix.S_IFREG {' 'if false && st.Mode&unix.S_IFMT != unix.S_IFREG {'
# The Fstat check below and readAllFD's own bound inside its read loop
# enforce the same limit twice on purpose (see maxTargetSize's doc comment):
# the Fstat is a single point in time, readAllFD's is independent of it, for
# a file that grows during the read itself. Disabling either one alone now
# leaves a too-large *existing* file (which readAllFD reads in one call, not
# growing under it) still caught by the other — that redundancy is the point,
# not a gap — so proving either guard is load-bearing needs both off at once.
mutate2 no-size-limit-anywhere TestExistingTargetTooLargeRefused \
	securewrite_unix.go 'if st.Size > maxTargetSize {' 'if false && st.Size > maxTargetSize {' \
	securewrite_unix.go 'if int64(len(out)+n) > maxTargetSize {' 'if false {'
# TestReadAllFDBoundedIndependentlyOfSizeHint calls readAllFD directly with a
# sizeHint that undersells the real size, bypassing readExisting's Fstat
# entirely — so this one mutation does still isolate the read-loop bound on
# its own, unlike the Fstat check above.
mutate no-read-loop-size-bound securewrite_unix.go TestReadAllFDBoundedIndependentlyOfSizeHint \
	'if int64(len(out)+n) > maxTargetSize {' 'if false {'

# Directory ownership has two call sites; each is proven by its own test on the
# function, sticky and not, and end to end by a real directory.
mutate no-owned-dir-writable agents.go TestAgentOwnedDirRefusedByRefuseWritable \
	'if a.hasUID(int64(st.Uid)) {' 'if false {'
mutate no-owned-dir-reachable agents.go TestAgentOwnedDirRefusedByRefuseReachable \
	'if a.hasUID(int64(st.Uid)) {' 'if false {' 2
mutateN no-owned-dir-both TestWriteThroughAgentOwnedParentRefused \
	agents.go 'if a.hasUID(int64(st.Uid)) {' 'if false {' \
	agents.go 'if a.hasUID(int64(st.Uid)) {' 'if false {'

# Directory descriptor hygiene: every descriptor walkToParent opens, and the
# one Write itself holds for the walked parent, must be closed by the time
# Write returns — a leak here is EMFILE on every job this process ever runs.
mutate write-parentfd-leak  write.go TestWriteDoesNotLeakDirectoryDescriptors \
	'defer func() { _ = unix.Close(parentFD) }()' 'defer func() { _ = parentFD }()'
mutate walk-ancestor-fd-leak securewrite_unix.go TestWriteDoesNotLeakDirectoryDescriptors \
	'_ = unix.Close(fd)' '_ = fd' 4
# Same two sites, proven again on the refusal path: a leak that only shows
# up when the write is refused is the more common case under an attack.
mutate write-parentfd-leak-on-refusal  write.go TestWriteDoesNotLeakDirectoryDescriptorsOnRefusal \
	'defer func() { _ = unix.Close(parentFD) }()' 'defer func() { _ = parentFD }()'
mutate walk-ancestor-fd-leak-on-refusal securewrite_unix.go TestWriteDoesNotLeakDirectoryDescriptorsOnRefusal \
	'_ = unix.Close(fd)' '_ = fd' 4

# Crash-mid-write defense: a failed fsync must abort before rename, leaving
# the original target untouched.
mutate no-fsync-check       securewrite_unix.go TestFsyncFailureLeavesOldContent \
	'if err := fsyncFD(fd); err != nil {' 'if err := error(nil); err != nil {'

# env-file: a value that cannot fit in one line must be refused rather than
# corrupt the file's line structure, and only the named field's own line may
# change.
mutate envfile-newline-ok   envfile.go TestEnvFileRejectsNewlineInValue \
	'bytes.IndexByte(val, envForbiddenLF) >= 0' 'false'
mutate envfile-wrong-line   envfile.go TestEnvFileNeighboringLinesByteIdentical \
	'prefix := append([]byte(t.Field), '"'"'='"'"')' 'prefix := []byte("zzWrongFieldzz=")'
mutate envfile-duplicate-ok envfile.go TestEnvFileDuplicateLineRefused \
	'if foundAt >= 0 {' 'if false {'

# launchd-env: only edits an existing plist's existing EnvironmentVariables
# dict — never invents either — and finds it by its place in the token stream,
# not by a text search.
mutate launchd-no-exists-check launchd.go TestLaunchdEnvMissingTargetRefusedDirect \
	'if !exists {' 'if false {'
mutate launchd-no-key-check    launchd.go TestLaunchdEnvNoEnvironmentVariablesKeyRefused \
	'if !done {' 'if false {'
# The mutant is the old lookup: a byte search for the key, then the next
# <dict>. A decoy (CDATA, escaped text, comment) ahead of the real key must
# defeat it in every test that plants one.
for t in TestTargetsAttack_PlistDecoyInCDATA TestLaunchdEnvDecoysAheadOfTheRealKeyIgnored TestLaunchdEnvKeyInsideCommentBeforeRealKeyRefused; do
	mutate "launchd-byte-search/$t" launchd.go "$t" \
		'func locateEnvDict(plist []byte, field string) (envLoc, error) {' \
		'func locateEnvDict(plist []byte, field string) (envLoc, error) {\n\tif i := bytes.Index(plist, []byte("<key>EnvironmentVariables</key>")); i >= 0 {\n\t\tj := bytes.Index(plist[i:], []byte("<dict>"))\n\t\tk := bytes.Index(plist[i+j:], []byte("</dict>"))\n\t\tif j >= 0 && k >= 0 {\n\t\t\treturn envLoc{start: i + j + 6, end: i + j + k}, nil\n\t\t}\n\t}'
done
# An empty <dict/> is not "the next <dict> in the file" (that one is another
# key's), and a key not followed by a dict is refused.
mutate launchd-empty-dict-ok   launchd.go TestLaunchdEnvEmptyDictNotSpilledIntoNextDict \
	'if selfClosing {' 'if selfClosing && false {'
# Two layers refuse a key followed by a scalar: the name check and the
# character-data check inside what would be the dict; both go off.
mutateN launchd-not-followed-by-dict TestLaunchdEnvKeyFollowedByStringRefused \
	launchd.go 'if name != "dict" {' 'if false {' \
	launchd.go 'case inEnv && len(stack) == 3 && !isBlank(t):' 'case false:'
mutate launchd-comment-ok      launchd.go TestLaunchdEnvCommentInsideDictRefused \
	'if inEnv {' 'if false {'
# A nested container is refused by three independent layers (the depth check,
# the dict/array case, the unknown-element default); all three go off.
mutateN launchd-nested-container-ok TestLaunchdEnvNestedContainerRefused \
	launchd.go 'case n > 4:' 'case false:' \
	launchd.go 'case name == "dict" || name == "array":' 'case false:' \
	launchd.go 'return envLoc{}, writeFailed("EnvironmentVariables dict holds an unknown element; not supported")' 'break'
# An unclosed or mismatched element is refused three ways over (the mismatch
# check, the open-element check at the end, the "no dict found" check); all
# three go off.
mutateN launchd-unclosed TestLaunchdEnvUnclosedRefused \
	launchd.go 'stack[n-1] != t.Name.Local {' 'false {' \
	launchd.go 'if len(stack) != 0 {' 'if false {' \
	launchd.go 'if !done {' 'if false {'
mutate launchd-non-string-ok   launchd.go TestLaunchdEnvExistingNonStringEntryRefused \
	'if name != "string" {' 'if false {'
mutate launchd-duplicate-ok    launchd.go TestLaunchdEnvDuplicateEntryRefused \
	'if loc.entry.found {' 'if false && loc.entry.found {'
mutate launchd-duplicate-top-level-ok launchd.go TestLaunchdEnvDuplicateTopLevelKeyRefused \
	'if done {' 'if false {'

# A value a format cannot hold byte for byte is refused, not stored altered
# (the fingerprint would attest to the altered one).
mutate launchd-altered-value   launchd.go TestValueNotRepresentableInFormatIsRefused \
	'if err != nil || !bytes.Equal(rt, val) {' 'if false && (err != nil || !bytes.Equal(rt, val)) {'
mutate json-invalid-utf8-ok    jsonpath.go TestValueNotRepresentableInFormatIsRefused \
	'if !utf8.Valid(val) {' 'if false && !utf8.Valid(val) {'
# A FIFO at the target name must not block the read of the existing target.
mutate open-existing-blocking  securewrite_unix.go TestFIFOAtTargetDoesNotBlockWrite \
	'unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)' 'unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)'

# JSON targets: the decoder's own message quotes the input, and a document
# after the first would be dropped by the re-encode.
mutate json-error-verbatim     jsonpath.go TestJSONPathMalformedExistingErrorLeaksNothing \
	'return nil, writeFailed("%s", jsonErrClass(err))' 'return nil, writeFailed("%v", err)'
mutate json-trailing-ok        jsonpath.go TestJSONPathTrailingDataRefused \
	'if _, err := dec.Token(); !errors.Is(err, io.EOF) {' 'if _, err := dec.Token(); false && !errors.Is(err, io.EOF) {'

mutate json-trailing-error-verbatim jsonpath.go TestJSONPathTrailingGarbageErrorLeaksNothing \
	'return nil, writeFailed("%s", jsonErrClass(err))' 'return nil, writeFailed("%v", err)' 2

# jsonpath's null-document refusal has two independent layers: decodeObject
# refuses a top-level JSON null outright (first "if doc == nil {"), and
# build() refuses again right where a nil map would otherwise reach
# setJSONPath (second occurrence, after decodeObject succeeds). Disabling
# the early layer alone must leave the late one catching it — proven below
# before the combined mutant that switches both off is allowed to mean
# anything.
assert_still_green json-null-early-off-alone jsonpath.go TestJSONTopLevelNullRefused \
	'if doc == nil {' 'if false {' 1
mutateN json-null-both-off TestJSONTopLevelNullRefused \
	jsonpath.go 'if doc == nil {' 'if false {' \
	jsonpath.go 'if doc == nil {' 'if false {'
# Same property, proven again by name for the mcp-config caller
# (TestJSONPathNullDocumentRefused): TestJSONTopLevelNullRefused exercises
# the same decodeObject/build() path but is a different test, and a red run
# is only a red run for the test it names.
assert_still_green json-null-early-off-alone-mcp jsonpath.go TestJSONPathNullDocumentRefused \
	'if doc == nil {' 'if false {' 1
mutateN json-null-both-off-mcp TestJSONPathNullDocumentRefused \
	jsonpath.go 'if doc == nil {' 'if false {' \
	jsonpath.go 'if doc == nil {' 'if false {'
# build's own encode-error path (the write-side sibling of json-error-verbatim
# above): encoding/json's error on a malformed json.RawMessage quotes the
# offending byte straight out of the value. "encode JSON failed" now appears
# five times in build (the placeholder measuring pass has its own two, ahead
# of this one) — nth=3 is the real compact-form Marshal, the one this test's
# broken quoter actually reaches; the placeholder pass never fails, since its
# value is always the literal `""`.
mutate json-encode-error-verbatim jsonpath.go TestJSONEncodeErrorLeaksNoByteOfValue \
	'return nil, writeFailed("encode JSON failed")' 'return nil, writeFailed("encode JSON: %v", err)' 3

# systemd-credential: the binary is found at a fixed, ownership-checked path,
# never on PATH, and runs with a minimal environment.
mutate systemd-path-lookup     systemdcred.go TestSystemdCredentialsBinaryNotLookedUpOnPATH \
	'func findSystemdCreds() (path string, present bool, err error) {' 'func findSystemdCreds() (path string, present bool, err error) {\n\tif p, lerr := exec.LookPath("systemd-creds"); lerr == nil {\n\t\treturn p, true, nil\n\t}'
mutate systemd-env-inherited   systemdcred.go TestSystemdCredentialsChildEnvironmentMinimal \
	'cmd.Env = childEnv' 'cmd.Env = nil'
mutate systemd-not-plain-file  systemdcred.go TestSystemdCredentialsUntrustedBinaryRefused \
	'case st.Mode&unix.S_IFMT != unix.S_IFREG:' 'case false:'
mutate systemd-foreign-owner   systemdcred.go TestSystemdCredentialsUntrustedBinaryRefused \
	'case int64(st.Uid) != sealToolTrustedUID:' 'case false:'
mutate systemd-writable        systemdcred.go TestSystemdCredentialsUntrustedBinaryRefused \
	'case st.Mode&0o022 != 0:' 'case false:'

mutate systemd-value-in-argv   systemdcred.go TestSystemdCredentialsChildEnvironmentMinimal \
	'args := []string{"encrypt"}' 'args := []string{"encrypt", string(val)}'
mutate systemd-no-name-encrypt systemdcred.go TestSystemdCredentialsChildEnvironmentMinimal \
	'if name := credName(t); name != "" {' 'if name := credName(t); false {' 1
mutate systemd-no-name-decrypt systemdcred.go TestSystemdCredentialsChildEnvironmentMinimal \
	'if name := credName(t); name != "" {' 'if name := credName(t); false {' 2

# The child's stderr must never be wired to this process's own — see the
# comment on runPiped. The mutant also needs the "os" import declared
# alongside it (systemdcred.go otherwise only imports "os/exec").
mutateN systemd-stderr-connected TestSystemdCredentialsChildStderrNotConnectedToProcess \
	systemdcred.go '"os/exec"' '"os"\n\t"os/exec"' \
	systemdcred.go 'cmd.Dir = "/"' 'cmd.Dir = "/"\n\tcmd.Stderr = os.Stderr'

# The mutant above wires the child's stderr to os.Stderr, the package
# variable — exactly what TestSystemdCredentialsChildStderrNotConnectedToProcess
# swaps out, so it catches it. A regression could instead dup the child's
# stderr onto this process's real fd 2 directly (os.NewFile(2, "stderr")),
# never touching the os.Stderr variable at all; that older test is blind to
# it (confirmed by hand: it stays green on this exact mutant), which is why
# TestSystemdCredentialsRealStderrFDNotConnectedToChild exists — it is the
# only one of the two that catches this mutant.
mutateN systemd-stderr-real-fd TestSystemdCredentialsRealStderrFDNotConnectedToChild \
	systemdcred.go '"os/exec"' '"os"\n\t"os/exec"' \
	systemdcred.go 'cmd.Stdin = bytes.NewReader(stdin)' 'cmd.Stdin = bytes.NewReader(stdin)\n\tcmd.Stderr = os.NewFile(2, "stderr")'

# Linux POSIX ACLs (macOS has its own check, proven by its own tests on a Mac).
# An access ACL on the directory; a default ACL (inherited by the temporary
# file, so the file check alone also catches it — both go off together); an
# ACL on the temporary file itself; and a failure to read the attribute must
# refuse, not pass.
if linux_only linux-acl; then
	mutate linux-acl-access-parent acl_linux.go TestAccessACLOnParentRefused \
		'[]string{xattrACLAccess, xattrACLDefault}' '[]string{xattrACLDefault}'
	mutateN linux-acl-default-parent TestDefaultACLOnParentRefused \
		acl_linux.go '[]string{xattrACLAccess, xattrACLDefault}' '[]string{xattrACLAccess}' \
		acl_linux.go 'return denied("file carries an extended ACL")' 'return nil'
	mutate linux-acl-tmpfile       acl_linux.go TestACLOnTemporaryFileRefused \
		'return denied("file carries an extended ACL")' 'return nil'
	mutate linux-acl-fails-open    acl_linux.go TestHasXattrFailsClosed \
		'return false, writeFailed("read %s: %v", name, err)' 'return false, nil'
fi

# A line-oriented format has three bytes it cannot carry, each switched off on
# its own; and a value that needs quoting is quoted, in a form a shell reads
# back as itself.
mutate envfile-nul-ok          envfile.go TestEnvFileRejectsNULAndCRInValue \
	'bytes.IndexByte(val, envForbiddenNUL) >= 0 ||' 'false ||'
mutate envfile-cr-ok           envfile.go TestEnvFileRejectsNULAndCRInValue \
	'bytes.IndexByte(val, envForbiddenCR) >= 0 {' 'false {'
# Without quoting, read-back refuses the line it just wrote (Write fails), and
# with read-back also lenient the consumer would see a different value: the
# round-trip test catches the first, the consumer-side attack the pair.
mutate envfile-no-quoting      envfile.go TestEnvFileQuotedValuesRoundTrip \
	'if bare {' 'if bare || true {'
mutateN envfile-no-quoting-lenient-readback TestTargetsAttack_EnvFileConsumerSeesSameValue \
	envfile.go 'if bare {' 'if bare || true {' \
	envfile.go 'return nil, writeFailed("written env-file line is not in the form this package writes")' 'out = append(out, c); i++; continue'
mutate envfile-quote-not-escaped envfile.go TestEnvFileQuotedValuesRoundTrip \
	'out = append(out, envEscQuote...)' 'out = append(out, c)'
mutate envfile-unquote-escaped envfile.go TestEnvFileQuotedValuesRoundTrip \
	'raw[i+1] == sq:' 'false:'
mutate envfile-unquote-lenient envfile.go TestShellUnquoteRefusesOtherForms \
	'return nil, writeFailed("written env-file line is not in the form this package writes")' 'out = append(out, c); i++; continue'

# JSON: only a string (or nothing, or null) is a secret slot.
mutate json-object-replaced    jsonpath.go TestJSONPathNonStringLeafNotReplaced \
	'case nil, string:' 'case nil, string, map[string]any, []any, bool, json.Number:'
mutate json-object-replaced-attack jsonpath.go TestTargetsAttack_JSONReplacesObjectWithString \
	'case nil, string:' 'case nil, string, map[string]any:'

# An existing target that others could have written is not adopted as the base
# for a kind that folds its content in — and is for one that does not.
mutate existing-world-writable agents.go TestTargetsAttack_ExistingTargetWritableByOthersRefused \
	'mode&0o002 != 0 {' 'mode&0o002 != 0 && false {' 2
mutate existing-group-writable agents.go TestTargetsAttack_ExistingTargetWritableByOthersRefused \
	'mode&0o020 != 0 && a.groupIsAgents(int64(st.Gid))' 'mode&0o020 != 0 && false' 2
mutate existing-check-always   securewrite_unix.go TestTargetsAttack_ExistingLooseTargetTightened \
	'if folds {' 'if true {'

# Every directory on the path is checked for writability, not only the last.
mutate writable-only-parent    securewrite_unix.go TestWritableAncestorDirRefused \
	'if err := ag.refuseWritable(fmt.Sprintf("directory %q", seg), &st); err != nil {' 'if err := ag.refuseWritable(fmt.Sprintf("directory %q", seg), &st); isParent && err != nil {'
# Each of the two reach bits alone refuses the parent.
mutate reach-bit-traverse-only agents.go TestAgentReachableParentDirRefusedForEachBit \
	'const dirReachBits = 0o5' 'const dirReachBits = 0o1'
mutate reach-bit-read-only     agents.go TestAgentReachableParentDirRefusedForEachBit \
	'const dirReachBits = 0o5' 'const dirReachBits = 0o4'
# Each "other" bit, and each group bit of an agent group, refuses the target.
mutate target-other-write-bits securewrite_unix.go TestTargetModeBitsEachRefused \
	'case mode&0o007 != 0:' 'case mode&0o004 != 0:'
mutate target-group-bits       securewrite_unix.go TestTargetModeBitsEachRefused \
	'if mode&0o070 != 0 && ag.groupIsAgents(gid) {' 'if mode&0o040 != 0 && ag.groupIsAgents(gid) {'

# The walk descends by descriptor, from the directory already opened.
mutate walk-by-path            securewrite_unix.go TestAncestorSwappedDuringWalkStaysInWalkedTree \
	'unix.Openat(fd, seg,' 'unix.Openat(fd, acc+"/"+seg,'
# The temporary name is created exclusively: a planted file is not adopted.
mutate tmp-no-excl             securewrite_unix.go TestPlantedTemporaryNameIsNotAdopted \
	'unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY' 'unix.O_CREAT|unix.O_WRONLY'
# The temporary file's mode is read back before the value is written.
mutate tmp-mode-not-checked    securewrite_unix.go TestTemporaryFileModeChangedAfterChmodRefused \
	'case uint32(st.Mode)&0o7777 != mode:' 'case false:'
# The two rechecks of the temporary file — before the first byte, and before
# the rename — are each proven alone.
mutate tmp-first-recheck-off   securewrite_unix.go TestHardlinkRaceAfterTmpCreateRefused \
	'if err := checkTmpFile(fd, uid, gid, mode); err != nil {' 'if err := error(nil); err != nil {'
mutate tmp-second-recheck-off  securewrite_unix.go TestHardlinkAddedDuringWriteRefusedBeforeRename \
	'if err := checkTmpFile(fd, uid, gid, mode); err != nil {' 'if err := error(nil); err != nil {' 2
# The temporary file's group is read back before the write, the same way its
# owner and mode are: a chown that silently keeps the old group is caught.
mutate tmp-gid-not-checked     securewrite_unix.go TestTemporaryFileGroupChangedAfterChownRefused \
	'case int64(st.Gid) != gid:' 'case false:'
# The read back after the rename runs the same checks as the read before it:
# the mutant reads the name without any of them.
mutate readback-unchecked      write.go TestReadBackRefusesTargetReplacedAfterRename \
	'written, _, err := readExisting(parentFD, base, t.Path, owners, ag, false)' \
	'written, _, err := func() ([]byte, bool, error) { rfd, oerr := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_CLOEXEC, 0); if oerr != nil { return nil, false, oerr }; defer func() { _ = unix.Close(rfd) }(); b, rerr := readAllFD(rfd, 0); return b, true, rerr }()'

# systemd-credential: the trusted binary is run by its fixed path even when a
# same-named binary sits first on PATH; the child's environment is exactly the
# fixed one; the production trust values are the safe ones.
mutate systemd-run-by-name     systemdcred.go TestSystemdCredentialsDecoyOnPATHNotRunWhenTrustedBinaryExists \
	'exec.Command(path, args...)' 'exec.Command("systemd-creds", args...)'
mutate systemd-env-extra       systemdcred.go TestSystemdCredentialsChildEnvironmentExact \
	'PATH=/usr/sbin:/usr/bin:/sbin:/bin"}' 'PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}'
mutate systemd-default-path    systemdcred.go TestSystemdCredentialsTrustDefaults \
	'sealToolPath = "/usr/bin/systemd-creds"' 'sealToolPath = "/opt/homebrew/bin/systemd-creds"'
mutate systemd-default-owner   systemdcred.go TestSystemdCredentialsTrustDefaults \
	'sealToolTrustedUID int64' 'sealToolTrustedUID int64 = 501'

# An existing target's ACL, per platform. (Where the code is not compiled the
# mutation is reported as not run, never as passed.)
if linux_only linux-acl-existing; then
	mutate linux-acl-existing-target acl_linux.go TestExistingTargetWithACLRefusedWhenFolded \
		'func checkExistingFileACL(fd int, _ string) error { return checkFileACL(fd) }' 'func checkExistingFileACL(fd int, _ string) error { return nil }'
fi
if darwin_only darwin-acl-existing; then
	mutate darwin-acl-existing-target acl_darwin.go TestExistingTargetWithACLRefusedWhenFolded \
		'func checkExistingFileACL(_ int, p string) error { return checkACL(p) }' 'func checkExistingFileACL(_ int, p string) error { return nil }'
	mutate darwin-everyone-group   agents.go TestEveryoneGroupCountsAsAgents \
		'return runtime.GOOS == "darwin" && gid == everyoneGID' 'return runtime.GOOS == "" && gid == everyoneGID'
	mutate darwin-everyone-reach   agents.go TestEveryoneGroupCountsAsAgents \
		'if (mode>>3)&dirReachBits != 0 && a.groupIsAgents(int64(st.Gid)) {' 'if (mode>>3)&dirReachBits != 0 && a.hasGID(int64(st.Gid)) {'
fi

# Second round of guards (guards2_test.go): the plist locator, the shell
# dialect, the existing-target rule, the descriptor and rename plumbing, and
# the systemd-creds child.
# Three depth checks each refuse the decoy on their own; the property is proven
# only with all three switched off together.
mutateN launchd-nested-key-decoy TestNestedEnvKeyDecoyAhead \
	launchd.go 'case n == 3 && stack[0] == "plist" && stack[1] == "dict":' 'case n >= 3 && stack[0] == "plist":' \
	launchd.go 'case inEnv && len(stack) == 4 && stack[3] == "key", !inEnv && len(stack) == 3 && stack[2] == "key":' 'case inEnv && len(stack) == 4 && stack[3] == "key", !inEnv && stack[len(stack)-1] == "key":' \
	launchd.go 'case !inEnv && n == 3 && name == "key":' 'case !inEnv && name == "key":'
mutateN launchd-top-key-prefix TestTopKeyMustBeExact \
	launchd.go '"errors"' '"errors"; "strings"' \
	launchd.go 'topKey == envVarsKey' 'strings.Contains(topKey, envVarsKey)'
mutateN launchd-entry-key-prefix TestEntryKeyMustBeExact \
	launchd.go '"errors"' '"errors"; "strings"' \
	launchd.go 'if envKey == field {' 'if strings.Contains(envKey, field) {'
mutate launchd-attr-allowed    launchd.go TestDictShapeRefused 'if len(t.Attr) > 0 {' 'if false {'
mutate launchd-key-key-ok      launchd.go TestDictShapeRefused 'if envKeyReady {' 'if false {'
mutate launchd-dangling-key-ok launchd.go TestDictShapeRefused 'if envKeyReady {' 'if false {' 2
mutate launchd-value-no-key-ok launchd.go TestDictShapeRefused 'if !envKeyReady {' 'if false {'
mutate launchd-markup-ok       launchd.go TestDictShapeRefused 'if inEnv {' 'if false {'
mutate launchd-root-not-plist  launchd.go TestPlistRootAndSecondLevel 'stack[0] == "plist"' 'true'
mutate launchd-second-not-dict launchd.go TestPlistRootAndSecondLevel 'stack[1] == "dict"' 'true'

# A crash guard: without the empty-file branch the line splitter indexes -1.
mutate envfile-empty-existing  envfile.go TestEmptyExistingFiles 'if !exists || len(existing) == 0 {' 'if !exists {'
mutate json-empty-existing     jsonpath.go TestEmptyExistingFiles 'len(bytes.TrimSpace(existing)) > 0' 'len(bytes.TrimSpace(existing)) >= 0'
mutate envfile-bare-dollar     envfile.go TestBareCharsEachByteThroughShell ',./-"' ',./-$"'
mutate json-empty-segment      jsonpath.go TestSplitFieldDirect 'if s == "" {' 'if s == "" && false {'

mutate folding-off             securewrite_unix.go TestFoldingKindsRefuseWritableExisting 'if folds {' 'if false {'
mutate writable-file-agent-group agents.go TestRefuseWritableFileDirect 'mode&0o020 != 0 && a.groupIsAgents(int64(st.Gid))' 'false' 2
mutate writable-file-agent-owner agents.go TestRefuseWritableFileDirect 'if a.hasUID(int64(st.Uid)) {' 'if false {' 3
mutate fingerprint-of-input    write.go TestFingerprintAttestsDiskNotInput 'computeFingerprint(fpKey, back)' 'computeFingerprint(fpKey, v)'
mutate systemd-stat-error-is-absence systemdcred.go TestSystemdStatErrorIsNotAbsence 'if errors.Is(err, unix.ENOENT) {' 'if errors.Is(err, unix.ENOENT) || true {'
mutate systemd-folds-existing  systemdcred.go TestSystemdCredFoldIsNotUsed 'foldsExisting() bool { return false }' 'foldsExisting() bool { return true }'
mutate systemd-child-cwd       systemdcred.go TestSystemdChildCwdIsRoot 'cmd.Dir = "/"' 'cmd.Dir = ""'
mutate systemd-readback-untrusted systemdcred.go TestSystemdReadBackRefusesBinaryTurnedUntrusted \
	'path, present, err := findSystemdCreds()' 'path, present, err := sealToolPath, true, error(nil)' 2

mutate root-fd-no-cloexec      securewrite_unix.go TestDescriptorsAreCloexec 'unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)' 'unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY, 0)'
mutate dir-fsync-ignored       securewrite_unix.go TestDirFsyncFailureReported 'if err := fsyncFD(parentFD); err != nil {' 'if err := fsyncFD(parentFD); false && err != nil {'
mutate walk-path-gate-off      securewrite_unix.go TestWalkToParentRefusals 'if !path.IsAbs(absPath) || path.Clean(absPath) != absPath || absPath == "/" {' 'if false && (!path.IsAbs(absPath) || path.Clean(absPath) != absPath || absPath == "/") {'
mutate walk-root-check-off     securewrite_unix.go TestWalkToParentRefusals 'if err := checkDir(fd, "/", ag, rootIsParent); err != nil {' 'if err := checkDir(fd, "/", ag, rootIsParent); false && err != nil {'
mutate perm-mode-bits-off      securewrite_unix.go TestValidateTargetPermDirect 'case mode == 0 || mode&^0o777 != 0:' 'case mode == 0:'
mutate perm-zero-mode-ok       securewrite_unix.go TestValidateTargetPermDirect 'case mode == 0 || mode&^0o777 != 0:' 'case mode&^0o777 != 0:'
mutate tmp-name-constant       securewrite_unix.go TestTmpNameRandom 'rand.Read(b)' 'rand.Read(b[:0])'

# Findings of the independent red-run pass over the second round.
mutate walk-ancestor-agent-owner agents.go TestWalkAgentOwnedAncestorRefused 'if a.hasUID(int64(st.Uid)) {' 'if false {'
# The parent is checked by two layers that both refuse an agent's ownership;
# only the pair switched off together proves the property.
mutateN walk-parent-agent-owner TestWalkToParentRefusals \
	agents.go 'if a.hasUID(int64(st.Uid)) {' 'if false {' \
	agents.go 'if a.hasUID(int64(st.Uid)) {' 'if false {'
mutate walk-clean-clause-off   securewrite_unix.go TestWalkToParentRefusals \
	'|| path.Clean(absPath) != absPath ||' '|| false ||'
mutate perm-setgid-ok          securewrite_unix.go TestValidateTargetPermDirect 'mode&^0o777 != 0:' 'mode&^0o2777 != 0:'
mutate writable-file-other-bit agents.go TestRefuseWritableFileDirect 'if mode&0o002 != 0 {' 'if mode&0o020 != 0 {' 2
mutate writable-file-group-bit agents.go TestRefuseWritableFileDirect 'mode&0o020 != 0 && a.groupIsAgents(int64(st.Gid))' 'mode&0o200 != 0 && a.groupIsAgents(int64(st.Gid))' 2
mutateN launchd-top-key-foldcase TestTopKeyMustBeExact \
	launchd.go '"errors"' '"errors"; "strings"' \
	launchd.go 'topKey == envVarsKey' 'strings.EqualFold(topKey, envVarsKey)'
mutateN launchd-entry-key-fold  TestEntryKeyMustBeExact \
	launchd.go '"errors"' '"errors"; "strings"' \
	launchd.go 'if envKey == field {' 'if strings.EqualFold(envKey, field) {'
mutateN launchd-entry-key-suffix TestEntryKeyMustBeExact \
	launchd.go '"errors"' '"errors"; "strings"' \
	launchd.go 'if envKey == field {' 'if strings.Contains(field, envKey) {'
mutate launchd-text-in-dict    launchd.go TestTextInsideEnvDictRefused 'case inEnv && len(stack) == 3 && !isBlank(t):' 'case false:'
mutate systemd-stat-loop-is-absence systemdcred.go TestSystemdStatLoopIsNotAbsence \
	'if errors.Is(err, unix.ENOENT) {' 'if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {'
mutate envfile-quote-escape-off envfile.go TestBareCharsEachByteThroughShell 'out = append(out, envEscQuote...)' 'out = append(out, sq)'
mutate tmp-name-short          securewrite_unix.go TestTmpNameRandom \
	'b := make([]byte, staleTmpSuffixLen/2)' 'b := make([]byte, 2)'

# The canary detector itself: an error message that echoes a value-derived
# string (here, in the env-file line-too-long refusal) must be caught by
# TestCanaryNeverInErrors, not just by whichever test exercises that one
# path — this proves the leak test would fail on a real leak, not just that
# today's code happens not to have one.
mutate canary-detector envfile.go TestCanaryNeverInErrors \
	'return nil, denied("value contains a byte that cannot appear in an env-file line")' \
	'return nil, denied("value contains a byte that cannot appear in an env-file line: %q", val)'

# hermes-config: a line in the profile's .env, read by Hermes's own loader. Each
# form of value the loader would change is refused by its own check, the field
# is an env name, not a dotted path, and the kind is routed to the env-line
# handler.
mutate hermes-nonprintable-ok  hermesenv.go TestHermesConfigRefusesValuesTheLoaderMisreads \
	'if c < hermesPrintableLow || c > hermesPrintableHigh {' 'if c < hermesPrintableLow && c > hermesPrintableHigh {'
mutate hermes-quote-ok         hermesenv.go TestHermesConfigRefusesValuesTheLoaderMisreads \
	'if bytes.IndexByte(val, hermesForbiddenQuote) >= 0 {' 'if false {'
mutate hermes-backslash-ok     hermesenv.go TestHermesConfigRefusesValuesTheLoaderMisreads \
	'if bytes.IndexByte(val, hermesForbiddenBackslash) >= 0 {' 'if false {'
mutate hermes-double-quote-ok  hermesenv.go TestHermesConfigRefusesValuesTheLoaderMisreads \
	'if bytes.IndexByte(val, hermesForbiddenDQuote) >= 0 {' 'if false {'
mutate hermes-interpolation-ok hermesenv.go TestHermesConfigRefusesValuesTheLoaderMisreads \
	'if bytes.Contains(val, hermesInterpolation) {' 'if false {'
mutate hermes-interpolation-wide hermesenv.go TestHermesConfigTakesValuesNextToTheRefusedClasses \
	'var hermesInterpolation = []byte("${")' 'var hermesInterpolation = []byte("$")'
mutate hermes-printable-low    hermesenv.go TestHermesConfigRefusesValuesTheLoaderMisreads \
	'hermesPrintableLow       byte = 0x20' 'hermesPrintableLow       byte = 0x1f'
mutate hermes-run-any-follower hermesenv.go TestHermesConfigTakesValuesNextToTheRefusedClasses \
	"case c == '=' && run >= hermesNameRun:" 'case run >= hermesNameRun:'
mutate hermes-run-not-reset    hermesenv.go TestHermesConfigTakesValuesNextToTheRefusedClasses \
	'run = 0' '_ = run'
mutate hermes-name-run-ok      hermesenv.go TestHermesConfigRefusesValuesTheLoaderMisreads \
	"case c == '=' && run >= hermesNameRun:" 'case false:'
mutate hermes-name-run-longer  hermesenv.go TestHermesConfigRefusesValuesTheLoaderMisreads \
	'hermesNameRun = 6' 'hermesNameRun = 8'
mutate hermes-name-run-shorter hermesenv.go TestHermesConfigTakesValuesNextToTheRefusedClasses \
	'hermesNameRun = 6' 'hermesNameRun = 4'
mutate hermes-refusal-text     hermesenv.go TestHermesConfigRefusesValuesTheLoaderMisreads \
	'return nil, denied(hermesRefusal)' 'return nil, denied("%s", hermesRefusal+string(val))'
mutate hermes-json-handler     write.go TestHermesConfigWritesEnvLine \
	'runnerproto.TargetHermesConfig:      hermesEnvHandler{},' 'runnerproto.TargetHermesConfig:      jsonPathHandler{},'
# The old shape: hermes-config validated as a dotted key like mcp-config.
mutateN hermes-dotted-field-ok TestHermesConfigDottedPathInvalid \
	../../pkg/runnerproto/job.go 'case TargetEnvFile, TargetLaunchdEnv, TargetHermesConfig:' 'case TargetEnvFile, TargetLaunchdEnv:' \
	../../pkg/runnerproto/job.go 'case TargetMCPConfig:' 'case TargetMCPConfig, TargetHermesConfig:'

# Entry boundaries of an env-file: the writer replaces "the line", so it refuses
# any existing file in which some line is not a complete entry on its own. For
# env-file (a POSIX shell) a line is accepted only if it is blank, a comment or
# [export] NAME=word [# comment]; for hermes-config (python-dotenv) the grammar
# is dotenv's. Each rule of that check is switched off on its own; the tests
# hold accepted and refused files for both readers, and a real shell reads what
# is written.
mutate envscan-build-no-check   envfile.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'if !existingIsSimple(existing, d) {' 'if false {'
mutate envscan-readback-no-check envfile.go TestEnvReadBackRefusesEntriesThatSpanLines \
	'if !existingIsSimple(content, d) {' 'if false {'
mutate envscan-build-reads-as-dotenv envfile.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'return envBuild(dialectShell,' 'return envBuild(dialectDotenv,'
mutate envscan-readback-reads-as-dotenv envfile.go TestEnvFileSimpleNeighbours \
	'return envReadBack(dialectShell,' 'return envReadBack(dialectDotenv,'
mutate envscan-hermes-build-reads-as-shell hermesenv.go TestHermesConfigSimpleNeighbours \
	'return envBuild(dialectDotenv,' 'return envBuild(dialectShell,'
mutate envscan-hermes-readback-reads-as-shell hermesenv.go TestHermesConfigSimpleNeighbours \
	'return envReadBack(dialectDotenv,' 'return envReadBack(dialectShell,'
# The shell whitelist.
mutate envscan-shell-comment-line-refused envscan.go TestEnvFileSimpleNeighbours \
	"if i >= len(line) || line[i] == '#' {" 'if i >= len(line) {'
mutate envscan-shell-empty-name-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'if j == i ||' 'if false ||'
mutate envscan-shell-digit-name-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	"line[i] >= '0' && line[i] <= '9' ||" 'false ||'
mutate envscan-shell-no-equals-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	"|| j >= len(line) || line[j] != '=' {" '|| j >= len(line) {'
mutate envscan-shell-export-not-skipped envscan.go TestEnvFileSimpleNeighbours \
	'i = skipBlanks(line, i+len(shellExport))' '_ = i'
mutate envscan-shell-trailing-word-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	"return k == len(line) || line[k] == '#'" 'return true'
mutate envscan-shell-trailing-comment-refused envscan.go TestEnvFileSimpleNeighbours \
	"return k == len(line) || line[k] == '#'" 'return k == len(line)'
mutate envscan-shell-blank-does-not-end-word envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'case isSpaceTab(c):' 'case false:'
mutate envscan-shell-unclosed-single-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'if end < 0 {' 'if end < 0 { k++; continue }; if false {'
mutate envscan-shell-unclosed-double-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'if end < 0 {' 'if end < 0 { k++; continue }; if false {' 2
mutate envscan-shell-expansion-in-double-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellInDouble = string([]byte{0x24, 0x60, 0x5c})' 'shellInDouble = string([]byte{0x0})'
mutate envscan-shell-dollar-in-double-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'0x24, 0x60, 0x5c' '0x60, 0x5c'
mutate envscan-shell-backtick-in-double-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'0x24, 0x60, 0x5c' '0x24, 0x5c'
mutate envscan-shell-backslash-in-double-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'0x24, 0x60, 0x5c' '0x24, 0x60'
mutate envscan-shell-any-backslash-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'line[k+1] != sq {' 'false {'
mutate envscan-shell-escaped-apostrophe-refused envscan.go TestEnvFileSimpleNeighbours \
	'case c == envBackslash:' 'case false:'
mutate envscan-shell-dollar-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "`;&|()<>~"'
mutate envscan-shell-backtick-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "$;&|()<>~"'
mutate envscan-shell-semicolon-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "$`&|()<>~"'
mutate envscan-shell-ampersand-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "$`;|()<>~"'
mutate envscan-shell-pipe-ok   envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "$`;&()<>~"'
mutate envscan-shell-open-paren-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "$`;&|)<>~"'
mutate envscan-shell-close-paren-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "$`;&|(<>~"'
mutate envscan-shell-less-than-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "$`;&|()>~"'
mutate envscan-shell-greater-than-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "$`;&|()<~"'
mutate envscan-shell-tilde-ok  envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'shellWordForbidden = "$`;&|()<>~"' 'shellWordForbidden = "$`;&|()<>"'
mutate envscan-shell-equals-at-word-start-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	"case c == '=' && (k == start ||" "case c == '=' && (k < 0 && k == start ||"
mutate envscan-shell-equals-after-colon-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	"|| line[k-1] == ':'):" '|| false):'
mutate envscan-shell-special-neighbour-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'if shellSpecialName(string(line[i:j])) {' 'if false {'
mutate envscan-special-field-ok envfile.go TestEnvFileSpecialFieldNamesAreRefused \
	'if d == dialectShell && shellSpecialName(t.Field) {' 'if false {'
mutate envscan-special-field-for-dotenv envfile.go TestEnvFileSpecialFieldNamesAreRefused \
	'if d == dialectShell && shellSpecialName(t.Field) {' 'if shellSpecialName(t.Field) {'
mutate envscan-special-names-empty envscan.go TestShellSpecialNamesAreExactlyThese \
	'var shellSpecialNames = namesSet(' 'var shellSpecialNames = namesSet(""); var _ = namesSet('
mutate envscan-special-name-dropped envscan.go TestShellSpecialNamesAreExactlyThese \
	'	OPTARG' '	XOPTARG'
mutate envscan-special-name-optind envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	OPTIND' '	XOPTIND'
mutate envscan-special-name-ifs envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	IFS' '	XIFS'
mutate envscan-special-name-status envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	status' '	Xstatus'
# Names a shell evaluates as arithmetic (a value such as x[$(cmd)] runs) or
# quotes in a message (the head of the value reaches the consumer's stderr).
mutate envscan-special-name-srandom envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	SRANDOM' '	XSRANDOM'
mutate envscan-special-name-jobmax envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	JOBMAX' '	XJOBMAX'
mutate envscan-special-name-savehist envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	SAVEHIST' '	XSAVEHIST'
mutate envscan-special-name-errno envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	ERRNO' '	XERRNO'
# The same names, proved against a real shell: only where the shell is
# installed and lists the variable itself (the tests read the shells they find).
if shell_lists bash SRANDOM; then
	mutate envscan-real-bash-srandom envscan.go TestEnvFileEveryShellOwnVariableIsRefusedOrReadCleanly \
		'	SRANDOM' '	XSRANDOM'
	mutate envscan-real-bash-srandom-cover envscan.go TestShellSpecialNamesCoverTheInstalledShells \
		'	SRANDOM' '	XSRANDOM'
else
	echo "skip envscan-real-bash-srandom: no bash here that lists SRANDOM (runs where bash is installed)"
fi
if shell_lists ksh JOBMAX; then
	mutate envscan-real-ksh-jobmax envscan.go TestEnvFileEveryShellOwnVariableIsRefusedOrReadCleanly \
		'	JOBMAX' '	XJOBMAX'
else
	echo "skip envscan-real-ksh-jobmax: no ksh here that lists JOBMAX"
fi
if shell_lists zsh SAVEHIST; then
	mutate envscan-real-zsh-savehist envscan.go TestEnvFileEveryShellOwnVariableIsRefusedOrReadCleanly \
		'	SAVEHIST' '	XSAVEHIST'
else
	echo "skip envscan-real-zsh-savehist: no zsh here that lists SAVEHIST"
fi
mutate envscan-special-prefix-lc envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'"LC_", ' '"LX_", '
mutate envscan-special-prefix-bash envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'"BASH_", ' '"BASX_", '
mutate envscan-special-prefix-zsh envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'"ZSH_", ' '"ZSX_", '
mutate envscan-special-prefix-zle envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'"ZLE_", ' '"ZLX_", '
mutate envscan-special-prefix-yash envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'"YASH_", ' '"YASX_", '
mutate envscan-special-prefix-comp envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'"COMP_", ' '"COMX_", '
mutate envscan-special-prefix-readline envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'"READLINE_", ' '"READLINX_", '
mutate envscan-special-prefix-terminfo envscan.go TestShellSpecialNamesAreExactlyThese \
	'"TERMINFO", ' '"TERMINFX", '
mutate envscan-special-name-editor envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	EDITOR' '	XEDITOR'
mutate envscan-special-name-histedit envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	HISTEDIT' '	XHISTEDIT'
mutate envscan-special-prefix-zftp envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'"ZFTP_", ' '"ZFTX_", '
mutate envscan-special-prefix-zcurses envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'"ZCURSES_"}' '"ZCURSEX_"}'
mutate envscan-special-name-ps0 envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	PS0' '	XPS0'
mutate envscan-special-name-rprompt envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	RPROMPT' '	XRPROMPT'
mutate envscan-special-name-period envscan.go TestEnvFileSpecialFieldNamesAreRefused \
	'	PERIOD' '	XPERIOD'
mutate envscan-later-form-not-checked envfile.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'if assignsField(l, t.Field, d) {' 'if assignsField(l, t.Field, d) && false {'
mutate envscan-readback-later-form-not-checked envfile.go TestEnvReadBackRefusesEntriesThatSpanLines \
	'if assignsField(later, t.Field, d) {' 'if assignsField(later, t.Field, d) && false {'
mutate envscan-assigns-shell-indent-not-trimmed envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'l = bytes.TrimLeft(l, spaceTab)' '_ = l' 
mutate envscan-assigns-shell-tab-not-trimmed envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'l = bytes.TrimLeft(l, spaceTab)' 'l = bytes.TrimLeft(l, " ")'
mutate envscan-assigns-dotenv-indent-not-trimmed envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'l = bytes.TrimLeftFunc(l, unicode.IsSpace)' '_ = l'
mutate envscan-assigns-dotenv-ascii-space-only envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'l = bytes.TrimLeftFunc(l, unicode.IsSpace)' 'l = bytes.TrimLeft(l, spaceTab)'
mutate envscan-assigns-export-not-skipped envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'if bytes.HasPrefix(l, shellExport) && len(l) > len(shellExport) && isSpaceTab(l[len(shellExport)]) {' 'if false {'
mutate envscan-assigns-dotenv-no-value-ok envscan.go TestEnvScanNeverPanics \
	'return len(rest) == 0 || rest[0] ==' 'return rest[0] =='
mutate envscan-assigns-dotenv-equals-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	"|| rest[0] == '=' ||" '||'
mutate envscan-assigns-dotenv-comment-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	"|| rest[0] == '#'" '|| false'
mutate envscan-assigns-shell-any-continuation envscan.go TestEnvFileSimpleNeighbours \
	"return len(rest) > 0 && rest[0] == '='" 'return len(rest) > 0'
mutate envscan-assigns-dotenv-any-continuation envscan.go TestHermesConfigSimpleNeighbours \
	"return len(rest) == 0 || rest[0] ==" "return true || rest[0] =="
mutate envscan-dotenv-bom-ok   envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'bytes.Contains(content, utf8BOM)' 'false'
mutate envscan-bare-equals-ok  envfile.go TestEnvFileWrittenValuesAreReadBackByShells \
	'_@%+:,./-"' '_@%+=:,./-"'
# The dotenv grammar.
mutate envscan-dotenv-odd-space-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'[]byte{0x0d, 0x0b, 0x0c, 0x1c, 0x1d, 0x1e, 0x1f}' '[]byte{}'
mutate envscan-dotenv-cr-ok    envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'[]byte{0x0d, 0x0b, 0x0c, 0x1c, 0x1d, 0x1e, 0x1f}' '[]byte{0x0b, 0x0c, 0x1c, 0x1d, 0x1e, 0x1f}'
mutate envscan-dotenv-vt-ok    envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'[]byte{0x0d, 0x0b, 0x0c, 0x1c, 0x1d, 0x1e, 0x1f}' '[]byte{0x0d, 0x0c, 0x1c, 0x1d, 0x1e, 0x1f}'
mutate envscan-dotenv-ff-ok    envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'[]byte{0x0d, 0x0b, 0x0c, 0x1c, 0x1d, 0x1e, 0x1f}' '[]byte{0x0d, 0x0b, 0x1c, 0x1d, 0x1e, 0x1f}'
mutate envscan-shell-tab-is-not-a-blank envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'string([]byte{0x20, 0x09})' 'string([]byte{0x20})'
mutate envscan-shell-space-is-not-a-blank envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'string([]byte{0x20, 0x09})' 'string([]byte{0x09})'
mutate envscan-shell-double-quote-last-byte-unchecked envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	'line[k+1:k+1+end]' 'line[k+1:k+end]'
mutate envscan-dotenv-double-quote-not-a-quote envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	"|| q == '\"'" '|| false'
mutate envscan-shell-zero-name-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	"line[i] >= '0' && line[i] <= '9' ||" "line[i] > '0' && line[i] <= '9' ||"
mutate envscan-shell-nine-name-ok envscan.go TestEnvFileEntriesThatSpanLinesAreRefused \
	"line[i] >= '0' && line[i] <= '9' ||" "line[i] >= '0' && line[i] < '9' ||"
mutate envscan-dotenv-name-run-boundary envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	"case c == '=' && run >= hermesNameRun:" "case c == '=' && run > hermesNameRun:"
mutate envscan-dotenv-name-run-off-by-one envscan.go TestHermesConfigSimpleNeighbours \
	"case c == '=' && run >= hermesNameRun:" "case c == '=' && run >= hermesNameRun-1:"
mutate envscan-dotenv-separator-controls-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'0x0c, 0x1c, 0x1d, 0x1e, 0x1f}' '0x0c}'
mutate envscan-dotenv-file-separator-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'0x0c, 0x1c, 0x1d, 0x1e, 0x1f}' '0x0c, 0x1d, 0x1e, 0x1f}'
mutate envscan-dotenv-group-separator-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'0x0c, 0x1c, 0x1d, 0x1e, 0x1f}' '0x0c, 0x1c, 0x1e, 0x1f}'
mutate envscan-dotenv-record-separator-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'0x0c, 0x1c, 0x1d, 0x1e, 0x1f}' '0x0c, 0x1c, 0x1d, 0x1f}'
mutate envscan-dotenv-unit-separator-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'0x0c, 0x1c, 0x1d, 0x1e, 0x1f}' '0x0c, 0x1c, 0x1d, 0x1e}'
mutate envscan-dotenv-not-utf8-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'!utf8.Valid(content)' 'false && !utf8.Valid(content)'
mutate envscan-dotenv-two-names-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'if countAssignmentNames(line) > 1 {' 'if false {'
mutate envscan-dotenv-name-run-too-long envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	"case c == '=' && run >= hermesNameRun:" "case c == '=' && run >= 100:"
mutate envscan-dotenv-name-not-counted envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'n++' 'n += 0'
mutate envscan-dotenv-escape-next-to-quote-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'if bytes.IndexByte(line, envBackslash) >= 0 &&' 'if false &&'
mutate envscan-dotenv-comment-line-scanned envscan.go TestHermesConfigSimpleNeighbours \
	"if i >= len(line) || line[i] == '#' {" 'if i >= len(line) {' 2
mutate envscan-dotenv-quote-without-equals-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'return !bytes.ContainsAny(line, quoteChars)' 'return true'
mutate envscan-dotenv-quoted-key-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'if bytes.ContainsAny(line[:eq], quoteChars) {' 'if false {'
mutate envscan-dotenv-unclosed-quote-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'if end < 0 {' 'if false {' 3
mutate envscan-dotenv-text-after-quote-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'return len(rest) == 0 ||' 'return true ||' 2
mutate envscan-dotenv-odd-leading-byte-ok envscan.go TestHermesConfigEntriesThatSpanLinesAreRefused \
	'if line[v] > 0x20 && line[v] < 0x7f {' 'if true {'

# Gaps the independent red-run review found: each protection below stayed
# green with it switched off, or made the test binary crash instead of a test
# fail (TestEnvScanNeverPanics turns those crashes into assertions).
mutate launchd-syntax-error-loops launchd.go TestLaunchdSyntaxErrorInDictRefused \
	'if err != nil {' 'if false {' 1
mutate envfile-field-missing-ok envfile.go TestEnvReadBackRefusesAFileWithoutTheField \
	'return secret.Value{}, writeFailed("field %q not found in written env-file", t.Field)' 'return secret.Value{}, nil'
# Two layers refuse an unusable key (before the write, and where the
# fingerprint is computed after it): the late one is proven with the early one off.
mutateN write-fingerprint-error-ok TestWriteFailsWhenTheFingerprintCannotBeComputed \
	write.go 'computeFingerprint(fpKey, secret.New([]byte{0})); err != nil {' 'computeFingerprint(fpKey, secret.New([]byte{0})); err != nil && false {' \
	write.go 'return "", unconfirmed("compute fingerprint: %v", err)' 'return "", nil'
mutate scan-export-bound envscan.go TestEnvScanNeverPanics \
	'&& i+len(shellExport) < len(line) &&' '&&'
mutate scan-name-bound envscan.go TestEnvScanNeverPanics \
	'j >= len(line) || ' ''
mutate scan-backslash-bound envscan.go TestEnvScanNeverPanics \
	'k+1 >= len(line) || ' ''
mutate scan-assigns-export-bound envscan.go TestEnvScanNeverPanics \
	'len(l) > len(shellExport) && ' ''
mutate scan-assigns-prefix-bound envscan.go TestEnvScanNeverPanics \
	'if !bytes.HasPrefix(l, []byte(field)) {' 'if false {'
mutate scan-shell-blank-bound envscan.go TestEnvScanNeverPanics \
	'i >= len(line) || ' '' 1
mutate scan-dotenv-blank-bound envscan.go TestEnvScanNeverPanics \
	'i >= len(line) || ' '' 2
mutate scan-dotenv-value-bound envscan.go TestEnvScanNeverPanics \
	'if v >= len(line) {' 'if false {'
mutate scan-dotenv-rest-bound envscan.go TestEnvScanNeverPanics \
	'len(rest) == 0 || ' '' 1
mutate scan-dotenv-rest-bound-2 envscan.go TestEnvScanNeverPanics \
	'len(rest) == 0 || ' '' 2
mutate scan-unquote-bound envfile.go TestEnvScanNeverPanics \
	'if j < 0 {' 'if false {'
mutate scan-export-is-name envscan.go TestEnvNeighboursThatLookLikeOtherEntries \
	'isSpaceTab(l[len(shellExport)])' 'true'
mutate scan-backslash-alone envscan.go TestHermesNeighboursThatOnlyLookRisky \
	'>= 0 && bytes.ContainsAny(line, quoteChars) {' '>= 0 {'
mutate scan-run-not-reset-after-count envscan.go TestHermesNeighboursThatOnlyLookRisky \
	'run = 0' '' 1
mutate scan-run-not-reset-on-other envscan.go TestHermesNeighboursThatOnlyLookRisky \
	'run = 0' '' 2
mutate reach-owner-bits agents.go TestAgentReachRuleIsTheGroupBitsOfTheParentOnly \
	'(mode>>3)&dirReachBits != 0' '(mode>>6)&dirReachBits != 0'
mutate reach-every-ancestor securewrite_unix.go TestAgentReachRuleIsTheGroupBitsOfTheParentOnly \
	'if err := checkDir(fd, seg, ag, isParent); err != nil {' 'if err := checkDir(fd, seg, ag, true); err != nil {'
mutate launchd-end-tag-mismatch launchd.go TestLaunchdMismatchedEndTagInDictRefused \
	'|| stack[n-1] != t.Name.Local' ''
mutate write-fingerprint-key-late write.go TestWriteFailsWhenTheFingerprintCannotBeComputed \
	'computeFingerprint(fpKey, secret.New([]byte{0})); err != nil {' 'computeFingerprint(fpKey, secret.New([]byte{0})); err != nil && false {'
# The confirm phase (everything after Renameat has already published new
# content) reclassifies every failure as ErrUnconfirmed instead of whatever
# class its source would naturally carry: reporting the old class here would
# tell the caller the target was untouched, which by this point is false.
# Each mutant reverts one call site to the old writeFailed wrapping and
# requires the matching test to notice the wrong class, not just a non-nil
# error. The third site (fingerprint.Compute) is only reachable through the
# computeFingerprint test seam - no natural input can make the pre-flight
# call (Write's "fingerprint key is unusable" check, before anything is
# opened) succeed and the confirm-phase call fail with the same key.
mutate unconfirmed-not-readback   write.go TestConfirmPhaseReadBackFailureAfterRenameReturnsErrUnconfirmed \
	'return "", unconfirmed("read back target after write: %v", err)' 'return "", writeFailed("read back target after write: %v", err)'
mutate unconfirmed-not-parse      write.go TestConfirmPhaseParseFailureAfterRenameReturnsErrUnconfirmed \
	'return "", unconfirmed("parse written target: %v", err)' 'return "", writeFailed("parse written target: %v", err)'
mutate unconfirmed-not-fingerprint write.go TestConfirmPhaseFingerprintFailureAfterRenameReturnsErrUnconfirmed \
	'return "", unconfirmed("compute fingerprint: %v", err)' 'return "", writeFailed("compute fingerprint: %v", err)'
mutate launchd-end-tag-stray launchd.go TestLaunchdStrayEndTagRefused \
	'if n == 0 || ' 'if '
mutate existing-fd-no-cloexec securewrite_unix.go TestExistingFDIsCloexec \
	'unix.O_NONBLOCK|unix.O_CLOEXEC, 0)' 'unix.O_NONBLOCK, 0)'
mutate walk-seg-no-cloexec securewrite_unix.go TestDescriptorsAreCloexec \
	'unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)' 'unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)'
mutate tmp-no-cloexec securewrite_unix.go TestDescriptorsAreCloexec \
	'unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)' 'unix.O_NOFOLLOW, 0o600)'
mutate envscan-special-name-zls-colours envscan.go TestShellSpecialNamesAreExactlyThese \
	'	ZLS_COLOURS' '	XZLS_COLOURS'
mutate show-key-unusable guards_test.go TestShowDigestDistinguishesContents \
	'var showKey, _ = fingerprint.GenerateKey("show")' 'var showKey fingerprint.Key'
mutate launchd-only-string-scalars launchd.go TestLaunchdScalarNeighboursKeptByteForByte \
	'var envScalarElements = map[string]bool{"string": true, "integer": true, "real": true, "true": true, "false": true, "data": true, "date": true}' 'var envScalarElements = map[string]bool{"string": true}'

# MR !31 review: the differential shell attack (TestTargetsAttack_EnvFileDifferentialShells)
# had no ratchet of its own — these two switch off the exact properties that
# review found the fuzz's default iteration budget had trouble reaching on its
# own. Needs a real consumer shell to read back what the mutant wrote; without
# one the test itself SKIPs (or FAILs under CI=1) rather than passing, so gate
# the same way the test's own zero-shells path does.
if command -v bash >/dev/null 2>&1 || command -v dash >/dev/null 2>&1 || command -v zsh >/dev/null 2>&1 || command -v ksh >/dev/null 2>&1 || command -v mksh >/dev/null 2>&1; then
	# No quoting at all: a value only round-trips through this package's own
	# readback by chance (the same shellUnquote/shell escaping-rule gap the
	# fuzz's fuzzEscapeAlpha alphabet exists to reach) — a real shell disagrees.
	mutate shellquote-no-quote envfile.go TestTargetsAttack_EnvFileDifferentialShells \
		'func shellQuote(val []byte) []byte {' 'func shellQuote(val []byte) []byte { return append([]byte{}, val...);'
	# existingIsSimple gates what hostile "existing" content the writer will
	# even build against; switching it off (envBuild's call, not envReadBack's)
	# lets a non-entry line stand in for a real one and desyncs what a shell
	# reads from what the package believes it wrote.
	mutate existingissimple-build-accepts-all envfile.go TestTargetsAttack_EnvFileDifferentialShells \
		'if !existingIsSimple(existing, d) {' 'if false {'
else
	echo "skip shellquote-no-quote: no shell here to read back the mutant's output (runs where bash/dash/zsh/ksh/mksh is installed)"
	echo "skip existingissimple-build-accepts-all: no shell here to read back the mutant's output (runs where bash/dash/zsh/ksh/mksh is installed)"
fi

# Orphaned .tmp-* cleanup: the call itself, and each safety condition on what
# it is willing to remove (exact name shape, one link, owned by euid or the
# target's configured owner).
mutate no-stale-tmp-cleanup securewrite_unix.go TestOrphanedTempFileFromCrashedWriteCleanedUpOnNextWrite \
	'cleanupStaleTmp(parentFD, base, uid, time.Now())' '_ = base'
mutate no-owned-stale-tmp-prefix securewrite_unix.go TestIsOwnedStaleTmpSafetyConditions \
	'if !strings.HasPrefix(name, prefix) {' 'if false {'
mutate no-owned-stale-tmp-suffix-len securewrite_unix.go TestIsOwnedStaleTmpSafetyConditions \
	'if len(suffix) != staleTmpSuffixLen {' 'if false {'
mutate no-owned-stale-tmp-hex securewrite_unix.go TestIsOwnedStaleTmpSafetyConditions \
	'if _, err := hex.DecodeString(suffix); err != nil {' 'if false {'
mutate no-owned-stale-tmp-nlink securewrite_unix.go TestIsOwnedStaleTmpSafetyConditions \
	'st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && slices.Contains(owners, int64(st.Uid))' 'st.Mode&unix.S_IFMT == unix.S_IFREG && slices.Contains(owners, int64(st.Uid))'
mutate no-owned-stale-tmp-owner securewrite_unix.go TestIsOwnedStaleTmpSafetyConditions \
	'st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && slices.Contains(owners, int64(st.Uid))' 'st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1'
# owners holds both euid and the target's configured uid — a root runner's
# orphan can belong to either depending on whether the crash landed before or
# after the temp file's Fchown. Checking only owners[0] would silently stop
# cleaning up orphans owned by the target uid; the "matches the target
# owner's orphan" subtest is what catches that regression.
mutate no-owned-stale-tmp-owner-list-full securewrite_unix.go TestIsOwnedStaleTmpSafetyConditions \
	'st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && slices.Contains(owners, int64(st.Uid))' 'st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && int64(st.Uid) == owners[0]'

# Stale .tmp-*: only files last modified no later than the start of the write
# go, and the canary a killed write left in one does not outlive the next write.
mutate stale-tmp-any-age securewrite_unix.go TestStaleTmpNewerThanTheWriteIsKept \
	'return !statMtime(st).After(t)' 'return !statMtime(st).After(t.Add(100*24*time.Hour))'
mutate stale-tmp-block-on-fifo securewrite_unix.go TestStaleTmpSwappedForFIFODoesNotBlock \
	'beforeStaleUnlink(parentFD, name)' 'beforeStaleUnlink(parentFD, name)\n\t\t\tif fd, err := unix.Openat(parentFD, name, unix.O_RDONLY, 0); err == nil {\n\t\t\t\t_ = unix.Close(fd)\n\t\t\t}'
mutate stale-tmp-owners-target-uid securewrite_unix.go TestStaleTmpOwnersIncludeTargetOwner \
	'return []int64{int64(unix.Geteuid()), uid}' 'return []int64{int64(unix.Geteuid())}'
mutate stale-tmp-canary-kept securewrite_unix.go TestStaleTmpWithValueGoneAfterNextWrite \
	'cleanupStaleTmp(parentFD, base, uid, time.Now())' '_ = base'

# ACL on every ancestor: the check runs on the filesystem root and on each
# directory above the parent, not on the parent alone.
mutate ancestor-acl-root-skipped securewrite_unix.go TestWalkChecksACLOnEveryAncestor \
	'aclCheck := checkAncestorACLHook' 'aclCheck := func(int, string) error { return nil }' 1
mutate ancestor-acl-loop-skipped securewrite_unix.go TestWalkChecksACLOnEveryAncestor \
	'aclCheck := checkAncestorACLHook' 'aclCheck := func(int, string) error { return nil }' 2
if linux_only linux-acl-ancestor; then
	mutate linux-ancestor-acl-ignored acl_linux.go TestAncestorACLGrantingWriteRefused \
		'if grantee != "" {' 'if false {'
	mutate linux-ancestor-acl-no-group acl_linux.go TestACLWriteGranteeExemptions \
		'e.tag == aclTagGroup && e.id != 0' 'false'
	mutate linux-ancestor-acl-no-user acl_linux.go TestACLWriteGranteeExemptions \
		'e.tag == aclTagUser && e.id != 0 && e.id != owner' 'false'
	mutate linux-ancestor-acl-no-mask acl_linux.go TestACLWriteGranteeExemptions \
		'if e.perm&mask&aclPermWrite == 0 {' 'if e.perm&(mask|0x07)&aclPermWrite == 0 {'
	mutate linux-ancestor-acl-root-user acl_linux.go TestACLWriteGranteeExemptions \
		'e.tag == aclTagUser && e.id != 0 && e.id != owner' 'e.tag == aclTagUser && e.id != owner'
	mutate linux-ancestor-acl-owner-user acl_linux.go TestACLWriteGranteeExemptions \
		'e.tag == aclTagUser && e.id != 0 && e.id != owner' 'e.tag == aclTagUser && e.id != 0'
	mutate linux-ancestor-acl-root-group acl_linux.go TestACLWriteGranteeExemptions \
		'e.tag == aclTagGroup && e.id != 0' 'e.tag == aclTagGroup'
	mutate linux-ancestor-acl-reads-default acl_linux.go TestAncestorACLGrantingWriteRefused \
		'n, err := unix.Fgetxattr(fd, xattrACLAccess, nil)' 'n, err := unix.Fgetxattr(fd, xattrACLDefault, nil)'
	mutate linux-ancestor-acl-version acl_linux.go TestAncestorACLMalformedRefused \
		'binary.LittleEndian.Uint32(buf) != aclXattrVersion' 'false'
	mutate linux-ancestor-acl-torn acl_linux.go TestAncestorACLMalformedRefused \
		'(len(buf)-4)%8 != 0' 'false'
fi
if darwin_only darwin-acl-ancestor; then
	mutate darwin-ancestor-acl-ignored acl_darwin.go TestAncestorACLGrantingWriteRefused \
		'if ancestorWritePerms[strings.TrimSpace(perm)] {' 'if false \&\& ancestorWritePerms[strings.TrimSpace(perm)] {'
	mutate darwin-ancestor-acl-add-file acl_darwin.go TestAncestorACLGrantingWriteRefused \
		'"add_file": true, ' ''
	mutate darwin-ancestor-acl-writesecurity acl_darwin.go TestAncestorACLGrantingWriteRefused \
		'"writesecurity": true, ' ''
	mutate darwin-ancestor-acl-add-subdirectory acl_darwin.go TestAncestorACLGrantingWriteRefused \
		'"add_subdirectory": true, ' ''
	mutate darwin-ancestor-acl-delete acl_darwin.go TestAncestorACLGrantingWriteRefused \
		'"delete": true, ' ''
	mutate darwin-ancestor-acl-delete-child acl_darwin.go TestAncestorACLGrantingWriteRefused \
		'"delete_child": true,' ''
	mutate darwin-ancestor-acl-chown acl_darwin.go TestAncestorACLGrantingWriteRefused \
		'"chown": true,' ''
	mutate darwin-ancestor-acl-root acl_darwin.go TestAncestorACLForRootAllowed \
		'strings.TrimSpace(e[:i]) == "user:root"' 'false'
	mutate darwin-ancestor-acl-deny acl_darwin.go TestAncestorACLNotGrantingWriteAllowed \
		'i := strings.LastIndex(e, " allow ")' 'e = strings.Replace(e, " deny ", " allow ", 1)\n\ti := strings.LastIndex(e, " allow ")'
fi

# systemd-credential without systemd-creds: refused unless the host policy
# flag arrived, and the notice fires when the fallback is used.
mutate cred-fallback-without-flag systemdcred.go TestSystemdCredentialWithoutBinaryRefusedByDefault \
	'if !h.plaintextFallback {' 'if false {'
mutate cred-fallback-flag-not-wired write.go TestSystemdCredentialPlaintextFallbackWithFlag \
	'plaintextFallback: o.credPlaintext,' 'plaintextFallback: false,'
mutate cred-fallback-no-notice write.go TestSystemdCredentialPlaintextFallbackWithFlag \
	'if fellBack && o.credNotice != nil {' 'if false {'
mutate cred-fallback-notice-before-write write.go TestSystemdCredentialFallbackNoticeOnlyAfterWrite \
	'mode := t.Mode' 'if fellBack \&\& o.credNotice != nil {\n\t\to.credNotice(t.Path)\n\t}\n\tmode := t.Mode'
mutate cred-fallback-mode-from-target write.go TestSystemdCredentialFallbackModeNeverWiderThan0600 \
	'		mode = 0o600' '		mode = t.Mode'
mutate cred-fallback-excuses-untrusted systemdcred.go TestSystemdCredentialFlagDoesNotExcuseUntrustedBinary \
	'path, present, err := findSystemdCreds()' 'path, present, err := findSystemdCreds()\n\tif err != nil \&\& h.plaintextFallback {\n\t\tpresent, err = false, nil\n\t}' 1

# jsonQuoteBytes builds the secret's JSON string literal straight from its
# []byte; these two mutants each switch off one class of required escaping.
mutate no-json-quote-control jsonpath.go TestJSONQuoteBytesMatchesStandardLibraryStringEncoding \
	'case c < 0x20:' 'case false:'
mutate no-json-quote-quote-backslash jsonpath.go TestJSONQuoteBytesMatchesStandardLibraryStringEncoding \
	"case c == '\"' || c == '\\\\\\\\':" 'case false:'

# build owns three JSON-quoted copies of the value (quoted, compact,
# indented) and wipes each; dropping any one wipe call is exactly the
# regression this fix closed.
mutate no-wipe-quoted jsonpath.go TestBuildWipesIntermediateJSONBuffers \
	'	defer wipe(quoted)' ''
mutate no-wipe-compact jsonpath.go TestBuildWipesIntermediateJSONBuffers \
	'	defer wipe(compact)' ''
mutate no-wipe-indented jsonpath.go TestBuildWipesIntermediateJSONBuffers \
	'	defer wipe(indented)' ''

# runPiped reads decrypt's plaintext stdout into three kinds of copy it owns:
# the read chunk, each abandoned growth step, and the whole partial output
# when the child fails. Dropping any one wipe is the regression this closed.
mutate no-wipe-piped-chunk systemdcred.go TestRunPipedWipesReadChunk \
	'	defer wipe(chunk)' ''
mutate no-wipe-piped-growth systemdcred.go TestRunPipedWipesPartialStdoutOnFailure \
	'wipe(out[:cap(out)]) // abandoned step' ''
mutate no-wipe-piped-error systemdcred.go TestRunPipedWipesPartialStdoutOnFailure \
	'wipe(out[:cap(out)]) // failed run' ''

# readBack owns the slice runPiped returns on success and wipes it once
# secret.New has copied it.
mutate no-wipe-readback-out systemdcred.go TestSystemdReadBackWipesDecryptedOutput \
	'defer wipe(out)' ''

# build reserves the exact bytes json.Indent will add, measured up front with
# a placeholder standing in for the real value, instead of the naive
# 2*len(compact) guess that used to leave an array-heavy document's real
# indentation overhead unreserved — which json.Indent's own internal growth
# would then silently paper over by reallocating past it, abandoning an
# unwiped copy of the document along the way. Forcing the measurement to 0
# reproduces exactly that: the reservation falls back to the naive guess,
# too small for TestBuildIndentReservationHoldsForArrayHeavyDocument's
# document, so build's own fail-closed check (below) catches the shortfall
# and returns an error instead of succeeding from a run that would have
# leaked a copy.
mutate no-overhead-measurement jsonpath.go TestBuildIndentReservationHoldsForArrayHeavyDocument \
	'overhead := measureBuf.Len() - len(measureCompact)' 'overhead := 0'
# json.Indent grows its destination to at least 2*len(compact) internally,
# regardless of what build already reserved — so for an ordinary, not
# array-heavy document, where that 2x floor is already enough, skipping it
# here would leave build's own (tighter, exactly-measured) reservation
# short of what Indent asks for on its own, triggering a reallocation before
# any content is written. Harmless in itself, but it defeats the fail-closed
# check's own assumption that nothing changes buf's capacity once reserved,
# so build's check misreads it as this fix's very regression and refuses a
# write that was never actually at risk.
mutate no-naive-floor jsonpath.go TestMCPConfigSetsDottedPathCreatesMissingObjects \
	'if naive := 2*len(compact) + 1; naive > reserve {' 'if naive := 2*len(compact) + 1; false {'

# The fail-closed check itself: if json.Indent reallocates its destination
# anyway (the measurement above is meant to make this unreachable), build
# must refuse rather than hand back content from a run that already
# abandoned an unwiped copy. Dropping the check (kept compiling with a
# blank `_ = reservedCap`) reproduces exactly that regression, letting a
# forced-undersized reservation (via the reserveJSONIndentBuf seam) succeed
# silently instead.
mutate no-reservation-failclosed jsonpath.go TestBuildFailsClosedWhenIndentReservationTooSmall \
	'if buf.Cap() != reservedCap {' 'if _ = reservedCap; false {'

# Verify (read-only "does this carrier hold exactly this key"): the verdict
# is a status only. Each mutation below puts back one way it could fail.
# A value or a neighbouring secret in an error text:
mutate verify-leak-value-in-error verify.go TestVerifyErrorsNeverLeak \
	'writeFailed("JSON field is not a string")' 'writeFailed("JSON field is not a string %v", cur)'
mutate verify-leak-neighbour-in-error verify.go TestVerifyErrorsNeverLeak \
	'writeFailed("selector matches more than one element")' 'writeFailed("selector matches more than one element %v", hit)'
mutate verify-leak-env-line-in-error verify.go TestVerifyErrorsNeverLeak \
	'writeFailed("carrier has an unterminated quote on the assignment")' 'writeFailed("carrier has an unterminated quote on the assignment %s", raw)'
# The verdict itself:
mutate verify-always-match verify.go TestVerifyMatchAndMismatchNeverLeak \
	'subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1' 'subtle.ConstantTimeCompare([]byte(got), []byte(want)) >= 0'
mutate verify-never-match verify.go TestVerifyMatchAndMismatchNeverLeak \
	'subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1' 'subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 2'
mutate verify-malformed-fingerprint-accepted verify.go TestVerifyErrorsNeverLeak \
	'if !fingerprint.Valid(want) {' 'if false {'
# Selection of the one field:
mutate verify-element-select-inverted verify.go TestVerifyMatchAndMismatchNeverLeak \
	'name == s.matchVal' 'name != s.matchVal'
mutate verify-ambiguous-picks-one verify.go TestVerifyErrorsNeverLeak \
	'switch n {' 'switch 1 {'
mutate verify-no-element-is-error verify.go TestVerifyAbsentAndRefusals \
	'case 0:' 'case 7:'
mutate verify-env-prefix-match verify.go TestVerifyRefusesNonRegularAndReadsLastAssignment \
	'bytes.CutPrefix(l, []byte(name+"="))' 'bytes.CutPrefix(l, []byte(name))'
# Opening the file:
mutate verify-follows-symlink verify.go TestVerifyAbsentAndRefusals \
	'unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)' 'unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)'
mutate verify-reads-non-regular verify.go TestVerifyFIFODoesNotHang \
	'if st.Mode&unix.S_IFMT != unix.S_IFREG {' 'if false {'
mutate verify-relative-path-accepted verify.go TestVerifyAbsentAndRefusals \
	'if !path.IsAbs(spec.Path) ||' 'if false && !path.IsAbs(spec.Path) ||'
# What it read is wiped, not left for the collector:
mutate verify-no-wipe-value verify.go TestVerifyWipesWhatItRead \
	'defer wipe(val)' 'defer func() {}()'
mutate verify-no-wipe-file verify.go TestVerifyWipesWhatItRead \
	'defer wipe(content)' 'defer func() {}()'
mutate verify-no-wipe-secret-copy verify.go TestVerifyWipesTheSecretCopy \
	'defer sv.Wipe()' 'defer func() {}()'
mutate verify-blocks-on-fifo verify.go TestVerifyFIFODoesNotHang \
	'unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)' 'unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)'
mutate verify-expands-dollar verify.go TestVerifyEnvSyntaxTable \
	"case '\$', " "case 'Z', "
mutate verify-expands-paren verify.go TestVerifyEnvSyntaxTable \
	"'(', ')'," "'Z', ')',"
mutate verify-expands-in-double-quotes verify.go TestVerifyEnvSyntaxTable \
	"if c == '\"' && bytes.ContainsAny(" "if false && bytes.ContainsAny("
mutate verify-export-space-only verify.go TestVerifyEnvSyntaxTable \
	"(rest[0] == ' ' ||" "(false && rest[0] == ' ' ||"
mutate verify-selector-lax-pair verify.go TestVerifySelectorTableAndLimits \
	'if !ok || k == "" || v == "" ||' 'if !ok || false ||'
mutate verify-selector-unclosed verify.go TestVerifySelectorTableAndLimits \
	'if !strings.HasSuffix(seg, "]") {' 'if false {'
mutate verify-selector-empty-key verify.go TestVerifySelectorTableAndLimits \
	'if s.key == "" {' 'if false {'
mutate verify-missing-key-is-error verify.go TestVerifySelectorTableAndLimits \
	'if !present {' 'if false && !present {'

mutate verify-leak-string-in-walk-error verify.go TestVerifyNeighbourBranchesNeverLeak \
	'writeFailed("JSON on the way to the field is not an object")' 'writeFailed("JSON on the way to the field is not an object %v", cur)'
mutate verify-leak-in-not-array-error verify.go TestVerifyNeighbourBranchesNeverLeak \
	'writeFailed("JSON member of the field path is not an array")' 'writeFailed("JSON member of the field path is not an array %v", next)'
mutate verify-leak-value-in-fingerprint-error verify.go TestVerifyNeighbourBranchesNeverLeak \
	'writeFailed("compute fingerprint: %v", err)' 'writeFailed("compute fingerprint: %v %s", err, val)'
mutate verify-json-offset-in-error verify.go TestVerifyNeighbourBranchesNeverLeak \
	'return nil, false, writeFailed("carrier is not a valid JSON object")' 'return nil, false, err'

# VerifyCarrier takes only carriers of the closed meshkey manifest; anything
# else is refused before a file is opened, without echoing the input:
mutate verify-manifest-gate-off verify.go TestVerifyCarrierAcceptsOnlyManifestCarriers \
	'if !c.Member() {' 'if false {'
mutate verify-manifest-refusal-echoes-path verify.go TestVerifyCarrierAcceptsOnlyManifestCarriers \
	'denied("carrier is not in the Mesh agent key manifest")' 'denied("carrier %q is not in the Mesh agent key manifest", c.Path)'
mutate verify-manifest-refusal-echoes-field verify.go TestVerifyCarrierAcceptsOnlyManifestCarriers \
	'denied("carrier is not in the Mesh agent key manifest")' 'denied("carrier is not in the Mesh agent key manifest: field %q", c.Field)'

# Carriers are read only under the runner's configured roots, checked before
# any open; errors name kind and ordinal, never the locator:
# The prefix test and the clean-component test in descend each refuse a path
# outside the roots, so each mutant switches both off: either alone is covered
# by the other, both together must turn the named test red.
mutate2 verify-roots-off TestVerifyCarrierOutsideRootsOpensNothing \
	verify.go 'if !strings.HasPrefix(c.Path, r+"/") {' 'if false {' \
	verify.go 'return comp != "" && comp != "." && comp != ".."' 'return true'
mutate verify-descend-follows-links verify.go TestVerifyCarrierOutsideRootsOpensNothing \
	'unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC' 'unix.O_DIRECTORY | unix.O_CLOEXEC'
mutate verify-final-symlink-check-off verify.go TestVerifyCarrierOutsideRootsOpensNothing \
	'if st.Mode&unix.S_IFMT == unix.S_IFLNK {' 'if false {'
mutate verify-open-by-path-after-check verify.go TestVerifyCarrierSwapAfterCheckStaysInRoot \
	'return verifyIn(dirfd, base,' '_ = base; return verifyIn(unix.AT_FDCWD, c.Path,'
mutate verify-root-resolving-to-slash verify.go TestVerifyCarrierLinksBelowTheRootNeverAnswerAbsent \
	'if rerr != nil || realRoot == "/" {' 'if rerr != nil {'
mutate verify-link-below-root-is-not-a-refusal verify.go TestVerifyCarrierLinksBelowTheRootNeverAnswerAbsent \
	'case errors.Is(oerr, unix.ELOOP), errors.Is(oerr, unix.ENOTDIR):' 'case false:'
mutate2 verify-root-prefix-without-separator TestVerifyCarrierSiblingWithTheSamePrefixIsOutside \
	verify.go 'if !strings.HasPrefix(c.Path, r+"/") {' 'if !strings.HasPrefix(c.Path, r) {' \
	verify.go 'return comp != "" && comp != "." && comp != ".."' 'return true'
mutate verify-descend-allows-dotdot verify.go TestDescendRefusesNonCleanComponents \
	'return comp != "" && comp != "." && comp != ".."' 'return true'
# A neighbour variable of the env file and a hard link to a file outside the
# root must not be answered:
mutate verify-env-any-variable ../carriers/meshkey/meshkey.go TestVerifyCarrierRefusesForeignEnvVariable \
	'strings.HasSuffix(base, ".env") && c.Field == DefaultEnvVar' 'strings.HasSuffix(base, ".env")'
mutate verify-hardlink-not-refused verify.go TestVerifyCarrierHardLinkIsRefused \
	'if st.Nlink != 1 {' 'if false {'
mutate verify-empty-roots-allow-all verify.go TestVerifyCarrierEmptyRootsRefuseEverything \
	'return -1, "", false, denied("no carrier root is configured")' 'return -1, "", true, nil'
mutate verify-agent-env-subdir-allowed verify.go TestVerifyCarrierAgentEnvSitsDirectlyInARoot \
	'if c.Kind == meshkey.AgentEnv && strings.Contains(rel, "/") {' 'if false {'
mutate verify-error-echoes-path verify.go TestVerifyCarrierErrorsNameKindAndOrdinalOnly \
	'fmt.Errorf("%w [carrier %s #%d]", err, carrierKind(c), ordinal)' 'fmt.Errorf("%w [carrier %s #%d %s]", err, carrierKind(c), ordinal, c.Path)'
mutate verify-error-echoes-field verify.go TestVerifySpecErrorsCarryNoLocator \
	'writeFailed("JSON field is not a string")' 'writeFailed("JSON field %q is not a string", field)'
mutate verify-error-echoes-path-in-read verify.go TestVerifySpecErrorsCarryNoLocator \
	'denied("carrier is a symlink")' 'denied("carrier %q is a symlink", p)' 2
mutate verify-error-without-ordinal verify.go TestVerifyCarrierErrorsNameKindAndOrdinalOnly \
	'carrierKind(c), ordinal)' 'carrierKind(c), 0)'
mutate verify-error-echoes-foreign-kind verify.go TestVerifyCarrierErrorsNameKindAndOrdinalOnly \
	'if c.Member() {' 'if true {'
mutate observe-systemd-credential observe.go TestObserveRefusesAnAgentOwnedCarrierAndAnUnverifiableKind \
	'if t.Kind == runnerproto.TargetSystemdCredential {' 'if false {'
mutate observe-owner-follows-symlink observe.go TestOwnerOfDoesNotFollowASymlinkAndSaysAbsentForAMissingFile \
	'unix.O_RDONLY|unix.O_NOFOLLOW|' 'unix.O_RDONLY|'
mutate observe-owner-regular-only observe.go TestOwnerOfRefusesANonRegularCarrier \
	'if st.Mode&unix.S_IFMT != unix.S_IFREG {' 'if false {'
mutate observe-owner-writable observe.go TestOwnerOfRefusesWhatAnAgentCanWriteBeforeAnythingIsRead \
	'if err := ag.refuseWritableFile("target", &st); err != nil {' 'if err := ag.refuseWritableFile("target", &st); err != nil && false {'
mutate observe-owner-links observe.go TestOwnerOfRefusesAHardLinkedCarrier \
	'if st.Nlink != 1 {' 'if st.Nlink != 1 && false {'
mutate observe-compare-always-equal observe.go TestObserveReportsOnlyTheFingerprintOfWhatTheCarrierHolds \
	'ConstantTimeCompare([]byte(a), []byte(b)) == 1' 'ConstantTimeCompare([]byte(a), []byte(b)) >= 0'

mutation_shard_finish
exit $fail
