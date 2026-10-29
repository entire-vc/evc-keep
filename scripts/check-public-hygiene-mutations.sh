#!/bin/sh
# Proves scripts/check-public-hygiene.sh can fail: in a scratch git copy of
# the tree, plant each kind of violation and require the check to reject
# it; plant each permitted form and require it to pass. The tree as it is
# must pass first — a baseline that is already red proves nothing.
set -eu

# Every probe runs in its own scratch repository, so a commit range from
# the caller (CI exports one for the real MR) means nothing there. Probes
# that test the range set their own.
unset HYGIENE_RANGE CI_PIPELINE_SOURCE CI_MERGE_REQUEST_TITLE \
	CI_MERGE_REQUEST_DESCRIPTION CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
# Every probe plants input in a scratch repository; no product source is mutated.
if mutation_apply_only; then
	echo 'ok   apply-only: no source anchors (probes plant inputs in a scratch repo)'
	exit 0
fi

# Private per-run build cache: on a shared host running several
# clones' go test/build concurrently, a shared $GOCACHE can serve one
# process a build-cache entry another process is evicting mid-write,
# producing a spurious build failure unrelated to any code change
# (seen as "could not import internal/chacha8rand ... no such file").
# Scoping the cache to each run removes the sharing, not just the
# symptom. Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
check="$root/scripts/check-public-hygiene.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace

# Cyrillic "privet" as octal UTF-8 bytes, so this file stays ASCII.
cyr=$(printf '\320\277\321\200\320\270\320\262\320\265\321\202')
wave="W$(printf '1.2')"
# Code points outside U+0400..U+04FF, as UTF-8 bytes; each pair is the first
# and last code point of a block the check must cover, then the code point
# just past the block, which it must not.
u0500=$(printf '\324\200') u052f=$(printf '\324\257') u0530=$(printf '\324\260')
u1c80=$(printf '\341\262\200') u1c8f=$(printf '\341\262\217') u1c90=$(printf '\341\262\220')
u2de0=$(printf '\342\267\240') u2dff=$(printf '\342\267\277') u2e00=$(printf '\342\270\200')
ua640=$(printf '\352\231\200') ua69f=$(printf '\352\232\237') ua6a0=$(printf '\352\232\240')

fresh() {
	# `git commit` can fork a detached `git gc --auto` (gc.autoDetach) that
	# keeps writing into .git/objects after this call returns. The NEXT
	# fresh() then races that background writer while trying to remove the
	# same tree, and BusyBox `rm -rf` (CI image golang:1.25-alpine) aborts
	# with "Directory not empty" instead of retrying — seen live in CI job
	# 98319 (MR !48, pipeline #6334), right between two `expect` results,
	# not merely at final cleanup. `-c gc.auto=0` on every commit below
	# removes the writer; `2>/dev/null || true` plus `mkdir -p` make this
	# call harmless even if some other process still wins the race — a
	# leftover loose object from the previous throwaway repo does not
	# change what the next commit's tree/check outcome will be.
	rm -rf "$work/tree" 2>/dev/null || true
	mkdir -p "$work/tree"
	(cd "$root" && git ls-files -z | xargs -0 tar cf -) | (cd "$work/tree" && tar xf -)
	(cd "$work/tree" && git init -q && git add -A &&
		git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -qm base)
}

fail=0
# expect NAME WANT(pass|fail) FILE LINE: append LINE to FILE, commit, run.
expect() {
	name=$1 want=$2 file=$3 line=$4
	fresh
	mkdir -p "$work/tree/$(dirname "$file")"
	printf '%s\n' "$line" >>"$work/tree/$file"
	(cd "$work/tree" && git add -A &&
		git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -qm probe)
	if "$check" "$work/tree" >"$work/out" 2>&1; then got=pass; else got=fail; fi
	if [ "$got" = "$want" ]; then
		echo "ok   $name: $got"
	else
		echo "FAIL $name: want $want, got $got"
		sed 's/^/  /' "$work/out"
		fail=1
	fi
}

fresh
if "$check" "$work/tree" >"$work/out" 2>&1; then
	echo "ok   baseline: current tree passes"
else
	echo "FAIL baseline: current tree is already red"
	sed 's/^/  /' "$work/out"
	exit 1
fi

expect "Cyrillic in a Go comment" fail pkg/secret/zz_probe.go "// $cyr"
expect "Cyrillic in an error message" fail internal/api/zz_probe.go "var errProbe = errors.New(\"$cyr\")"
expect "Cyrillic in CI config" fail .gitlab-ci.yml "# $cyr"
expect "wave label in a comment" fail internal/store/zz_probe.go "// see $wave"
expect "wave label in a test name" fail test/security/zz_probe_test.go "func Test${wave%%.*}_2(t *testing.T) { t.Log(\"$wave\") }"
expect "Cyrillic under docs/ is allowed" pass docs/zz_probe.md "$cyr"
expect "explicit per-line exception" pass pkg/secret/zz_probe.go "// $cyr public-hygiene:allow homoglyph fixture"
expect "Latin lookalike W12 without a dot" pass pkg/secret/zz_probe.go "// W12 and AW1.2x"

# Cyrillic above U+04FF.
expect "Cyrillic Supplement first (U+0500)" fail pkg/secret/zz_probe.go "// $u0500"
expect "Cyrillic Supplement last (U+052F)" fail pkg/secret/zz_probe.go "// $u052f"
expect "Armenian just past it (U+0530) is allowed" pass pkg/secret/zz_probe.go "// $u0530"
expect "Cyrillic Extended-C first (U+1C80)" fail pkg/secret/zz_probe.go "// $u1c80"
expect "Cyrillic Extended-C last (U+1C8F)" fail pkg/secret/zz_probe.go "// $u1c8f"
expect "Georgian just past it (U+1C90) is allowed" pass pkg/secret/zz_probe.go "// $u1c90"
expect "Cyrillic Extended-A first (U+2DE0)" fail pkg/secret/zz_probe.go "// $u2de0"
expect "Cyrillic Extended-A last (U+2DFF)" fail pkg/secret/zz_probe.go "// $u2dff"
expect "Supplemental Punctuation just past it (U+2E00) is allowed" pass pkg/secret/zz_probe.go "// $u2e00"
expect "Cyrillic Extended-B first (U+A640)" fail pkg/secret/zz_probe.go "// $ua640"
expect "Cyrillic Extended-B last (U+A69F)" fail pkg/secret/zz_probe.go "// $ua69f"
expect "Bamum just past it (U+A6A0) is allowed" pass pkg/secret/zz_probe.go "// $ua6a0"

# Cyrillic in file names.
expect "Cyrillic in a file name" fail "pkg/secret/$cyr.go" "package secret"
expect "Cyrillic in a directory name" fail "internal/$cyr/x.go" "package x"
expect "Extended Cyrillic in a file name" fail "pkg/secret/$u0500.go" "package secret"
expect "Cyrillic file name under docs/ is allowed" pass "docs/$cyr.md" "text"
expect "marker in the path does not excuse a Cyrillic name" fail "pkg/secret/public-hygiene:allow-$cyr.go" "package secret"

# Wave labels beyond the plain W<n>.<n>.
# (Built from parts so this file does not trip the check it tests.)
w=W
expect "multi-digit wave label" fail pkg/secret/zz_probe.go "// see ${w}12.34"
expect "wave label with an underscore" fail pkg/secret/zz_probe.go "// see ${w}1_2"
expect "wave label after an underscore" fail pkg/secret/zz_probe.go "func Test_${w}1_2(t *testing.T) {}"
expect "wave label after an underscore, no Test prefix" fail pkg/secret/zz_probe.go "var snake_${w}1_2 = 1"
expect "wave label glued to a Benchmark prefix" fail pkg/secret/zz_probe.go "func Benchmark${w}1_2(b *testing.B) {}"
expect "wave label glued to a Fuzz prefix" fail pkg/secret/zz_probe.go "func Fuzz${w}1_2(f *testing.F) {}"
expect "wave label glued to an Example prefix" fail pkg/secret/zz_probe.go "func Example${w}1_2() {}"
expect "wave label glued to a digit is allowed" pass pkg/secret/zz_probe.go "// 1${w}1.2x"
expect "wave label glued to a Test prefix" fail pkg/secret/zz_probe.go "func Test${w}1_2(t *testing.T) {}"
expect "wave label in a string" fail pkg/secret/zz_probe.go "var s = \"$wave\""
expect "W<n>_<n> with a glued capital letter is allowed" pass pkg/secret/zz_probe.go "// A${w}1_2x"

# A marker in the PATH must not excuse Cyrillic in the CONTENT.
expect "marker in the path does not excuse Cyrillic content" fail "pkg/secret/public-hygiene:allow.go" "// $cyr"

# The marker excuses its own line only.
fresh
printf '// %s public-hygiene:allow fixture\n// %s\n' "$cyr" "$cyr" >>"$work/tree/pkg/secret/zz_probe.go"
(cd "$work/tree" && git add -A &&
	git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -qm probe)
if "$check" "$work/tree" >"$work/out" 2>&1; then
	echo "FAIL marker excuses the whole file: second line not caught"
	fail=1
else
	echo "ok   marker excuses its own line only: fail"
fi

# A binary file is not scanned (documented in the check).
fresh
printf 'a\0%s\n' "$cyr" >"$work/tree/pkg/secret/zz_probe.bin"
(cd "$work/tree" && git add -A &&
	git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -qm probe)
if "$check" "$work/tree" >"$work/out" 2>&1; then
	echo "ok   binary file with Cyrillic bytes is not scanned: pass"
else
	echo "FAIL binary file with Cyrillic bytes is not scanned: rejected"
	sed 's/^/  /' "$work/out"
	fail=1
fi

# Commit message range.
fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: $wave follow-up")
if HYGIENE_RANGE=HEAD~1..HEAD "$check" "$work/tree" >"$work/out" 2>&1; then
	echo "FAIL wave label in a commit message: not caught"
	fail=1
else
	echo "ok   wave label in a commit message: fail"
fi

fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: $cyr")
if HYGIENE_RANGE=HEAD~1..HEAD "$check" "$work/tree" >"$work/out" 2>&1; then
	echo "FAIL Cyrillic in a commit message: not caught"
	fail=1
else
	echo "ok   Cyrillic in a commit message: fail"
fi

# Commit message body, not only the subject.
fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: clean subject" -m "details: $cyr")
if HYGIENE_RANGE=HEAD~1..HEAD "$check" "$work/tree" >"$work/out" 2>&1; then
	echo "FAIL Cyrillic in a commit body: not caught"
	fail=1
else
	echo "ok   Cyrillic in a commit body: fail"
fi

fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: clean subject" -m "details: see $wave")
if HYGIENE_RANGE=HEAD~1..HEAD "$check" "$work/tree" >"$work/out" 2>&1; then
	echo "FAIL wave label in a commit body: not caught"
	fail=1
else
	echo "ok   wave label in a commit body: fail"
fi

# Merge-request pipeline: title, description, empty range. Every probe has
# a clean commit in a valid range so only the named input can fail it.
fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: clean subject")
mr() {
	name=$1 want=$2 range=$3 title=$4 desc=$5 trunc=${6:-false}
	if (cd "$work/tree" && CI_PIPELINE_SOURCE=merge_request_event HYGIENE_RANGE=$range \
		CI_MERGE_REQUEST_TITLE=$title CI_MERGE_REQUEST_DESCRIPTION=$desc \
		CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED=$trunc "$check" "$work/tree") >"$work/out" 2>&1; then got=pass; else got=fail; fi
	if [ "$got" = "$want" ]; then
		echo "ok   $name: $got"
	else
		echo "FAIL $name: want $want, got $got"
		sed 's/^/  /' "$work/out"
		fail=1
	fi
}
mr "MR pipeline, clean title and description" pass HEAD~1..HEAD "fix: clean" "Clean text."
mr "MR title with a wave label" fail HEAD~1..HEAD "fix: $wave" "Clean text."
mr "MR title with Cyrillic" fail HEAD~1..HEAD "fix: $cyr" "Clean text."
mr "MR description with a wave label" fail HEAD~1..HEAD "fix: clean" "line one
see $wave"
mr "MR description with Cyrillic" fail HEAD~1..HEAD "fix: clean" "line one
$cyr"
mr "MR description truncated by CI" fail HEAD~1..HEAD "fix: clean" "Clean text." true
# Base missing but the range itself non-empty: HEAD is moved back one commit
# and the range is "..<old head>", which git reads as HEAD..<old head>.
old=$(cd "$work/tree" && git rev-parse HEAD)
(cd "$work/tree" && git checkout -q HEAD~1)
mr "MR pipeline with the range base missing (non-empty range)" fail "..$old" "fix: clean" "Clean text."
(cd "$work/tree" && git checkout -q "$old")
mr "MR pipeline with the range base missing" fail ..HEAD "fix: clean" "Clean text."
mr "MR pipeline with the range head missing" fail HEAD~1.. "fix: clean" "Clean text."
mr "MR pipeline with no range at all" fail "" "fix: clean" "Clean text."
mr "MR pipeline with an empty commit range" fail HEAD..HEAD "fix: clean" "Clean text."
# Outside a merge-request pipeline the old behaviour stays: no range means
# the tree only, and title variables are not looked at.
if (cd "$work/tree" && CI_MERGE_REQUEST_TITLE="fix: $wave" "$check" "$work/tree") >"$work/out" 2>&1; then
	echo "ok   no MR pipeline, no range: tree only: pass"
else
	echo "FAIL no MR pipeline, no range: tree only: rejected"
	sed 's/^/  /' "$work/out"
	fail=1
fi

# A scan that cannot run must not pass: point the check at a directory
# that is not a git repository.
mkdir "$work/not-a-repo"
if "$check" "$work/not-a-repo" >"$work/out" 2>&1; then
	echo "FAIL git grep error: reported as a clean tree"
	fail=1
else
	echo "ok   git grep error: fail"
fi

exit $fail
