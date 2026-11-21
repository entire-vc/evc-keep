#!/bin/sh
# Proves scripts/check-public-hygiene.sh can fail: in a scratch git copy of
# the tree, plant each kind of violation and require the check to reject
# it; plant each permitted form and require it to pass. The tree as it is
# must pass first — a baseline that is already red proves nothing.
set -eu

# Every probe runs in its own scratch repository, so a commit range from
# the caller (CI exports one for the real MR) means nothing there. Probes
# that test the range set their own.
# The merge request API variables go too: no probe may ask the real GitLab
# about a scratch branch (the merged-parent tests bring their own stub).
unset HYGIENE_RANGE CI_PIPELINE_SOURCE CI_MERGE_REQUEST_TITLE \
	CI_MERGE_REQUEST_DESCRIPTION CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED \
	CI_MERGE_REQUEST_SOURCE_BRANCH_NAME PUBLIC_HYGIENE_DENYLIST \
	CI_MERGE_REQUEST_TARGET_BRANCH_NAME CI_MERGE_REQUEST_DIFF_BASE_SHA \
	CI_API_V4_URL CI_PROJECT_ID CI_JOB_TOKEN PUBLIC_HYGIENE_API_TOKEN \
	PUBLIC_HYGIENE_API_TIMEOUT

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
check="$root/scripts/check-public-hygiene.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace

fail=0

# Merged parent of a stacked merge request (check-public-hygiene.sh,
# merged_parent and merge_subject): every guard of the proof is switched off
# in a copy of the check, one at a time, and the selftest
# scripts/test_public_hygiene_merged_parent.py must go red against that copy
# (HYGIENE_CHECK). Each mutant names the tests that witness it. The selftest
# runs whole against the unmutated check first: a red baseline proves
# nothing. In apply-only mode the mutants are only applied, and the rest of
# this suite (probes that plant inputs, not source edits) does not run.
selftest="$root/scripts/test_public_hygiene_merged_parent.py"
mutant="$work/check-mutant.sh"
# pmut NAME TESTS FROM TO [FROM2 TO2]: the check with FROM replaced by TO
# (and then FROM2 by TO2); TESTS (space-separated MergedParent.<test>) must
# fail against it.
pmut() {
	name=$1 pm_tests=$2
	shift 2
	if ! mutation_edit "$check" "$1" "$2" >"$mutant"; then
		fail=1
		return 0
	fi
	if [ $# -ge 4 ]; then
		if ! mutation_edit "$mutant" "$3" "$4" >"$mutant.2"; then
			fail=1
			return 0
		fi
		mv "$mutant.2" "$mutant"
	fi
	mutation_applied "$name" && return 0
	# shellcheck disable=SC2086 # the test list splits on spaces
	if HYGIENE_CHECK=$mutant python3 "$selftest" $pm_tests >"$work/out" 2>&1; then
		echo "FAIL $name: survived ($pm_tests stayed green)"
		sed 's/^/  /' "$work/out" | tail -20
		fail=1
	elif ! tail -n 1 "$work/out" | grep -q -E '^FAILED \(failures=[0-9]+\)$'; then
		# A witness that errors (a broken mutant, a missing tool) proves
		# nothing: only assertion failures count as red.
		echo "FAIL $name: the witness errored instead of failing"
		sed 's/^/  /' "$work/out" | tail -20
		fail=1
	else
		echo "ok   $name: red"
	fi
}

if ! mutation_apply_only; then
	if python3 "$selftest" >"$work/out" 2>&1; then
		echo "ok   merged-parent selftest baseline: green"
	else
		echo "FAIL merged-parent selftest baseline: red on the unmutated check"
		sed 's/^/  /' "$work/out" | tail -40
		exit 1
	fi
fi

T=MergedParent.test_
# Condition 1: one merged merge request of this source branch and target.
pmut parent-state "${T}red_parent_opened ${T}red_parent_closed" \
	'elif .state != "merged" then' 'elif false then'
pmut parent-target "${T}red_parent_targets_another_branch" \
	'elif .target_branch != $target then' 'elif false then'
pmut parent-unique "${T}red_ambiguous_answer" \
	'elif length > 1 then' 'elif false then'
pmut parent-source-branch "${T}red_answer_about_another_branch" \
	'if .source_branch != $ref then' 'if false then'
pmut parent-verdict-accept "${T}red_parent_opened ${T}red_empty_answer" \
	'		mp_reason=${mp_line#no }
		return 1' '		mp_reason=${mp_line#no }
		return 0'
pmut parent-query-state "${T}green_remote_tracking_template" \
	'&state=all&' '&state=merged&'
pmut parent-job-token "${T}green_remote_tracking_template" \
	'		printf '"'"'header = "JOB-TOKEN: %s"\n'"'"' "$CI_JOB_TOKEN"' '		:'
pmut parent-per-page "${T}red_ambiguous_answer ${T}green_remote_tracking_template" \
	'&per_page=100"' '&per_page=1"'
pmut parent-uri-branch "${T}green_branch_name_needing_url_encoding" \
	'source_branch=\($r|@uri)' 'source_branch=\($r)'
pmut parent-uri-project "${T}green_project_path_needing_url_encoding" \
	'projects/\($p|@uri)/' 'projects/\($p)/'
pmut parent-private-token "${T}green_private_token_outside_ci" \
	'PRIVATE-TOKEN: %s' 'X-Token: %s'
pmut parent-sha-format "${T}red_head_not_a_commit_id ${T}red_merge_commit_not_a_commit_id" \
	'def sha: type == "string" and test("^[0-9a-f]{40}([0-9a-f]{24})?$");' 'def sha: type == "string";'
pmut parent-head-sha "${T}red_head_not_a_commit_id" \
	' or (.sha | sha | not)' ''
pmut parent-iid-type "${T}red_iid_a_string" \
	'(.iid | type) != "number" or ' ''
pmut parent-iid-digits "${T}red_iid_not_an_integer" \
	'	"" | *[!0-9]*)' '	"")'
# Condition 2: the parent's merge or squash commit is in the diff base.
pmut parent-base-ancestor "${T}red_merge_and_squash_not_in_base" \
	'if git merge-base --is-ancestor "$mp_c" "$mp_base" 2>/dev/null; then' 'if true; then'
pmut parent-base-verdict "${T}red_merge_and_squash_not_in_base ${T}red_merge_and_squash_unknown" \
	'if [ "$mp_in_base" -ne 1 ]; then' 'if false; then'
pmut parent-base-git-error "${T}red_base_git_error_despite_valid_squash" \
	'if [ "$mp_git" -gt 1 ]; then' 'if false; then'
# Condition 3: the commit is in the parent's head, fetched when missing.
pmut parent-head-ancestor "${T}red_fake_merge_outside_the_parent" \
	'if ! git merge-base --is-ancestor "$mp_commit" "$mp_head" 2>/dev/null; then' 'if false; then'
pmut parent-head-fetch "${T}green_parent_head_fetched_from_merge_request_ref" \
	'git fetch -q --no-tags origin "refs/merge-requests/$mp_i/head"' ':'
pmut parent-fetch-error "${T}red_fetch_error_after_objects_arrive" \
	'if [ "$mp_fetch" -ne 0 ]; then' 'if false; then'
pmut parent-head-missing-accept "${T}red_fetched_ref_does_not_contain_head" \
	'			mp_reason="its head commit is not available"
			return 1' '			mp_reason="its head commit is not available"
			return 0'
# The commit: two or more parents, a merge-request pipeline, the exact template.
pmut parent-two-parents "${T}red_single_parent_with_the_subject" \
	'if [ "$in_mr" -ne 1 ] || [ "$ms_parents" -lt 2 ]; then' 'if [ "$in_mr" -ne 1 ]; then'
pmut parent-mr-pipeline "${T}red_outside_a_merge_request_pipeline" \
	'if [ "$in_mr" -ne 1 ] || [ "$ms_parents" -lt 2 ]; then' 'if [ "$ms_parents" -lt 2 ]; then'
pmut parent-template-anchor "${T}red_text_before_the_template" \
	'	"Merge remote-tracking branch '"'"'origin/main'"'"' into "?*)' \
	'	*"Merge remote-tracking branch '"'"'origin/main'"'"' into "?*)' \
	'ms_ref=${ms_subj#"$ms_pre"}' 'ms_ref=${ms_subj#*"$ms_pre"}'
pmut parent-template-ref "${T}red_text_before_the_branch_name" \
	'ms_ref=${ms_subj#"$ms_pre"}' 'ms_ref=${ms_subj##* }'
pmut source-exact "${T}red_source_template_with_text_after" \
	'if [ "$ms_subj" = "$(printf "$ms_tpl" "$ms_src")" ]; then' \
	'if [ "${ms_subj#"$(printf "$ms_tpl" "$ms_src")"}" != "$ms_subj" ]; then'
# Errors excuse nothing.
pmut parent-request-error-accept "${T}red_api_error ${T}red_api_unreachable ${T}red_api_timeout" \
	'		mp_reason="the merge request lookup failed (curl exit $mp_cs)"
		return 1' '		mp_reason="the merge request lookup failed (curl exit $mp_cs)"
		return 0'
pmut parent-json-error-accept "${T}red_answer_not_json" \
	'		mp_reason="the merge request answer is not JSON"
		return 1' '		mp_reason="the merge request answer is not JSON"
		return 0'
pmut parent-variables-accept "${T}red_without_api_url ${T}red_without_target_branch ${T}red_without_diff_base" \
	'DIFF_BASE_SHA is not set"
		return 1' 'DIFF_BASE_SHA is not set"
		return 0'
# The whole proof, and the report of what it excused.
pmut parent-proof-noop "${T}red_parent_opened ${T}red_fake_merge_outside_the_parent" \
	'if merged_parent "$ms_ref" "$ms_commit"; then' 'if :; then'
pmut parent-report "${T}green_remote_tracking_template" \
	'echo "commit $rm_short: $ms_note" >&2' ':'

if mutation_apply_only; then
	# The probes below plant inputs in a scratch repository; no source edit.
	exit "$fail"
fi

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

# Deny-list probes, and the merge-request probes (a merge-request pipeline
# requires a list), use their own made-up list: a word, and a short word
# that is also the tail of a longer one. They are built from parts so the
# probe list does not flag this file itself.
dw="zebra""quux"
sw="qui""ll"
long="s${sw}"
printf '  %s \r\n\n%s\n\n' "$dw" "$sw" >"$work/deny"
: >"$work/deny-empty"
printf ' \n\r\n\n' >"$work/deny-blank"

fresh() {
	# One copy of the tracked files and one base commit per run; every later
	# call resets the files through the snapshot and the repository by refs,
	# so a probe writes a handful of files instead of a whole repository.
	# `-c gc.auto=0` on every commit: `git commit` can fork a detached
	# `git gc --auto` that keeps writing into .git/objects after it returns
	# (seen live in CI job 98319, MR !48, pipeline #6334).
	mutation_snapshot "$work/tree" tracked
	if [ -z "${fresh_base:-}" ]; then
		(cd "$work/tree" && git init -q && git add -A &&
			git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -qm base)
		fresh_base=$(cd "$work/tree" && git rev-parse HEAD)
		fresh_branch=$(cd "$work/tree" && git symbolic-ref HEAD)
		return 0
	fi
	# Back to the single base commit: drop every ref a probe made (branches,
	# origin/main, a detached HEAD), then the index. Loose objects the probe
	# wrote stay unreachable. A repository that is not back fails the run.
	if ! (cd "$work/tree" &&
		git for-each-ref --format='%(refname)' >"$work/refs" &&
		while IFS= read -r ref; do git update-ref -d "$ref" || exit 1; done <"$work/refs" &&
		git update-ref "$fresh_branch" "$fresh_base" &&
		git symbolic-ref HEAD "$fresh_branch" &&
		git reset -q &&
		[ "$(git for-each-ref --format='%(refname)')" = "$fresh_branch" ] &&
		[ "$(git rev-list --all | wc -l | tr -d ' ')" = 1 ] &&
		[ -z "$(git status --porcelain --untracked-files=all)" ]); then
		echo 'FAIL fresh: the scratch repository did not return to its base commit'
		exit 2
	fi
}

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
# The title becomes the commit subject on main and is checked; the
# description never reaches a commit, so nothing in it (nor its length)
# may fail the job.
fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: clean subject")
mr() {
	name=$1 want=$2 range=$3 title=$4 desc=$5 trunc=${6:-false}
	if (cd "$work/tree" && CI_PIPELINE_SOURCE=merge_request_event HYGIENE_RANGE=$range \
		CI_MERGE_REQUEST_TITLE=$title CI_MERGE_REQUEST_DESCRIPTION=$desc \
		CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED=$trunc PUBLIC_HYGIENE_DENYLIST="$work/deny" \
		"$check" "$work/tree") >"$work/out" 2>&1; then got=pass; else got=fail; fi
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
mr "MR title with Cyrillic, description truncated" fail HEAD~1..HEAD "fix: $cyr" "Clean text." true
mr "MR description with a wave label" pass HEAD~1..HEAD "fix: clean" "line one
see $wave"
mr "MR description with Cyrillic" pass HEAD~1..HEAD "fix: clean" "line one
$cyr"
mr "MR description truncated by CI" pass HEAD~1..HEAD "fix: clean" "Clean text." true
# A description past GitLab's 2700-character cut, holding every kind of
# violation at once: still not checked.
longdesc=$(awk 'BEGIN { for (i = 0; i < 300; i++) printf "clean text "; print "" }')
mr "MR description over 2700 characters with Cyrillic and a wave label" pass HEAD~1..HEAD "fix: clean" "$longdesc
$cyr $wave $dw" true
# The description variable may be absent altogether; the title may not
# (see "aborted run" below).
if (cd "$work/tree" && unset CI_MERGE_REQUEST_DESCRIPTION CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED &&
	CI_PIPELINE_SOURCE=merge_request_event HYGIENE_RANGE=HEAD~1..HEAD \
	CI_MERGE_REQUEST_TITLE="fix: clean" PUBLIC_HYGIENE_DENYLIST="$work/deny" \
	"$check" "$work/tree") >"$work/out" 2>&1; then
	echo "ok   MR pipeline without a description variable: pass"
else
	echo "FAIL MR pipeline without a description variable: want pass, got fail"
	sed 's/^/  /' "$work/out"
	fail=1
fi
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

# Deny-list probes below.
# dexpect NAME WANT FILE LINE: as expect, with the probe deny-list set.
dexpect() {
	name=$1 want=$2 file=$3 line=$4
	fresh
	mkdir -p "$work/tree/$(dirname "$file")"
	printf '%s\n' "$line" >>"$work/tree/$file"
	(cd "$work/tree" && git add -A &&
		git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -qm probe)
	if PUBLIC_HYGIENE_DENYLIST="$dlist" "$check" "$work/tree" >"$work/out" 2>&1; then got=pass; else got=fail; fi
	if [ "$got" = "$want" ]; then
		echo "ok   $name: $got"
	else
		echo "FAIL $name: want $want, got $got"
		sed 's/^/  /' "$work/out"
		fail=1
	fi
}
dlist=$work/deny
fresh
if PUBLIC_HYGIENE_DENYLIST="$work/deny" "$check" "$work/tree" >"$work/out" 2>&1 &&
	grep -q '^deny-list: checking 2 words$' "$work/out"; then
	echo "ok   deny-list baseline: current tree passes, 2 words checked"
else
	echo "FAIL deny-list baseline: current tree rejected or word count wrong"
	sed 's/^/  /' "$work/out"
	fail=1
fi
dexpect "deny-listed word in a Go comment" fail internal/api/zz_probe.go "// owner: $dw"
dexpect "deny-listed word, other case" fail internal/api/zz_probe.go "// owner: Zebra""Quux"
dexpect "deny-listed word glued to punctuation" fail internal/api/zz_probe.go "// see keep-$dw-pg and $dw.env"
dexpect "deny-listed word in CI config" fail .gitlab-ci.yml "# $dw"
dexpect "deny-listed word under docs/" fail docs/zz_probe.md "Ask $dw."
dexpect "deny-listed word in a file name" fail "internal/api/$dw.txt" "text"
dexpect "deny-listed word excused by the marker" pass internal/api/zz_probe.go "// $dw public-hygiene:allow fixture"
dexpect "deny-listed word inside a longer word" pass internal/api/zz_probe.go "// $long: keep [flags]"
dexpect "deny-listed word as an identifier part" pass internal/api/zz_probe.go "var ${dw}_x, x${dw} = 1, 2"
dexpect "short deny-listed word after its longer form" fail internal/api/zz_probe.go "// $long, then $sw"
# The FAIL message names path:line, never the word.
dexpect "hit reported without the word (setup)" fail internal/api/zz_probe.go "// $dw"
if grep -q 'internal/api/zz_probe.go:[0-9]' "$work/out" && ! grep -qi "$dw" "$work/out"; then
	echo "ok   hit reported as path:line without the word"
else
	echo "FAIL hit report: missing path:line or it prints the word"
	sed 's/^/  /' "$work/out"
	fail=1
fi
# The marker excuses its own line only.
fresh
printf '// %s public-hygiene:allow fixture\n// %s\n' "$dw" "$dw" >>"$work/tree/internal/api/zz_probe.go"
(cd "$work/tree" && git add -A &&
	git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -qm probe)
if PUBLIC_HYGIENE_DENYLIST="$work/deny" "$check" "$work/tree" >"$work/out" 2>&1; then
	echo "FAIL deny-list marker excuses the whole file: second line not caught"
	fail=1
else
	echo "ok   deny-list marker excuses its own line only: fail"
fi
# A file name may hold colons and the marker; it excuses nothing, for the
# deny-list and for the Cyrillic rule alike.
cname="internal/api/x:y:public-hygiene:allow.go"
dexpect "deny-listed word in a file named with colons and the marker" fail "$cname" "// $dw"
expect "Cyrillic in a file named with colons and the marker" fail "$cname" "// $cyr"
# File names are matched as whole words and in any case.
dexpect "longer word in a file name" pass "internal/api/$long.txt" "text"
dexpect "deny-listed word in a file name, other case" fail "internal/api/Zebra""Quux.txt" "text"
# List words are fixed strings: a "." in a word is not a wildcard.
printf '%s.%s\n' qu ll >"$work/deny-re"
dlist=$work/deny-re
dexpect "deny-list word with a dot is not a pattern" pass internal/api/zz_probe.go "// $sw"
dlist=$work/deny

# A failing lookup must say so, never read as "no hit": a git wrapper fails
# the one git grep call whose last argument is HYG_FAIL_ARG.
realgit=$(command -v git)
mkdir -p "$work/shim"
{
	echo '#!/bin/sh'
	echo 'last='
	echo 'for a; do last=$a; done'
	echo 'case " $* " in'
	echo '*" grep "*) if [ -n "${HYG_FAIL_ARG:-}" ] && [ "$last" = "$HYG_FAIL_ARG" ]; then exit 2; fi ;;'
	echo '*" log -1 --format=%b "*) if [ "${HYG_FAIL_LOG:-}" = body ]; then exit 2; fi ;;'
	echo '*" log -1 --format=%s "*) if [ "${HYG_FAIL_LOG:-}" = subject ]; then exit 2; fi ;;'
	echo '*" rev-list --parents "*) if [ "${HYG_FAIL_LOG:-}" = parents ]; then exit 2; fi ;;'
	echo '*" rev-list "*) if [ "${HYG_FAIL_LOG:-}" = list ]; then exit 2; fi ;;'
	echo '*" rev-parse --short "*) if [ "${HYG_FAIL_LOG:-}" = short ]; then exit 2; fi ;;'
	echo 'esac'
	printf 'exec "%s" "$@"\n' "$realgit"
} >"$work/shim/git"
chmod +x "$work/shim/git"
gfail() {
	name=$1 arg=$2 want=$3
	if (cd "$work/tree" && PATH="$work/shim:$PATH" HYG_FAIL_ARG=$arg HYGIENE_RANGE=HEAD~1..HEAD \
		PUBLIC_HYGIENE_DENYLIST="$work/deny" "$check" "$work/tree") >"$work/out" 2>&1; then
		echo "FAIL $name: passed"
		sed 's/^/  /' "$work/out"
		fail=1
	elif grep -qF "$want" "$work/out"; then
		echo "ok   $name: fail, says so"
	else
		echo "FAIL $name: the report lacks '$want'"
		sed 's/^/  /' "$work/out"
		fail=1
	fi
}
fresh
printf '// %s\n' "$cyr" >>"$work/tree/internal/api/zz_probe.go"
(cd "$work/tree" && git add -A &&
	git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -qm "fix: probe")
gfail "git grep error in the deny-list tree scan" . "git grep failed"
gfail "git grep error in the deny-list file-name scan" names "git grep failed"
gfail "git grep error in the deny-list commit scan" text "git grep failed"
gfail "git grep error in the report redaction" r "report withheld"
# A commit message git cannot read is a failure, not an empty message:
# the wrapper fails one git call of the commit scan at a time (the commit
# list, a commit's parents, subject, body, short hash), outside a
# merge-request pipeline, where no other range check runs.
fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: clean subject")
for lf in list parents subject body short; do
	if (cd "$work/tree" && PATH="$work/shim:$PATH" HYG_FAIL_LOG=$lf HYGIENE_RANGE=HEAD~1..HEAD \
		PUBLIC_HYGIENE_DENYLIST="$work/deny" "$check" "$work/tree") >"$work/out" 2>&1; then
		echo "FAIL git error in the commit scan ($lf): passed"
		sed 's/^/  /' "$work/out"
		fail=1
	elif grep -qF "git could not read them" "$work/out"; then
		echo "ok   git error in the commit scan ($lf): fail, says so"
	else
		echo "FAIL git error in the commit scan ($lf): the report lacks 'git could not read them'"
		sed 's/^/  /' "$work/out"
		fail=1
	fi
done

# Deny-list in commit messages (subject and body) of HYGIENE_RANGE.
dcommit() {
	name=$1 want=$2
	shift 2
	fresh
	(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty "$@")
	if HYGIENE_RANGE=HEAD~1..HEAD PUBLIC_HYGIENE_DENYLIST="$work/deny" "$check" "$work/tree" >"$work/out" 2>&1; then got=pass; else got=fail; fi
	if [ "$got" = "$want" ]; then
		echo "ok   $name: $got"
	else
		echo "FAIL $name: want $want, got $got"
		sed 's/^/  /' "$work/out"
		fail=1
	fi
}
dcommit "deny-listed word in a commit subject" fail -m "fix: ask $dw"
dcommit "deny-listed word in a commit body" fail -m "fix: clean subject" -m "reviewed by $dw"
dcommit "commit message with only the longer word" pass -m "fix: $long text" -m "clean body"

# Deny-list in a merge-request pipeline: title, description, and the
# variable itself (unset, missing file, empty, blank-only list fail).
fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: clean subject")
dmr() {
	name=$1 want=$2 list=$3 title=$4 desc=$5
	if (cd "$work/tree" && CI_PIPELINE_SOURCE=merge_request_event HYGIENE_RANGE=HEAD~1..HEAD \
		CI_MERGE_REQUEST_TITLE=$title CI_MERGE_REQUEST_DESCRIPTION=$desc \
		CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED=false PUBLIC_HYGIENE_DENYLIST=$list \
		"$check" "$work/tree") >"$work/out" 2>&1; then got=pass; else got=fail; fi
	if [ "$got" = "$want" ]; then
		echo "ok   $name: $got"
	else
		echo "FAIL $name: want $want, got $got"
		sed 's/^/  /' "$work/out"
		fail=1
	fi
}
dmr "MR pipeline with the deny-list, clean" pass "$work/deny" "fix: clean" "Clean text."
dmr "MR title with a deny-listed word" fail "$work/deny" "fix: for $dw" "Clean text."
dmr "MR description with a deny-listed word" pass "$work/deny" "fix: clean" "line one
asked by $dw"
dmr "MR pipeline without the deny-list variable" fail "" "fix: clean" "Clean text."
dmr "MR pipeline with a missing deny-list file" fail "$work/no-such-list" "fix: clean" "Clean text."
dmr "MR pipeline with an empty deny-list" fail "$work/deny-empty" "fix: clean" "Clean text."
dmr "MR pipeline with a blank-only deny-list" fail "$work/deny-blank" "fix: clean" "Clean text."
# No report line of any rule shows a listed word while a list is loaded.
noword() {
	if grep -qi "$dw" "$work/out"; then
		echo "FAIL $1: the report shows the deny-listed word"
		sed 's/^/  /' "$work/out"
		fail=1
	else
		echo "ok   $1: word not in the report"
	fi
}
dexpect "Cyrillic and a deny-listed word on one line" fail internal/api/zz_probe.go "// $cyr $dw"
noword "Cyrillic and a deny-listed word on one line"
dexpect "wave label and a deny-listed word on one line" fail internal/api/zz_probe.go "// $wave $dw"
noword "wave label and a deny-listed word on one line"
dexpect "deny-listed word in a file name (report)" fail "internal/api/$dw.txt" "text"
noword "deny-listed word in a file name"
dexpect "deny-listed word in a Cyrillic file name" fail "internal/api/$cyr-$dw.txt" "text"
noword "deny-listed word in a Cyrillic file name"
dcommit "Cyrillic and a deny-listed word in a commit subject" fail -m "fix: $cyr $dw"
noword "Cyrillic and a deny-listed word in a commit subject"
fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: clean subject")
dmr "wave label and a deny-listed word in the MR title" fail "$work/deny" "fix: $wave $dw" "Clean text."
noword "wave label and a deny-listed word in the MR title"

# Merge commits of main into a branch whose name holds a deny-listed word
# (lane branches do): git's default subject passes in a merge-request
# pipeline when the branch is the MR source branch; every other shape of
# the same text fails. mbranch builds the scratch repository: main, the
# branch "$mb" with one commit, main one commit ahead, origin/main pointing
# at it; HEAD is left on "$mb", before the merge.
mb="$dw/1234abcd-x"
dflt="Merge remote-tracking branch 'origin/main' into $mb"
g() { git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 "$@"; }
mbranch() {
	fresh
	(cd "$work/tree" && git branch -M main && git checkout -q -b "$mb" &&
		g commit -q --allow-empty -m "fix: clean subject" &&
		git checkout -q main && g commit -q --allow-empty -m "fix: main moves" &&
		git update-ref refs/remotes/origin/main main && git checkout -q "$mb")
}
# mrun NAME WANT SOURCE [PIPELINE]: run the check over base..HEAD in a
# merge-request pipeline (or PIPELINE) with CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
# set to SOURCE ("-" leaves it unset).
mrun() {
	name=$1 want=$2 src=$3 pipe=${4:-merge_request_event}
	base=$(cd "$work/tree" && git rev-list --max-parents=0 HEAD)
	if (cd "$work/tree" && if [ "$src" = - ]; then unset CI_MERGE_REQUEST_SOURCE_BRANCH_NAME; else
		CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=$src && export CI_MERGE_REQUEST_SOURCE_BRANCH_NAME; fi &&
		CI_PIPELINE_SOURCE=$pipe HYGIENE_RANGE=$base..HEAD \
		CI_MERGE_REQUEST_TITLE="fix: clean" CI_MERGE_REQUEST_DESCRIPTION="Clean text." \
		CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED=false PUBLIC_HYGIENE_DENYLIST="$work/deny" \
		"$check" "$work/tree") >"$work/out" 2>&1; then got=pass; else got=fail; fi
	if [ "$got" = "$want" ]; then
		echo "ok   $name: $got"
	else
		echo "FAIL $name: want $want, got $got"
		sed 's/^/  /' "$work/out"
		fail=1
	fi
}
mbranch
(cd "$work/tree" && g merge -q --no-edit origin/main)
if [ "$(cd "$work/tree" && git log -1 --format=%s)" = "$dflt" ]; then
	echo "ok   git merge origin/main writes the default subject the check expects"
else
	echo "FAIL git merge origin/main wrote another subject; the probes below test nothing"
	fail=1
fi
mrun "default merge subject into the MR source branch" pass "$mb"
noword "default merge subject into the MR source branch"
# The exemption is never silent: the report names the commit it excused.
mshort=$(cd "$work/tree" && git rev-parse --short HEAD)
if grep -qF "commit $mshort: default merge subject, source branch name not checked" "$work/out"; then
	echo "ok   default merge subject into the MR source branch: exemption reported"
else
	echo "FAIL default merge subject into the MR source branch: exemption not reported"
	sed 's/^/  /' "$work/out"
	fail=1
fi
mrun "default merge subject, source branch unset" fail -
mrun "default merge subject, source branch empty" fail ""
mrun "default merge subject into another branch than the source" fail "other/1234abcd-y"
mrun "default merge subject outside a merge-request pipeline" fail "$mb" push
mbranch
(cd "$work/tree" && g commit -q --allow-empty -m "$dflt")
mrun "default merge subject on a commit that is not a merge" fail "$mb"
mbranch
(cd "$work/tree" && g merge -q --no-edit origin/main && g commit -q --amend -m "$dflt" -m "asked by $dw")
mrun "default merge subject, deny-listed word in the body" fail "$mb"
noword "default merge subject, deny-listed word in the body"
mbranch
(cd "$work/tree" && g merge -q --no-edit origin/main && g commit -q --amend -m "$dflt" -m "see $wave")
mrun "default merge subject, wave label in the body" fail "$mb"
mbranch
(cd "$work/tree" && g merge -q -m "Merge main, asked by $dw" origin/main)
mrun "merge with an authored subject holding a deny-listed word" fail "$mb"
mbranch
(cd "$work/tree" && g merge -q -m "Merge remote-tracking branch 'origin/$dw' into $mb" origin/main)
mrun "merge of another branch named with a deny-listed word" fail "$mb"
mbranch
(cd "$work/tree" && g merge -q -m "$dflt and $dw" origin/main)
mrun "default merge subject with text after the branch" fail "$mb"
mbranch
(cd "$work/tree" && g merge -q -m "Merge branch 'main' of https://example.invalid/keep into $mb" origin/main)
mrun "git pull merge subject" fail "$mb"
mbranch
(cd "$work/tree" && g merge -q -m "Merge branch 'main' into $mb" origin/main)
mrun "merge of local main, default subject" pass "$mb"
mbranch
(cd "$work/tree" && g merge -q -m "Merge branch 'main' into '$mb'" origin/main)
mrun "merge of main, quoted branch (GitLab form)" pass "$mb"
# An empty source branch name excuses nothing, not even the empty name in
# "Merge branch 'main' into ''": the check must not report an exemption.
mbranch
(cd "$work/tree" && g merge -q -m "Merge branch 'main' into ''" origin/main)
mrun "quoted empty branch, source branch empty" pass ""
if grep -q 'source branch name not checked' "$work/out"; then
	echo "FAIL quoted empty branch, source branch empty: reported as an exemption"
	sed 's/^/  /' "$work/out"
	fail=1
else
	echo "ok   quoted empty branch, source branch empty: no exemption reported"
fi
# Neither does the source branch name excuse an ordinary commit carrying it.
mbranch
(cd "$work/tree" && g commit -q --allow-empty -m "fix: work on $mb")
mrun "source branch name in an ordinary commit subject" fail "$mb"

# A run that aborts (here: set -u on a merge-request pipeline whose title
# variable is missing) must exit non-zero, not with the status of its
# cleanup. It runs on a fresh tree with one clean commit and a clean
# description, so nothing but the missing title can fail it; the same call
# with the title set is the positive control, and the abort must name the
# title variable.
fresh
(cd "$work/tree" && git -c user.name=t -c user.email=t@example.invalid -c gc.auto=0 commit -q --allow-empty -m "fix: clean subject")
if (cd "$work/tree" && export CI_MERGE_REQUEST_TITLE="fix: clean" CI_MERGE_REQUEST_DESCRIPTION="Clean text." &&
	CI_PIPELINE_SOURCE=merge_request_event HYGIENE_RANGE=HEAD~1..HEAD \
	PUBLIC_HYGIENE_DENYLIST="$work/deny" "$check" "$work/tree") >"$work/out" 2>&1; then
	echo "ok   aborted run, control with the title set: pass"
else
	echo "FAIL aborted run, control with the title set: want pass, got fail"
	sed 's/^/  /' "$work/out"
	fail=1
fi
if (cd "$work/tree" && unset CI_MERGE_REQUEST_TITLE && export CI_MERGE_REQUEST_DESCRIPTION="Clean text." &&
	CI_PIPELINE_SOURCE=merge_request_event HYGIENE_RANGE=HEAD~1..HEAD \
	PUBLIC_HYGIENE_DENYLIST="$work/deny" "$check" "$work/tree") >"$work/out" 2>&1; then
	echo "FAIL aborted run: exit status 0"
	sed 's/^/  /' "$work/out"
	fail=1
elif ! grep -q 'CI_MERGE_REQUEST_TITLE' "$work/out"; then
	echo "FAIL aborted run: failed, but not on the missing title variable"
	sed 's/^/  /' "$work/out"
	fail=1
else
	echo "ok   aborted run: fail"
fi

# Outside a merge-request pipeline an unset or empty list is a skip, said
# out loud; a set variable naming a missing file is still a failure.
fresh
for l in "" "$work/deny-empty"; do
	if (cd "$work/tree" && PUBLIC_HYGIENE_DENYLIST=$l "$check" "$work/tree") >"$work/out" 2>&1 &&
		grep -q '^deny-list: not configured' "$work/out"; then
		echo "ok   no MR pipeline, deny-list '${l##*/}': skipped out loud: pass"
	else
		echo "FAIL no MR pipeline, deny-list '${l##*/}': not a stated skip"
		sed 's/^/  /' "$work/out"
		fail=1
	fi
done
if (cd "$work/tree" && PUBLIC_HYGIENE_DENYLIST="$work/no-such-list" "$check" "$work/tree") >"$work/out" 2>&1; then
	echo "FAIL no MR pipeline, missing deny-list file: passed"
	fail=1
else
	echo "ok   no MR pipeline, missing deny-list file: fail"
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
