#!/bin/sh
# Public-repo hygiene: this repository is mirrored to a public showcase, so
# code, comments, error messages, scripts and CI config are written in
# English and carry no internal planning labels. Fails on:
#
#   - Cyrillic anywhere in a tracked text file or in a tracked file NAME:
#     U+0400..U+052F, U+1C80..U+1C8F, U+2DE0..U+2DFF, U+A640..U+A69F;
#   - internal wave labels (see "wave" below) in file contents.
#
# What counts as a wave label: the letter W, one or more digits, a "." or
# "_", one or more digits (W<n>.<n>, W<n>_<n>; multi-digit numbers too).
# It must not be glued to a preceding letter or digit, so "AW1.2x" and
# "W12" pass; an underscore or a Test/Benchmark/Fuzz/Example prefix does
# not shield it, so Test_W<n>_<n> and TestW<n>_<n> are caught.
#
# Binary files are not scanned (git grep -I): a tracked binary is not text
# a reader sees in a diff, and random bytes would hit the Cyrillic lead
# bytes by chance.
#
# Not scanned by these two rules: docs/ (translations and quoted sources
# may live there). The deny-list below does scan docs/.
# Per-line exception: put the marker "public-hygiene:allow" on the line
# itself, with a reason next to it; it excuses that line only, never the
# rest of the file, and never a file name. Prefer an escape instead where
# the language has one (a homoglyph test host is "\u0430pi.example.com",
# not the literal character).
#
# With HYGIENE_RANGE=<base>..<head>, commit messages (subject and body)
# in that range are checked by the same rules (CI sets it to the MR diff).
# In a merge-request pipeline (CI_PIPELINE_SOURCE=merge_request_event) the
# MR title is checked too: it becomes the subject of the commit on main
# (the merge commit carries "Merge branch ...", the title and "See merge
# request ..."; a squash commit carries the title) and so reaches the
# public mirror. The MR description is NOT checked: no commit template of
# this project puts it into a commit, so it never reaches main or the
# mirror, and the GitLab project itself is private. Its length (GitLab
# truncates CI_MERGE_REQUEST_DESCRIPTION at 2700 characters) therefore
# does not matter either. If a commit template ever starts to include the
# description, it must be checked here again. In a merge-request pipeline
# an unset, malformed or empty range is a failure, not a pass: a check
# that has nothing to look at must say so. Outside a merge-request pipeline (a push
# to a branch, a local run) there is no base to diff against, so an unset
# range keeps meaning "tree only".
#
# Merge commits: to resolve a conflict with main, run
# `git fetch origin && git merge origin/main` (no rebase, no force-push).
# Its default subject, "Merge remote-tracking branch 'origin/main' into
# <branch>", passes even when the branch name holds a deny-listed word: in
# a merge-request pipeline, for a commit with two or more parents whose
# subject is byte for byte that template (or "Merge branch 'main' into
# <branch>", or the same with <branch> in quotes) and <branch> is
# CI_MERGE_REQUEST_SOURCE_BRANCH_NAME, only that branch name is replaced by
# a placeholder; the rest of the subject and the body are checked by every
# rule. The source branch name is already on main in GitLab's own merge
# commits. A `git pull` subject (" of <url> into ...") is not excused, and
# outside a merge-request pipeline nothing is.
#
# Merged parent of a stacked merge request: a branch started from another
# merge request's branch carries that parent's own merges of main. When the
# parent is squash-merged they are not on main, so they reappear in this
# range, and their default subject names the parent branch. In a
# merge-request pipeline, for a commit with two or more parents whose
# subject is byte for byte one of the three templates above with another
# <branch>, that branch name alone is replaced by "<merged-parent-branch>"
# when GitLab and git prove all of:
#   1. exactly one merge request of the project (CI_API_V4_URL,
#      CI_PROJECT_ID, with CI_JOB_TOKEN) has <branch> as its source branch,
#      and it is merged into CI_MERGE_REQUEST_TARGET_BRANCH_NAME;
#   2. its merge or squash commit is an ancestor of
#      CI_MERGE_REQUEST_DIFF_BASE_SHA;
#   3. the commit is an ancestor of that merge request's head (sha), fetched
#      from refs/merge-requests/<iid>/head when the clone lacks it.
# Each excused commit is named on stderr with the parent's !<iid>. Any API
# or git error, an empty, ambiguous or unexpected answer, or a missing
# variable, curl or jq excuses nothing. The body, the rest of the subject
# and everything else are checked as before. Outside CI, set
# PUBLIC_HYGIENE_API_TOKEN to a read-only token (sent as PRIVATE-TOKEN) when
# CI_JOB_TOKEN is unset; PUBLIC_HYGIENE_API_TIMEOUT caps the request
# (seconds, default 20).
#
# Deny-list: PUBLIC_HYGIENE_DENYLIST names a file with one word per line
# (CI provides it as a file variable; the list itself is not in this
# repository). Each word is matched case-insensitively as a whole word
# (git grep -i -w -F) across the whole tree INCLUDING docs/, in tracked
# file names, and in the same commit messages and merge request title as
# the rules above (not in the description); the "public-hygiene:allow"
# marker excuses a content line. A hit is reported as path:line only (a file
# name hit as its position in git ls-files), never with the matched text,
# and while a list is loaded any report line of any rule that would show
# a listed word is withheld, so the job log does not republish the list.
# Blank
# lines and surrounding spaces in the file are ignored. In a merge-request
# pipeline an unset variable, a missing file or a list with no words is a
# failure; elsewhere (a local run) an unset variable prints "deny-list:
# not configured, skipped", while a set variable pointing at a missing
# file still fails.
#
# Usage: scripts/check-public-hygiene.sh [repo-root]   (default: this repo)
set -eu

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
cd "$root"

# Byte-level match in the C locale. UTF-8 lead bytes 0xD0..0xD3 are all of
# U+0400..U+04FF, 0xD4 0x80..0xAF is U+0500..U+052F (0xD4 0xB0.. is
# Armenian, not matched); the three-byte blocks are matched on their first
# two bytes plus the continuation range. Built with printf so this file
# itself stays ASCII.
#   E1 B2 80..8F  U+1C80..U+1C8F  Cyrillic Extended-C
#   E2 B7 A0..BF  U+2DE0..U+2DFF  Cyrillic Extended-A
#   EA 99 80..BF, EA 9A 80..9F  U+A640..U+A69F  Cyrillic Extended-B
cyr=$(printf '[\320-\323]|\324[\200-\257]|\341\262[\200-\217]|\342\267[\240-\277]|\352(\231[\200-\277]|\232[\200-\237])')
wave='(^|[^A-Za-z0-9])W[0-9]+[._][0-9]+|(Test|Benchmark|Fuzz|Example)W[0-9]+[._][0-9]+'
marker='public-hygiene:allow'

fail=0
in_mr=0
[ "${CI_PIPELINE_SOURCE:-}" = "merge_request_event" ] && in_mr=1

# Deny-list: normalise the word file into a private copy without edge
# whitespace (CR included), so a padded or CRLF word still matches, and
# count the non-blank lines as words (git grep -f skips blank lines
# itself); deny_list stays empty when there is nothing to check.
tmp=$(mktemp -d)
# A run aborted by set -e or set -u must not turn into a pass because the
# cleanup succeeded (some shells report $? = 0 in the trap after a set -u
# abort): only a run that reached its verdict below may exit 0.
finished=0
trap 'st=$?; rm -rf "$tmp"; if [ "$finished" -ne 1 ] && [ "$st" -eq 0 ]; then st=2; fi; exit $st' EXIT
deny_list=
deny_src=${PUBLIC_HYGIENE_DENYLIST:-}
if [ -z "$deny_src" ]; then
	if [ "$in_mr" -eq 1 ]; then
		echo "FAIL deny-list: PUBLIC_HYGIENE_DENYLIST is not set in a merge-request pipeline"
		fail=1
	else
		echo "deny-list: not configured, skipped"
	fi
elif [ ! -f "$deny_src" ] || [ ! -r "$deny_src" ]; then
	echo "FAIL deny-list: PUBLIC_HYGIENE_DENYLIST does not name a readable file"
	fail=1
else
	sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$deny_src" >"$tmp/deny"
	words=$(grep -c . "$tmp/deny" || true)
	if [ "${words:-0}" -eq 0 ]; then
		if [ "$in_mr" -eq 1 ]; then
			echo "FAIL deny-list: the list has no words in a merge-request pipeline"
			fail=1
		else
			echo "deny-list: not configured (empty list), skipped"
		fi
	else
		deny_list=$tmp/deny
		echo "deny-list: checking $words words"
	fi
fi

# redact: copy stdin to stdout, replacing every line that holds a
# deny-listed word (in a path, a file name or quoted content) with a
# placeholder, so no report line republishes the list. A failed lookup
# withholds everything.
redact() {
	if [ -z "$deny_list" ]; then
		cat
		return
	fi
	cat >"$tmp/r"
	rs=0
	rl=$(cd "$tmp" && git grep --no-index -a -h -n -i -w -F -f "$deny_list" -- r) || rs=$?
	if [ "$rs" -gt 1 ]; then
		echo "[report withheld: deny-list lookup failed (exit $rs)]"
		return
	fi
	printf '%s\n' "$rl" | cut -d: -f1 >"$tmp/rn"
	awk 'NR == FNR { if ($0 != "") bad[$0] = 1; next }
		{ if (FNR in bad) print "[line withheld: it holds a deny-listed word]"; else print }' "$tmp/rn" "$tmp/r"
}

scan() {
	label=$1 pattern=$2
	# git grep exits 1 on "no match" and >1 on a real error; an error must
	# not read as a clean tree.
	gs=0
	# git judges the marker on each line's content, so neither a file name
	# (which may itself hold colons and the marker) nor another line can
	# excuse a hit.
	hits=$(LC_ALL=C git grep -nIE -e "$pattern" --and --not -e "$marker" \
		-- . ':(exclude)docs/**') || gs=$?
	if [ "$gs" -gt 1 ]; then
		echo "FAIL $label: git grep failed (exit $gs)"
		fail=1
		return
	fi
	if [ -n "$hits" ]; then
		echo "FAIL $label:"
		printf '%s\n' "$hits" | redact | sed 's/^/  /'
		fail=1
	fi
}
scan "Cyrillic in tracked files (write it in English)" "$cyr"
scan "internal wave label in tracked files" "$wave"

# File names: git prints non-ASCII names quoted unless quotepath is off.
names=$(git -c core.quotepath=off ls-files -- . ':(exclude)docs/**' |
	LC_ALL=C grep -E "$cyr" || true)
if [ -n "$names" ]; then
	echo "FAIL Cyrillic in tracked file names (write it in English):"
	printf '%s\n' "$names" | redact | sed 's/^/  /'
	fail=1
fi

# denygrep ARGS...: git grep for the deny-list words; prints path:line of
# every hit not excused by the marker, without the matched content. git
# judges the marker on the line's content; -z separates path, line number
# and content with NUL (turned into \001 here), so a path holding colons
# cannot shift the split.
soh=$(printf '\001')
denygrep() {
	ds=0
	git grep -z -n -I -i -w -F \( -f "$deny_list" \) --and --not -e "$marker" \
		"$@" >"$tmp/dz" || ds=$?
	if [ "$ds" -gt 1 ]; then
		echo "git grep failed (exit $ds)"
		return
	fi
	tr '\000' '\001' <"$tmp/dz" | grep -v '^$' |
		while IFS= read -r l; do
			rest=${l#*"$soh"}
			printf '%s:%s\n' "${l%%"$soh"*}" "${rest%%"$soh"*}"
		done
}

if [ -n "$deny_list" ]; then
	hits=$(denygrep -- .)
	if [ -n "$hits" ]; then
		echo "FAIL deny-listed word in tracked files (docs/ included):"
		printf '%s\n' "$hits" | redact | sed 's/^/  /'
		fail=1
	fi
	git -c core.quotepath=off ls-files -- . >"$tmp/names"
	ns=0
	names=$(cd "$tmp" && git grep --no-index -a -h -n -i -w -F -f "$deny_list" -- names) || ns=$?
	if [ "$ns" -gt 1 ]; then
		echo "FAIL deny-listed word in tracked file names: git grep failed (exit $ns)"
		fail=1
	elif [ -n "$names" ]; then
		echo "FAIL deny-listed word in tracked file names (see: git ls-files | sed -n '<N>p'):"
		printf '%s\n' "$names" | cut -d: -f1 | sed 's/^/  tracked file #/'
		fail=1
	fi
fi

# textcheck LABEL TEXT: apply the same rules to a block of free text.
textcheck() {
	label=$1 text=$2
	for p in "$cyr" "$wave"; do
		bad=$(printf '%s\n' "$text" | LC_ALL=C grep -nE "$p" || true)
		if [ -n "$bad" ]; then
			echo "FAIL $label:"
			printf '%s\n' "$bad" | redact | sed 's/^/  /'
			fail=1
		fi
	done
	if [ -n "$deny_list" ]; then
		printf '%s\n' "$text" >"$tmp/text"
		bad=$(cd "$tmp" && denygrep --no-index -- text)
		if [ -n "$bad" ]; then
			echo "FAIL deny-listed word in $label:"
			printf '%s\n' "$bad" | sed 's/^text:/  line /'
			fail=1
		fi
	fi
}

# merged_parent REF COMMIT: succeed, with mp_iid set, only when GitLab and
# git prove that REF is the source branch of a merged merge request of this
# project (conditions 1-3 in the header); otherwise fail with mp_reason set.
# Reasons are fixed text: neither REF nor anything from the answer is
# printed, so no report republishes a branch name. The token never reaches
# an argument list: curl reads its header from stdin.
mp_iid='' mp_reason=''
merged_parent() {
	mp_ref=$1 mp_commit=$2 mp_iid='' mp_reason=''
	mp_api=${CI_API_V4_URL:-} mp_project=${CI_PROJECT_ID:-}
	mp_target=${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-} mp_base=${CI_MERGE_REQUEST_DIFF_BASE_SHA:-}
	if [ -z "$mp_api" ] || [ -z "$mp_project" ] || [ -z "$mp_target" ] || [ -z "$mp_base" ]; then
		mp_reason="CI_API_V4_URL, CI_PROJECT_ID, CI_MERGE_REQUEST_TARGET_BRANCH_NAME or CI_MERGE_REQUEST_DIFF_BASE_SHA is not set"
		return 1
	fi
	if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
		mp_reason="curl or jq is not installed"
		return 1
	fi
	if ! mp_path=$(jq -nr --arg p "$mp_project" --arg r "$mp_ref" \
		'"projects/\($p|@uri)/merge_requests?source_branch=\($r|@uri)&state=all&per_page=100"'); then
		mp_reason="jq could not build the request"
		return 1
	fi
	mp_cs=0
	if [ -n "${CI_JOB_TOKEN:-}" ]; then
		printf 'header = "JOB-TOKEN: %s"\n' "$CI_JOB_TOKEN"
	elif [ -n "${PUBLIC_HYGIENE_API_TOKEN:-}" ]; then
		printf 'header = "PRIVATE-TOKEN: %s"\n' "$PUBLIC_HYGIENE_API_TOKEN"
	fi | curl -s -f --max-time "${PUBLIC_HYGIENE_API_TIMEOUT:-20}" -K - \
		-o "$tmp/mr.json" "$mp_api/$mp_path" 2>/dev/null || mp_cs=$?
	if [ "$mp_cs" -ne 0 ]; then
		mp_reason="the merge request lookup failed (curl exit $mp_cs)"
		return 1
	fi
	# One line: "ok <iid> <head> <merge|-> <squash|->" or "no <reason>".
	if ! mp_line=$(jq -r --arg ref "$mp_ref" --arg target "$mp_target" '
		def sha: type == "string" and test("^[0-9a-f]{40}([0-9a-f]{24})?$");
		def commit: if sha then . else "-" end;
		if type != "array" then "no the answer is not a list"
		elif length == 0 then "no no merge request has this source branch"
		elif length > 1 then "no several merge requests have this source branch"
		else .[0] |
			if .source_branch != $ref then "no the answer is about another source branch"
			elif .state != "merged" then "no the merge request is not merged"
			elif .target_branch != $target then "no the merge request has another target branch"
			elif (.iid | type) != "number" or (.sha | sha | not) then "no the answer has no iid or head commit"
			else "ok \(.iid) \(.sha) \(.merge_commit_sha | commit) \(.squash_commit_sha | commit)"
			end
		end' "$tmp/mr.json" 2>/dev/null); then
		mp_reason="the merge request answer is not JSON"
		return 1
	fi
	read -r mp_v mp_i mp_head mp_merge mp_squash <<EOF
$mp_line
EOF
	if [ "$mp_v" != ok ]; then
		mp_reason=${mp_line#no }
		return 1
	fi
	case $mp_i in
	"" | *[!0-9]*)
		mp_reason="the answer has no iid or head commit"
		return 1
		;;
	esac
	# Condition 2: the parent's merge or squash commit is in the diff base.
	mp_in_base=0
	for mp_c in "$mp_merge" "$mp_squash"; do
		[ "$mp_c" = - ] && continue
		if git merge-base --is-ancestor "$mp_c" "$mp_base" 2>/dev/null; then
			mp_in_base=1
		else
			mp_git=$?
			# Exit 1 means not an ancestor; every other failure is a
			# broken proof, even when the other candidate is reachable.
			if [ "$mp_git" -gt 1 ]; then
				mp_reason="git could not check the diff base ancestry"
				return 1
			fi
		fi
	done
	if [ "$mp_in_base" -ne 1 ]; then
		mp_reason="neither its merge commit nor its squash commit is in the diff base"
		return 1
	fi
	# Condition 3: the commit is in the parent's accepted head.
	if ! git cat-file -e "$mp_head^{commit}" 2>/dev/null; then
		mp_fetch=0
		git fetch -q --no-tags origin "refs/merge-requests/$mp_i/head" >/dev/null 2>&1 || mp_fetch=$?
		if [ "$mp_fetch" -ne 0 ]; then
			mp_reason="git could not fetch its head commit"
			return 1
		fi
		if ! git cat-file -e "$mp_head^{commit}" 2>/dev/null; then
			mp_reason="its head commit is not available"
			return 1
		fi
	fi
	if ! git merge-base --is-ancestor "$mp_commit" "$mp_head" 2>/dev/null; then
		mp_reason="the commit is not in its head"
		return 1
	fi
	mp_iid=$mp_i
	return 0
}

# merge_subject SUBJECT PARENTS COMMIT: set ms_out to the subject with the
# branch name replaced by a placeholder when the commit is a merge of main
# under git's or GitLab's default subject into either the MR source branch
# ("$src_placeholder") or a proven merged parent ("$parent_placeholder"),
# and ms_note to the line that reports it; otherwise ms_out is the subject
# unchanged. Every condition must hold: a merge-request pipeline, at least
# two parents, and the subject byte for byte one of the three templates.
# The rest of the subject and the body are checked as before; a `git pull`
# subject (" of <url> into ...") is never excused. Runs in the current
# shell (not in $(...)), so the caller sees ms_out and ms_note.
src_placeholder='<source-branch>'
parent_placeholder='<merged-parent-branch>'
merge_subject() {
	ms_subj=$1 ms_parents=$2 ms_commit=$3
	ms_out=$ms_subj ms_note=''
	if [ "$in_mr" -ne 1 ] || [ "$ms_parents" -lt 2 ]; then
		return 0
	fi
	ms_src=${CI_MERGE_REQUEST_SOURCE_BRANCH_NAME:-}
	if [ -n "$ms_src" ]; then
		for ms_tpl in "Merge remote-tracking branch 'origin/main' into %s" \
			"Merge branch 'main' into %s" "Merge branch 'main' into '%s'"; do
			# shellcheck disable=SC2059 # the template is the format
			if [ "$ms_subj" = "$(printf "$ms_tpl" "$ms_src")" ]; then
				# shellcheck disable=SC2059
				ms_out=$(printf "$ms_tpl" "$src_placeholder")
				ms_note="default merge subject, source branch name not checked"
				return 0
			fi
		done
	fi
	# Another branch in the same templates: anchored at both ends, so text
	# before the template or after a quoted name is no match, and text after
	# an unquoted name is part of the name GitLab is asked about.
	ms_pre='' ms_suf=''
	case $ms_subj in
	"Merge remote-tracking branch 'origin/main' into "?*)
		ms_pre="Merge remote-tracking branch 'origin/main' into " ;;
	"Merge branch 'main' into '"?*"'")
		ms_pre="Merge branch 'main' into '" ms_suf="'" ;;
	"Merge branch 'main' into "?*)
		ms_pre="Merge branch 'main' into " ;;
	*)
		return 0 ;;
	esac
	ms_ref=${ms_subj#"$ms_pre"}
	ms_ref=${ms_ref%"$ms_suf"}
	if merged_parent "$ms_ref" "$ms_commit"; then
		ms_out="$ms_pre$parent_placeholder$ms_suf"
		ms_note="default merge subject of merged parent !$mp_iid, branch name not checked"
	else
		ms_note="default merge subject naming another branch, not excused: $mp_reason"
	fi
}

# range_messages RANGE: "<short hash> <subject>" and the body of every
# commit in RANGE, newest first (as git log prints them), with a default
# merge subject passed through merge_subject. Returns non-zero when any git
# call fails, so a message that could not be read never counts as clean.
range_messages() {
	rm_list=$(git rev-list "$1") || return 1
	for rm_c in $rm_list; do
		rm_parents=$(git rev-list --parents -n 1 "$rm_c") || return 1
		set -- $rm_parents
		rm_subj=$(git log -1 --format=%s "$rm_c") || return 1
		rm_body=$(git log -1 --format=%b "$rm_c") || return 1
		rm_short=$(git rev-parse --short "$rm_c") || return 1
		merge_subject "$rm_subj" $(($# - 1)) "$rm_c"
		if [ -n "$ms_note" ]; then
			echo "commit $rm_short: $ms_note" >&2
		fi
		printf '%s %s\n%s\n' "$rm_short" "$ms_out" "$rm_body"
	done
}

range=${HYGIENE_RANGE:-}
if [ "$in_mr" -eq 1 ]; then
	case $range in
	"" | ..* | *..)
		echo "FAIL merge-request pipeline without a usable commit range (HYGIENE_RANGE='$range'):"
		echo "  the diff base is missing, so no commit message was checked"
		fail=1
		range=
		;;
	esac
fi

if [ -n "$range" ]; then
	if [ "$in_mr" -eq 1 ] && [ -z "$(git rev-list "$range")" ]; then
		echo "FAIL merge-request pipeline: commit range $range is empty"
		fail=1
	fi
	if range_messages "$range" >"$tmp/msgs"; then
		textcheck "commit messages in $range" "$(cat "$tmp/msgs")"
	else
		echo "FAIL commit messages in $range: git could not read them"
		fail=1
	fi
fi

if [ "$in_mr" -eq 1 ]; then
	# The title becomes the commit subject on main; the description never
	# reaches a commit (see the header), so it is not read at all. An
	# unset title variable aborts the run under set -u: a title we were
	# not given cannot be called clean.
	echo "checking merge request title (${#CI_MERGE_REQUEST_TITLE} chars); the description is not checked, it does not reach main"
	textcheck "merge request title" "$CI_MERGE_REQUEST_TITLE"
fi

finished=1
if [ "$fail" -ne 0 ]; then
	echo "public hygiene: see CONTRIBUTING.md (\"Public repository\")."
	exit 1
fi
if [ -n "$deny_list" ]; then
	echo "ok   public hygiene: no Cyrillic, no wave labels, no deny-listed words"
else
	echo "ok   public hygiene: no Cyrillic, no wave labels"
fi
