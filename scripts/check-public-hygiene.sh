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
# Not scanned: docs/ (translations and quoted sources may live there).
# Per-line exception: put the marker "public-hygiene:allow" on the line
# itself, with a reason next to it; it excuses that line only, never the
# rest of the file, and never a file name. Prefer an escape instead where
# the language has one (a homoglyph test host is "\u0430pi.example.com",
# not the literal character).
#
# With HYGIENE_RANGE=<base>..<head>, commit messages (subject and body)
# in that range are checked by the same rules (CI sets it to the MR diff).
# In a merge-request pipeline (CI_PIPELINE_SOURCE=merge_request_event) the
# MR title and description are checked too: with squash they become the
# commit message on main and reach the public mirror. There an unset,
# malformed or empty range is a failure, not a pass: a check that has
# nothing to look at must say so. Outside a merge-request pipeline (a push
# to a branch, a local run) there is no base to diff against, so an unset
# range keeps meaning "tree only".
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
scan() {
	label=$1 pattern=$2
	# git grep exits 1 on "no match" and >1 on a real error; an error must
	# not read as a clean tree.
	gs=0
	out=$(LC_ALL=C git grep -nIE "$pattern" -- . ':(exclude)docs/**') || gs=$?
	if [ "$gs" -gt 1 ]; then
		echo "FAIL $label: git grep failed (exit $gs)"
		fail=1
		return
	fi
	# Lines are path:line:content; judge the marker on the content only, so
	# neither a file name nor another line can excuse a hit.
	hits=$(printf '%s\n' "$out" | grep -v '^$' |
		while IFS= read -r l; do
			content=${l#*:*:}
			if [ "${content#*"$marker"}" = "$content" ]; then printf '%s\n' "$l"; fi
		done)
	if [ -n "$hits" ]; then
		echo "FAIL $label:"
		printf '%s\n' "$hits" | sed 's/^/  /'
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
	printf '%s\n' "$names" | sed 's/^/  /'
	fail=1
fi

# textcheck LABEL TEXT: apply the same rules to a block of free text.
textcheck() {
	label=$1 text=$2
	for p in "$cyr" "$wave"; do
		bad=$(printf '%s\n' "$text" | LC_ALL=C grep -nE "$p" || true)
		if [ -n "$bad" ]; then
			echo "FAIL $label:"
			printf '%s\n' "$bad" | sed 's/^/  /'
			fail=1
		fi
	done
}

in_mr=0
[ "${CI_PIPELINE_SOURCE:-}" = "merge_request_event" ] && in_mr=1

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
	textcheck "commit messages in $range" "$(git log --format='%h %s%n%b' "$range")"
fi

if [ "$in_mr" -eq 1 ]; then
	# GitLab truncates the description variable at 2700 characters; a
	# description we cannot read in full cannot be called clean.
	if [ "${CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED:-false}" = "true" ]; then
		echo "FAIL merge request description is truncated in CI (over 2700 characters): shorten it"
		fail=1
	fi
	echo "checking merge request title (${#CI_MERGE_REQUEST_TITLE} chars) and description (${#CI_MERGE_REQUEST_DESCRIPTION} chars)"
	textcheck "merge request title" "${CI_MERGE_REQUEST_TITLE:-}"
	textcheck "merge request description" "${CI_MERGE_REQUEST_DESCRIPTION:-}"
fi

if [ "$fail" -ne 0 ]; then
	echo "public hygiene: see CONTRIBUTING.md (\"Public repository\")."
	exit 1
fi
echo "ok   public hygiene: no Cyrillic, no wave labels"
