#!/bin/sh
# Rejects the two comment directives that hide a forbidigo finding without
# touching .golangci.yml (threat model 4.1, guard "expose-callers"):
#   //line FILE:N   golangci-lint reports a finding at the path the directive
#                   names, and the zone's path exclusion then drops it for a
#                   call that sits outside the zone.
#   //nolint        drops the finding directly. Bare, "all", or a list naming
#                   forbidigo or depguard is the hole; //nolint:gosec and the
#                   like stay legal, they cannot hide these two linters.
# No .go file in the tree may carry either. A real need is a decision for the
# lead with a threat-model entry, not a comment. Usage: [ROOT]; exit 1 on a hit.
# scripts/check-import-boundaries.sh proves this script can fail.
set -eu

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
test -f "$root/go.mod" || { echo "refuse: $root does not look like the repo root" >&2; exit 2; }

# Go reads //line only at the start of a line and /*line */ anywhere.
# A nolint is bare when no ":linters" follows it, so what comes next is a
# space, the end of the line or the comment's end.
nl='(//|/\*)[[:space:]]*nolint'
pattern="^//line |/\\*line |${nl}([[:space:]]|\$|\\*/)|${nl}[[:space:]]*:([^/]*[,[:space:]])?(forbidigo|depguard|all)([^[:alnum:]_-]|\$)"

# Walk what the go tool walks: it skips only directories (and files) named
# .*, _* and testdata, so node_modules, .artifacts and the like are read, and
# a symlink to a file counts (go list includes it). -print0 | xargs -0: a path
# with a space cannot split into two arguments. The inner sh keeps the
# arguments that resolve to a regular file (a dangling link or a link to a
# directory is not a source file) and turns grep's exit 1, "no match", into
# success, so xargs (123 for any failing child on GNU and busybox, 1 on BSD)
# fails only on a real fault, and set -e then stops the script.
hits=$(cd "$root" && find . \( -name '.?*' -o -name '_*' -o -name testdata \) -prune -o \( -type f -o -type l \) -name '*.go' -print0 |
	xargs -0 sh -c 'p=$0; for f; do if test -f "$f"; then set -- "$@" "$f"; fi; shift; done; grep -niE -e "$p" /dev/null "$@" || test $? -eq 1' "$pattern")

if [ -n "$hits" ]; then
	echo "FAIL lint directives: //line and //nolint are not allowed in Go files:"
	printf '%s\n' "$hits"
	exit 1
fi
echo "ok   lint directives: no //line or //nolint in any .go file"
