#!/usr/bin/env bash
# What scripts/check-upgrade-rollback.sh and its red runs may copy from a log
# of the probe (go test) or of the check itself into the job log. Those logs
# can carry the canary, the database password or the root key: a probe
# assertion or a panic that quotes what it saw, a psql or docker message. So
# nothing is printed from them but fixed messages of a closed list, read from
# the tree on every run, and a count of the lines left out:
#
#   - the literal of each t.Fatal("...") and the text of each t.Fatalf("...")
#     up to its first verb, in cmd/keep-server/app/upgrade_probe_test.go;
#   - "FAIL upgrade-rollback: " and the text of each fail "..." up to its
#     first expansion, and each echo "FAIL upgrade-rollback: ...", in
#     scripts/check-upgrade-rollback.sh.
#
# A message that starts with a verb or an expansion contributes its first
# literal piece instead ("$t is required" -> " is required"). The log is
# matched with grep -o -F against the list, so only list entries can reach
# the output, never the rest of a line. An entry shorter than six characters
# or without a letter is left out: it would only count how often punctuation
# occurs. grep -a: a log with a NUL or invalid UTF-8 is still read as text,
# never answered with grep's "binary file matches".
#
#   upgrade-rollback-report.sh FILE [PREFIX]  matched messages, then
#                                             "not printed: N lines"
#   upgrade-rollback-report.sh --list         one entry per call site, in
#                                             source order (the self-test
#                                             counts them)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
probe_src=$root/cmd/keep-server/app/upgrade_probe_test.go
check_src=$root/scripts/check-upgrade-rollback.sh

# entries: one line per call site; an empty line is a call site whose message
# has no literal text at all.
entries() {
	awk '
	function first_piece(s, sep,   n, i, parts) {
		n = split(s, parts, sep)
		if (parts[1] != "") return parts[1]
		for (i = 2; i <= n; i++) if (parts[i] != "") return parts[i]
		return ""
	}
	BEGIN {
		shellx = "[$]([{][^}]*[}]|[(][^)]*[)]|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?!$-])"
		verb = "%[-+# 0-9.*]*[a-zA-Z%]"
	}
	FILENAME ~ /_test[.]go$/ {
		s = $0
		while (match(s, /t[.]Fatalf?[(]"[^"]*"/)) {
			call = substr(s, RSTART, RLENGTH)
			s = substr(s, RSTART + RLENGTH)
			q = index(call, "\"")
			text = substr(call, q + 1, length(call) - q - 1)
			if (call ~ /^t[.]Fatalf/) text = first_piece(text, verb)
			print text
		}
		next
	}
	{
		s = $0
		while (match(s, /(^|[^A-Za-z0-9_])fail "[^"]*"/)) {
			call = substr(s, RSTART, RLENGTH)
			s = substr(s, RSTART + RLENGTH)
			q = index(call, "\"")
			text = first_piece(substr(call, q + 1, length(call) - q - 1), shellx)
			if (substr(call, q + 1, 1) == "$" || text == "") print text
			else print "FAIL upgrade-rollback: " text
		}
		s = $0
		while (match(s, /echo "FAIL upgrade-rollback: [^"$][^"]*"/)) {
			call = substr(s, RSTART, RLENGTH)
			s = substr(s, RSTART + RLENGTH)
			print first_piece(substr(call, 7, length(call) - 7), shellx)
		}
	}' "$probe_src" "$check_src"
}

if [ "${1:-}" = --list ]; then
	entries
	exit 0
fi
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: upgrade-rollback-report.sh FILE [PREFIX] | --list" >&2; exit 2; }
file=$1
prefix=${2:-}
list=$(mktemp)
trap 'rm -f "$list"' EXIT
{ echo "FAIL upgrade-rollback: "; entries; } | awk 'length($0) >= 6 && /[A-Za-z]/' | LC_ALL=C sort -u >"$list"
[ -s "$list" ] || { echo "${prefix}report: the list of fixed messages is empty" >&2; exit 2; }
[ -f "$file" ] || { echo "${prefix}report: no log to report on" >&2; exit 2; }
LC_ALL=C grep -a -o -F -f "$list" -- "$file" | awk -v p="$prefix" '{ print p $0 }' || true
left=$(LC_ALL=C grep -a -c -v -F -f "$list" -- "$file" || true)
echo "${prefix}not printed: ${left:-0} lines"
