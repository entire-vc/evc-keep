#!/bin/sh
# Every throwaway postgres service in the CI files must start with fsync off:
# CREATE/DROP DATABASE in pgscratch each force a checkpoint, and on the shared
# runner disk a checkpoint with fsync outlasts the per-operation deadline.
# Usage: check-ci-postgres-fsync.sh [ci-file...]   (default: .gitlab-ci.yml and
# every file under .gitlab/ci, where the full-tests jobs live)
set -eu
if [ "$#" -eq 0 ]; then
	set -- .gitlab-ci.yml .gitlab/ci/*.yml
fi
total=0
status=0
for f in "$@"; do
	bad=$(awk '
		# A service is the list item "- name: postgres:..." and everything
		# indented deeper than its dash; comments do not count (whole-line or
		# trailing), so a commented command or a following service command
		# cannot satisfy it.
		function flush() { if (n && !found) print n; n = 0 }
		{
			match($0, /^[ \t]*/); ind = RLENGTH
			if (n && $0 !~ /^[ \t]*(#|$)/ && ind <= dash) flush()
		}
		/^[ \t]*- name: postgres:/ { flush(); n = NR; found = 0; dash = ind; next }
		n && $0 ~ /^[ \t]*command:/ { line = $0; sub(/[ \t]#.*$/, "", line); if (line ~ /"fsync=off"/) found = 1 }
		END { flush() }
	' "$f")
	if [ -n "$bad" ]; then
		echo "FAIL: postgres service without fsync=off in $f at line(s): $(echo "$bad" | tr '\n' ' ')" >&2
		status=1
	fi
	count=$(grep -c -E -- '^[[:space:]]*- name: postgres:' "$f" || true)
	total=$((total + count))
done
[ "$status" -eq 0 ] || exit 1
[ "$total" -gt 0 ] || { echo "FAIL: no postgres service found (guard blind)" >&2; exit 1; }
echo "ok: $total postgres services, all with fsync=off"
