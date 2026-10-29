#!/bin/sh
# The core shards together are exactly `go list ./...` minus internal/targets:
# no package dropped, none run twice. Red control: CORE_SHARD_DROP removes one
# package from shard 1's output (CORE_SHARD_DUP adds one to shard 2) and this
# check must then fail.
set -eu
cd "$(dirname "$0")/.."
all=$(go list ./... | grep -v '/internal/targets$' | sort)
test -n "$all"
n=${CORE_SHARDS:-2}
got=""
i=1
while [ "$i" -le "$n" ]; do
	part=$(printf '%s\n' "$all" | ./scripts/core-shard.sh "$i" "$n" 2>/dev/null)
	test -n "$part" || { echo "shard $i is empty" >&2; exit 1; }
	if [ -n "${CORE_SHARD_DROP:-}" ] && [ "$i" -eq 1 ]; then
		part=$(printf '%s\n' "$part" | grep -vx "$CORE_SHARD_DROP" || true)
	fi
	if [ -n "${CORE_SHARD_DUP:-}" ] && [ "$i" -eq 2 ]; then
		part=$(printf '%s\n%s\n' "$part" "$CORE_SHARD_DUP")
	fi
	got=$(printf '%s\n%s\n' "$got" "$part")
	i=$((i + 1))
done
got=$(printf '%s\n' "$got" | sed '/^$/d' | sort)
if [ "$got" != "$all" ]; then
	echo "core shards differ from go list (dropped or duplicated package):" >&2
	printf '%s\n' "$got" | diff - "$(printf '%s\n' "$all" > "${TMPDIR:-/tmp}/core-all.$$"; echo "${TMPDIR:-/tmp}/core-all.$$")" >&2 || true
	rm -f "${TMPDIR:-/tmp}/core-all.$$"
	exit 1
fi
echo "core shards cover $(printf '%s\n' "$all" | wc -l | tr -d ' ') packages exactly once"
