#!/bin/sh
# Proves the weighted assignment of scripts/core-shard.sh: (1) on a fixture it
# gives the greedy split we expect, (2) on the real package list the estimated
# shard loads stay within CORE_SHARD_MAX_SKEW seconds, (3) the skew check fails
# on a split that is skewed (red control: one dominant package, no bias).
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf 'a 10\nb 9\nc 2\nd 1\n' >"$tmp/w"
got1=$(printf 'a\nb\nc\nd\n' | CORE_SHARD_WEIGHTS="$tmp/w" CORE_SHARD_BIAS="0 0" ./scripts/core-shard.sh 1 2 2>/dev/null | tr '\n' ' ')
got2=$(printf 'a\nb\nc\nd\n' | CORE_SHARD_WEIGHTS="$tmp/w" CORE_SHARD_BIAS="0 0" ./scripts/core-shard.sh 2 2 2>/dev/null | tr '\n' ' ')
[ "$got1" = "a d " ] && [ "$got2" = "b c " ] || { echo "fixture split wrong: '$got1' / '$got2'" >&2; exit 1; }

# skew <weights> <bias>: prints |load1 - load2| for the real package list.
skew() {
	all=$(go list ./... | grep -v '/internal/targets$')
	l1=$(printf '%s\n' "$all" | CORE_SHARD_WEIGHTS="$1" CORE_SHARD_BIAS="$2" ./scripts/core-shard.sh 1 2 2>&1 >/dev/null | awk '{print $3}')
	l2=$(printf '%s\n' "$all" | CORE_SHARD_WEIGHTS="$1" CORE_SHARD_BIAS="$2" ./scripts/core-shard.sh 2 2 2>&1 >/dev/null | awk '{print $3}')
	echo $((l1 > l2 ? l1 - l2 : l2 - l1))
}
max=${CORE_SHARD_MAX_SKEW:-60}
real=$(skew scripts/core-shard-weights.txt "0 0")
[ "$real" -le "$max" ] || { echo "real weights: shard skew ${real}s > ${max}s" >&2; exit 1; }

# Red control: one package outweighs everything else, so no split can balance.
pkg=$(go list ./... | grep -v '/internal/targets$' | head -1)
printf '%s 5000\n' "$pkg" >"$tmp/skewed"
bad=$(skew "$tmp/skewed" "0 0")
if [ "$bad" -le "$max" ]; then echo "red control did not trip: skew ${bad}s <= ${max}s" >&2; exit 1; fi
echo "core shard balance ok: skew ${real}s <= ${max}s; red control skew ${bad}s trips"
