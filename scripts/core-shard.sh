#!/bin/sh
# Prints the packages of core shard $1 (1-based) of $2: greedy balance by the
# per-package seconds in scripts/core-shard-weights.txt (heaviest first, onto the
# lightest shard; ties by name, so the split is deterministic). Reads the package
# list from stdin, one import path per line; unknown packages weigh 5. Shard k
# starts with CORE_SHARD_BIAS[k] seconds of load: pipeline 16196 spent ~100 s more
# per job outside package time on core-2 (heavier builds) than on core-1; pipelines
# 16988 and 17001 measured ~230 s (core-1) against ~200 s (core-2), so the bias is 0.
set -eu
shard=${1:?shard}
total=${2:?shards}
dir=$(dirname "$0")
sort | awk -v s="$shard" -v n="$total" -v wf="${CORE_SHARD_WEIGHTS:-$dir/core-shard-weights.txt}" -v bias="${CORE_SHARD_BIAS:-0 0}" '
  BEGIN { split(bias, bi, " "); for (j = 1; j <= n; j++) load[j] = bi[j] + 0
    while ((getline l < wf) > 0) if (l !~ /^#/ && l != "") { split(l, a, " "); w[a[1]] = a[2] } }
  { p[NR] = $0; x[NR] = ($0 in w) ? w[$0] : 5 }
  END {
    # selection sort by weight desc, input order (sorted by name) on ties
    for (i = 1; i <= NR; i++) used[i] = 0
    for (k = 1; k <= NR; k++) {
      b = 0
      for (i = 1; i <= NR; i++) if (!used[i] && (b == 0 || x[i] > x[b])) b = i
      used[b] = 1
      m = 1
      for (j = 2; j <= n; j++) if (load[j] < load[m]) m = j
      load[m] += x[b]; own[b] = m
    }
    for (i = 1; i <= NR; i++) if (own[i] == s) print p[i]
    printf "shard %d: %d s\n", s, load[s] > "/dev/stderr"
  }'
