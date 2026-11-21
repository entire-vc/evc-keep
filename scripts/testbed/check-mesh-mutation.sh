#!/usr/bin/env bash
# Red run of the Mesh part of the rotation testbed (docs/rotation-testbed.md).
#
# In a scratch copy of the tree rotationParts.provider is changed to always
# return the Generator, so that Mesh is never asked for a key. The Mesh stand is
# then run from that copy: scenario 1 must FAIL, on the property that the key
# ids in Mesh changed. The same procedure on an untouched copy must PASS, so a
# stand that fails for another reason is not mistaken for a caught mutation.
#
#   TESTBED_MESH_SRC=<evc-mesh checkout> scripts/testbed/check-mesh-mutation.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/keep-mesh-mutation.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

copy() { # copy DIR
  mkdir -p "$1"
  (cd "$SRC" && git ls-files -co --exclude-standard | grep -v '^scripts/testbed/out/' | tar -T - -cf -) | tar -x -C "$1"
}

run() { # run NAME DIR: the whole Mesh stand from DIR, in its own compose project
  TESTBED_PROJECT="keep-mesh-mutation-$1" TESTBED_OUT="$WORK/$1-out" "$2/scripts/testbed/rotation.sh" all --mesh >"$WORK/$1.log" 2>&1
}

mutate() { # mutate DIR: the provider is the Generator whatever the bindings say
  local f="$1/cmd/keep-server/app/rotation.go"
  python3 - "$f" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = "func (p *rotationParts) provider(ctx context.Context, ref rotation.Ref) (prot.RotationProvider, error) {\n"
if a not in s:
    sys.exit("the mutated function is not where this check expects it")
s = s.replace(a, a + "\treturn rotation.Generator{Entropy: p.entropy}, nil\n")
open(p, "w").write(s)
PY
  if cmp -s "$f" "$SRC/cmd/keep-server/app/rotation.go"; then echo "the mutation changed nothing"; exit 1; fi
}

copy "$WORK/clean"; copy "$WORK/mutant"; mutate "$WORK/mutant"

status=0
if run clean "$WORK/clean"; then
  echo "clean copy: scenarios PASS"
else
  echo "FAIL: the unmodified copy does not pass; the red run below would prove nothing"; tail -20 "$WORK/clean.log"; status=1
fi
if [ $status -eq 0 ]; then
  if run mutant "$WORK/mutant"; then
    echo "FAIL: the mutated server passed: the check cannot fail"; status=1
  elif grep -q '^FAIL mesh 1: the key ids in Mesh changed' "$WORK/mutant.log"; then
    echo "mutated copy: scenario 1 FAILS as required:"; grep '^\(PASS\|FAIL\) \(scenario\|mesh\) 1' "$WORK/mutant.log"
  else
    echo "FAIL: the mutated run failed, but not on the Mesh key ids:"; tail -15 "$WORK/mutant.log"; status=1
  fi
fi
for p in clean mutant; do COMPOSE_PROFILES=mesh TESTBED_PROJECT="keep-mesh-mutation-$p" docker compose -f "$HERE/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true; done
exit $status
