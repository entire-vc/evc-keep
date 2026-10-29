#!/bin/sh
# Exercise cache ownership and EXIT cleanup without compiling Go. An optional
# library path lets the same assertions test a deliberately broken copy.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
lib=${1:-$root/scripts/lib/gocache.sh}
workspace_lib=${2:-$root/scripts/temp-workspace.sh}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/repo with spaces" "$scratch/external"
testroot="$scratch/repo with spaces"
touch "$testroot/go.mod" "$scratch/external/keep"

# Keep one check active while a second check in the same checkout finishes.
# The second cleanup must leave the first check's cache usable.
mkdir "$scratch/caches" "$scratch/adversarial"
cat >"$scratch/second.sh" <<'SH'
set -eu
root=$1; . "$2"
mkdir -p "$GOCACHE"
printf '%s\n' "$GOCACHE" >"$3"
SH
for shell in sh bash; do
    command -v "$shell" >/dev/null 2>&1 || continue
    (unset GOCACHE; TMPDIR="$scratch/caches" "$shell" -c '
        set -eu
        root=$1; . "$2"
        mkdir -p "$GOCACHE"; touch "$GOCACHE/active"
        first_cache=$GOCACHE
        (unset GOCACHE; "$3" "$5" "$root" "$2" "$4")
        [ -f "$first_cache/active" ] || { echo "FAIL overlapping checks: active cache removed"; exit 1; }
        [ "$(cat "$4")" != "$first_cache" ] || { echo "FAIL overlapping checks: default cache shared"; exit 1; }
    ' sh "$testroot" "$lib" "$shell" "$scratch/second-cache" "$scratch/second.sh")
    [ -z "$(ls -A "$scratch/caches")" ] || { echo "FAIL overlapping checks: owned cache remains"; exit 1; }
    echo "ok   $shell overlapping checks: distinct caches, active cache preserved, both cleaned"
done

# A checkout-local TMPDIR must not pull Go cache entries into snapshots.
mkdir "$testroot/nested-tmp"
for shell in sh bash; do
    command -v "$shell" >/dev/null 2>&1 || continue
    (unset GOCACHE; TMPDIR="$testroot/nested-tmp" "$shell" -c '
        set -eu
        root=$(cd "$1" && pwd -P); . "$2"
        case "$GOCACHE/" in "$root/"*) echo "FAIL checkout-local TMPDIR: cache inside checkout"; exit 1 ;; esac
        printf "%s\n" "$GOCACHE" >"$3"
        touch "$GOCACHE/probe"
    ' sh "$testroot" "$lib" "$scratch/fallback-cache")
    fallback_cache=$(cat "$scratch/fallback-cache")
    [ ! -e "$fallback_cache" ] || { echo "FAIL checkout-local TMPDIR: cache remains"; exit 1; }
    [ -z "$(ls -A "$testroot/nested-tmp")" ] || { echo "FAIL checkout-local TMPDIR: nested cache remains"; exit 1; }
    echo "ok   $shell checkout-local TMPDIR: external cache allocated and cleaned"
done

cat >"$scratch/probe.sh" <<'SH'
set -eu
root=$1
. "$2"
mkdir -p "$root/work"
trap 'gocache_cleanup; rm -rf "$root/work"' EXIT
mkdir -p "$GOCACHE"
touch "$GOCACHE/probe"
case $3 in
    fail) false ;;
    change) GOCACHE="$root/../external" ;;
esac
SH

cat >"$scratch/export-probe.sh" <<'SH'
test "${GOCACHE:-}" = "$1"
SH

shells=sh
if command -v bash >/dev/null 2>&1; then shells="$shells bash"; fi
for shell in $shells; do
    (unset GOCACHE; TMPDIR="$scratch/caches" "$shell" -c '
        root=$(cd "$1" && pwd -P); . "$2"
        expected_parent=$(cd "$TMPDIR" && pwd -P)
        case "$GOCACHE" in "$expected_parent"/keep-gocache.*) ;; *) echo "FAIL: default cache is not private"; exit 1 ;; esac
        sh "$3" "$GOCACHE" || { echo "FAIL: private cache is not exported"; exit 1; }
        mkdir -p "$GOCACHE"; touch "$GOCACHE/probe"
    ' sh "$testroot" "$lib" "$scratch/export-probe.sh")
    [ -z "$(ls -A "$scratch/caches")" ] || { echo "FAIL $shell early exit: cache remains"; exit 1; }
    echo "ok   $shell early exit: library trap removed cache"
    for mode in pass fail change; do
        if (unset GOCACHE; TMPDIR="$scratch/caches" "$shell" "$scratch/probe.sh" "$testroot" "$lib" "$mode"); then
            status=0
        else
            status=$?
        fi
        want=0
        [ "$mode" != fail ] || want=1
        [ "$status" -eq "$want" ] || { echo "FAIL $shell $mode: exit $status, want $want"; exit 1; }
        [ -z "$(ls -A "$scratch/caches")" ] || { echo "FAIL $shell $mode: cache remains"; exit 1; }
        [ ! -e "$testroot/work" ] || { echo "FAIL $shell $mode: original cleanup lost"; exit 1; }
        [ -f "$scratch/external/keep" ] || { echo "FAIL $shell $mode: foreign path removed"; exit 1; }
        echo "ok   $shell $mode: owned cache and work removed, status $status"
    done
    for cache in "$scratch/external" "$testroot/.gocache"; do
        GOCACHE="$cache" "$shell" "$scratch/probe.sh" "$testroot" "$lib" pass
        [ -f "$cache/probe" ] || { echo "FAIL $shell external: cache removed"; exit 1; }
        rm -rf "$testroot/.gocache"
    done
    echo "ok   $shell external: caller caches preserved, including root/.gocache"
    for cache in '' off; do
        GOCACHE="$cache" "$shell" -c 'root=$1; . "$2"; test "$GOCACHE" = "$3"' sh "$testroot" "$lib" "$cache"
    done
    echo "ok   $shell empty/off: caller settings preserved"

    # Even corruption of the owned-path bookkeeping cannot remove a sibling.
    (unset GOCACHE; TMPDIR="$scratch/adversarial" "$shell" -c 'root=$1; . "$2"; gocache_owned_path="$root/../external"' sh "$testroot" "$lib")
    [ -f "$scratch/external/keep" ] || { echo "FAIL $shell guard: foreign path removed"; exit 1; }
    echo "ok   $shell guard: foreign owned-path refused"

    # Refuse deletion if the allocated directory is replaced with a symlink.
    (unset GOCACHE; TMPDIR="$scratch/adversarial" "$shell" -c '
        set -eu
        root=$1; . "$2"
        rmdir "$GOCACHE"
        ln -s "$3" "$GOCACHE"
    ' sh "$testroot" "$lib" "$scratch/external")
    [ -f "$scratch/external/keep" ] || { echo "FAIL $shell symlink: target removed"; exit 1; }
    echo "ok   $shell symlink: deletion refused, target preserved"

done

# The shared workspace owns the final EXIT/signal trap. It must clean both
# scratch and the cache without replacing the original exit status.
mkdir "$scratch/outer"
for shell in $shells; do
    for mode in pass fail HUP INT TERM; do
        want=0
        case $mode in fail) want=23 ;; HUP) want=129 ;; INT) want=130 ;; TERM) want=143 ;; esac
        if (unset GOCACHE; TMPDIR="$scratch/outer" "$shell" -c '
            set -eu
            root=$1; . "$2"; . "$3"; temp_workspace
            mkdir -p "$GOCACHE"; touch "$GOCACHE/probe" "$TMPDIR/probe"
            case $4 in
                fail) exit 23 ;;
                HUP|INT|TERM) kill -s "$4" "$$"; exit 99 ;;
            esac
        ' "$shell" "$testroot" "$lib" "$workspace_lib" "$mode"); then
            status=0
        else
            status=$?
        fi
        [ "$status" -eq "$want" ] || { echo "FAIL $shell workspace/$mode: exit $status, want $want"; exit 1; }
        [ -z "$(ls -A "$scratch/outer")" ] || { echo "FAIL $shell workspace/$mode: cache or scratch remains"; exit 1; }
        echo "ok   $shell workspace/$mode: cache and scratch removed, status $status"
    done
    GOCACHE="$scratch/external" TMPDIR="$scratch/outer" "$shell" -c '
        set -eu
        root=$1; . "$2"; . "$3"; temp_workspace
        touch "$GOCACHE/probe" "$TMPDIR/probe"
    ' "$shell" "$testroot" "$lib" "$workspace_lib"
    [ -f "$scratch/external/probe" ] || { echo "FAIL $shell workspace external: cache removed"; exit 1; }
    [ -z "$(ls -A "$scratch/outer")" ] || { echo "FAIL $shell workspace external: scratch remains"; exit 1; }
    echo "ok   $shell workspace external: cache preserved, scratch removed"
done

# Keep the integration contract visible for every mutation script, including
# newly added ones. Both the early-exit trap and the scratch cleanup must run.
for script in "$root"/scripts/check-*-mutations.sh "$root/scripts/check-w3-stubs.sh"; do
    grep -qxF '. "$root/scripts/lib/gocache.sh"' "$script" || { echo "FAIL $script: missing cache library"; exit 1; }
    grep -qxF '. "$root/scripts/temp-workspace.sh"' "$script" || { echo "FAIL $script: missing workspace library"; exit 1; }
    grep -qxF 'temp_workspace' "$script" || { echo "FAIL $script: workspace cleanup not activated"; exit 1; }
    if grep -q '^trap ' "$script"; then
        echo "FAIL $script: workspace cleanup trap overridden"; exit 1
    fi
    case $script in
      */check-runner-enroll-mutations.sh|*/check-w3-stubs.sh)
        grep -qF 'test -f "$root/go.mod"' "$script" || { echo "FAIL $script: missing repository guard"; exit 1; }
        ;;
    esac
    case $script in
      */check-runner-enroll-mutations.sh)
        for shell in $shells; do
            for setting in unset empty; do
                if (unset KEEP_DATABASE_URL GOCACHE
                    if [ "$setting" = empty ]; then KEEP_DATABASE_URL=; export KEEP_DATABASE_URL; fi
                    TMPDIR="$scratch/outer" "$shell" "$script" >"$scratch/precondition.log" 2>&1); then
                    status=0
                else
                    status=$?
                fi
                if [ "$status" -ne 2 ] || ! grep -qF 'a migrated PostgreSQL database is required' "$scratch/precondition.log"; then
                    echo "FAIL $script: $shell $setting database must exit 2, got $status"; exit 1
                fi
                [ -z "$(ls -A "$scratch/outer")" ] || { echo "FAIL $script: precondition left cache or scratch"; exit 1; }
                echo "ok   $shell runner-enroll/$setting database: status 2, cache and scratch removed"
            done
            if KEEP_DATABASE_URL= GOCACHE="$scratch/external" "$shell" "$script" >"$scratch/precondition.log" 2>&1; then status=0; else status=$?; fi
            [ "$status" -eq 2 ] && [ -f "$scratch/external/keep" ] || { echo "FAIL $script: caller-cache precondition"; exit 1; }
        done
        ;;
      */check-intake-service-mutations.sh|*/check-intake-receiver-mutations.sh|*/check-intake-page-mutations.sh)
        # Some /bin/sh versions turn a parameter-expansion failure into exit
        # zero when an EXIT trap runs. Missing PostgreSQL must fail explicitly,
        # before Python starts, while preserving a caller-owned cache.
        if KEEP_DATABASE_URL= GOCACHE="$scratch/external" sh "$script" >"$scratch/precondition.log" 2>&1; then
            status=0
        else
            status=$?
        fi
        if [ "$status" -ne 2 ] || ! grep -qF 'a migrated PostgreSQL database is required' "$scratch/precondition.log"; then
            echo "FAIL $script: missing database must exit 2 before Python"; exit 1
        fi
        [ -f "$scratch/external/keep" ] || { echo "FAIL $script: precondition removed caller cache"; exit 1; }
        ;;
    esac
    # Python must inherit the shell-owned cache, never create an unowned
    # fallback behind the wrapper's ownership bookkeeping.
    if grep -E "setdefault[[:space:]]*\\([[:space:]]*['\"]GOCACHE['\"]|\\[['\"]GOCACHE['\"]\\][[:space:]]*=" "$script" >/dev/null; then
        echo "FAIL $script: Python must inherit wrapper GOCACHE"; exit 1
    fi
done
echo "ok   all mutation scripts source the library and chain EXIT cleanup"

# Reject a copied script outside a checkout before sourcing helpers or
# allocating a cache. No libraries are planted in this invalid repository.
mkdir -p "$scratch/not-repo/scripts"
for script in check-runner-enroll-mutations.sh check-w3-stubs.sh; do
    cp "$root/scripts/$script" "$scratch/not-repo/scripts/$script"
    for shell in $shells; do
        if (unset GOCACHE; TMPDIR="$scratch/outer" "$shell" "$scratch/not-repo/scripts/$script" >"$scratch/precondition.log" 2>&1); then status=0; else status=$?; fi
        if [ "$status" -ne 2 ] || ! grep -qF 'is not the repo root' "$scratch/precondition.log"; then
            echo "FAIL $shell $script: repository precondition must exit 2"; exit 1
        fi
        [ -z "$(ls -A "$scratch/outer")" ] || { echo "FAIL $shell $script: invalid root allocated cache or scratch"; exit 1; }
        echo "ok   $shell $script: invalid repository refused before allocation"
    done
done

# The lane wrapper that drops a caller's GOCACHE is checked with the same job.
[ $# -gt 0 ] || "$root/scripts/check-run-mutation-checks.sh"
