# Sourced by mutation checks after resolving $root. A caller's GOCACHE is
# owned by the caller (including an empty setting or "off"). Each default
# cache belongs to one run, even when checks share a checkout. Never delete
# based on the mutable GOCACHE value.
gocache_owned_path=
gocache_default_path=
gocache_temp_root=
gocache_repo_root=$(cd "$root" && pwd -P)
test "$gocache_repo_root" != / && test -f "$gocache_repo_root/go.mod" || {
    echo "refuse: cache root must be a repository" >&2
    exit 2
}

gocache_cleanup() {
    # Only the exact directory allocated by this run can qualify. Refuse
    # symlinks and a temporary parent redirected since setup, too.
    if [ -n "$gocache_owned_path" ] &&
        [ "$gocache_owned_path" = "$gocache_default_path" ] &&
        [ "${gocache_owned_path%/*}" = "$gocache_temp_root" ] &&
        [ ! -L "$gocache_owned_path" ] &&
        [ "$(cd "$gocache_temp_root" 2>/dev/null && pwd -P)" = "$gocache_temp_root" ]; then
        rm -rf -- "$gocache_owned_path" 2>/dev/null || true
    fi
    # Cache cleanup must not change the mutation check's verdict.
    return 0
}

if [ "${GOCACHE+x}" != x ]; then
    gocache_temp_root=$(cd "${TMPDIR:-/tmp}" && pwd -P) || exit 2
    # A checkout-local TMPDIR would copy the cache into mutation snapshots.
    case "$gocache_temp_root/" in
        "$gocache_repo_root/"*) gocache_temp_root=$(cd /tmp && pwd -P) || exit 2 ;;
    esac
    case "$gocache_temp_root/" in
        "$gocache_repo_root/"*)
            echo "refuse: cache parent must be outside the repository" >&2
            exit 2 ;;
    esac
    gocache_default_path=$(mktemp -d "$gocache_temp_root/keep-gocache.XXXXXXXX") || exit 2
    GOCACHE=$gocache_default_path
    gocache_owned_path=$GOCACHE
fi
export GOCACHE

# Covers exits before scratch setup. Each caller chains gocache_cleanup into
# its existing EXIT trap once that trap has a scratch directory to clean.
trap 'gocache_cleanup' EXIT
