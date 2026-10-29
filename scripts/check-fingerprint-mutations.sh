#!/bin/sh
# Proves the fingerprint tests can fail (threat model 4.1, guards (a)-(c) and
# the key's leak tests): in a scratch copy of the tree, switch off one
# property of pkg/fingerprint at a time and require `go test
# ./pkg/fingerprint/` to go red. A property whose removal
# leaves the tests green is not tested. Exits 0 only if every mutation is
# caught and the real code is green.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"

# Private per-run build cache: on a shared host running several
# clones' go test/build concurrently, a shared $GOCACHE can serve one
# process a build-cache entry another process is evicting mid-write,
# producing a spurious build failure unrelated to any code change
# (seen as "could not import internal/chacha8rand ... no such file").
# Scoping the cache to each run removes the sharing, not just the
# symptom. Respects an already-exported GOCACHE.
. "$root/scripts/lib/gocache.sh"
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace
pkg=pkg/fingerprint

fail=0
# mutate NAME FILE FROM TO: replace the first literal occurrence of FROM with TO.
mutate() {
	name=$1 src=$pkg/$2 from=$3 to=$4
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	if ! awk -v from="$from" -v to="$to" '
		!done && (i = index($0, from)) { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$src" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 120s -count=1 ./$pkg/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		# Red because the mutant does not build is not a failing test.
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

# guard (a): the tag depends on the store's key
mutate fixed-key          fingerprint.go 'm := hmac.New(sha256.New, k.b)' 'm := hmac.New(sha256.New, []byte(domain))'
# guard (b): no bare digest
mutate bare-sha256        fingerprint.go 'm := hmac.New(sha256.New, k.b)' 'm := hmac.New(sha256.New, k.b); m = sha256.New()'
mutate zero-key-accepted  fingerprint.go 'if len(k.b) != KeySize || allZero(k.b) {' 'if false {'
# format: domain, separator, truncation, encoding, strict parse
mutate no-domain          fingerprint.go 'm.Write([]byte(domain))' '_ = domain'
mutate no-separator       fingerprint.go 'm.Write([]byte{0})' 'm.Write(nil)'
mutate long-tag           fingerprint.go 'm.Sum(nil)[:TagBytes]' 'm.Sum(nil)[:TagBytes+1]'
mutate upper-tag          fingerprint.go 'lower(b32.EncodeToString(' '(b32.EncodeToString('
mutate unanchored-format  fingerprint.go '{16})$`)' '{16})`)'
mutate loose-key-id       fingerprint.go 'keyIDRe = regexp.MustCompile(`^[a-z0-9]{1,16}$`)' 'keyIDRe = regexp.MustCompile(`^[a-z0-9:-]{0,32}$`)'
# the key never leaves in a printable form, Parse never echoes
mutate key-printed        fingerprint.go 'return "fingerprint.Key(" + k.id + ")"' 'return "fingerprint.Key(" + k.id + fmt.Sprintf("%x", k.b) + ")"'
mutate parse-echoes       fingerprint.go 'return Parsed{}, ErrMalformed' 'return Parsed{}, fmt.Errorf("%w: %s", ErrMalformed, s)'
mutate newkey-aliases     fingerprint.go 'return Key{id: id, b: c}, nil' '_ = c; return Key{id: id, b: b}, nil'
# the shared-secret MAC is keyed and covers its message
mutate mac-unkeyed        mac.go 'm := hmac.New(sha256.New, key)' 'm := hmac.New(sha256.New, []byte("k")); _ = key'
mutate mac-ignores-msg    mac.go 'm.Write(msg)' 'm.Write(nil)'

if mutation_apply_only; then
	:
elif (cd "$root" && go test -timeout 120s -count=1 ./$pkg/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
