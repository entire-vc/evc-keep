#!/bin/sh
# Proves that the plaintext boundaries in .golangci.yml can fail: in a
# scratch copy of the tree, add a file that crosses each boundary and
# require golangci-lint to reject it with a finding from that boundary's own
# rule (depguard for imports, forbidigo for Expose calls). Exits 0 only if
# every crossing is caught and every permitted use still passes.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/temp-workspace.sh"
temp_workspace
# golangci-lint's on-disk result cache defaults to a fixed path shared by
# every invocation on this host; a concurrent run from another lane (or an
# earlier probe in this same script racing a stale absolute path) can serve
# a cached result for a tree that no longer exists, producing a spurious
# FAIL unrelated to the code under test. Every invocation below gets its
# own cache for this script run instead.
export GOLANGCI_LINT_CACHE="$work/lint-cache"

fail=0

# Sharding for a GitLab `parallel: N` job: with CI_NODE_TOTAL=N, shard
# CI_NODE_INDEX=i runs the probes whose 0-based call number k satisfies
# k % N == i-1, so N shards together run every probe exactly once. Without
# CI_NODE_TOTAL the script runs every probe. Each probe function starts with
# `shard_take || return 0`; the counter lives in this shell, so a probe
# function must be called directly, never inside a pipeline or $(...),
# where the increment would be lost in a subshell.
# BEGIN shard-setup
shard_total=${CI_NODE_TOTAL:-1}
# Without CI_NODE_TOTAL this is not a parallel job: run every probe whatever
# CI_NODE_INDEX says (a stray index must not narrow or abort an unsharded run).
if [ -z "${CI_NODE_TOTAL:-}" ]; then
	shard_index=1
else
	shard_index=${CI_NODE_INDEX:-1}
fi
for shard_value in "$shard_total" "$shard_index"; do
	case $shard_value in
	'' | 0* | *[!0-9]*)
		echo "refuse: CI_NODE_TOTAL/CI_NODE_INDEX must be positive integers (got '$shard_total'/'$shard_index')" >&2
		exit 2 ;;
	esac
done
if [ "$shard_total" -gt 1 ] && [ -z "${CI_NODE_INDEX:-}" ]; then
	echo "refuse: CI_NODE_TOTAL=$shard_total without CI_NODE_INDEX would run one shard only" >&2
	exit 2
fi
if [ "$shard_index" -gt "$shard_total" ]; then
	echo "refuse: CI_NODE_INDEX=$shard_index is greater than CI_NODE_TOTAL=$shard_total" >&2
	exit 2
fi
# END shard-setup
shard_seq=0
shard_ran=0
# shard_take: number one probe; succeed only when this shard runs it.
shard_take() {
	shard_k=$shard_seq
	shard_seq=$((shard_seq + 1))
	[ $((shard_k % shard_total)) -eq $((shard_index - 1)) ] || return 1
	shard_ran=$((shard_ran + 1))
}

# probe NAME RULE DIR IMPORT [STUBDIR]: the import must be rejected by the
# named depguard rule itself; a rejection by any other rule does not count.
probe() {
	shard_take || return 0
	name=$1 rule=$2 dir=$3 import=$4 stub=${5:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	mkdir -p "$work/tree/$dir"
	pkg=$(basename "$dir")
	case $pkg in keep*) pkg=main ;; esac
	case $dir in web/intake) pkg=intakeweb ;; esac
	cat >"$work/tree/$dir/zz_boundary_probe.go" <<GO
package $pkg

import _ "$import"
GO
	if [ -n "$stub" ] && [ ! -d "$root/$stub" ]; then
		mkdir -p "$work/tree/$stub"
		printf 'package %s\n' "$(basename "$stub")" >"$work/tree/$stub/stub.go"
	fi
	if out=$(cd "$work/tree" && golangci-lint run --enable-only depguard ./... 2>&1); then
		echo "FAIL $name: forbidden import of $import from $dir was not rejected"
		fail=1
	elif printf '%s' "$out" | grep -q "zz_boundary_probe.go.*list '$rule'"; then
		echo "ok   $name: rejected by rule $rule"
	else
		echo "FAIL $name: lint failed, but not by rule $rule on the probe:"
		printf '%s\n' "$out"
		fail=1
	fi
}

# allow NAME DIR IMPORT: the same import from a permitted place must pass,
# otherwise the rule is simply "deny everything" and proves nothing.
allow() {
	shard_take || return 0
	name=$1 dir=$2 import=$3 stub=${4:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	mkdir -p "$work/tree/$dir"
	pkg=$(basename "$dir")
	case $pkg in keep*) pkg=main ;; esac
	case $dir in web/intake) pkg=intakeweb ;; esac
	printf 'package %s\n\nimport _ "%s"\n' "$pkg" "$import" >"$work/tree/$dir/zz_boundary_probe.go"
	if [ -n "$stub" ] && [ ! -d "$root/$stub" ]; then
		mkdir -p "$work/tree/$stub"
		printf 'package %s\n' "$(basename "$stub")" >"$work/tree/$stub/stub.go"
	fi
	if out=$(cd "$work/tree" && golangci-lint run --enable-only depguard ./... 2>&1); then
		echo "ok   $name: allowed"
	else
		echo "FAIL $name: permitted import was rejected:"
		printf '%s\n' "$out"
		fail=1
	fi
}

# call NAME RULE DIR RECV STMT: a forbidigo boundary. The probe file declares
# a parameter of type RECV and runs STMT; it must be rejected by forbidigo
# with a message starting with "RULE:". EXPECT=allow flips it: the same
# call from a permitted place must pass.
call() {
	shard_take || return 0
	name=$1 rule=$2 dir=$3 recv=$4 stmt=$5 expect=${6:-deny}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	mkdir -p "$work/tree/$dir"
	# A receiver from internal/identity needs that package imported, unless
	# the probe sits inside it.
	idimp= iduse=
	case $recv in identity.*)
		idimp='"github.com/entire-vc/evc-keep/internal/identity"'
		iduse='var _ = identity.NewToken' ;;
	esac
	cat >"$work/tree/$dir/zz_boundary_probe.go" <<GO
package $(basename "$dir")

import (
	$idimp
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

var _ = secret.New
var _ = fingerprint.Valid
$iduse

func zzBoundaryProbe(x $recv) { $stmt }
GO
	out=$(cd "$work/tree" && golangci-lint run --enable-only forbidigo ./... 2>&1) && ok=1 || ok=0
	if [ "$expect" = allow ]; then
		if [ $ok = 1 ]; then echo "ok   $name: allowed"; else
			echo "FAIL $name: permitted call was rejected:"; printf '%s\n' "$out"; fail=1; fi
	elif [ $ok = 1 ]; then
		echo "FAIL $name: call in $dir was not rejected"
		fail=1
	elif printf '%s' "$out" | grep -q "zz_boundary_probe.go.*$rule:"; then
		echo "ok   $name: rejected by rule $rule"
	else
		echo "FAIL $name: lint failed, but not by rule $rule on the probe:"
		printf '%s\n' "$out"
		fail=1
	fi
}

# directive NAME BODY: a comment directive that hides a forbidigo finding from
# golangci-lint without touching .golangci.yml. The file plants a secret.Expose
# call outside the plaintext zone with BODY (a line, or a line-directive and
# the call) in front of it. Rejected means one of two things: forbidigo still
# flags the call, or scripts/check-lint-directives.sh (which runs on the same
# scratch tree) exits 1 naming the directive. Anything else is a hole.
# DIR (default internal/catalog) is where the file goes; with SYMLINK=1 the
# body lives in zz_boundary_target.src and zz_boundary_probe.go links to it.
directive() {
	shard_take || return 0
	name=$1 pre=$2 dir=${3:-internal/catalog} symlink=${4:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	mkdir -p "$work/tree/$dir"
	body=zz_boundary_probe.go
	[ -z "$symlink" ] || body=zz_boundary_target.src
	cat >"$work/tree/$dir/$body" <<GO
package catalog

import "github.com/entire-vc/evc-keep/pkg/secret"

func zzBoundaryProbe(x secret.Value) {
$pre
	secret.Expose(x, func([]byte) {})
}
GO
	[ -z "$symlink" ] || ln -s zz_boundary_target.src "$work/tree/$dir/zz_boundary_probe.go"
	if (cd "$work/tree" && golangci-lint run --enable-only forbidigo ./... >/dev/null 2>&1); then lint=pass; else lint=fail; fi
	if [ -x "$work/tree/scripts/check-lint-directives.sh" ]; then
		"$work/tree/scripts/check-lint-directives.sh" "$work/tree" >"$work/guard.out" 2>&1 && guard=pass || guard=fail
	else
		: >"$work/guard.out"
		guard=pass
	fi
	if [ $lint = fail ]; then
		echo "ok   $name: forbidigo still rejects the call"
	elif [ $guard = fail ] && grep -q "zz_boundary_probe.go" "$work/guard.out"; then
		echo "ok   $name: rejected by check-lint-directives.sh"
	else
		echo "FAIL $name: the directive hides a secret.Expose call outside the zone and was not rejected"
		fail=1
	fi
}

# depdirective NAME RULE DIR IMPORT HEAD [TAIL]: a comment directive that
# hides a depguard finding without touching .golangci.yml. The file imports
# IMPORT from DIR, which the depguard rule RULE forbids, with HEAD on the
# line in front of `package` (a //line or /*line */ directive moves every
# position in the file, and a file-level //nolint drops all findings) and
# TAIL after the import (//nolint on the import line). The guard is
# scripts/check-lint-directives.sh on the same scratch tree: ok only when it
# exits 1 naming the probe file. Whether depguard alone still rejects is
# reported but does not count: a guard that is not exercised by the probe
# would stay green when it is switched off.
depdirective() {
	shard_take || return 0
	name=$1 rule=$2 dir=$3 import=$4 head=$5 tail=${6:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	mkdir -p "$work/tree/$dir"
	{
		[ -z "$head" ] || printf '%s\n' "$head"
		printf 'package %s\n\nimport _ "%s"' "$(basename "$dir")" "$import"
		[ -z "$tail" ] || printf ' %s' "$tail"
		printf '\n'
	} >"$work/tree/$dir/zz_boundary_probe.go"
	if out=$(cd "$work/tree" && golangci-lint run --enable-only depguard ./... 2>&1); then
		lint="depguard alone: hidden"
	elif printf '%s' "$out" | grep -q "list '$rule'"; then
		lint="depguard alone: still rejects"
	else
		lint="depguard alone: fails, not by rule $rule"
	fi
	if [ -x "$work/tree/scripts/check-lint-directives.sh" ]; then
		"$work/tree/scripts/check-lint-directives.sh" "$work/tree" >"$work/guard.out" 2>&1 && guard=pass || guard=fail
	else
		: >"$work/guard.out"
		guard=pass
	fi
	if [ $guard = fail ] && grep -q "zz_boundary_probe.go" "$work/guard.out"; then
		echo "ok   $name: rejected by check-lint-directives.sh ($lint)"
	else
		echo "FAIL $name: the directive hides an import of $import from $dir and check-lint-directives.sh did not name it ($lint)"
		fail=1
	fi
}

# The probes run with --enable-only, which switches a linter on regardless
# of the config. So they alone would stay green if a linter were dropped from
# the config's enable list, while the real lint job stopped enforcing it.
# Check the enable list itself.
# It counts as one probe for sharding.
check_enabled() {
	shard_take || return 0
	enabled=$(cd "$root" && golangci-lint linters 2>&1 | sed -n '/^Enabled by your configuration/,/^$/p')
	for l in depguard forbidigo gocritic; do
		if printf '%s\n' "$enabled" | grep -q "^$l:"; then
			echo "ok   enabled: $l"
		else
			echo "FAIL enabled: $l is not enabled by .golangci.yml — the real lint job would not enforce its rules"
			fail=1
		fi
	done
}
check_enabled

# nocompile NAME EXPECT BODY [IMPORT]: BODY, placed in a fresh package, must
# fail to build with an error matching EXPECT. IMPORT, if given, is an extra
# import path added alongside pkg/fingerprint and pkg/secret (BODY is
# expected to reference it, so no unused-import guard is needed).
nocompile() {
	shard_take || return 0
	name=$1 expect=$2 body=$3 extra=${4:-}
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	mkdir -p "$work/tree/internal/zzbypass"
	extraimp=
	[ -n "$extra" ] && extraimp="\"$extra\""
	cat >"$work/tree/internal/zzbypass/zz.go" <<GO
package zzbypass

import (
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
	$extraimp
)

var _ = secret.New
var _ = fingerprint.Valid

$body
GO
	if out=$(cd "$work/tree" && go build ./internal/zzbypass/ 2>&1); then
		echo "FAIL $name: the bypass compiles"
		fail=1
	elif printf '%s' "$out" | grep -q "$expect"; then
		echo "ok   $name: does not compile ($expect)"
	else
		echo "FAIL $name: build failed, but not with '$expect':"
		printf '%s\n' "$out"
		fail=1
	fi
}

# allow_test NAME DIR IMPORT: the import is permitted in a _test.go file.
allow_test() {
	shard_take || return 0
	name=$1 dir=$2 import=$3
	rm -rf "$work/tree"
	mutation_snapshot "$work/tree"
	mkdir -p "$work/tree/$dir"
	printf 'package %s\n\nimport _ "%s"\n' "$(basename "$dir")" "$import" >"$work/tree/$dir/zz_boundary_probe_test.go"
	if out=$(cd "$work/tree" && golangci-lint run --enable-only depguard ./... 2>&1); then
		echo "ok   $name: allowed in tests"
	else
		echo "FAIL $name: permitted test import was rejected:"
		printf '%s\n' "$out"
		fail=1
	fi
}

# Exercise crypto identifiers and method/function aliases with the actual
# type-aware lint job. Filename controls the narrow intake exception.
crypto_call() {
 shard_take || return 0
 name=$1 rule=$2 dir=$3 file=$4 import=$5 stmt=$6 expect=${7:-deny}
 rm -rf "$work/tree"
 mutation_snapshot "$work/tree"
 mkdir -p "$work/tree/$dir"
 imports=$(printf '%s' "$import" | tr ',' '\n')
 if [ -f "$root/$dir/$file" ]; then
  for imported in $imports; do
   if ! grep -Fq "\"$imported\"" "$work/tree/$dir/$file"; then
    awk -v imported="$imported" '/^import \($/ { print; print "\"" imported "\""; next } { print }' \
     "$work/tree/$dir/$file" > "$work/tree/$dir/$file.tmp"
    mv "$work/tree/$dir/$file.tmp" "$work/tree/$dir/$file"
   fi
  done
  printf '\nfunc zzCryptoProbe(b []byte) { %s }\n' "$stmt" >> "$work/tree/$dir/$file"
 else
  {
   printf 'package %s\nimport (\n' "$(basename "$dir")"
   for imported in $imports; do printf '"%s"\n' "$imported"; done
   printf ')\nfunc zzCryptoProbe(b []byte) { %s }\n' "$stmt"
  } > "$work/tree/$dir/$file"
 fi
 out=$(cd "$work/tree" && golangci-lint run --enable-only depguard,forbidigo,gocritic ./... 2>&1) && ok=1 || ok=0
 if [ "$expect" = allow ]; then
  if [ "$ok" = 1 ]; then echo "ok   $name: allowed"; else
   echo "FAIL $name: permitted crypto call was rejected"; printf '%s\n' "$out"; fail=1; fi
 elif [ "$ok" = 0 ] && printf '%s' "$out" | grep -q "$file.*$rule"; then
  echo "ok   $name: rejected by $rule"
 else
  echo "FAIL $name: crypto boundary did not reject its own probe"; printf '%s\n' "$out"; fail=1
 fi
}
crypto_call sha256-in-handshake "list 'mesh-handshake-digest'" internal/api mesh_handshake.go crypto/sha256 '_ = sha256.Sum256(b)'
crypto_call subtle-in-handshake "list 'mesh-handshake-digest'" internal/api mesh_handshake.go crypto/subtle '_ = subtle.ConstantTimeCompare(b,b)'
crypto_call hmac-in-handshake "list 'mesh-handshake-digest'" internal/api mesh_handshake.go crypto/hmac,crypto/sha256 '_ = hmac.New(sha256.New,b)'
crypto_call sha256-in-new-handshake-file "list 'mesh-handshake-digest'" internal/api mesh_handshake_window.go crypto/sha256 '_ = sha256.Sum256(b)'
crypto_call sha256-in-new-mesh-file "list 'mesh-handshake-digest'" internal/api mesh_window.go crypto/sha256 '_ = sha256.Sum256(b)'
crypto_call sha256-in-mesh-go "list 'mesh-handshake-digest'" internal/api mesh.go crypto/sha256 '_ = sha256.Sum256(b)'
crypto_call subtle-in-mesh-ui "list 'mesh-handshake-digest'" internal/api mesh_ui.go crypto/subtle '_ = subtle.ConstantTimeCompare(b,b)'
crypto_call sha256-mesh-nested-lookalike "list 'mesh-handshake-digest'" internal/api/x/internal/api mesh_body_digest.go crypto/sha256 '_ = sha256.Sum256(b)'
crypto_call sha256-body-digest-control "list 'mesh-handshake-digest'" internal/api mesh_body_digest.go crypto/sha256 '_ = sha256.Sum256(b)' allow
crypto_call sha256-handshake-test-control "list 'mesh-handshake-digest'" internal/api mesh_handshake_probe_test.go crypto/sha256 '_ = sha256.Sum256(b)' allow
crypto_call circl-from-builtin "list 'intake-circl'" internal/builtin zz_crypto_probe.go github.com/cloudflare/circl/hpke '_ = hpke.KDF_HKDF_SHA256.Extract(b,nil)'
crypto_call circl-delivery-nested-lookalike "list 'intake-circl'" internal/api/internal/builtin delivery.go github.com/cloudflare/circl/hpke '_ = hpke.KEM_X25519_HKDF_SHA256'
crypto_call circl-nested-lookalike "list 'intake-circl'" internal/api/internal/builtin intake_probe.go github.com/cloudflare/circl/hpke '_ = hpke.KEM_X25519_HKDF_SHA256'
crypto_call kdf-extract intake-kdf: internal/builtin intake_probe.go github.com/cloudflare/circl/hpke '_ = hpke.KDF_HKDF_SHA256.Extract(b,nil)'
crypto_call kdf-expand intake-kdf: internal/builtin intake_probe.go github.com/cloudflare/circl/hpke '_ = hpke.KDF_HKDF_SHA256.Expand(b,nil,32)'
crypto_call kdf-method-alias intake-kdf: internal/builtin intake_probe.go github.com/cloudflare/circl/hpke 'var k hpke.KDF = 1; f := k.Extract; _ = f(b,nil)'
crypto_call circl-delivery-control "list 'intake-circl'" internal/builtin delivery.go github.com/cloudflare/circl/hpke '_ = hpke.KEM_X25519_HKDF_SHA256' allow
crypto_call kdf-delivery-denied intake-kdf: internal/builtin delivery.go github.com/cloudflare/circl/hpke '_ = hpke.KDF_HKDF_SHA256.Extract(b,nil)'
crypto_call kdf-intake-control intake-kdf: internal/builtin intake.go github.com/cloudflare/circl/hpke '_ = hpke.KDF_HKDF_SHA256.Extract(b,nil)' allow
crypto_call kdf-test-control intake-kdf: internal/builtin intake_probe_test.go github.com/cloudflare/circl/hpke '_ = hpke.KDF_HKDF_SHA256.Extract(b,nil)' allow
crypto_call sign-ed25519 descriptor-sign: internal/builtin zz_crypto_probe.go crypto/ed25519 '_ = ed25519.Sign(ed25519.PrivateKey(b),b)'
crypto_call sign-ed25519-alias descriptor-sign: internal/builtin zz_crypto_probe.go crypto/ed25519 'f := ed25519.Sign; _ = f(ed25519.PrivateKey(b),b)'
crypto_call sign-ecdsa descriptor-sign: internal/builtin zz_crypto_probe.go crypto/ecdsa '_,_,_ = ecdsa.Sign(nil,new(ecdsa.PrivateKey),b)'
crypto_call sign-rsa descriptor-sign: internal/builtin zz_crypto_probe.go crypto/rsa '_,_ = rsa.SignPKCS1v15(nil,new(rsa.PrivateKey),0,b)'
crypto_call sign-key-method descriptor-sign: internal/builtin zz_crypto_probe.go crypto/ed25519 '_,_ = ed25519.PrivateKey(b).Sign(nil,b,nil)'
crypto_call sign-interface descriptor-sign: internal/builtin zz_crypto_probe.go crypto 'var s crypto.Signer; _,_ = s.Sign(nil,b,nil)'
crypto_call sign-interface-alias descriptor-sign: internal/builtin zz_crypto_probe.go crypto 'var s crypto.Signer; f := s.Sign; _,_ = f(nil,b,nil)'
crypto_call sign-interface-expression descriptor-sign: internal/builtin zz_crypto_probe.go crypto 'var s crypto.Signer; f := crypto.Signer.Sign; _,_ = f(s,nil,b,nil)'
crypto_call sign-interface-nested-lookalike descriptor-sign: internal/api/pkg/runnerproto zz_crypto_probe.go crypto 'var s crypto.Signer; _,_ = s.Sign(nil,b,nil)'
crypto_call sign-structural-direct descriptor-sign: internal/builtin zz_crypto_probe.go crypto,crypto/ed25519,io 'var s interface { Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte,error) } = ed25519.PrivateKey(b); _,_ = s.Sign(nil,b,crypto.Hash(0))'
crypto_call sign-structural-nested-lookalike descriptor-sign: internal/api/pkg/runnerproto zz_crypto_probe.go crypto,crypto/ed25519,io 'var s interface { Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte,error) } = ed25519.PrivateKey(b); _,_ = s.Sign(nil,b,crypto.Hash(0))'
crypto_call sign-structural-alias descriptor-sign: internal/builtin zz_crypto_probe.go crypto,crypto/ed25519,io 'var s interface { Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte,error) } = ed25519.PrivateKey(b); f := s.Sign; _,_ = f(nil,b,crypto.Hash(0))'
crypto_call sign-structural-expression descriptor-sign: internal/builtin zz_crypto_probe.go crypto,crypto/ed25519,io 'type signer interface { Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte,error) }; var s signer = ed25519.PrivateKey(b); f := signer.Sign; _,_ = f(s,nil,b,crypto.Hash(0))'
crypto_call sign-org-job-nested-lookalike descriptor-sign: internal/api/internal/builtin/orgpki sign_job.go crypto/ed25519 '_ = ed25519.Sign(ed25519.PrivateKey(b),b)'
crypto_call sign-org-job-control descriptor-sign: internal/builtin/orgpki sign_job.go crypto/ed25519 '_ = ed25519.Sign(ed25519.PrivateKey(b),b)' allow
crypto_call sign-structural-intake-control descriptor-sign: internal/builtin intake.go crypto,crypto/ed25519,io 'var s interface { Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte,error) } = ed25519.PrivateKey(b); _,_ = s.Sign(nil,b,crypto.Hash(0))' allow
crypto_call sign-structural-job-control descriptor-sign: pkg/runnerproto zz_crypto_probe.go crypto,crypto/ed25519,io 'var s interface { Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte,error) } = ed25519.PrivateKey(b); _,_ = s.Sign(nil,b,crypto.Hash(0))' allow
crypto_call sign-structural-test-control descriptor-sign: internal/builtin zz_crypto_probe_test.go crypto,crypto/ed25519,io 'var s interface { Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte,error) } = ed25519.PrivateKey(b); _,_ = s.Sign(nil,b,crypto.Hash(0))' allow
crypto_call sign-interface-intake-control descriptor-sign: internal/builtin intake.go crypto 'var s crypto.Signer; _,_ = s.Sign(nil,b,nil)' allow
crypto_call sign-interface-job-control descriptor-sign: pkg/runnerproto zz_crypto_probe.go crypto 'var s crypto.Signer; _,_ = s.Sign(nil,b,nil)' allow
crypto_call sign-interface-test-control descriptor-sign: internal/builtin zz_crypto_probe_test.go crypto 'var s crypto.Signer; _,_ = s.Sign(nil,b,nil)' allow
crypto_call sign-intake-control descriptor-sign: internal/builtin intake.go crypto/ed25519 '_ = ed25519.Sign(ed25519.PrivateKey(b),b)' allow
crypto_call sign-job-control descriptor-sign: pkg/runnerproto zz_crypto_probe.go crypto/ed25519 '_ = ed25519.Sign(ed25519.PrivateKey(b),b)' allow
crypto_call sign-test-control descriptor-sign: internal/builtin zz_crypto_probe_test.go crypto/ed25519 '_ = ed25519.Sign(ed25519.PrivateKey(b),b)' allow

m=github.com/entire-vc/evc-keep
allow  secret-from-runner internal/runner $m/pkg/secret
probe  secret-from-api   secret-value internal/api   $m/pkg/secret
probe  secret-from-mcp   secret-value internal/mcp   $m/pkg/secret
probe  secret-from-audit secret-value internal/audit $m/pkg/secret
probe  secret-from-intake secret-value internal/intake $m/pkg/secret
probe  secret-from-intake-page secret-value web/intake $m/pkg/secret
probe  secret-from-cli   secret-value cmd/keep       $m/pkg/secret
probe  secret-from-runnerproto runnerproto-no-plaintext pkg/runnerproto $m/pkg/secret
allow_test secret-in-runnerproto-tests pkg/runnerproto $m/pkg/secret
probe  sealer-from-api   sealer       internal/api   $m/internal/builtin/sealer internal/builtin/sealer

# Threat model 4.1, guard (d): no digest of a plaintext value outside
# pkg/fingerprint. Hashing stays legal where no plaintext is reachable.
probe  sha256-in-sealer   plaintext-digest internal/builtin/sealer crypto/sha256
probe  hmac-in-runner     plaintext-digest internal/runner         crypto/hmac
probe  fnv-in-provider    plaintext-digest pkg/provider/memory     hash/fnv
probe  md5-in-secret      plaintext-digest pkg/secret              crypto/md5
probe  sha3-in-targets    plaintext-digest internal/targets        crypto/sha3
allow  sha256-in-fingerprint pkg/fingerprint crypto/sha256
allow  sha256-in-audit       internal/audit  crypto/sha256

# Plaintext zone: who may read a value's bytes, and a fingerprint key's.
call   expose-from-catalog   expose-callers internal/catalog  secret.Value 'secret.Expose(x, func([]byte) {})'
call   expose-func-value     expose-callers internal/identity secret.Value 'f := secret.Expose; f(x, func([]byte) {})'
call   expose-from-runner    expose-callers internal/runner   secret.Value 'secret.Expose(x, func([]byte) {})' allow
call   expose-from-targets   expose-callers internal/targets  secret.Value 'secret.Expose(x, func([]byte) {})' allow
call   fpkey-from-provider   fpkey-expose   pkg/provider/memory fingerprint.Key 'fingerprint.ExposeKey(x, func([]byte) {})'
call   fpkey-func-value      fpkey-expose   internal/catalog  fingerprint.Key 'f := fingerprint.ExposeKey; f(x, func([]byte) {})'
call   fpkey-from-sealer     fpkey-expose   internal/builtin/sealer fingerprint.Key 'fingerprint.ExposeKey(x, func([]byte) {})' allow
# internal/targets computes fingerprints only via fingerprint.Compute, never
# by reaching into the key's own bytes with ExposeKey — this is the boundary
# that keeps it that way.
call   fpkey-from-targets    fpkey-expose   internal/targets  fingerprint.Key 'fingerprint.ExposeKey(x, func([]byte) {})'

# A path fragment matching a zone name, nested under an UNRELATED package,
# used to inherit the zone's forbidigo exclusion under the old `(^|/)`
# prefix — the same shape as the test/security hole fixed in 168d2bb
# ("a smuggled internal/api/test/security/helper.go"). Root-anchored now:
# the exclusion covers pkg/secret/**, not .../pkg/secret/** wherever nested.
call   expose-nested-lookalike expose-callers internal/api/pkg/secret        secret.Value    'secret.Expose(x, func([]byte) {})'
call   fpkey-nested-lookalike  fpkey-expose   internal/api/internal/builtin fingerprint.Key 'fingerprint.ExposeKey(x, func([]byte) {})'

# Positive controls: the real subpackages that DO need the zone's trust
# (sealer's crypto, providertest's conformance fixtures) must stay allowed
# after root-anchoring — the fix must not also bound nesting depth.
call   expose-from-sealer        expose-callers internal/builtin/sealer   secret.Value  'secret.Expose(x, func([]byte) {})' allow
call   expose-from-provider-test expose-callers pkg/provider/providertest secret.Value  'secret.Expose(x, func([]byte) {})' allow

# Identity tokens: their text leaves the Token type only in internal/identity.
call   reveal-from-api       token-reveal   internal/api      identity.Token '_ = identity.Reveal(x)'
call   reveal-func-value     token-reveal   internal/catalog  identity.Token 'f := identity.Reveal; _ = f(x)'
call   reveal-in-identity    token-reveal   internal/identity Token          '_ = Reveal(x)' allow
# A subpackage of internal/identity is a different import path with its own
# forbidigo scope; the exclusion above is anchored to files directly in
# internal/identity (`[^/]+\.go$`) precisely so it does not quietly extend
# trust to a subpackage that could re-export Reveal.
call   reveal-in-identity-subpkg token-reveal internal/identity/zz identity.Token '_ = identity.Reveal(x)'
# The test/security exclusion covers attack _test.go files, not the package
# wholesale: a non-test file there (a smuggled helper) and any nested
# "test/security" directory outside the real top-level one must still be
# rejected — a broader exclusion once let both through
# (`call`'s probe file is never named *_test.go).
call   reveal-nontest-in-security token-reveal test/security             identity.Token '_ = identity.Reveal(x)'
call   reveal-nested-test-security token-reveal internal/api/test/security identity.Token '_ = identity.Reveal(x)'

# Expose is a package function, not a method, so it cannot be reached through
# an interface or a generic constraint, where forbidigo would no longer see
# the type. These must not even compile.
nocompile iface-value    'missing method Expose' 'type exposer interface{ Expose(func([]byte)) }
func zzBypass(v secret.Value) { var e exposer = v; e.Expose(func([]byte) {}) }'
nocompile generic-value  'cannot infer F' 'func zzG[F ~func([]byte)](e interface{ Expose(F) }) { e.Expose(F(func([]byte) {})) }
func zzBypass(v secret.Value) { zzG(v) }'
nocompile iface-fpkey    'missing method Expose' 'type exposer interface{ Expose(func([]byte)) }
func zzBypass(k fingerprint.Key) { var e exposer = k; e.Expose(func([]byte) {}) }'
# Reveal is a package function of internal/identity for the same reason:
# identity.Token has no Reveal() method for an interface or generic
# constraint to catch, so neither can reach the token's text.
nocompile iface-token    'missing method Reveal' 'type revealer interface{ Reveal() string }
func zzBypass(t identity.Token) { var r revealer = t; _ = r.Reveal() }' github.com/entire-vc/evc-keep/internal/identity

# Zone internals: an export from them cannot reach server code.
probe  runner-from-catalog  zone-internals internal/catalog $m/internal/runner  internal/runner
probe  targets-from-api     zone-internals internal/api     $m/internal/targets internal/targets
probe  builtin-from-catalog zone-internals internal/catalog $m/internal/builtin internal/builtin
probe  svctoken-from-api    zone-internals internal/api     $m/pkg/provider/svctoken
probe  svctoken-from-mcp    zone-internals internal/mcp     $m/pkg/provider/svctoken
probe  svctoken-from-audit  zone-internals internal/audit   $m/pkg/provider/svctoken
probe  svctoken-from-cli    zone-internals cmd/keep         $m/pkg/provider/svctoken
allow  svctoken-from-server cmd/keep-server $m/pkg/provider/svctoken
allow  runner-from-cmd      cmd/keep-runner $m/internal/runner internal/runner
allow  targets-from-cmd     cmd/keep-runner $m/internal/targets internal/targets

# Exclusion globs written `!**/zone/**` also match the zone name nested under
# an unrelated package, handing that lookalike the zone's trust (the same
# shape as the forbidigo holes above). One probe per exclusion glob.
probe  sealer-nested-builtin      sealer           internal/api/internal/builtin $m/internal/builtin/sealer internal/builtin/sealer
probe  digest-nested-fingerprint  plaintext-digest internal/runner/pkg/fingerprint crypto/sha256
probe  zone-nested-secret         zone-internals   internal/api/pkg/secret       $m/internal/runner  internal/runner
probe  zone-nested-fingerprint    zone-internals   internal/api/pkg/fingerprint  $m/internal/runner  internal/runner
probe  zone-nested-provider       zone-internals   internal/api/pkg/provider     $m/internal/runner  internal/runner
probe  zone-nested-builtin        zone-internals   internal/api/internal/builtin $m/internal/runner  internal/runner
probe  zone-nested-runner         zone-internals   internal/api/internal/runner  $m/internal/targets internal/targets
probe  zone-nested-targets        zone-internals   internal/api/internal/targets $m/internal/runner  internal/runner
probe  zone-nested-keep-server    zone-internals   internal/api/cmd/keep-server  $m/internal/runner  internal/runner
probe  zone-nested-keep-runner    zone-internals   internal/api/cmd/keep-runner  $m/internal/targets internal/targets
# Positive controls: the real zone subpackages keep their trust.
allow  zone-real-sealer-to-runner internal/builtin/sealer $m/internal/runner internal/runner
allow  zone-real-provider-memory  pkg/provider/memory     $m/internal/runner internal/runner

# reflect and unsafe read unexported fields; production code may not import them.
probe  reflect-in-catalog no-reflect internal/catalog reflect
probe  unsafe-in-api      no-reflect internal/api     unsafe
allow_test reflect-in-test internal/api reflect
# Directives that move or silence a forbidigo finding. A //line directive
# makes golangci-lint report the call at the path the directive names, and the
# zone's path exclusion then drops it; //nolint drops it directly. Both are
# comments, so neither touches .golangci.yml.
directive expose-line-directive '//line ../runner/zz.go:1'
directive expose-nolint '	//nolint:forbidigo'
directive expose-nolint-bare '	//nolint'
directive expose-nolint-list '	//nolint:gosec,forbidigo // reason'
directive expose-line-directive-block '/*line ../runner/zz.go:1*/'
directive expose-nolint-space '	//nolint: forbidigo'
directive expose-nolint-upper '	//nolint:FORBIDIGO'
directive expose-nolint-list-space '	//nolint:gosec, forbidigo'
# Go compiles node_modules and symlinked .go files; the guard must read them.
directive expose-line-node-modules '//line ../../runner/zz.go:1' internal/catalog/node_modules
directive expose-line-symlink '//line ../runner/zz.go:1' internal/catalog symlink

# The same directives against depguard: //nolint on the import line or in
# front of package silences the rule, and a //line or /*line */ directive in
# front of package moves the import out of the rule's files (the path must
# leave the rule's directory: //line zz.go:1 stays inside it). golangci-lint
# ignores /*nolint*/, but the guard rejects it all the same.
depdirective secret-value-nolint-depguard secret-value internal/api $m/pkg/secret '' '//nolint:depguard'
depdirective secret-value-nolint-bare secret-value internal/api $m/pkg/secret '' '//nolint'
depdirective secret-value-nolint-all secret-value internal/api $m/pkg/secret '' '//nolint:all'
depdirective secret-value-nolint-list secret-value internal/api $m/pkg/secret '' '//nolint:gosec, depguard // reason'
depdirective secret-value-nolint-upper secret-value internal/api $m/pkg/secret '' '//nolint:DEPGUARD'
depdirective secret-value-nolint-block secret-value internal/api $m/pkg/secret '' '/*nolint:depguard*/'
depdirective secret-value-nolint-file secret-value internal/api $m/pkg/secret '//nolint:depguard'
depdirective secret-value-line-before-package secret-value internal/api $m/pkg/secret '//line ../../zz.go:1'
depdirective secret-value-line-block-before-package secret-value internal/api $m/pkg/secret '/*line ../../zz.go:1*/'
depdirective plaintext-digest-nolint-depguard plaintext-digest internal/builtin/sealer crypto/sha256 '' '//nolint:depguard'
depdirective plaintext-digest-nolint-bare plaintext-digest internal/builtin/sealer crypto/sha256 '' '//nolint'
depdirective plaintext-digest-nolint-all plaintext-digest internal/builtin/sealer crypto/sha256 '' '//nolint:all'
depdirective plaintext-digest-nolint-list plaintext-digest internal/builtin/sealer crypto/sha256 '' '//nolint:gosec, depguard // reason'
depdirective plaintext-digest-nolint-upper plaintext-digest internal/builtin/sealer crypto/sha256 '' '//nolint:DEPGUARD'
depdirective plaintext-digest-nolint-block plaintext-digest internal/builtin/sealer crypto/sha256 '' '/*nolint:depguard*/'
depdirective plaintext-digest-nolint-file plaintext-digest internal/builtin/sealer crypto/sha256 '//nolint:depguard'
depdirective plaintext-digest-line-before-package plaintext-digest internal/builtin/sealer crypto/sha256 '//line ../../../zz.go:1'
depdirective plaintext-digest-line-block-before-package plaintext-digest internal/builtin/sealer crypto/sha256 '/*line ../../../zz.go:1*/'

echo "shard $shard_index/$shard_total ran $shard_ran probes (of $shard_seq)"
if [ "$shard_ran" -eq 0 ]; then
	echo "FAIL shard $shard_index/$shard_total ran no probe"
	fail=1
fi
exit $fail
