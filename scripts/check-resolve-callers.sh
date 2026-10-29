#!/bin/sh
# Guard for the one place Keep returns a stored value to a caller that is not a
# runner (POST /orgs/{org}/mesh/secrets/{ref}/resolve): any use of the
# ResolveSecret selector in non-test code must sit inside handleResolveSecret,
# except the one-line delegating adapter in cmd/keep-server/app. A second reader of
# the plaintext bytes, or a method value taken from the vault, is a failure.
# Usage: scripts/check-resolve-callers.sh [root]   (default: the repo root)
set -eu
root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
test -f "$root/go.mod" || { echo "refuse: $root does not look like the repo root" >&2; exit 2; }
out=$(cd "$root" && find . \( -path ./.git -o -path ./vendor \) -prune -o -name '*.go' ! -name '*_test.go' -print | LC_ALL=C sort |
	while read -r f; do
		awk -v file="$f" '
			/^func / {
				cur = $0
				if (cur ~ /^func \(m \*meshRoutes\) handleResolveSecret\(/) print "HANDLER " file
				if (cur ~ /^func \(v meshVault\) ResolveSecret\(/) print "ADAPTERDECL " file
			}
			/^[a-z]/ && !/^func / { cur = "" }
			{
				# One lexer pass: strings, runes, raw strings and comments are blanked in order,
				# so a quote inside a comment (or a comment marker inside a string) cannot hide code.
				line = $0; out = ""; n = length(line); i = 1
				while (i <= n) {
					c = substr(line, i, 1); d = substr(line, i, 2)
					if (inblock) { if (d == "*/") { inblock = 0; i += 2; out = out " " } else i++; continue }
					if (inraw) { if (c == "`") { inraw = 0; out = out "``" } i++; continue }
					if (d == "//") break
					if (d == "/*") { inblock = 1; i += 2; continue }
					if (c == "`") { inraw = 1; i++; continue }
					if (c == "\"" || c == "\x27") {
						q = c; i++
						while (i <= n && substr(line, i, 1) != q) { if (substr(line, i, 1) == "\\") i++; i++ }
						i++; out = out q q; continue
					}
					out = out c; i++
				}
				line = out
				# A selector may be split after the dot: "v.\n\tResolveSecret(".
				broken = (prev ~ /\.[ \t]*$/ && line ~ /^[ \t]*ResolveSecret/)
				if (line ~ /[^ \t]/) prev = line
				if (line !~ /\.[ \t]*ResolveSecret/ && !broken) next
				if (cur ~ /^func \(m \*meshRoutes\) handleResolveSecret\(/ && file == "./internal/api/mesh.go") { print "ALLOWED " file ":" NR; next }
				if (cur ~ /^func \(v meshVault\) ResolveSecret\(/ && file == "./cmd/keep-server/app/main.go") { print "ADAPTER " file ":" NR; next }
				print "FORBIDDEN " file ":" NR ": " $0
			}' "$f"
	done)
bad=$(printf '%s\n' "$out" | grep '^FORBIDDEN' || true)
if [ -n "$bad" ]; then
	echo "FAIL: ResolveSecret used outside handleResolveSecret:" >&2
	printf '%s\n' "$bad" >&2
	exit 1
fi
# Exactly one handler and one adapter, each in its own file.
if [ "$(printf '%s\n' "$out" | grep -c '^HANDLER ')" != 1 ] || ! printf '%s\n' "$out" | grep -qx 'HANDLER ./internal/api/mesh.go' ||
	[ "$(printf '%s\n' "$out" | grep -c '^ADAPTERDECL ')" != 1 ] || ! printf '%s\n' "$out" | grep -qx 'ADAPTERDECL ./cmd/keep-server/app/main.go'; then
	echo "FAIL: ResolveSecret handler/adapter must be declared exactly once, in internal/api/mesh.go and cmd/keep-server/app/main.go (second ResolveSecret declaration?):" >&2
	printf '%s\n' "$out" | grep -E '^(HANDLER|ADAPTERDECL) ' >&2
	exit 1
fi
# Positive control: the guard must see the one legitimate call.
if ! printf '%s\n' "$out" | grep -q '^ALLOWED '; then
	echo "FAIL: handleResolveSecret no longer calls ResolveSecret; the guard cannot see it, update it" >&2
	exit 1
fi
echo "ok   ResolveSecret has one caller: handleResolveSecret ($(printf '%s\n' "$out" | grep -c '^ADAPTER ') adapter)"
