#!/usr/bin/env sh
# Fail-closed guard before the Mesh image is pushed: the commit-SHA tag must not
# exist yet, so a published reference is never moved. Only a registry answer
# that says "not found" counts as absent; any other failure (login refused,
# network, server error) stops the pipeline. Runs in the pinned crane image.
# CRANE_OPTS (e.g. --insecure) is for the local test only; credentials come
# from CI_REGISTRY_* and are never printed.
set -eu
fail() { echo "FAIL check-mesh-tag-absent: $1" >&2; exit 1; }
printf '%s' "${CI_COMMIT_SHA:-}" | grep -Eqx '[0-9a-f]{40}' || fail "CI_COMMIT_SHA is not a full commit"
[ -n "${CI_REGISTRY_IMAGE:-}" ] || fail "CI_REGISTRY_IMAGE is not set"
repo="$CI_REGISTRY_IMAGE/keep-server-mesh"
if [ -n "${CI_REGISTRY_PASSWORD:-}" ]; then
	printf '%s' "$CI_REGISTRY_PASSWORD" | crane auth login "$CI_REGISTRY" -u "$CI_REGISTRY_USER" --password-stdin >/dev/null 2>&1 \
		|| fail "registry login refused"
fi
err=$(mktemp)
# `crane -v` logs every registry response as "<ts> <-- <status> <url> (<time>)".
# Those lines come from the HTTP transport, not from error text, so "absent"
# is decided on them. EVERY logged answer must be expected: 2xx, the auth
# challenge (401 on /v2/), or the 404 for the FULL manifest URL of THIS tag on THIS
# registry host and repository, and that 404 must be present. Any other answer for the target
# manifest URL (a 2xx above all), in any order, blocks the push. A 5xx/403/other 401 on any endpoint,
# a transport failure, or free text that merely mentions a code or a 404 stops
# the pipeline before the push. The client must also report the registry's
# structured not-found code.
# shellcheck disable=SC2086
if found=$(crane ${CRANE_OPTS:-} -v digest "$repo:$CI_COMMIT_SHA" 2>"$err"); then
	rm -f "$err"
	fail "tag $CI_COMMIT_SHA already exists ($found); published references are never moved"
fi
host=${repo%%/*}
repopath=${repo#*/}
# Every logged answer must come from the registry host or, for the token
# exchange, from the CI server host (CI_SERVER_HOST); any other authority fails.
verdict=$(awk -v host="$host" -v srv="${CI_SERVER_HOST:-}" -v path="/v2/$repopath/manifests/$CI_COMMIT_SHA" '
$3 == "<--" && $1 ~ /^[0-9]+\/[0-9]+\/[0-9]+$/ && $2 ~ /^[0-9:]+$/ {
	st = $4; url = $5
	if (st !~ /^[0-9][0-9][0-9]$/) { bad++; next }
	if (url !~ /^https?:\/\/[^\/]+\//) { bad++; next }
	rest = url; sub(/^https?:\/\//, "", rest)
	auth = rest; sub(/\/.*$/, "", auth)
	p = substr(rest, length(auth) + 1)
	if (auth != host && (srv == "" || auth != srv)) { bad++; next }
	if (auth == host && p == path) {
		if (st == "404") nf++; else bad++
		next
	}
	if (st ~ /^2/) next
	if (st == "401" && auth == host && p == "/v2/") next
	bad++
}
END { print (bad == 0 && nf > 0) ? "absent" : "other" }' "$err")
if [ "$verdict" = "absent" ] && grep -Eq '^Error: .*: (MANIFEST_UNKNOWN|NAME_UNKNOWN): ' "$err"; then
	rm -f "$err"
	echo "ok: tag $CI_COMMIT_SHA is absent"
	exit 0
fi
rm -f "$err"
fail "registry did not answer 'not found' for this tag (output withheld)"
