#!/usr/bin/env sh
# Pulls the published Mesh image back by its digest (crane, busybox sh) and
# writes what scripts/mesh_image_receipt.py needs:
#
#   mesh-keep-server           the keep-server ELF out of the image layers
#   image-config.json          the image config of that exact digest
#   mesh-image-pulled.json     digest pulled, digest the tag points at, ELF sha256, job id
#
# Input: mesh-image-publish.json (written by image-publish-mesh) in the
# current directory. The manifest bytes are hashed here, so a registry that
# answers a digest with other content is caught. CRANE_OPTS (e.g. --insecure)
# is for the local test only. Registry credentials come from CI_REGISTRY_*
# and are never printed.
set -eu
fail() { echo "FAIL pull-mesh-image: $1" >&2; exit 1; }
if [ -f mesh-image-auth-only.json ]; then
	echo "auth-only: no image was published, nothing to pull"
	exit 0
fi
pub=${PUBLISH_JSON:-mesh-image-publish.json}
[ -f "$pub" ] || fail "no publish record"
field() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p' "$pub"; }
repo=$(field repository)
tag=$(field tag)
digest=$(field digest)
printf '%s' "$digest" | grep -Eqx 'sha256:[0-9a-f]{64}' || fail "published digest is malformed"
printf '%s' "$tag" | grep -Eqx '[0-9a-f]{40}' || fail "published tag is not a full commit"
printf '%s' "$repo" | grep -Eqx '[a-z0-9.:-]+(/[a-z0-9._-]+)+' || fail "repository is malformed"
[ -z "${CI_REGISTRY_IMAGE:-}" ] || [ "$repo" = "$CI_REGISTRY_IMAGE/keep-server-mesh" ] || fail "repository is outside the project registry"
[ -z "${CI_COMMIT_SHA:-}" ] || [ "$tag" = "$CI_COMMIT_SHA" ] || fail "published tag is not this commit"

if [ -n "${CI_REGISTRY_PASSWORD:-}" ]; then
	printf '%s' "$CI_REGISTRY_PASSWORD" | crane auth login "$CI_REGISTRY" -u "$CI_REGISTRY_USER" --password-stdin >/dev/null 2>&1 \
		|| fail "registry login refused"
fi
# shellcheck disable=SC2086
crane() { command crane ${CRANE_OPTS:-} "$@"; }

tag_digest=$(crane digest "$repo:$tag") || fail "tag $tag cannot be resolved"
crane manifest "$repo@$digest" >manifest.json || fail "digest $digest cannot be pulled"
got="sha256:$(sha256sum manifest.json | cut -d' ' -f1)"
[ "$got" = "$digest" ] || fail "registry served other content for $digest"
grep -q '"manifests"' manifest.json && fail "digest is an index, not a single-platform image"
crane config "$repo@$digest" >image-config.json || fail "image config cannot be pulled"
crane export "$repo@$digest" - | tar -xO usr/local/bin/keep-server >mesh-keep-server 2>/dev/null \
	|| fail "no keep-server binary in the image"
[ -s mesh-keep-server ] || fail "keep-server binary is empty"
chmod +x mesh-keep-server
elf=$(sha256sum mesh-keep-server | cut -d' ' -f1)
printf '{"job_id":"%s","digest":"%s","tag_digest":"%s","elf_sha256":"%s"}\n' \
	"${CI_JOB_ID:-0}" "$got" "$tag_digest" "$elf" >mesh-image-pulled.json
echo "pulled $repo@$digest (tag $tag -> $tag_digest), elf $elf"
