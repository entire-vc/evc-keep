#!/usr/bin/env sh
# Pushes the kaniko-built Mesh image tarball to the project registry under the
# full commit SHA, in ONE job: the tag must be absent (check-mesh-tag-absent.sh)
# and the push follows in the same script, inside the job's resource group, so
# two pipelines or a retry cannot interleave between the check and the push.
# Writes mesh-image-publish.json for the pull and receipt jobs. Registry
# credentials come from CI_REGISTRY_* and are never printed. CRANE_OPTS is for
# the local test only.
set -eu
fail() { echo "FAIL publish-mesh-image: $1" >&2; exit 1; }
tar_file=${MESH_IMAGE_TAR:-mesh-image.tar}
[ -s "$tar_file" ] || fail "no image tarball"
printf '%s' "${CI_COMMIT_SHA:-}" | grep -Eqx '[0-9a-f]{40}' || fail "CI_COMMIT_SHA is not a full commit"
printf '%s' "${CI_COMMIT_TIMESTAMP:-}" | grep -Eqx '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})' \
	|| fail "CI_COMMIT_TIMESTAMP is not RFC 3339"
[ -n "${CI_REGISTRY_IMAGE:-}" ] || fail "CI_REGISTRY_IMAGE is not set"
repo="$CI_REGISTRY_IMAGE/keep-server-mesh"

# Authorization first: the CI server and the registry must show this job as the
# publisher and grant push on the Mesh repository (the probe below, `allow`:
# server-side context, push allowed, delete reported, wildcard absent), before
# anything is checked or pushed.
python3 -I "$(dirname "$0")/registry_auth_probe.py" allow || fail "registry authorization probe refused"
# Default is auth-only: nothing is written to the registry unless the protected
# project variable KEEP_MESH_IMAGE_WRITE_SHA names exactly this commit. An absent,
# empty or different value (a stale opt-in for an older commit included) stops
# here with success and writes only the auth-only marker: no image, no digest,
# no receipt. Publishing a commit is therefore an explicit act: set the variable
# to its full SHA, then retry this job.
if [ "${KEEP_MESH_IMAGE_WRITE_SHA:-}" != "$CI_COMMIT_SHA" ]; then
	printf '{"mode":"auth-only","source_sha":"%s"}\n' "$CI_COMMIT_SHA" >mesh-image-auth-only.json
	echo "auth-only: registry push authorization verified; no image was written (KEEP_MESH_IMAGE_WRITE_SHA does not name $CI_COMMIT_SHA)"
	exit 0
fi
sh "$(dirname "$0")/check-mesh-tag-absent.sh"
if [ -n "${CI_REGISTRY_PASSWORD:-}" ]; then
	printf '%s' "$CI_REGISTRY_PASSWORD" | crane auth login "$CI_REGISTRY" -u "$CI_REGISTRY_USER" --password-stdin >/dev/null 2>&1 \
		|| fail "registry login refused"
fi
# shellcheck disable=SC2086
out=$(crane ${CRANE_OPTS:-} push "$tar_file" "$repo:$CI_COMMIT_SHA") || fail "push refused"
digest=${out##*@}
printf '%s' "$digest" | grep -Eqx 'sha256:[0-9a-f]{64}' || fail "push reported no digest"
# shellcheck disable=SC2086
[ "$(crane ${CRANE_OPTS:-} digest "$repo:$CI_COMMIT_SHA")" = "$digest" ] || fail "tag does not point at the pushed digest"
printf '{"source_sha":"%s","pipeline_id":"%s","job_id":"%s","repository":"%s","tag":"%s","digest":"%s","build_time":"%s"}\n' \
	"$CI_COMMIT_SHA" "${CI_PIPELINE_ID:-0}" "${CI_JOB_ID:-0}" "$repo" "$CI_COMMIT_SHA" "$digest" "$CI_COMMIT_TIMESTAMP" >mesh-image-publish.json
echo "published $repo@$digest from $CI_COMMIT_SHA"
