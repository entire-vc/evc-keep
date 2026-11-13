#!/usr/bin/env python3
"""Read-only registry authorization probe for the Mesh image repository.

`allow` runs inside the publisher job `image-publish-mesh` before anything is
written, `deny` in the merge-request job `image-auth-deny-mesh`. With the job
credential it
  * asks the CI server who this job is (/api/v4/job: job, pipeline, project,
    actor), which is server-side context, not the CI_* variables;
  * asks the registry token service separately for the scopes `pull`,
    `pull,push`, `pull,delete` and `pull,*` on exactly the Mesh repository and
    reads the actions inside every issued token.
Every token must keep `pull` (the credential is accepted), name only that
repository and never carry the wildcard. `allow`: the job is the publisher
(job name, push pipeline, project) and push is granted; delete is only
reported, it follows the native rights. `deny`: the job is the merge-request
probe and neither push nor delete is granted.
A failed request, a redirect, a non-JSON or malformed answer, another
repository or a context mismatch fails the probe: it is never an allow or a
deny. Nothing is written. Prints claimed-versus-server context and the
decision, never a credential, a token, a header or a raw answer. Run as
`python3 -I`.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

SCOPES = ("pull", "pull,push", "pull,delete", "pull,*")
EXPECTED = {"allow": {"job": "image-publish-mesh", "source": "push"},
            "deny": {"job": "image-auth-deny-mesh", "source": "merge_request_event"}}


def fail(why):
    print(f"FAIL registry_auth_probe: {why}", file=sys.stderr)
    sys.exit(1)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def get_json(server, path, headers):
    request = urllib.request.Request(server.rstrip("/") + path, headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            if response.status != 200:
                return None
            data = json.loads(response.read(1 << 20))
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def granted(server, name, scope, basic):
    """Actions the registry grants for `scope`; None for anything unusable."""
    query = urllib.parse.urlencode({"service": "container_registry", "scope": f"repository:{name}:{scope}"})
    data = get_json(server, "/jwt/auth?" + query, {"Authorization": f"Basic {basic}"})
    try:
        part = data["token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        access = claims["access"]
        actions = set()
        for entry in access:
            if entry.get("type") != "repository" or entry.get("name") != name:
                return None
            actions.update(str(a) for a in entry.get("actions", []))
    except (TypeError, KeyError, IndexError, ValueError, AttributeError):
        return None
    return actions


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode not in EXPECTED:
        fail("usage: registry_auth_probe.py allow|deny")
    server = os.environ.get("CI_SERVER_URL", "")
    image = os.environ.get("CI_REGISTRY_IMAGE", "")
    credential = os.environ.get("CI_JOB_TOKEN", "")
    if not (server and image and credential and "/" in image):
        fail("CI_SERVER_URL, CI_REGISTRY_IMAGE or CI_JOB_TOKEN is not set")
    parsed = urllib.parse.urlparse(server)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname == "127.0.0.1"):
        fail("the CI server URL is not https")
    name = image.split("/", 1)[1] + "/keep-server-mesh"
    job = get_json(server, "/api/v4/job", {"JOB-TOKEN": credential})
    try:
        pipeline = job["pipeline"]
        context = {"job_id": job["id"], "job_name": job["name"], "pipeline_id": pipeline["id"],
                   "project_id": pipeline["project_id"], "source": pipeline["source"], "actor_id": job["user"]["id"]}
    except (TypeError, KeyError):
        fail("the CI server did not return a job context")
    want = EXPECTED[mode]
    if context["job_name"] != want["job"] or context["source"] != want["source"]:
        fail(f"the server-side job context is not the {mode} context")
    for field, env in (("job_id", "CI_JOB_ID"), ("pipeline_id", "CI_PIPELINE_ID"), ("project_id", "CI_PROJECT_ID")):
        if str(context[field]) != os.environ.get(env, ""):
            fail(f"the server-side {field} differs from the pipeline's own claim")
    basic = base64.b64encode(f"gitlab-ci-token:{credential}".encode()).decode()
    seen = {}
    for scope in SCOPES:
        got = granted(server, name, scope, basic)
        if got is None:
            fail(f"the request for scope {scope} failed or was malformed (not an answer)")
        if "pull" not in got:
            fail("pull was not granted: the credential was not accepted")
        if "*" in got:
            fail("the registry granted the wildcard action")
        seen[scope] = got
    push = "push" in seen["pull,push"]
    delete = "delete" in seen["pull,delete"]
    if push != (mode == "allow"):
        fail(f"push is {'granted' if push else 'refused'}, the {mode} context needs the opposite")
    if mode == "deny" and delete:
        fail("an untrusted pipeline was granted delete")
    print("auth-probe: " + json.dumps({"mode": mode, "server_context": context, "repository": name,
                                       "push": "allow" if push else "deny", "delete": "allow" if delete else "deny",
                                       "wildcard": "deny", "pull": "allow"}, sort_keys=True))


main()
