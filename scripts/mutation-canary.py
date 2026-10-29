#!/usr/bin/env python3
"""One explicit tenancy-body canary. Every uncertain input runs the command."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = ROOT / "mutation-canary.decision"
ALWAYS = {"public-hygiene", "sealer", "fingerprint", "execpolicy", "providertest",
          "identity", "identity-attack", "audit", "loghygiene", "targets",
          "runnerproto", "deploy", "discovery", "health", "loop", "runner-enroll", "execrun",
          "resolve-callers"}


def require(condition):
    if not condition:
        raise ValueError("canary binding not proven")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, timeout=10).decode().strip()


def selector():
    spec = importlib.util.spec_from_file_location("mutation_selector", ROOT / "scripts/mutation-select.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def descriptor(context):
    d = json.loads(context.get("KEEP_MUTATION_CANARY", ""))
    require(d["schema"] == "keep-tenancy-canary-v1")
    require(d["omitted_jobs"] == ["tenancy-mutations"])
    require(context.get("CI_PIPELINE_SOURCE") == "merge_request_event")
    require(context.get("CI_PROJECT_ID") == "70" == str(d["project_id"]))
    require(context.get("CI_MERGE_REQUEST_IID") == str(d["mr_iid"]))
    require(context.get("CI_MERGE_REQUEST_EVENT_TYPE") == "detached")
    require(not context.get("KEEP_FULL_CI"))
    require(bool(context.get("CI_DEFAULT_BRANCH")))
    require(context.get("CI_COMMIT_BRANCH") != context["CI_DEFAULT_BRANCH"])
    require(re.fullmatch(r"[1-9][0-9]*", str(d["mr_iid"])) is not None)
    require(re.fullmatch(r"[1-9][0-9]*", context.get("CI_PIPELINE_ID", "")) is not None)
    require(context.get("CI_COMMIT_SHA") == d["head"])
    require(context.get("CI_MERGE_REQUEST_DIFF_BASE_SHA") == d["base"])
    for key in ("head", "base", "merge_base", "source_tree"):
        require(re.fullmatch(r"[0-9a-f]{40}", d[key]) is not None)
    for key in ("map_sha256", "selector_sha256", "graph_sha256", "working_tracked_sha256",
                "mutation_inventory_sha256", "go_binary_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", d[key]) is not None)
    # An independently reviewed exact-SHA full reference is a prerequisite,
    # not something inferred from a green omission job or queried with tokens.
    require(d["full_reference"]["sha"] == d["head"])
    require(re.fullmatch(r"[1-9][0-9]*", str(d["full_reference"]["pipeline_id"])) is not None)
    require(str(d["full_reference"]["pipeline_id"]) != context["CI_PIPELINE_ID"])
    require(d["full_reference"]["status"] == "success")
    return d


def validate(d, report, context):
    require(report["mode"] == "graph" and report["all"] is False)
    p, graph = report["provenance"], report["graph"]
    require(p["schema"] == "keep-mutation-shadow-provenance-v1")
    require(p["input_mode"] == "git-diff")
    require(p.get("status") not in ("error", "unknown"))
    for key in ("head", "base"):
        require(p[key]["commit"] == d[key])
    for key in ("merge_base", "source_tree", "working_tracked_sha256", "map_sha256",
                "selector_sha256", "mutation_inventory_sha256"):
        require(p[key] == d[key])
    require(p["checkout_commit"] == d["head"] == git("rev-parse", "HEAD"))
    require(git("rev-parse", "HEAD^{tree}") == d["source_tree"])
    require(git("merge-base", d["base"], d["head"]) == d["merge_base"])
    require(git("diff", "--name-only", "HEAD", "--") == "")
    require(graph["status"] == "observed")
    require(graph["sha256"] == d["graph_sha256"] == canonical(graph["packages"]))
    listing = graph["listing"]
    require(listing["status"] == "observed" and listing["exit_code"] == 0)
    require(listing["source_binding_status"] == "observed-stable")
    require(listing["source_before_sha256"] == listing["source_after_sha256"] == d["working_tracked_sha256"])
    require(listing["argv"] == ["go", "list", "-json", "./..."])
    require(listing["target"] == {"GOOS": "linux", "GOARCH": "amd64", "GOFLAGS": "-buildvcs=false", "CGO_ENABLED": "0"})
    require(listing["version"] == d["go_version"])
    require(listing["binary_sha256"] == d["go_binary_sha256"])
    require(re.fullmatch(r"go version go1\.25\.14 linux/amd64", d["go_version"]) is not None)
    module = selector()
    require(canonical(module.source_snapshot()) == d["working_tracked_sha256"])
    require(digest((ROOT / "scripts/mutation-select.py").read_bytes()) == d["selector_sha256"])
    require(digest((ROOT / "scripts/mutation-select.map").read_bytes()) == d["map_sha256"])
    inventory = {str(f.relative_to(ROOT)): digest(f.read_bytes())
                 for f in sorted((ROOT / "scripts").glob("*mutations.sh"))}
    require(canonical(inventory) == d["mutation_inventory_sha256"])
    files, links = module.diff_listing(d["base"], d["head"])
    # The first canary is one actual carriers leaf, not every graph route.
    require(files and not links and all(re.fullmatch(r"internal/carriers/[^/]+\.go", f) for f in files))
    require(report["changed"] == files)
    mapping = module.Map((ROOT / "scripts/mutation-select.map").read_text())
    require({s for s, v in mapping.scripts.items() if v["always"]} == ALWAYS)
    require(len(mapping.scripts) == 48)  # pinned to the current map; any other map is not this canary.
    packages = graph["packages"]
    require(packages and all(isinstance(v, dict) and set(v) == {"dir", "imports", "tests"}
                            for v in packages.values()))
    require(all(dependency in packages for v in packages.values()
                for dependency in v["imports"] + v["tests"]))
    selected, skipped = module.select(files, packages, mapping)
    require(report["selected"] == selected and report["skipped"] == skipped)
    require("tenancy" in {s["script"] for s in skipped})
    require(ALWAYS | {"carriers"} <= {s["script"] for s in selected})


def prepare(context):
    line = "ALL"
    try:
        d = descriptor(context)
        # Do not incur a Go listing on ordinary/default pipelines.
        output = ROOT / "mutation-canary-selector.json"
        env = dict(os.environ, CGO_ENABLED="0")
        subprocess.run([sys.executable, str(ROOT / "scripts/mutation-select.py"),
                        "--base", d["base"], "--head", d["head"], "--json", str(output)],
                       cwd=ROOT, env=env, check=True, timeout=90, stdout=subprocess.DEVNULL)
        report = json.loads(output.read_text())
        validate(d, report, context)
        line = "KEEP_TENANCY_CANARY_V1 OMIT " + " ".join((context["CI_PIPELINE_ID"],
                context["CI_COMMIT_SHA"], context["CI_MERGE_REQUEST_IID"], "tenancy-mutations"))
    except Exception:
        pass  # Metadata/installation/selector failures never omit tests.
    ARTIFACT.write_text(line + "\n")
    print("Tenancy canary decision: " + ("ALL" if line == "ALL" else "OMIT_TENANCY_BODY"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare",))
    parser.parse_args()
    prepare(os.environ)
    return 0


if __name__ == "__main__":
    sys.exit(main())
