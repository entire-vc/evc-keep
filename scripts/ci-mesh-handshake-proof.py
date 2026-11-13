#!/usr/bin/env python3
"""Evidence-only pinned base overlay versus the store-and-extension coexistence code.

Runs TestMeshHandshakeUpgradesStoreBinding on a real PostgreSQL twice on the
pipeline commit: once with only internal/api/mesh_handshake.go replaced by the
pinned !315 merge version (the upgrade itself succeeds with 200, then the store
events secret no longer verifies: the lookup the extension's health goes through
must go RED), once
unchanged (all subtests GREEN, nothing skipped). Go Output events are never
published: a failed leak assertion can echo a canary. Only test identities,
actions and checked facts survive.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

BASE = "af636a5d2b139982e02dc2286f3c2183ebde5b65"
PACKAGE = "github.com/entire-vc/evc-keep/cmd/keep-server/app"
HANDLER = "internal/api/mesh_handshake.go"
OVERLAID = [HANDLER, "internal/api/mesh.go", "internal/builtin/mesh_vault.go"]
RED_SIGNATURE = "signing-secret lookup after the upgrade: store-signed resolve: 401"
PARENT = "TestMeshHandshakeUpgradesStoreBinding"
SUBTESTS = [
    "upgrades_with_a_live_window", "upgrade_spends_the_budget", "no_window",
    "window_for_another_secret", "expired_window", "window_naming_another_Mesh",
    "extension_binding_is_not_replaced", "window_of_another_organisation",
    "reinstall_revokes_the_extension_secret",
]
RED = {"upgrades_with_a_live_window"}
OUT = Path("mesh-handshake-proof")


def require(condition, diagnostic):
    if not condition:
        raise RuntimeError(diagnostic)


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def validate(events, status, phase):
    require(status == (1 if phase == "base" else 0), "unexpected go test exit status")
    require(all(e.get("Package") == PACKAGE for e in events), "unexpected package/build error")
    require(not any(e.get("Action") in {"skip", "build-fail"} for e in events), "skipped test or build failure")
    names = [PARENT] + [PARENT + "/" + s for s in SUBTESTS]
    started, terminal = [], {}
    for e in events:
        name, action = e.get("Test"), e.get("Action")
        if not name:
            continue
        if action == "run":
            started.append(name)
        if action in {"pass", "fail"}:
            require(name not in terminal, "duplicate result")
            terminal[name] = action
    require(sorted(started) == sorted(names), "test inventory missing/duplicate/extra")
    expected = {n: "pass" for n in names}
    if phase == "base":
        expected[PARENT] = "fail"
        for s in RED:
            expected[PARENT + "/" + s] = "fail"
    require(terminal == expected, "subtest outcomes differ")
    return terminal


def run(phase, overlay=None):
    command = ["go", "test", "-json", "-count=1", "-timeout=240s"]
    if overlay:
        command += ["-overlay", str(overlay)]
    command += ["-run", "^" + PARENT + "$", "./cmd/keep-server/app"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    events = [json.loads(line) for line in result.stdout.splitlines()]
    terminal = validate(events, result.returncode, phase)
    hits = 0
    if phase == "base":
        for e in events:
            if e.get("Test") == PARENT + "/upgrades_with_a_live_window":
                out = e.get("Output", "")
                require("handshake over a store binding: 401" not in out, "base refused the upgrade itself")
                hits += int(RED_SIGNATURE in out)
        require(hits == 1, "the base coexistence-red signature is absent")
    safe = [{k: v for k, v in e.items() if k != "Output"} for e in events]
    data = "".join(json.dumps(e, sort_keys=True) + "\n" for e in safe).encode()
    (OUT / (phase + ".go-test.jsonl")).write_bytes(data)
    times = {e["Test"]: e["Elapsed"] for e in events if e.get("Test") and e.get("Action") in {"pass", "fail"}}
    return terminal, result.returncode, hashlib.sha256(data).hexdigest(), hits, times


def main():
    OUT.mkdir(exist_ok=True)
    source = os.environ["CI_COMMIT_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", source), "full source SHA required")
    require(source == git("rev-parse", "HEAD").decode().strip(), "source SHA differs")
    require(git("status", "--porcelain", "--untracked-files=no").strip() == b"", "worktree is not the commit")
    require(git("merge-base", "--is-ancestor", BASE, source) is not None, "base is not an ancestor")
    head_blob = ",".join(git("rev-parse", source + ":" + f).decode().strip() for f in OVERLAID)
    base_blob = ",".join(git("rev-parse", BASE + ":" + f).decode().strip() for f in OVERLAID)
    for f in OVERLAID:
        require(git("rev-parse", source + ":" + f) != git("rev-parse", BASE + ":" + f), f + " is identical to the base; nothing to prove")
    with tempfile.TemporaryDirectory(prefix="handshake-proof-") as tmp:
        replace = {}
        for f in OVERLAID:
            old = Path(tmp) / Path(f).name
            old.write_bytes(git("show", BASE + ":" + f))
            for k in {str(Path(f).resolve()), os.path.join(os.environ.get("PWD", os.getcwd()), f)}:
                replace[k] = str(old)
        # The metadata probe's files name two declarations only the current
        # mesh.go has; the shim stands in for them under the pinned mesh.go.
        shim = str(Path("scripts/proof-overlay/mesh_metadata_shim.go.txt").resolve())
        for k in {str(Path("internal/api/zz_proof_shim.go").resolve()),
                  os.path.join(os.environ.get("PWD", os.getcwd()), "internal/api/zz_proof_shim.go")}:
            replace[k] = shim
        overlay = Path(tmp) / "overlay.json"
        overlay.write_text(json.dumps({"Replace": replace}))
        red, red_exit, red_hash, hits, red_times = run("base", overlay)
    require(git("status", "--porcelain", "--untracked-files=no").strip() == b"", "overlaid files changed the worktree")
    green, green_exit, green_hash, _, green_times = run("head")
    props = {
        "proof.base_sha": BASE, "proof.source_sha": source,
        "proof.scope": "commit tests; mesh_handshake.go, mesh.go and mesh_vault.go overlaid from the pinned base",
        "proof.base_overlaid_blobs": base_blob, "proof.head_overlaid_blobs": head_blob,
        "proof.test": PARENT, "proof.subtest_count": len(SUBTESTS),
        "proof.output_events_removed": 1, "proof.skip": 0,
        "proof.base.exit_status": red_exit, "proof.base.parent": red[PARENT],
        "proof.base.subtest_fail": len(RED), "proof.base.subtest_pass": len(SUBTESTS) - len(RED),
        "proof.base.coexistence_red_signatures": hits, "proof.base.json_sha256": red_hash,
        "proof.head.exit_status": green_exit, "proof.head.parent": green[PARENT],
        "proof.head.subtest_pass": len(SUBTESTS), "proof.head.subtest_fail": 0,
        "proof.head.json_sha256": green_hash,
    }
    for i, s in enumerate(SUBTESTS, 1):
        props[f"proof.subtest.{i}.name"] = s
        props[f"proof.subtest.{i}.base"] = red[PARENT + "/" + s]
        props[f"proof.subtest.{i}.head"] = green[PARENT + "/" + s]
    suite = ET.Element("testsuite", name="mesh-handshake-pinned-proof", tests=str(2 * (len(SUBTESTS) + 1)),
                       failures=str(len(RED) + 1), errors="0", skipped="0")
    holder = ET.SubElement(suite, "properties")
    for k, v in props.items():
        ET.SubElement(holder, "property", name=k, value=str(v))
    for phase, outcomes, times in (("base", red, red_times), ("head", green, green_times)):
        for name, outcome in outcomes.items():
            case = ET.SubElement(suite, "testcase", classname=phase, name=name, time=str(times[name]))
            if outcome == "fail":
                ET.SubElement(case, "failure", type="ExpectedBaseRed", message="designated assertion failed")
    ET.ElementTree(suite).write(OUT / "results.xml", encoding="utf-8", xml_declaration=True)
    descriptor = {"version": 1, "sources": [{
        "source_sha": source, "pipeline_id": int(os.environ["CI_PIPELINE_ID"]),
        "job_id": int(os.environ["CI_JOB_ID"]), "criterion_ids": ["A1"],
        "extractor": "junit-properties-v1", "artifact_path": "mesh-handshake-proof/results.xml",
        "properties": {"names": sorted(props), "prefixes": {}},
    }]}
    (OUT / "historical-ci-sources.json").write_text(json.dumps(descriptor, indent=2) + "\n")
    (OUT / "summary.json").write_text(json.dumps(props, indent=2) + "\n")
    print("base-red: exit=1 upgrade 200 then store-secret lookup FAIL=%d others PASS=%d SKIP=0" % (len(RED), len(SUBTESTS) - len(RED)))
    print("head-green: exit=0 PASS=%d FAIL=0 SKIP=0" % len(SUBTESTS))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("FAIL: pinned runtime proof validation rejected; no unverified JUnit emitted", file=sys.stderr)
        sys.exit(1)
