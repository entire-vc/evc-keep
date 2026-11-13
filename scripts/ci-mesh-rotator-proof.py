#!/usr/bin/env python3
"""Evidence-only RED to GREEN of the keep-rotator connect on the merged !326 consumer.

Runs the rotator tests on a real PostgreSQL twice on the pipeline commit: once
with only the Keep handshake code (internal/api/mesh.go, mesh_handshake.go,
internal/builtin/mesh_vault.go) replaced by the pinned main merge c9f1c95, the
consumer that answered the rotator with 401 and left it unhealthy, and once
unchanged. The designated connect test must go RED on the base, which refuses to
open the rotator's window (400), and GREEN on the head, with the same inventory, nothing skipped.
The tests read each install answer as Mesh does for health (any 2xx; Mesh
discards the body) for rotator and keep after the store upgrade, one of them
with the request bytes captured from the real Mesh producer. Go Output events are
never published: a failed leak assertion can echo a canary.
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

BASE = "c9f1c9594ff3eff525a3f3275144a9a1f595e206"
PACKAGE = "github.com/entire-vc/evc-keep/cmd/keep-server/app"
OVERLAID = ["internal/api/mesh_handshake.go", "internal/api/mesh.go", "internal/builtin/mesh_vault.go"]
CONNECT = "TestMeshRotatorConnectsAfterStoreUpgradeAndKeepsTheStore"
REAL = "TestMeshRotatorAcceptsTheRealMeshProducerRequest"
PARENTS = [CONNECT, REAL, "TestMeshRotatorHandshake"]
RED_SIGNATURE = "rotator window: 400"
OUT = Path("mesh-rotator-proof")


def require(condition, diagnostic):
    if not condition:
        raise RuntimeError(diagnostic)


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def run(phase, overlay=None):
    command = ["go", "test", "-json", "-count=1", "-timeout=240s"]
    if overlay:
        command += ["-overlay", str(overlay)]
    command += ["-run", "^(" + "|".join(PARENTS) + ")$", "./cmd/keep-server/app"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    events = [json.loads(line) for line in result.stdout.splitlines()]
    require(all(e.get("Package") == PACKAGE for e in events), "unexpected package/build error")
    require(not any(e.get("Action") in {"skip", "build-fail"} for e in events), "skipped test or build failure")
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
    require(len(started) == len(set(started)) and set(PARENTS) <= set(started), "test inventory missing/duplicate")
    require(set(started) == set(terminal), "a test started without a result")
    hits = 0
    if phase == "base":
        require(result.returncode == 1, "base must exit 1")
        require(terminal[CONNECT] == "fail", "the connect test did not fail on the base")
        require(terminal[REAL] == "fail", "the real-producer vector test did not fail on the base")
        hits = sum(RED_SIGNATURE in e.get("Output", "") for e in events if e.get("Test") == CONNECT)
        if hits != 1:
            for e in events:
                for m in re.findall(r"_test\.go:\d+: ((?:store|keep|rotator)[a-z ]*: \d{3})\b", e.get("Output", "")):
                    if e.get("Test") == CONNECT:
                        print("base failure step: " + m, file=sys.stderr)
        require(hits == 1, "the base rotator-window-refused signature is absent")
    else:
        require(result.returncode == 0 and set(terminal.values()) == {"pass"}, "head must be all green")
    safe = [{k: v for k, v in e.items() if k != "Output"} for e in events]
    data = "".join(json.dumps(e, sort_keys=True) + "\n" for e in safe).encode()
    (OUT / (phase + ".go-test.jsonl")).write_bytes(data)
    times = {e["Test"]: e["Elapsed"] for e in events if e.get("Test") and e.get("Action") in {"pass", "fail"}}
    return terminal, result.returncode, hashlib.sha256(data).hexdigest(), hits, times, sorted(started)


def main():
    OUT.mkdir(exist_ok=True)
    source = os.environ["CI_COMMIT_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", source), "full source SHA required")
    require(source == git("rev-parse", "HEAD").decode().strip(), "source SHA differs")
    require(git("status", "--porcelain", "--untracked-files=no").strip() == b"", "worktree is not the commit")
    git("merge-base", "--is-ancestor", BASE, source)
    for f in OVERLAID:
        require(git("rev-parse", source + ":" + f) != git("rev-parse", BASE + ":" + f), f + " is identical to the base; nothing to prove")
    with tempfile.TemporaryDirectory(prefix="rotator-proof-") as tmp:
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
        red, red_exit, red_hash, hits, red_times, red_inv = run("base", overlay)
    require(git("status", "--porcelain", "--untracked-files=no").strip() == b"", "overlaid files changed the worktree")
    green, green_exit, green_hash, _, green_times, green_inv = run("head")
    require(red_inv == green_inv, "base and head ran different tests")
    props = {
        "proof.base_sha": BASE, "proof.source_sha": source,
        "proof.scope": "commit tests; mesh_handshake.go, mesh.go and mesh_vault.go overlaid from the pinned main merge",
        "proof.tests": ",".join(PARENTS), "proof.test_count": len(green_inv),
        "proof.output_events_removed": 1, "proof.skip": 0,
        "proof.base.exit_status": red_exit, "proof.base.connect": red[CONNECT],
        "proof.base.failed": sum(v == "fail" for v in red.values()),
        "proof.base.rotator_window_refused_signatures": hits, "proof.base.json_sha256": red_hash,
        "proof.head.exit_status": green_exit, "proof.head.connect": green[CONNECT],
        "proof.head.failed": 0, "proof.head.passed": len(green), "proof.head.json_sha256": green_hash,
    }
    suite = ET.Element("testsuite", name="mesh-rotator-pinned-proof", tests=str(len(red) + len(green)),
                       failures=str(props["proof.base.failed"]), errors="0", skipped="0")
    holder = ET.SubElement(suite, "properties")
    for k, v in props.items():
        ET.SubElement(holder, "property", name=k, value=str(v))
    for phase, outcomes, times in (("base", red, red_times), ("head", green, green_times)):
        for name, outcome in outcomes.items():
            case = ET.SubElement(suite, "testcase", classname=phase, name=name, time=str(times[name]))
            if outcome == "fail":
                ET.SubElement(case, "failure", type="ExpectedBaseRed", message="designated assertion failed")
    ET.ElementTree(suite).write(OUT / "results.xml", encoding="utf-8", xml_declaration=True)
    (OUT / "summary.json").write_text(json.dumps(props, indent=2) + "\n")
    print("base-red: exit=1 %s FAIL, rotator window refused (signature x%d), tests=%d SKIP=0" % (CONNECT, hits, len(red)))
    print("head-green: exit=0 PASS=%d FAIL=0 SKIP=0" % len(green))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("FAIL: pinned runtime proof validation rejected; no unverified JUnit emitted", file=sys.stderr)
        sys.exit(1)
