#!/usr/bin/env python3
"""Evidence-only pinned main overlay versus unchanged CLI sources.

Never publish Go Output events: failed leak assertions can contain canaries.
Only structured test identities/actions and checked numeric facts survive.
Runs on the exact commit of the pipeline (CI_COMMIT_SHA).
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

MAIN = "10fcf35d6f1c99ea5f1a69de86001e852874f426"
PACKAGE = "github.com/entire-vc/evc-keep/cmd/keep"
TESTS = {
    "TestPrintAPIErrorNeverPrintsMessage": "fail",
    "TestRunnerEnrollTokenFailsClosedOnEmptyToken": "fail",
    "TestRunnerEnrollTokenSuccessLineIsClosedList": "fail",
    "TestRunnerEnrollTokenRejectsNonCanonicalTokenID": "fail",
    "TestRunnerEnrollTokenSuccessLineEchoesOwnHost": "pass",
    "TestRunnerRevokeFailsClosedOnOKFalse": "fail",
    "TestRunnerResponseDecodeNoLeak": "pass",
}
OUT = Path("runner-response-proof")


def require(condition, diagnostic):
    if not condition:
        raise RuntimeError(diagnostic)


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def source_check(source):
    """The committed cmd/keep tree of the pipeline commit equals the bytes on disk."""
    require(source == git("rev-parse", "HEAD").decode().strip(), "source SHA differs")
    entries = git("ls-tree", "-rz", source, "cmd/keep").split(b"\0")
    expected = {}
    for entry in filter(None, entries):
        meta, filename = entry.split(b"\t", 1)
        mode, kind, blob = meta.split()
        require(kind == b"blob" and mode == b"100644", "unexpected CLI source type")
        name = filename.decode()
        expected[name] = blob.decode()
        require(Path(name).read_bytes() == git("cat-file", "blob", blob.decode()),
                "CLI source bytes differ from the commit")
    actual = {str(p) for p in Path("cmd/keep").rglob("*") if p.is_file()}
    require(actual == set(expected), "CLI source file inventory differs")
    return git("rev-parse", source + ":cmd/keep").decode().strip(), len(expected)


def validate_events(events, status, phase):
    require(status == (1 if phase == "main" else 0), "unexpected go test exit status")
    require(all(e.get("Package") == PACKAGE for e in events), "unexpected package/build error")
    require(not any(e.get("Action") in {"skip", "build-fail"} for e in events),
            "skipped test or build failure")
    terminal = {}
    starts = []
    for event in events:
        name, action = event.get("Test"), event.get("Action")
        if name and "/" not in name:
            if action == "run":
                starts.append(name)
            if action in {"pass", "fail"}:
                require(name not in terminal, "duplicate parent result")
                terminal[name] = action
    require(sorted(starts) == sorted(TESTS), "test inventory missing/duplicate/extra")
    expected = TESTS if phase == "main" else dict.fromkeys(TESTS, "pass")
    require(terminal == expected, "designated parent outcomes differ")
    require([e["Action"] for e in events if not e.get("Test") and
             e.get("Action") in {"pass", "fail"}] == ["fail" if phase == "main" else "pass"],
            "missing package completion")
    return terminal


def run(phase, overlay=None):
    command = ["go", "test", "-json", "-count=1", "-timeout=90s"]
    if overlay:
        command += ["-overlay", str(overlay)]
    command += ["-run", "^(" + "|".join(TESTS) + ")$", "./cmd/keep"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    # Neither stream is forwarded, including on parser/validation failures.
    events = [json.loads(line) for line in result.stdout.splitlines()]
    terminal = validate_events(events, result.returncode, phase)
    canary_hits = 0
    message_hits = 0
    if phase == "main":
        for event in events:
            output = event.get("Output", "")
            if event.get("Test") == "TestRunnerEnrollTokenSuccessLineIsClosedList":
                canary_hits += int("canary from token_id/host reached output:" in output)
            if event.get("Test") == "TestPrintAPIErrorNeverPrintsMessage":
                message_hits += int('class "' in output and "m kc" in output)
        require(canary_hits == 1 and message_hits == 3, "canary assertion signatures absent")
    safe_events = [{k: v for k, v in e.items() if k != "Output"} for e in events]
    data = "".join(json.dumps(e, sort_keys=True) + "\n" for e in safe_events).encode()
    (OUT / (phase + ".go-test.jsonl")).write_bytes(data)
    timings = {e["Test"]: e["Elapsed"] for e in events if e.get("Test") in TESTS
               and e.get("Action") in {"pass", "fail"}}
    return terminal, result.returncode, hashlib.sha256(data).hexdigest(), canary_hits, message_hits, timings


def main():
    OUT.mkdir(exist_ok=True)
    source = os.environ["CI_COMMIT_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", source), "full source SHA required")
    tree, files = source_check(source)
    main_blob = git("rev-parse", MAIN + ":cmd/keep/runner.go").decode().strip()
    with tempfile.TemporaryDirectory(prefix="runner-proof-") as tmp:
        runner = Path(tmp) / "runner.go"
        runner.write_bytes(git("cat-file", "blob", main_blob))
        overlay = Path(tmp) / "overlay.json"
        # go keys overlays by $PWD, which differs from the resolved path under a symlinked checkout.
        keys = {str(Path("cmd/keep/runner.go").resolve()),
                os.path.join(os.environ.get("PWD", os.getcwd()), "cmd/keep/runner.go")}
        overlay.write_text(json.dumps({"Replace": {key: str(runner) for key in keys}}))
        red, red_exit, red_hash, token_hits, message_hits, red_times = run("main", overlay)
    source_check(source)
    green, green_exit, green_hash, _, _, green_times = run("head")
    source_check(source)
    props = {
        "proof.main_sha": MAIN, "proof.source_sha": source,
        "proof.scope": "commit tests and CLI tree; only runner.go overlaid from pinned main",
        "proof.cli_tree": tree, "proof.cli_file_count": files,
        "proof.cli_byte_identical_before_overlay": 1,
        "proof.cli_byte_identical_after_runs": 1, "proof.main_runner_blob": main_blob,
        "proof.test_count": len(TESTS), "proof.output_events_removed": 1,
        "proof.main.exit_status": red_exit, "proof.main.parent_pass": 2,
        "proof.main.parent_fail": 5, "proof.main.skip": 0,
        "proof.head.exit_status": green_exit, "proof.head.parent_pass": 7,
        "proof.head.parent_fail": 0, "proof.head.skip": 0,
        "proof.main.token_id_host_canary_assertions": token_hits,
        "proof.main.message_canary_assertions": message_hits,
        "proof.main.json_sha256": red_hash, "proof.head.json_sha256": green_hash,
    }
    for i, name in enumerate(TESTS, 1):
        props[f"proof.test.{i}.name"] = name
        props[f"proof.test.{i}.main"] = red[name]
        props[f"proof.test.{i}.head"] = green[name]
    suite = ET.Element("testsuite", name="runner-response-pinned-proof", tests="14", failures="5", errors="0", skipped="0")
    properties = ET.SubElement(suite, "properties")
    for name, value in props.items():
        ET.SubElement(properties, "property", name=name, value=str(value))
    for phase, outcomes, timings in (("main", red, red_times), ("head", green, green_times)):
        for name, outcome in outcomes.items():
            case = ET.SubElement(suite, "testcase", classname=phase, name=name, time=str(timings[name]))
            if outcome == "fail":
                ET.SubElement(case, "failure", type="ExpectedMainRed", message="designated assertion failed")
    artifact = "runner-response-proof/results.xml"
    ET.ElementTree(suite).write(OUT / "results.xml", encoding="utf-8", xml_declaration=True)
    spec = {"names": sorted(props), "prefixes": {}}
    descriptor = {"version": 1, "sources": [{
        "source_sha": source, "pipeline_id": int(os.environ["CI_PIPELINE_ID"]),
        "job_id": int(os.environ["CI_JOB_ID"]), "criterion_ids": ["A1"],
        "extractor": "junit-properties-v1", "artifact_path": artifact, "properties": spec,
    }]}
    (OUT / "historical-ci-sources.json").write_text(json.dumps(descriptor, indent=2) + "\n")
    (OUT / "summary.json").write_text(json.dumps(props, indent=2) + "\n")
    print("main-red: exit=1 PASS=2 FAIL=5 SKIP=0; canary token_id/host=1 message=3")
    print("head-green: exit=0 PASS=7 FAIL=0 SKIP=0; CLI bytes unchanged")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Runtime test output and exception details are deliberately never logged.
        print("FAIL: pinned runtime proof validation rejected; no unverified JUnit emitted", file=sys.stderr)
        sys.exit(1)
