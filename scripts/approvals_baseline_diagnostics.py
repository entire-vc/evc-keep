"""Safe diagnostics only; caller retains the baseline verdict and commands."""
import json
import re

STAGES = {"fixture_open_migration": "open migration database",
          "fixture_migrate": "migrate test database",
          "fixture_open_pool": "open test pool"}
CAUSES = ("invalid_dsn", "database_deadline", "connection_unclassified", "unsafe_query_mode", "unknown")
SQLSTATES = ("08000", "08001", "08006", "28000", "28P01", "3D000", "53300", "57P03", "57014")
CAUSE_LINE = re.compile(r"^\s*\S+_test\.go:[0-9]+: open migration database: (.*)$")
TEST = re.compile(r"\bfunc (Test[A-Za-z0-9_]+)\(")
PACKAGES = ("internal/deployment", "internal/api", "internal/notify", "internal/identity")
PREFIX = "github.com/entire-vc/evc-keep/"
# "timeout" is written by the caller when its own subprocess deadline fired.
PACKAGE_ACTIONS = ("pass", "fail", "skip", "timeout")
TIMEOUT_PANIC = "panic: test timed out after "
RUNNING_HEADER = "\trunning tests:"
RUNNING = re.compile(r"^\t\t(Test[A-Za-z0-9_]+)(?:/\S*)? \([0-9][^()]*\)$")


def report(events, root):
    known = {}
    for package in PACKAGES:
        known[PREFIX + package] = set()
        for path in (root / package).glob("*_test.go"):
            known[PREFIX + package].update(TEST.findall(path.read_text()))
    cause_counts, sqlstate_counts = {}, {}
    ids = set()
    counts = {stage: 0 for stage in STAGES}
    timed_out, build_failed, packages = set(), False, []
    # Names count only between the panic's "running tests:" line and the
    # first line that is not a running-test entry.
    in_block = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        path = event.get("ImportPath")
        if event.get("Action") == "build-fail" and isinstance(path, str) and path.split(" ")[0] in known:
            build_failed = True
        package, test = event.get("Package"), event.get("Test")
        if not isinstance(package, str) or package not in known:
            continue
        if test is None and event.get("Action") in PACKAGE_ACTIONS:
            elapsed = event.get("Elapsed")
            ok = isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool)
            packages.append({"package": package.removeprefix(PREFIX), "action": event["Action"],
                             "elapsed": round(float(elapsed), 1) if ok else None})
            build_failed = build_failed or "FailedBuild" in event
            if event["Action"] == "timeout":
                timed_out.add(package)
        if event.get("Action") in ("fail", "skip") and isinstance(test, str) and test in known[package]:
            ids.add(test)
        output = event.get("Output")
        if event.get("Action") == "output" and isinstance(output, str):
            for line in output.splitlines():
                if line.startswith(TIMEOUT_PANIC):
                    timed_out.add(package)
                running = RUNNING.fullmatch(line)
                if package in in_block and not running:
                    in_block.discard(package)
                if running and package in in_block and running[1] in known[package]:
                    ids.add(running[1])
                if line == RUNNING_HEADER and package in timed_out:
                    in_block.add(package)
                match = CAUSE_LINE.fullmatch(line)
                if match:
                    cause = match[1]
                    if cause in CAUSES:
                        cause_counts[cause] = cause_counts.get(cause, 0) + 1
                    elif cause.startswith("connection_sqlstate code=") and cause.removeprefix("connection_sqlstate code=") in SQLSTATES:
                        code = cause.removeprefix("connection_sqlstate code=")
                        cause_counts["connection_sqlstate"] = cause_counts.get("connection_sqlstate", 0) + 1
                        sqlstate_counts[code] = sqlstate_counts.get(code, 0) + 1
            for stage, marker in STAGES.items():
                counts[stage] += sum(marker in line for line in output.splitlines())
    names = sorted(ids)
    print(json.dumps({"event": "approvals-baseline-failure", "test_ids": names[:16],
                      "test_id_count": len(names), "test_ids_truncated": len(names) > 16,
                      "fixture_cause_counts": cause_counts, "fixture_sqlstate_counts": sqlstate_counts,
                      "fixture_stage_counts": {k: v for k, v in counts.items() if v}, "packages": packages,
                      "classification": "timeout" if timed_out else "build_failed" if build_failed
                      else "fixture_setup" if any(counts.values()) else "unknown"}, sort_keys=True), flush=True)
