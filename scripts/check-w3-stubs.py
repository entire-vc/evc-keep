"""Fail-closed attack inventory and executable negative controls."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT, WORK = map(Path, sys.argv[1:3]) if len(sys.argv) >= 3 else (Path(), Path())
# Explicit inventory: deriving it from the Go source would conceal deletion.
NAMES = [
    "A01_LostCarrierNeverReissues", "A02_PartialDeployKeepsOldVersion",
    "A03_SamePrefixValueIsStale", "A04_FingerprintIsKeyedHMACNotSha256",
    "A05_ScannerStaysInsideList", "A06_ScannerRefusesSymlink",
    "A07_NoValueInRotationStateIncidentErrors", "A08_ConcurrentRotationsSerialize",
    "A09_RestartMidRotationResumesSafely", "A10_ForeignTenantCarriersInvisible",
    "A11_CarrierGuessOracleBlocked", "A12_StaleHealthEchoNotAccepted",
    "A13_AgentCannotInjectRotationValue",
]
CARRIER_IDS = (1, 3, 4, 7, 10, 11)
ROTATION_IDS = (1, 2, 7, 8, 9, 12)  # engine witnesses that replaced their stubs
ROTATION_PARTIAL_IDS = (10, 13)  # engine witness added; API part stays pending
TARGETS = {
    "TestW3_" + name: "scanner" if i in (3, 4, 5, 6, 11) else "rotationapi"
    for i, name in enumerate(NAMES, 1)
    if i in (3, 4, 5, 6, 11) or i in ROTATION_PARTIAL_IDS
}
REAL = {"TestW3_" + NAMES[i - 1] + "_Carriers" for i in CARRIER_IDS}
REAL |= {"TestW3_" + NAMES[i - 1] for i in ROTATION_IDS}
REAL |= {"TestW3_" + NAMES[i - 1] + "_Rotation" for i in ROTATION_PARTIAL_IDS}
EXPECTED = set(TARGETS) | REAL


def run(tree, pattern, label, pending_root=None):
    env = os.environ.copy()
    env.pop("KEEP_W3_ROOT", None)
    if pending_root:
        env["KEEP_W3_ROOT"] = str(pending_root)
    proc = subprocess.run(
        ["go", "test", "-json", "-count=1", "-timeout=120s", "-run", pattern,
         "./test/security/"], cwd=tree, env=env, capture_output=True,
        text=True, timeout=180, check=False,
    )
    (WORK / (label + ".jsonl")).write_text(proc.stdout)
    (WORK / (label + ".stderr")).write_text(proc.stderr)
    return proc.returncode, [json.loads(line) for line in proc.stdout.splitlines()]


def valid(result, expected, red=None):
    code, events = result
    if code != (1 if red else 0):
        return False
    started, terminal, output = {}, {}, {}
    package_end = []
    for event in events:
        name, action = event.get("Test"), event["Action"]
        if not name:
            if action in ("pass", "fail", "skip"):
                package_end.append(action)
            continue
        if "/" in name:
            if action in ("fail", "skip"):
                return False
            continue
        if action == "run":
            started[name] = started.get(name, 0) + 1
        elif action in ("pass", "fail", "skip"):
            if name in terminal:
                return False
            terminal[name] = action
        elif action == "output":
            output[name] = output.get(name, "") + event.get("Output", "")
    if package_end != ["fail" if red else "pass"]:
        return False
    if set(started) != expected or set(terminal) != expected:
        return False
    for name in expected:
        if started[name] != 1:
            return False
        text = output.get(name, "")
        if red:
            if terminal[name] != "fail" or red[name] not in text:
                return False
        elif name in REAL:
            if terminal[name] != "pass":
                return False
        else:
            attack_id = "W3-" + name.split("_")[1]
            marker = attack_id + ": pending target " + TARGETS[name] + " absent"
            if terminal[name] != "skip" or marker not in text:
                return False
    return True


def why(result):
    """Bounded account of a run that did not match: what failed, in which test.

    Exit status and event counts, then the file:line output of tests that
    failed. The attack tests print classes and synthetic names only, and each
    line is capped, so this is safe to leave in a public CI trace.
    """
    code, events = result
    count, failed, output = {}, [], {}
    for event in events:
        action, name = event["Action"], event.get("Test")
        if name and action in ("pass", "fail", "skip") and "/" not in name:
            count[action] = count.get(action, 0) + 1
        if name and action == "fail":
            failed.append(name)
        if name and action == "output":
            output.setdefault(name, []).append(event.get("Output", "").strip())
    lines = []
    for name in failed:
        lines.append("failed test " + name)
        for text in output.get(name, []):
            if re.search(r"\.go:\d+:|panic:|deadline exceeded|not ready", text):
                lines.append("  " + text[:200])
    summary = "exit %s, %s" % (code, ", ".join("%d %s" % (n, a) for a, n in sorted(count.items())) or "no test finished")
    return "\n".join(["diagnostic: " + summary] + lines[:12])


def require_run(result, expected, label, red=None):
    ok = valid(result, expected, red)
    if not ok:
        print(why(result), flush=True)
    require(ok, label)


def require(ok, label):
    if not ok:
        raise RuntimeError(label)
    print("ok   " + label, flush=True)


def snapshot():
    tree = WORK / "tree"
    if tree.exists():
        shutil.rmtree(tree)
    shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns(
        ".git", ".gocache", ".gomodcache", ".artifacts"))
    return tree


def edit(tree, path, old, new):
    path = tree / path
    text = path.read_text()
    require(old in text, "control mutation applies")
    path.write_text(text.replace(old, new, 1))


def main():
    require(bool(os.environ.get("KEEP_DATABASE_URL")), "PostgreSQL configured")
    for path in (ROOT / "test/security").glob("w3*test.go"):
        if path.name != "w3_pending_test.go":
            require(not re.search(r"\.Skip(?:f|Now)?\s*\(", path.read_text()),
                    "no bare skip in " + path.name)
    require_run(run(ROOT, "^TestW3_", "baseline"), EXPECTED,
                "mixed baseline: all real witnesses pass; only named absent targets skip")
    for target in sorted(set(TARGETS.values())):
        names = {n for n, t in TARGETS.items() if t == target}
        planted = WORK / target
        (planted / "internal" / target).mkdir(parents=True)
        (planted / "pkg").mkdir()
        (planted / "go.mod").touch()
        (planted / "internal" / target / "probe.go").write_text("package probe\n")
        pattern = "^(" + "|".join(sorted(names)) + ")$"
        red = {n: "pending target " + target + " exists; implement this attack" for n in names}
        require_run(run(ROOT, pattern, "planted-" + target, planted), names,
                    "planted " + target + ": every designated pending attack fails", red)

    linked = WORK / "linked-target"
    (linked / "internal").mkdir(parents=True)
    (linked / "pkg").mkdir()
    (linked / "go.mod").touch()
    (linked / "internal" / "rotationapi").symlink_to(
        WORK / "rotationapi" / "internal" / "rotationapi", target_is_directory=True)
    pending = set(TARGETS)
    pattern = "^(" + "|".join(sorted(pending)) + ")$"
    require(valid(run(ROOT, pattern, "symlink-target", linked), pending,
                  {n: "cannot inspect pending target package" for n in pending}),
            "symlink target: inventory inspection fails closed")

    controls = [
        ("bare-skip", "test/security/w3_attack_stubs_test.go",
         'w3Pending(t, "W3-A03", "scanner")', 't.Skip("quiet")'),
        ("quiet-skip", "test/security/w3_pending_test.go",
         't.Skip(id + ": pending target " + target + " absent")', 't.Skip("quiet")'),
        ("missing-witness", "test/security/w3_carriers_attack_test.go",
         "func TestW3_A01_LostCarrierNeverReissues_Carriers(", "func removedCarrierWitness("),
        ("build-failure", "test/security/w3_pending_test.go",
         '"os"', '"missing.invalid/package"'),
        ("setup-failure", "test/security/w3_carriers_attack_test.go",
         "w := carrierWorld(t)", 't.Fatal("synthetic setup failure"); w := carrierWorld(t)'),
    ]
    for label, path, old, new in controls:
        tree = snapshot()
        edit(tree, path, old, new)
        require(not valid(run(tree, "^TestW3_", label), EXPECTED),
                label + ": invalid baseline rejected")

    mutations = [
        (1, "repo.go", "state='unknown'", "state='registered'", "lost carrier history changed"),
        (3, "repo.go", "return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1",
         "return subtle.ConstantTimeCompare([]byte(a), []byte(a)) == 1", "prefix-equivalent value marked healthy"),
        (4, "repo.go", "return err == nil && a.KeyID == b.KeyID",
         'return err == nil && a.KeyID != "" && b.KeyID != ""', "foreign store key accepted"),
        (7, "format.go", 'func (Metadata) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }',
         'func (m Metadata) LogValue() slog.Value { return slog.StringValue(m.Host) }', "canary in log output"),
        (10, "repo.go", "SELECT id FROM secrets WHERE org_id=$1 AND id=$2`",
         "SELECT id FROM secrets WHERE $1::uuid IS NOT NULL AND id=$2`", "foreign inventory visible"),
        (11, "repo.go", "if err != nil || !allowed {", "if err != nil || (!allowed && false) {",
         "unapproved guessed carrier accepted"),
    ]
    rotation_mutations = [
        # Two independent database gates stand between a partial layout and the
        # revoke; the control switches both off.
        (2, "internal/rotation/store.go", "return err == nil && total > 0 && total == ok, err",
         "return err == nil && total > 0, err", "partial success revoked or hid the failure",
         ("internal/rotation/store.go", "return err == nil && total > 0 && total == good, err",
          "return err == nil && good > 0, err")),
        # The index itself is switched off in check-rotation-mutations.sh (scratch
        # database); here the shared, already migrated database keeps it.
        (1, "internal/rotation/engine.go", "if derr != nil {", "if derr != nil && false {", "lost carrier"),
        (7, "internal/rotation/engine.go", "return ErrIncident", "return err",
         "canary reached rotation state"),
        (8, "internal/rotation/store.go", 'pe.ConstraintName == "rotation_runs_one_active_idx"',
         'pe.ConstraintName == "none"', "second simultaneous rotation"),
        (9, "internal/rotation/engine.go", 'if s.Deploy != "ok" {', "if true {", "lost or duplicated"),
        # Two independent checks keep another organization out of a run.
        (10, "internal/rotation/engine.go", "if run.Ref != ref {", "if false {",
         "foreign organization saw the run",
         ("internal/rotation/store.go", "if org != ref.OrgID || sec != ref.SecretID {", "if false {")),
        (12, "internal/rotation/engine.go", "!fingerprint.Valid(rep.Fingerprint) || rep.Fingerprint != run.ExpectedFP",
         "false", "stale echo accepted"),
        (13, "internal/rotation/rotation.go", "LeaseTTL time.Duration", "LeaseTTL time.Duration; Value []byte",
         "lets a caller steer the rotation"),
    ]
    for attack, path, old, new, marker, *more in rotation_mutations:
        tree = snapshot()
        edit(tree, path, old, new)
        for extra in more:
            edit(tree, *extra)
        name = "TestW3_" + NAMES[attack - 1] + ("_Rotation" if attack in ROTATION_PARTIAL_IDS else "")
        require(valid(run(tree, "^" + name + "$", "rotation-red-" + str(attack)),
                      {name}, {name: marker}),
                "rotation A%02d: designated behavioral failure" % attack)
    for attack, path, old, new, marker in mutations:
        tree = snapshot()
        edit(tree, "internal/carriers/" + path, old, new)
        name = "TestW3_" + NAMES[attack - 1] + "_Carriers"
        require(valid(run(tree, "^" + name + "$", "carrier-red-" + str(attack)),
                      {name}, {name: marker}),
                "carrier A%02d: designated behavioral failure" % attack)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print("FAIL attack guard: " + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
        sys.exit(1)
