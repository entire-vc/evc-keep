"""Conservative changed-path dispatcher for the existing Keep self-test gate."""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable, Iterable, Mapping, Sequence

COMMANDS = (
    ("mutation_shards", ("python3", "scripts/test_mutation_shards.py"), {}),
    ("carriers", ("python3", "scripts/test_carriers_mutations.py"), {}),
    ("intake_baseline", ("python3", "scripts/test_intake_baseline_diagnostics.py"), {}),
    ("intake_mutant", ("python3", "scripts/test_intake_mutant_diagnostics.py"), {}),
    ("catalog_mutant", ("python3", "scripts/test_catalog_mutant_diagnostics.py"), {}),
    ("runnerproto", ("python3", "scripts/test_runnerproto_mutations.py"), {}),
    ("tenancy", ("python3", "scripts/test_tenancy_mutations.py"), {}),
    ("cli_witnesses", ("python3", "scripts/test_cli_mutation_witnesses.py"), {}),
    ("approvals", ("python3", "scripts/test_approvals_baseline_diagnostics.py"), {}),
    ("builtin_job_cache", ("python3", "scripts/test_builtin_job_cache.py"), {"KEEP_JOB_CACHE_REAL_TIMEOUT": "1"}),
    ("baseline_diag", ("./scripts/check-baseline-diag.sh",), {}),
    ("w3_stubs", ("python3", "scripts/test_w3_stubs_diagnostics.py"), {}),
    ("dispatch_baseline", ("python3", "scripts/test_dispatch_baseline_diagnostics.py"), {}),
    ("mutation_select", ("python3", "scripts/test_mutation_select.py"), {}),
    ("mutation_select_redrun", ("./scripts/check-mutation-select-redrun.sh",), {}),
    ("intake_hpke_mutant", ("python3", "scripts/test_intake_hpke_mutant_diagnostics.py"), {}),
    ("upgrade_rollback_output", ("python3", "scripts/test_upgrade_rollback_output_leak.py"), {}),
    ("driver_output_leak", ("python3", "scripts/test_driver_output_leak.py"), {}),
    ("release_nightly_gate", ("python3", "scripts/test_release_nightly_gate.py"), {}),
    ("quickstart_output_leak", ("python3", "scripts/test_quickstart_output_leak.py"), {}),
    ("public_hygiene_parent", ("python3", "scripts/test_public_hygiene_merged_parent.py"), {}),
)
NAMES = tuple(row[0] for row in COMMANDS)
FULL = frozenset(range(len(COMMANDS)))
# These checks are controls over the selector and W3 stub contract and always run on a narrowed MR.
ALWAYS_NARROW = frozenset({11, 13, 14})
# The redrun is split by its cuts, not placed whole: every node runs its
# shard (REDRUN_SHARD=k/n), and only the other commands are spread by weight.
REDRUN = NAMES.index("mutation_select_redrun")
# Seconds each command took in a full run (job 731313; driver_output_leak
# timed on its own). They only balance the nodes: a stale weight makes a node
# longer, it never drops a command. New commands start with a small estimate
# until their first CI timing. A command without a weight is refused.
WEIGHTS = {
    "mutation_shards": 81, "carriers": 32, "intake_baseline": 1, "intake_mutant": 3,
    "catalog_mutant": 1, "runnerproto": 6, "tenancy": 1, "cli_witnesses": 104,
    "approvals": 2, "builtin_job_cache": 2, "baseline_diag": 3, "w3_stubs": 1,
    "dispatch_baseline": 2, "mutation_select": 32, "intake_hpke_mutant": 1,
    "upgrade_rollback_output": 71, "driver_output_leak": 92,
    "release_nightly_gate": 26,  # /usr/bin/time -p: real 25.16s, rounded up.
    "quickstart_output_leak": 2,
    "public_hygiene_parent": 115,  # local run: 42 scenarios, 114.2 s.
}

# Only exact test-driver files have a proven one-to-one dependency. Other scripts,
# helper changes, and all unlisted paths take the complete suite.
SCRIPT_TEST_MAP = {
    "scripts/test_mutation_shards.py": {0},
    "scripts/test_carriers_mutations.py": {1},
    "scripts/test_intake_baseline_diagnostics.py": {2},
    "scripts/test_intake_mutant_diagnostics.py": {3},
    "scripts/test_intake_hpke_mutant_diagnostics.py": {15},
    "scripts/test_catalog_mutant_diagnostics.py": {4},
    "scripts/test_runnerproto_mutations.py": {5},
    "scripts/test_tenancy_mutations.py": {6},
    "scripts/test_cli_mutation_witnesses.py": {7},
    "scripts/test_approvals_baseline_diagnostics.py": {8},
    "scripts/test_builtin_job_cache.py": {9},
    "scripts/test_w3_stubs_diagnostics.py": {11},
    "scripts/test_dispatch_baseline_diagnostics.py": {12},
    "scripts/test_mutation_select.py": {13, 14},
    "scripts/test_driver_output_leak.py": {17},
    "scripts/test_quickstart_output_leak.py": {19},
    "scripts/test_public_hygiene_merged_parent.py": {20},
    "scripts/check-quickstart.sh": {17, 19},
    "scripts/check-quickstart-redruns.sh": {19},
    "scripts/check-e2e-w2.sh": {17, 19},
    "scripts/check-identity-attack-mutations.sh": {0, 17},
    "scripts/check-keep-cli-mutations.sh": {7},
    "scripts/cli-mutation-witnesses.sh": {7},
    "scripts/test_upgrade_rollback_output_leak.py": {16},
    "scripts/upgrade-rollback-report.sh": {16},
    "scripts/check-upgrade-rollback.sh": {16},
    "scripts/check-upgrade-rollback-mutations.sh": {16},
    "scripts/test_release_nightly_gate.py": {18},
    "scripts/release-nightly-gate.py": {18},
}
# Product files below are copied/read by exactly these mutation controls. Shared
# Go/CI/test helpers are deliberately absent and therefore force the full suite.
PRODUCT_MAP = {
    "internal/carriers/repo.go": {1},
    "internal/carriers/format.go": {1},
    "internal/carriers/deploy.go": {1},
    "internal/store/migrations/00015_carriers.sql": {1},
    "cmd/keep": {7},
    "internal/identity/token.go": {0},
    "internal/identity/repo.go": {0},
    "internal/identity/middleware.go": {0},
    "internal/identity/rights.go": {0},
    "internal/identity/principal.go": {0},
    "internal/obs/obs.go": {0},
    "internal/testutil/canary/canary.go": {0},
    "test/security/identity_attack_test.go": {0},
    "internal/tenancy/repo.go": {0, 6},
    "internal/tenancy/resolve.go": {0, 6},
    "internal/tenancy/catalog_reads.go": {0, 6},
}

@dataclass(frozen=True)
class Selection:
    indices: tuple[int, ...]
    reason: str
    # The redrun's part on this node; 1/1 is the whole redrun.
    redrun_shard: str = "1/1"

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(NAMES[i] for i in self.indices)


def _product_match(path: str) -> set[int] | None:
    if path in PRODUCT_MAP:
        return set(PRODUCT_MAP[path])
    if path.startswith("cmd/keep/") and path.endswith(".go"):
        return {7}
    return None


def select(changed_paths: Iterable[str] | None, *, context: str = "mr", full_ci: bool = False,
           mutation_batch: bool = False,
           diff_error: bool = False) -> Selection:
    if mutation_batch:
        return Selection((), "existing suppression")
    if context != "mr" or full_ci:
        return Selection(tuple(range(len(COMMANDS))), "full context")
    if diff_error or changed_paths is None:
        return Selection(tuple(range(len(COMMANDS))), "diff unavailable")
    paths = tuple(changed_paths)
    if not paths:
        return Selection(tuple(range(len(COMMANDS))), "empty diff is untrusted")
    chosen = set(ALWAYS_NARROW)
    for path in paths:
        if not path or path.startswith("/") or ".." in PurePosixPath(path).parts:
            return Selection(tuple(range(len(COMMANDS))), "invalid path")
        if path in SCRIPT_TEST_MAP:
            chosen.update(SCRIPT_TEST_MAP[path])
            continue
        product = _product_match(path)
        if product is not None:
            chosen.update(product)
            continue
        return Selection(tuple(range(len(COMMANDS))), f"unmapped path: {path}")
    return Selection(tuple(sorted(chosen)), "exact dependency map")


def node_from_env(env: Mapping[str, str]) -> tuple[int, int]:
    """This job's node, k of n, from GitLab's parallel variables. Neither set:
    one node. One set without the other, or a value out of range: refused."""
    index, total = env.get("CI_NODE_INDEX"), env.get("CI_NODE_TOTAL")
    if index is None and total is None:
        return 1, 1
    if index is None or total is None:
        raise ValueError("CI_NODE_INDEX and CI_NODE_TOTAL come together")
    if not (index.isdigit() and total.isdigit() and index.isascii() and total.isascii()):
        raise ValueError(f"node {index!r}/{total!r} is not k/n")
    k, n = int(index), int(total)
    if not 1 <= k <= n:
        raise ValueError(f"node {k}/{n} is out of range")
    return k, n


def shard(selection: Selection, index: int, total: int) -> Selection:
    """The part of selection node index of total runs. The selected commands
    other than the redrun go to the nodes by LPT (heaviest first, each to the
    least loaded node, ties to the lower node); every node runs its own shard of
    the redrun when it is selected. Over index 1..total the nodes run each
    selected command exactly once and every redrun shard once."""
    if not (type(index) is int and type(total) is int and 1 <= index <= total):
        raise ValueError(f"node {index}/{total} is out of range")
    loads = [0] * total
    nodes: list[list[int]] = [[] for _ in range(total)]
    rest = [i for i in selection.indices if i != REDRUN]
    for i in sorted(rest, key=lambda i: (-WEIGHTS[NAMES[i]], i)):
        node = min(range(total), key=lambda k: (loads[k], k))
        nodes[node].append(i)
        loads[node] += WEIGHTS[NAMES[i]]
    mine = set(nodes[index - 1])
    if REDRUN in selection.indices:
        mine.add(REDRUN)
    return Selection(tuple(sorted(mine)), f"{selection.reason}, node {index}/{total}",
                     f"{index}/{total}")


def changed_paths_from_git(base: str | None, head: str | None,
                           runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> tuple[list[str] | None, bool]:
    if not base or not head or any(c not in "0123456789abcdefABCDEF" for c in base + head):
        return None, True
    try:
        result = runner(["git", "diff", "--name-only", "-z", "--no-renames", f"{base}...{head}"],
                        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return [p.decode("utf-8", "strict") for p in result.stdout.split(b"\0") if p], False
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None, True


def run(selection: Selection, *, runner: Callable[..., object] = subprocess.run,
        env: Mapping[str, str] | None = None) -> int:
    base_env = dict(os.environ if env is None else env)
    for i in selection.indices:
        name, argv, extra = COMMANDS[i]
        child_env = dict(base_env)
        child_env.update(extra)
        if i == REDRUN:
            child_env["REDRUN_SHARD"] = selection.redrun_shard
        start = time.monotonic()
        runner(list(argv), check=True, env=child_env)
        print(f"ci-selftests: {name} done in {time.monotonic() - start:.0f}s", flush=True)
    return len(selection.indices)



def pipeline_context(env: Mapping[str, str]) -> str:
    """Only GitLab merge-request pipelines may use changed-path narrowing."""
    if (env.get("CI_PIPELINE_SOURCE") == "merge_request_event"
            and env.get("CI_MERGE_REQUEST_IID")):
        return "mr"
    return "non-mr"


def main() -> int:
    env = os.environ
    context = pipeline_context(env)
    paths, failed = changed_paths_from_git(env.get("CI_MERGE_REQUEST_DIFF_BASE_SHA"), env.get("CI_COMMIT_SHA")) if context == "mr" else (None, False)
    choice = select(paths, context=context,
                    full_ci=bool(env.get("KEEP_FULL_CI")),
                    mutation_batch=env.get("KEEP_MUTATION_BATCH") == "true",
                    diff_error=failed)
    if not choice.indices:
        print(f"ci-selftests: suppressed ({choice.reason})")
        return 0
    index, total = node_from_env(env)
    part = shard(choice, index, total)
    print(f"ci-selftests: running {len(choice.indices)}/{len(COMMANDS)} ({choice.reason}); "
          f"node {index}/{total} runs {', '.join(part.names) or 'nothing'}"
          + (f" (redrun shard {part.redrun_shard})" if REDRUN in part.indices else ""), flush=True)
    run(part)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
