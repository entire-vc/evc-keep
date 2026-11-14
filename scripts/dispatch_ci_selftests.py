"""Conservative changed-path dispatcher for the existing Keep self-test gate."""
from __future__ import annotations

import os
import subprocess
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
)
NAMES = tuple(row[0] for row in COMMANDS)
FULL = frozenset(range(len(COMMANDS)))
# These checks are controls over the selector and W3 stub contract and always run on a narrowed MR.
ALWAYS_NARROW = frozenset({11, 13, 14})

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
    "scripts/check-identity-attack-mutations.sh": {0},
    "scripts/check-keep-cli-mutations.sh": {7},
    "scripts/cli-mutation-witnesses.sh": {7},
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
           mutation_batch: bool = False, branch_push_scan_only: bool = False,
           diff_error: bool = False) -> Selection:
    if mutation_batch or branch_push_scan_only:
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
        runner(list(argv), check=True, env=child_env)
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
                    branch_push_scan_only=env.get("KEEP_BRANCH_PUSH_SCAN_ONLY") == "true",
                    diff_error=failed)
    if not choice.indices:
        print(f"ci-selftests: suppressed ({choice.reason})")
        return 0
    print(f"ci-selftests: running {len(choice.indices)}/{len(COMMANDS)} ({choice.reason})")
    run(choice)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
