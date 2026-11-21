"""Focused contract tests for changed-path ci-selftests dispatch."""
import os
import subprocess
import unittest
from pathlib import Path
from dispatch_ci_selftests import (COMMANDS, NAMES, REDRUN, WEIGHTS, Selection, changed_paths_from_git,
                                   node_from_env, pipeline_context, run, select, shard)

ROOT = Path(__file__).resolve().parent.parent
REDRUN_SCRIPT = ROOT / "scripts/check-mutation-select-redrun.sh"


def redrun_list(value):
    """The cuts REDRUN_SHARD=value runs, listed without running them."""
    env = dict(os.environ, REDRUN_LIST="1", REDRUN_SHARD=value)
    r = subprocess.run(["sh", str(REDRUN_SCRIPT)], env=env, cwd=ROOT, capture_output=True, text=True)
    return r.returncode, [l for l in r.stdout.splitlines() if l.startswith("cut ")], r.stdout + r.stderr

class DispatcherTests(unittest.TestCase):
    def test_exact_driver_change_keeps_mandatory_controls(self):
        s=select(['scripts/test_carriers_mutations.py'])
        self.assertEqual(s.indices, (1,11,13,14))
    def test_union_for_multiple_exact_inputs(self):
        s=select(['scripts/test_carriers_mutations.py','cmd/keep/cli.go'])
        self.assertEqual(s.indices, (1,7,11,13,14))
    def test_unknown_or_shared_paths_force_full(self):
        for paths in (['scripts/lib/gocache.sh'], ['go.mod'], ['internal/catalog/catalog.go'], ['.gitlab-ci.yml'], ['scripts/new-test.py']):
            with self.subTest(paths=paths): self.assertEqual(select(paths).indices, tuple(range(21)))
    def test_missing_or_failed_diff_forces_full(self):
        self.assertEqual(select(None).indices, tuple(range(21)))
        self.assertEqual(select([], diff_error=True).indices, tuple(range(21)))
        self.assertEqual(select([]).indices, tuple(range(21)))
    def test_delete_and_rename_names_are_unioned_without_rename_detection(self):
        self.assertEqual(select(['internal/carriers/repo.go','scripts/test_carriers_mutations.py']).indices, (1,11,13,14))
        def fake(argv, **kwargs):
            self.assertIn('--no-renames', argv)
            return subprocess.CompletedProcess(argv, 0, b'cmd/keep/cli.go\0old/name.go\0', b'')
        paths, failed=changed_paths_from_git('a'*40,'b'*40,fake)
        self.assertFalse(failed)
        self.assertEqual(paths,['cmd/keep/cli.go','old/name.go'])
        self.assertEqual(select(paths).indices, tuple(range(21)))
        self.assertEqual(select(['scripts/check-identity-attack-mutations.sh','test/security/identity_attack_test.go']).indices, (0,11,13,14,17))
    def test_filter_drivers_select_the_output_leak_test(self):
        # A driver printing through test-result-names.sh, or the filter itself,
        # never narrows past driver_output_leak (a raw print would go unseen).
        from pathlib import Path
        scripts = Path(__file__).resolve().parent
        paths = ['scripts/test-result-names.sh', 'scripts/test-result-names.py'] + [
            'scripts/' + p.name for p in sorted(scripts.glob('check-*.sh')) if 'test-result-names.sh' in p.read_text()]
        self.assertGreater(len(paths), 10)
        for path in paths:
            with self.subTest(path=path):
                self.assertIn('driver_output_leak', select([path]).names)
    def test_contexts_and_existing_suppressions(self):
        for context,full in [('main',False),('schedule',False),('release',False),('mr',True)]:
            self.assertEqual(select(['cmd/keep/cli.go'],context=context,full_ci=full).indices, tuple(range(21)))
        self.assertEqual(select(['cmd/keep/cli.go'],full_ci=True).indices, tuple(range(21)))
        self.assertEqual(select(['bad'],mutation_batch=True).indices, ())
    def test_only_mr_pipeline_source_can_narrow(self):
        self.assertEqual(pipeline_context({"CI_PIPELINE_SOURCE":"merge_request_event","CI_MERGE_REQUEST_IID":"17"}),"mr")
        for source in ("schedule","push","web","parent_pipeline","api","external"):
            env={"CI_PIPELINE_SOURCE":source,"CI_MERGE_REQUEST_IID":"17"}
            self.assertEqual(pipeline_context(env),"non-mr")
            self.assertEqual(select(["cmd/keep/cli.go"],context=pipeline_context(env)).indices,tuple(range(21)))
        self.assertEqual(pipeline_context({"CI_PIPELINE_SOURCE":"merge_request_event"}),"non-mr")
    def test_upgrade_rollback_paths_select_their_output_test(self):
        for path in ('scripts/upgrade-rollback-report.sh','scripts/check-upgrade-rollback.sh',
                     'scripts/check-upgrade-rollback-mutations.sh','scripts/test_upgrade_rollback_output_leak.py'):
            with self.subTest(path=path): self.assertEqual(select([path]).indices,(11,13,14,16))
    def test_release_gate_paths_select_their_test(self):
        for path in ('scripts/release-nightly-gate.py','scripts/test_release_nightly_gate.py'):
            with self.subTest(path=path): self.assertEqual(select([path]).indices,(11,13,14,18))
    def test_quickstart_and_e2e_paths_select_their_output_test(self):
        for path in ('scripts/check-quickstart-redruns.sh',
                     'scripts/test_quickstart_output_leak.py'):
            with self.subTest(path=path): self.assertEqual(select([path]).indices,(11,13,14,19))
        for path in ('scripts/check-quickstart.sh','scripts/check-e2e-w2.sh'):
            with self.subTest(path=path): self.assertEqual(select([path]).indices,(11,13,14,17,19))
    def test_test_w3_always_present_on_narrow_path(self):
        self.assertIn('w3_stubs', select(['scripts/test_catalog_mutant_diagnostics.py']).names)
    def test_all_commands_are_registered_in_original_order(self):
        self.assertEqual(len(COMMANDS),21)
        self.assertEqual(NAMES,('mutation_shards','carriers','intake_baseline','intake_mutant','catalog_mutant','runnerproto','tenancy','cli_witnesses','approvals','builtin_job_cache','baseline_diag','w3_stubs','dispatch_baseline','mutation_select','mutation_select_redrun','intake_hpke_mutant','upgrade_rollback_output','driver_output_leak','release_nightly_gate','quickstart_output_leak','public_hygiene_parent'))
    def test_runner_uses_fixed_argv_order_and_timeout_env(self):
        calls=[]
        def fake(argv, **kwargs): calls.append((argv,kwargs['env']))
        run(select(['scripts/test_builtin_job_cache.py']),runner=fake,env={'BASE':'1'})
        self.assertEqual([c[0] for c in calls],[list(COMMANDS[i][1]) for i in (9,11,13,14)])
        self.assertEqual(calls[0][1]['KEEP_JOB_CACHE_REAL_TIMEOUT'],'1')
        self.assertNotIn('KEEP_JOB_CACHE_REAL_TIMEOUT',calls[1][1])



class ShardTests(unittest.TestCase):
    """ci-selftests runs on parallel nodes: together they run what one node ran."""

    SELECTIONS = (
        select(None),                                           # full
        select(['scripts/test_carriers_mutations.py']),         # narrowed
        select(['scripts/test_carriers_mutations.py', 'cmd/keep/cli.go',
                'scripts/test_upgrade_rollback_output_leak.py']),
        Selection((0, 7, 16, 17), "no redrun"),
        Selection((REDRUN,), "redrun only"),
    )

    def test_every_command_but_the_redrun_has_a_weight(self):
        self.assertEqual(set(WEIGHTS), set(NAMES) - {NAMES[REDRUN]})
        for name, weight in WEIGHTS.items():
            with self.subTest(name=name):
                self.assertIs(type(weight), int)
                self.assertGreater(weight, 0)

    def test_nodes_together_run_the_selection_once(self):
        # Through run(), as the job runs them: argv per command, and the
        # REDRUN_SHARD each node's redrun gets.
        for selection in self.SELECTIONS:
            for total in range(1, 7):
                with self.subTest(selection=selection.reason, total=total):
                    ran, shards = [], []
                    for index in range(1, total + 1):
                        def fake(argv, **kwargs):
                            i = [list(c[1]) for c in COMMANDS].index(argv)
                            if i == REDRUN:
                                shards.append(kwargs['env']['REDRUN_SHARD'])
                            else:
                                ran.append(i)
                        run(shard(selection, index, total), runner=fake, env={})
                    rest = [i for i in selection.indices if i != REDRUN]
                    self.assertEqual(sorted(ran), rest)  # each exactly once, none added
                    expected = [f"{k}/{total}" for k in range(1, total + 1)] if REDRUN in selection.indices else []
                    self.assertEqual(sorted(shards), sorted(expected))

    def test_lpt_balances_the_full_run(self):
        full = select(None)
        loads = [sum(WEIGHTS[NAMES[i]] for i in shard(full, k, 4).indices if i != REDRUN) for k in range(1, 5)]
        # A growing suite can make the average node heavier than any command.
        lower_bound = max(max(WEIGHTS.values()), (sum(WEIGHTS.values()) + 3) // 4)
        self.assertLessEqual(max(loads), lower_bound + 10, loads)

    def test_one_node_is_the_whole_selection(self):
        for selection in self.SELECTIONS:
            with self.subTest(selection=selection.reason):
                part = shard(selection, 1, 1)
                self.assertEqual(part.indices, selection.indices)
                self.assertEqual(part.redrun_shard, "1/1")

    def test_bad_node_refused(self):
        for index, total in ((0, 4), (5, 4), (1, 0), (-1, 4), (True, 4), ("1", 4)):
            with self.subTest(node=(index, total)), self.assertRaises(ValueError):
                shard(select(None), index, total)

    def test_node_from_env(self):
        self.assertEqual(node_from_env({}), (1, 1))
        self.assertEqual(node_from_env({"CI_NODE_INDEX": "3", "CI_NODE_TOTAL": "4"}), (3, 4))
        for env in ({"CI_NODE_INDEX": "1"}, {"CI_NODE_TOTAL": "4"},
                    {"CI_NODE_INDEX": "0", "CI_NODE_TOTAL": "4"}, {"CI_NODE_INDEX": "5", "CI_NODE_TOTAL": "4"},
                    {"CI_NODE_INDEX": "1", "CI_NODE_TOTAL": "0"}, {"CI_NODE_INDEX": "x", "CI_NODE_TOTAL": "4"},
                    {"CI_NODE_INDEX": "-1", "CI_NODE_TOTAL": "4"}, {"CI_NODE_INDEX": "", "CI_NODE_TOTAL": ""},
                    {"CI_NODE_INDEX": "\u0661", "CI_NODE_TOTAL": "4"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                node_from_env(env)

    def test_main_runs_only_its_node(self):
        # The job's entry point: each node gets its part, the parts add up.
        import dispatch_ci_selftests as d
        from unittest import mock
        seen = []
        for k in range(1, 5):
            env = {"CI_PIPELINE_SOURCE": "push", "CI_NODE_INDEX": str(k), "CI_NODE_TOTAL": "4"}
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(d, "run", side_effect=lambda part: seen.append(part)), \
                    mock.patch("builtins.print"):
                self.assertEqual(d.main(), 0)
        self.assertEqual([p.redrun_shard for p in seen], ["1/4", "2/4", "3/4", "4/4"])
        self.assertEqual(sorted(i for p in seen for i in p.indices if i != REDRUN),
                         [i for i in range(len(COMMANDS)) if i != REDRUN])
        with mock.patch.dict(os.environ, {"CI_PIPELINE_SOURCE": "push", "CI_NODE_INDEX": "1"}, clear=True), \
                mock.patch.object(d, "run") as ran, mock.patch("builtins.print"), \
                self.assertRaises(ValueError):
            d.main()
        ran.assert_not_called()

    def test_redrun_shards_partition_the_cuts(self):
        code, whole, out = redrun_list("1/1")
        self.assertEqual(code, 0, out)
        self.assertGreater(len(whole), 50, out)
        self.assertIn(f"cuts run: {len(whole)} of {len(whole)} (shard 1/1)", out)
        for total in range(2, 7):
            with self.subTest(total=total):
                parts = []
                for k in range(1, total + 1):
                    code, cuts, out = redrun_list(f"{k}/{total}")
                    self.assertEqual(code, 0, out)
                    self.assertTrue(cuts, out)  # no shard is empty while n <= the cuts
                    self.assertIn(f"cuts run: {len(cuts)} of {len(whole)} (shard {k}/{total})", out)
                    parts += cuts
                self.assertEqual(sorted(parts), sorted(whole))  # union is the list, no overlap
                self.assertEqual(len(parts), len(set(parts)))

    def test_redrun_shard_left_empty_by_a_broken_split_is_red(self):
        # The script's own guard: with the shard predicate shifted (k-1 -> k)
        # the last shard holds no cut, and the script, not only this test,
        # must say so and fail.
        import tempfile
        text = REDRUN_SCRIPT.read_text()
        good = "-eq $((k - 1)) ]"
        self.assertEqual(text.count(good), 1)
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "scripts").mkdir()
            (Path(tmp) / "go.mod").write_text("module x\n")
            broken = Path(tmp) / "scripts" / REDRUN_SCRIPT.name
            broken.write_text(text.replace(good, "-eq $((k)) ]"))
            env = dict(os.environ, REDRUN_LIST="1", REDRUN_SHARD="4/4")
            r = subprocess.run(["sh", str(broken)], env=env, cwd=tmp, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAIL: shard 4/4 ran no cut", r.stderr)

    def test_redrun_shard_beyond_the_cuts_may_be_empty(self):
        _, whole, _ = redrun_list("1/1")
        n = len(whole) + 1
        code, cuts, out = redrun_list(f"{n}/{n}")
        self.assertEqual((code, cuts), (0, []), out)

    def test_bad_redrun_shard_refused(self):
        for value in ("0/4", "5/4", "1/0", "x", "1/", "/4", "1/4/2", "01/4", " 1/4", "1/4 ", "-1/4", ""):
            with self.subTest(value=value):
                code, cuts, out = redrun_list(value)
                if value == "":  # unset and empty mean the default, 1/1
                    self.assertEqual(code, 0, out)
                    continue
                self.assertEqual((code, cuts), (2, []), out)
                self.assertIn("refuse", out)

if __name__=='__main__': unittest.main()
