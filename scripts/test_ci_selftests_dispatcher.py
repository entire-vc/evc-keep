"""Focused contract tests for changed-path ci-selftests dispatch."""
import subprocess
import unittest
from dispatch_ci_selftests import COMMANDS, NAMES, changed_paths_from_git, pipeline_context, run, select

class DispatcherTests(unittest.TestCase):
    def test_exact_driver_change_keeps_mandatory_controls(self):
        s=select(['scripts/test_carriers_mutations.py'])
        self.assertEqual(s.indices, (1,11,13,14))
    def test_union_for_multiple_exact_inputs(self):
        s=select(['scripts/test_carriers_mutations.py','cmd/keep/cli.go'])
        self.assertEqual(s.indices, (1,7,11,13,14))
    def test_unknown_or_shared_paths_force_full(self):
        for paths in (['scripts/lib/gocache.sh'], ['go.mod'], ['internal/catalog/catalog.go'], ['.gitlab-ci.yml'], ['scripts/new-test.py']):
            with self.subTest(paths=paths): self.assertEqual(select(paths).indices, tuple(range(16)))
    def test_missing_or_failed_diff_forces_full(self):
        self.assertEqual(select(None).indices, tuple(range(16)))
        self.assertEqual(select([], diff_error=True).indices, tuple(range(16)))
        self.assertEqual(select([]).indices, tuple(range(16)))
    def test_delete_and_rename_names_are_unioned_without_rename_detection(self):
        self.assertEqual(select(['internal/carriers/repo.go','scripts/test_carriers_mutations.py']).indices, (1,11,13,14))
        def fake(argv, **kwargs):
            self.assertIn('--no-renames', argv)
            return subprocess.CompletedProcess(argv, 0, b'cmd/keep/cli.go\0old/name.go\0', b'')
        paths, failed=changed_paths_from_git('a'*40,'b'*40,fake)
        self.assertFalse(failed)
        self.assertEqual(paths,['cmd/keep/cli.go','old/name.go'])
        self.assertEqual(select(paths).indices, tuple(range(16)))
        self.assertEqual(select(['scripts/check-identity-attack-mutations.sh','test/security/identity_attack_test.go']).indices, (0,11,13,14))
    def test_contexts_and_existing_suppressions(self):
        for context,full in [('main',False),('schedule',False),('release',False),('mr',True)]:
            self.assertEqual(select(['cmd/keep/cli.go'],context=context,full_ci=full).indices, tuple(range(16)))
        self.assertEqual(select(['cmd/keep/cli.go'],full_ci=True).indices, tuple(range(16)))
        self.assertEqual(select(['bad'],mutation_batch=True).indices, ())
        self.assertEqual(select(['bad'],branch_push_scan_only=True).indices, ())
    def test_only_mr_pipeline_source_can_narrow(self):
        self.assertEqual(pipeline_context({"CI_PIPELINE_SOURCE":"merge_request_event","CI_MERGE_REQUEST_IID":"17"}),"mr")
        for source in ("schedule","push","web","parent_pipeline","api","external"):
            env={"CI_PIPELINE_SOURCE":source,"CI_MERGE_REQUEST_IID":"17"}
            self.assertEqual(pipeline_context(env),"non-mr")
            self.assertEqual(select(["cmd/keep/cli.go"],context=pipeline_context(env)).indices,tuple(range(16)))
        self.assertEqual(pipeline_context({"CI_PIPELINE_SOURCE":"merge_request_event"}),"non-mr")
    def test_test_w3_always_present_on_narrow_path(self):
        self.assertIn('w3_stubs', select(['scripts/test_catalog_mutant_diagnostics.py']).names)
    def test_all_commands_are_registered_in_original_order(self):
        self.assertEqual(len(COMMANDS),16)
        self.assertEqual(NAMES,('mutation_shards','carriers','intake_baseline','intake_mutant','catalog_mutant','runnerproto','tenancy','cli_witnesses','approvals','builtin_job_cache','baseline_diag','w3_stubs','dispatch_baseline','mutation_select','mutation_select_redrun','intake_hpke_mutant'))
    def test_runner_uses_fixed_argv_order_and_timeout_env(self):
        calls=[]
        def fake(argv, **kwargs): calls.append((argv,kwargs['env']))
        run(select(['scripts/test_builtin_job_cache.py']),runner=fake,env={'BASE':'1'})
        self.assertEqual([c[0] for c in calls],[list(COMMANDS[i][1]) for i in (9,11,13,14)])
        self.assertEqual(calls[0][1]['KEEP_JOB_CACHE_REAL_TIMEOUT'],'1')
        self.assertNotIn('KEEP_JOB_CACHE_REAL_TIMEOUT',calls[1][1])

if __name__=='__main__': unittest.main()
