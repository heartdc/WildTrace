"""Real batch/queue/AST contracts; only process and Git observations are mocked."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ohvul import component_batch as batch, compiler_analysis as compiler, review_queue as queue
from ohvul.engine_adapter import normalize_findings, engine_result_to_audit_result
from ohvul.engine_profile import validate_profile
from ohvul.report.schema import build_audit_report
from ohvul.source_snapshot import source_snapshot
from tests.test_clang_facts import SOURCE, fixture
from tests.test_compiler_analysis import MACROS


class ComponentCompilerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'a.c').write_bytes(SOURCE)
        self.profile = self.base / 'profile.json'
        self.profile.write_text(json.dumps({
            'schema': 'engine-profile-0.1', 'component': 'fixture',
            'source_repositories': {'.': 'a' * 40}, 'source_files': ['a.c'],
            'include_dirs': [], 'defines': [], 'extra_compile_args': [],
            'engines': ['clang-static-analyzer']}), encoding='utf-8')
        self.manifest, self.output = self.base / 'manifest.json', self.base / 'out'
        self.jobs = [{'id': 'one', 'source_root': 'source', 'profile': 'profile.json',
                      'analyses': ['profile-engines', 'compiler-ast']}]
        self.write_manifest()
        for module in (batch, compiler):
            self.enterContext(patch.object(module, 'prepare_profile', side_effect=self.prepared))
            self.enterContext(patch.object(module, 'recheck_profile', side_effect=self.recheck))
        self.engine = self.enterContext(patch.object(batch, 'scan_engine_profile', side_effect=self.scanned))
        self.invoked = self.enterContext(patch.object(compiler, '_invoke', side_effect=self.reply))
        self.compiler_status = 'completed'
        self.empty_ast = False

    def write_manifest(self, version='0.2'):
        self.manifest.write_text(json.dumps({'schema': 'component-batch-' + version, 'jobs': self.jobs}))

    def prepared(self, path, root, **kwargs):
        profile = validate_profile(json.loads(path.read_bytes()))
        receipt = {'schema': 'profile-validation-0.1', 'profile_sha256': queue.sha256(path.read_bytes()),
                   'source_root': str(root), 'semgrep_rule_sha256': {},
                   'inputs': {'complete': True, 'source_files': 1, 'include_dirs': 0,
                              'missing_files': [], 'missing_include_dirs': [], 'missing_rule_files': []},
                   'provenance': {'verified': True, 'mismatches': [], 'repositories': 1,
                                  'checks': [{'repository': '.', 'expected': 'a' * 40, 'actual': 'a' * 40,
                                              'clean': True, 'status': 'matched'}]}}
        return profile, receipt

    def recheck(self, path, root, profile, receipt):
        if queue.sha256(path.read_bytes()) != receipt['profile_sha256']:
            raise ValueError('changed profile')

    def scanned(self, root, path, **kwargs):
        raw = normalize_findings({'findings': [{'rule': 'core.NullDereference',
            'description': 'synthetic diagnostic', 'location': {'file': 'a.c', 'line': 3}}]},
            engine='clang', source_root=root, engine_version='fixture')
        raw.update(status='completed', input_errors=[], files_scanned=1, engine_runs=1,
                   file_results=[{'source_file': str(root / 'a.c'), 'status': 'completed'}])
        result = engine_result_to_audit_result(raw, source_root=root, source_snapshot_sha256=source_snapshot(root))
        result['profile_validation'] = {**self.prepared(path, root)[1],
                                        'source_snapshot_sha256': source_snapshot(root)}
        return result

    def reply(self, command, timeout, **kwargs):
        if '--version' in command:
            raw = b'clang version 22.1.8\n'
        elif '-dM' in command:
            raw = MACROS
        else:
            tree, fn, _ = fixture()
            fn['loc']['file'] = command[-1]
            raw = json.dumps(tree if not self.empty_ast else {'kind': 'TranslationUnitDecl', 'inner': []}).encode()
            return {'status': self.compiler_status, 'reason': None if self.compiler_status == 'completed' else 'fixture_failure',
                    'stdout': raw, 'stderr': b'', 'seconds': .01,
                    'returncode': 0 if self.compiler_status == 'completed' else 1}
        return {'status': 'completed', 'reason': None, 'stdout': raw, 'stderr': b'', 'seconds': .01, 'returncode': 0}

    def run_batch(self, **kwargs):
        return batch.run_batch(self.manifest, self.output, timeout=60, **kwargs)

    def summary_path(self):
        return sorted(self.output.glob('summary-*.json'))[-1]

    def summary(self):
        return json.loads(self.summary_path().read_bytes())

    def result(self):
        return json.loads((self.output / 'one/result.json').read_bytes())

    def rewrite_result(self, value):
        summary = self.summary()
        for key, filename, data in [('result', 'result.json', value),
                                     ('report', 'report.candidate.json', build_audit_report(value))]:
            raw = queue.canonical_bytes(data)
            (self.output / 'one' / filename).write_bytes(raw)
            summary['jobs'][0]['artifacts'][key] = {'path': filename, 'bytes': len(raw), 'sha256': queue.sha256(raw)}
        self.summary_path().write_bytes(queue.canonical_bytes(summary))

    def test_compiler_only_does_not_run_profile_engines(self):
        self.jobs[0]['analyses'] = ['compiler-ast']; self.write_manifest()
        self.assertEqual(self.run_batch(), 0)
        self.engine.assert_not_called()
        self.assertEqual(self.invoked.call_count, 3)
        value = queue.build_review_queue(self.summary_path())
        self.assertEqual(value['sources'][0]['selected_engines'], ['compiler-ast'])
        self.assertEqual(value['groups'][0]['category'], 'memory_safety_candidate')
        self.assertTrue(value['groups'][0]['compiler_context']['observations'])
        queue.validate_review_queue(value, self.summary_path())

    def test_combined_engines_preserve_facts_without_double_counting_files(self):
        self.assertEqual(self.run_batch(), 0)
        result = self.result()
        self.assertEqual(result['scan']['files_scanned'], 1)
        self.assertEqual({x['engine'] for x in result['engine_observations']}, {'clang', compiler.ENGINE})
        value = queue.build_review_queue(self.summary_path())
        self.assertEqual((value['raw_diagnostics'], value['group_count']), (2, 2))
        self.assertEqual(value['sources'][0]['compiler_analysis']['files_scanned'], 1)
        self.assertTrue(all(g['final_verdict'] == 'undetermined' for g in value['groups']))

    def test_preflight_has_no_compiler_or_analyzer_invocation(self):
        self.assertEqual(self.run_batch(preflight_only=True), 0)
        self.engine.assert_not_called(); self.invoked.assert_not_called()
        self.assertEqual(self.summary()['status'], 'ready')
        self.assertEqual(self.summary()['jobs'][0]['selected_engines'], ['clang-static-analyzer', 'compiler-ast'])

    def test_legacy_schema_does_not_invoke_new_stage(self):
        self.jobs[0].pop('analyses'); self.write_manifest('0.1')
        self.assertEqual(self.run_batch(), 0)
        self.invoked.assert_not_called()
        self.assertEqual(self.summary()['schema'], 'component-batch-summary-0.1')
        self.assertNotIn('compiler_analysis', queue.build_review_queue(self.summary_path())['sources'][0])

    def test_invalid_selection_fails_before_any_execution(self):
        for analyses in ([], True, ['target-run'], ['compiler-ast'] * 2, ['compiler-ast', 'profile-engines']):
            with self.subTest(analyses=analyses):
                self.jobs[0]['analyses'] = analyses; self.write_manifest()
                with self.assertRaises((ValueError, TypeError)): self.run_batch()
                self.assertFalse(self.output.exists())
        self.invoked.assert_not_called(); self.engine.assert_not_called()

    def test_compiler_timeout_budget_rejected_before_jobs(self):
        with self.assertRaises(ValueError): batch.run_batch(self.manifest, self.output, timeout=121)
        self.invoked.assert_not_called(); self.engine.assert_not_called()

    def test_compiler_failure_keeps_engine_diagnostic_but_never_success_report(self):
        self.compiler_status = 'input_error'
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(len(self.result()['findings']), 1)
        self.assertTrue(self.result()['input_errors'])
        self.assertFalse((self.output / 'one/report.candidate.json').exists())
        with self.assertRaises(ValueError): queue.build_review_queue(self.summary_path())

    def test_engine_exception_keeps_compiler_result_without_success(self):
        self.engine.side_effect = OSError('unavailable analyzer')
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(len(self.result()['compiler_facts']), 1)
        self.assertEqual(len(self.result()['findings']), 1)
        self.assertEqual(self.result()['input_errors'][0]['analysis'], 'profile-engines')
        self.assertFalse((self.output / 'one/report.candidate.json').exists())

    def test_later_independent_job_continues_after_failure(self):
        second = self.base / 'second.json'; second.write_bytes(self.profile.read_bytes())
        self.jobs.append({**self.jobs[0], 'id': 'two', 'profile': 'second.json', 'analyses': ['compiler-ast']})
        self.write_manifest(); self.engine.side_effect = OSError('engine failure')
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual([j['status'] for j in self.summary()['jobs']], ['validation_failed', 'completed'])

    def test_zero_finding_compiler_coverage_and_limits_are_not_lost(self):
        self.empty_ast = True
        self.assertEqual(self.run_batch(), 0)
        compiler_summary = queue.build_review_queue(self.summary_path())['sources'][0]['compiler_analysis']
        self.assertEqual(compiler_summary['files_scanned'], 1)
        self.assertFalse(compiler_summary['units'][0]['coverage']['control_flow_proven'])

    def test_tampered_facts_rejected_even_with_rewritten_artifact_hashes(self):
        self.assertEqual(self.run_batch(), 0)
        result = self.result(); result['compiler_facts'][0]['statistics']['calls'] += 1
        self.rewrite_result(result)
        with self.assertRaises(ValueError): queue.build_review_queue(self.summary_path())

    def test_missing_facts_and_changed_profile_or_file_binding_rejected(self):
        self.assertEqual(self.run_batch(), 0)
        original = self.result()
        for field in ('compiler_facts', 'compiler_profile_validation', 'input_bindings_valid'):
            value = copy.deepcopy(original); value.pop(field); self.rewrite_result(value)
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                queue.build_review_queue(self.summary_path())

    def test_silently_dropped_compiler_diagnostic_rejected(self):
        self.assertEqual(self.run_batch(), 0)
        value = self.result(); value['findings'] = [f for f in value['findings'] if f['source'] != compiler.ENGINE]
        self.rewrite_result(value)
        with self.assertRaises(ValueError): queue.build_review_queue(self.summary_path())

    def test_selection_cannot_downgrade_to_hide_missing_compiler(self):
        self.assertEqual(self.run_batch(), 0)
        summary = self.summary(); summary['jobs'][0]['selected_engines'] = ['clang-static-analyzer']
        self.summary_path().write_bytes(queue.canonical_bytes(summary))
        with self.assertRaises(ValueError): queue.build_review_queue(self.summary_path())

    def test_offline_queue_never_opens_embedded_source_or_profile(self):
        self.assertEqual(self.run_batch(), 0)
        original = Path.open
        def confined(path, *args, **kwargs):
            self.assertTrue(path.is_relative_to(self.output), str(path))
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', confined), patch.object(compiler, '_invoke') as execute:
            queue.build_review_queue(self.summary_path())
            execute.assert_not_called()

    def test_one_command_reaches_handoff_without_models_or_task_closure(self):
        from tools.component_review import run_pipeline
        from ohvul import llm_review
        with patch.object(llm_review, 'chat_completion') as network:
            status = run_pipeline(self.manifest, self.output, timeout=60)
            network.assert_not_called()
        self.assertEqual(status['status'], 'static_review_ready')
        self.assertEqual((status['raw_diagnostics'], status['review_groups'], status['open_evidence_tasks']), (2, 2, 10))
        handoff = json.loads((self.output / 'review/handoff.json').read_bytes())
        self.assertTrue(all(g['compiler_context']['observations'] for g in handoff['groups']))
        self.assertTrue(all(t['answer'] == 'unknown' for g in handoff['groups'] for t in g['tasks']))
        self.assertFalse(status['target_executed'])
        self.assertEqual(status['runtime_verification'], 'not_run')

    def test_failed_pipeline_never_creates_readiness_record(self):
        from tools.component_review import run_pipeline
        self.compiler_status = 'timeout'
        with self.assertRaises(ValueError): run_pipeline(self.manifest, self.output, timeout=60)
        self.assertFalse((self.output / 'status.json').exists())
        self.assertFalse((self.output / 'review').exists())
        self.assertTrue((self.output / 'batch/one/result.json').exists())

    def test_pipeline_rejects_existing_or_source_output_before_execution(self):
        from tools.component_review import run_pipeline
        for out in (self.base, self.root / 'out'):
            with self.subTest(out=str(out)), self.assertRaises(ValueError):
                run_pipeline(self.manifest, out, timeout=60)
        self.engine.assert_not_called(); self.invoked.assert_not_called()

    def test_late_source_mutation_does_not_publish_readiness(self):
        from tools import component_review
        original = component_review.write_review_handoff
        def mutate(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.root / 'a.c').write_bytes(SOURCE + b'/* changed */')
            return result
        with patch.object(component_review, 'write_review_handoff', side_effect=mutate):
            with self.assertRaises(ValueError): component_review.run_pipeline(self.manifest, self.output, timeout=60)
        self.assertFalse((self.output / 'status.json').exists())

    def test_invalid_compiler_profile_and_execution_probes_cannot_be_accepted(self):
        self.assertEqual(self.run_batch(), 0)
        original = self.result()
        changes = [('compiler_probes', {'version': {}, 'layout': {}}),
                   ('compiler_profile_validation', {**original['compiler_profile_validation'], 'profile_sha256': '0' * 64})]
        for key, new in changes:
            value = copy.deepcopy(original); value[key] = new; self.rewrite_result(value)
            with self.subTest(field=key), self.assertRaises(ValueError): queue.build_review_queue(self.summary_path())


if __name__ == '__main__':
    unittest.main()
