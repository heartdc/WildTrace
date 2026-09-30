"""Synthetic operator-record tests, never real execution or authorization."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from ohvul import runtime_evidence as runtime
from ohvul.detect.scanner import scan_path
from ohvul.report.schema import build_audit_report
from ohvul.review_queue import sha256
from ohvul.source_snapshot import source_snapshot


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'source'; self.root.mkdir()
        (self.root / 'a.c').write_text('void f(char *s) {char d[4]; strcpy(d,s);}\n', encoding='utf-8')
        self.result = scan_path(self.root)
        self.result['scan']['source_snapshot_sha256'] = source_snapshot(self.root)
        self.result_path, self.report_path = self.base / 'result.json', self.base / 'report.json'
        self.save(self.result_path, self.result)
        self.report = build_audit_report(self.result)
        self.save(self.report_path, self.report)
        self.alert = self.result['findings'][0]['alert_id']
        self.case_path = self.base / 'case.json'
        self.case = runtime.prepare_case(self.result_path, self.report_path, self.root, self.alert, self.case_path)
        self.artifacts = self.base / 'collected'; self.artifacts.mkdir()
        self.record_path = self.base / 'record.json'
        self.poc = self.artifact('poc.txt', 'synthetic contract fixture, not executable')
        self.build_log = self.artifact('build.txt', 'operator fixture: build succeeded')
        configuration = self.artifact('configuration.txt', 'TEST-ONLY build recipe and target configuration')
        self.record = {'schema': 'external-runtime-evidence-0.1', 'case_id': self.case['case_id'],
            'case_sha256': sha256(self.case_path.read_bytes()), 'origin': 'real_target',
            'product': {'name': 'TEST-ONLY', 'version': 'fixture', 'configuration_sha256': configuration['sha256']},
            'configuration': configuration,
            'environment': {'id': 'fixture-vm', 'isolation': 'vm', 'image_sha256': 'c' * 64},
            'authorization': {'reference': 'TEST-ONLY-NOT-A-GRANT', 'approved_by': 'fixture operator',
                              'environment_id': 'fixture-vm', 'case_id': self.case['case_id']},
            'trigger_definition': 'TEST-ONLY expected safety invariant violation',
            'poc': self.poc, 'patch': {'artifact': self.artifact('patch.txt', 'synthetic patch'),
                                      'source_snapshot_sha256': 'd' * 64}, 'runs': []}
        for i in range(3): self.add_run('baseline', str(i), 'triggered')
        self.add_run('independent', 'independent', 'triggered')
        self.add_run('patched', 'patched', 'not_triggered')
        self.add_run('regression', 'regression', 'passed')

    def save(self, path, value):
        path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')

    def artifact(self, name, text):
        path = self.artifacts / name
        path.write_text(text, encoding='utf-8')
        raw = path.read_bytes()
        return {'path': name, 'bytes': len(raw), 'sha256': sha256(raw)}

    def add_run(self, phase, suffix, status):
        run = {'id': phase + '-' + suffix, 'phase': phase, 'session_id': 'session-' + suffix,
            'operator': 'fixture', 'environment_id': 'fixture-vm',
            'source_snapshot_sha256': self.case['input_bindings']['source_snapshot_sha256']
                if phase in ('baseline', 'independent') else 'd' * 64,
            'poc_sha256': self.poc['sha256'], 'build_status': 'succeeded', 'target_executed': True,
            'status': status, 'exit_code': 0, 'elapsed_seconds': 1.0,
            'build_log': self.build_log, 'log': self.artifact(phase + '-' + suffix + '.log', phase + suffix),
            'reset_log': self.artifact('reset-' + suffix + '.log', 'TEST-ONLY reset receipt')
                if phase == 'independent' else None}
        self.record['runs'].append(run)
        return run

    def inspect(self):
        self.save(self.record_path, self.record)
        return runtime.inspect_runtime(self.case_path, self.result_path, self.report_path,
            self.root, self.record_path, self.artifacts)[0]

    def test_complete_records_are_not_vulnerability_or_execution_proof(self):
        value = self.inspect()
        self.assertEqual(value['status'], 'ready_for_human_evidence_review')
        self.assertEqual(value['confirmed_vulnerabilities'], 0)
        self.assertFalse(value['execution_independently_observed'])
        self.assertFalse(value['authorization_authenticity_verified'])
        self.assertFalse(value['patch_effectiveness_verified'])
        self.assertFalse(value['target_executed_by_this_tool'])

    def test_prepare_binds_source_and_does_not_grant_permission(self):
        self.assertFalse(self.case['execution_authorized_by_this_document'])
        self.assertEqual(set(self.case['runtime_requirements'].values()), {'pending'})
        self.assertEqual(self.case['input_bindings']['result_sha256'], sha256(self.result_path.read_bytes()))

    def test_synthetic_cannot_satisfy_real_target_gate(self):
        self.record['origin'] = 'synthetic'
        value = self.inspect()
        self.assertIn('real_target_origin_declared', value['blockers'])
        self.assertEqual(value['status'], 'evidence_incomplete')

    def test_missing_authorization_is_blocked_not_auto_approved(self):
        self.record['authorization'] = None
        self.assertIn('scoped_authorization_record_present', self.inspect()['blockers'])

    def test_authorization_scope_mismatch_is_rejected(self):
        self.record['authorization']['environment_id'] = 'wrong-vm'
        with self.assertRaises(ValueError): self.inspect()

    def test_single_trigger_does_not_satisfy_repetition(self):
        self.record['runs'] = self.record['runs'][2:]
        self.assertIn('repeat_trigger_records_complete', self.inspect()['blockers'])

    def test_build_failure_is_preserved_not_counted_as_trigger(self):
        r = self.record['runs'][0]
        r.update(status='build_failed', build_status='failed', target_executed=False, exit_code=2)
        value = self.inspect()
        self.assertIn('repeat_trigger_records_complete', value['blockers'])
        self.assertEqual(value['failure_records'][0]['status'], 'build_failed')

    def test_timeout_is_preserved_and_does_not_count_as_no_trigger(self):
        self.record['runs'][4].update(status='timeout', exit_code=None)
        value = self.inspect()
        self.assertIn('patch_nontrigger_records_complete', value['blockers'])
        self.assertEqual(value['failure_records'][0]['status'], 'timeout')

    def test_trigger_cannot_hide_failed_build_or_unexecuted_target(self):
        for changes in ({'build_status': 'failed'}, {'target_executed': False}, {'exit_code': None}):
            original = copy.deepcopy(self.record['runs'][0])
            self.record['runs'][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.inspect()
            self.record['runs'][0] = original

    def test_independent_session_cannot_reuse_baseline_session(self):
        self.record['runs'][3]['session_id'] = self.record['runs'][0]['session_id']
        self.assertIn('separate_session_trigger_records_complete', self.inspect()['blockers'])

    def test_patch_alone_is_not_effectiveness_evidence(self):
        self.record['runs'] = self.record['runs'][:4]
        value = self.inspect()
        self.assertIn('patch_nontrigger_records_complete', value['blockers'])
        self.assertIn('functional_regression_records_complete', value['blockers'])

    def test_failed_functional_regression_blocks_patch_completion(self):
        self.record['runs'][-1].update(status='failed', exit_code=1)
        self.assertIn('functional_regression_records_complete', self.inspect()['blockers'])

    def test_nontrigger_and_regression_cannot_hide_nonzero_exit(self):
        for index in (4, 5):
            self.record['runs'][index]['exit_code'] = 1
            with self.subTest(index=index), self.assertRaises(ValueError): self.inspect()
            self.record['runs'][index]['exit_code'] = 0

    def test_independent_execution_requires_reset_record(self):
        self.record['runs'][3]['reset_log'] = None
        self.assertIn('separate_session_trigger_records_complete', self.inspect()['blockers'])

    def test_configuration_digest_must_match_collected_configuration(self):
        self.record['product']['configuration_sha256'] = 'e' * 64
        with self.assertRaises(ValueError): self.inspect()

    def test_run_poc_or_source_cannot_be_substituted(self):
        for key in ('poc_sha256', 'source_snapshot_sha256'):
            previous = self.record['runs'][0][key]
            self.record['runs'][0][key] = 'f' * 64
            with self.subTest(key=key), self.assertRaises(ValueError): self.inspect()
            self.record['runs'][0][key] = previous

    def test_duplicate_runs_and_log_reuse_are_rejected(self):
        self.record['runs'].append(copy.deepcopy(self.record['runs'][0]))
        with self.assertRaises(ValueError): self.inspect()
        self.record['runs'].pop()
        self.record['runs'][1]['log'] = copy.deepcopy(self.record['runs'][0]['log'])
        with self.assertRaises(ValueError): self.inspect()

    def test_aliased_logs_cannot_inflate_repeat_count(self):
        original = self.record['runs'][0]['log']; destination = self.artifacts / 'alias.log'
        try: os.link(self.artifacts / original['path'], destination)
        except OSError: self.skipTest('hard links unavailable')
        self.record['runs'][1]['log'] = {**original, 'path': 'alias.log'}
        with self.assertRaises(ValueError): self.inspect()

    def test_log_tamper_or_wrong_size_is_rejected(self):
        self.record['runs'][0]['log']['bytes'] += 1
        with self.assertRaises(ValueError): self.inspect()
        self.record['runs'][0]['log']['bytes'] -= 1
        (self.artifacts / self.record['runs'][0]['log']['path']).write_text('tampered', encoding='utf-8')
        with self.assertRaises(ValueError): self.inspect()

    def test_artifact_escape_and_links_are_rejected(self):
        previous = copy.deepcopy(self.record['poc'])
        for name in ('../poc.txt', 'C:/outside.txt', '/outside.txt', 'sub/../../poc.txt'):
            self.record['poc'] = {**previous, 'path': name}
            with self.subTest(name=name), self.assertRaises(ValueError): self.inspect()
        self.record['poc'] = previous
        from ohvul import source_scope
        real = source_scope.is_link
        with patch.object(source_scope, 'is_link', side_effect=lambda p: p.name == 'poc.txt' or real(p)):
            with self.assertRaises(ValueError): self.inspect()

    def test_case_or_report_source_mismatch_is_rejected(self):
        self.case['candidate']['description'] = 'forged'
        self.save(self.case_path, self.case)
        with self.assertRaises(ValueError): self.inspect()

    def test_actual_source_mutation_invalidates_existing_case(self):
        (self.root / 'a.c').write_text('void f(void) {}\n', encoding='utf-8')
        with self.assertRaises(ValueError): self.inspect()

    def test_duplicate_report_alert_cannot_be_deduplicated_into_validity(self):
        self.report['findings'].append(copy.deepcopy(self.report['findings'][0]))
        self.save(self.report_path, self.report)
        with self.assertRaises(ValueError):
            runtime.prepare_case(self.result_path, self.report_path, self.root, self.alert, self.base / 'other.json')

    def test_prepare_no_overwrite_and_no_source_output(self):
        for output in (self.case_path, self.root / 'new.json'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                runtime.prepare_case(self.result_path, self.report_path, self.root, self.alert, output)

    def test_runtime_limits_and_json_duplicates_fail_closed(self):
        original = self.record['runs'][0]['elapsed_seconds']
        for value in (True, float('nan'), -1, 86401):
            self.record['runs'][0]['elapsed_seconds'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): self.inspect()
        self.record['runs'][0]['elapsed_seconds'] = original
        self.save(self.record_path, self.record)
        raw = self.record_path.read_text(encoding='utf-8')
        self.record_path.write_text(raw[:-1] + ',"runs":[]}', encoding='utf-8')
        with self.assertRaises(ValueError):
            runtime.inspect_runtime(self.case_path, self.result_path, self.report_path, self.root,
                                    self.record_path, self.artifacts)

    def test_offline_import_never_invokes_target_model_or_network(self):
        with patch('subprocess.Popen') as proc, patch('urllib.request.urlopen') as net:
            self.inspect()
        proc.assert_not_called(); net.assert_not_called()

    def test_publication_rechecks_artifact_bytes(self):
        self.save(self.record_path, self.record)
        original = runtime.exclusive_json
        def mutate(*args, **kwargs):
            (self.artifacts / self.poc['path']).write_text('changed', encoding='utf-8')
            return original(*args, **kwargs)
        output = self.base / 'appendix.json'
        with patch.object(runtime, 'exclusive_json', side_effect=mutate), self.assertRaises(ValueError):
            runtime.write_runtime_review(self.case_path, self.result_path, self.report_path, self.root,
                self.record_path, self.artifacts, output)
        self.assertFalse(output.exists())

    def test_cli_offline_verify_rejects_incomplete_and_tampered_appendix(self):
        self.save(self.record_path, self.record)
        output = self.base / 'appendix.json'
        args = ['--case', str(self.case_path), '--result', str(self.result_path), '--report', str(self.report_path),
                '--root', str(self.root), '--record', str(self.record_path),
                '--artifacts-root', str(self.artifacts), '--output', str(output)]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(runtime.main(['inspect', *args]), 0)
            self.assertEqual(runtime.main(['verify', *args]), 0)
            doc = json.loads(output.read_bytes()); doc['confirmed_vulnerabilities'] = 1
            self.save(output, doc)
            self.assertEqual(runtime.main(['verify', *args]), 2)
        self.record['origin'] = 'synthetic'; self.save(self.record_path, self.record)
        args[-1] = str(self.base / 'synthetic-appendix.json')
        with redirect_stdout(io.StringIO()):
            self.assertEqual(runtime.main(['inspect', *args]), 1)
            self.assertEqual(runtime.main(['verify', *args]), 1)


if __name__ == '__main__':
    unittest.main()
