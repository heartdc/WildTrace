"""Offline review fixtures: real evidence/report validation, no analyzers."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ohvul.engine_adapter import normalize_findings, engine_result_to_audit_result
from ohvul.report.schema import build_audit_report
from ohvul.source_snapshot import source_snapshot
from ohvul import review_queue as queue


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def raw_finding(engine='clang', rule='deadcode.DeadStores', description='unused value', line=2):
    return {'engine': engine, 'rule': rule, 'description': description,
            'location': {'file': 'a.c', 'line': line}}


class BatchFixture:
    def __init__(self, base, findings=None):
        self.base = base
        self.source = base / 'source'
        self.source.mkdir()
        (self.source / 'a.c').write_text('int f(int *p) {\n    return *p;\n}\n', encoding='utf-8')
        self.batch = base / 'batch'
        self.folder = self.batch / 'one'
        self.folder.mkdir(parents=True)
        self.summary_path = self.batch / 'summary-0003.json'
        self.output = base / 'review.json'
        normalized = []
        for item in findings if findings is not None else [raw_finding()]:
            engine = item['engine']
            item = {k: v for k, v in item.items() if k != 'engine'}
            value = normalize_findings({'findings': [item]}, engine=engine,
                                       source_root=self.source, engine_version='fixture')
            normalized.extend(value['findings'])
        snap = source_snapshot(self.source)
        self.result = engine_result_to_audit_result(
            {'engine': 'clang', 'engine_version': 'fixture', 'source_root': str(self.source),
             'status': 'completed', 'findings': normalized, 'files_scanned': 1,
             'input_errors': [], 'engine_runs': 1,
             'file_results': [{'source_file': str(self.source / 'a.c'), 'status': 'completed'}]},
            source_root=self.source, source_snapshot_sha256=snap)
        engines = sorted({x['source'] for x in normalized} or {'clang'})
        self.result['engine_observations'] = [
            {'engine': engine, 'engine_version': 'fixture', 'status': 'completed', 'input_errors': [],
             'scan': {'root': str(self.source), 'source_snapshot_sha256': snap, 'files_scanned': 1},
             'file_results': [{'source_file': str(self.source / 'a.c'), 'status': 'completed'}]}
            for engine in engines]
        self.profile = {'schema': 'profile-validation-0.1', 'profile_sha256': 'b' * 64,
                        'source_root': str(self.source), 'semgrep_rule_sha256': {},
                        'inputs': {'complete': True, 'source_files': 1, 'include_dirs': 0,
                                   'missing_files': [], 'missing_include_dirs': [], 'missing_rule_files': []},
                        'provenance': {'verified': True, 'mismatches': [], 'repositories': 1,
                                       'scope': 'declared_repositories', 'checks': [
                                           {'repository': '.', 'expected': 'a' * 40, 'actual': 'a' * 40,
                                            'clean': True, 'status': 'matched'}]}}
        self.result['profile_validation'] = {**copy.deepcopy(self.profile), 'source_snapshot_sha256': snap}
        self.receipt = {'schema': 'component-batch-receipt-0.1', 'boundary': copy.deepcopy(queue.BOUNDARY),
                        'manifest_sha256': 'c' * 64, 'source_root': str(self.source),
                        'profile': str(base / 'not-read-profile.json'), 'profile_sha256': 'b' * 64,
                        'source_snapshot_sha256': snap, 'profile_receipts': [copy.deepcopy(self.profile),
                             copy.deepcopy(self.result['profile_validation'])],
                        'preflight_only': False, 'outcome': 'completed', 'error': None,
                        'acceptance': 'requires_final_summary', 'elapsed_seconds': 1.0}
        self.job = {'id': 'one', 'status': 'completed', 'analysis_attempted': True,
                    'candidate_findings': len(normalized),
                    'selected_engines': ['clang-static-analyzer' if e == 'clang' else e for e in engines],
                    'inputs': {k: self.receipt[k] for k in (
                        'manifest_sha256', 'profile_sha256', 'source_snapshot_sha256', 'source_root', 'profile')},
                    'artifacts': {}, 'elapsed_seconds': 1.0, 'analysis_seconds': 0.5}
        self.summary = {'schema': 'component-batch-summary-0.1', 'status': 'completed',
                        'preflight_only': False, 'boundary': copy.deepcopy(queue.BOUNDARY),
                        'manifest': str(base / 'not-read-manifest.json'), 'manifest_sha256': 'c' * 64,
                        'jobs': [self.job], 'counts': {'completed': 1},
                        'totals': {'jobs': 1, 'completed': 1, 'analysis_attempted': 1,
                                   'ready': 0, 'blocked': 0, 'failed': 0, 'pending': 0},
                        'candidate_findings': len(normalized)}
        self.persist()

    def persist(self):
        self.report = build_audit_report(self.result)
        for label, filename, value in [('result', 'result.json', self.result),
                                       ('report', 'report.candidate.json', self.report),
                                       ('receipt', 'receipt.json', self.receipt)]:
            raw = encode(value)
            (self.folder / filename).write_bytes(raw)
            self.job['artifacts'][label] = {'path': filename, 'sha256': hashlib.sha256(raw).hexdigest(),
                                           'bytes': len(raw)}
        self.save_summary()

    def save_summary(self):
        self.summary_path.write_bytes(encode(self.summary))


class ReviewQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.f = BatchFixture(self.base)

    def build(self):
        return queue.build_review_queue(self.f.summary_path)

    def reject(self):
        with self.assertRaises((ValueError, OSError)):
            self.build()

    def test_deterministic_queue_and_independent_verification(self):
        a = self.build()
        self.assertEqual(a, self.build())
        self.assertEqual(a['raw_diagnostics'], 1)
        self.assertEqual(a['group_count'], 1)
        self.assertEqual(a['confirmed_vulnerabilities'], 0)
        self.assertEqual(a['final_verdict'], 'undetermined')
        self.assertEqual(a['groups'][0]['category'], 'code_quality_signal')
        queue.validate_review_queue(a, self.f.summary_path)

    def test_zero_finding_jobs_are_retained(self):
        self.f.result['findings'] = []
        self.f.result['evidence_bundles'] = []
        self.f.job['candidate_findings'] = self.f.summary['candidate_findings'] = 0
        self.f.persist()
        result = self.build()
        self.assertEqual(result['raw_diagnostics'], 0)
        self.assertEqual(len(result['sources']), 1)
        self.assertEqual(result['groups'], [])

    def test_never_reads_embedded_profile_manifest_or_source_paths(self):
        original = Path.open
        def restricted(path, *args, **kwargs):
            self.assertTrue(path.is_relative_to(self.f.batch), str(path))
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', restricted):
            self.build()

    def test_artifact_digest_and_byte_size_tamper(self):
        for key, value in [('sha256', 'f' * 64), ('bytes', 1), ('bytes', True)]:
            original = copy.deepcopy(self.f.job['artifacts'])
            self.f.job['artifacts']['result'][key] = value
            self.f.save_summary()
            self.reject()
            self.f.job['artifacts'] = original
        self.f.save_summary()

    def test_report_and_receipt_bytes_are_both_checked(self):
        for name in ['report.candidate.json', 'receipt.json']:
            path = self.f.folder / name
            before = path.read_bytes()
            path.write_bytes(before + b' ')
            self.reject()
            path.write_bytes(before)

    def test_preflight_running_failed_and_false_completed_rejected(self):
        for changes in ({'status': 'ready'}, {'status': 'running'}, {'status': 'failed'},
                        {'preflight_only': True}, {'candidate_findings': 2}, {'counts': {'completed': 2}}):
            original = copy.deepcopy(self.f.summary)
            self.f.summary.update(changes)
            self.f.save_summary()
            self.reject()
            self.f.summary = original
        self.f.save_summary()

    def test_boundary_boolean_is_not_integer_zero(self):
        self.f.summary['boundary']['confirmed_vulnerabilities'] = False
        self.f.save_summary()
        self.reject()

    def test_job_cannot_be_blocked_or_unattempted(self):
        self.f.job['status'] = 'blocked'
        self.f.save_summary()
        self.reject()
        self.f.job['status'] = 'completed'
        self.f.job['analysis_attempted'] = False
        self.f.save_summary()
        self.reject()

    def test_path_traversal_absolute_and_git_metadata_rejected(self):
        for name in ['../result.json', str(self.base / 'outside.json'), '.git', 'a/result.json']:
            self.f.job['artifacts']['result']['path'] = name
            self.f.save_summary()
            self.reject()

    def test_duplicate_case_alias_job_ids_rejected(self):
        other = copy.deepcopy(self.f.job)
        other['id'] = 'ONE'
        self.f.summary['jobs'].append(other)
        self.f.save_summary()
        self.reject()

    def test_json_duplicate_keys_and_nonfinite_rejected(self):
        original = self.f.summary_path.read_bytes()
        for raw in [original[:-2] + b',"status":"completed"}\n', b'{"schema":NaN}', b'[]']:
            self.f.summary_path.write_bytes(raw)
            self.reject()
        self.f.summary_path.write_bytes(original)

    def test_summary_limit_and_artifact_limit(self):
        with patch.object(queue, 'MAX_SUMMARY_BYTES', 5):
            self.reject()
        with patch.object(queue, 'MAX_ARTIFACT_BYTES', 5):
            self.reject()

    def test_corrupt_profile_and_snapshot_bindings(self):
        self.f.result['scan']['source_snapshot_sha256'] = 'e' * 64
        self.f.persist()
        self.reject()

    def test_receipt_outcome_and_provenance_are_not_trusted(self):
        self.f.receipt['outcome'] = 'blocked'
        self.f.persist()
        self.reject()
        self.f.receipt['outcome'] = 'completed'
        self.f.result['profile_validation']['provenance']['verified'] = False
        self.f.persist()
        self.reject()

    def test_duplicate_alert_and_non_candidate_findings_rejected(self):
        self.f.result['findings'].append(copy.deepcopy(self.f.result['findings'][0]))
        self.f.job['candidate_findings'] = self.f.summary['candidate_findings'] = 2
        self.f.persist()
        self.reject()
        self.f.result['findings'].pop()
        self.f.result['findings'][0]['status'] = 'verified'
        self.f.job['candidate_findings'] = self.f.summary['candidate_findings'] = 1
        self.f.persist()
        self.reject()

    def test_invalid_locations_rejected_even_when_report_is_rebuilt(self):
        original = copy.deepcopy(self.f.result)
        for loc in [{'file': '../out.c', 'line': 2}, {'file': '.git/config', 'line': 2},
                    {'file': 'a.c', 'line': True}, {'file': 'a.c', 'line': 0}]:
            self.f.result['findings'][0]['location'] = loc
            self.f.persist()
            self.reject()
            self.f.result = copy.deepcopy(original)

    def test_queue_tampering_removal_and_verdict_rejected(self):
        value = self.build()
        for mutated in [dict(value, groups=[]), dict(value, confirmed_vulnerabilities=1),
                        dict(value, raw_diagnostics=0), dict(value, final_verdict='safe')]:
            with self.assertRaises(ValueError):
                queue.validate_review_queue(mutated, self.f.summary_path)

    def test_output_is_exclusive_and_input_trees_are_protected(self):
        queue.write_review_queue(self.f.summary_path, self.f.output)
        original = self.f.output.read_bytes()
        with self.assertRaises((ValueError, OSError)):
            queue.write_review_queue(self.f.summary_path, self.f.output)
        self.assertEqual(self.f.output.read_bytes(), original)
        for path in [self.f.batch / 'new.json', self.f.source / 'new.json',
                     self.base / '.git' / 'new.json']:
            with self.assertRaises((ValueError, OSError)):
                queue.write_review_queue(self.f.summary_path, path)
            self.assertFalse(path.exists())

    def test_changed_input_while_building_is_rejected(self):
        original = queue.decode_json
        def changed(raw):
            value = original(raw)
            if isinstance(value, dict) and value.get('schema') == 'component-batch-receipt-0.1':
                self.f.summary_path.write_bytes(self.f.summary_path.read_bytes() + b' ')
            return value
        with patch.object(queue, 'decode_json', side_effect=changed):
            self.reject()

    def test_concurrent_destination_is_preserved(self):
        original = queue.recheck_inputs
        calls = []
        def race(captured):
            original(captured)
            calls.append(1)
            if len(calls) == 2:
                self.f.output.write_bytes(b'concurrent owner')
        with patch.object(queue, 'recheck_inputs', side_effect=race):
            with self.assertRaises(FileExistsError):
                queue.write_review_queue(self.f.summary_path, self.f.output)
        self.assertEqual(self.f.output.read_bytes(), b'concurrent owner')

    def test_missing_selected_engine_and_failed_file_outcome_rejected(self):
        self.f.job['selected_engines'].append('semgrep')
        self.f.save_summary()
        self.reject()
        self.f.job['selected_engines'].pop()
        self.f.result['engine_observations'][0]['file_results'][0]['status'] = 'input_error'
        self.f.persist()
        self.reject()

    def test_bound_presentation_fields_cannot_be_relabelled(self):
        original = copy.deepcopy(self.f.result)
        for field, value in [('source', 'semgrep'), ('rule', 'changed-rule'),
                             ('description', 'changed-description'), ('engine_version', 'changed-version')]:
            with self.subTest(field=field):
                self.f.result['findings'][0][field] = value
                self.f.persist()
                self.reject()
                self.f.result = copy.deepcopy(original)

    def test_duplicate_report_rows_rejected_even_with_fresh_artifact_hash(self):
        report = copy.deepcopy(self.f.report)
        report['findings'].append(copy.deepcopy(report['findings'][0]))
        raw = encode(report)
        (self.f.folder / 'report.candidate.json').write_bytes(raw)
        self.f.job['artifacts']['report'].update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        self.f.save_summary()
        self.reject()


class ReviewGroupingTests(unittest.TestCase):
    def build(self, findings):
        with tempfile.TemporaryDirectory() as temp:
            fixture = BatchFixture(Path(temp).resolve(), findings)
            return queue.build_review_queue(fixture.summary_path)

    def test_aliases_group_but_keep_every_observation(self):
        result = self.build([raw_finding(), raw_finding('clang-tidy', 'clang-analyzer-deadcode.DeadStores'),
                             raw_finding('clang-tidy', 'clang-analyzer-deadcode.DeadStores')])
        self.assertEqual(result['raw_diagnostics'], 3)
        self.assertEqual(result['group_count'], 1)
        self.assertEqual(len(result['groups'][0]['observations']), 3)
        self.assertEqual(len({x['alert_id'] for x in result['groups'][0]['observations']}), 3)

    def test_different_messages_and_unrelated_engines_do_not_merge(self):
        result = self.build([raw_finding(), raw_finding(description='different unused value'),
                             raw_finding('semgrep', 'clang-analyzer-deadcode.DeadStores')])
        self.assertEqual(result['group_count'], 3)
        self.assertIn('unclassified_requires_review', result['categories'])

    def test_api_advisory_does_not_claim_vulnerability(self):
        result = self.build([raw_finding('clang-tidy',
                             'clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling')])
        group = result['groups'][0]
        self.assertEqual(group['category'], 'api_advisory')
        self.assertEqual(group['final_verdict'], 'undetermined')
        self.assertTrue(group['review_questions'])
        self.assertTrue(all(q['status'] == 'unknown' for q in group['review_questions']))


if __name__ == '__main__':
    unittest.main()
