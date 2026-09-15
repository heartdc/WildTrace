"""Synthetic fixtures only; installed analyzers are never invoked."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ohvul import component_batch as batch
from ohvul.engine_adapter import engine_result_to_audit_result
from ohvul.engine_profile import validate_profile
from ohvul.source_snapshot import source_snapshot


class ComponentBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'a.c').write_bytes(b'int x;\n')
        self.profile = self.base / 'profile.json'
        self.profile.write_text(json.dumps({
            'schema': 'engine-profile-0.1', 'component': 'synthetic',
            'source_repositories': {'.': 'a' * 40}, 'source_files': ['a.c'],
            'include_dirs': [], 'defines': [], 'extra_compile_args': [],
            'engines': ['clang-static-analyzer']}), encoding='utf-8')
        self.manifest = self.base / 'manifest.json'
        self.output = self.base / 'new-output'
        self.jobs = [{'id': 'one', 'source_root': 'source', 'profile': 'profile.json'}]
        self.write_manifest()
        self.before = source_snapshot(self.root)
        self.prepare = self.enterContext(patch.object(batch, 'prepare_profile', side_effect=self.prepared))
        self.recheck = self.enterContext(patch.object(batch, 'recheck_profile', side_effect=self.checked))
        self.scan = self.enterContext(patch.object(batch, 'scan_engine_profile', side_effect=self.scanned))

    def write_manifest(self):
        self.manifest.write_bytes(json.dumps({'schema': 'component-batch-0.1', 'jobs': self.jobs}).encode())

    def prepared(self, path, root):
        # Typed receipt follows the real interface; evidence validation remains real.
        profile = validate_profile(json.loads(path.read_bytes()))
        receipt = {'schema': 'profile-validation-0.1',
                   'profile_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                   'source_root': str(root),
                   'provenance': {'verified': True, 'mismatches': [], 'repositories': 1,
                                  'checks': [], 'scope': 'declared_repositories'},
                   'inputs': {'complete': True, 'source_files': 1, 'include_dirs': 0,
                              'missing_files': [], 'missing_include_dirs': [], 'missing_rule_files': []},
                   'semgrep_rule_sha256': {}}
        return profile, receipt

    def checked(self, path, root, profile, receipt):
        if hashlib.sha256(path.read_bytes()).hexdigest() != receipt['profile_sha256']:
            raise ValueError('profile changed')

    def scanned(self, root, path, **kwargs):
        result = engine_result_to_audit_result({
            'engine': 'clang', 'engine_version': 'synthetic', 'status': 'completed',
            'findings': [], 'engine_runs': 1, 'files_scanned': 1, 'files_failed': 0,
            'file_results': [{'engine': 'clang', 'source_file': str(root / 'a.c'), 'status': 'completed'}]},
            source_root=root, source_snapshot_sha256=source_snapshot(root))
        result['profile_validation'] = {**self.prepared(path, root)[1],
                                        'source_snapshot_sha256': source_snapshot(root)}
        return result

    def run_batch(self, **kwargs):
        return batch.run_batch(self.manifest, self.output, **kwargs)

    def summary(self):
        return json.loads(sorted(self.output.glob('summary-*.json'))[-1].read_bytes())

    def assert_rejected(self, **kwargs):
        with self.assertRaises((ValueError, OSError, TypeError)):
            self.run_batch(**kwargs)
        self.assertFalse(self.output.exists())
        self.prepare.assert_not_called()
        self.scan.assert_not_called()

    def test_malformed_duplicate_empty_and_nonfinite_json_before_job_io(self):
        for raw in (b'', b'{', b'{}', b'[]', b'null', b'{"schema":"component-batch-0.1","jobs":[]}',
                    b'{"schema":"component-batch-0.1","jobs":[],"jobs":[]}',
                    b'{"schema":NaN,"jobs":[]}',
                    b'{"schema":"component-batch-0.1","jobs":[{"id":"a","id":"b"}]}'):
            with self.subTest(raw=raw):
                self.manifest.write_bytes(raw)
                with patch.object(Path, 'mkdir') as mkdir:
                    self.assert_rejected()
                    mkdir.assert_not_called()

    def test_invalid_schema_types_and_exact_keys(self):
        for jobs in ({}, None, [False], [{'id': 'x'}], [{**self.jobs[0], 'extra': 1}],
                     [{**self.jobs[0], 'source_root': True}], [{**self.jobs[0], 'profile': []}]):
            with self.subTest(jobs=jobs):
                self.jobs = jobs
                self.write_manifest()
                self.assert_rejected()
        for data in ({'schema': 'wrong', 'jobs': []}, {'schema': 'component-batch-0.1', 'jobs': [], 'x': 1}):
            self.manifest.write_bytes(json.dumps(data).encode())
            self.assert_rejected()

    def test_invalid_ids_and_case_duplicates(self):
        job = self.jobs[0]
        for name in (True, 1, None, '', '../x', '.git', 'a.b', 'CON', 'NUL', 'a/b', 'x ' , 'é', 'x' * 65):
            with self.subTest(name=name):
                self.jobs = [{**job, 'id': name}]
                self.write_manifest()
                self.assert_rejected()
        self.jobs = [job, {**job, 'id': 'ONE'}]
        self.write_manifest()
        self.assert_rejected()

    def test_duplicate_normalized_job_alias(self):
        self.jobs.append({'id': 'two', 'source_root': './source/../source', 'profile': './profile.json'})
        self.write_manifest()
        self.assert_rejected()

    def test_ambiguous_and_git_metadata_paths(self):
        for value in ('C:source', '\\source', '\\\\server\\share', '//server/share',
                      'source/.git', 'source/NUL', 'source/a.c:stream', 'source/trailing.'):
            with self.subTest(value=value):
                self.jobs[0]['source_root'] = value
                self.write_manifest()
                self.assert_rejected()

    def test_resource_limits(self):
        for kwargs in ({'max_jobs': True}, {'max_jobs': 0}, {'max_jobs': 1.5},
                       {'timeout': True}, {'timeout': 0}, {'timeout': float('inf')},
                       {'timeout': float('nan')}, {'timeout': '3'}, {'preflight_only': 1}):
            with self.subTest(kwargs=kwargs):
                self.assert_rejected(**kwargs)

    def test_manifest_limit(self):
        self.manifest.write_bytes(b' ' * (batch.MAX_MANIFEST_BYTES + 1))
        self.assert_rejected()

    def test_cli_timeout_matches_real_integer_adapter_contract(self):
        def real_contract(root, profile, **kwargs):
            if type(kwargs['timeout']) is not int:
                raise ValueError('real Clang adapter requires an integer timeout')
            return self.scanned(root, profile, **kwargs)
        self.scan.side_effect = real_contract
        code = batch.main(['--manifest', str(self.manifest), '--output', str(self.output),
                           '--timeout', '17'])
        self.assertEqual(code, 0)
        self.assertEqual(self.summary()['jobs'][0]['status'], 'completed')

    def test_fractional_and_excessive_timeout_rejected_before_io(self):
        for timeout in (1.5, 900.1, 901):
            with self.subTest(timeout=timeout):
                self.assert_rejected(timeout=timeout)

    def test_artifact_exclusive_create_preserves_concurrent_destination(self):
        destination = self.base / 'artifact.json'
        original = Path.open
        def concurrent_open(path, mode='r', *args, **kwargs):
            if path == destination and mode == 'xb':
                with original(path, 'wb') as stream:
                    stream.write(b'concurrent evidence')
            return original(path, mode, *args, **kwargs)
        with patch.object(Path, 'open', new=concurrent_open):
            with self.assertRaises(FileExistsError):
                batch._publish(destination, {'value': 1})
        self.assertEqual(destination.read_bytes(), b'concurrent evidence')

    def test_later_job_output_collision_before_writes(self):
        later = self.base / 'later'
        later.mkdir()
        self.jobs.append({'id': 'two', 'source_root': 'later', 'profile': 'profile.json'})
        self.write_manifest()
        self.output = later / 'output'
        self.assert_rejected()

    def test_profile_manifest_conflict(self):
        self.jobs[0]['profile'] = 'manifest.json'
        self.write_manifest()
        self.assert_rejected()

    def test_output_metadata_and_input_conflicts(self):
        for output in (self.root / '.git' / 'new', self.profile, self.manifest, self.base):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    batch.run_batch(self.manifest, output)
        self.prepare.assert_not_called()

    def test_exclusive_no_overwrite(self):
        self.output.mkdir()
        sentinel = self.output / 'old'
        sentinel.write_bytes(b'evidence')
        with self.assertRaises(ValueError):
            self.run_batch()
        self.assertEqual(sentinel.read_bytes(), b'evidence')
        self.prepare.assert_not_called()

    def test_output_created_after_validation_is_not_reused(self):
        original = batch._validate
        def raced(*args):
            validated = original(*args)
            self.output.mkdir()
            return validated
        with patch.object(batch, '_validate', side_effect=raced):
            with self.assertRaises(FileExistsError):
                self.run_batch()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_link_ancestors_rejected_without_resolving(self):
        original = batch.is_link
        with patch.object(batch, 'is_link', side_effect=lambda p: p == self.base or original(p)):
            self.assert_rejected()

    def test_source_link_blocks_preflight(self):
        original = batch.is_link
        with patch.object(batch, 'is_link', side_effect=lambda p: p == self.root / 'a.c' or original(p)):
            self.assertEqual(self.run_batch(), 1)
        self.scan.assert_not_called()
        self.assertEqual(self.summary()['jobs'][0]['status'], 'blocked')

    def test_true_preflight_ready_never_scans(self):
        self.assertEqual(self.run_batch(preflight_only=True), 0)
        self.scan.assert_not_called()
        summary = self.summary()
        self.assertTrue(summary['preflight_only'])
        self.assertEqual(summary['status'], 'ready')
        self.assertEqual(summary['counts'], {'ready': 1})
        self.assertFalse((self.output / 'one' / 'result.json').exists())
        self.assertEqual(source_snapshot(self.root), self.before)

    def test_wrong_git_pin_blocks_real_prepare(self):
        from ohvul.engine_profile import prepare_profile
        self.prepare.side_effect = prepare_profile
        def git(path, *args, **kwargs):
            if args[0] == 'config':
                return ''
            if args[0] == 'status':
                return ''
            if '--show-toplevel' in args:
                return str(self.root)
            return 'b' * 40
        with patch('ohvul.engine_profile._git', side_effect=git):
            self.assertEqual(self.run_batch(), 1)
        self.scan.assert_not_called()
        entry = self.summary()['jobs'][0]
        self.assertEqual(entry['status'], 'blocked')
        self.assertIn('HEAD does not match', entry['error']['message'])

    def test_clean_zero_findings_completed_and_hashes(self):
        self.assertEqual(self.run_batch(timeout=17), 0)
        summary = self.summary()
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(summary['candidate_findings'], 0)
        self.assertEqual(summary['boundary']['confirmed_vulnerabilities'], 0)
        self.assertEqual(summary['manifest_sha256'], hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        entry = summary['jobs'][0]
        for artifact in entry['artifacts'].values():
            raw = (self.output / 'one' / artifact['path']).read_bytes()
            self.assertEqual(artifact['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(artifact['bytes'], len(raw))
        receipt = json.loads((self.output / 'one' / 'receipt.json').read_bytes())
        self.assertEqual(len(receipt['profile_receipts']), 2)
        self.assertEqual(receipt['profile_sha256'], hashlib.sha256(self.profile.read_bytes()).hexdigest())
        self.assertEqual(source_snapshot(self.root), self.before)
        self.assertEqual(self.scan.call_args.kwargs, {'timeout': 17})

    def test_changed_profile_manifest_source_before_publication(self):
        for kind in ('profile', 'manifest', 'source'):
            with self.subTest(kind=kind):
                self.output = self.base / ('out-' + kind)
                self.write_manifest()
                original_profile = self.profile.read_bytes()
                (self.root / 'a.c').write_bytes(b'int x;\n')
                def changed(root, profile, **kwargs):
                    result = self.scanned(root, profile, **kwargs)
                    path = {'profile': self.profile, 'manifest': self.manifest, 'source': self.root / 'a.c'}[kind]
                    path.write_bytes(path.read_bytes() + b' ')
                    return result
                self.scan.side_effect = changed
                self.assertEqual(self.run_batch(), 1)
                self.assertEqual(self.summary()['status'], 'failed')
                self.assertFalse((self.output / 'one' / 'report.candidate.json').exists())
                self.profile.write_bytes(original_profile)

    def test_failed_then_successful_job(self):
        other = self.base / 'other.json'
        other.write_bytes(self.profile.read_bytes())
        self.jobs.append({'id': 'two', 'source_root': 'source', 'profile': 'other.json'})
        self.write_manifest()
        def scan(root, profile, **kwargs):
            if profile == self.profile:
                raise RuntimeError('synthetic analyzer failure')
            return self.scanned(root, profile, **kwargs)
        self.scan.side_effect = scan
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(self.scan.call_count, 2)
        self.assertEqual([j['status'] for j in self.summary()['jobs']], ['analysis_failed', 'completed'])

    def test_blocked_then_successful_job(self):
        other = self.base / 'other.json'
        other.write_bytes(self.profile.read_bytes())
        self.jobs.append({'id': 'two', 'source_root': 'source', 'profile': 'other.json'})
        self.write_manifest()
        self.prepare.side_effect = lambda p, r: self.prepared(p, r) if p == other else batch._raise(ValueError('blocked'))
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(self.prepare.call_count, 2)
        self.assertEqual(self.scan.call_count, 1)
        self.assertEqual([j['status'] for j in self.summary()['jobs']], ['blocked', 'completed'])

    def test_partial_preserves_engine_observations_no_report(self):
        def partial(root, profile, **kwargs):
            result = self.scanned(root, profile, **kwargs)
            result.update(status='partial', engine_observations=[
                {'engine': 'clang', 'status': 'completed', 'scan': {'files_scanned': 1}},
                {'engine': 'clang-tidy', 'status': 'timeout', 'scan': {'files_scanned': 0}}])
            return result
        self.scan.side_effect = partial
        self.assertEqual(self.run_batch(), 1)
        saved = json.loads((self.output / 'one' / 'result.json').read_bytes())
        self.assertEqual(saved['status'], 'partial')
        self.assertEqual(self.summary()['jobs'][0]['engine_observations'], saved['engine_observations'])
        self.assertFalse((self.output / 'one' / 'report.candidate.json').exists())

    def test_invalid_result_evidence_and_bindings(self):
        def corrupt(root, profile, **kwargs):
            result = self.scanned(root, profile, **kwargs)
            result['findings'] = [{'evidence_id': 'missing'}]
            return result
        self.scan.side_effect = corrupt
        self.assertEqual(self.run_batch(), 1)
        self.assertIn('Missing finding evidence', self.summary()['jobs'][0]['error']['message'])
        self.assertFalse((self.output / 'one' / 'report.candidate.json').exists())

    def test_result_wrong_snapshot_and_receipt(self):
        for field in ('snapshot', 'receipt', 'schema'):
            with self.subTest(field=field):
                self.output = self.base / ('bad-' + field)
                def corrupt(root, profile, **kwargs):
                    result = self.scanned(root, profile, **kwargs)
                    if field == 'snapshot':
                        result['scan']['source_snapshot_sha256'] = '0' * 64
                    elif field == 'receipt':
                        result['profile_validation']['profile_sha256'] = '0' * 64
                    else:
                        result['schema_version'] = '0.1'
                    return result
                self.scan.side_effect = corrupt
                self.assertEqual(self.run_batch(), 1)
                self.assertFalse((self.output / 'one' / 'report.candidate.json').exists())

    def test_report_contract_rejected(self):
        with patch.object(batch, 'build_audit_report', return_value={}):
            self.assertEqual(self.run_batch(), 1)
        self.assertFalse((self.output / 'one' / 'report.candidate.json').exists())

    def test_report_and_summary_publication_failure(self):
        original = batch._publish
        for target in ('report.candidate.json', 'summary-0002.json', 'summary-0003.json'):
            with self.subTest(target=target):
                self.output = self.base / ('failure-' + target)
                def fail(path, value):
                    if path.name == target:
                        raise OSError('synthetic publication failure')
                    return original(path, value)
                with patch.object(batch, '_publish', side_effect=fail):
                    self.assertEqual(self.run_batch(), 1)
                self.assertNotEqual(self.summary()['status'], 'completed')

    def test_final_recheck_detects_change_after_report_write(self):
        original = batch._publish
        def changed(path, value):
            artifact = original(path, value)
            if path.name == 'receipt.json':
                self.manifest.write_bytes(self.manifest.read_bytes() + b' ')
            return artifact
        with patch.object(batch, '_publish', side_effect=changed):
            self.assertEqual(self.run_batch(), 1)
        self.assertEqual(self.summary()['jobs'][0]['status'], 'binding_failed')

    def test_published_artifact_tamper_rejected(self):
        original = batch._publish
        def changed(path, value):
            artifact = original(path, value)
            if path.name == 'receipt.json':
                (path.parent / 'result.json').write_bytes(b'{}')
            return artifact
        with patch.object(batch, '_publish', side_effect=changed):
            self.assertEqual(self.run_batch(), 1)
        self.assertEqual(self.summary()['jobs'][0]['status'], 'binding_failed')

    def test_absolute_paths_and_cli_preflight_exit(self):
        self.jobs[0].update(source_root=str(self.root), profile=str(self.profile))
        self.write_manifest()
        self.assertEqual(batch.main(['--manifest', str(self.manifest), '--output', str(self.output),
                                     '--preflight-only', '--max-jobs', '1', '--timeout', '10']), 0)
        self.scan.assert_not_called()
        self.assertEqual(batch.main(['--manifest', str(self.manifest), '--output', str(self.output)]), 2)


if __name__ == '__main__':
    unittest.main()
