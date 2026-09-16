"""Offline delivery checks reuse the real pipeline with mocked engine I/O."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import component_review as pipeline
from tests import test_component_compiler_integration as fixtures


class DeliveryVerificationTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.ComponentCompilerIntegrationTests()
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        self.output = self.fx.base / 'delivery'
        self.status = pipeline.run_pipeline(self.fx.manifest, self.output)
        self.status_path = self.output / 'status.json'

    def verify(self):
        return pipeline.verify_pipeline(self.fx.manifest, self.output)

    def read(self, path):
        return json.loads(path.read_bytes())

    def write(self, path, value):
        path.write_text(json.dumps(value), encoding='utf-8')

    def fingerprints(self):
        return {p.relative_to(self.fx.base).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.fx.base.rglob('*') if p.is_file()}

    def test_verify_never_reruns_analysis_or_changes_files(self):
        before = self.fingerprints()
        engine_calls, compiler_calls = self.fx.engine.call_count, self.fx.invoked.call_count
        with patch.object(pipeline, 'run_batch', side_effect=AssertionError('analysis must not run')):
            result = self.verify()
            code = pipeline.main(['--manifest', str(self.fx.manifest), '--output', str(self.output), '--verify'])
        self.assertEqual(code, 0)
        self.assertEqual(result, self.status)
        self.assertEqual(result['runtime_verification'], 'not_run')
        self.assertEqual(result['confirmed_vulnerabilities'], 0)
        self.assertEqual(before, self.fingerprints())
        self.assertEqual((engine_calls, compiler_calls), (self.fx.engine.call_count, self.fx.invoked.call_count))

    def test_readiness_fields_cannot_be_relabelled(self):
        for key, value in [('status', 'submission_ready'), ('runtime_verification', 'passed'),
                           ('confirmed_vulnerabilities', 1), ('review_groups', 0),
                           ('manifest_sha256', '0' * 64), ('jobs', 2), ('model_invoked', True)]:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.status)
                changed[key] = value
                self.write(self.status_path, changed)
                with self.assertRaises(ValueError): self.verify()
        self.write(self.status_path, self.status)

    def test_artifact_path_in_receipt_never_selects_an_input(self):
        changed = copy.deepcopy(self.status)
        changed['artifacts'][0]['path'] = '../unrelated-secret.txt'
        self.write(self.status_path, changed)
        seen = []
        original = pipeline.read_bounded
        def read(path, limit):
            seen.append(Path(path))
            return original(path, limit)
        with patch.object(pipeline, 'read_bounded', side_effect=read):
            with self.assertRaises(ValueError): self.verify()
        self.assertFalse(any(p.name == 'unrelated-secret.txt' for p in seen))

    def test_current_profile_and_manifest_bytes_are_required(self):
        for path in (self.fx.profile, self.fx.manifest):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                with self.assertRaises(ValueError): self.verify()
                path.write_bytes(original)

    def test_source_mutation_is_not_accepted_by_unchanged_receipt(self):
        (self.fx.root / 'a.c').write_bytes(b'void changed(void) {}\n')
        with self.assertRaises(ValueError): self.verify()

    def test_queue_tamper_even_with_receipt_rehash_is_rejected(self):
        path = self.output / 'review/queue.json'
        value = self.read(path)
        value['raw_diagnostics'] += 1
        self.write(path, value)
        status = copy.deepcopy(self.status)
        status['raw_diagnostics'] += 1
        artifact = next(x for x in status['artifacts'] if x['path'] == 'review/queue.json')
        raw = path.read_bytes()
        artifact.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self.write(self.status_path, status)
        with self.assertRaises(ValueError): self.verify()

    def test_missing_or_truncated_receipt_does_not_get_recreated(self):
        self.status_path.unlink()
        with self.assertRaises((ValueError, OSError)): self.verify()
        self.assertFalse(self.status_path.exists())
        self.status_path.write_bytes(b'{')
        with self.assertRaises(ValueError): self.verify()
        self.assertEqual(self.status_path.read_bytes(), b'{')

    def test_original_run_mode_still_rejects_existing_output(self):
        before = self.fingerprints()
        with self.assertRaises(ValueError):
            pipeline.run_pipeline(self.fx.manifest, self.output)
        self.assertEqual(before, self.fingerprints())

    def test_malformed_summary_and_selection_are_clean_cli_rejections(self):
        path = self.output / 'batch/summary-0003.json'
        original = self.read(path)
        changed = copy.deepcopy(original)
        changed['jobs'][0]['analysis_selection'] = []
        for value in ([], changed):
            with self.subTest(value=value):
                self.write(path, value)
                self.assertEqual(pipeline.main(['--manifest', str(self.fx.manifest),
                    '--output', str(self.output), '--verify']), 1)
        self.write(path, original)

    def test_status_change_during_verify_is_rejected(self):
        original = pipeline.validate_review_handoff
        def change(*args, **kwargs):
            original(*args, **kwargs)
            modified = copy.deepcopy(self.status)
            modified['confirmed_vulnerabilities'] = 1
            self.write(self.status_path, modified)
        with patch.object(pipeline, 'validate_review_handoff', side_effect=change):
            with self.assertRaises(ValueError): self.verify()


if __name__ == '__main__':
    unittest.main()
