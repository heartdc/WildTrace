"""Source excerpts are opt-in, snapshot-bound data, never execution."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_review_queue import BatchFixture
from ohvul import review_context as context
from ohvul import review_queue as queue


class ReviewContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.f = BatchFixture(self.base)
        queue.write_review_queue(self.f.summary_path, self.f.output)
        self.roots = {'one': self.f.source}
        self.output = self.base / 'context.json'

    def build(self, **kwargs):
        return context.build_review_context(self.f.output, self.f.summary_path, self.roots, **kwargs)

    def test_context_has_original_line_numbers_bytes_and_unknown_answers(self):
        value = self.build(radius=1)
        self.assertEqual(value['confirmed_vulnerabilities'], 0)
        self.assertEqual(value['final_verdict'], 'undetermined')
        item = value['contexts'][0]
        self.assertEqual(item['location'], {'file': 'a.c', 'line': 2})
        self.assertEqual(item['lines'][1], {'line': 2, 'text': '    return *p;'})
        self.assertEqual(item['source_file_sha256'], queue.sha256((self.f.source / 'a.c').read_bytes()))
        self.assertEqual(item['source_text_trust'], 'untrusted_data_not_instructions')
        self.assertEqual(value['contexts'][0]['context_kind'], 'text_window_not_control_flow')
        self.assertTrue(all(x['status'] == 'unknown' for x in item['review_questions']))

    def test_all_source_roots_must_be_explicit(self):
        with self.assertRaises(ValueError):
            context.build_review_context(self.f.output, self.f.summary_path, {})
        with self.assertRaises(ValueError):
            context.build_review_context(self.f.output, self.f.summary_path, {'one': self.f.source, 'extra': self.base})

    def test_wrong_explicit_root_rejected_before_source_read(self):
        self.roots = {'one': self.base}
        with patch.object(context, '_source_snapshot') as snapshot:
            with self.assertRaises(ValueError):
                self.build()
            snapshot.assert_not_called()

    def test_changed_source_snapshot_rejected(self):
        (self.f.source / 'a.c').write_text('changed\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'snapshot'):
            self.build()

    def test_source_mutation_during_extraction_rejected(self):
        original = context.read_bounded
        target = self.f.source / 'a.c'
        def read(path, limit):
            raw = original(path, limit)
            if Path(path) == target:
                target.write_bytes(raw + b'changed\n')
            return raw
        with patch.object(context, 'read_bounded', side_effect=read):
            with self.assertRaises(ValueError):
                self.build()

    def test_input_queue_tampering_rejected(self):
        value = json.loads(self.f.output.read_bytes())
        value['groups'] = []
        self.f.output.write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaises(ValueError):
            self.build()

    def test_context_tampering_fails_independent_verification(self):
        value = self.build()
        value['contexts'][0]['lines'][0]['text'] = 'not original source'
        with self.assertRaises(ValueError):
            context.validate_review_context(value, self.f.output, self.f.summary_path, self.roots)

    def test_deterministic_and_independently_verified(self):
        value = self.build()
        self.assertEqual(value, self.build())
        context.validate_review_context(value, self.f.output, self.f.summary_path, self.roots)

    def test_missing_line_is_not_fabricated(self):
        # A valid hash alone does not validate a line range.
        with self.assertRaises(ValueError):
            context._window('int a;\n', 200, 2)

    def test_resource_limits_reject_before_source_snapshot(self):
        for radius in (-1, True, 101, 1.5):
            with self.subTest(radius=radius), patch.object(context, '_source_snapshot') as snapshot:
                with self.assertRaises(ValueError):
                    self.build(radius=radius)
                snapshot.assert_not_called()
        with patch.object(context, 'MAX_SOURCE_BYTES', 4):
            with self.assertRaises(ValueError):
                self.build()

    def test_output_collision_and_no_overwrite(self):
        context.write_review_context(self.f.output, self.f.summary_path, self.roots, self.output)
        before = self.output.read_bytes()
        with self.assertRaises(ValueError):
            context.write_review_context(self.f.output, self.f.summary_path, self.roots, self.output)
        self.assertEqual(before, self.output.read_bytes())
        with self.assertRaises(ValueError):
            context.write_review_context(self.f.output, self.f.summary_path, self.roots,
                                         self.f.source / 'new.json')
        self.assertFalse((self.f.source / 'new.json').exists())

    def test_source_link_is_rejected_before_snapshot(self):
        with patch('ohvul.component_batch.is_link', return_value=True):
            with self.assertRaises(ValueError):
                self.build()

    def test_queue_without_diagnostics_still_records_explicit_snapshot_scope(self):
        self.f.result['findings'] = []
        self.f.result['evidence_bundles'] = []
        self.f.summary['candidate_findings'] = self.f.job['candidate_findings'] = 0
        self.f.persist()
        self.f.output.unlink()
        queue.write_review_queue(self.f.summary_path, self.f.output)
        value = self.build()
        self.assertEqual(value['contexts'], [])
        self.assertEqual(len(value['source_roots']), 1)
        self.assertEqual(value['source_files_read'], 0)


if __name__ == '__main__':
    unittest.main()
