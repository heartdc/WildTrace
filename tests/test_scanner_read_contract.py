"""Regression tests for explicit coverage and failure propagation."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from ohvul.detect.scanner import scan_path
from ohvul.shards import scan_manifest


class ScannerReadContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'a.c').write_text('int a;\n', encoding='utf-8')
        (self.root / 'bad.c').write_bytes(b'\xff\xfe\xff')

    def test_decode_failure_is_not_successful_coverage(self):
        result = scan_path(self.root)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['scan']['files_scanned'], 1)
        self.assertEqual(result['scan']['files_failed'], 1)
        self.assertEqual(result['input_errors'][0]['error_type'], 'UnicodeDecodeError')

    def test_all_failed_inputs_are_input_error(self):
        result = scan_path(self.root, relative_files=['bad.c'])
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['scan']['files_scanned'], 0)

    def test_read_oserror_is_recorded(self):
        with patch('pathlib.Path.read_bytes', side_effect=PermissionError('synthetic denied')), \
                patch('pathlib.Path.read_text', side_effect=PermissionError('synthetic denied')):
            result = scan_path(self.root, relative_files=['a.c'])
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['scan']['files_attempted'], 1)
        self.assertEqual(result['scan']['files_scanned'], 0)
        self.assertEqual(result['input_errors'][0]['error_type'], 'PermissionError')

    def test_missing_explicit_source_is_not_silently_skipped(self):
        result = scan_path(self.root, relative_files=['missing.c'])
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['scan']['files_failed'], 1)

    def test_invalid_scope_types_and_aliases_are_rejected(self):
        for entries in ('a.c', [], [None], ['a.c', './a.c'], [str(self.root / 'a.c')]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                scan_path(self.root, relative_files=entries)

    def test_invalid_root_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_path(self.base / 'missing')

    def test_success_records_exact_source_bytes_digest(self):
        import hashlib
        (self.root / 'a.c').write_text('memcpy(dst,src,n);\n', encoding='utf-8')
        result = scan_path(self.root, relative_files=['a.c'])
        digest = hashlib.sha256((self.root / 'a.c').read_bytes()).hexdigest()
        self.assertEqual(result['findings'][0]['evidence']['file_sha256'], digest)
        self.assertEqual(result['file_results'][0]['file_sha256'], digest)

    def test_shard_merge_preserves_partial_status_and_errors(self):
        result = scan_manifest(self.root, {'root': str(self.root.resolve()),
                                         'shards': [{'files': ['a.c']}, {'files': ['bad.c']}]})
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['scan']['files_scanned'], 1)
        self.assertEqual(result['scan']['files_failed'], 1)
        self.assertEqual(len(result['input_errors']), 1)

    def test_cli_failed_read_does_not_publish_success(self):
        from ohvul import cli
        from ohvul.workflow import AuditJournal, load_checkpoint
        output, checkpoint, journal = (self.base / n for n in ('result.json', 'checkpoint.json', 'journal.log'))
        argv = ['cli', str(self.root), '--output', str(output), '--checkpoint', str(checkpoint),
                '--journal', str(journal), '--task-id', 'read-failure']
        with patch.object(sys, 'argv', argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                cli.main()
        self.assertNotEqual(error.exception.code, 0)
        self.assertFalse(output.exists())
        self.assertEqual(load_checkpoint(checkpoint).state, 'blocked')
        self.assertIsNone(load_checkpoint(checkpoint).result_sha256)
        self.assertEqual(AuditJournal(journal).last_status('read-failure'), 'aborted')

    def test_enumeration_failure_is_not_an_empty_success(self):
        def failed_walk(root, **kwargs):
            error = PermissionError('synthetic directory denial')
            error.filename = str(root / 'locked')
            kwargs['onerror'](error)
            return iter(())
        with patch('ohvul.detect.scanner.os.walk', side_effect=failed_walk):
            result = scan_path(self.root)
        self.assertEqual(result['status'], 'input_error')
        self.assertFalse(result['scan']['scope_complete'])
        self.assertIsNone(result['scan']['files_requested'])
        self.assertEqual(result['input_errors'][0]['stage'], 'enumeration')

    def test_explicit_link_path_is_rejected_without_read(self):
        with patch('ohvul.source_scope.is_link', return_value=True), patch('pathlib.Path.read_bytes') as read:
            result = scan_path(self.root, relative_files=['a.c'])
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['scan']['files_scanned'], 0)
        read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
