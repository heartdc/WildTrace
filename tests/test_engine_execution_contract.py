"""Synthetic analyzer outcomes; no compiler, network or target execution."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ohvul import engine_cli, cli
from ohvul.engine_adapter import engine_result_to_audit_result, merge_engine_result, normalize_semgrep_json, normalize_clang_plist
from ohvul.engine_shards import scan_engine_manifest, scan_engine_shard
from ohvul.source_snapshot import source_snapshot
from ohvul.workflow.fsm import load_checkpoint
from ohvul.workflow.journal import AuditJournal


class EngineExecutionContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.root = self.home / 'source'
        self.root.mkdir()
        for name in ('a.c', 'b.c'):
            (self.root / name).write_text('int value;\n', encoding='utf-8')

    def normalized(self, status='completed', **extra):
        return {'engine': 'clang', 'engine_version': 'synthetic',
                'source_root': str(self.root.resolve()), 'findings': [],
                'status': status, **extra}

    def manifest(self, files):
        return {'root': str(self.root.resolve()), 'shards': [{'files': files}]}

    def projected(self, engine='clang', status='completed', snapshot='a' * 64):
        result = engine_result_to_audit_result(
            {'engine': engine, 'engine_version': 'synthetic', 'findings': []},
            source_root=self.root, source_snapshot_sha256=snapshot,
        )
        result['status'] = status
        result['scan']['files_scanned'] = 1 if status == 'completed' else 0
        result['input_errors'] = ([] if status == 'completed' else
                                  [{'engine': engine, 'status': status, 'reason': 'synthetic failure'}])
        return result

    def run_cli(self, *arguments):
        argv = ['engine_cli', str(self.root / 'a.c'), '--source-root', str(self.root), *arguments]
        with patch.object(sys, 'argv', argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            try:
                return engine_cli.main()
            except SystemExit as exc:
                return exc.code

    def test_clean_zero_findings_counts_successfully_analyzed_file(self):
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value=self.normalized()):
            result = scan_engine_shard(self.root, {'files': ['a.c']})
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['scan']['files_scanned'], 1)
        self.assertEqual(result['scan']['files_failed'], 0)

    def test_partial_success_is_independent_of_candidate_count(self):
        outcomes = [self.normalized(), self.normalized('timeout')]
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=outcomes):
            result = scan_engine_manifest(self.root, self.manifest(['a.c', 'b.c']))
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['scan']['files_scanned'], 1)
        self.assertEqual(result['scan']['files_failed'], 1)
        self.assertEqual(result['engine_runs'], 2)
        self.assertEqual(result['input_errors'][0]['status'], 'timeout')

    def test_all_failures_are_not_successful_coverage(self):
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value=self.normalized('input_error')):
            result = scan_engine_manifest(self.root, self.manifest(['a.c', 'b.c']))
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['scan']['files_scanned'], 0)
        self.assertEqual(result['scan']['files_failed'], 2)

    def test_empty_manifest_is_not_a_completed_scan(self):
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer') as analyzer:
            with self.assertRaises(ValueError):
                scan_engine_manifest(self.root, self.manifest([]))
        analyzer.assert_not_called()

    def test_absolute_manifest_path_is_rejected_without_execution(self):
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer') as analyzer:
            result = scan_engine_shard(self.root, {'files': [str(self.root / 'a.c')]})
        analyzer.assert_not_called()
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['scan']['files_attempted'], 0)

    def test_source_change_during_engine_scan_is_rejected(self):
        def analyzer(*args, **kwargs):
            (self.root / 'b.c').write_text('int changed;\n', encoding='utf-8')
            return self.normalized()

        with patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=analyzer):
            with self.assertRaisesRegex(ValueError, 'snapshot'):
                scan_engine_manifest(self.root, self.manifest(['a.c']))

    def test_engine_start_failure_becomes_explicit_error(self):
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=OSError('not installed')):
            result = scan_engine_manifest(self.root, self.manifest(['a.c']))
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['input_errors'][0]['status'], 'input_error')
        self.assertIn('not installed', result['input_errors'][0]['reason'])

    def test_completed_engine_with_errors_is_not_counted_as_success(self):
        outcome = self.normalized(input_errors=[{'status': 'input_error'}])
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value=outcome):
            result = scan_engine_manifest(self.root, self.manifest(['a.c']))
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['scan']['files_scanned'], 0)

    def test_projection_preserves_failure_and_explicit_coverage(self):
        normalized = self.normalized('partial', files_scanned=1,
                                     input_errors=[{'engine': 'clang', 'status': 'timeout'}])
        result = engine_result_to_audit_result(normalized, source_root=self.root)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['scan']['files_scanned'], 1)
        self.assertEqual(result['input_errors'][0]['status'], 'timeout')

    def test_projection_does_not_invent_coverage_from_findings(self):
        result = engine_result_to_audit_result(self.normalized(), source_root=self.root)
        self.assertIsNone(result['scan']['files_scanned'])
        self.assertEqual(result['scan']['files_with_findings'], 0)

    def test_projection_rejects_a_different_declared_source_root(self):
        normalized = self.normalized(source_root=str(self.home / 'another-source'))
        with self.assertRaises(ValueError):
            engine_result_to_audit_result(normalized, source_root=self.root)

    def test_merge_preserves_failed_engine_and_both_provenances(self):
        base, failed = self.projected(), self.projected('semgrep', 'input_error')
        before = copy.deepcopy((base, failed))
        merged = merge_engine_result(base, failed, source_root=self.root)
        self.assertEqual(merged['status'], 'partial')
        self.assertEqual(merged['input_errors'][0]['engine'], 'semgrep')
        self.assertEqual({r['engine'] for r in merged['engine_observations']}, {'clang', 'semgrep'})
        self.assertEqual((base, failed), before)

    def test_merge_rejects_one_sided_snapshot_binding(self):
        base, other = self.projected(), self.projected('semgrep')
        del other['scan']['source_snapshot_sha256']
        with self.assertRaisesRegex(ValueError, 'snapshot'):
            merge_engine_result(base, other, source_root=self.root)

    def test_cli_failed_engine_returns_nonzero_with_diagnostics(self):
        destination = self.home / 'engine.json'
        # Patch both existing and shared-executor locations during migration.
        with patch('ohvul.engine_cli.run_wsl_clang_analyzer', return_value=self.normalized('input_error'), create=True), \
             patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value=self.normalized('input_error')):
            code = self.run_cli('--output', str(destination))
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(destination.read_text())['status'], 'input_error')

    def test_cli_cannot_overwrite_scanned_source(self):
        source = self.root / 'a.c'
        before = source.read_bytes()
        with patch('ohvul.engine_cli.run_wsl_clang_analyzer', return_value=self.normalized(), create=True), \
             patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value=self.normalized()):
            code = self.run_cli('--output', str(source))
        self.assertNotEqual(code, 0)
        self.assertEqual(source.read_bytes(), before)

    def test_semgrep_embedded_errors_cannot_become_clean_output(self):
        result = normalize_semgrep_json(
            {'results': [], 'errors': [{'type': 'ParseError', 'message': 'synthetic parse failure'}]},
            source_root=self.root,
        )
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['input_errors'][0]['engine'], 'semgrep')

    def test_malformed_clang_plist_is_not_a_clean_scan(self):
        import plistlib
        with self.assertRaises(ValueError):
            normalize_clang_plist(plistlib.dumps({}), source_root=self.root)

    def test_duplicate_aliases_do_not_inflate_coverage(self):
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer') as analyzer:
            with self.assertRaises(ValueError):
                scan_engine_manifest(self.root, self.manifest(['a.c', './a.c']))
        analyzer.assert_not_called()

    def test_main_cli_engine_failure_aborts_without_success_artifacts(self):
        files = self.home / 'files.txt'
        files.write_text('a.c\n', encoding='utf-8')
        output, checkpoint, journal = (self.home / name for name in ('result.json', 'checkpoint.json', 'journal.jsonl'))
        engine = self.projected(status='input_error', snapshot=source_snapshot(self.root))
        argv = ['cli', str(self.root), '--engine-files-from', str(files), '--output', str(output),
                '--checkpoint', str(checkpoint), '--journal', str(journal), '--task-id', 'engine-failed']
        with patch.object(sys, 'argv', argv), patch('ohvul.cli.scan_engine_manifest', return_value=engine), \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as stopped:
                cli.main()
        self.assertNotEqual(stopped.exception.code, 0)
        self.assertFalse(output.exists())
        saved = load_checkpoint(checkpoint)
        self.assertEqual(saved.state, 'blocked')
        self.assertIsNone(saved.result_sha256)
        self.assertEqual(AuditJournal(journal).last_status('engine-failed'), 'aborted')


if __name__ == '__main__':
    unittest.main()
