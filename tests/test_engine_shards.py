import unittest
from pathlib import Path
from unittest.mock import patch
from ohvul.engine_shards import scan_engine_shard
from ohvul.engine_shards import scan_engine_manifest
from ohvul.source_snapshot import source_snapshot


class EngineShardTests(unittest.TestCase):
    def test_missing_file_is_input_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch('ohvul.engine_shards.source_snapshot', side_effect=AssertionError('must not scan tree')) as snapshot:
                result = scan_engine_shard(root, {'files': ['does-not-exist.c']})
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(len(result['input_errors']), 1)
        snapshot.assert_not_called()
        self.assertEqual(result['scan']['files_attempted'], 0)
        self.assertNotIn('source_snapshot_sha256', result['scan'])

    def test_invalid_manifest_never_reads_unrelated_tree_or_runs_engine(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {'root': str(root.resolve()), 'shards': [
                {'files': ['missing.c']}, {'files': ['../outside.c']} ]}
            with patch('ohvul.engine_shards.source_snapshot', side_effect=AssertionError('must not scan tree')), \
                 patch('ohvul.engine_shards.run_wsl_clang_analyzer') as engine:
                result = scan_engine_manifest(root, manifest)
            engine.assert_not_called()
            self.assertEqual(result['status'], 'input_error')
            self.assertEqual(result['scan']['files_requested'], 2)
            self.assertEqual(result['scan']['files_failed'], 2)
            self.assertEqual(result['scan']['files_attempted'], 0)
            self.assertNotIn('source_snapshot_sha256', result['scan'])

    def test_manifest_renumbers_engine_alerts(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('int a;')
            (root / 'b.c').write_text('int b;')
            normalized = lambda file: {'status': 'completed', 'findings': [{'location': {'file': file, 'line': 1}, 'rule': 'R', 'evidence_id': file}]}
            with patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=lambda source, root, **kwargs: normalized(source.name)), \
                 patch('ohvul.engine_shards.source_snapshot', wraps=__import__(
                     'ohvul.engine_shards', fromlist=['source_snapshot']).source_snapshot) as snapshot:
                result = scan_engine_manifest(root, {'root': str(root.resolve()), 'shards': [{'files': ['a.c']}, {'files': ['b.c']}]})
            self.assertEqual([f['alert_id'] for f in result['findings']], ['AL-ENG-000001', 'AL-ENG-000002'])
            self.assertEqual(snapshot.call_count, 2)
            self.assertEqual(result['scan']['source_snapshot_sha256'], source_snapshot(root))

    def test_partial_tidy_result_keeps_findings_and_degrades_status(self):
        # A non-zero clang-tidy exit that still produced diagnostics must
        # contribute its findings; the shard status degrades to partial (#13).
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('int a;')
            partial = {'status': 'partial', 'engine_version': 'v9',
                       'findings': [{'location': {'file': 'a.c', 'line': 1}, 'rule': 'R'}],
                       'stderr': 'error: expected expression'}
            with patch('ohvul.engine_shards.run_wsl_clang_tidy', return_value=partial) as tidy:
                result = scan_engine_shard(root, {'files': ['a.c']}, engine='clang-tidy')
            tidy.assert_called_once()
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(len(result['findings']), 1)
            self.assertEqual(result['findings'][0]['rule'], 'R')
            self.assertEqual(result['scan']['files_scanned'], 1)
            self.assertEqual(len(result['input_errors']), 1)
            self.assertIn('stderr', result['input_errors'][0])
            # file_results stay finding-free by contract
            self.assertNotIn('findings', result['file_results'][0])

    def test_shard_runner_call_contract_matches_runner_signatures(self):
        # Locks the kwargs the shard caller passes to the runner signatures,
        # so a signature change cannot silently drift past MagicMock-based
        # tests (issue #15's missing regression).
        import inspect
        import tempfile
        from ohvul.engine_adapter import run_wsl_clang_analyzer, run_wsl_clang_tidy
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('int a;')
            (root / 'b.c').write_text('int b;')
            with patch('ohvul.engine_shards.run_wsl_clang_analyzer',
                       return_value={'status': 'completed', 'findings': []}) as analyzer, \
                 patch('ohvul.engine_shards.run_wsl_clang_tidy',
                       return_value={'status': 'completed', 'findings': []}) as tidy:
                scan_engine_shard(root, {'files': ['a.c']}, engine='clang',
                                  llvm_root='/l', timeout=11, compile_args=('-DFOO',))
                scan_engine_shard(root, {'files': ['b.c']}, engine='clang-tidy',
                                  llvm_root='/l', timeout=11, compile_args=())
            for mock, runner in ((analyzer, run_wsl_clang_analyzer),
                                 (tidy, run_wsl_clang_tidy)):
                signature = inspect.signature(runner)
                for call in mock.call_args_list:
                    self.assertEqual(len(call.args), 2, runner.__name__)
                    for name in call.kwargs:
                        self.assertIn(name, signature.parameters, (runner.__name__, name))
                self.assertEqual(call.kwargs.get('compile_args'), tuple(call.kwargs.get('compile_args', ())))


if __name__ == '__main__':
    unittest.main()
