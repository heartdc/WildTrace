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


if __name__ == '__main__':
    unittest.main()
