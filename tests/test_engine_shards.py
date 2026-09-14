import unittest
from pathlib import Path
from ohvul.engine_shards import scan_engine_shard
from ohvul.engine_shards import scan_engine_manifest


class EngineShardTests(unittest.TestCase):
    def test_missing_file_is_input_error(self):
        result = scan_engine_shard(Path('.'), {'files': ['does-not-exist.c']})
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(len(result['input_errors']), 1)

    def test_manifest_renumbers_engine_alerts(self):
        from unittest.mock import patch
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('int a;')
            (root / 'b.c').write_text('int b;')
            normalized = lambda file: {'status': 'completed', 'findings': [{'location': {'file': file, 'line': 1}, 'rule': 'R', 'evidence_id': file}]}
            with patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=lambda source, root, **kwargs: normalized(source.name)):
                result = scan_engine_manifest(root, {'root': str(root.resolve()), 'shards': [{'files': ['a.c']}, {'files': ['b.c']}]})
            self.assertEqual([f['alert_id'] for f in result['findings']], ['AL-ENG-000001', 'AL-ENG-000002'])


if __name__ == '__main__':
    unittest.main()
