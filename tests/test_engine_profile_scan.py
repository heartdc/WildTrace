import unittest
from pathlib import Path
from unittest.mock import patch
from ohvul.engine_shards import scan_engine_profile


class EngineProfileScanTests(unittest.TestCase):
    def test_profile_scan_passes_declared_files_and_args(self):
        root = Path('C:/profile-root')
        profile = Path('docs/design/camera_app_engine_profile.json')
        calls = []
        def fake(source, root, **kwargs):
            calls.append((source.name, kwargs['compile_args']))
            return {'status': 'completed', 'findings': []}
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=fake), \
             patch('pathlib.Path.is_file', return_value=True), \
             patch('pathlib.Path.is_dir', return_value=True):
            result = scan_engine_profile(root, profile)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(calls), 3)
        self.assertIn('-DABILITY_WINDOW_SUPPORT', calls[0][1])


if __name__ == '__main__':
    unittest.main()
