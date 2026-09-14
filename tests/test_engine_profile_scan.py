import unittest
import json
import tempfile
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

    def test_profile_runs_declared_local_semgrep_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('int x;\n')
            (root / 'rules.yml').write_text('rules: []\n')
            profile_path = root / 'profile.json'
            profile_path.write_text(json.dumps({
                'schema': 'engine-profile-0.1', 'component': 'x',
                'source_repositories': {'x': 'a' * 40},
                'source_files': ['a.c'], 'include_dirs': [], 'defines': [],
                'extra_compile_args': [], 'engines': ['semgrep'],
                'semgrep_rule_files': ['rules.yml']}))
            fake = {'schema_version': '0.1', 'engine': 'semgrep',
                    'engine_version': '1.177.0', 'status': 'completed',
                    'findings': [{'rule': 'taint', 'location': {'file': 'a.c', 'line': 1}}]}
            with patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value={'status': 'completed', 'findings': []}), \
                 patch('ohvul.engine_shards.run_wsl_semgrep', return_value=fake) as run:
                result = scan_engine_profile(root, profile_path)
            run.assert_called_once()
            self.assertEqual(len(result['findings']), 1)
            self.assertEqual(result['findings'][0]['source'], 'semgrep')
            self.assertEqual(len(result['engine_profiles']['semgrep_rule_sha256']['rules.yml']), 64)


if __name__ == '__main__':
    unittest.main()
