import unittest
import json
import tempfile
import os
import subprocess
from pathlib import Path
from unittest.mock import patch
from contextlib import contextmanager
from ohvul.engine_shards import scan_engine_profile


@contextmanager
def local_profile(engines, files=('a.c',)):
    """Use real local Git identity; only analyzer execution is mocked."""
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        root = base / 'source'
        root.mkdir()
        for name in files:
            (root / name).write_text('int x;\n', encoding='utf-8')
        (root / 'rules.yml').write_text('rules: []\n', encoding='utf-8')
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
        def git(*args):
            return subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                                  text=True, timeout=30, check=True, env=env).stdout
        git('init', '-q')
        git('add', *files, 'rules.yml')
        git('-c', 'user.name=Local Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'core.hooksPath=' + str(base / 'no-hooks'), 'commit', '-qm', 'fixture')
        profile_path = base / 'profile.json'
        profile_path.write_text(json.dumps({
            'schema': 'engine-profile-0.1', 'component': 'fixture',
            'source_repositories': {'.': git('rev-parse', 'HEAD').strip()},
            'source_files': list(files), 'include_dirs': [], 'defines': ['ABILITY_WINDOW_SUPPORT'],
            'extra_compile_args': [], 'engines': engines,
            'semgrep_rule_files': ['rules.yml'] if 'semgrep' in engines else []}), encoding='utf-8')
        yield root, profile_path


class EngineProfileScanTests(unittest.TestCase):
    def test_profile_scan_passes_declared_files_and_args(self):
        calls = []
        def fake(source, root, **kwargs):
            calls.append((source.name, kwargs['compile_args']))
            return {'status': 'completed', 'findings': []}
        with local_profile(['clang-static-analyzer', 'clang-tidy'], ('a.c', 'b.c', 'c.c')) as (root, profile), \
             patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=fake), \
             patch('ohvul.engine_shards.run_wsl_clang_tidy', return_value={'status': 'completed', 'findings': []}) as tidy:
            result = scan_engine_profile(root, profile)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(calls), 3)
        self.assertEqual(tidy.call_count, 3)
        self.assertEqual({item['engine'] for item in result['engine_observations']}, {'clang', 'clang-tidy'})
        self.assertIn('-DABILITY_WINDOW_SUPPORT', calls[0][1])

    def test_profile_runs_declared_local_semgrep_rules(self):
        with local_profile(['semgrep']) as (root, profile_path):
            fake = {'schema_version': '0.1', 'engine': 'semgrep',
                    'engine_version': '1.177.0', 'status': 'completed',
                    'findings': [{'rule': 'taint', 'location': {'file': 'a.c', 'line': 1}}]}
            with patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value={'status': 'completed', 'findings': []}) as clang, \
                 patch('ohvul.engine_shards.run_wsl_semgrep', return_value=fake) as run:
                result = scan_engine_profile(root, profile_path)
            run.assert_called_once()
            clang.assert_not_called()
            self.assertEqual(len(result['findings']), 1)
            self.assertEqual(result['findings'][0]['source'], 'semgrep')
            self.assertEqual(len(result['engine_profiles']['semgrep_rule_sha256']['rules.yml']), 64)

    def test_profile_preserves_structured_semgrep_errors(self):
        with local_profile(['semgrep']) as (root, profile_path):
            error = {'engine': 'semgrep', 'type': 'ParseError', 'message': 'synthetic parse failure'}
            outcome = {'engine': 'semgrep', 'status': 'input_error', 'findings': [], 'input_errors': [error]}
            with patch('ohvul.engine_shards.run_wsl_semgrep', return_value=outcome):
                result = scan_engine_profile(root, profile_path)
            self.assertEqual(result['status'], 'input_error')
            self.assertEqual(result['input_errors'], [error])


if __name__ == '__main__':
    unittest.main()
