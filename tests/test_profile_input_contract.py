"""Local-only profile contract tests; analyzers are always mocked."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from ohvul.engine_profile import load_profile, validate_profile_provenance
from ohvul.engine_shards import scan_engine_profile


def profile_data(**changes):
    data = {'schema': 'engine-profile-0.1', 'component': 'fixture',
            'source_repositories': {'.': 'a' * 40}, 'source_files': ['a.c'],
            'include_dirs': [], 'defines': [], 'extra_compile_args': [],
            'engines': ['clang-static-analyzer']}
    data.update(changes)
    return data


class ProfileInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'profile.json'

    def reject(self, data):
        self.path.write_text(json.dumps(data), encoding='utf-8')
        with self.assertRaises(ValueError):
            load_profile(self.path)

    def test_lists_are_validated_before_iteration(self):
        for field in ('source_files', 'include_dirs', 'defines', 'extra_compile_args', 'engines'):
            for value in (None, 'a.c', 3, {}, [None], [True]):
                with self.subTest(field=field, value=value):
                    self.reject(profile_data(**{field: value}))

    def test_empty_scope_and_engines_are_rejected(self):
        for field, value in (('source_files', []), ('engines', []), ('source_repositories', {}), ('component', '  ')):
            with self.subTest(field=field):
                self.reject(profile_data(**{field: value}))

    def test_repository_paths_cannot_escape_or_be_absolute(self):
        for repository in ('../other', '/tmp/other', 'C:\\other', 'C:relative', '\\\\server\\share', 'a\x00b', 'a:b'):
            with self.subTest(repository=repository):
                self.reject(profile_data(source_repositories={repository: 'a' * 40}))

    def test_duplicate_and_aliased_paths_are_rejected(self):
        for data in (profile_data(source_files=['a.c', './a.c']),
                     profile_data(engines=['clang-static-analyzer'] * 2),
                     profile_data(defines=['SIZE=1', 'SIZE=2'])):
            self.reject(data)

    def test_response_files_plugins_and_output_flags_are_rejected(self):
        for arguments in (['@flags.rsp'], ['-Xclang', '-load', 'plugin.dll'],
                          ['-o', 'a.c'], ['--sysroot=C:/outside'], ['-I../outside'], ['--'], ['-fplugin=x']):
            with self.subTest(arguments=arguments):
                self.reject(profile_data(extra_compile_args=arguments))

    def test_macro_names_and_control_characters_are_rejected(self):
        for define in ('BAD-NAME=1', '=1', 'X=1\n-DY', 'X\x00=1'):
            self.reject(profile_data(defines=[define]))

    def test_small_compile_option_subset_is_accepted(self):
        self.path.write_text(json.dumps(profile_data(extra_compile_args=['-std=c++17', '-Wno-c++11-narrowing'],
                                                    defines=['FEATURE', 'SIZE=4'])), encoding='utf-8')
        self.assertEqual(load_profile(self.path)['defines'], ['FEATURE', 'SIZE=4'])

    def test_duplicate_json_fields_are_rejected(self):
        text = json.dumps(profile_data())[:-1] + ', "component": "replacement"}'
        self.path.write_text(text, encoding='utf-8')
        with self.assertRaises(ValueError):
            load_profile(self.path)

    def test_hilog_build_declared_compiler_options_are_allowed(self):
        args = ['-Wall', '-fno-common', '-fno-strict-aliasing', '-O2']
        self.path.write_text(json.dumps(profile_data(extra_compile_args=args)), encoding='utf-8')
        self.assertEqual(load_profile(self.path)['extra_compile_args'], args)


class ProfileExecutionTests(unittest.TestCase):
    """Real temporary Git repositories exercise provenance, never project Git."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'a.c').write_text('int a;\n', encoding='utf-8')
        (self.root / 'rules.yml').write_text('rules: []\n', encoding='utf-8')
        self.path = self.base / 'profile.json'
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
        self.git('init', '-q')
        self.git('add', 'a.c', 'rules.yml')
        self.git('-c', 'user.name=Local Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'core.hooksPath=' + str(self.base / 'no-hooks'), 'commit', '-qm', 'synthetic fixture')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.data = profile_data(source_repositories={'.': self.head})
        self.write_profile()

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], env=self.env, check=True,
                              capture_output=True, text=True, timeout=30).stdout

    def write_profile(self):
        self.path.write_text(json.dumps(self.data), encoding='utf-8')

    def test_matching_repository_has_bound_profile_receipt(self):
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value={'status': 'completed', 'findings': []}) as run:
            result = scan_engine_profile(self.root, self.path)
        run.assert_called_once()
        self.assertTrue(result['profile_validation']['provenance']['verified'])
        self.assertEqual(len(result['profile_validation']['profile_sha256']), 64)

    def test_wrong_commit_prevents_all_analyzer_calls(self):
        self.data['source_repositories'] = {'.': 'b' * 40}
        self.write_profile()
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer') as run:
            with self.assertRaisesRegex(ValueError, 'provenance'):
                scan_engine_profile(self.root, self.path)
            run.assert_not_called()

    def test_dirty_repository_cannot_claim_fixed_commit(self):
        (self.root / 'a.c').write_text('int changed;\n', encoding='utf-8')
        result = validate_profile_provenance(self.data, self.root)
        self.assertFalse(result['verified'])

    def test_nested_nonrepository_does_not_inherit_parent_identity(self):
        (self.root / 'nested').mkdir()
        result = validate_profile_provenance({'source_repositories': {'nested': self.head}}, self.root)
        self.assertFalse(result['verified'])

    def test_git_timeout_is_explicit_unverified_result(self):
        with patch('ohvul.engine_profile.subprocess.run', side_effect=subprocess.TimeoutExpired('git', 30)):
            result = validate_profile_provenance(self.data, self.root)
        self.assertFalse(result['verified'])

    def test_missing_include_is_rejected_before_engine_execution(self):
        self.data['include_dirs'] = ['missing']
        self.write_profile()
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer') as run:
            with self.assertRaises(ValueError):
                scan_engine_profile(self.root, self.path)
            run.assert_not_called()

    def test_external_profile_changes_during_run_are_rejected(self):
        def analyze(*args, **kwargs):
            self.path.write_text(self.path.read_text() + ' ', encoding='utf-8')
            return {'status': 'completed', 'findings': []}
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=analyze):
            with self.assertRaisesRegex(ValueError, 'profile'):
                scan_engine_profile(self.root, self.path)

    def test_semgrep_only_still_requires_valid_provenance(self):
        self.data.update(engines=['semgrep'], semgrep_rule_files=['rules.yml'], source_repositories={'.': 'b' * 40})
        self.write_profile()
        with patch('ohvul.engine_shards.run_wsl_semgrep', return_value={'engine': 'semgrep', 'status': 'completed', 'findings': []}) as run:
            with self.assertRaisesRegex(ValueError, 'provenance'):
                scan_engine_profile(self.root, self.path)
            run.assert_not_called()

    def test_engine_cli_profile_does_not_bypass_provenance(self):
        from ohvul import engine_cli
        self.data['source_repositories'] = {'.': 'b' * 40}
        self.write_profile()
        argv = ['engine_cli', str(self.root / 'a.c'), '--source-root', str(self.root), '--profile', str(self.path)]
        with patch.object(sys, 'argv', argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value={'status': 'completed', 'findings': []}) as run:
            with self.assertRaises(SystemExit) as error:
                engine_cli.main()
        self.assertNotEqual(error.exception.code, 0)
        run.assert_not_called()

    def test_ignored_target_cannot_inherit_repository_commit(self):
        (self.root / '.git/info/exclude').write_text('ignored.c\n', encoding='utf-8')
        (self.root / 'ignored.c').write_text('int ignored;\n', encoding='utf-8')
        self.data['source_files'] = ['ignored.c']
        self.write_profile()
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer') as run:
            with self.assertRaisesRegex(ValueError, 'tracked'):
                scan_engine_profile(self.root, self.path)
            run.assert_not_called()

    def test_assume_unchanged_target_is_rejected(self):
        self.git('update-index', '--assume-unchanged', 'a.c')
        (self.root / 'a.c').write_text('int hidden_change;\n', encoding='utf-8')
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer') as run:
            with self.assertRaisesRegex(ValueError, 'tracked'):
                scan_engine_profile(self.root, self.path)
            run.assert_not_called()

    def test_wrong_rule_hash_is_rejected_before_semgrep(self):
        self.data.update(engines=['semgrep'], semgrep_rule_files=['rules.yml'],
                         semgrep_rule_sha256={'rules.yml': '0' * 64})
        self.write_profile()
        with patch('ohvul.engine_shards.run_wsl_semgrep') as run:
            with self.assertRaisesRegex(ValueError, 'rule digest'):
                scan_engine_profile(self.root, self.path)
            run.assert_not_called()

    def test_linked_include_directory_is_rejected(self):
        from ohvul.source_scope import is_link
        (self.root / 'include').mkdir()
        self.data['include_dirs'] = ['include']
        self.write_profile()
        with patch('ohvul.source_scope.is_link', side_effect=lambda p: p.name == 'include' or is_link(p)), \
                patch('ohvul.engine_shards.run_wsl_clang_analyzer') as run:
            with self.assertRaisesRegex(ValueError, 'link|junction'):
                scan_engine_profile(self.root, self.path)
            run.assert_not_called()

    def test_engine_cli_profile_success_retains_receipt(self):
        from ohvul import engine_cli
        output = self.base / 'result.json'
        argv = ['engine_cli', str(self.root / 'a.c'), '--source-root', str(self.root),
                '--profile', str(self.path), '--output', str(output)]
        with patch.object(sys, 'argv', argv), \
                patch('ohvul.engine_shards.run_wsl_clang_analyzer', return_value={'status': 'completed', 'findings': []}):
            self.assertEqual(engine_cli.main(), 0)
        result = json.loads(output.read_text(encoding='utf-8'))
        self.assertTrue(result['profile_validation']['provenance']['verified'])

    def test_engine_cli_rejects_source_not_declared_in_profile(self):
        from ohvul import engine_cli
        argv = ['engine_cli', str(self.root / 'rules.yml'), '--source-root', str(self.root), '--profile', str(self.path)]
        with patch.object(sys, 'argv', argv), redirect_stderr(io.StringIO()), \
                patch('ohvul.engine_shards.run_wsl_clang_analyzer') as run:
            with self.assertRaises(SystemExit):
                engine_cli.main()
            run.assert_not_called()

    def test_configured_git_filters_are_not_executed(self):
        self.git('config', 'filter.fixture.clean', 'echo unsupported-filter')
        result = validate_profile_provenance(self.data, self.root)
        self.assertFalse(result['verified'])
        self.assertIn('filters', result['mismatches'][0]['reason'])


if __name__ == '__main__':
    unittest.main()
