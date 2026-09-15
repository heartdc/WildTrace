"""Capture uses real disposable Git repositories, not the project's Git."""
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ohvul.engine_profile import prepare_profile
from ohvul.profile_capture import capture_profile


class ProfileCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
        self.main_head = self.repo('component', 'a.c', 'int a;\n')
        self.dep_head = self.repo('dependency', 'include/a.h', 'typedef int value;\n')
        self.template = self.base / 'template.json'
        self.output = self.base / 'captured.json'
        self.data = {'schema': 'engine-profile-0.1', 'component': 'synthetic',
                     'source_repositories': {'component': self.main_head},
                     'source_files': ['component/a.c'], 'include_dirs': ['dependency/include'],
                     'defines': [], 'extra_compile_args': [], 'engines': ['clang-static-analyzer']}
        self.write()

    def git(self, path, *args):
        return subprocess.run(['git', '-C', str(path), *args], env=self.env,
                              capture_output=True, text=True, timeout=30, check=True).stdout.strip()

    def repo(self, name, file, content):
        repo = self.root / name
        repo.mkdir()
        source = repo / file
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(content, encoding='utf-8')
        self.git(repo, 'init', '-q')
        self.git(repo, 'add', '--', file)
        self.git(repo, '-c', 'user.name=Local Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'core.hooksPath=' + str(self.base / 'no-hooks'), 'commit', '-qm', 'synthetic fixture')
        return self.git(repo, 'rev-parse', 'HEAD')

    def write(self):
        self.template.write_text(json.dumps(self.data), encoding='utf-8')

    def test_adds_missing_dependency_and_preserves_existing_pin(self):
        before = {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.root.rglob('*') if p.is_file()}
        template = self.template.read_bytes()
        with patch('ohvul.engine_shards.run_wsl_clang_analyzer') as analyzer:
            receipt = capture_profile(self.template, self.root, self.output)
        analyzer.assert_not_called()
        profile, verified = prepare_profile(self.output, self.root)
        self.assertEqual(profile['source_repositories'], {'component': self.main_head, 'dependency': self.dep_head})
        self.assertEqual(receipt['added_repositories'], {'dependency': self.dep_head})
        self.assertEqual(receipt['profile_sha256'], verified['profile_sha256'])
        self.assertEqual(self.template.read_bytes(), template)
        after = {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(after, before)

    def test_wrong_existing_pin_is_not_refreshed(self):
        self.data['source_repositories']['component'] = 'f' * 40
        self.write()
        with self.assertRaisesRegex(ValueError, 'provenance'):
            capture_profile(self.template, self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_dirty_dependency_cannot_be_captured(self):
        (self.root / 'dependency/include/a.h').write_text('changed\n')
        with self.assertRaisesRegex(ValueError, 'provenance'):
            capture_profile(self.template, self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_existing_output_and_template_are_never_overwritten(self):
        self.output.write_bytes(b'existing')
        with self.assertRaises(FileExistsError):
            capture_profile(self.template, self.root, self.output)
        self.assertEqual(self.output.read_bytes(), b'existing')
        with self.assertRaises(FileExistsError):
            capture_profile(self.template, self.root, self.template)

    def test_output_inside_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'outside source'):
            capture_profile(self.template, self.root, self.root / 'new.json')
        self.assertFalse((self.root / 'new.json').exists())

    def test_missing_input_does_not_publish(self):
        self.data['include_dirs'] = ['missing/include']
        self.write()
        with self.assertRaises(ValueError):
            capture_profile(self.template, self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_external_owner_is_not_captured(self):
        # The declared include directory has no repository, and cannot acquire
        # a parent's identity outside the explicitly chosen source root.
        (self.root / 'unowned').mkdir()
        self.data['include_dirs'] = ['unowned']
        self.write()
        with self.assertRaises(ValueError):
            capture_profile(self.template, self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_existing_rule_pin_is_not_refreshed(self):
        rule = self.root / 'rules.yml'
        rule.write_text('rules: []\n', encoding='utf-8')
        self.data.update(engines=['semgrep'], semgrep_rule_files=['rules.yml'],
                         semgrep_rule_sha256={'rules.yml': 'f' * 64})
        self.write()
        with self.assertRaisesRegex(ValueError, 'rule digest'):
            capture_profile(self.template, self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_template_change_is_detected_before_publish(self):
        import ohvul.profile_capture as module
        original = module._prepare_profile_bytes
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.template.write_bytes(self.template.read_bytes() + b' ')
            return result
        with patch.object(module, '_prepare_profile_bytes', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'template changed'):
                capture_profile(self.template, self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_concurrent_output_is_preserved(self):
        import ohvul.profile_capture as module
        original = module._prepare_profile_bytes
        def competing(*args, **kwargs):
            result = original(*args, **kwargs)
            self.output.write_bytes(b'other writer')
            return result
        with patch.object(module, '_prepare_profile_bytes', side_effect=competing):
            with self.assertRaises(FileExistsError):
                capture_profile(self.template, self.root, self.output)
        self.assertEqual(self.output.read_bytes(), b'other writer')

    def test_repository_change_before_publication_is_rejected(self):
        import ohvul.profile_capture as module
        original = module._prepare_profile_bytes
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.root / 'dependency/include/a.h').write_text('changed\n')
            return result
        with patch.object(module, '_prepare_profile_bytes', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'repository changed'):
                capture_profile(self.template, self.root, self.output)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
