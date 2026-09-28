import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ohvul.toolchain
from ohvul.toolchain import (DEFAULT_LLVM_ROOT, preflight, resolve_clang_bin,
                             resolve_clang_tidy_bin, resolve_llvm_root,
                             resolve_semgrep_bin, wsl_prefix)


class ResolverTests(unittest.TestCase):
    def test_defaults_without_environment(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ('OHVUL_LLVM_BIN', 'OHVUL_LLVM_ROOT', 'OHVUL_SEMGREP_BIN')}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(resolve_llvm_root(), DEFAULT_LLVM_ROOT)
            self.assertEqual(resolve_clang_bin(), DEFAULT_LLVM_ROOT + '/bin/clang')
            self.assertEqual(resolve_clang_tidy_bin(), DEFAULT_LLVM_ROOT + '/bin/clang-tidy')

    def test_root_override(self):
        with patch.dict(os.environ, {'OHVUL_LLVM_ROOT': '/opt/llvm'}, clear=False):
            self.assertEqual(resolve_llvm_root(), '/opt/llvm')
            self.assertEqual(resolve_clang_bin(), '/opt/llvm/bin/clang')

    def test_bin_override_takes_precedence_and_implies_tidy_sibling(self):
        with patch.dict(os.environ, {'OHVUL_LLVM_BIN': '/opt/x/bin/clang',
                                     'OHVUL_LLVM_ROOT': '/opt/ignored'}, clear=False):
            self.assertEqual(resolve_clang_bin(), '/opt/x/bin/clang')
            self.assertEqual(resolve_clang_tidy_bin(), '/opt/x/bin/clang-tidy')
        with patch.dict(os.environ, {'OHVUL_LLVM_BIN': 'C:' + chr(92) + 'x' + chr(92) + 'clang.EXE'}, clear=False):
            self.assertEqual(resolve_clang_tidy_bin(), 'C:' + chr(92) + 'x' + chr(92) + 'clang-tidy.EXE')

    def test_blank_override_is_rejected(self):
        with patch.dict(os.environ, {'OHVUL_LLVM_ROOT': '  '}, clear=False):
            with self.assertRaisesRegex(ValueError, 'OHVUL_LLVM_ROOT'):
                resolve_llvm_root()

    def test_wsl_prefix_follows_platform(self):
        self.assertEqual(wsl_prefix() == [], os.name != 'nt')


class PreflightTests(unittest.TestCase):
    def _fake_dir(self):
        if not hasattr(self, '_tool_dir'):
            holder = tempfile.TemporaryDirectory()
            self.addCleanup(holder.cleanup)
            self._tool_dir = Path(holder.name)
        return self._tool_dir

    def _fake_tool(self, name):
        directory = type('D', (), {'name': str(self._fake_dir())})()
        if os.name == 'nt':
            path = Path(directory.name) / (name + '.cmd')
            path.write_text('@echo 1.2.3 fake' + chr(13) + chr(10), encoding='ascii')
            return str(path)
        path = Path(directory.name) / name
        path.write_text('#!/bin/sh' + chr(10) + 'echo "1.2.3 fake"' + chr(10),
                        encoding='utf-8', newline='\n')
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        return str(path)

    def test_preflight_passes_with_fake_toolchain(self):
        clang = self._fake_tool('clang')
        tidy = self._fake_tool('clang-tidy')
        semgrep = self._fake_tool('semgrep')
        with (patch.dict(os.environ, {'OHVUL_LLVM_BIN': clang,
                                     'OHVUL_SEMGREP_BIN': semgrep}, clear=False),
             patch.object(ohvul.toolchain, 'wsl_prefix', return_value=[])):
            result = preflight()
        by_name = {c['name']: c for c in result['checks']}
        self.assertEqual(by_name['clang']['status'], 'ok')
        self.assertEqual(by_name['clang_tidy']['status'], 'ok')
        self.assertEqual(by_name['semgrep']['status'], 'ok')
        self.assertTrue(result['ok'])
        self.assertEqual(result['resolved']['clang_bin'], clang)
        self.assertEqual(Path(result['resolved']['clang_tidy_bin']).name,
                         Path(tidy).name)

    def test_preflight_fails_when_required_tool_missing(self):
        missing = str(Path(tempfile.gettempdir()) / 'definitely-missing-clang-xyz')
        with (patch.dict(os.environ, {'OHVUL_LLVM_BIN': missing,
                                     'OHVUL_SEMGREP_BIN': missing}, clear=False),
             patch.object(ohvul.toolchain, 'wsl_prefix', return_value=[])):
            result = preflight()
        self.assertFalse(result['ok'])
        self.assertIn('clang', result['failed_required'])
        self.assertIn('clang_tidy', result['failed_required'])

    def test_optional_semgrep_failure_does_not_fail_preflight(self):
        clang = self._fake_tool('clang')
        self._fake_tool('clang-tidy')
        missing = str(Path(tempfile.gettempdir()) / 'definitely-missing-semgrep-xyz')
        with (patch.dict(os.environ, {'OHVUL_LLVM_BIN': clang,
                                     'OHVUL_SEMGREP_BIN': missing}, clear=False),
             patch.object(ohvul.toolchain, 'wsl_prefix', return_value=[])):
            result = preflight()
        by_name = {c['name']: c for c in result['checks']}
        self.assertNotEqual(by_name['semgrep']['status'], 'ok')
        self.assertTrue(result['ok'])


class EngineWiringTests(unittest.TestCase):
    def test_compiler_analysis_command_uses_resolved_clang(self):
        from ohvul.compiler_analysis import _command
        with patch.dict(os.environ, {'OHVUL_LLVM_BIN': '/opt/fake/bin/clang'}, clear=False):
            command = _command(['--version'], 30)
        self.assertIn('/opt/fake/bin/clang', command)
        self.assertNotIn('/home/airgap', command)

    def test_engine_adapter_resolves_root_when_unset(self):
        from ohvul import engine_adapter
        with (patch.dict(os.environ, {'OHVUL_LLVM_ROOT': '/opt/fake-llvm'}, clear=False),
             patch.object(engine_adapter, 'windows_to_wsl_path',
                          side_effect=lambda path: str(path)),
             patch.object(engine_adapter.subprocess, 'run') as run,
             patch.object(engine_adapter, '_tidy_version', return_value={'version': 'x'})):
            run.return_value = subprocess.CompletedProcess([], 0, stdout='', stderr='')
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'a.c'
                source.write_text('int a;', encoding='utf-8')
                engine_adapter.run_wsl_clang_tidy(source, root)
        command = run.call_args[0][0]
        self.assertTrue(any('/opt/fake-llvm/bin/clang-tidy' in part for part in command))


if __name__ == '__main__':
    unittest.main()
