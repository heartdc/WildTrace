"""Engine identity comes from observed output, never installation assumptions."""
import hashlib
import os
import json
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ohvul.engine_adapter import (
    engine_result_to_audit_result, merge_engine_result, normalize_clang_plist,
    normalize_semgrep_json, run_wsl_clang_tidy, run_wsl_semgrep,
)


class EngineProvenanceTests(unittest.TestCase):
    def test_clang_uses_version_from_plist(self):
        raw = plistlib.dumps({'clang_version': 'clang version 99.2.3 (local fixture)',
                             'files': [], 'diagnostics': []})
        result = normalize_clang_plist(raw, source_root=Path('.'))
        self.assertEqual(result['engine_version'], '99.2.3')
        self.assertEqual(result['version_observation']['raw'], 'clang version 99.2.3 (local fixture)')

    def test_semgrep_uses_version_from_json(self):
        result = normalize_semgrep_json({'version': '99.1.2', 'results': []}, source_root=Path('.'))
        self.assertEqual(result['engine_version'], '99.1.2')

    @unittest.skipUnless(os.name == "nt", "WSL bridge requires a Windows host")
    def test_unobserved_semgrep_version_stays_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('int a;\n')
            (root / 'rules.yml').write_text('rules: []\n')
            completed = subprocess.CompletedProcess([], 0, '{"results": []}', '')
            with patch('ohvul.engine_adapter.subprocess.run', return_value=completed):
                result = run_wsl_semgrep(root, root / 'rules.yml', ('a.c',))
            self.assertEqual(result['engine_version'], 'unknown')

    @unittest.skipUnless(os.name == "nt", "WSL bridge requires a Windows host")
    def test_tidy_uses_selected_toolchain_and_observed_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'a.c'
            source.write_text('int a;\n')
            def run(command, **kwargs):
                text = 'LLVM version 99.4.5\n' if '--version' in command else ''
                return subprocess.CompletedProcess(command, 0, text, '')
            with patch('ohvul.engine_adapter.subprocess.run', side_effect=run) as calls:
                result = run_wsl_clang_tidy(source, root, llvm_root='/opt/reviewed-llvm')
            self.assertEqual(result['engine_version'], '99.4.5')
            self.assertTrue(all('/opt/reviewed-llvm/bin/clang-tidy' in c.args[0] for c in calls.call_args_list))
            self.assertEqual(result['execution']['returncode'], 0)

    def test_version_and_execution_are_bound_to_candidate_evidence(self):
        normalized = {'engine': 'clang', 'engine_version': '99.2.3', 'status': 'completed',
                      'source_root': str(Path('.').resolve()), 'findings': [{
                          'source': 'clang', 'engine_version': '99.2.3', 'rule': 'R',
                          'location': {'file': 'a.c', 'line': 1},
                          'evidence': {'engine_execution': {'command': ['clang', '--analyze'], 'returncode': 0}},
                      }]}
        result = engine_result_to_audit_result(normalized, source_root=Path('.'))
        self.assertEqual(result['findings'][0]['evidence']['engine_version'], '99.2.3')
        self.assertEqual(result['findings'][0]['engine_version'], '99.2.3')

    def test_merge_keeps_profile_receipt_and_version_observation(self):
        root = Path('.').resolve()
        base = engine_result_to_audit_result({'engine': 'clang', 'status': 'completed', 'findings': []},
                                             source_root=root, source_snapshot_sha256='a' * 64)
        part = engine_result_to_audit_result({'engine': 'semgrep', 'status': 'completed', 'findings': [],
                                             'version_observation': {'source': 'semgrep_json', 'version': '99.1.2'}},
                                             source_root=root, source_snapshot_sha256='a' * 64)
        receipt = {'schema': 'profile-validation-0.1', 'profile_sha256': 'b' * 64,
                   'source_root': str(root), 'provenance': {'verified': True}}
        part['profile_validation'] = receipt
        result = merge_engine_result(base, part, source_root=root)
        self.assertEqual(result['profile_validations'], [receipt])
        semgrep = next(x for x in result['engine_observations'] if x['engine'] == 'semgrep')
        self.assertEqual(semgrep['version_observation']['version'], '99.1.2')
        result['profile_validations'][0]['profile_sha256'] = 'c' * 64
        self.assertEqual(part['profile_validation']['profile_sha256'], 'b' * 64)

    def test_different_shard_versions_are_not_labelled_as_one_version(self):
        from ohvul.engine_shards import scan_engine_manifest
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('int a;\n')
            (root / 'b.c').write_text('int b;\n')
            manifest = {'root': str(root.resolve()), 'shards': [{'files': ['a.c']}, {'files': ['b.c']}]}
            def run(source, *args, **kwargs):
                return {'engine': 'clang', 'engine_version': '99.1.0' if source.name == 'a.c' else '99.2.0',
                        'status': 'completed', 'findings': []}
            with patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=run):
                result = scan_engine_manifest(root, manifest)
            self.assertEqual(result['scan']['engine_version'], 'unknown')
            self.assertEqual({x['engine_version'] for x in result['file_results']}, {'99.1.0', '99.2.0'})

    @unittest.skipUnless(os.name == "nt", "WSL bridge requires a Windows host")
    def test_failed_tidy_version_probe_does_not_claim_a_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'a.c'
            source.write_text('int a;\n')
            def run(command, **kwargs):
                return subprocess.CompletedProcess(command, 1 if '--version' in command else 0,
                                                   'LLVM version 99.9.9\n' if '--version' in command else '', '')
            with patch('ohvul.engine_adapter.subprocess.run', side_effect=run):
                result = run_wsl_clang_tidy(source, root)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['engine_version'], 'unknown')
            self.assertEqual(result['version_observation']['returncode'], 1)


if __name__ == '__main__':
    unittest.main()
