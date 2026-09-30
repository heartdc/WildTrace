"""Contract tests only: no target, compiler, sandbox or network is invoked."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.validation_cases import run_zlib_controls as c


def output(mode='fragmented'):
    return json.dumps({'status': 'roundtrip_and_capture_passed', 'mode': mode,
                      'input_bytes': 65, 'output_bytes': 8,
                      'counts_as_new_vulnerability': False}).encode()


class LocalControlContracts(unittest.TestCase):
    def test_opt_in_required_before_io_or_process(self):
        with patch.object(c, 'capture_source') as capture, patch.object(c, '_invoke') as invoke:
            with self.assertRaises(ValueError):
                c.run(Path('missing'), Path('out'), allow_target_execution=False, approval_reference='')
            capture.assert_not_called(); invoke.assert_not_called()

    def test_runtime_has_no_writable_host_bind_and_uses_network_namespace(self):
        args = c.sandbox(['/case', 'fragmented'], inputs=Path('C:/inputs'), executable=Path('C:/case'))
        self.assertIn('--unshare-all', args)
        self.assertIn('--clearenv', args)
        self.assertIn('--cap-drop', args)
        self.assertIn('ALL', args)
        self.assertNotIn('--bind', args)
        self.assertNotIn('--share-net', args)
        self.assertFalse(any(x.startswith('--as=') for x in args))
        self.assertIn('--cpu=5', args)

    def test_runtime_rejects_writable_build_mount(self):
        with self.assertRaises(ValueError):
            c.sandbox(['/case'], inputs=Path('C:/inputs'), build=Path('C:/work'))

    def test_compiler_is_time_and_address_space_limited(self):
        args = c.sandbox(['clang'], inputs=Path('C:/inputs'), build=Path('C:/work'), compile_mode=True)
        self.assertIn('--as=4294967296', args)
        self.assertIn('--cpu=45', args)

    def test_only_exact_functional_output_is_success(self):
        err = b'CASE_START mode=fragmented zlib=1.3.1 input=65\n'
        self.assertEqual(c.classify(output(), err, 'fragmented', 0, 'completed'), 'functional_control_passed')
        self.assertEqual(c.classify(output(), err, 'fragmented', 2, 'input_error'), 'execution_failed')
        self.assertEqual(c.classify(output(), err, 'fragmented', 124, 'timeout'), 'timeout')
        self.assertEqual(c.classify(output(), b'', 'fragmented', 0, 'completed'), 'invalid_control_output')
        self.assertEqual(c.classify(output('whole'), err, 'fragmented', 0, 'completed'), 'invalid_control_output')
        self.assertEqual(c.classify(b'{}', err, 'fragmented', 0, 'completed'), 'invalid_control_output')

    def test_sanitizer_report_is_not_automatically_a_vulnerability(self):
        status = c.classify(b'', b'ERROR: AddressSanitizer: heap-buffer-overflow', 'fragmented', 1, 'input_error')
        self.assertEqual(status, 'sanitizer_report_requires_review')

    def test_boolean_exit_code_cannot_be_used_as_success_zero(self):
        self.assertEqual(c.classify(output(), b'CASE_START mode=fragmented zlib=1.3.1 input=65',
                                    'fragmented', False, 'completed'), 'execution_failed')


class MockedEndToEnd(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve(); self.root = self.base / 'source'; self.root.mkdir()
        self.out = self.base / 'run'
        self.files = {}
        for name in c.SOURCES + c.HEADERS:
            raw = ('fixture: ' + name).encode(); (self.root / name).write_bytes(raw)
            self.files[name] = {'bytes': len(raw), 'sha256': c.sha(raw)}
        self.enterContext(patch.object(c, 'capture_source', return_value=self.files))
        self.enterContext(patch.object(c, 'linux', side_effect=str))
        self.invoker = self.enterContext(patch.object(c, '_invoke', side_effect=self.reply))

    def reply(self, command, timeout, **kwargs):
        err = b''
        if '-c' in command and '/usr/bin/python3' in command:
            raw = json.dumps({'uid': 1000, 'home_hidden': True, 'host_mount_hidden': True,
                 'interfaces': ['lo'], 'effective_capabilities': '0000000000000000'}).encode()
        elif '--version' in command:
            raw = b'clang version TEST-FIXTURE\n'
        elif '-o' in command:
            build = Path(command[command.index('--bind') + 1]); (build / 'case').write_bytes(b'ELF fixture, not executed')
            raw = b''
        else:
            mode = command[-1]; raw = output(mode)
            err = ('CASE_START mode=' + mode + ' zlib=1.3.1 input=65\n').encode()
        return {'status': 'completed', 'reason': None, 'returncode': 0, 'seconds': 0.0, 'stdout': raw, 'stderr': err}

    def run_controls(self):
        return c.run(self.root, self.out, allow_target_execution=True, approval_reference='TEST-ONLY-not-real-authorization')

    def test_mocked_chain_and_offline_recheck(self):
        value = self.run_controls()
        self.assertEqual(value['status'], 'functional_controls_passed')
        self.assertEqual(len(value['runs']), 10)
        self.assertEqual(self.invoker.call_count, 14)
        self.assertEqual(c.verify(self.out, self.root), value)
        self.assertEqual(self.invoker.call_count, 14)

    def test_no_overwrite(self):
        self.run_controls()
        with self.assertRaises(ValueError): self.run_controls()

    def test_mutated_artifact_and_source_snapshot_rejected(self):
        self.run_controls()
        path = self.out / 'run-1-1-fragmented.stdout'; old = path.read_bytes(); path.write_bytes(b'changed')
        with self.assertRaises(ValueError): c.verify(self.out, self.root)
        path.write_bytes(old)
        (self.out / 'inputs/inflate.c').write_bytes(b'changed')
        with self.assertRaises(ValueError): c.verify(self.out, self.root)

    def test_summary_run_and_verdict_tamper_rejected(self):
        original = self.run_controls()
        for key, val in [('status', 'vulnerability_confirmed'), ('real_target_runs', 999),
                         ('confirmed_new_vulnerabilities', 1), ('confirmed_new_vulnerabilities', False),
                         ('historical_bug_reproduced', True), ('product_reachability_verified', True)]:
            altered = copy.deepcopy(original); altered[key] = val
            (self.out / 'acceptance.json').write_text(json.dumps(altered), encoding='utf-8')
            with self.subTest(key=key), self.assertRaises(ValueError): c.verify(self.out, self.root)

    def test_failed_build_cannot_publish_acceptance(self):
        actual = self.reply
        def failure(command, timeout, **kwargs):
            value = actual(command, timeout, **kwargs)
            if '-o' in command: value.update(status='input_error', returncode=1)
            return value
        self.invoker.side_effect = failure
        with self.assertRaises(ValueError): self.run_controls()
        self.assertFalse((self.out / 'acceptance.json').exists())

    def test_receipt_cannot_choose_new_source_root(self):
        original = self.run_controls(); original['source_root'] = '/other-source'
        (self.out / 'acceptance.json').write_text(json.dumps(original), encoding='utf-8')
        with self.assertRaises(ValueError): c.verify(self.out, self.root)

    def test_build_metadata_must_match_binary_artifact(self):
        original = self.run_controls(); original['builds'][0]['sha256'] = 'f' * 64
        (self.out / 'acceptance.json').write_text(json.dumps(original), encoding='utf-8')
        with self.assertRaises(ValueError): c.verify(self.out, self.root)


if __name__ == '__main__':
    unittest.main()
