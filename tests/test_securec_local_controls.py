"""Transport fixtures test the opt-in runner; never execute a fixture binary."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.validation_cases import run_securec_controls as m


def stdout_controls():
    rows = [{'case_id': c, 'kind': 'functional_control', 'passed': True,
             'counts_as_vulnerability': False} for c in m.CASES]
    rows += [{'kind': 'functional_control_summary', 'cases': 6, 'failures': 0,
              'confirmed_vulnerabilities': 0}]
    return b'\n'.join(json.dumps(row).encode() for row in rows) + b'\n'


MARKER = b'CASE_START securec-memcpy-controls cases=6\n'


class SecurecClassificationTests(unittest.TestCase):
    def test_exact_controls_are_not_vulnerability_verdict(self):
        self.assertEqual(m.classify(stdout_controls(), MARKER, 0, 'completed'), 'functional_control_passed')

    def test_errors_cannot_be_hidden_by_success_stdout(self):
        for stderr, code, status, expected in (
            (MARKER, 1, 'input_error', 'execution_failed'),
            (MARKER, None, 'timeout', 'timeout'),
            (MARKER + b'ERROR: AddressSanitizer', 0, 'completed', 'sanitizer_report_requires_review'),
            (MARKER + b'runtime error: invalid access', 0, 'completed', 'sanitizer_report_requires_review'),
            (MARKER, False, 'completed', 'execution_failed')):
            with self.subTest(status=status, stderr=stderr):
                self.assertEqual(m.classify(stdout_controls(), stderr, code, status), expected)

    def test_incomplete_duplicate_forged_or_boolean_counts_rejected(self):
        raw = stdout_controls()
        bad = [raw.split(b'\n', 1)[1], raw + raw, b'{}', raw.replace(b'"cases": 6', b'"cases": true'),
               raw.replace(b'"counts_as_vulnerability": false', b'"counts_as_vulnerability": true'),
               raw.replace(b'"passed": true', b'"passed": false')]
        for value in bad:
            with self.subTest(value=value[:70]):
                self.assertEqual(m.classify(value, MARKER, 0, 'completed'), 'invalid_control_output')
        for marker in (b'', MARKER * 2):
            self.assertEqual(m.classify(raw, marker, 0, 'completed'), 'invalid_control_output')

    def test_no_execution_or_source_io_without_opt_in(self):
        with patch.object(m, 'source_inputs') as source, patch.object(m, '_invoke') as invoke:
            for approval, opt in (('', True), ('test', False), ('test', 1), ('bad\nref', True)):
                with self.assertRaises(ValueError):
                    m.run(Path('.'), Path('unused'), approval_reference=approval, allow_target_execution=opt)
            source.assert_not_called(); invoke.assert_not_called()

    def test_runtime_sandbox_has_no_host_writable_bind_or_network(self):
        plan = list(m.steps(Path('C:/test-output').resolve()))
        self.assertEqual(len(plan), 10)
        for label, command, _ in plan:
            self.assertIn('--unshare-all', command)
            self.assertIn('--cap-drop', command)
            self.assertIn('--clearenv', command)
            if label.startswith('run-'):
                self.assertNotIn('--bind', command)
                self.assertNotIn('--share-net', command)
            if label.startswith('build-'):
                self.assertIn('-fsanitize=address,undefined', command)
                self.assertIn('-DSECUREC_WITH_PERFORMANCE_ADDONS=0', command)

    def test_non_object_isolation_json_is_rejected(self):
        for raw in (b'[]', b'null', b'true'):
            with self.assertRaises(ValueError): m.isolate_ok(raw)


class SecurecReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / 'source'; self.root.mkdir()
        for name in m.INPUTS:
            path = self.root / name; path.parent.mkdir(exist_ok=True)
            path.write_bytes(b'/* test-only input, never compiled */\n')
        self.out = self.base / 'output'
        self.enterContext(patch.object(m, 'source_inputs', side_effect=self.capture))
        self.invocation = self.enterContext(patch.object(m, '_invoke', side_effect=self.invoke))
        self.preflight_ok = True
        self.failed_label = None

    def capture(self, root):
        return {name: {'bytes': len((root / name).read_bytes()), 'sha256': m.sha((root / name).read_bytes())}
                for name in m.INPUTS}

    def invoke(self, command, timeout, **kwargs):
        stdout, stderr = b'', b''
        status, code = 'completed', 0
        if '/usr/bin/python3' in command:
            stdout = json.dumps({'home_hidden': True, 'host_mount_hidden': True,
                'interfaces': ['lo'] if self.preflight_ok else ['lo', 'eth0'],
                'effective_capabilities': '0000000000000000'}).encode()
        elif '--version' in command:
            stdout = b'clang version 22.1.8 TEST-ONLY\n'
        elif '-fsanitize=address,undefined' in command:
            variant = 'o0' if '-O0' in command else 'o2'
            (self.out / ('build-' + variant) / 'case').write_bytes(b'not executable; mocked transport')
            if self.failed_label == 'build':
                status, code = 'input_error', 1
        else:
            stdout, stderr = stdout_controls(), MARKER
            if self.failed_label == 'runtime':
                status, code, stderr = 'input_error', 1, MARKER + b'ERROR: AddressSanitizer TEST-ONLY'
        return {'stdout': stdout, 'stderr': stderr, 'status': status,
                'reason': None if code == 0 else 'test-only failure', 'returncode': code, 'seconds': 0.01}

    def run_fixture(self):
        return m.run(self.root, self.out, allow_target_execution=True,
                     approval_reference='TEST-ONLY-NOT-A-GRANT')

    def test_complete_schedule_and_offline_reclassification(self):
        result = self.run_fixture()
        self.assertEqual(self.invocation.call_count, 10)
        self.assertEqual((result['real_target_runs'], result['control_observations']), (6, 36))
        self.invocation.reset_mock()
        self.assertEqual(m.verify(self.out, self.root), result)
        self.invocation.assert_not_called()

    def test_bad_isolation_stops_before_build_or_target(self):
        self.preflight_ok = False
        with self.assertRaises(ValueError): self.run_fixture()
        self.assertEqual(self.invocation.call_count, 1)
        self.assertFalse((self.out / 'acceptance.json').exists())

    def test_build_failure_does_not_write_success_receipt(self):
        self.failed_label = 'build'
        with self.assertRaises(ValueError): self.run_fixture()
        self.assertEqual(self.invocation.call_count, 3)
        self.assertFalse((self.out / 'acceptance.json').exists())

    def test_sanitizer_report_is_preserved_not_counted_as_pass(self):
        self.failed_label = 'runtime'
        value = self.run_fixture()
        self.assertEqual(value['status'], 'runtime_review_required')
        self.assertEqual(value['control_observations'], 0)
        self.assertEqual(m.verify(self.out, self.root), value)

    def test_new_output_required(self):
        self.out.mkdir()
        with self.assertRaises(ValueError): self.run_fixture()
        self.invocation.assert_not_called()

    def test_source_change_invalidates_receipt(self):
        self.run_fixture(); (self.root / m.INPUTS[0]).write_bytes(b'changed')
        with self.assertRaises(ValueError): m.verify(self.out, self.root)

    def test_copied_source_or_harness_change_is_rejected(self):
        self.run_fixture()
        for name in (*m.INPUTS, 'case.c'):
            path = self.out / 'inputs' / name; old = path.read_bytes(); path.write_bytes(b'changed')
            with self.subTest(name=name), self.assertRaises(ValueError): m.verify(self.out, self.root)
            path.write_bytes(old)

    def test_log_or_binary_tamper_rejected(self):
        self.run_fixture()
        for name in ('run-o0-1.stdout', 'build-o0/case', 'isolation.stdout'):
            path = self.out / name; old = path.read_bytes(); path.write_bytes(old + b'changed')
            with self.subTest(name=name), self.assertRaises(ValueError): m.verify(self.out, self.root)
            path.write_bytes(old)

    def test_receipt_schedule_and_promotion_tampering_rejected(self):
        original = self.run_fixture()
        variants = []
        for key, value in (('confirmed_vulnerabilities', 1), ('vulnerability_reproduced', True),
                           ('real_target_runs', True), ('control_observations', 99), ('llm_invoked', True)):
            changed = copy.deepcopy(original); changed[key] = value; variants.append(changed)
        changed = copy.deepcopy(original); changed['records'][2]['command'].append('--bad'); variants.append(changed)
        changed = copy.deepcopy(original); changed['runs'][1] = changed['runs'][0]; variants.append(changed)
        changed = copy.deepcopy(original); changed['approval']['independently_authenticated'] = True; variants.append(changed)
        changed = copy.deepcopy(original); changed['approval']['scope'] = 'arbitrary_remote_targets'; variants.append(changed)
        for changed in variants:
            (self.out / 'acceptance.json').write_text(json.dumps(changed), encoding='utf-8')
            with self.assertRaises(ValueError): m.verify(self.out, self.root)

    def test_source_change_during_verify_is_not_accepted(self):
        self.run_fixture()
        original = m.classify
        def change(*args):
            (self.root / m.INPUTS[0]).write_bytes(b'concurrent source edit')
            return original(*args)
        with patch.object(m, 'classify', side_effect=change), self.assertRaises(ValueError):
            m.verify(self.out, self.root)

    def test_case_attachment_preserves_candidate_and_performs_no_execution(self):
        controls = self.run_fixture()
        case = {'case_id': 'RC-TEST-ONLY', 'candidate': {'alert_id': 'AL-TEST',
                'location': {'file': 'src/memcpy_s.c', 'line': 518}},
                'input_bindings': {'source_file_sha256': controls['source_files']['src/memcpy_s.c']['sha256']}}
        case_path = self.base / 'case.json'; case_path.write_text(json.dumps(case), encoding='utf-8')
        self.invocation.reset_mock()
        from ohvul import runtime_evidence
        with patch.object(runtime_evidence, '_case', return_value=(case, [], lambda: None)):
            review = m.attach_case(self.out, self.root, case_path, self.base / 'result.json',
                                   self.base / 'report.json', self.base / 'control-review.json')
        self.invocation.assert_not_called()
        self.assertEqual(review['confirmed_vulnerabilities'], 0)
        self.assertFalse(review['candidate_closed'])
        self.assertFalse(review['vulnerability_reproduced'])

    def test_attachment_rejects_mixed_source(self):
        self.run_fixture()
        case = {'case_id': 'RC-TEST-ONLY', 'candidate': {'alert_id': 'AL-TEST',
                'location': {'file': 'src/memcpy_s.c', 'line': 518}},
                'input_bindings': {'source_file_sha256': 'f' * 64}}
        path = self.base / 'case.json'; path.write_text(json.dumps(case), encoding='utf-8')
        from ohvul import runtime_evidence
        with patch.object(runtime_evidence, '_case', return_value=(case, [], lambda: None)), self.assertRaises(ValueError):
            m.attach_case(self.out, self.root, path, self.base / 'result.json',
                          self.base / 'report.json', self.base / 'bad-review.json')
        self.assertFalse((self.base / 'bad-review.json').exists())


if __name__ == '__main__':
    unittest.main()
