"""Offline case contract checks. No compiler, library target or network runs."""
import unittest
from pathlib import Path
from unittest.mock import patch
from tools import cjson_case as case


class CaseTests(unittest.TestCase):
    def test_patch_changes_only_reviewed_branch(self):
        raw = b'before\n' + case.OLD + b'\nafter\n'
        self.assertEqual(case.patch_source(raw), b'before\n' + case.NEW + b'\nafter\n')

    def test_patch_preserves_crlf(self):
        raw = case.OLD.replace(b'\n', b'\r\n')
        self.assertEqual(case.patch_source(raw), case.NEW.replace(b'\n', b'\r\n'))

    def test_missing_duplicate_or_already_patched_branch_is_rejected(self):
        for raw in (b'', case.OLD + b'\n' + case.OLD, case.NEW):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                case.patch_source(raw)

    def test_timeout_never_means_reproduced(self):
        log = 'ERROR: AddressSanitizer: heap-use-after-free\n cJSON_Duplicate_rec\n merge_patch\n'
        self.assertEqual(case.classify(1, log, timed_out=True), 'incomplete')
        self.assertEqual(case.classify(1, log, output_limited=True), 'incomplete')

    def test_uaf_requires_expected_library_access_stack(self):
        base = 'ERROR: AddressSanitizer: heap-use-after-free\n'
        self.assertEqual(case.classify(1, base + 'cJSON_Duplicate_rec\nmerge_patch'), 'library_uaf_observed')
        self.assertEqual(case.classify(1, base + 'cJSON_Delete\nmain\nfreed by thread\nmerge_patch'), 'unexpected')
        self.assertEqual(case.classify(1, base + 'main\nfreed by thread\ncJSON_Duplicate\nmerge_patch'), 'unexpected')

    def test_exit_or_generic_crash_is_not_a_library_uaf(self):
        for rc, text in ((1, 'segmentation fault'), (124, 'timeout'), (0, ''),
                         (1, 'ERROR: AddressSanitizer: heap-buffer-overflow cJSON_Duplicate merge_patch')):
            self.assertEqual(case.classify(rc, text), 'unexpected')

    def test_control_requires_semantics_and_clean_sanitizers(self):
        self.assertEqual(case.classify(0, 'CASE_OK independent normal\n'), 'functional_control_passed')
        for text in ('', 'CASE_OK independent normal\nruntime error:',
                     'CASE_OK independent normal\nERROR: LeakSanitizer'):
            self.assertEqual(case.classify(0, text), 'unexpected')

    def test_execution_requires_separate_opt_in(self):
        with patch('subprocess.Popen') as proc, self.assertRaises(ValueError):
            case.execute(Path('unused'), False)
        proc.assert_not_called()

    def test_sandbox_has_no_network_or_host_root_bind(self):
        args = case.sandbox(Path('/case/original'), Path('/case/build'), build=False)
        for flag in ('--unshare-all', '--die-with-parent', '--new-session', '--clearenv', '--cap-drop'):
            self.assertIn(flag, args)
        self.assertNotIn('--share-net', args)
        self.assertNotIn('--bind', args)
        self.assertNotIn('/', args)
        self.assertIn('/src', args)

    def test_only_build_outputs_are_writable_in_build_mode(self):
        args = case.sandbox(Path('/case/original'), Path('/case/build'), build=True)
        slot = args.index('--bind')
        self.assertEqual(args[slot + 1:slot + 3], [str(Path('/case/build')), '/out'])
        self.assertEqual(args.count('--bind'), 1)

    def test_poc_does_not_delete_consumed_target_after_merge(self):
        text = (case.CASE / 'poc.c').read_text(encoding='utf-8')
        tail = text[text.index('result = sensitive'):]
        self.assertIn('target = NULL;', tail)
        self.assertNotIn('cJSON_Delete(target)', tail)
        self.assertIn('cJSON_Compare', tail)
        self.assertIn('if (owns_patch) cJSON_Delete(patch);', tail)

    def runtime_fixture(self):
        import json, tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        folder = Path(tmp.name)
        (folder / 'prepared.json').write_bytes(b'{"schema": "cjson-case-prepared-0.1"}')
        runtime = folder / 'runtime'
        runtime.mkdir()
        uaf = b'ERROR: AddressSanitizer: heap-use-after-free\n cJSON_Duplicate\n merge_patch\n'
        ok = b'CASE_OK control normal\n'
        rows = []
        for variant in ('original', 'independent', 'patched'):
            (runtime / ('build-' + variant + '.log')).write_bytes(b'')
            rows.append({'command': ['x'], 'exit_code': 0, 'seconds': 1.0, 'timed_out': False,
                         'output_limited': False, 'log': 'build-' + variant + '.log',
                         'log_sha256': case.sha(b''), 'classification': 'unexpected',
                         'phase': 'build', 'variant': variant})
            bindir = runtime / variant
            bindir.mkdir()
            probe = b'probe-' + variant.encode()
            (bindir / 'probe').write_bytes(probe)
            for i, (name, sensitive) in enumerate(case._selection(variant)):
                uaf_row = variant in ('original', 'independent') and name == 'subtree'
                raw = uaf if uaf_row else ok
                (runtime / f'{variant}-{i:02d}.log').write_bytes(raw)
                expected = 'library_uaf_observed' if uaf_row else 'functional_control_passed'
                rows.append({'command': ['x'], 'exit_code': 1 if uaf_row else 0, 'seconds': 0.1,
                             'timed_out': False, 'output_limited': False,
                             'log': f'{variant}-{i:02d}.log', 'log_sha256': case.sha(raw),
                             'classification': expected, 'phase': 'run', 'variant': variant,
                             'case': name, 'case_sensitive': sensitive, 'expected': expected,
                             'passed': True, 'binary_sha256': case.sha(probe)})
        version_raw = b'clang version 22.1.8\n'
        (runtime / 'compiler-version.log').write_bytes(version_raw)
        matrix = {'schema': 'cjson-observed-matrix-0.1', 'status': 'passed',
                  'prepared_sha256': case.sha((folder / 'prepared.json').read_bytes()),
                  'rows': rows,
                  'isolation': {'netns': 'net:[1]', 'pidns': 'pid:[1]', 'host_mount': False,
                                'home': False, 'netdev': '  lo: bytes'},
                  'compiler_version_record': {'exit_code': 0, 'log': 'compiler-version.log',
                                              'log_sha256': case.sha(version_raw)},
                  'compiler_binary_sha256': 'a' * 64,
                  'target_executed': True, 'public_known_case': True,
                  'independent_scope': case.INDEPENDENT_SCOPE,
                  'product_reachability': 'not_established', 'confirmed_product_vulnerabilities': 0,
                  'limitations': case.LIMITATIONS}
        (runtime / 'acceptance.json').write_text(json.dumps(matrix), encoding='utf-8')
        return folder, runtime, matrix

    def test_verify_runtime_recomputes_full_matrix_without_execution(self):
        from unittest.mock import patch
        folder, runtime, matrix = self.runtime_fixture()
        with patch.object(case, 'verify_prepared', return_value={}) as prepared, \
                patch('subprocess.Popen') as proc:
            value = case.verify_runtime(folder)
            code = case.main(['verify-runtime', '--output', str(folder)])
        self.assertEqual(prepared.call_count, 2)
        proc.assert_not_called()
        self.assertEqual(code, 0)
        self.assertEqual(value['status'], 'passed')
        self.assertEqual(value['rows'], 29)
        self.assertEqual(value['classifications'], {'unexpected': 3, 'library_uaf_observed': 4,
                                                    'functional_control_passed': 22})
        self.assertEqual((value['uaf_reproduced'], value['controls_passed']), (4, 22))

    def test_verify_runtime_rejects_tampered_matrices(self):
        import json
        from unittest.mock import patch
        def fresh_mutated(change):
            folder, runtime, matrix = self.runtime_fixture()
            change(folder, runtime, matrix)
            (runtime / 'acceptance.json').write_text(json.dumps(matrix), encoding='utf-8')
            return folder
        def relabel(folder, runtime, matrix):
            matrix['rows'][1]['classification'] = 'functional_control_passed'
        def flip_pass(folder, runtime, matrix):
            matrix['rows'][1]['passed'] = False
        def rewrite_log(folder, runtime, matrix):
            (runtime / 'original-00.log').write_bytes(b'CASE_OK swapped\n')
        def wrong_binding(folder, runtime, matrix):
            (folder / 'prepared.json').write_bytes(b'{}')
        def downgrade_label(folder, runtime, matrix):
            matrix['product_reachability'] = 'established'
        def trim_rows(folder, runtime, matrix):
            matrix['rows'] = matrix['rows'][:-1]
        def traversal_log(folder, runtime, matrix):
            matrix['rows'][4]['log'] = '../prepared.json'
        def probe_swap(folder, runtime, matrix):
            (runtime / 'original' / 'probe').write_bytes(b'other binary')
        for change in (relabel, flip_pass, rewrite_log, wrong_binding, downgrade_label,
                       trim_rows, traversal_log, probe_swap):
            with self.subTest(change=change.__name__):
                folder = fresh_mutated(change)
                with patch.object(case, 'verify_prepared', return_value={}):
                    with self.assertRaises(ValueError):
                        case.verify_runtime(folder)

    def test_verify_runtime_mode_refuses_execution_flags(self):
        from unittest.mock import patch
        with patch('subprocess.Popen') as proc:
            code = case.main(['verify-runtime', '--output', 'unused', '--execute-authorized'])
        proc.assert_not_called()
        self.assertEqual(code, 1)


if __name__ == '__main__':
    unittest.main()
