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


if __name__ == '__main__':
    unittest.main()
