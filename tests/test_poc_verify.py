"""Tests for the compile-and-run verification step (no compiler required).

The compile/run path itself needs a real toolchain, so these tests cover the
classification and the failure plumbing; the end-to-end numbers live in
deliverables/LLM_PoC四步验证结果.json from an actual run.
"""
import unittest
from pathlib import Path

from ohvul.poc_verify import (CRASH_CODES, classify_poc, discover_compiler,
                              parse_undefined_symbols, run_poc, verdict_for)

REAL_LINK = ('#include "cJSON.h"\n#include <stdio.h>\n'
             'int main(void){ cJSON *j = cJSON_Parse("{}"); return j ? 0 : 1; }')
COPIED = ('#include <stdio.h>\n'
          'static int parse_string(void *b, void *i, int *o){ return 0; }\n'
          'int main(void){ return parse_string(0, 0, 0); }')
NO_MAIN = '#include <stdio.h>\nstatic int helper(void){ return 0; }\n'


class ClassifyTests(unittest.TestCase):
    def test_quoted_project_include_is_real_link(self):
        self.assertEqual(classify_poc(REAL_LINK, 'parse_string', {'cJSON.h'}),
                         'real_link')

    def test_copied_target_wins_over_header(self):
        copied_with_header = ('#include "cJSON.h"\n' + COPIED)
        self.assertEqual(classify_poc(copied_with_header, 'parse_string',
                                      {'cJSON.h'}), 'copied_target')

    def test_std_only_include_is_self_contained(self):
        self.assertEqual(classify_poc(COPIED.replace('parse_string', 'other_fn'),
                                      'parse_string', {'cJSON.h'}),
                         'self_contained')

    def test_missing_main_is_build_failed(self):
        self.assertEqual(classify_poc(NO_MAIN, '', set()), 'build_failed')

    def test_crash_codes_cover_windows_and_posix(self):
        self.assertIn(3221225477, CRASH_CODES)   # 0xC0000005 access violation
        self.assertIn(139, CRASH_CODES)          # SIGSEGV


class EnvironmentTests(unittest.TestCase):
    def test_discover_compiler_returns_command_list_or_none(self):
        found = discover_compiler()
        if found is not None:
            self.assertIsInstance(found, list)
            self.assertTrue(found)

    def test_explicit_compiler_is_respected(self):
        self.assertEqual(discover_compiler('zig cc'), ['zig', 'cc'])

    def test_missing_binary_is_reported_not_raised(self):
        result = run_poc(Path('does_not_exist_anywhere.exe'), timeout=2)
        self.assertFalse(result['crashed'])
        self.assertIsNone(result['exit_code'])


class UndefinedSymbolTests(unittest.TestCase):
    """The link set is inferred from the linker's own complaints, so parsing
    them correctly is what makes hand-written --link unnecessary."""

    def test_lld_link_format(self):
        stderr = ("lld-link: error: undefined symbol: cJSONUtils_GetPointer\n"
                  "lld-link: error: undefined symbol: cJSON_Parse")
        self.assertEqual(parse_undefined_symbols(stderr),
                         ['cJSONUtils_GetPointer', 'cJSON_Parse'])

    def test_gnu_ld_format(self):
        stderr = ("/usr/bin/ld: draft.o: in function `main':\n"
                  "draft.c:(.text+0x1f): undefined reference to `cJSON_Delete'")
        self.assertEqual(parse_undefined_symbols(stderr), ['cJSON_Delete'])

    def test_msvc_format(self):
        stderr = "error LNK2019: unresolved external symbol cJSON_Print referenced"
        self.assertEqual(parse_undefined_symbols(stderr), ['cJSON_Print'])

    def test_duplicates_are_collapsed(self):
        stderr = ("undefined symbol: cJSON_Parse\n"
                  "undefined symbol: cJSON_Parse\n"
                  "undefined symbol: cJSON_Delete")
        self.assertEqual(parse_undefined_symbols(stderr),
                         ['cJSON_Parse', 'cJSON_Delete'])

    def test_unrelated_errors_yield_nothing(self):
        self.assertEqual(parse_undefined_symbols(
            "error: 'cJSON.h' file not found"), [])


class VerdictTests(unittest.TestCase):
    """Three states, so "no crash from a real-link client" (a result) is never
    mixed with "no crash from a copied body" (says nothing)."""

    def _row(self, **kwargs):
        base = {'compiled': True, 'exit_code': 0, 'crashed': False,
                'kind': 'real_link'}
        base.update(kwargs)
        return base

    def test_real_link_crash_is_confirmed(self):
        verdict, reason = verdict_for(self._row(crashed=True, exit_code=3221225477))
        self.assertEqual(verdict, 'confirmed')
        self.assertEqual(reason, 'crash_inside_library')

    def test_real_link_without_crash_is_refuted(self):
        verdict, reason = verdict_for(self._row())
        self.assertEqual(verdict, 'refuted')
        self.assertEqual(reason, 'real_link_no_crash')

    def test_copied_target_crash_is_undetermined(self):
        verdict, reason = verdict_for(self._row(kind='copied_target', crashed=True,
                                                exit_code=3221225477))
        self.assertEqual(verdict, 'undetermined')
        self.assertIn('tautology', reason)

    def test_build_failure_is_undetermined(self):
        verdict, reason = verdict_for({'compiled': False})
        self.assertEqual(verdict, 'undetermined')
        self.assertEqual(reason, 'build_failed')

    def test_no_crash_is_not_a_refutation_without_a_memory_checker(self):
        """CVE-2026-87933 returns 0 on the default heap and SIGSEGVs under a
        quarantining allocator, so a silent UAF must stay undetermined."""
        verdict, reason = verdict_for(self._row(pattern='P8_use_after_free'),
                                      memory_checks=False)
        self.assertEqual(verdict, 'undetermined')
        self.assertEqual(reason, 'no_crash_without_memory_checker')

    def test_null_deref_can_still_be_refuted_without_a_checker(self):
        # a null dereference faults on any build, so "no crash" is a result
        verdict, reason = verdict_for(self._row(pattern='P6_null_deref'),
                                      memory_checks=False)
        self.assertEqual(verdict, 'refuted')
        self.assertEqual(reason, 'real_link_no_crash')

    def test_unlinked_crash_is_undetermined(self):
        verdict, reason = verdict_for(self._row(kind='self_contained', crashed=True,
                                                exit_code=3221225477))
        self.assertEqual(verdict, 'undetermined')
        self.assertEqual(reason, 'not_linked_against_library')


if __name__ == '__main__':
    unittest.main()
