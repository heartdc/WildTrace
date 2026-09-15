"""Synthetic candidate quality regressions; no target code is executed."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from ohvul.detect.scanner import scan_path
from ohvul.engine_adapter import normalize_findings, engine_result_to_audit_result
from ohvul.verify import validate_result


class CandidateQualityTests(unittest.TestCase):
    def scan(self, code):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'sample.cpp').write_text(code, encoding='utf-8', newline='\n')
            return scan_path(root)

    def pointers(self, result):
        return [item for item in result['findings'] if item['cwe_candidate'] == 'CWE-476']

    def test_declarations_are_not_dereferences(self):
        for code in ('int *p;', 'int **p;', 'const char *s = 0;',
                     'sample_value *value = 0;', 'void f(int *p) {}'):
            with self.subTest(code=code):
                self.assertEqual(self.pointers(self.scan(code)), [])

    def test_multiplication_is_not_a_pointer_dereference(self):
        self.assertEqual(self.pointers(self.scan('int f(int a,int b){return a * b;}')), [])

    def test_actual_dereferences_remain_candidates(self):
        for code in ('int f(int *p){return *p;}', '*p = 1;', 'return p->field;',
                     'int *p = 0; return *p;', 'return *(p + 1);', 'return n * *p;'):
            with self.subTest(code=code):
                self.assertTrue(self.pointers(self.scan(code)))

    def test_line_and_byte_evidence_stay_on_original_source(self):
        code = '/* *ignored */\nint *p = 0;\nreturn *p;\n'
        result = self.scan(code)
        findings = self.pointers(result)
        self.assertEqual([item['location']['line'] for item in findings], [3])
        self.assertEqual(findings[0]['evidence']['code'], 'return *p;')
        self.assertEqual(findings[0]['evidence']['file_sha256'], hashlib.sha256(code.encode()).hexdigest())
        validate_result(result)

    def test_comments_and_literals_do_not_trigger_rules(self):
        samples = ['// strcpy(d,s); *p;\nint x;', '/* memcpy(d,s,n);\n*p; */\nint x;',
                   'const char *s = "strcpy(d,s); *p";',
                   'auto s = R"tag(strcpy(d,s);\n*p; )tag";',
                   'const char *s = "escaped \\" strcpy(d,s);";']
        for code in samples:
            with self.subTest(code=code):
                self.assertEqual(self.scan(code)['findings'], [])

    def test_string_cannot_request_ignore(self):
        result = self.scan('const char *s = "ohvul:ignore"; strcpy(d,s);')
        self.assertTrue(any(item['cwe_candidate'] == 'CWE-122' for item in result['findings']))

    def test_real_line_comment_ignore_is_recorded(self):
        result = self.scan('strcpy(d,s); // ohvul:ignore')
        self.assertEqual(result['findings'], [])
        self.assertTrue(any(x['evidence']['decision'] == 'explicit_line_suppression'
                            for x in result['rule_observations']))
        validate_result(result)

    def test_ternary_guard_becomes_observation_not_vulnerability_verdict(self):
        result = self.scan('int f(int *p){ return p ? *p : 0; }')
        self.assertEqual(self.pointers(result), [])
        observations = result['rule_observations']
        self.assertTrue(any(x['evidence']['decision'] == 'same_expression_guard' for x in observations))
        self.assertTrue(all(x['status'] == 'observation' and x['evidence']['final_verdict'] == 'undetermined'
                            for x in observations))
        validate_result(result)

    def test_if_guard_becomes_observation(self):
        result = self.scan('int f(int *p){ if(p != 0) return *p; return 0; }')
        self.assertEqual(self.pointers(result), [])
        self.assertTrue(any(x['evidence']['decision'] == 'same_expression_guard'
                            for x in result['rule_observations']))

    def test_guard_does_not_cover_another_pointer(self):
        self.assertTrue(self.pointers(self.scan('return p ? *q : 0;')))

    def test_wrong_guard_is_not_safe(self):
        self.assertTrue(self.pointers(self.scan('if(p == 0) return *p;')))

    def test_reassignment_inside_guard_is_not_suppressed(self):
        self.assertTrue(self.pointers(self.scan('if(p) { p = 0; return *p; }')))

    def test_unguarded_use_after_guard_on_same_line_is_retained(self):
        result = self.scan('if(p) return *p; return *p;')
        self.assertTrue(self.pointers(result))

    def test_volatile_and_macro_contexts_are_not_guard_suppressed(self):
        for code in ('int *volatile p; int f(){ return p ? *p : 0; }',
                     '#define p get_pointer()\nreturn p ? *p : 0;'):
            with self.subTest(code=code):
                self.assertTrue(self.pointers(self.scan(code)))

    def test_guard_observation_tampering_is_rejected(self):
        result = self.scan('return p ? *p : 0;')
        result['rule_observations'][0]['evidence']['decision'] = 'safe'
        with self.assertRaises(ValueError):
            validate_result(result)

    def test_unknown_control_flow_is_not_discarded(self):
        self.assertTrue(self.pointers(self.scan('if(!p) stop(); return *p;')))

    def test_control_statement_dereference_is_retained(self):
        for code in ('if(flag) *p = 1;', 'while(flag) *p = 2;',
                     'if(flag) f(); else *p = 1;', 'do *p = 1; while(flag);'):
            with self.subTest(code=code):
                self.assertTrue(self.pointers(self.scan(code)))

    def test_cr_only_and_crlf_keep_line_locations(self):
        for eol in ('\r', '\r\n'):
            with self.subTest(eol=eol):
                result = self.scan('// ignored *p' + eol + 'int *p;' + eol + 'return *p;')
                self.assertEqual([x['location']['line'] for x in self.pointers(result)], [3])

    def test_literal_with_ignore_and_guard_does_not_hide_later_use(self):
        result = self.scan('const char *s="return p ? *p : 0; // ohvul:ignore"; return *p;')
        self.assertTrue(self.pointers(result))

    def test_shard_merge_retains_observations(self):
        from ohvul.shards import merge_shard_results
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('return p ? *p : 0;')
            first = scan_path(root, ['a.c'])
            merged = merge_shard_results([first], root)
            self.assertEqual(merged['rule_observations'], first['rule_observations'])
            validate_result(merged)


class CweMappingQualityTests(unittest.TestCase):
    def normalize(self, rule, engine='clang-tidy', **fields):
        item = {'rule': rule, 'location': {'file': 'a.c', 'line': 1}, **fields}
        return normalize_findings({'findings': [item]}, engine=engine, source_root=Path('.'))

    def test_tidy_null_checker_maps_without_losing_rule(self):
        normalized = self.normalize('clang-analyzer-core.NullDereference')
        item = normalized['findings'][0]
        self.assertEqual(item['cwe_candidate'], 'CWE-476')
        self.assertEqual(item['rule'], 'clang-analyzer-core.NullDereference')
        result = engine_result_to_audit_result(normalized, source_root=Path('.'))
        self.assertEqual(result['findings'][0]['cwe_candidate'], 'CWE-476')
        validate_result(result)

    def test_generic_malloc_checker_does_not_imply_use_after_free(self):
        self.assertIsNone(self.normalize('unix.Malloc', engine='clang')['findings'][0]['cwe_candidate'])

    def test_unknown_checker_remains_unclassified(self):
        self.assertIsNone(self.normalize('unmodeled.checker')['findings'][0]['cwe_candidate'])

    def test_another_engine_does_not_inherit_clang_mapping(self):
        self.assertIsNone(self.normalize('core.NullDereference', engine='semgrep')['findings'][0]['cwe_candidate'])

    def test_reported_cwe_is_not_mislabelled_as_builtin_inference(self):
        item = self.normalize('external.rule', cwe_candidate='CWE-125')['findings'][0]
        self.assertEqual(item['cwe_candidate'], 'CWE-125')
        self.assertEqual(item['cwe_mapping_source'], 'engine_reported')
        self.assertIsNone(item['cwe_mapping_version'])

    def test_invalid_reported_cwe_is_rejected(self):
        for value in ('', 'CWE-0', 'CWE-abc', 476, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.normalize('external.rule', cwe_candidate=value)

    def test_projected_cwe_is_bound_to_evidence(self):
        normalized = self.normalize('clang-analyzer-core.NullDereference')
        result = engine_result_to_audit_result(normalized, source_root=Path('.'))
        self.assertEqual(result['findings'][0]['evidence']['cwe_candidate'], 'CWE-476')
        changed = copy.deepcopy(result)
        changed['findings'][0]['cwe_candidate'] = 'CWE-416'
        with self.assertRaises(ValueError):
            validate_result(changed)


if __name__ == '__main__':
    unittest.main()
