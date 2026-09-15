"""Local syntax contracts. No model, analyzer, network or target execution."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ohvul import semantic_rules as rules
from ohvul.verify import validate_result


class SemanticBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def put(self, text, name='a.c'):
        path = self.root / name
        path.write_text(text, encoding='utf-8')
        return path

    def local(self, text):
        return rules.length_candidates(self.put(text), root=self.root)

    def cross(self, text):
        self.put(text)
        return rules.cross_function_length_candidates(self.root, ['a.c'])

    def test_snprintf_size_is_second_argument_not_format(self):
        result = self.local('void f(char*d,char*s,size_t n){ snprintf(d, n, "%s", s); }')
        self.assertEqual(result[0]['sink']['size_expression'], 'n')

    def test_nested_and_multiline_arguments_are_not_split_early(self):
        result = self.local('void f(char*d,char*s,size_t n){\nmemcpy(\n d,\n s,\n bounded(n, limit(n, 32))\n);\n}')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['sink']['size_expression'], 'bounded(n, limit(n, 32))')

    def test_separate_calls_on_one_line_keep_distinct_sizes(self):
        result = self.local('void f(char*d,char*s){ memcpy(d,s,1); memcpy(d,s,2); }')
        self.assertEqual([x['sink']['size_expression'] for x in result], ['1', '2'])

    def test_comments_literals_and_definitions_are_not_sinks(self):
        result = self.local('''// memcpy(d,s,n);
#define COPY(d,s,n) memcpy(d,s,n)
void f(void) { const char *s = "memcpy(d,s,n)"; }
''')
        self.assertEqual(result, [])

    def test_local_evidence_does_not_cross_function_boundary(self):
        result = self.local('''void before(char*s) { size_t n=strlen(s); if(n<64){} }
void after(char*d,char*s,size_t n) { memcpy(d,s,n); }
''')
        self.assertEqual(result[0]['source_lines'], [])
        self.assertEqual(result[0]['guard_lines'], [])

    def test_later_source_and_guard_on_same_line_do_not_count(self):
        result = self.local('void f(char*d,char*s,size_t n){ memcpy(d,s,n); n=strlen(s); if(n<64){} }')
        self.assertEqual(result[0]['source_lines'], [])
        self.assertEqual(result[0]['guard_lines'], [])

    def test_no_sink_from_next_function(self):
        self.assertEqual(self.cross('''void empty(char*d,char*s,size_t n) {
}
void other(char*d,char*s,size_t n) {
 memcpy(d,s,n);
}
void caller(char*d,char*s) {
 size_t n=strlen(s);
 empty(d,s,n);
}
'''), [])

    def test_signature_and_call_can_span_lines(self):
        result = self.cross('''void sink(
 char*d, const char*s, size_t n)
{
 memcpy(d,s,n);
}
void caller(char*d,char*s){
 size_t n=strlen(s);
 sink(d,
 s,
 n);
}
''')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['callee']['size_parameter'], 'n')

    def test_parameter_position_is_not_assumed_to_be_last(self):
        result = self.cross('''void sink(char*d,size_t n,const char*s){memcpy(d,s,n);}
void caller(char*d,char*s){size_t amount=strlen(s); sink(d,amount,s);}
''')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['caller']['length_argument'], 'amount')
        self.assertEqual(result[0]['callee']['size_parameter_index'], 1)

    def test_parameter_only_in_destination_is_not_a_length_link(self):
        self.assertEqual(self.cross('''void sink(char*d,char*s,size_t n){memcpy(d+n,s,8);}
void caller(char*d,char*s){size_t n=strlen(s);sink(d,s,n);}
'''), [])

    def test_inline_length_producer_keeps_real_evidence_line(self):
        result = self.cross('''void sink(char*d,char*s,size_t n){memcpy(d,s,n);}
void caller(char*d,char*s){sink(d,s,strlen(s)+1);}
''')
        self.assertEqual(len(result), 1)
        sources = [e for e in result[0]['evidence'] if e['kind'] == 'caller_length_source']
        self.assertEqual([e['line'] for e in sources], [2])

    def test_length_source_after_call_does_not_support_call(self):
        self.assertEqual(self.cross('''void sink(char*d,char*s,size_t n){memcpy(d,s,n);}
void caller(char*d,char*s,size_t n){sink(d,s,n);n=strlen(s);}
'''), [])

    def test_unrelated_length_variable_is_not_linked(self):
        self.assertEqual(self.cross('''void sink(char*d,char*s,size_t n){memcpy(d,s,n);}
void caller(char*d,char*s,size_t n){size_t other=strlen(s);sink(d,s,n);}
'''), [])

    def test_old_length_assignment_does_not_survive_overwrite(self):
        self.assertEqual(self.cross('''void sink(char*d,char*s,size_t n){memcpy(d,s,n);}
void caller(char*d,char*s){size_t n=strlen(s);n=8;sink(d,s,n);}
'''), [])

    def test_duplicate_callees_are_not_resolved_by_last_wins(self):
        result = self.cross('''void sink(char*d,char*s,size_t n){memcpy(d,s,n);}
void sink(char*d,char*s,int n){memmove(d,s,n);}
void caller(char*d,char*s){size_t n=strlen(s);sink(d,s,n);}
''')
        self.assertEqual(result, [])

    def test_member_call_is_not_bound_to_same_named_free_function(self):
        self.assertEqual(self.cross('''void sink(char*d,char*s,size_t n){memcpy(d,s,n);}
void caller(char*d,char*s){size_t n=strlen(s);obj.sink(d,s,n);}
'''), [])

    def test_long_functions_do_not_have_arbitrary_eighty_line_cutoff(self):
        text = 'void sink(char*d,char*s,size_t n){\n' + '\n'*90 + 'memcpy(d,s,n);\n}\n'
        text += 'void caller(char*d,char*s){\nsize_t n=strlen(s);\n' + '\n'*12 + 'sink(d,s,n);\n}\n'
        self.assertEqual(len(self.cross(text)), 1)

    def test_static_definition_cannot_be_linked_from_another_file(self):
        self.put('static void sink(char*d,char*s,size_t n){memcpy(d,s,n);}', 'a.c')
        self.put('void caller(char*d,char*s){size_t n=strlen(s);sink(d,s,n);}', 'b.c')
        self.assertEqual(rules.cross_function_length_candidates(self.root, ['a.c', 'b.c']), [])

    def test_input_duplicates_and_aliases_rejected(self):
        self.put('void f(void){}')
        for names in ([], ['a.c', 'a.c'], ['a.c', './a.c'], ['../a.c']):
            with self.subTest(names=names), self.assertRaises(ValueError):
                rules.cross_function_length_candidates(self.root, names)

    def test_invalid_utf8_is_not_silently_replaced(self):
        (self.root/'a.c').write_bytes(b'void f(void){}\xff')
        with self.assertRaises((ValueError, UnicodeError)):
            rules.cross_function_length_candidates(self.root, ['a.c'])

    def test_projection_does_not_infer_coverage_from_findings(self):
        result = rules.candidates_to_audit_result([], root=self.root)
        self.assertIsNone(result['scan']['files_scanned'])

    def test_complete_scan_counts_zero_finding_files(self):
        self.put('int f(void){return 0;}')
        result = rules.scan_semantic_files(self.root, ['a.c'])
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['scan']['files_scanned'], 1)
        self.assertEqual(result['findings'], [])
        validate_result(result)

    def test_failed_read_not_counted_as_success_and_retained(self):
        self.put('int f(void){return 0;}')
        result = rules.scan_semantic_files(self.root, ['a.c', 'missing.c'])
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['scan']['files_scanned'], 1)
        self.assertEqual(result['scan']['files_failed'], 1)
        self.assertEqual(result['input_errors'][0]['file'], 'missing.c')

    def test_unknown_syntax_remains_visible(self):
        self.put('void f(char*d,char*s,int n){memcpy(d,s,n);')
        result = rules.scan_semantic_files(self.root, ['a.c'])
        self.assertTrue(result['analysis_issues'])
        self.assertEqual(result['analysis_coverage']['status'], 'partial_lexical_analysis')
        self.assertEqual(result['findings'][0]['status'], 'candidate')

    def test_candidates_bind_both_source_files_and_no_verdict(self):
        self.put('void sink(char*d,char*s,size_t n){memcpy(d,s,n);}', 'a.c')
        self.put('void caller(char*d,char*s){size_t n=strlen(s);sink(d,s,n);}', 'b.c')
        result = rules.scan_semantic_files(self.root, ['a.c', 'b.c'])
        cross = [x for x in result['findings'] if x['rule']=='cross_function_length_propagation_candidate']
        self.assertEqual(len(cross), 1)
        value = cross[0]['evidence']['semantic_candidate']
        self.assertEqual(set(value['source_file_sha256']), {'a.c','b.c'})
        self.assertEqual(value['semantic_status'], 'lexical_association_not_data_flow')
        validate_result(result)

    def test_comma_declarator_does_not_invent_length_origin(self):
        self.assertEqual(self.cross('''void sink(char*d,char*s,size_t n){memcpy(d,s,n);}
void caller(char*d,char*s){size_t n=8, other=strlen(s);sink(d,s,n);}
'''), [])

    def test_callee_mutation_does_not_claim_parameter_propagation(self):
        self.assertEqual(self.cross('''void sink(char*d,char*s,size_t n){n=8;memcpy(d,s,n);}
void caller(char*d,char*s){size_t n=strlen(s);sink(d,s,n);}
'''), [])

    def test_increment_and_address_escape_invalidate_origin(self):
        for change in ('++n;', 'n++;', 'change(&n);'):
            with self.subTest(change=change):
                self.assertEqual(self.cross('void sink(char*d,char*s,size_t n){memcpy(d,s,n);}\n'
                    'void caller(char*d,char*s){size_t n=strlen(s);' + change + 'sink(d,s,n);}'), [])

    def test_unevaluated_size_operand_is_not_value_propagation(self):
        self.assertEqual(self.cross('''void sink(char*d,char*s,size_t n){memcpy(d,s,sizeof(n));}
void caller(char*d,char*s){size_t n=strlen(s);sink(d,s,n);}
'''), [])

    def test_variadic_signature_remains_unresolved_and_local_candidate_kept(self):
        self.put('void sink(char*d,size_t n,...){memcpy(d,d,n);}\n'
                 'void caller(char*d){size_t n=strlen(d);sink(d,n,d);}')
        result = rules.scan_semantic_files(self.root, ['a.c'])
        self.assertTrue(result['analysis_issues'])
        self.assertEqual(result['analysis_coverage']['local_candidates'], 1)
        self.assertEqual(result['analysis_coverage']['cross_function_candidates'], 0)

    def test_macro_candidates_do_not_claim_preprocessor_resolution(self):
        self.put('#if FLAG\nvoid sink(char*d,char*s,int n){memcpy(d,s,n);}\n#endif\n')
        result = rules.scan_semantic_files(self.root, ['a.c'])
        self.assertIn('preprocessor_not_evaluated', [x['reason'] for x in result['analysis_issues']])
        self.assertFalse(result['analysis_coverage']['compiler_semantics_verified'])

    def test_same_named_calls_in_comments_are_not_correlated(self):
        self.assertEqual(self.cross('''void sink(char*d,char*s,size_t n){memcpy(d,s,n);}
void caller(char*d,char*s){size_t n=strlen(s); /* sink(d,s,n); */}
'''), [])

    def test_input_mutation_during_analysis_is_rejected(self):
        path = self.put('void f(char*d,char*s){memcpy(d,s,8);}')
        original = rules._analyze
        def changed(units):
            result = original(units)
            path.write_bytes(path.read_bytes() + b'\n// changed')
            return result
        with patch.object(rules, '_analyze', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed'):
                rules.scan_semantic_files(self.root, ['a.c'])

    def test_invalid_selection_does_not_read_sources(self):
        from ohvul import semantic_syntax as syntax
        self.put('int x;')
        for names in (['../outside.c'], ['a.c', 'a.c'], ['a.txt'], ['.git/a.c']):
            with self.subTest(names=names), patch.object(syntax, 'read_source') as read:
                with self.assertRaises(ValueError):
                    rules.scan_semantic_files(self.root, names)
                read.assert_not_called()

    def test_links_are_rejected_before_reads(self):
        from ohvul import semantic_syntax as syntax
        self.put('int x;')
        with patch.object(syntax, 'is_link', return_value=True), patch.object(syntax, 'read_source') as read:
            with self.assertRaises(ValueError):
                rules.scan_semantic_files(self.root, ['a.c'])
            read.assert_not_called()

    def test_all_input_errors_remain_non_success(self):
        result = rules.scan_semantic_files(self.root, ['missing.c'])
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['scan']['files_scanned'], 0)
        self.assertEqual(result['scan']['files_failed'], 1)

    def test_resource_budgets_do_not_turn_into_empty_success(self):
        from ohvul import semantic_syntax as syntax
        self.put('void f(void){}')
        with patch.object(syntax, 'MAX_SOURCE_BYTES', 4):
            self.assertEqual(rules.scan_semantic_files(self.root, ['a.c'])['status'], 'input_error')
        with patch.object(syntax, 'MAX_TOTAL_BYTES', 4):
            with self.assertRaises(ValueError):
                rules.scan_semantic_files(self.root, ['a.c'])
        with patch.object(syntax, 'MAX_FILES', 0), patch.object(syntax, 'read_source') as read:
            with self.assertRaises(ValueError):
                rules.scan_semantic_files(self.root, ['a.c'])
            read.assert_not_called()

    def test_all_advisories_do_not_receive_unproved_cwe(self):
        self.put('void f(char*d,char*s,int n){memcpy(d,s,n);}')
        result = rules.scan_semantic_files(self.root, ['a.c'])
        self.assertTrue(all(f['cwe_candidate'] is None for f in result['findings']))
        result['findings'][0]['cwe_candidate'] = 'CWE-120'
        with self.assertRaises(ValueError):
            validate_result(result)

    def test_api_prototypes_are_not_invocations(self):
        self.assertEqual(self.local('void memcpy(char*d,const char*s,size_t n);\n'), [])
        self.assertEqual(self.local('void f(void){void memcpy(char*d,char*s,int n);}\n'), [])

    def test_callee_prototype_does_not_become_caller_evidence(self):
        self.assertEqual(self.cross('void sink(char*d,char*s,size_t n){memcpy(d,s,n);}\n'
            'void caller(char*d,char*s){size_t n=strlen(s);void sink(char*d,char*s,size_t n);}'), [])

    def test_standard_namespace_size_apis_are_included(self):
        found = self.local('void f(char*d,char*s,size_t n){std::memcpy(d,s,n);}')
        self.assertEqual(found[0]['sink']['size_expression'], 'n')

    def test_other_namespace_is_not_assumed_to_be_standard_api(self):
        self.assertEqual(self.local('void f(char*d,char*s,size_t n){custom::memcpy(d,s,n);}'), [])

    def test_compound_assignment_and_shadowing_invalidate_origin(self):
        for change in ('n%=8;', 'n<<=1;', '{int n;'):
            suffix = '}' if change.startswith('{') else ''
            with self.subTest(change=change):
                self.assertEqual(self.cross('void sink(char*d,char*s,size_t n){memcpy(d,s,n);}\n'
                    'void caller(char*d,char*s){size_t n=strlen(s);' + change + 'sink(d,s,n);' + suffix + '}'), [])

    def test_labelled_calls_are_not_prototypes(self):
        for prefix in ('label:', 'switch(n){case 1:', 'switch(n){default:'):
            suffix = '}' if prefix.startswith('switch') else ''
            result = self.local('void f(char*d,char*s,int n){' + prefix + 'memcpy(d,s,n);' + suffix + '}')
            self.assertEqual(len(result), 1)

    def test_conditional_size_argument_is_explicitly_unresolved(self):
        self.put('void f(char*d,char*s,int n){memcpy(d,s,(n<8?n:8));}')
        result = rules.scan_semantic_files(self.root, ['a.c'])
        self.assertEqual(result['analysis_coverage']['local_candidates'], 1)
        self.assertIn('sink_arguments_unresolved', [x['reason'] for x in result['analysis_issues']])

    def test_multiple_return_names_are_not_counted_as_multiple_vulnerabilities(self):
        self.put('void sink(char*d,char*s,size_t n){memcpy(d,s,n);}\n'
                 'void caller(char*d,char*s){size_t n=strlen(s);sink(d,s,n);}')
        result = rules.scan_semantic_files(self.root, ['a.c'])
        self.assertEqual(result['analysis_coverage']['local_candidates'], 1)
        self.assertEqual(result['analysis_coverage']['cross_function_candidates'], 1)
        self.assertTrue(all(x['status'] == 'candidate' for x in result['findings']))


if __name__ == '__main__':
    unittest.main()
