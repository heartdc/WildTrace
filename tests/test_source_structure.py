"""Pure text navigation; no compiler, source execution or external input."""
import unittest
from unittest.mock import patch
from ohvul.source_structure import source_structure, function_at


class SourceStructureTests(unittest.TestCase):
    def test_balanced_nested_control_keeps_original_function(self):
        text = 'int f(int x) { if (x) { call(); } return 0; }\nint y;'
        result = source_structure(text)
        self.assertEqual([f['symbol'] for f in result['functions']], ['f'])
        self.assertEqual(function_at(result, text.index('call')), 'f')
        self.assertIsNone(function_at(result, text.index('int y')))

    def test_multiline_and_same_line_functions(self):
        value = source_structure('int\nf(int x)\n{ return x; } int g(){ f(0); }')
        self.assertEqual([f['symbol'] for f in value['functions']], ['f', 'g'])
        self.assertEqual(value['functions'][0]['start_line'], 1)
        self.assertEqual(value['functions'][0]['name_line'], 2)
        self.assertEqual([(c['symbol'], c['function']) for c in value['calls']], [('f', 'g')])

    def test_literal_braces_and_fake_functions_do_not_change_ranges(self):
        text = '/* int fake(){ */ int f(){ const char *x=R"tag( } fake() { )tag"; go(); }'
        value = source_structure(text)
        self.assertEqual([f['symbol'] for f in value['functions']], ['f'])
        self.assertEqual([c['symbol'] for c in value['calls']], ['go'])
        self.assertEqual(value['issues'], [])

    def test_macro_braces_are_not_function_body_delimiters(self):
        text = '#define DO(x) do { \\\n use(x); \\\n } while(0)\nvoid f(){ DO(p); }'
        value = source_structure(text)
        self.assertEqual(value['macros'][0]['end_line'], 3)
        self.assertEqual([f['symbol'] for f in value['functions']], ['f'])
        self.assertEqual([c['symbol'] for c in value['calls']], ['DO'])

    def test_conditional_definitions_are_both_retained(self):
        result = source_structure('#if WIN\n#define CHECK(x) ((x)>0)\n#else\n#define CHECK(x) ((x)<10)\n#endif\n')
        self.assertEqual([m['symbol'] for m in result['macros']], ['CHECK', 'CHECK'])
        self.assertTrue(result['has_preprocessor'])

    def test_unclosed_function_is_not_repaired(self):
        value = source_structure('void f(){ call();\n')
        self.assertEqual(value['functions'], [])
        self.assertIn('unmatched_delimiter', value['issues'])

    def test_lambda_and_bare_macro_block_not_claimed_as_function(self):
        value = source_structure('auto callback = [](){ call(); };\nBLOCK(x){ call(); }')
        self.assertEqual(value['functions'], [])

    def test_namespace_and_const_method(self):
        value = source_structure('namespace N { int A::f() const { return 0; } }')
        self.assertEqual([f['symbol'] for f in value['functions']], ['A::f'])

    def test_bounds_checked_before_unbounded_token_collection(self):
        with patch('ohvul.source_structure.MAX_SOURCE_BYTES', 10):
            with self.assertRaises(ValueError):
                source_structure('int f(){return 0;}')
        with patch('ohvul.source_structure.MAX_TOKENS', 2):
            with self.assertRaises(ValueError):
                source_structure('int f(){return 0;}')

    def test_empty_source(self):
        value = source_structure('')
        self.assertEqual(value['functions'], [])
        self.assertEqual(value['calls'], [])

    def test_unbalanced_branch_does_not_create_confident_ownership(self):
        value = source_structure('void f(){\n#if A\n{\n#else\n{\n#endif\n call();\n}}')
        self.assertTrue(value['issues'])
        self.assertEqual(value['functions'], [])
        self.assertTrue(all(c['function'] is None for c in value['calls']))


if __name__ == '__main__':
    unittest.main()
