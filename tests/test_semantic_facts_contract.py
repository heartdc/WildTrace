"""Regression tests for bounded lexical ownership, never a data-flow proof."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ohvul.semantic_facts import extract_facts, extract_tree


class SemanticContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / 'a.c'

    def facts(self, text):
        self.file.write_text(text, encoding='utf-8')
        return extract_facts(self.file, root=self.root)

    def test_multiline_definition_has_owner(self):
        facts = self.facts('int\nrun(int *p)\n{\n free(p);\n return 0;\n}\n')
        self.assertEqual([f.function for f in facts if f.kind == 'release'], ['run'])

    def test_function_ownership_ends_at_matching_brace(self):
        facts = self.facts('void one() { free(p); }\nvoid *global = malloc(4);\n')
        self.assertEqual([f.function for f in facts if f.kind == 'allocation'], [None])

    def test_control_block_does_not_rename_function(self):
        facts = self.facts('void one(int x) {\n if (x) {\n free(p);\n }\n}\n')
        self.assertEqual([f.function for f in facts if f.kind == 'release'], ['one'])
        self.assertEqual([f.symbol for f in facts if f.kind == 'function'], ['one'])

    def test_comments_strings_and_macro_definitions_are_not_executed_facts(self):
        facts = self.facts('/* malloc(8); free(p); */\n#define COPY(x) \\\n strcpy(x,y)\nvoid f() { const char *s="free(p); malloc(9)"; }\n')
        self.assertFalse([f for f in facts if f.kind in ('allocation', 'release', 'copy')])

    def test_definition_is_not_a_call(self):
        facts = self.facts('void one() { one(); }\n')
        self.assertEqual(len([f for f in facts if f.kind == 'call' and f.symbol == 'one']), 1)

    def test_same_line_functions_have_distinct_owners(self):
        facts = self.facts('void a(){ free(x); } void b(){ free(y); }\n')
        self.assertEqual([f.function for f in facts if f.kind == 'release'], ['a', 'b'])

    def test_invalid_utf8_is_not_replacement_decoded(self):
        self.file.write_bytes(b'void f(){free(p);}\xff')
        with self.assertRaises(ValueError):
            extract_facts(self.file, root=self.root)

    def test_duplicate_absolute_and_empty_scope_rejected_before_reads(self):
        self.file.write_text('void f(){}')
        for values in ([], 'a.c', ['a.c', './a.c'], [str(self.file.resolve())]):
            with self.subTest(values=values), patch('ohvul.semantic_facts.extract_facts') as read:
                with self.assertRaises(ValueError):
                    extract_tree(self.root, values)
                read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
