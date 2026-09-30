import tempfile
import unittest
from pathlib import Path

from ohvul.semantic_facts import extract_facts, extract_tree


class SemanticFactsTests(unittest.TestCase):
    def test_extracts_function_calls_and_memory_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'sample.cpp'
            source.write_text('''void run(char *p) {\n  char *q = (char*)malloc(8);\n  strcpy(q, p);\n  free(q);\n  p->field = 1;\n}\n''')
            facts = extract_facts(source, root=root)
            kinds = [item.kind for item in facts]
            self.assertIn('function', kinds)
            self.assertIn('allocation', kinds)
            self.assertIn('copy', kinds)
            self.assertIn('release', kinds)
            self.assertIn('dereference', kinds)
            self.assertTrue(any(item.symbol == 'strcpy' for item in facts))

    def test_explicit_tree_rejects_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('void f() {}')
            with self.assertRaises(ValueError):
                extract_tree(root, ['../outside.c'])


if __name__ == '__main__':
    unittest.main()
