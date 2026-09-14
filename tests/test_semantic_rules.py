import tempfile
import unittest
from pathlib import Path

from ohvul.semantic_rules import length_candidates


class SemanticRuleTests(unittest.TestCase):
    def test_length_candidate_keeps_source_sink_and_guard_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'sample.cpp'
            source.write_text('''void copy(char *dst, const char *src, size_t n) {\n  size_t len = strlen(src);\n  if (len < 64) {\n    memcpy(dst, src, n);\n  }\n}\n''')
            candidates = length_candidates(source, root=root)
            self.assertEqual(len(candidates), 1)
            item = candidates[0]
            self.assertEqual(item['status'], 'candidate')
            self.assertEqual(item['sink']['kind'], 'memcpy')
            self.assertEqual(item['source_lines'], [2])
            self.assertEqual(item['guard_lines'], [3])
            self.assertEqual(len(item['evidence']), 3)

    def test_non_copy_function_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'a.c'
            path.write_text('void f(char *p) { strlen(p); }')
            self.assertEqual(length_candidates(path, root=path.parent), [])


if __name__ == '__main__':
    unittest.main()
