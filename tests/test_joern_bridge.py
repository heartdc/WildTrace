import json
import unittest
from pathlib import Path

from ohvul.joern_bridge import JoernAnalyzer, JoernFinding


class JoernBridgeTests(unittest.TestCase):
    """Tests for the Joern CPG bridge."""

    def test_finding_dataclass(self):
        f = JoernFinding("J4", "test.c", 10, "func", "detail", 75)
        self.assertEqual(f.pattern, "J4")
        self.assertEqual(f.confidence, 75)

    def test_queries_defined(self):
        from ohvul.joern_bridge import JOERN_QUERIES
        self.assertIn("J4_unbounded_copy", JOERN_QUERIES)
        self.assertIn("J6_null_deref", JOERN_QUERIES)
        self.assertIn("J8_use_after_free", JOERN_QUERIES)
        for name, script in JOERN_QUERIES.items():
            self.assertIn("importCpg", script)
            self.assertIn("__CPG__", script)

    def test_availability_check(self):
        analyzer = JoernAnalyzer("/tmp")
        # Just check it doesn't crash
        result = analyzer.is_available()
        self.assertIsInstance(result, bool)

    def test_cpg_path_conversion(self):
        analyzer = JoernAnalyzer("D:/test/path")
        wsl = analyzer._to_wsl("D:\\test\\path")
        self.assertEqual(wsl, "/mnt/d/test/path")
        wsl2 = analyzer._to_wsl("/home/user/project")
        self.assertEqual(wsl2, "/home/user/project")


if __name__ == "__main__":
    unittest.main()
