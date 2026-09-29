import tempfile
import unittest
from pathlib import Path

from ohvul.cross_uaf import build_facts, scan_cross_uaf


def _make_source(root: Path):
    d = root / "src"
    d.mkdir(parents=True)
    # Pattern A: caller frees ptr, then passes to callee that derefs
    # Note: callee param name is 'p' (different from caller's 'ptr') to test positional resolution
    (d / "pattern_a.c").write_text(
        "#include <stdlib.h>\n"
        "void helper(int *p) { p[0] = 1; }\n"
        "void caller_a(int *ptr) {\n"
        "    free(ptr);\n"
        "    helper(ptr);\n"
        "}\n", encoding="utf-8")
    # Pattern B: callee frees param, caller uses after
    (d / "pattern_b.c").write_text(
        "#include <stdlib.h>\n"
        "void destroy(int *p) { free(p); }\n"
        "void caller_b(int *ptr) {\n"
        "    destroy(ptr);\n"
        "    ptr[0] = 1;\n"
        "}\n", encoding="utf-8")
    # Pattern C: double free (caller and callee both free)
    (d / "pattern_c.c").write_text(
        "#include <stdlib.h>\n"
        "void cleanup(int *p) { free(p); }\n"
        "void caller_c(int *ptr) {\n"
        "    cleanup(ptr);\n"
        "    free(ptr);\n"
        "}\n", encoding="utf-8")
    # Safe: pass before free (no UAF)
    (d / "safe.c").write_text(
        "#include <stdlib.h>\n"
        "void helper(int *p) { p[0] = 1; }\n"
        "void safe_caller(int *ptr) {\n"
        "    helper(ptr);\n"
        "    free(ptr);\n"
        "}\n", encoding="utf-8")


class CrossUafTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        _make_source(self.root)
        self.facts = build_facts(self.root)
        self.findings = scan_cross_uaf(self.root, self.facts)

    def tearDown(self):
        self.tmp.cleanup()

    def test_facts_built(self):
        self.assertIn('helper', self.facts)
        self.assertIn('destroy', self.facts)
        self.assertIn('caller_a', self.facts)
        self.assertIn('caller_b', self.facts)

    def test_positional_alias_resolution(self):
        """Helper takes 'p', caller passes 'ptr' — positional mapping works."""
        cf = self.facts['caller_a']
        # caller_a passes ptr to helper
        helper_passes = [p for p in cf.passes if p['callee'] == 'helper']
        self.assertTrue(helper_passes, "caller_a should pass to helper")
        # helper's param at position 0 is 'p'
        hf = self.facts['helper']
        self.assertEqual(hf.param_list[0], 'p')
        self.assertIn('p', hf.deref)

    def test_pattern_a_detected(self):
        """Free→Pass: caller_a frees ptr then passes to helper which derefs."""
        a_findings = [f for f in self.findings if f.function == 'caller_a']
        self.assertTrue(a_findings, f"Pattern A not detected for caller_a")

    def test_pattern_b_detected(self):
        """Callee-Frees: destroy frees, caller_b uses after."""
        b_findings = [f for f in self.findings if f.function == 'caller_b']
        self.assertTrue(b_findings, f"Pattern B not detected for caller_b")

    def test_pattern_c_detected(self):
        """Double-Free: cleanup and caller_c both free."""
        c_findings = [f for f in self.findings if f.function == 'caller_c'
                      and f.pattern == 'P8_double_free']
        self.assertTrue(c_findings, f"Pattern C not detected for caller_c")

    def test_safe_not_flagged(self):
        """Safe case (pass before free) is not flagged."""
        safe = [f for f in self.findings if f.function == 'safe_caller']
        self.assertFalse(safe, f"Safe case incorrectly flagged: {[f.description for f in safe]}")

    def test_finding_metadata(self):
        for f in self.findings:
            self.assertIn(f.cwe, ("CWE-416", "CWE-415"))
            self.assertTrue(f.reachability)
            self.assertGreaterEqual(f.confidence, 0)
            self.assertLessEqual(f.confidence, 100)


if __name__ == "__main__":
    unittest.main()
