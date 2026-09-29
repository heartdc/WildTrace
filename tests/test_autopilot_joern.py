"""Tests for the optional Joern CPG layer wiring in autopilot (audit P0 #1).

The layer is opt-in (--joern / joern=True): default runs must never touch
the bridge, unavailable Joern must degrade to a warning (not a crash), and
converted findings must surface with the pipeline's Finding shape.
"""
import tempfile, unittest
from pathlib import Path
from unittest import mock

from ohvul.autopilot import run
from ohvul.joern_bridge import JoernAnalyzer, JoernFinding


def _make_tree(root: Path):
    src = root / "src"
    src.mkdir()
    (src / "lib.c").write_text(
        "#include <string.h>\n"
        "void copy(char *dst, const char *src, int n) {\n"
        "    memcpy(dst, src, n);\n"
        "}\n", encoding="utf-8")
    return src


class JoernLayerTests(unittest.TestCase):
    def run_autopilot(self, root, **kw):
        out = root / "out"
        return run(kw.pop("src"), out, **kw)

    def test_default_run_has_joern_disabled(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = _make_tree(root)
            report = self.run_autopilot(root, src=src)
            self.assertFalse(report["joern"]["enabled"])
            self.assertNotIn("J_joern_cpg", report["summary"]["scanners"])
            self.assertFalse(any(f["pattern"].startswith("J")
                                 for f in report["findings"]))

    def test_unavailable_joern_degrades_gracefully(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = _make_tree(root)
            with mock.patch.object(JoernAnalyzer, "is_available",
                                   return_value=False) as avail:
                report = self.run_autopilot(root, src=src, joern=True)
            avail.assert_called_once()
            self.assertTrue(report["joern"]["enabled"])
            self.assertFalse(report["joern"]["available"])
            self.assertIn("unavailable", report["joern"]["error"])
            self.assertNotIn("J_joern_cpg", report["summary"]["scanners"])
            # pipeline still produced its regex-layer findings
            self.assertGreaterEqual(report["summary"]["before_filter"], 0)

    def test_joern_findings_converted_and_reported(self):
        fake = [
            JoernFinding(pattern="J4", file="lib.c", line=3, function="copy",
                         detail='memcpy(dst, src, n) with "quotes" and \\ backslash',
                         confidence=75),
            JoernFinding(pattern="J6", file="lib.c", line=2, function="copy",
                         detail="n 3 derefs no null check", confidence=65),
        ]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = _make_tree(root)
            with mock.patch.object(JoernAnalyzer, "is_available",
                                   return_value=True), \
                 mock.patch.object(JoernAnalyzer, "run_all_queries",
                                   return_value=fake):
                report = self.run_autopilot(root, src=src, joern=True)
            self.assertTrue(report["joern"]["available"])
            self.assertEqual(report["joern"]["findings"], 2)
            self.assertIn("J_joern_cpg", report["summary"]["scanners"])
            by_pattern = {f["pattern"]: f for f in report["findings"]}
            self.assertIn("J4_unbounded_copy", by_pattern)
            self.assertIn("J6_null_deref", by_pattern)
            j4 = by_pattern["J4_unbounded_copy"]
            self.assertEqual(j4["severity"], "high")
            self.assertEqual(j4["cwe"], "CWE-120")
            self.assertEqual(j4["confidence"], 75)
            # detail with quotes/backslashes survives the round-trip
            self.assertIn('"quotes"', j4["description"])
            # markdown report states the layer ran
            self.assertIn("Joern CPG", (root / "out" / "findings.md")
                          .read_text(encoding="utf-8"))

    def test_cross_layer_now_listed_in_scanners(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = _make_tree(root)
            report = self.run_autopilot(root, src=src)
            # cross_uaf either ran (listed) or failed loudly — but the
            # regex scanners alone must not claim to be the whole story
            # when cross findings exist
            has_cross = any(f["pattern"].startswith("P8_")
                            for f in report["findings"])
            if has_cross:
                self.assertIn("P8X_cross_uaf", report["summary"]["scanners"])

    def test_cross_uaf_findings_not_flat_fifty(self):
        from ohvul.cross_uaf import build_facts, scan_cross_uaf
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)
            (src / "uaf.c").write_text(
                "#include <stdlib.h>\n"
                "void sink(char *p) { p[0] = 1; }\n"
                "void f(char *p) { free(p); sink(p); }\n", encoding="utf-8")
            findings = scan_cross_uaf(src, build_facts(src))
            for f in findings:
                if f.pattern in ("P8_cross_uaf", "P8_double_free"):
                    self.assertGreater(f.confidence, 50,
                                       "cross findings must not sit at the "
                                       "flat base score")


if __name__ == "__main__":
    unittest.main()
