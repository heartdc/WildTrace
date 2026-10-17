"""Paired true/false baselines for the P8 same-function UAF heuristic.

Locks the two documented false-positive shapes (works report 不足#2):
branch-exclusive free (escape-terminated / else-sibling) and callback
closure use — while keeping every true-positive shape firing.
"""
import tempfile
import unittest
from pathlib import Path

from ohvul.autopilot import scan_p8


def _ids(findings, var):
    return [f.finding_id for f in findings if f.struct_type == var]


class P8BranchSensitivityTests(unittest.TestCase):

    def _scan(self, sources):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in sources.items():
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            suppressed = []
            findings = scan_p8(root, _suppressed=suppressed)
            return findings, suppressed

    def test_plain_uaf_still_fires(self):
        findings, _ = self._scan({
            "a.c": "void f(int *p) {\n    free(p);\n    p[0] = 1;\n}\n"})
        self.assertTrue(_ids(findings, "p"), "plain free-then-use must fire")

    def test_free_in_nonescaping_branch_still_fires(self):
        findings, _ = self._scan({
            "a.c": ("int f(int err, int *p) {\n"
                    "    if (err) { free(p); }\n"
                    "    p[0] = 1;\n    return 0;\n}\n")})
        self.assertTrue(_ids(findings, "p"),
                        "free without return falls through to the use — live UAF")

    def test_use_before_branch_return_still_fires(self):
        findings, _ = self._scan({
            "a.c": ("int f(int err, int *p) {\n"
                    "    if (err) { free(p); p[0] = 1; return -1; }\n"
                    "    return 0;\n}\n")})
        self.assertTrue(_ids(findings, "p"),
                        "use between the free and the return is on the free path")

    def test_escape_terminated_free_branch_suppressed(self):
        findings, suppressed = self._scan({
            "a.c": ("int f(int err, int *p) {\n"
                    "    if (err != 0) { free(p); return -1; }\n"
                    "    p[0] = 1;\n    return 0;\n}\n")})
        self.assertFalse(_ids(findings, "p"),
                         "error-branch free + return cannot reach the later use")
        self.assertTrue(any("escape-terminated" in s["reason"] for s in suppressed))

    def test_else_sibling_use_suppressed(self):
        findings, suppressed = self._scan({
            "a.c": ("void f(int a, int *p) {\n"
                    "    if (a) { free(p); }\n"
                    "    else { p[0] = 1; }\n}\n")})
        self.assertFalse(_ids(findings, "p"),
                         "the else arm never runs on the free path")
        self.assertTrue(any("else-sibling" in s["reason"] for s in suppressed))

    def test_closure_use_suppressed_with_reason(self):
        findings, suppressed = self._scan({
            "a.cpp": ("struct S { int len; };\n"
                      "void f(S *s) {\n"
                      "    free(s);\n"
                      "    queue.Push([s]() { return s->len; });\n}\n")})
        self.assertFalse(_ids(findings, "s"),
                         "use inside a lambda body is a registered-lifetime lead, "
                         "not a same-execution UAF")
        self.assertTrue(any("closure" in s["reason"] for s in suppressed))

    def test_free_inside_closure_use_inside_still_fires(self):
        findings, _ = self._scan({
            "a.cpp": ("struct S { int len; };\n"
                      "void f(S *s) {\n"
                      "    queue.Push([s]() { free(s); return s->len; });\n}\n")})
        self.assertTrue(_ids(findings, "s"),
                        "free and use inside the same closure body is a live UAF")

    def test_suppression_log_carries_location(self):
        _, suppressed = self._scan({
            "a.c": ("int f(int err, int *p) {\n"
                    "    if (err != 0) { free(p); return -1; }\n"
                    "    p[0] = 1;\n    return 0;\n}\n")})
        self.assertTrue(suppressed)
        entry = suppressed[0]
        self.assertEqual(entry["file"], "a.c")
        self.assertEqual(entry["function"], "f")
        self.assertEqual(entry["var"], "p")
        self.assertIn("reason", entry)


if __name__ == "__main__":
    unittest.main()
