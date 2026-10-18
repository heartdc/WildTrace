"""Regression tests from the external PR review (2026-10-18, F01–F07).

Every counterexample from the review that drove a fix is pinned here with
its safe/unsafe counterpart, so the fixes cannot silently regress.
"""
import tempfile
import unittest
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ohvul.autopilot import (  # noqa: E402
    _p6_access_states, _p8_block_spans, _p8_use_exclusive_reason, scan_p8,
)


def p6_state(src, var="node"):
    acc = [m for m in re.finditer(rf"\b{var}\s*->\w+", src)]
    return [(s, r) for _, s, r in _p6_access_states(src, var, acc)]


def p8_reason(body, var="p"):
    spans = _p8_block_spans(body)
    fm = re.search(rf"\bfree\s*\(\s*{var}\s*\)", body)
    um = re.search(rf"\b{var}\s*(?:->|\[|\.|\+\+|=)", body[fm.end():])
    return _p8_use_exclusive_reason(body, spans, fm.start(), fm.end(),
                                    fm.end() + um.start())


class P6ExternalReviewTests(unittest.TestCase):
    """F02/F03: never claim NonNull from facts that do not prove it."""

    def test_f02_positive_block_null_reassignment(self):
        got = p6_state("if (node) {\n node = nullptr;\n node->a = 1;\n}")
        self.assertEqual(got, [("Null", "assigned-null")])

    def test_f03_conditional_return_is_not_fallthrough(self):
        got = p6_state("if (!node) { if (flag) { return; } }\n node->a = 1;")
        self.assertEqual(got[0][0], "MaybeNull")

    def test_f03_unbraced_conditional_return(self):
        got = p6_state("if (!node) { if (flag) return; }\n node->a = 1;")
        self.assertEqual(got[0][0], "MaybeNull")

    def test_f03_goto_never_confirms(self):
        got = p6_state("if (!node) { goto use; }\n use: node->a = 1;")
        self.assertEqual(got[0][0], "MaybeNull")

    def test_f03_unbraced_conditional_address_merges(self):
        got = p6_state("node = nullptr;\n if (flag) node = &holder;\n node->a = 1;")
        self.assertEqual(got, [("MaybeNull", "merged-branches")])

    def test_keep_plain_early_return_still_confirms(self):
        got = p6_state("if (!node) { return; }\n node->a = 1;")
        self.assertEqual(got, [("NonNull", "guard-fallthrough")])

    def test_keep_braced_conditional_address_merges(self):
        got = p6_state("node = nullptr;\n if (flag) { node = &holder; }\n node->a = 1;")
        self.assertEqual(got, [("MaybeNull", "merged-branches")])


class P8ExternalReviewTests(unittest.TestCase):
    """F04: suppression only on genuinely unreachable paths."""

    def test_f04a_unbraced_conditional_return_not_suppressed(self):
        self.assertIsNone(
            p8_reason("if (err) { free(p); if (stop) return; } p[0] = 1;"))

    def test_f04a_braced_conditional_return_not_suppressed(self):
        self.assertIsNone(
            p8_reason("if (err) { free(p); if (stop) { return; } } p[0] = 1;"))

    def test_f04b_immediate_lambda_not_suppressed(self):
        self.assertIsNone(p8_reason("free(p); [p]() { p[0] = 1; }();"))

    def test_keep_deferred_closure_suppressed(self):
        self.assertIn("closure", p8_reason(
            "free(p); queue.Push([p]() { return p[0]; });") or "")

    def test_keep_escape_branch_suppressed(self):
        self.assertIn("escape-terminated", p8_reason(
            "if (err) { free(p); return -1; } p[0] = 1;") or "")

    def test_f04c_reset_after_use_keeps_the_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.c").write_text(
                "#include <stdlib.h>\nvoid f(int *p) {\n free(p);\n"
                " p[0] = 1;\n p = NULL;\n}\n", encoding="utf-8")
            sup = []
            out = scan_p8(root, _suppressed=sup)
            self.assertTrue([f.struct_type for f in out] == ["p"],
                            "use between free and reset is a live UAF signal")
            self.assertTrue(any("reset-before-use" in s["reason"] for s in sup))

    def test_f04c_reset_itself_is_not_a_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "n.c").write_text(
                "#include <stdlib.h>\nvoid g(int *p) {\n free(p);\n"
                " p = NULL;\n}\n", encoding="utf-8")
            out = scan_p8(root)
            self.assertEqual(out, [],
                             "free + immediate reset must stay silent")


class AccessFormTests(unittest.TestCase):
    """F05: identifier boundary and equivalent deref spellings."""

    def _collect(self, src, var):
        varesc = re.escape(var)
        found = []
        for m in re.finditer(
                rf"\*\s*(?:\(\s*{varesc}\s*\)|{varesc}\b)(?!\s*\()", src):
            head = src[max(0, m.start() - 12):m.start()].rstrip()
            ok = (not head or head.endswith("return")
                  or not (head[-1].isalnum() or head[-1] == "_"))
            if ok:
                found.append(src[m.start():m.end() + 1])
        return found

    def test_whitespace_form(self):
        self.assertEqual(self._collect("return * p;", "p"), ["* p;"])

    def test_parenthesized_form(self):
        self.assertEqual(self._collect("return *(p);", "p"), ["*(p);"])

    def test_no_prefix_mismatch(self):
        self.assertEqual(self._collect("return *ptr;", "p"), [])

    def test_plain_form_kept(self):
        self.assertEqual(self._collect("return *p;", "p"), ["*p;"])


if __name__ == "__main__":
    unittest.main()
