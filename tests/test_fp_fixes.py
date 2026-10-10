"""Regressions for the 2026-10-11 dsoftbus FP audit fixes.

Three fixes pinned here:
  1. guard-macro suppression recognizes prefixed families (AUTH_/TRANS_/
     NASKX_CHECK_*) and condition forms (var != NULL), plus RETURN_IF*
     — 229 P6 leads on dsoftbus were explainable by these shapes;
  2. finding_id carries the triggering variable (501 collided rows were
     distinct observations sharing a location id);
  3. run() deduplicates same-id findings and fills source snippets for
     every finding (P6/P8 previously shipped empty snippets).
"""
import json
import tempfile
import time
import unittest
from pathlib import Path

from ohvul.autopilot import run, scan_p6

UNGUARDED = """
int widget_sum(Widget *wid) {
    return wid->a + wid->b + wid->c;
}
"""

PREFIXED_CONDITION = """
int print_info(ConnInfo *info) {
    AUTH_CHECK_AND_RETURN_LOGE(info != NULL, AUTH_FSM, "info is null");
    return info->a + info->b + info->c;
}
"""

PREFIXED_BARE = """
int handle_msg(Msg *msg) {
    TRANS_CHECK_AND_RETURN_RET(msg, 0);
    return msg->a + msg->b + msg->c;
}
"""

RETURN_FORM = """
int apply_node(Node *node) {
    RETURN_IF_NOT_NULL(node);
    return node->a + node->b + node->c;
}
"""

MACRO_ON_OTHER_VAR = """
int sum_two(ConnInfo *info, Other *other) {
    AUTH_CHECK_AND_RETURN_LOGE(other != NULL, AUTH_FSM, "other");
    return info->a + info->b + info->c;
}
"""


def _tree(root: Path, files: dict):
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _p6_ids(files: dict):
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _tree(root, files)
        return [f.finding_id for f in scan_p6(root)]


class GuardMacroSuppressionTests(unittest.TestCase):
    def test_prefixed_condition_form_is_suppressed(self):
        ids = _p6_ids({"a.c": "typedef struct { int a, b, c; } ConnInfo;\n"
                            + PREFIXED_CONDITION})
        self.assertEqual(ids, [])

    def test_prefixed_bare_form_is_suppressed(self):
        ids = _p6_ids({"a.c": "typedef struct { int a, b, c; } Msg;\n"
                            + PREFIXED_BARE})
        self.assertEqual(ids, [])

    def test_return_macro_form_is_suppressed(self):
        ids = _p6_ids({"a.c": "typedef struct { int a, b, c; } Node;\n"
                            + RETURN_FORM})
        self.assertEqual(ids, [])

    def test_macro_referencing_another_var_does_not_suppress(self):
        ids = _p6_ids({"a.c": "typedef struct { int a, b, c; } ConnInfo;\n"
                              "typedef struct { int x; } Other;\n"
                            + MACRO_ON_OTHER_VAR})
        self.assertEqual(len(ids), 1)
        self.assertIn("info", ids[0])

    def test_condition_macro_without_return_polarity_not_suppressed(self):
        # PR #95 semantics preserved: CHECK_INVOKE(param != nullptr) acts
        # when NON-null — extending the guard must not swallow this.
        code = ("typedef struct { int a, b, c; } BtParam;\n"
                "void f(const BtParam *param) {\n"
                "    AUTH_CHECK_INVOKE(param != nullptr);\n"
                "    int a = param->a; int b = param->b; int c = param->c;\n"
                "}\n")
        ids = _p6_ids({"a.c": code})
        self.assertEqual(len(ids), 1)

    def test_unguarded_still_reported_with_var_in_id(self):
        ids = _p6_ids({"a.c": "typedef struct { int a, b, c; } Widget;\n"
                            + UNGUARDED})
        self.assertEqual(len(ids), 1)
        self.assertIn("_wid", ids[0])


class FindingIdAndSnippetTests(unittest.TestCase):
    def test_two_vars_one_location_get_distinct_ids_and_snippets(self):
        fixture = (
            "typedef struct { int a, b, c; } A;\n"
            "typedef struct { int x, y, z; } B;\n"
            "int both(A *one, B *two) {\n"
            "    return one->a + one->b + one->c + two->x + two->y + two->z;\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _tree(root, {"a.c": fixture})
            report = run(root, root / "out")
        p6 = [f for f in report["findings"] if f["pattern"] == "P6_null_deref"]
        self.assertEqual(len(p6), 2)
        self.assertEqual(len({f["finding_id"] for f in p6}), 2)
        for f in p6:
            self.assertTrue(f["source_snippet"], f["finding_id"])
            self.assertIn("both", f["source_snippet"])

    def test_duplicate_ids_are_collapsed(self):
        fixture = (
            "#include <stdlib.h>\n"
            "int use_after(int n) {\n"
            "    char *p = (char *)malloc(8);\n"
            "    if (n == 1) { free(p); return 0; }\n"
            "    p[0] = 1; p[1] = 2; p[2] = 3;\n"
            "    free(p);\n"
            "    return p[0] + p[1] + p[2];\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _tree(root, {"a.c": fixture})
            report = run(root, root / "out")
        ids = [f["finding_id"] for f in report["findings"]]
        self.assertEqual(len(ids), len(set(ids)))
        for f in report["findings"]:
            self.assertTrue(f["source_snippet"], f["finding_id"])


if __name__ == "__main__":
    unittest.main()
