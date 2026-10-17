"""P6 detection contract: semantics that must survive renaming and count,
and protection that must actually protect (mentor review 2026-10, Gap A).

Rows map to the mentor's suggested table (提升_doc §五), plus two
branch-sensitivity contracts for the `!= NULL` positive form:

  nullable param, one unprotected access     -> candidate
  same code, parameter renamed to p          -> candidate (renaming is noise)
  check only AFTER the access                -> candidate (late check ≠ guard)
  null-check that only logs                  -> candidate (log ≠ abort)
  null-check followed by return              -> NO candidate
  correct early return, braced               -> NO candidate (braces are noise)
  reassign nullable value after check        -> candidate (fact invalidated)
  access inside `if (p != NULL)` block       -> NO candidate (true-branch fact)
  access after that block, unchecked         -> candidate

"应产生候选" is a statement about candidate GENERATION, not proof of a real
product bug; ranking stays free to sort these below multi-deref findings.
"""
import tempfile
import unittest
from pathlib import Path

from ohvul.autopilot import scan_p6


def _finds(root: Path, function: str, var: str) -> list:
    return [f for f in scan_p6(root)
            if f.pattern == "P6_null_deref" and f.function == function
            and f.struct_type == var]


class P6DetectionContractTests(unittest.TestCase):
    """Test约定：参数可以为空；非空时指向有效 Node。只讨论空值。"""

    def detect(self, parameter: str, body: str) -> list:
        """Write the sample and scan it while the tempdir still exists."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sample.c").write_text(
                "typedef struct Node { int a, b, c; } Node;\n"
                "void note_null(void);\n"
                f"void use(Node *{parameter}) {{\n{body}\n}}\n",
                encoding="utf-8")
            return _finds(root, "use", parameter)

    def test_single_unprotected_access_is_a_candidate(self):
        found = self.detect("node", "    node->a = 1;")
        self.assertTrue(found,
                        "one unprotected deref of a nullable param must "
                        "generate a candidate (count belongs to ranking)")

    def test_renaming_to_single_char_keeps_candidate(self):
        found = self.detect("p", "    p->a = 1;\n    p->b = 2;")
        self.assertTrue(found,
                        "consistent local renaming must not lose the candidate")

    def test_check_after_access_still_candidates(self):
        found = self.detect("node", "    node->a = 1;\n"
                                    "    if (!node) return;")
        self.assertTrue(found,
                        "a later check cannot protect the earlier access")

    def test_log_only_check_still_candidates(self):
        found = self.detect("node", "    if (!node) { note_null(); }\n"
                                    "    node->a = 1;")
        self.assertTrue(found,
                        "a check that only logs does not abort the null path")

    def test_return_guard_suppresses(self):
        self.assertEqual(self.detect(
            "node", "    if (!node) return;\n    node->a = 1;"), [])

    def test_braced_return_guard_suppresses(self):
        self.assertEqual(self.detect(
            "node", "    if (!node) {\n        return;\n    }\n"
                    "    node->a = 1;"), [])

    def test_access_inside_positive_block_is_protected(self):
        self.assertEqual(self.detect(
            "node", "    if (node != NULL) {\n        node->a = 1;\n    }"), [],
            "access on the true branch of != NULL is protected")

    def test_access_after_positive_block_is_not(self):
        found = self.detect("node", "    if (node != NULL) {\n"
                                    "        note_null();\n"
                                    "    }\n"
                                    "    node->a = 1;")
        self.assertTrue(found, "the fact does not survive the block")

    def test_reassignment_after_check_invalidates_guard(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sample.c").write_text(
                "typedef struct Node { int a; } Node;\n"
                "Node *find_node(int id);\n"
                "void use(Node *node) {\n"
                "    if (!node) return;\n"
                "    node = find_node(2);\n"
                "    node->a = 1;\n"
                "}\n", encoding="utf-8")
            self.assertTrue(_finds(root, "use", "node"),
                            "non-null fact is invalidated by reassignment")


if __name__ == "__main__":
    unittest.main()
