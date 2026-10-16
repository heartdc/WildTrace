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


class P6StateModelTests(unittest.TestCase):
    """Step-4 contracts: Null/NonNull/MaybeNull with explicit reasons.

    NonNull means non-null only, never alive-or-valid; malloc results stay
    MaybeNull (allocation can return NULL). Unknown forms stay MaybeNull
    with a reason — the tool never guesses safety.
    """

    def _state(self, parameter: str, body: str):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sample.c").write_text(
                "typedef struct Node { int a, b; } Node;\n"
                "Node *find_node(int id);\n"
                f"void use(Node *{parameter}) {{\n{body}\n}}\n",
                encoding="utf-8")
            found = _finds(root, "use", parameter)
            return (found[0] if found else None)

    def test_assigned_null_access_is_certain(self):
        f = self._state("node", "    node = NULL;\n    node->a = 1;")
        self.assertIsNotNone(f)
        self.assertIn("state=Null (assigned-null)", f.description)
        self.assertEqual(f.severity, "high")

    def test_address_of_assignment_is_non_null(self):
        f = self._state("node", "    struct { int a; } holder;\n"
                                "    node = &holder;\n    node->a = 1;")
        self.assertIsNone(f, "assigned &x is NonNull by construction")

    def test_nullable_source_guarded_then_accessed(self):
        f = self._state("node", "    node = find_node(1);\n"
                                "    if (!node) return;\n"
                                "    node->a = 1;")
        self.assertIsNone(f, "guard after a nullable source restores NonNull")

    def test_nullable_source_unguarded_labels_reason(self):
        f = self._state("node", "    node = find_node(1);\n    node->a = 1;")
        self.assertIsNotNone(f)
        self.assertIn("assigned-source-unknown", f.description)

    def test_plain_param_labels_no_contract(self):
        f = self._state("node", "    node->a = 1;")
        self.assertIsNotNone(f)
        self.assertIn("state=MaybeNull (param-no-contract)", f.description)

    def test_ffi_export_gets_provable_ranking(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sample.c").write_text(
                "typedef struct Node { int a; } Node;\n"
                "void FfiUseNode(Node *node) {\n"
                "    node->a = 1;\n"
                "}\n", encoding="utf-8")
            found = _finds(root, "FfiUseNode", "node")
            self.assertTrue(found)
            self.assertIn("+15 (FFI export: dlopen-provable entry)",
                          found[0].confidence_factors)


class P6LocalPointerTests(unittest.TestCase):
    """GT1 contracts (mentor step 6 first item): local pointer /
    smart-pointer declarations join the state timeline via their
    initializer — retro GT1's 'sptr<> proxy = GetRemoteProxy(...)' shape."""

    def _state(self, body: str, var: str = "proxy"):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sample.cpp").write_text(
                "struct IObs { void Fire(int x); };\n"
                "template <typename T> T *GetRemoteProxy(int id);\n"
                "int other(void);\n"
                f"void use() {{\n{body}\n}}\n",
                encoding="utf-8")
            found = _finds(root, "use", var)
            return (found[0] if found else None)

    def test_local_sptr_unguarded_is_candidate(self):
        f = self._state(
            "    sptr<IObs> proxy = GetRemoteProxy<IObs>(1);\n"
            "    proxy->Fire(2);")
        self.assertIsNotNone(f)
        self.assertIn("assigned-source-unknown", f.description)

    def test_local_sptr_macro_guarded_suppresses(self):
        # CHECK_AND_RETURN_LOG_RET form is a return-polarity guard
        f = self._state(
            "    #define CHECK_AND_RETURN_LOG_RET(c, r, ...) do { "
            "if (!(c)) return r; } while (0)\n"
            "    sptr<IObs> proxy = GetRemoteProxy<IObs>(1);\n"
            "    CHECK_AND_RETURN_LOG_RET(proxy != nullptr, -1, \"null\");\n"
            "    proxy->Fire(2);")
        self.assertIsNone(f)

    def test_local_sptr_if_guarded_suppresses(self):
        f = self._state(
            "    sptr<IObs> proxy = GetRemoteProxy<IObs>(1);\n"
            "    if (proxy == nullptr) {\n"
            "        return;\n"
            "    }\n"
            "    proxy->Fire(2);")
        self.assertIsNone(f)

    def test_local_raw_pointer_unguarded_is_candidate(self):
        f = self._state(
            "    IObs *p = other();\n"
            "    p->Fire(1);", var="p")
        self.assertIsNotNone(f)
        self.assertIn("assigned-source-unknown", f.description)

    def test_local_null_assignment_is_certain(self):
        f = self._state(
            "    IObs *p = NULL;\n"
            "    p->Fire(1);", var="p")
        self.assertIsNotNone(f)
        self.assertIn("state=Null (assigned-null)", f.description)
        self.assertEqual(f.severity, "high")

    def test_local_address_of_is_non_null(self):
        f = self._state(
            "    IObs holder;\n"
            "    IObs *p = &holder;\n"
            "    p->Fire(1);", var="p")
        self.assertIsNone(f)

    def test_disjunction_with_null_test_guards(self):
        # short-circuit: the branch is taken when p is null on its own
        f = self._state(
            "    sptr<IObs> proxy = GetRemoteProxy<IObs>(1);\n"
            "    if (proxy == nullptr || other()) {\n"
            "        return;\n"
            "    }\n"
            "    proxy->Fire(2);")
        self.assertIsNone(f)

    def test_disjunction_null_test_on_either_side_guards(self):
        f = self._state(
            "    sptr<IObs> proxy = GetRemoteProxy<IObs>(1);\n"
            "    if (other() || !proxy) {\n"
            "        return;\n"
            "    }\n"
            "    proxy->Fire(2);")
        self.assertIsNone(f)

    def test_conjunction_with_null_test_does_not_guard(self):
        # p null but other() false → branch not taken → not a guard
        f = self._state(
            "    sptr<IObs> proxy = GetRemoteProxy<IObs>(1);\n"
            "    if (proxy == nullptr && other()) {\n"
            "        return;\n"
            "    }\n"
            "    proxy->Fire(2);")
        self.assertIsNotNone(f)

    def test_conditional_null_assignment_merges_to_maybenull(self):
        # if (x) p = foo(); else p = NULL; p->a  — on the x-true path p is
        # non-null; straight-line 'latest assign wins' must not call it Null
        f = self._state(
            "    IObs *p = NULL;\n"
            "    if (other()) {\n"
            "        p = other();\n"
            "    }\n"
            "    p->Fire(1);", var="p")
        self.assertIsNotNone(f)
        self.assertIn("merged-branches", f.description)
        self.assertNotIn("state=Null", f.description)
        self.assertEqual(f.severity, "medium")

    def test_toplevel_null_assignment_stays_certain(self):
        f = self._state(
            "    IObs *p = NULL;\n"
            "    p->Fire(1);", var="p")
        self.assertIsNotNone(f)
        self.assertIn("state=Null", f.description)

    def test_scoped_guard_does_not_protect_after_block(self):
        # the return only happens when other() is true; the fall-through
        # path can still carry a null p
        f = self._state(
            "    sptr<IObs> proxy = GetRemoteProxy<IObs>(1);\n"
            "    if (other()) {\n"
            "        if (!proxy) {\n"
            "            return;\n"
            "        }\n"
            "    }\n"
            "    proxy->Fire(2);")
        self.assertIsNotNone(f)


if __name__ == "__main__":
    unittest.main()
