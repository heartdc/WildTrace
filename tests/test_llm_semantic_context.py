"""Tests for LLM PoC semantic context injection (step ③).

The state model's output (pointer state, reason, trigger strategy) is
injected into the LLM prompt as a dedicated section, so the model
receives "why this pointer might be null" instead of guessing from
raw source (mentor §8: "给模型的材料应该围绕问题组织").
"""
import unittest

from ohvul.llm_poc import _build_prompt, _extract_semantic_context


class SemanticContextTests(unittest.TestCase):
    def _finding(self, description, trigger_hint="use(NULL)"):
        return {
            "pattern": "P6_null_deref",
            "description": description,
            "trigger_hint": trigger_hint,
            "struct_type": "node",
            "function": "vulnerable_fn",
            "file": "src/vuln.c",
            "line": 42,
            "cwe": "CWE-476",
            "severity": "medium",
            "confidence_factors": "+10 (known-nullable API)",
        }

    def test_known_nullable_source_gets_strategy(self):
        f = self._finding(
            "Ptr 'node' ×3 deref(s), access state=MaybeNull "
            "(known-nullable-source)")
        ctx = _extract_semantic_context(f)
        self.assertIn("known-nullable-source", ctx)
        self.assertIn("Trigger strategy", ctx)
        self.assertIn("VERIFIED nullable-returning API", ctx)
        self.assertIn("node", ctx)
        self.assertIn("use(NULL)", ctx)

    def test_check_after_access_gets_critical_strategy(self):
        f = self._finding(
            "Ptr 'info' ×8 deref(s), access state=MaybeNull "
            "(check-after-access)")
        ctx = _extract_semantic_context(f)
        self.assertIn("check-after-access", ctx)
        self.assertIn("CRITICAL", ctx)
        self.assertIn("before the check is reached", ctx)

    def test_assigned_null_gets_confirmed_strategy(self):
        f = self._finding(
            "Ptr 'p' ×1 deref(s), access state=Null (assigned-null)")
        ctx = _extract_semantic_context(f)
        self.assertIn("assigned-null", ctx)
        self.assertIn("CONFIRMED NULL DEREFERENCE", ctx)

    def test_non_p6_returns_empty(self):
        f = self._finding("some description")
        f["pattern"] = "P8_use_after_free"
        ctx = _extract_semantic_context(f)
        self.assertEqual(ctx, "")

    def test_prompt_contains_semantic_section(self):
        f = self._finding(
            "Ptr 'node' ×3 deref(s), access state=MaybeNull "
            "(check-after-access)")
        messages = _build_prompt(f, "int x = 1;", "#include <stdio.h>",
                                 semantic_context=_extract_semantic_context(f))
        user_msg = messages[1]["content"]
        self.assertIn("Pointer State Analysis", user_msg)
        self.assertIn("check-after-access", user_msg)
        self.assertIn("Trigger Strategy", user_msg)
        self.assertIn("Follow the Trigger Strategy", user_msg)

    def test_prompt_without_semantic_still_works(self):
        f = self._finding("some other pattern")
        f["pattern"] = "P8_use_after_free"
        messages = _build_prompt(f, "int x = 1;", "#include <stdio.h>")
        user_msg = messages[1]["content"]
        self.assertNotIn("Pointer State Analysis", user_msg)
        self.assertIn("Source Code Context", user_msg)


if __name__ == "__main__":
    unittest.main()
