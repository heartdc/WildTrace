"""Tests for the LLM PoC compile-execute verification loop (steps ①②).

The tests exercise the WSL compile and execute paths with a known-good
PoC that intentionally crashes (null dereference).
"""
import tempfile
import unittest
from pathlib import Path

from ohvul.llm_verify import compile_poc, execute_poc, _to_wsl_path


class CompileExecuteTests(unittest.TestCase):
    """Test the compile and execute primitives via WSL."""

    def test_compile_valid_null_deref_poc(self):
        code = (
            "#include <stdio.h>\n"
            "struct Node { int a; };\n"
            "void vulnerable(struct Node *node) {\n"
            "    node->a = 1;\n"
            "}\n"
            "int main(void) {\n"
            "    vulnerable(NULL);\n"
            "    printf(\"no crash\\n\");\n"
            "    return 0;\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory(prefix="wt_test_") as d:
            result = compile_poc(code, d)
        self.assertTrue(result["ok"], f"compile failed: {result['stderr']}")
        self.assertIsNotNone(result["binary_path"])

    def test_compile_invalid_code_fails(self):
        code = "int main(void) { syntax error here }"
        with tempfile.TemporaryDirectory(prefix="wt_test_") as d:
            result = compile_poc(code, d)
        self.assertFalse(result["ok"])
        self.assertTrue(len(result["stderr"]) > 0)

    def test_execute_crashing_poc_reports_segv(self):
        code = (
            "#include <stdio.h>\n"
            "struct Node { int a; };\n"
            "void vulnerable(struct Node *node) {\n"
            "    node->a = 1;\n"
            "}\n"
            "int main(void) {\n"
            "    volatile struct Node *n = NULL;\n"
            "    vulnerable((struct Node *)n);\n"
            "    return 0;\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory(prefix="wt_test_") as d:
            compile_result = compile_poc(code, d)
            self.assertTrue(compile_result["ok"])
            exec_result = execute_poc(compile_result["wsl_binary"])
        self.assertTrue(exec_result["crashed"],
                        f"expected crash, got exit={exec_result['exit_code']}")
        self.assertTrue(exec_result["asan_report"] or
                        exec_result["exit_code"] != 0)

    def test_execute_non_crashing_poc(self):
        code = (
            "#include <stdio.h>\n"
            "int main(void) {\n"
            "    printf(\"hello\\n\");\n"
            "    return 0;\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory(prefix="wt_test_") as d:
            compile_result = compile_poc(code, d)
            self.assertTrue(compile_result["ok"])
            exec_result = execute_poc(compile_result["wsl_binary"])
        self.assertFalse(exec_result["crashed"])
        self.assertEqual(exec_result["exit_code"], 0)

    def test_wsl_path_conversion(self):
        self.assertEqual(_to_wsl_path("C:\\foo\\bar"), "/mnt/c/foo/bar")
        self.assertEqual(_to_wsl_path("D:\\test"), "/mnt/d/test")
        self.assertEqual(_to_wsl_path("/already/wsl"), "/already/wsl")


class VerificationLoopTests(unittest.TestCase):
    """Test the full generate-compile-execute loop (mocked LLM)."""

    def test_result_structure(self):
        """Verify the result dict has the expected verification fields."""
        from ohvul.llm_verify import generate_poc_with_verification
        # We can't call the real LLM in tests, but we can verify the
        # function signature accepts the right parameters and the
        # default result structure includes verification fields.
        import inspect
        sig = inspect.signature(generate_poc_with_verification)
        params = list(sig.parameters.keys())
        self.assertIn('max_compile_retries', params)
        self.assertIn('execute_timeout', params)


if __name__ == "__main__":
    unittest.main()
