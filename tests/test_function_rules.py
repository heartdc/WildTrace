import json
import tempfile
import unittest
from pathlib import Path
from ohvul.detect.function_rules import scan_functions, extract_functions
from ohvul.domain.evidence import validate_bundle


def _scan(code: str, suffix: str = ".c") -> dict:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / ("sample" + suffix)).write_text(code, encoding="utf-8")
        return scan_functions(root)


def _cwes(result: dict) -> set[str]:
    return {finding["cwe_candidate"] for finding in result["findings"]}


class ExtractFunctionsTests(unittest.TestCase):
    def test_extracts_function_line_ranges(self):
        code = "int add(int a, int b) {\n  return a + b;\n}\n"
        functions = extract_functions(code)
        self.assertEqual(len(functions), 1)
        self.assertEqual((functions[0]["name"], functions[0]["start"], functions[0]["end"]),
                         ("add", 1, 3))

    def test_ignores_control_flow_blocks(self):
        code = "void f(int n) {\n  if (n > 0) {\n    n--;\n  }\n}\n"
        self.assertEqual(len(extract_functions(code)), 1)


class IntegerOverflowRuleTests(unittest.TestCase):
    def test_reports_unchecked_product_size(self):
        code = ("void resize(int w, int h) {\n"
                "  char *p = malloc(w * h * 4);\n"
                "  p[0] = 1;\n"
                "}\n")
        self.assertIn("CWE-190", _cwes(_scan(code)))

    def test_sizeof_only_size_is_safe(self):
        code = ("void copy(void *src) {\n"
                "  struct frame *f = malloc(sizeof(struct frame));\n"
                "  f->len = 0;\n"
                "}\n")
        result = _scan(code)
        self.assertNotIn("CWE-190", _cwes(result))

    def test_literal_only_size_is_safe(self):
        code = "void f(void) {\n  char *p = malloc(1024 + 16);\n  p[0] = 0;\n}\n"
        self.assertNotIn("CWE-190", _cwes(_scan(code)))

    def test_prior_bounds_check_suppresses(self):
        code = ("void resize(int w, int h) {\n"
                "  if (w > 0 && h > 0 && w * h < 4096) {\n"
                "    char *p = malloc(w * h);\n"
                "    p[0] = 1;\n"
                "  }\n"
                "}\n")
        self.assertNotIn("CWE-190", _cwes(_scan(code)))


class NullableDerefRuleTests(unittest.TestCase):
    def test_reports_deref_without_null_check(self):
        code = ("void f(size_t n) {\n"
                "  char *p = malloc(n);\n"
                "  p[0] = 'x';\n"
                "}\n")
        self.assertIn("CWE-476", _cwes(_scan(code)))

    def test_null_check_before_deref_is_safe(self):
        code = ("int f(size_t n) {\n"
                "  char *p = malloc(n);\n"
                "  if (p == NULL) {\n"
                "    return -1;\n"
                "  }\n"
                "  p[0] = 'x';\n"
                "  return 0;\n"
                "}\n")
        self.assertNotIn("CWE-476", _cwes(_scan(code)))

    def test_bang_check_is_safe(self):
        code = ("int f(const char *name) {\n"
                "  char *v = getenv(name);\n"
                "  if (!v) {\n"
                "    return -1;\n"
                "  }\n"
                "  return v[0];\n"
                "}\n")
        self.assertNotIn("CWE-476", _cwes(_scan(code)))

    def test_plain_struct_pointer_deref_is_not_reported(self):
        code = ("void g(struct frame *fr) {\n"
                "  fr->len = 1;\n"
                "}\n")
        self.assertNotIn("CWE-476", _cwes(_scan(code)))


class FixedBufferCopyRuleTests(unittest.TestCase):
    def test_reports_strcpy_into_local_array(self):
        code = ("void f(const char *src) {\n"
                "  char buf[64];\n"
                "  strcpy(buf, src);\n"
                "}\n")
        self.assertIn("CWE-121", _cwes(_scan(code)))

    def test_literal_source_is_safe(self):
        code = ("void f(void) {\n"
                "  char buf[64];\n"
                "  strcpy(buf, \"ok\");\n"
                "}\n")
        self.assertNotIn("CWE-121", _cwes(_scan(code)))

    def test_heap_destination_is_not_fixed_buffer(self):
        code = ("void f(const char *src) {\n"
                "  char *buf = malloc(64);\n"
                "  strcpy(buf, src);\n"
                "}\n")
        result = _scan(code)
        self.assertNotIn("CWE-121", _cwes(result))

    def test_sprintf_without_percent_s_is_safe(self):
        code = ("void f(int value) {\n"
                "  char buf[16];\n"
                "  sprintf(buf, \"%d\", value);\n"
                "}\n")
        self.assertNotIn("CWE-121", _cwes(_scan(code)))

    def test_memcpy_within_declared_literal_size_is_safe(self):
        code = ("void f(const void *src) {\n"
                "  char buf[32];\n"
                "  memcpy(buf, src, 16);\n"
                "}\n")
        self.assertNotIn("CWE-121", _cwes(_scan(code)))

    def test_memcpy_with_symbolic_size_is_reported(self):
        code = ("void f(const void *src, size_t n) {\n"
                "  char buf[32];\n"
                "  memcpy(buf, src, n);\n"
                "}\n")
        self.assertIn("CWE-121", _cwes(_scan(code)))


class ContractTests(unittest.TestCase):
    def test_result_contract_and_evidence_bundles_validate(self):
        code = ("void f(size_t n, const char *src) {\n"
                "  char *p = malloc(n * 2);\n"
                "  char buf[32];\n"
                "  strcpy(buf, src);\n"
                "  p[0] = 0;\n"
                "}\n")
        result = _scan(code)
        self.assertEqual(result["schema_version"], "0.3")
        self.assertEqual(len(result["findings"]), len(result["evidence_bundles"]))
        for bundle in result["evidence_bundles"]:
            validate_bundle(bundle)
        for finding in result["findings"]:
            self.assertEqual(finding["status"], "candidate")
            self.assertIn("evidence_id", finding)

    def test_ignore_comment_suppresses_line(self):
        code = ("void f(size_t n) {\n"
                "  char *p = malloc(n * 2); // ohvul:ignore\n"
                "  p[0] = 0;\n"
                "}\n")
        self.assertNotIn("CWE-190", _cwes(_scan(code)))

    def test_json_serializable(self):
        code = "void f(size_t n) {\n  char *p = malloc(n * 2);\n  p[0] = 0;\n}\n"
        json.dumps(_scan(code), ensure_ascii=False)


if __name__ == "__main__":
    unittest.main()
