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


class PathSensitivityTests(unittest.TestCase):
    """Counter-examples from PR review: NULL-check placement variants."""

    def test_check_after_deref_still_reported(self):
        code = ("int f(size_t n) {\n"
                "  char *p = malloc(n);\n"
                "  p[0] = 'x';\n"
                "  if (p == NULL) {\n"
                "    return -1;\n"
                "  }\n"
                "  return 0;\n"
                "}\n")
        self.assertIn("CWE-476", _cwes(_scan(code)))

    def test_multiple_nullable_vars_both_reported(self):
        code = ("void f(size_t n, const char *name) {\n"
                "  char *p = malloc(n);\n"
                "  char *v = getenv(name);\n"
                "  p[0] = 'x';\n"
                "  v[0] = 'y';\n"
                "}\n")
        result = _scan(code)
        self.assertGreaterEqual(len([f for f in result["findings"]
                                     if f["cwe_candidate"] == "CWE-476"]), 2)

    @unittest.expectedFailure
    def test_branch_only_check_is_known_false_negative(self):
        """A NULL check inside one branch does not guard the fall-through deref.

        Known limitation of the lightweight model (no CFG); documented in the
        module docstring. If this ever starts passing, update the docstring.
        """
        code = ("int f(int flag, size_t n) {\n"
                "  char *p = malloc(n);\n"
                "  if (flag) {\n"
                "    if (p == NULL) {\n"
                "      return -1;\n"
                "    }\n"
                "  }\n"
                "  p[0] = 'x';\n"
                "  return 0;\n"
                "}\n")
        self.assertIn("CWE-476", _cwes(_scan(code)))


class ParserBoundaryTests(unittest.TestCase):
    def test_multiline_signature_extracted(self):
        code = "int add(int a,\n    int b)\n{\n  return a + b;\n}\n"
        functions = extract_functions(code)
        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0]["name"], "add")

    def test_brace_in_string_literal_is_structural_nothing(self):
        code = ("void f(void) {\n"
                "  printf(\"trigger {\");\n"
                "  char *s = \"} else {\";\n"
                "}\n"
                "void g(void) {\n"
                "}\n")
        self.assertEqual(len(extract_functions(code)), 2)

    def test_block_comment_braces_ignored(self):
        code = ("/* { if (x) { */\n"
                "void f(size_t n) {\n"
                "  char *p = malloc(n); /* } */\n"
                "  p[0] = 0;\n"
                "}\n"
                "// }\n")
        functions = extract_functions(code)
        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0]["name"], "f")

    def test_preprocessor_lines_skipped(self):
        code = ("#define LOOP(x) do { (x)++; } while (0)\n"
                "void f(size_t n) {\n"
                "  char *p = malloc(n);\n"
                "  p[0] = 0;\n"
                "}\n")
        functions = extract_functions(code)
        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0]["name"], "f")


class GuardPrecisionTests(unittest.TestCase):
    def test_for_loop_comparison_does_not_suppress(self):
        """Only if/else guards suppress; loop conditions bound nothing here."""
        code = ("void f(int i, int w, int h) {\n"
                "  for (i = 0; i < w; i++) {\n"
                "    char *p = malloc(w * h);\n"
                "    p[0] = 1;\n"
                "  }\n"
                "}\n")
        self.assertIn("CWE-190", _cwes(_scan(code)))

    def test_if_guard_still_suppresses(self):
        code = ("void resize(int w, int h) {\n"
                "  if (w > 0 && h > 0) {\n"
                "    char *p = malloc(w * h);\n"
                "    p[0] = 1;\n"
                "  }\n"
                "}\n")
        self.assertNotIn("CWE-190", _cwes(_scan(code)))


class FixedBufferLimitTests(unittest.TestCase):
    def test_long_string_literal_reported(self):
        code = 'void f(void) {\n  char buf[8];\n  strcpy(buf, "0123456789");\n}\n'
        self.assertIn("CWE-121", _cwes(_scan(code)))

    def test_short_literal_still_safe(self):
        code = 'void f(void) {\n  char buf[8];\n  strcpy(buf, "0123");\n}\n'
        self.assertNotIn("CWE-121", _cwes(_scan(code)))

    def test_symbolic_array_size_not_tracked(self):
        """Documented limitation: only numeric-size char arrays are tracked."""
        code = ("void f(const char *src) {\n"
                "  char buf[SIZE];\n"
                "  strcpy(buf, src);\n"
                "}\n")
        self.assertNotIn("CWE-121", _cwes(_scan(code)))


class RelativeFilesTests(unittest.TestCase):
    def test_explicit_paths_only_read_those_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.c").write_text("void f(size_t n) {\n  char *p = malloc(n);\n  p[0] = 0;\n}\n")
            (root / "b.c").write_text("void g(size_t n) {\n  char *q = malloc(n);\n  q[0] = 0;\n}\n")
            result = scan_functions(root, relative_files=["a.c"])
            self.assertEqual(result["scan"]["files_scanned"], 1)
            self.assertTrue(all(f["location"]["file"] == "a.c" for f in result["findings"]))

    def test_escape_entries_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for entry in ("../outside.c", "/absolute/path.c", "sub/../../escape.c"):
                with self.assertRaises(ValueError):
                    scan_functions(root, relative_files=[entry])


class UnifiedSchemaTests(unittest.TestCase):
    def test_output_passes_validate_result(self):
        from ohvul.verify import validate_result
        code = ("void f(size_t n, const char *src) {\n"
                "  char *p = malloc(n * 2);\n"
                "  char buf[32];\n"
                "  strcpy(buf, src);\n"
                "  p[0] = 0;\n"
                "}\n")
        result = _scan(code)
        self.assertEqual(validate_result(result), len(result["evidence_bundles"]))


if __name__ == "__main__":
    unittest.main()
