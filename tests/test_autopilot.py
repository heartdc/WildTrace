import json
import tempfile
import unittest
from pathlib import Path

from ohvul.autopilot import Finding, generate_poc, run


class AutopilotV2Tests(unittest.TestCase):
    """End-to-end autopilot v2 pipeline tests (9 pattern families)."""

    def _make_cj_source(self, root: Path):
        d = root / "comp" / "frameworks" / "cj" / "src"
        d.mkdir(parents=True)
        (d / "impl.cpp").write_text(
            "typedef struct { int8_t vt; char* key; void* value; int64_t size; } CParameters;\n"
            "typedef struct { CParameters* head; int64_t size; } CArrParameters;\n"
            "void ProcessData(CArrParameters params) {\n"
            "    for (int i = 0; i < params.size; i++) {\n"
            "        auto item = params.head + i;\n"
            "        process(item->key);\n"
            "    }\n"
            "}\n", encoding="utf-8")

    def _make_general_source(self, root: Path):
        d = root / "native"
        d.mkdir(parents=True)
        # P4: unbounded memcpy
        (d / "copy.c").write_text(
            "#include <string.h>\n"
            "void copy_data(char *dst, const char *src, int len) {\n"
            "    memcpy(dst, src, len);\n"
            "}\n", encoding="utf-8")
        # P5: stack buffer + strcpy
        (d / "stack.c").write_text(
            "#include <string.h>\n"
            "void handle_name(const char *name) {\n"
            "    char buf[32];\n"
            "    strcpy(buf, name);\n"
            "}\n", encoding="utf-8")
        # P8: UAF
        (d / "uaf.c").write_text(
            "#include <stdlib.h>\n"
            "void use_ptr(int *p) { return; }\n"
            "void process(int *data) {\n"
            "    free(data);\n"
            "    use_ptr(data);\n"
            "    data[0] = 1;\n"
            "}\n", encoding="utf-8")

    def test_cj_pipeline_produces_findings_and_pocs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_cj_source(root)
            out = root / "output"
            report = run(root, out)
            self.assertGreater(report["summary"]["total"], 0)
            self.assertGreater(report["summary"]["pocs"], 0)
            self.assertTrue((out / "findings.json").exists())
            self.assertTrue((out / "findings.md").exists())
            self.assertTrue(list((out / "pocs").glob("*.c")))

    def test_general_pipeline_produces_findings(self):
        """General C/C++ patterns (P4-P9) work on non-CJ code."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_general_source(root)
            out = root / "output"
            report = run(root, out)
            # Should find P4 (memcpy), P5 (stack overflow), P8 (UAF)
            self.assertGreater(report["summary"]["total"], 0)
            patterns = set(report["summary"]["patterns"].keys())
            self.assertTrue(
                patterns & {"P4_unbounded_copy", "P5_stack_overflow", "P8_use_after_free"},
                f"Expected at least one general pattern, got {patterns}")

    def test_poc_generation_v2(self):
        finding = Finding(
            finding_id="test_42", pattern="P4_unbounded_copy", severity="high",
            file="test.c", line=10, function="TestFunc", struct_type="memcpy",
            cwe="CWE-120", description="test", trigger_hint="oversized len")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            name = generate_poc(finding, out)
            self.assertTrue(name)
            content = (out / name).read_text()
            self.assertIn("P4", content)
            self.assertIn("CWE-120", content)

    def test_all_findings_have_cwe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_cj_source(root)
            self._make_general_source(root)
            out = root / "output"
            report = run(root, out)
            for f in report["findings"]:
                self.assertTrue(f["cwe"].startswith("CWE-"),
                                f"Missing CWE: {f['finding_id']}")

    def test_scanner_selection(self):
        """CJ-specific scanners only run when CJ files present."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # No CJ files → P1-P3 should not run
            (root / "plain.c").write_text("int main() { return 0; }\n", encoding="utf-8")
            out = root / "output"
            report = run(root, out)
            self.assertNotIn("P1", report["summary"]["scanners"])
            self.assertIn("P4", report["summary"]["scanners"])


if __name__ == "__main__":
    unittest.main()
