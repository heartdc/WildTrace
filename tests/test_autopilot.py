import json
import tempfile
import unittest
from pathlib import Path

from ohvul.autopilot import Finding, generate_poc, run


class AutopilotTests(unittest.TestCase):
    """End-to-end autopilot pipeline tests."""

    def _make_cj_source(self, root: Path):
        """Create a minimal CJ FFI source file with a known pattern."""
        cj_dir = root / "test_component" / "frameworks" / "cj" / "src"
        cj_dir.mkdir(parents=True)
        # P1 pattern: CArrParameters head unchecked
        (cj_dir / "test_impl.cpp").write_text(
            "#include <vector>\n"
            "typedef struct { int8_t vt; char* key; void* value; int64_t size; } CParameters;\n"
            "typedef struct { CParameters* head; int64_t size; } CArrParameters;\n"
            "void ProcessData(CArrParameters params) {\n"
            "    for (int i = 0; i < params.size; i++) {\n"
            "        auto item = params.head + i;\n"
            "        process(item->key);\n"
            "    }\n"
            "}\n",
            encoding="utf-8")
        # P2 pattern: truncation
        (cj_dir / "test_ffi.cpp").write_text(
            "typedef struct { uint8_t* head; int64_t size; } CArrUI8;\n"
            "int32_t FfiTest(CArrUI8 data) {\n"
            "    uint32_t len = static_cast<uint32_t>(data.size);\n"
            "    return process(data.head, len);\n"
            "}\n",
            encoding="utf-8")

    def test_end_to_end_pipeline(self):
        """Full autopilot run produces findings + PoC files."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_cj_source(root)
            out = root / "output"
            report = run(root, out)

            self.assertGreater(report["summary"]["total_findings"], 0)
            self.assertGreater(report["summary"]["pocs_generated"], 0)
            self.assertTrue((out / "findings.json").exists())
            self.assertTrue((out / "findings.md").exists())
            self.assertTrue(list((out / "pocs").glob("*.c")))

            # Verify JSON is parseable and has required fields
            data = json.loads((out / "findings.json").read_text())
            self.assertIn("surface", data)
            self.assertIn("summary", data)
            self.assertIn("findings", data)
            for f in data["findings"]:
                self.assertIn("pattern", f)
                self.assertIn("severity", f)
                self.assertIn("cwe", f)

    def test_poc_generation(self):
        """PoC is generated with correct pattern metadata."""
        finding = Finding(
            finding_id="test_123",
            pattern="P1_null_len",
            severity="high",
            file="test.cpp",
            line=42,
            function="TestFunc",
            struct_type="CArrParameters",
            cwe="CWE-476",
            description="Test vulnerability",
            ffi_export="FfiTestExport",
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            poc_name = generate_poc(finding, out)
            poc_path = out / poc_name
            self.assertTrue(poc_path.exists())
            content = poc_path.read_text()
            self.assertIn("P1_null_len", content)
            self.assertIn("CWE-476", content)
            self.assertIn("FfiTestExport", content)
            self.assertIn("dlopen", content)  # Uses FFI loading

    def test_no_cj_no_findings(self):
        """Non-CJ source produces no CJ FFI findings."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "plain.c").write_text(
                "#include <string.h>\nint main() { char buf[10]; strcpy(buf, \"x\"); return 0; }\n",
                encoding="utf-8")
            out = root / "output"
            report = run(root, out)
            self.assertEqual(report["summary"]["total_findings"], 0)

    def test_findings_have_cwe(self):
        """Every finding must have a CWE classification."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_cj_source(root)
            out = root / "output"
            report = run(root, out)
            for f in report["findings"]:
                self.assertTrue(f["cwe"].startswith("CWE-"),
                                f"Finding {f['finding_id']} missing CWE")


if __name__ == "__main__":
    unittest.main()
