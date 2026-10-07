"""Regression tests for the residual B/C fixes (2026-09-29 survey).

B: detection-engine P2s — P6 cpp coverage, PoC filename collision,
wrapper-aware P8 scoring, cross_uaf local-variable tracking, reachability
wiring. C: report-generator robustness — edge-case records, source-snippet
content, overwrite refusal, empty-input failure, markdown escaping.
"""
import json, tempfile, unittest
from pathlib import Path
from unittest import mock

from ohvul.autopilot import scan_p6, scan_p8, generate_poc, Finding, run, CallGraph
from ohvul.cross_uaf import build_facts, scan_cross_uaf
from ohvul.vuln_report import read_case, generate_report
from ohvul.competition_report import assemble


def _write(root: Path, name: str, code: str) -> Path:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code, encoding="utf-8")
    return p


class DetectionP2Tests(unittest.TestCase):
    def test_p6_covers_cpp_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.cpp",
                   "struct S { int a; int b; };\n"
                   "void consume(S *info) {\n"
                   "    int x = info->a + info->b;\n"
                   "    info->a = x;\n"
                   "    x = info->b;\n"
                   "}\n")
            findings = scan_p6(root)
        self.assertTrue(any(f.function == "consume" for f in findings),
                        "P6 must scan *.cpp, not only *.c")

    def test_poc_files_do_not_collide_on_shared_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            fid = "P8_" + "x" * 80  # identical first 40 sanitized chars
            f1 = Finding(fid + "_A", "P8_use_after_free", "high", "a.c", 1,
                         "f", "p", "CWE-416", "d")
            f2 = Finding(fid + "_B", "P8_use_after_free", "high", "a.c", 2,
                         "f", "p", "CWE-416", "d")
            n1, n2 = generate_poc(f1, out), generate_poc(f2, out)
            self.assertNotEqual(n1, n2)
            self.assertTrue((out / n1).exists() and (out / n2).exists())

    def test_p8_scoring_honors_wrapper_free_reassignment(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c",
                   "void SoftBusFree(void *p);\n"
                   "void f(char *msg, char *other) {\n"
                   "    SoftBusFree(msg);\n"
                   "    msg = other;\n"   # non-NULL reassignment: not suppressed by the scanner
                   "    msg[0] = 1;\n"
                   "}\n")
            findings = scan_p8(root)
        self.assertTrue(findings)
        self.assertIn("-30 (reassigned after free)", findings[0].confidence_factors)

    def test_cross_uaf_tracks_freed_locals(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c",
                   "void use(char *p) { p[0] = 1; }\n"
                   "void f(void) {\n"
                   "    char *loc = (char*)0;\n"
                   "    free(loc);\n"
                   "    use(loc);\n"
                   "}\n")
            findings = scan_cross_uaf(root, build_facts(root))
        self.assertTrue([f for f in findings if f.finding_id.startswith("P8A_")],
                        "free-then-pass of a LOCAL pointer must be detected")

    def test_run_enriches_reachability(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c",
                   "void inner(int *p) { p[0] = p[1] + p[2]; }\n"
                   "void outer(int *p) { inner(p); }\n")
            report = run(root, Path(d) / "out")
        for f in report["findings"]:
            if f["function"] == "inner":
                self.assertIn("outer", f["reachability"])
                self.assertNotEqual("n/a", f["reachability"])


class ReportRobustnessTests(unittest.TestCase):
    def _case(self, root: Path, record: dict, name="edge"):
        cd = root / "cases" / name
        cd.mkdir(parents=True)
        (cd / "case.json").write_text(json.dumps(record, ensure_ascii=False),
                                      encoding="utf-8")
        return cd

    def test_string_evidence_list_does_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cd = self._case(root, {
                "component": "third_party/x",
                "cve_reference": "CVE-TEST-1",
                "evidence_locations": ["just a string"],
            })
            data = read_case(cd)
        self.assertEqual(data["source_file"], "just a string")

    def test_null_component_and_dict_cwe_do_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cd = self._case(root, {
                "component": None,
                "cve_reference": None,
                "cwe_candidate": {"id": "CWE-122"},
            })
            data = read_case(cd)
        self.assertEqual(data["component"], "")
        self.assertIn("CWE-122", data["cwe"])

    def test_source_snippet_embeds_case_dir_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cd = self._case(root, {"component": "third_party/x"})
            (cd / "source_snippet.txt").write_text(
                "int vulnerable(char *p) { return p[0]; }", encoding="utf-8")
            data = read_case(cd)
        self.assertIn("int vulnerable", data["source_snippet"])
        self.assertIn("```c", data["source_snippet"])

    def test_source_snippet_quotes_recorded_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cd = self._case(root, {
                "component": "third_party/x",
                "oh_source": {"l4_evidence": "OH vf_quirc.c has quirc_resize only in config_input"},
            })
            data = read_case(cd)
        self.assertIn("quirc_resize", data["source_snippet"])

    def test_descriptive_evidence_locations_are_quoted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cd = self._case(root, {
                "component": "third_party/x",
                "evidence_locations": {"consume_target": "cJSON_Utils.c:1325-1330"},
            })
            data = read_case(cd)
        self.assertIn("cJSON_Utils.c:1325-1330", data["source_snippet"])

    def test_patch_falls_back_to_upstream_named_file(self):
        # §5 must inline the fix diff when only an upstream_*.patch is
        # present, not degrade to a bare pointer.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cd = self._case(root, {"component": "third_party/x"})
            (cd / "upstream_abc123.patch").write_text(
                "--- a/f.c\n+++ b/f.c\n@@ -1,2 +1,2 @@\n-x\n+y\n", encoding="utf-8")
            data = read_case(cd)
        self.assertIn("upstream_abc123.patch", data["patch_content"])
        self.assertIn("```diff", data["patch_content"])

    def test_large_patch_becomes_pointer_with_name(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cd = self._case(root, {"component": "third_party/x"})
            (cd / "patch.diff").write_text("x" * 20000, encoding="utf-8")
            data = read_case(cd)
        self.assertIn("patch.diff", data["patch_content"])
        self.assertIn("20000 字节", data["patch_content"])
        self.assertNotIn("```diff", data["patch_content"])

    def test_report_refuses_to_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._case(root, {"component": "third_party/x"})
            out = Path(d) / "report.md"
            generate_report(root / "cases", out)
            with self.assertRaises(ValueError):
                generate_report(root / "cases", out)
            generate_report(root / "cases", out, force=True)  # ok

    def test_pipe_characters_do_not_break_tables(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._case(root, {"component": "a|b", "cve_reference": "CVE|x"})
            out = Path(d) / "report.md"
            generate_report(root / "cases", out)
            content = out.read_text(encoding="utf-8")
        # pipes inside field values must arrive escaped
        self.assertIn("a\\|b", content)
        self.assertIn("CVE\\|x", content)

    def test_competition_report_empty_cases_dir_fails_loudly(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "cases").mkdir()
            with self.assertRaises(ValueError):
                assemble(root / "cases")


if __name__ == "__main__":
    unittest.main()
