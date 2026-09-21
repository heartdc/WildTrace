import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tools.kb_version_probe import probe

_KB = [
    {"id": "CVE-2020-1111", "cwe": ["CWE-125"], "summary": "OOB read in demo.",
     "component": "demolib", "affected_versions": ["1.2.0", "1.2.1"],
     "fixed_versions": ["1.2.2"], "source": "https://example/1"},
    {"id": "CVE-2021-2222", "cwe": [], "summary": "Other issue.",
     "component": "otherlib", "affected_versions": ["0.9"],
     "fixed_versions": ["1.0.0"], "source": "https://example/2"},
]


class ProbeTests(unittest.TestCase):
    def _tree(self, root: Path, dirname, name, version):
        directory = root / "third_party" / dirname
        directory.mkdir(parents=True)
        (directory / "README.OpenSource").write_text(
            f"OpenHarmony third_party component\n\nName: {name}\nVersion: {version}\nLicense: MIT\n",
            encoding="utf-8")

    def test_exact_and_unresolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._tree(root, "demolib", "demolib", "1.2.0")   # exact hit
            self._tree(root, "otherlib", "otherlib", "2.0")   # known component, no match
            self._tree(root, "unknownlib", "unknownlib", "3.0")  # not in KB
            kb = root / "kb.json"
            kb.write_text(json.dumps({"schema": "0.1", "records": _KB}), encoding="utf-8")
            report = probe(root, [kb])
            self.assertEqual(report["components_seen"], 3)
            self.assertEqual(len(report["exact_candidates"]), 1)
            hit = report["exact_candidates"][0]
            self.assertEqual((hit["cve"], hit["version"], hit["alias"]),
                             ("CVE-2020-1111", "1.2.0", "demolib"))
            self.assertEqual(len(report["unresolved_components"]), 1)
            self.assertEqual(report["unresolved_components"][0]["alias"], "otherlib")

    def test_cjson_alias_and_missing_version_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._tree(root, "cjson", "third_party_cJSON", "1.7.19")
            (root / "third_party" / "noversion").mkdir()
            (root / "third_party" / "noversion" / "README.OpenSource").write_text(
                "Name: noversion\n", encoding="utf-8")
            kb = root / "kb.json"
            kb.write_text(json.dumps({"schema": "0.1", "records": [
                {"id": "CVE-2023-3333", "cwe": [], "summary": "x",
                 "component": "cjson", "affected_versions": ["1.7.19"],
                 "fixed_versions": [], "source": "https://example/3"}]}), encoding="utf-8")
            report = probe(root, [kb])
            self.assertEqual(report["components_seen"], 1)  # noversion skipped
            self.assertEqual(report["exact_candidates"][0]["cve"], "CVE-2023-3333")

    def test_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._tree(root, "demolib", "demolib", "1.2.1")
            kb = root / "kb.json"
            kb.write_text(json.dumps({"schema": "0.1", "records": _KB}), encoding="utf-8")
            out = root / "report.json"
            proc = subprocess.run(
                [sys.executable, "-X", "utf8", str(Path("tools/kb_version_probe.py")),
                 str(root), "--kb", str(kb), "--output", str(out)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["exact_candidates"], 1)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8-sig"))
                             ["exact_candidates"][0]["cve"], "CVE-2020-1111")


if __name__ == "__main__":
    unittest.main()
