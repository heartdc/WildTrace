import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tools.kb_partner_import import convert, import_batch
from ohvul.knowledge_base import load_records

_RICH = [
    {
        "id": "CVE-2026-0001",
        "cwe": ["CWE-416"],
        "summary": "UAF in demo component.",
        "component": "Demo_Component",
        "affected_versions": ["OpenHarmony-v6.0-Release"],
        "fixed_versions": [
            {"fixed_version": "6.0.x",
             "commits": ["https://gitcode.com/openharmony/demo/commit/abc123"]}
        ],
        "source": "https://example/advisory",
        "source_date": "2026-03-03T00:00:00Z",
        "source_record": "| row |",
        "evidence_refs": [{"6.0.x": [{"filename": "a.c", "diff": "@@ -1 +1 @@\n-x\n+x"}]}],
        "review_status": "unreviewed",
    },
    {
        "id": "CVE-2026-0002",
        "cwe": [],
        "summary": "Unresolved record without fixed version.",
        "component": "demo_other",
        "affected_versions": [],
        "fixed_versions": [],
        "source": "https://example/advisory-2",
        "review_status": "unreviewed",
    },
    {
        "id": "CVE-2026-0003",
        "cwe": ["CWE-476"],
        "summary": "String-form fixed versions pass through.",
        "component": "demo_plain",
        "affected_versions": ["v1"],
        "fixed_versions": ["1.2.x", "1.2.x"],
        "source": "https://example/advisory-3",
    },
]


class ConvertTests(unittest.TestCase):
    def test_split_and_flatten(self):
        runtime, sidecar, unresolved, norms = convert(_RICH)
        self.assertEqual([r["id"] for r in runtime],
                         ["CVE-2026-0001", "CVE-2026-0003"])
        self.assertEqual(runtime[0]["fixed_versions"], ["6.0.x"])
        self.assertEqual(runtime[0]["component"], "demo_component")
        self.assertEqual(runtime[0]["fixed_version_semantics"],
                         "oh_advisory_version_branches")
        self.assertEqual(runtime[1]["fixed_versions"], ["1.2.x"])  # dedup
        self.assertEqual(len(sidecar), 3)
        self.assertEqual(sidecar[0]["structured_fixed"][0]["commits"],
                         ["https://gitcode.com/openharmony/demo/commit/abc123"])
        self.assertEqual(sidecar[0]["evidence_refs"][0]["6.0.x"][0]["filename"], "a.c")
        self.assertEqual(unresolved, ["CVE-2026-0002"])
        self.assertEqual(norms, [{"id": "CVE-2026-0001",
                                  "from": "Demo_Component", "to": "demo_component"}])

    def test_missing_id_or_component_rejected(self):
        with self.assertRaises(ValueError):
            convert([{"id": "", "component": "x"}])
        with self.assertRaises(ValueError):
            convert([{"id": "CVE-2026-0009", "component": ""}])


class ImportTests(unittest.TestCase):
    def test_batch_roundtrip_validates_through_canonical_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            batch = base / "records.json"
            batch.write_text(json.dumps({"schema": "0.1", "records": _RICH}),
                             encoding="utf-8")
            out = base / "out"
            result = import_batch(batch, out)
            self.assertEqual(result["runtime_records"], 2)
            self.assertEqual(result["unresolved_no_fixed"], ["CVE-2026-0002"])
            database = load_records(out / "records_runtime.json")
            self.assertEqual(len(database["records"]), 2)
            self.assertEqual(database["records_sha256"], result["records_sha256"])
            sidecar = json.loads((out / "records_evidence.json").read_text(encoding="utf-8-sig"))
            self.assertEqual(sidecar["schema"], "partner-evidence-sidecar-0.1")
            self.assertEqual(len(sidecar["records"]), 3)

    def test_invalid_batch_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            batch = base / "records.json"
            batch.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                import_batch(batch, base / "out")
            self.assertFalse((base / "out" / "records_runtime.json").exists())

    def test_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            batch = base / "records.json"
            batch.write_text(json.dumps({"schema": "0.1", "records": _RICH}),
                             encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-X", "utf8", str(Path("tools/kb_partner_import.py")),
                 str(batch), "--out-dir", str(base / "out")],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout.splitlines()[0])
            self.assertEqual(payload["runtime_records"], 2)
            self.assertIn("normalized component: CVE-2026-0001", proc.stdout)


if __name__ == "__main__":
    unittest.main()
