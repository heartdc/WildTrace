import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from ohvul.kb_sync import (build_kb, load_sharded_kb, parse_cvelist, parse_osv,
                           merge_sources)
from ohvul.knowledge_base import load_records

_CVELIST_RECORD = {
    "cveMetadata": {"cveId": "CVE-2024-0001"},
    "containers": {"cna": {
        "descriptions": [{"lang": "en", "value": "  Heap overflow in the parser.  "}],
        "problemTypes": [{"descriptions": [{"cweId": "CWE-122"}]}],
        "affected": [{"product": "libdemo", "vendor": "example",
                      "versions": [{"version": "1.2.0"}, {"version": "1.3.0",
                                                           "lessThan": "1.3.1"}]}],
    }},
}

_CVELIST_MINIMAL = {
    "cveMetadata": {"cveId": "CVE-2024-0002"},
    "containers": {"cna": {
        "descriptions": [{"lang": "en", "value": "Disclosure of private data."}],
        "affected": [{"product": "tinylib", "versions": [{"version": "0.9"}]}],
    }},
}

_OSV_RECORD = {
    "id": "OSV-2024-7",
    "aliases": ["CVE-2024-0003"],
    "summary": "Use-after-free in decode",
    "affected": [{"package": {"ecosystem": "OSS-Fuzz", "name": "mediacodec"},
                  "versions": ["2.1"],
                  "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2"}]}],
                  "database_specific": {"cwe_ids": ["CWE-416"]}}],
}

_OSV_NON_CVE = {
    "id": "OSV-2024-8",
    "summary": "No CVE alias here",
    "affected": [{"package": {"ecosystem": "OSS-Fuzz", "name": "otherlib"},
                  "versions": ["1.0"]}],
}

_OSV_OTHER_ECOSYSTEM = {
    "id": "GHSA-1111-2222-3333",
    "aliases": ["CVE-2024-0004"],
    "summary": "npm advisory, not relevant",
    "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
                  "versions": ["1.0"]}],
}


def _write(root: Path, relative: str, payload) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _cvelist_dir(target: Path) -> Path:
    _write(target, "cves/2024/0xxx/CVE-2024-0001.json", _CVELIST_RECORD)
    _write(target, "cves/2024/0xxx/CVE-2024-0002.json", _CVELIST_MINIMAL)
    _write(target, "cves/2024/0xxx/CVE-2024-0001-copy.json", _CVELIST_RECORD)
    _write(target, "cves/2024/0xxx/CVE-2024-0009.json", "{not json")
    return target


def _osv_dir(target: Path) -> Path:
    _write(target, "osv-export/OSV-2024-7.json", _OSV_RECORD)
    _write(target, "osv-export/OSV-2024-8.json", _OSV_NON_CVE)
    _write(target, "osv-export/GHSA-1111.json", _OSV_OTHER_ECOSYSTEM)
    _write(target, "osv-export/broken.json", "[]")
    return target


class ParseCvelistTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = _cvelist_dir(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_projects_records_with_versions_and_cwe(self):
        records, stats = parse_cvelist(self.root)
        by_id = {r["id"]: r for r in records}
        first = by_id["CVE-2024-0001"]
        self.assertEqual(first["component"], "libdemo")
        self.assertEqual(first["summary"], "Heap overflow in the parser.")
        self.assertEqual(first["cwe"], ["CWE-122"])
        self.assertEqual(first["affected_versions"], ["1.2.0", "1.3.0"])
        self.assertEqual(first["fixed_versions"], ["1.3.1"])
        self.assertEqual(by_id["CVE-2024-0002"]["cwe"], [])
        self.assertEqual(stats["records_kept"], 2)
        self.assertEqual(stats["duplicate_ids"], 1)
        self.assertEqual(stats["skipped"], 1)

    def test_output_loads_through_canonical_loader(self):
        records, _stats = parse_cvelist(self.root)
        path = Path(self._tmp.name) / "single.json"
        path.write_text(json.dumps({"schema": "0.1", "records": records}), encoding="utf-8")
        database = load_records(path)
        self.assertEqual(len(database["records"]), 2)


class ParseOsvTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = _osv_dir(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_keeps_cve_aliased_allowlisted_records_only(self):
        records, stats = parse_osv(self.root, {"OSS-Fuzz"})
        self.assertEqual([r["id"] for r in records], ["CVE-2024-0003"])
        record = records[0]
        self.assertEqual(record["component"], "mediacodec")
        self.assertEqual(record["cwe"], ["CWE-416"])
        self.assertEqual(record["affected_versions"], ["2.1"])
        self.assertEqual(record["fixed_versions"], ["2.2"])
        self.assertEqual(record["source"], "osv:OSV-2024-7")
        self.assertEqual(stats["skipped_non_cve"], 1)
        self.assertEqual(stats["skipped_ecosystem"], 1)

    def test_ecosystem_allowlist_is_configurable(self):
        records, _stats = parse_osv(self.root, {"npm"})
        self.assertEqual([r["id"] for r in records], ["CVE-2024-0004"])


class BuildAndVerifyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.cvelist = _cvelist_dir(self.base / "src1")
        self.osv = _osv_dir(self.base / "src2")
        self.out = self.base / "kb"

    def tearDown(self):
        self._tmp.cleanup()

    def test_build_shards_load_and_roundtrip(self):
        manifest = build_kb(self.cvelist, self.osv, self.out,
                            snapshot_version="2026-09-14",
                            max_records_per_shard=1)
        self.assertEqual(manifest["records_total"], 3)
        self.assertEqual(len(manifest["shards"]), 3)
        database = load_sharded_kb(self.out)
        self.assertEqual(len(database["records"]), 3)
        self.assertEqual(database["snapshot_version"], "2026-09-14")
        self.assertEqual(database["records_sha256"], manifest["records_sha256"])
        # Same digest formula as the canonical single-file loader.
        single = self.base / "single.json"
        single.write_text(json.dumps({"schema": "0.1",
                                      "records": database["records"]}), encoding="utf-8")
        self.assertEqual(load_records(single)["records_sha256"],
                         database["records_sha256"])

    def test_cvelist_wins_on_duplicate_cve(self):
        merged = merge_sources([(parse_osv(self.osv, {"OSS-Fuzz"})[0], "osv"),
                                (parse_cvelist(self.cvelist)[0], "cvelistV5")])
        by_id = {r["id"]: r for r in merged}
        self.assertEqual(by_id["CVE-2024-0001"]["source"], "cvelistV5")

    def test_build_is_deterministic(self):
        first = build_kb(self.cvelist, self.osv, self.out, snapshot_version="s")
        second = build_kb(self.cvelist, self.osv, self.base / "kb2", snapshot_version="s")
        self.assertEqual(first["records_sha256"], second["records_sha256"])
        self.assertEqual([s["sha256"] for s in first["shards"]],
                         [s["sha256"] for s in second["shards"]])

    def test_tampered_shard_rejected(self):
        build_kb(self.cvelist, self.osv, self.out, snapshot_version="s")
        shard = self.out / "kb_part_0000.json"
        shard.write_text(shard.read_text(encoding="utf-8").replace("1.2.0", "9.9.9"),
                         encoding="utf-8")
        with self.assertRaises(ValueError):
            load_sharded_kb(self.out)

    def test_cross_shard_duplicate_rejected(self):
        build_kb(self.cvelist, self.osv, self.out, snapshot_version="s",
                 max_records_per_shard=1)
        duplicate = json.loads((self.out / "kb_part_0000.json").read_text(encoding="utf-8"))
        (self.out / "kb_part_0001.json").write_text(
            json.dumps({"schema": "0.1", "records": duplicate["records"]}), encoding="utf-8")
        with self.assertRaises(ValueError):
            load_sharded_kb(self.out)

    def test_requires_at_least_one_source(self):
        with self.assertRaises(ValueError):
            build_kb(None, None, self.out, snapshot_version="s")


class CliTests(unittest.TestCase):
    def test_build_and_verify_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            cvelist = _cvelist_dir(base / "src1")
            osv = _osv_dir(base / "src2")
            out = base / "kb"
            build_cmd = [sys.executable, "-m", "ohvul.kb_sync", "build",
                         "--cvelist", str(cvelist), "--osv", str(osv),
                         "--out", str(out), "--snapshot", "2026-09-14"]
            built = subprocess.run(build_cmd, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            payload = json.loads(built.stdout)
            self.assertEqual(payload["status"], "built")
            self.assertEqual(payload["records"], 3)
            verified = subprocess.run([sys.executable, "-m", "ohvul.kb_sync", "verify",
                                       "--kb", str(out)], capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(json.loads(verified.stdout)["status"], "ok")

    def test_verify_rejects_missing_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-m", "ohvul.kb_sync", "verify",
                                     "--kb", str(Path(directory))],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("INVALID", result.stderr)


if __name__ == "__main__":
    unittest.main()
