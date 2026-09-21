"""Offline CVE knowledge-base synchronization; build phase never scans targets.

Normalizes local copies of public vulnerability data (cvelistV5 JSON trees and
extracted OSV export directories) into the schema-0.1 knowledge-base files that
ohvul.knowledge_base.load_records accepts. Sources are prepared by the operator
(git clone / zip download) before this tool runs; the tool itself performs no
network access and executes no target code.

Documented v1 limitations:
- One component per CVE record (the 0.1 schema keys records by CVE id); the
  first affected product wins and dropped products are recorded as auditable
  samples in the manifest source stats (recall candidates only).
- OSV records without a CVE alias are skipped (the schema requires CVE ids).
- Version semantics stay exact strings. Values projected into fixed_versions
  are RANGE BOUNDARIES, not verified exact fix releases; each record carries
  fixed_version_semantics stating the projection (cvelist_lessThan_boundaries
  or osv_fixed_events). GHSA YAML is not parsed directly (GHSA data arrives
  via OSV aliases).
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
from pathlib import Path

from .knowledge_base import load_records

SHARD_SCHEMA = "0.1"
MANIFEST_SCHEMA = "kb-manifest-0.1"
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE_ID = re.compile(r"CWE-[1-9]\d*")
_MAX_SHARD_BYTES = 8 * 1024 * 1024
_DROPPED_SAMPLE_CAP = 1000


def _note_dropped(stats: dict, cve: str, kept: str, dropped: str) -> None:
    if len(stats.get("dropped_product_samples", [])) >= _DROPPED_SAMPLE_CAP:
        stats["dropped_products_truncated"] = True
        return
    stats.setdefault("dropped_product_samples", []).append(
        {"cve": cve, "kept": kept, "dropped": dropped})


def _canonical_digest(records: list[dict]) -> str:
    return hashlib.sha256(json.dumps(records, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()


def _text(value, limit: int = 500) -> str:
    return " ".join(str(value).split())[:limit] if value else ""


def _clean_cwes(values) -> list[str]:
    found = []
    for value in values or []:
        for token in re.findall(r"CWE-\d+", str(value).upper()):
            normalized = f"CWE-{token.split('-')[1]}"
            if _CWE_ID.fullmatch(normalized) and normalized not in found:
                found.append(normalized)
    return found


def parse_cvelist(root: Path) -> tuple[list[dict], dict]:
    """Walk a cvelistV5 checkout and project CVE records; layout independent."""
    records: dict[str, dict] = {}
    stats = {"files_seen": 0, "records_kept": 0, "skipped": 0, "dropped_products": 0}
    for path in sorted(root.rglob("CVE-*.json")):
        stats["files_seen"] += 1
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="strict"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            stats["skipped"] += 1
            continue
        cna = (data.get("containers", {}).get("cna") or {}) if isinstance(data, dict) else {}
        identifier = data.get("cveMetadata", {}).get("cveId") if isinstance(data, dict) else None
        if not isinstance(identifier, str) or not _CVE_ID.fullmatch(identifier):
            identifier = path.stem
            if not _CVE_ID.fullmatch(identifier):
                stats["skipped"] += 1
                continue
        descriptions = [d.get("value") for d in cna.get("descriptions", [])
                        if isinstance(d, dict) and str(d.get("lang", "")).startswith("en")]
        summary = _text(descriptions[0] if descriptions else "")
        cwes = _clean_cwes([d.get("cweId") for block in cna.get("problemTypes", [])
                            if isinstance(block, dict)
                            for d in block.get("descriptions", []) if isinstance(d, dict)])
        affected_versions: list[str] = []
        fixed_versions: list[str] = []
        component = ""
        for entry in cna.get("affected", []):
            if not isinstance(entry, dict):
                continue
            product = _text(entry.get("product"), limit=200)
            if not product:
                continue
            if not component:
                component = product
            elif product != component:
                stats["dropped_products"] = stats.get("dropped_products", 0) + 1
                _note_dropped(stats, identifier, component, product)
            for version in entry.get("versions", []):
                if not isinstance(version, dict):
                    continue
                value = _text(version.get("version"), limit=100)
                if value and value not in affected_versions:
                    affected_versions.append(value)
                bound = _text(version.get("lessThan"), limit=100)
                if bound and bound not in ("0", "?", "n/a") and bound not in fixed_versions:
                    fixed_versions.append(bound)
        if not component or not summary:
            stats["skipped"] += 1
            continue
        record = {"id": identifier, "cwe": cwes, "summary": summary,
                  "component": component,
                  "affected_versions": affected_versions,
                  "fixed_versions": fixed_versions,
                  "fixed_version_semantics": ("cvelist_lessThan_boundaries"
                                              if fixed_versions else "none"),
                  "source": "cvelistV5"}
        if records.setdefault(identifier, record) is record:
            stats["records_kept"] += 1
        else:
            stats["duplicate_ids"] = stats.get("duplicate_ids", 0) + 1
    return sorted(records.values(), key=lambda r: r["id"]), stats


def parse_osv(root: Path, ecosystems: set[str]) -> tuple[list[dict], dict]:
    """Walk an extracted OSV export and project CVE-aliased records."""
    records: dict[str, dict] = {}
    stats = {"files_seen": 0, "records_kept": 0, "skipped_non_cve": 0,
             "skipped_ecosystem": 0, "skipped_no_component": 0, "dropped_products": 0}
    for path in sorted(root.rglob("*.json")):
        stats["files_seen"] += 1
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="strict"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            stats["files_seen"] -= 1
            continue
        if not isinstance(data, dict) or not isinstance(data.get("affected"), list):
            continue
        aliases = [a for a in data.get("aliases", []) if isinstance(a, str)]
        identifier = next((a for a in aliases if _CVE_ID.fullmatch(a)), None)
        cve_origin = "alias" if identifier is not None else None
        if identifier is None and isinstance(data.get("id"), str) and _CVE_ID.fullmatch(data["id"]):
            identifier = data["id"]
            cve_origin = "id"
        if identifier is None:
            # OSS-Fuzz exports often carry no aliases at all; their CVE links
            # live in references. Derived ids are weaker evidence and are
            # labeled as such on the record.
            for reference in data.get("references", []):
                url = reference.get("url") if isinstance(reference, dict) else None
                if isinstance(url, str):
                    found = _CVE_ID.search(url)
                    if found:
                        identifier = found.group(0)
                        cve_origin = "reference"
                        break
        if identifier is None:
            stats["skipped_non_cve"] += 1
            continue
        summary = _text(data.get("summary")) or _text(data.get("details"), limit=500)
        component = ""
        affected_versions: list[str] = []
        fixed_versions: list[str] = []
        cwes: list[str] = []
        relevant = False
        for entry in data["affected"]:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package") or {}
            if str(package.get("ecosystem", "")) not in ecosystems:
                continue
            relevant = True
            product = _text(package.get("name"), limit=200)
            if not product:
                continue
            if not component:
                component = product
            elif product != component:
                stats["dropped_products"] = stats.get("dropped_products", 0) + 1
                _note_dropped(stats, identifier, component, product)
            for value in entry.get("versions", []):
                value = _text(value, limit=100)
                if value and value not in affected_versions:
                    affected_versions.append(value)
            for version_range in entry.get("ranges", []):
                if not isinstance(version_range, dict):
                    continue
                for event in version_range.get("events", []):
                    if isinstance(event, dict):
                        fixed = _text(event.get("fixed"), limit=100)
                        if fixed and fixed not in fixed_versions:
                            fixed_versions.append(fixed)
            specific = entry.get("database_specific") or {}
            if isinstance(specific, dict):
                for cwe_id in specific.get("cwe_ids", []):
                    for normalized in _clean_cwes([cwe_id]):
                        if normalized not in cwes:
                            cwes.append(normalized)
        if not relevant:
            stats["skipped_ecosystem"] += 1
            continue
        if not component or not summary:
            stats["skipped_no_component"] += 1
            continue
        records.setdefault(identifier, {"id": identifier, "cwe": cwes,
                                        "summary": summary, "component": component,
                                        "affected_versions": affected_versions,
                                        "fixed_versions": fixed_versions,
                                        "fixed_version_semantics": ("osv_fixed_events"
                                                                    if fixed_versions
                                                                    else "none"),
                                        "cve_origin": cve_origin or "alias",
                                        "source": f"osv:{data.get('id', 'export')}"})
        stats["records_kept"] += 1
    return sorted(records.values(), key=lambda r: r["id"]), stats


def merge_sources(parsed: list[tuple[list[dict], str]]) -> list[dict]:
    """First source per CVE id wins; later sources only fill missing ids."""
    merged: dict[str, dict] = {}
    for records, _origin in parsed:
        for record in records:
            merged.setdefault(record["id"], record)
    return sorted(merged.values(), key=lambda r: r["id"])


def build_kb(cvelist_root: Path | None, osv_root: Path | None, out_dir: Path, *,
             snapshot_version: str, osv_ecosystems: set[str] | None = None,
             max_records_per_shard: int = 2000) -> dict:
    if max_records_per_shard < 1:
        raise ValueError("max_records_per_shard must be positive")
    ecosystems = osv_ecosystems if osv_ecosystems is not None else {"OSS-Fuzz"}
    parsed = []
    source_stats = {}
    if cvelist_root is not None:
        records, stats = parse_cvelist(Path(cvelist_root))
        parsed.append((records, "cvelistV5"))
        source_stats["cvelistV5"] = stats
    if osv_root is not None:
        records, stats = parse_osv(Path(osv_root), ecosystems)
        parsed.append((records, "osv"))
        source_stats["osv"] = stats
    if not parsed:
        raise ValueError("at least one source directory is required")
    merged = merge_sources(parsed)
    out_dir = Path(out_dir)
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    # Build into a staging directory and swap atomically; a failed build leaves
    # any previous output untouched and the swap replaces stale shards wholly.
    staging = Path(tempfile.mkdtemp(prefix=out_dir.name + ".staging-", dir=str(out_dir.parent)))
    try:
        shards = []
        for index in range(0, len(merged), max_records_per_shard):
            chunk = merged[index:index + max_records_per_shard]
            shard_name = f"kb_part_{len(shards):04d}.json"
            shard_path = staging / shard_name
            payload = json.dumps({"schema": SHARD_SCHEMA, "records": chunk},
                                 ensure_ascii=False, indent=1) + "\n"
            if len(payload.encode("utf-8")) > _MAX_SHARD_BYTES:
                raise ValueError(f"shard {shard_name} exceeds {_MAX_SHARD_BYTES} bytes; "
                                 f"lower max_records_per_shard")
            shard_path.write_bytes(payload.encode("utf-8"))
            # Round-trip through the canonical loader so bad output fails at build time.
            load_records(shard_path)
            shards.append({"file": shard_name, "count": len(chunk),
                           "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest()})
        manifest = {"schema": MANIFEST_SCHEMA, "snapshot_version": snapshot_version,
                    "records_total": len(merged),
                    "records_sha256": _canonical_digest(merged),
                    "shards": shards, "source_stats": source_stats}
        manifest_path = staging / "manifest.json"
        manifest_path.write_bytes((json.dumps(manifest, ensure_ascii=False, indent=1)
                                   + "\n").encode("utf-8"))
        # Validate the staged output as a whole before the swap.
        load_sharded_kb(staging)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    if out_dir.exists():
        backup = Path(tempfile.mkdtemp(prefix=out_dir.name + ".previous-",
                                       dir=str(out_dir.parent)))
        os.rename(out_dir, backup / "previous")
        try:
            os.rename(staging, out_dir)
        except BaseException:
            os.rename(backup / "previous", out_dir)
            shutil.rmtree(staging, ignore_errors=True)
            raise
        shutil.rmtree(backup, ignore_errors=True)
    else:
        os.rename(staging, out_dir)
    return manifest


def load_sharded_kb(kb_dir: Path) -> dict:
    """Merge shards through the canonical loader; verify digests and duplicates."""
    kb_dir = Path(kb_dir)
    manifest = json.loads((kb_dir / "manifest.json").read_text(encoding="utf-8-sig"))
    if manifest.get("schema") != MANIFEST_SCHEMA or not isinstance(manifest.get("shards"), list):
        raise ValueError("invalid knowledge-base manifest")
    records: list[dict] = []
    seen: set[str] = set()
    for shard in manifest["shards"]:
        if not isinstance(shard, dict) or not isinstance(shard.get("file"), str):
            raise ValueError("invalid manifest shard entry")
        entry = pathlib.PurePosixPath(shard["file"])
        if entry.is_absolute() or ".." in entry.parts:
            raise ValueError(f"manifest shard entry escapes kb directory: {shard['file']}")
        shard_path = kb_dir / entry
        if not shard_path.resolve().is_relative_to(kb_dir.resolve()):
            raise ValueError(f"manifest shard entry resolves outside kb directory: {shard['file']}")
        raw = shard_path.read_bytes()
        if "sha256" in shard and hashlib.sha256(raw).hexdigest() != shard["sha256"]:
            raise ValueError(f"shard digest mismatch: {shard['file']}")
        database = load_records(shard_path)
        for record in database["records"]:
            if record["id"] in seen:
                raise ValueError(f"duplicate id across shards: {record['id']}")
            seen.add(record["id"])
            records.append(record)
    digest = _canonical_digest(records)
    if manifest.get("records_total") != len(records):
        raise ValueError("manifest record count differs from shards")
    if manifest.get("records_sha256") != digest:
        raise ValueError("manifest records digest differs from shards")
    return {"schema": SHARD_SCHEMA, "records": records, "records_sha256": digest,
            "snapshot_version": manifest.get("snapshot_version"), "manifest": manifest}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline CVE knowledge-base sync")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="normalize local sources into sharded schema-0.1 KB")
    build.add_argument("--out", type=Path, required=True)
    build.add_argument("--snapshot", required=True, help="snapshot version label, e.g. 2026-09-14")
    build.add_argument("--cvelist", type=Path, help="local cvelistV5 checkout")
    build.add_argument("--osv", type=Path, help="extracted OSV export directory")
    build.add_argument("--osv-ecosystem", action="append", default=None,
                       help="OSV ecosystem to keep (repeatable; default OSS-Fuzz)")
    build.add_argument("--max-records-per-shard", type=int, default=2000)
    verify = sub.add_parser("verify", help="verify a sharded knowledge base")
    verify.add_argument("--kb", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            ecosystems = set(args.osv_ecosystem) if args.osv_ecosystem else None
            manifest = build_kb(args.cvelist, args.osv, args.out,
                                snapshot_version=args.snapshot,
                                osv_ecosystems=ecosystems,
                                max_records_per_shard=args.max_records_per_shard)
            print(json.dumps({"status": "built", "records": manifest["records_total"],
                              "shards": len(manifest["shards"]),
                              "records_sha256": manifest["records_sha256"]},
                             ensure_ascii=True))
        else:
            database = load_sharded_kb(args.kb)
            print(json.dumps({"status": "ok", "records": len(database["records"]),
                              "snapshot_version": database["snapshot_version"],
                              "records_sha256": database["records_sha256"]},
                             ensure_ascii=True))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
