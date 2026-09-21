"""Convert partner-collected CVE records into runtime KB plus evidence sidecar.

Partner batches use the rich collection format (structured fixed_versions with
per-branch commits and per-file diffs). The runtime knowledge base requires
schema 0.1 with flat string version lists, so this tool splits each batch into:

- <out>/records_runtime.json : load_records-compatible records (extra fields
  preserved; components normalized to lowercase registry spellings)
- <out>/records_evidence.json: partner-evidence-sidecar-0.1 keeping every
  commit URL and diff verbatim for patch-comparison and PoC analysis

Records without any fixed version go to the sidecar only (unresolved). The
runtime file is validated through the canonical loader before anything is
written; a batch that cannot validate fails without partial output.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ohvul.knowledge_base import load_records  # noqa: E402

RUNTIME_SCHEMA = "0.1"
SIDECAR_SCHEMA = "partner-evidence-sidecar-0.1"


def _flat_versions(rich_fixed):
    flat = []
    for entry in rich_fixed:
        if isinstance(entry, str):
            version = entry.strip()
        elif isinstance(entry, dict):
            version = str(entry.get("fixed_version") or "").strip()
        else:
            version = ""
        if version and version not in flat:
            flat.append(version)
    return flat


def convert(records):
    runtime, sidecar, unresolved, normalizations = [], [], [], []
    for record in records:
        identifier = record.get("id")
        component = str(record.get("component") or "").strip()
        if not identifier or not component:
            raise ValueError("partner record requires id and component")
        normalized = component.lower()
        if normalized != component:
            normalizations.append({"id": identifier, "from": component, "to": normalized})
        flat = _flat_versions(record.get("fixed_versions", []))
        sidecar.append({
            "id": identifier, "component": normalized,
            "structured_fixed": record.get("fixed_versions", []),
            "evidence_refs": record.get("evidence_refs", []),
            "source_date": record.get("source_date"),
        })
        if not flat:
            unresolved.append(identifier)
            continue
        runtime.append({
            "id": identifier,
            "cwe": list(record.get("cwe") or []),
            "summary": str(record.get("summary") or "").strip(),
            "component": normalized,
            "affected_versions": [str(a) for a in record.get("affected_versions", []) if a],
            "fixed_versions": flat,
            "fixed_version_semantics": "oh_advisory_version_branches",
            "source": str(record.get("source") or "").strip(),
            "source_record": str(record.get("source_record") or ""),
            "review_status": str(record.get("review_status") or "unreviewed"),
        })
    return runtime, sidecar, unresolved, normalizations


def import_batch(batch_path: Path, out_dir: Path) -> dict:
    batch = json.loads(Path(batch_path).read_text(encoding="utf-8-sig"))
    records = batch.get("records") if isinstance(batch, dict) else batch
    if not isinstance(records, list) or not records:
        raise ValueError("partner batch must be a non-empty records list")
    runtime, sidecar, unresolved, normalizations = convert(records)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    runtime_doc = {"schema": RUNTIME_SCHEMA, "records": runtime}
    runtime_path = out_dir / "records_runtime.json"
    sidecar_path = out_dir / "records_evidence.json"
    # Validate through the canonical loader BEFORE writing anything.
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                     encoding="utf-8") as probe:
        json.dump(runtime_doc, probe, ensure_ascii=False)
        probe_path = probe.name
    try:
        database = load_records(Path(probe_path))
    finally:
        Path(probe_path).unlink(missing_ok=True)
    runtime_path.write_text(json.dumps(runtime_doc, ensure_ascii=False, indent=1) + "\n",
                            encoding="utf-8")
    sidecar_path.write_text(json.dumps(
        {"schema": SIDECAR_SCHEMA, "records": sidecar}, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8")
    return {"records_total": len(records), "runtime_records": len(runtime),
            "unresolved_no_fixed": unresolved,
            "component_normalizations": normalizations,
            "records_sha256": database["records_sha256"]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch", type=Path, help="partner records.json (rich format)")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = import_batch(args.batch, args.out_dir)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: v for k, v in result.items()
                      if k != "component_normalizations"}, ensure_ascii=True))
    for entry in result["component_normalizations"]:
        print(f"normalized component: {entry['id']}: {entry['from']} -> {entry['to']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
