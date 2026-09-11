"""Conservative offline matching; exact versions are not impact confirmation."""
from __future__ import annotations
import json
from pathlib import Path
from ohvul.domain.evidence import make_bundle


def load_vulnerability_metadata(path: Path | None) -> list[dict]:
    if path is None:
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        raise ValueError("vulnerability metadata must be a JSON list")
    for index, record in enumerate(data):
        if not isinstance(record, dict):
            raise ValueError(f"record {index}: expected an object")
        for key in ("id", "component"):
            if not isinstance(record.get(key), str) or not record[key].strip():
                raise ValueError(f"record {index}: nonempty {key} required")
        if record.get("version") is not None and not isinstance(record["version"], str):
            raise ValueError(f"record {index}: version must be string or null")
    return data


def _version(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    return None if value.lower() in ("", "unknown", "unspecified", "*") else value


def match_components(components, records, *, metadata_source="local_metadata", metadata_digest=None):
    groups = []
    for component in components:
        name = component["name"]
        version = _version(component.get("version"))
        group = {"component": name, "version": version, "matches": [], "unresolved": []}
        for record in records:
            if str(record.get("component", "")).casefold() != name.casefold():
                continue
            expected = _version(record.get("version"))
            if version is not None and expected is not None and version != expected:
                continue
            status = "exact_version_candidate" if version and expected else "unknown"
            reason = "exact_version_equal" if status != "unknown" else "version_missing_or_unspecified"
            evidence = {"record_id": str(record.get("id", "")), "component": name,
                        "version": version, "record": record, "match_status": status,
                        "metadata_source": metadata_source, "metadata_digest": metadata_digest}
            bundle = make_bundle("known_vulnerability_match",
                                 {"component": name, "version": version,
                                  "metadata_source": metadata_source, "metadata_digest": metadata_digest}, evidence=evidence)
            item = {"id": record.get("id"), "cwe": record.get("cwe"),
                    "summary": record.get("summary"), "source": metadata_source,
                    "status": "candidate", "match_status": status, "reason": reason,
                    "evidence_id": bundle.evidence_id, "_metadata_record": dict(record), "_bundle": bundle.to_dict()}
            group["matches" if status != "unknown" else "unresolved"].append(item)
        groups.append(group)
    return groups


def strip_internal_bundles(groups):
    bundles = []
    for group in groups:
        for key in ("matches", "unresolved"):
            for item in group.get(key, []):
                bundle = item.pop("_bundle", None)
                if bundle:
                    bundles.append(bundle)
    return groups, bundles
