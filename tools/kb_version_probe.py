"""Probe component versions in an OpenHarmony tree against the local CVE KB.

Reads third_party/*/README.OpenSource (the OH convention carrying the vendored
upstream version), matches each (component, version) against one or more
schema-0.1 knowledge bases, and writes a candidate report:

- exact: the observed version appears in a record's affected_versions
- unresolved: the component has records but the version did not match

Candidates only — a match is a review lead, never a vulnerability verdict.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ohvul.knowledge_base import load_records, match_records  # noqa: E402

_VERSION_LINE = re.compile(r"^\s*Version\s*[:：]\s*(\S+)\s*$", re.M | re.I)
_NAME_LINE = re.compile(r"^\s*Name\s*[:：]\s*(\S+)\s*$", re.M | re.I)
MAX_README_BYTES = 262144


def _read_manifest(readme: Path):
    """(name, version) declared by a README.OpenSource, or None.

    Real OpenHarmony trees carry a JSON-array manifest ("Name" / "Version
    Number" keys, CRLF endings); the older plain-text Name:/Version: layout
    stays supported. The first entry declaring a version wins."""
    raw = readme.read_bytes()[:MAX_README_BYTES]
    text = raw.decode("utf-8", "replace")
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            # Vendored manifests in the wild sometimes carry trailing commas;
            # tolerate them rather than skipping the whole component.
            entries = json.loads(re.sub(r",(\s*[}\]])", r"\1", stripped))
        except (ValueError, TypeError):
            return None
        if not isinstance(entries, list):
            return None
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("Name") or entry.get("name")
            version = entry.get("Version Number") or entry.get("Version")
            if isinstance(version, str) and version.strip():
                return ((name.strip() if isinstance(name, str) and name.strip() else None),
                        version.strip())
        return None
    version = _VERSION_LINE.search(text)
    if version is None:
        return None
    extracted = _NAME_LINE.search(text)
    return (extracted.group(1) if extracted else None, version.group(1))


def probe_component_versions(source_root: Path):
    """Yield (directory, readme_name, extracted_name, version) per component."""
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise ValueError("source root must be an existing directory")
    third_party = root / "third_party"
    base = third_party if third_party.is_dir() else root
    for readme in sorted(base.rglob("README.OpenSource")):
        if not readme.is_file():
            continue
        manifest = _read_manifest(readme)
        if manifest is None:
            continue
        name, version = manifest
        yield (readme.parent.relative_to(root).as_posix(), readme.name,
               name if name else readme.parent.name, version)


_VERSION_TOKEN = re.compile(r"^[vV]?\d+(\.\d+)+$")


def _component_alias(component: str) -> str:
    normalized = component.strip().lower()
    # Some manifests embed the version in the Name field ("OpenSSL 3.0.9");
    # strip trailing version-like tokens so the alias can match KB spellings.
    while normalized:
        head, _, tail = normalized.rpartition(" ")
        if tail and head and _VERSION_TOKEN.match(tail):
            normalized = head
        else:
            break
    aliases = {"third_party_cjson": "cjson", "cjson": "cjson"}
    return aliases.get(normalized, normalized)


def probe(source_root: Path, kb_paths) -> dict:
    databases = []
    for path in kb_paths:
        loaded = load_records(Path(path))
        loaded["_by_component"] = {}
        for record in loaded["records"]:
            loaded["_by_component"].setdefault(
                _component_alias(record["component"]), []).append(record)
        databases.append(loaded)
    components, exact, unresolved = [], [], []
    for directory, readme, name, version in probe_component_versions(source_root):
        alias = _component_alias(name) or _component_alias(Path(directory).name)
        entry = {"directory": directory, "readme": readme, "name": name,
                 "version": version, "alias": alias}
        components.append(entry)
        matched = False
        for database in databases:
            if alias in database["_by_component"]:
                matches = match_records({"records": database["_by_component"][alias],
                                         "records_sha256": database["records_sha256"]},
                                        alias, version)
                for match in matches:
                    if match["match_level"] == "exact":
                        exact.append({**entry, "cve": match["id"],
                                      "kb_records_sha256": database["records_sha256"]})
                        matched = True
                if not matched:
                    unresolved.append({**entry,
                                       "kb_record_count": len(database["_by_component"][alias])})
    return {"schema": "kb-version-probe-0.1",
            "source_root": str(Path(source_root).resolve()),
            "components_seen": len(components),
            "exact_candidates": exact,
            "unresolved_components": unresolved,
            "disclaimer": "Candidates only; a version match is a review lead, "
                          "not a vulnerability verdict."}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_root", type=Path,
                        help="OpenHarmony source root (third_party/ is auto-detected)")
    parser.add_argument("--kb", type=Path, action="append", required=True,
                        help="schema-0.1 knowledge base file (repeatable)")
    parser.add_argument("--output", type=Path, help="optional JSON report path")
    args = parser.parse_args(argv)
    try:
        report = probe(args.source_root, args.kb)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(report, ensure_ascii=False, indent=1)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    summary = {"components_seen": report["components_seen"],
               "exact_candidates": len(report["exact_candidates"]),
               "unresolved_components": len(report["unresolved_components"])}
    print(json.dumps(summary, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
