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
        raw = readme.read_bytes()[:MAX_README_BYTES]
        text = raw.decode("utf-8", "replace")
        version = _VERSION_LINE.search(text)
        if version is None:
            continue
        extracted = _NAME_LINE.search(text)
        yield (readme.parent.relative_to(root).as_posix(), readme.name,
               extracted.group(1) if extracted else readme.parent.name,
               version.group(1))


def _component_alias(component: str) -> str:
    normalized = component.strip().lower()
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
