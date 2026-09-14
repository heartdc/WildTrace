"""Offline metrics for manually labelled engine candidate results."""
from __future__ import annotations
import json
import re
from pathlib import Path


def evaluate(cases: list[dict], result: dict) -> dict:
    if not isinstance(cases, list) or not isinstance(result, dict) or result.get("schema_version") != "0.3":
        raise ValueError("invalid engine benchmark input")
    expected = {}
    source_paths = {}
    labels = {"candidate", "candidate_requires_context", "reviewed_suppressed", "safe_control"}
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not isinstance(case.get("expected_cwe"), list):
            raise ValueError("invalid labelled case")
        if case.get("label") not in labels:
            raise ValueError("invalid labelled case label")
        if any(not isinstance(cwe, str) or not re.fullmatch(r"CWE-[1-9][0-9]*", cwe) for cwe in case["expected_cwe"]):
            raise ValueError("invalid expected CWE")
        if case["label"] in {"safe_control", "reviewed_suppressed"} and case["expected_cwe"]:
            raise ValueError("safe labels require empty expected_cwe")
        if case["id"] in expected:
            raise ValueError("duplicate labelled case")
        expected[case["id"]] = set(case["expected_cwe"])
        if case.get("source_file"):
            source_paths[case["id"]] = Path(case["source_file"]).as_posix()
    observed = {case_id: set() for case_id in expected}
    unavailable = set()
    for error in result.get("input_errors", []):
        file_name = Path(error.get("source_file", "")).name
        for case_id in expected:
            if file_name.startswith(case_id):
                unavailable.add(case_id)
    for finding in result.get("findings", []):
        file_name = Path(finding.get("location", {}).get("file", "")).name
        finding_path = Path(finding.get("location", {}).get("file", "")).as_posix()
        for case_id in expected:
            matches = (finding_path == source_paths[case_id]) if case_id in source_paths else file_name.startswith(case_id)
            if matches and finding.get("cwe_candidate"):
                observed[case_id].add(finding["cwe_candidate"])
    evaluated = [k for k in expected if k not in unavailable]
    tp = sum(len(observed[k] & expected[k]) for k in evaluated)
    fp = sum(len(observed[k] - expected[k]) for k in evaluated)
    fn = sum(len(expected[k] - observed[k]) for k in evaluated)
    return {"benchmark_schema": "engine-0.1", "cases": len(expected),
            "candidate_metrics": {"tp": tp, "fp": fp, "fn": fn,
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None},
            "evaluated_cases": len(evaluated), "input_unavailable_cases": len(unavailable),
            "disclaimer": "Candidate-engine statistics only; input-unavailable cases excluded; no vulnerability verdict."}


def bootstrap_cases(result: dict, *, source_snapshot_sha256: str, component: str,
                    version: str) -> list[dict]:
    """Create unreviewed annotation drafts from result locations."""
    if not isinstance(result, dict) or result.get("schema_version") != "0.3":
        raise ValueError("schema 0.3 result required")
    if not isinstance(source_snapshot_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", source_snapshot_sha256):
        raise ValueError("source snapshot must be a SHA-256 hex digest")
    if not all(isinstance(x, str) and x.strip() for x in (component, version)):
        raise ValueError("snapshot, component and version are required")
    seen, cases = set(), []
    for finding in result.get("findings", []):
        path = finding.get("location", {}).get("file")
        if not isinstance(path, str) or path in seen:
            continue
        seen.add(path)
        cases.append({"id": Path(path).stem, "source_file": path,
                      "source_snapshot_sha256": source_snapshot_sha256,
                      "component": component, "version": version,
                      "expected_cwe": [], "label": "candidate_requires_context",
                      "reason": "待人工复核引擎规则、源码上下文和 CWE。",
                      "reviewer": "", "reviewed_at": ""})
    return cases


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, nargs="?")
    parser.add_argument("result", type=Path)
    parser.add_argument("--bootstrap-output", type=Path)
    parser.add_argument("--source-snapshot")
    parser.add_argument("--component")
    parser.add_argument("--version")
    args = parser.parse_args()
    try:
        if args.bootstrap_output:
            if not all(x is not None for x in (args.source_snapshot, args.component, args.version)):
                parser.error("bootstrap requires source-snapshot, component and version")
            result = json.loads(args.result.read_text(encoding="utf-8-sig"))
            drafts = bootstrap_cases(result, source_snapshot_sha256=args.source_snapshot,
                                     component=args.component, version=args.version)
            args.bootstrap_output.write_text(json.dumps(drafts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            return 0
        if args.cases is None:
            parser.error("cases is required unless --bootstrap-output is used")
        print(json.dumps(evaluate(json.loads(args.cases.read_text(encoding="utf-8-sig")),
                                 json.loads(args.result.read_text(encoding="utf-8-sig"))), indent=2))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"INVALID: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
