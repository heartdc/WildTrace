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
        error_path = Path(error.get("source_file", "")).as_posix()
        for case_id in expected:
            matches = (error_path == source_paths[case_id]) if case_id in source_paths else file_name.startswith(case_id)
            if matches:
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
    return {"benchmark_schema": "engine-0.1", "metric_scope": "file_cwe_presence", "cases": len(expected),
            "candidate_metrics": {"tp": tp, "fp": fp, "fn": fn,
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None},
            "evaluated_cases": len(evaluated), "input_unavailable_cases": len(unavailable),
            "disclaimer": "File/CWE presence statistics, not per-alert accuracy; input-unavailable cases excluded; no vulnerability verdict."}


def _relative_path(value: object) -> bool:
    """Accept canonical, case-sensitive POSIX paths relative to scan.root only."""
    return (isinstance(value, str) and bool(value) and "\\" not in value
            and ":" not in value and "\x00" not in value
            and all(part not in {"", ".", ".."} for part in value.split("/")))


def _maximum_location_matches(observed: list[tuple], expected: list[tuple]) -> int:
    """Iterative augmenting paths: deterministic maximum one-to-one matching."""
    observed = sorted(observed)
    expected = sorted(expected)
    edges = [[j for j, (cwe, start, end, _) in enumerate(expected)
              if item[0] == cwe and start <= item[1] <= end] for item in observed]
    assigned = {}
    matched = {}
    visits = 0
    for origin in range(len(observed)):
        queue, parents, seen = [origin], {}, {origin}
        terminal = None
        for node in queue:
            for right in edges[node]:
                visits += 1
                if visits > 2000000:
                    raise ValueError("matching exceeds 2000000-edge-visit limit")
                if right in parents:
                    continue
                parents[right] = node
                if right not in assigned:
                    terminal = right
                    break
                other = assigned[right]
                if other not in seen:
                    queue.append(other)
                    seen.add(other)
            if terminal is not None:
                break
        while terminal is not None:
            left = parents[terminal]
            previous = matched.get(left)
            assigned[terminal] = left
            matched[left] = terminal
            terminal = previous
    return len(matched)


def evaluate_location(cases: list[dict], result: dict) -> dict:
    """Evaluate reviewed location annotations, schema engine-location-0.1.

    Each case has a unique id and canonical POSIX root-relative source_file,
    source_snapshot_sha256 matching result.scan.source_snapshot_sha256,
    review_status='reviewed', nonblank reviewer/reviewed_at declarations, label,
    and expected_findings=[{id, cwe, line_start, line_end}]. Lines are inclusive
    positive integers. Candidate labels require findings; safe_control and
    reviewed_suppressed require none (an omitted list is allowed for these).
    Review metadata records a declaration, not verification of human identity.

    Findings use schema 0.3 location.file/location.line/cwe_candidate. A line
    inside the annotated range and the same CWE creates a matching edge.
    Maximum bipartite matching counts each alert and annotation at most once.
    Unknown CWEs count as FP and also appear in unknown_cwe_findings. Unlabelled
    files are outside the benchmark and reported separately. Exact input-error
    paths exclude the affected cases. Invalid/unbound annotations never fall
    back to file-level metrics. Limits bound matching time and memory.
    Only completed scans or partial scans with errors exactly associated with
    annotated files are evaluable. Absolute input-error paths are rejected;
    callers must provide canonical scan-root-relative paths before evaluation.
    """
    report = {"benchmark_schema": "engine-location-0.1", "metric_scope": "location_cwe_one_to_one",
              "status": "not_evaluable", "candidate_metrics": None,
              "disclaimer": "Reviewed candidate-location statistics only; no vulnerability verdict."}
    reasons = []
    if not isinstance(cases, list) or not isinstance(result, dict) or result.get("schema_version") != "0.3":
        return {**report, "reasons": ["invalid benchmark input or result schema"]}
    if result.get("status") not in ("completed", "partial"):
        return {**report, "reasons": ["scan status must be completed or partial"]}
    scan = result.get("scan")
    snapshot = scan.get("source_snapshot_sha256") if isinstance(scan, dict) else None
    if not isinstance(snapshot, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", snapshot):
        reasons.append("result scan requires source_snapshot_sha256")
    if not cases:
        reasons.append("no reviewed cases")
    if len(cases) > 5000:
        return {**report, "reasons": ["benchmark exceeds 5000-case limit"]}
    annotation_count = 0
    for case in cases:
        expected = case.get("expected_findings") if isinstance(case, dict) else None
        if isinstance(expected, list):
            annotation_count += len(expected)
            if annotation_count > 5000:
                return {**report, "reasons": ["benchmark exceeds 5000-total-annotation limit"]}
    annotations, case_ids, finding_ids = {}, set(), set()
    for index, case in enumerate(cases):
        prefix = f"case[{index}]"
        if not isinstance(case, dict):
            reasons.append(f"{prefix}: expected object")
            continue
        case_id, path = case.get("id"), case.get("source_file")
        if not isinstance(case_id, str) or not case_id.strip() or case_id in case_ids:
            reasons.append(f"{prefix}: missing or duplicate id")
        else:
            case_ids.add(case_id)
        if not _relative_path(path) or path in annotations:
            reasons.append(f"{prefix}: source_file must be unique canonical root-relative path")
            continue
        if case.get("review_status") != "reviewed" or any(
                not isinstance(case.get(key), str) or not case[key].strip()
                for key in ("reviewer", "reviewed_at")):
            reasons.append(f"{prefix}: explicit completed review declaration required")
        digest = case.get("source_snapshot_sha256")
        if not isinstance(digest, str) or not isinstance(snapshot, str) or digest.lower() != snapshot.lower():
            reasons.append(f"{prefix}: source snapshot missing or mismatched")
        label = case.get("label")
        if label not in {"candidate", "candidate_requires_context", "safe_control", "reviewed_suppressed"}:
            reasons.append(f"{prefix}: invalid label")
        safe = label in {"safe_control", "reviewed_suppressed"}
        expected = case.get("expected_findings", [] if safe else None)
        annotations[path] = []
        if not isinstance(expected, list) or (not safe and not expected) or (safe and expected):
            reasons.append(f"{prefix}: expected_findings missing or inconsistent with label")
            continue
        if len(expected) > 5000:
            reasons.append(f"{prefix}: exceeds 5000-annotation limit")
            continue
        for item in expected:
            if not isinstance(item, dict):
                reasons.append(f"{prefix}: invalid expected finding")
                continue
            fid, cwe = item.get("id"), item.get("cwe")
            start, end = item.get("line_start"), item.get("line_end")
            if (not isinstance(fid, str) or not fid.strip() or fid in finding_ids
                    or not isinstance(cwe, str) or not re.fullmatch(r"CWE-[1-9][0-9]*", cwe)
                    or type(start) is not int or type(end) is not int or not 1 <= start <= end):
                reasons.append(f"{prefix}: invalid or duplicate expected finding")
                continue
            finding_ids.add(fid)
            annotations[path].append((cwe, start, end, fid))
    errors, findings = result.get("input_errors", []), result.get("findings")
    if not isinstance(errors, list) or not isinstance(findings, list):
        return {**report, "reasons": reasons + ["findings and input_errors must be lists"]}
    if len(findings) > 5000 or len(errors) > 5000 or len(finding_ids) > 5000:
        return {**report, "reasons": reasons + ["benchmark exceeds 5000-record limit"]}
    if result["status"] == "completed" and errors:
        reasons.append("completed scan contains input errors")
    unavailable = set()
    for error in errors:
        path = error.get("source_file") if isinstance(error, dict) else None
        if not _relative_path(path):
            reasons.append("input error requires canonical root-relative source_file")
        elif path in annotations:
            unavailable.add(path)
    if result["status"] == "partial" and not unavailable:
        reasons.append("partial scan requires input errors exactly associated with reviewed cases")
    observed = {path: [] for path in annotations}
    unknown, out_of_scope, excluded = 0, 0, 0
    for item in findings:
        loc = item.get("location") if isinstance(item, dict) else None
        if not isinstance(loc, dict) or not _relative_path(loc.get("file")):
            reasons.append("finding requires canonical root-relative location.file")
            continue
        path, line = loc["file"], loc.get("line")
        if path not in annotations:
            out_of_scope += 1
            continue
        if path in unavailable:
            excluded += 1
            continue
        if type(line) is not int or line < 1:
            reasons.append("in-scope finding requires positive integer location.line")
            continue
        cwe = item.get("cwe_candidate")
        if not isinstance(cwe, str) or not re.fullmatch(r"CWE-[1-9][0-9]*", cwe):
            cwe = ""
            unknown += 1
        observed[path].append((cwe, line))
    evaluated = sorted(set(annotations) - unavailable)
    if not evaluated:
        reasons.append("no available reviewed cases")
    if sum(len(observed[p]) * len(annotations[p]) for p in evaluated) > 1000000:
        reasons.append("matching exceeds 1000000-edge-comparison limit")
    if reasons:
        return {**report, "reasons": sorted(set(reasons))}
    try:
        tp = sum(_maximum_location_matches(observed[p], annotations[p]) for p in evaluated)
    except ValueError as exc:
        return {**report, "reasons": [str(exc)]}
    fp = sum(len(observed[p]) for p in evaluated) - tp
    fn = sum(len(annotations[p]) for p in evaluated) - tp
    return {**report, "status": "evaluable", "reasons": [], "cases": len(cases),
            "evaluated_cases": len(evaluated), "input_unavailable_cases": len(unavailable),
            "unknown_cwe_findings": unknown, "out_of_scope_findings": out_of_scope,
            "input_unavailable_findings": excluded,
            "candidate_metrics": {"tp": tp, "fp": fp, "fn": fn,
                                  "precision": tp / (tp + fp) if tp + fp else None,
                                  "recall": tp / (tp + fn) if tp + fn else None}}


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
    parser.add_argument("--location-metrics", action="store_true",
                        help="Require reviewed snapshot-bound location annotations; never fall back to file/CWE presence")
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
        evaluator = evaluate_location if args.location_metrics else evaluate
        report = evaluator(json.loads(args.cases.read_text(encoding="utf-8-sig")),
                           json.loads(args.result.read_text(encoding="utf-8-sig")))
        print(json.dumps(report, indent=2))
        if args.location_metrics and report["status"] == "not_evaluable":
            return 2
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"INVALID: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
