"""Deterministic semantic candidate rules built on local facts."""
from __future__ import annotations

import re
from pathlib import Path
from .semantic_facts import SemanticFact, extract_facts
from .domain.evidence import make_bundle

_COPY = re.compile(r"\b(memcpy|memmove|strncpy|snprintf)\s*\(([^)]*)\)")
_LENGTH_SOURCE = re.compile(r"\b(strlen|strnlen|read|recv|memcpy)\s*\(")
_GUARD = re.compile(r"\b(?:sizeof|std::min|min|bounded|limit|max_len|capacity)\b|<\s*(?:sizeof|[0-9]+)")


def length_candidates(path: Path, *, root: Path | None = None) -> list[dict]:
    """Find copy-size paths that require review; never confirms a flaw."""
    path = Path(path).resolve()
    root = Path(root).resolve() if root else path.parent
    facts = extract_facts(path, root=root)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    functions = [f for f in facts if f.kind == "function"]
    copies = [f for f in facts if f.kind == "copy" and f.symbol in {"memcpy", "memmove", "strncpy", "snprintf"}]
    candidates = []
    for copy in copies:
        line = lines[copy.line - 1]
        match = _COPY.search(line)
        if not match:
            continue
        args = [x.strip() for x in match.group(2).split(",")]
        size_arg = args[2] if len(args) >= 3 else ""
        start = max(0, copy.line - 6)
        context = lines[start:copy.line]
        source_lines = [index + 1 for index, text in enumerate(context, start=start)
                        if index + 1 != copy.line and _LENGTH_SOURCE.search(text)]
        guard_lines = [index + 1 for index, text in enumerate(context, start=start) if _GUARD.search(text)]
        if not source_lines and not size_arg:
            continue
        candidates.append({
            "kind": "length_propagation_candidate",
            "status": "candidate",
            "source_file": path.relative_to(root).as_posix(),
            "function": copy.function,
            "sink": {"kind": copy.symbol, "line": copy.line, "size_expression": size_arg},
            "source_lines": source_lines,
            "guard_lines": guard_lines,
            "evidence": [
                {"kind": "copy_sink", "line": copy.line, "symbol": copy.symbol},
                *[{"kind": "length_source", "line": line} for line in source_lines],
                *[{"kind": "guard_or_bound", "line": line} for line in guard_lines],
            ],
            "review_questions": [
                "Is the size expression bounded by the destination capacity?",
                "Can the source length originate from an untrusted or IPC input?",
                "Does an integer conversion change the validated length?",
            ],
        })
    return candidates


def cross_function_length_candidates(root: Path, relative_files: list[str]) -> list[dict]:
    """Link a caller's length expression to a callee copy sink conservatively."""
    root = Path(root).resolve()
    sources = {}
    for relative in relative_files:
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("source file escapes root or is missing")
        sources[relative] = path.read_text(encoding="utf-8", errors="replace").splitlines()
    callees = {}
    for relative, lines in sources.items():
        for number, line in enumerate(lines, 1):
            match = re.search(r"\b(?:void|int|size_t|bool|char\s*\*)\s+(\w+)\s*\([^)]*\b(\w+)\s*\)\s*\{", line)
            if match:
                name, size_param = match.groups()
                for sink_line in range(number, min(len(lines), number + 80)):
                    sink = _COPY.search(lines[sink_line])
                    if sink and re.search(r"\b" + re.escape(size_param) + r"\b", sink.group(2)):
                        callees[name] = (relative, number, sink_line + 1, size_param)
                        break
    candidates = []
    for relative, lines in sources.items():
        for number, line in enumerate(lines, 1):
            for name, (callee_file, callee_start, sink_line, size_param) in callees.items():
                if number == callee_start and relative == callee_file:
                    continue
                call = re.search(r"\b" + re.escape(name) + r"\s*\(([^)]*)\)", line)
                if not call:
                    continue
                args = [x.strip() for x in call.group(1).split(",")]
                if not args:
                    continue
                length_arg = args[-1]
                prior = "\n".join(lines[max(0, number - 6):number + 1])
                if not _LENGTH_SOURCE.search(prior):
                    continue
                candidates.append({
                    "kind": "cross_function_length_propagation_candidate",
                    "status": "candidate",
                    "caller": {"source_file": relative, "call_line": number, "callee": name, "length_argument": length_arg},
                    "callee": {"source_file": callee_file, "definition_line": callee_start, "sink_line": sink_line, "size_parameter": size_param},
                    "evidence": [{"kind": "caller_length_source", "source_file": relative, "line": number - 1},
                                 {"kind": "callee_copy_sink", "source_file": callee_file, "line": sink_line}],
                    "review_questions": ["Does the caller length reach the callee unchanged?", "Is the destination capacity checked before the copy?"]
                })
    return candidates


def candidates_to_audit_result(candidates: list[dict], *, root: Path,
                               source_snapshot_sha256: str | None = None) -> dict:
    """Project semantic candidates into schema 0.3 without changing verdict."""
    root = Path(root).resolve()
    bundles, findings = [], []
    for index, candidate in enumerate(candidates, 1):
        if not isinstance(candidate, dict) or candidate.get("status") != "candidate":
            raise ValueError("semantic candidate must remain candidate")
        if "sink" in candidate:
            file_name = candidate["source_file"]
            line = candidate["sink"]["line"]
        else:
            file_name = candidate["callee"]["source_file"]
            line = candidate["callee"]["sink_line"]
        evidence = {"semantic_candidate": candidate}
        bundle = make_bundle("static_scan", {"root": str(root), "file": file_name, "line": line}, evidence=evidence)
        bundles.append(bundle.to_dict())
        findings.append({"alert_id": f"AL-SEM-{index:06d}", "source": "wildtrace-semantic-rules",
                         "cwe_candidate": "CWE-120", "rule": candidate["kind"],
                         "description": "Length propagation requires manual review",
                         "location": {"file": file_name, "line": line},
                         "evidence": evidence, "evidence_id": bundle.evidence_id, "status": "candidate"})
    scan = {"root": str(root), "files_scanned": len({f["location"]["file"] for f in findings}),
            "engine": "wildtrace-semantic", "engine_version": "0.1"}
    if source_snapshot_sha256 is not None:
        scan["source_snapshot_sha256"] = source_snapshot_sha256
    return {"schema_version": "0.3", "scan": scan, "findings": findings,
            "evidence_bundles": bundles,
            "safety": {"local_only": True, "no_execution": True, "no_network": True}}
