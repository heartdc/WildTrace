"""Deterministic semantic candidate rules built on local facts."""
from __future__ import annotations

import re
from pathlib import Path
from .semantic_facts import SemanticFact, extract_facts

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
