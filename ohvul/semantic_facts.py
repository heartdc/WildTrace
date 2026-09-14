"""Deterministic, local C/C++ semantic facts for downstream candidate rules.

This is deliberately a conservative lexical layer.  It does not claim to be a
compiler-grade AST and never upgrades a fact into a vulnerability verdict.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from pathlib import Path


@dataclass(frozen=True)
class SemanticFact:
    kind: str
    source_file: str
    line: int
    function: str | None = None
    symbol: str | None = None
    text: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


_FUNCTION = re.compile(
    r"(?:^|\s)(?:[A-Za-z_][\w:\s*&<>~]*\s+)?([A-Za-z_]\w*(?:::\w+)*)\s*\([^;{}]*\)\s*\{",
)
_CALL = re.compile(r"\b([A-Za-z_]\w*(?:::\w+)*)\s*\(")
_ALLOC = re.compile(r"\b(?:new|malloc|calloc|realloc)\b")
_RELEASE = re.compile(r"\b(?:delete|free)\s*(?:\[\s*\])?\s*\(?\s*([A-Za-z_]\w*)")
_COPY = re.compile(r"\b(memcpy|memmove|strcpy|strncpy|sprintf|snprintf)\s*\(")
_DEREF = re.compile(r"(?:->|\*\s*[A-Za-z_]\w*)")


def extract_facts(path: Path, *, root: Path | None = None) -> list[SemanticFact]:
    """Extract conservative facts from one local C/C++ file."""
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError("source file is required")
    root = Path(root).resolve() if root else path.parent
    if not path.is_relative_to(root):
        raise ValueError("source file escapes root")
    relative = path.relative_to(root).as_posix()
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    facts: list[SemanticFact] = []
    current: str | None = None
    for number, line in enumerate(lines, 1):
        match = _FUNCTION.search(line)
        if match:
            current = match.group(1)
            facts.append(SemanticFact("function", relative, number, current, current, line.strip()))
        for call in _CALL.finditer(line):
            symbol = call.group(1)
            if symbol not in {"if", "for", "while", "switch", "catch"}:
                facts.append(SemanticFact("call", relative, number, current, symbol, line.strip()))
        if _ALLOC.search(line):
            facts.append(SemanticFact("allocation", relative, number, current, None, line.strip()))
        release = _RELEASE.search(line)
        if release:
            facts.append(SemanticFact("release", relative, number, current, release.group(1), line.strip()))
        copy = _COPY.search(line)
        if copy:
            facts.append(SemanticFact("copy", relative, number, current, copy.group(1), line.strip()))
        if _DEREF.search(line):
            facts.append(SemanticFact("dereference", relative, number, current, None, line.strip()))
    return facts


def extract_tree(root: Path, relative_files: list[str]) -> list[dict]:
    """Extract and serialize facts for an explicit local file list."""
    root = Path(root).resolve()
    facts = []
    for relative in relative_files:
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root):
            raise ValueError("source file escapes root")
        facts.extend(extract_facts(candidate, root=root))
    return [fact.to_dict() for fact in facts]
