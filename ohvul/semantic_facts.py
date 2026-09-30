"""Deterministic, local C/C++ semantic facts for downstream candidate rules.

This is deliberately a conservative lexical layer.  It does not claim to be a
compiler-grade AST and never upgrades a fact into a vulnerability verdict.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from pathlib import Path
from bisect import bisect_right
from .source_scope import local_input_path, relative_paths, is_link
from .source_structure import MAX_SOURCE_BYTES, source_structure, function_at


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
    path = Path(path).absolute()
    if any(is_link(p) for p in (path, *path.parents)):
        raise ValueError("source path must not contain links")
    root = Path(root).absolute() if root else path.parent
    if any(is_link(p) for p in (root, *root.parents)) or not root.is_dir():
        raise ValueError('source root must be an existing unlinked directory')
    root = root.resolve()
    path = path.resolve()
    if not path.is_relative_to(root):
        raise ValueError("source file escapes root")
    relative = path.relative_to(root).as_posix()
    path = local_input_path(root, relative)
    if not path.is_file():
        raise ValueError("source file is required")
    with path.open('rb') as stream:
        raw = stream.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError('source byte budget exceeded')
    text = raw.decode('utf-8-sig')
    structure = source_structure(text)
    lines = text.splitlines()
    facts: list[SemanticFact] = []
    for function in structure['functions']:
        number = function['name_line']
        facts.append(SemanticFact('function', relative, number, function['symbol'],
                                  function['symbol'], lines[number - 1].strip()))
    for call in structure['calls']:
        number = call['line']
        facts.append(SemanticFact('call', relative, number, call['function'],
                                  call['symbol'], lines[number - 1].strip()))
    for kind, pattern in (('allocation', _ALLOC), ('release', _RELEASE), ('copy', _COPY), ('dereference', _DEREF)):
        for match in pattern.finditer(structure['code']):
            number = bisect_right(structure['line_starts'], match.start())
            symbol = match.group(1) if kind in ('release', 'copy') else None
            facts.append(SemanticFact(kind, relative, number, function_at(structure, match.start()),
                                      symbol, lines[number - 1].strip()))
    return sorted(facts, key=lambda f: f.line)


def extract_tree(root: Path, relative_files: list[str]) -> list[dict]:
    """Extract and serialize facts for an explicit local file list."""
    root = Path(root).absolute()
    names = relative_paths(relative_files, nonempty=True)
    if any(is_link(p) for p in (root, *root.parents)) or not root.is_dir():
        raise ValueError('source root must be an existing unlinked directory')
    root = root.resolve()
    paths = [local_input_path(root, name) for name in names]
    if any(not path.is_file() for path in paths):
        raise ValueError('explicit source is missing')
    facts = []
    for candidate in paths:
        facts.extend(extract_facts(candidate, root=root))
    return [fact.to_dict() for fact in facts]
