"""Function-scope rule drafts; candidates only, never vulnerability verdicts.

Draft rules reduce two known false-positive classes of the line-level scanner:
every-dereference CWE-476 hits and sizeof-only CWE-190 hits. Detection is
function-scoped via lightweight brace matching; strings containing braces are
not modeled (documented limitation for hand-written samples, not general C).
"""
from __future__ import annotations
import hashlib
import pathlib
import re
from datetime import datetime, timezone
from ohvul.domain.evidence import make_bundle, validate_bundle

EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}

_CONTROL_KEYWORDS = ("if", "for", "while", "switch", "else", "do", "return")
_NULLABLE_CALLS = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*(?:\(\s*[A-Za-z_]\w*\s*\*\s*\)\s*)?"
    r"([A-Za-z_]*alloc[A-Za-z_]*|getenv|strdup|fopen|realloc)\s*\(")
_TYPE_KEYWORDS = {"sizeof", "char", "int", "long", "short", "unsigned", "size_t",
                  "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t",
                  "int16_t", "int32_t", "int64_t", "void", "const", "struct"}
_SIZE_CALL = re.compile(r"\b(malloc|calloc|realloc|alloca|memcpy|memmove)\s*\(")
_DEREF = r"{var}\s*->|\*\s*{var}\b|{var}\s*\["
_NULL_CHECK = r"\b{var}\b\s*(?:==\s*NULL|!=\s*NULL)|NULL\s*(?:==|!=)\s*\b{var}\b|!\s*\b{var}\b|\b{var}\b\s*\("
_COPY_CALL = re.compile(r"\b(strcpy|strcat|sprintf|memcpy)\s*\(")
_LOCAL_ARRAY = re.compile(r"\bchar\s+([A-Za-z_]\w*)\s*\[\s*([0-9]+|[A-Za-z_]\w*)\s*\]\s*;")


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.strip().encode()).hexdigest()[:16]


def extract_functions(text: str) -> list[dict]:
    """Return [{'name','start','end','lines'}] with 1-based inclusive line numbers."""
    lines = text.splitlines()
    functions: list[dict] = []
    depth = 0
    header: tuple[str, int] | None = None
    for index, line in enumerate(lines, 1):
        stripped = line.strip()
        first_word = re.match(r"([A-Za-z_]\w*)", stripped)
        if (depth == 0 and header is None and "(" in stripped
                and stripped.endswith("{")
                and (not first_word or first_word.group(1) not in _CONTROL_KEYWORDS)):
            before_paren = stripped[:stripped.index("(")]
            identifiers = re.findall(r"[A-Za-z_]\w*", before_paren)
            header = (identifiers[-1] if identifiers else "<anonymous>", index)
        depth += line.count("{") - line.count("}")
        if header is not None and depth == 0:
            functions.append({"name": header[0], "start": header[1],
                              "end": index, "lines": lines[header[1] - 1:index]})
            header = None
        if depth < 0:
            depth = 0
    return functions


def _top_level_args(line: str, call_start: int) -> list[str] | None:
    """Split the argument list of the call whose '(' is at call_start."""
    depth = 0
    current: list[str] = []
    args: list[str] = []
    for position in range(call_start, len(line)):
        char = line[position]
        if char == "(":
            depth += 1
            if depth == 1:
                continue
        elif char == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(current))
                return args
        if depth >= 1:
            if char == "," and depth == 1:
                args.append("".join(current))
                current = []
            else:
                current.append(char)
    return None


def _size_operands(expression: str) -> set[str]:
    return {name for name in re.findall(r"[A-Za-z_]\w*", expression)
            if name not in _TYPE_KEYWORDS}


def _rule_integer_overflow(function: dict, file: str, root: str) -> list[dict]:
    hits: list[dict] = []
    for offset, line in enumerate(function["lines"]):
        if "ohvul:ignore" in line:
            continue
        for match in _SIZE_CALL.finditer(line):
            args = _top_level_args(line, match.start(1) + len(match.group(1)))
            if not args:
                continue
            size_expression = args[-1].strip()
            if not re.search(r"[+*]", size_expression):
                continue
            operands = _size_operands(size_expression)
            if not operands:
                continue
            guarded = any(
                operand in line_before and re.search(r"[<>]|<=|>=", line_before)
                for operand in operands
                for line_before in function["lines"][:offset]
                if operand in line_before)
            if guarded:
                continue
            hits.append({"cwe": "CWE-190", "rule": "integer-overflow-size-arg",
                         "detail": f"size expression '{size_expression}' uses unchecked operand(s) "
                                   f"{sorted(operands)}",
                         "line": function["start"] + offset, "code": line})
    return hits


def _rule_nullable_deref(function: dict, file: str, root: str) -> list[dict]:
    nullable: dict[str, int] = {}
    checked: dict[str, int] = {}
    hits: list[dict] = []
    for offset, line in enumerate(function["lines"], start=function["start"]):
        if "ohvul:ignore" in line:
            continue
        for match in _NULLABLE_CALLS.finditer(line):
            nullable.setdefault(match.group(1), offset)
        for var in list(nullable):
            if re.search(_NULL_CHECK.format(var=var), line):
                checked[var] = offset
            deref = re.search(_DEREF.format(var=var), line)
            if (deref and offset > nullable[var] and var not in checked):
                hits.append({"cwe": "CWE-476", "rule": "nullable-return-deref",
                             "detail": f"'{var}' from nullable-returning call at line "
                                       f"{nullable[var]} is dereferenced without a NULL check",
                             "line": offset, "code": line})
    return hits


def _rule_fixed_buffer_copy(function: dict, file: str, root: str) -> list[dict]:
    arrays: dict[str, str] = {m.group(1): m.group(2)
                              for line in function["lines"]
                              for m in _LOCAL_ARRAY.finditer(line)}
    hits: list[dict] = []
    for offset, line in enumerate(function["lines"]):
        if "ohvul:ignore" in line:
            continue
        for match in _COPY_CALL.finditer(line):
            args = _top_level_args(line, match.start(1) + len(match.group(1)))
            if not args:
                continue
            dest = args[0].strip()
            name = re.fullmatch(r"&?\*?([A-Za-z_]\w*)", dest)
            if not name or name.group(1) not in arrays:
                continue
            api = match.group(1)
            risky = False
            if api in ("strcpy", "strcat"):
                risky = len(args) > 1 and not args[1].strip().startswith('"')
            elif api == "sprintf":
                risky = len(args) > 1 and (not args[1].strip().startswith('"')
                                           or "%s" in args[1])
            elif api == "memcpy":
                size = args[2].strip() if len(args) > 2 else "0"
                declared = arrays[name.group(1)]
                risky = not (size.isdigit() and declared.isdigit()
                             and int(size) <= int(declared))
            if risky:
                hits.append({"cwe": "CWE-121", "rule": "fixed-buffer-copy",
                             "detail": f"{api} into fixed local array '{name.group(1)}' "
                                       f"[{arrays[name.group(1)]}] requires boundary review",
                             "line": function["start"] + offset, "code": line})
    return hits


_RULES = (_rule_integer_overflow, _rule_nullable_deref, _rule_fixed_buffer_copy)


def scan_functions(root, relative_files=None) -> dict:
    """Function-scope scan with the same result contract as detect.scanner.scan_path."""
    root = pathlib.Path(root).resolve()
    findings: list[dict] = []
    bundles: list[dict] = []
    files = 0
    allowed = set(relative_files) if relative_files is not None else None
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue
        relative = path.relative_to(root).as_posix()
        if allowed is not None and relative not in allowed:
            continue
        files += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for function in extract_functions(text):
            for rule in _RULES:
                for hit in rule(function, relative, str(root)):
                    evidence = {"code": hit["code"].strip(), "line_hash": _line_hash(hit["code"]),
                                "function": function["name"], "rule_detail": hit["detail"]}
                    bundle = make_bundle("static_scan",
                                         {"root": str(root), "file": relative,
                                          "line": hit["line"], "function": function["name"],
                                          "scanner": "function_rules"},
                                         evidence=evidence)
                    validate_bundle(bundle.to_dict())
                    bundles.append(bundle.to_dict())
                    findings.append({"alert_id": f"AL-{len(findings) + 1:06d}",
                                     "source": "function_rule",
                                     "cwe_candidate": hit["cwe"],
                                     "rule": hit["rule"],
                                     "description": hit["detail"],
                                     "location": {"file": relative, "line": hit["line"]},
                                     "evidence": evidence,
                                     "evidence_id": bundle.evidence_id,
                                     "status": "candidate"})
    return {"schema_version": "0.3",
            "scan": {"root": str(root), "files_scanned": files,
                     "completed_at": datetime.now(timezone.utc).isoformat(),
                     "scanner": "function_rules"},
            "findings": findings,
            "evidence_bundles": bundles,
            "safety": {"local_only": True, "no_execution": True, "no_network": True}}
