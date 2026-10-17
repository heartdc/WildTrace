"""End-to-end automated vulnerability analysis pipeline (v3 — confidence + cross-function).

Given any C/C++ source tree, this tool automatically:
  1. Discovers files and classifies the code surface (CJ FFI / general native)
  2. Runs 9 pattern-family scanners (P1–P9) + cross-function UAF layer;
     optionally an 11th layer, Joern CPG deep analysis (--joern, requires
     WSL /opt/joern — skipped with a warning when unavailable)
  3. Scores each finding with a confidence (0–100) to prioritize real issues
  4. Traces cross-function variable flow (lightweight CPG, Joern-inspired)
  5. Auto-generates PoC templates for high-confidence findings
  6. Produces a unified report sorted by confidence

Confidence scoring (Coverity-inspired statistical prioritization):
  Each pattern family has specific heuristics that raise or lower confidence:
  - P6 null-deref: more derefs ↑, early returns ↓, related checks ↓
  - P8 UAF: more post-free uses ↑, reassignment ↓, error-path free ↓
  - P4 unbounded copy: param-as-size ↑, any nearby bounds check ↓
  - All: known CWE pattern ↑, defensive coding style ↓

Usage: python -m ohvul.autopilot <source_root> --output <dir> [--min-confidence N]
"""
from __future__ import annotations
import json, hashlib, os, re, sys, time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    finding_id: str; pattern: str; severity: str; file: str; line: int
    function: str; struct_type: str; cwe: str; description: str
    ffi_export: str = ""; reachability: str = "n/a"; poc_file: str = ""
    source_snippet: str = ""; trigger_hint: str = ""
    confidence: int = 0        # 0–100
    confidence_factors: str = ""  # human-readable scoring breakdown


# ---------------------------------------------------------------------------
# Shared parser (unchanged from v2)
# ---------------------------------------------------------------------------
_FUNC_RE = re.compile(
    r'(?:(?:static\s+|inline\s+|extern\s+|virtual\s+|unsigned\s+|signed\s+|const\s+|struct\s+)*'
    r'[\w:<>~\[\]*&\s]{0,80}?)\s*(\w+)\s*\(([^;{}()]{0,800}?)\)\s*\{', re.S)
# 2026-10-15: separator relaxed \s+ -> \s* — out-of-line C++ method
# definitions (Class::Method(...), the standard OH frameworks style)
# carry no whitespace after '::' and parsed to ZERO functions before;
# bluetooth replay GT4 was triply unreachable: file-level parse, sptr
# param shape, deref-count threshold. The keyword filter and the
# '){'-anchored brace walk keep control flow out.

_NON_FUNC_KEYWORDS = {'if', 'for', 'while', 'switch', 'else', 'return', 'sizeof'}


def _mask_comments_strings(text: str) -> str:
    """Blank out comments and literal contents with spaces (newlines kept).

    Length-preserving, so offsets and line numbers computed against the
    mask match the original text. Brace/paren scanning must run on the
    masked copy: an apostrophe inside a comment used to put the old
    scanner into an unbalanced quote-skip and silently drop the function.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == '//':
            j = text.find('\n', i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = ' '
            i = j
        elif two == '/*':
            j = text.find('*/', i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
        elif c in '"\'':
            q = c
            j = i + 1
            while j < n and text[j] != q:
                if text[j] == '\\':
                    j += 1
                j += 1
            j = min(j, n - 1)
            for k in range(i, j + 1):
                if out[k] != '\n':
                    out[k] = ' '
            i = j + 1
        else:
            i += 1
    return ''.join(out)


_BRACE_RE = re.compile(r'[{}]')

# Per-process parse cache: P1–P9, CallGraph and cross_uaf each walk the
# same files — without this the tree is re-masked and re-split 8×, which
# made large-tree runs hours long (found while measuring PERFORMANCE).
# Bounded by cumulative source size (not entry count) so trees with more
# files than a fixed cap still get cross-scanner reuse.
_PARSE_CACHE: dict = {}
_PARSE_CACHE_CHARS = 0
_PARSE_CACHE_BUDGET_CHARS = 220 * 1024 * 1024


def _parse_functions(text):
    """Split source text into functions (mask → headers → brace match)."""
    masked = _mask_comments_strings(text)
    out = []
    for m in _FUNC_RE.finditer(masked):
        name, params = m.group(1), m.group(2)
        if name in _NON_FUNC_KEYWORDS:
            continue  # `else if (x) { ...` is not a function named "if"
        # the header regex's type part can span newlines, so decide on the
        # line that actually carries the function name
        name_line_start = masked.rfind('\n', 0, m.start(1)) + 1
        if masked[name_line_start:m.start(1)].lstrip().startswith('#'):
            continue  # preprocessor directive (e.g. #define macro body)
        start = m.end() - 1
        depth = 0
        end = -1
        # iterate brace POSITIONS only — a per-character walk over large
        # bodies dominated whole-tree runtime before this
        for bm in _BRACE_RE.finditer(masked, start):
            if bm.group(0) == '{':
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    end = bm.start()
                    break
        if end < 0 or end - start > 50000:
            continue
        line = text.count('\n', 0, start) + 1
        body = text[start:end + 1]
        cleaned = re.sub(r'//[^\n]*', '', body)
        # keep the newline count so downstream line offsets stay true to
        # the source (block comments used to collapse lines and drift
        # reported line numbers)
        cleaned = re.sub(r'/\*.*?\*/',
                         lambda mm: '\n' * mm.group(0).count('\n'),
                         cleaned, flags=re.S)
        cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', cleaned)
        cleaned = re.sub(r"'(?:[^'\\]|\\.)*'", "''", cleaned)
        out.append((name, params, line, body, cleaned))
    return out


def _iter_functions(text):
    global _PARSE_CACHE_CHARS
    key = hashlib.sha1(text.encode('utf-8', errors='replace')).hexdigest()
    cached = _PARSE_CACHE.get(key)
    if cached is not None:
        return iter(cached[1])
    funcs = _parse_functions(text)
    _PARSE_CACHE[key] = (text, funcs)
    _PARSE_CACHE_CHARS += len(text)
    while _PARSE_CACHE and _PARSE_CACHE_CHARS > _PARSE_CACHE_BUDGET_CHARS:
        _, (old_text, _) = _PARSE_CACHE.pop(next(iter(_PARSE_CACHE)))
        _PARSE_CACHE_CHARS -= len(old_text)
    return iter(funcs)

def _has_null_check(cleaned, var):
    return bool(re.search(
        rf'if\s*\([^)]*{var}\s*(?:==\s*(?:NULL|nullptr|0)\b|!=\s*(?:NULL|nullptr))',
        cleaned, re.I))

def _has_bound_check(cleaned, var):
    return bool(re.search(rf'if\s*\([^)]*{var}\s*(?:[<>]=?|==)\s*\d', cleaned))


# ---------------------------------------------------------------------------
# Confidence scoring engine (Coverity-inspired)
# ---------------------------------------------------------------------------

def score_finding(f: Finding, body: str, cleaned: str, params: str) -> Finding:
    """Assign confidence 0-100 with human-readable factor breakdown."""
    factors = []
    score = 50  # base

    if f.pattern == "P6_null_deref":
        # Higher confidence: more dereferences of the same pointer
        deref_count = len(re.findall(
            rf'\b{re.escape(f.struct_type)}\s*(?:->\w+|\[|\.\w)', cleaned))
        if deref_count >= 5:
            score += 20; factors.append(f"+20 ({deref_count} derefs)")
        elif deref_count >= 3:
            score += 10; factors.append(f"+10 ({deref_count} derefs)")
        elif deref_count == 1:
            # Ranking signal only (Gap-A contract 2026-10-15): a single
            # unprotected deref still generates — it just sorts lower.
            score -= 10; factors.append("-10 (single deref)")
        # Lower: function has early returns (defensive style)
        early_returns = len(re.findall(r'\bif\s*\(.*\)\s*\{?\s*return', cleaned))
        if early_returns >= 2:
            score -= 15; factors.append(f"-15 ({early_returns} early returns)")
        elif early_returns == 1:
            score -= 5; factors.append("-5 (1 early return)")
        # Lower: pointer is checked in a different form (e.g., !ptr in a macro)
        if re.search(rf'\b(?:ASSERT|CHECK|RET_VAL|RETURN_IF)\s*\([^)]*{re.escape(f.struct_type)}', cleaned, re.I):
            score -= 20; factors.append("-20 (macro-based check)")
        # Higher: in a security-critical path (auth/crypto/ipc) — demoted
        # from +15 to +5 per mentor ranking guidance ("目录名最多作为次
        # 要提示"): semantic evidence should dominate over path keywords
        if any(k in f.file.lower() for k in ('auth', 'crypto', 'ipc', 'ssl', 'tls', 'security')):
            score += 5; factors.append("+5 (security-critical path, secondary)")
        # Provability ranking (Gap-A, mentor step: 排序依据问题证据):
        # an Ffi* export symbol is directly reachable by a dlopen driver —
        # the exact validation ladder WildTrace already runs — so those
        # leads sort first in the proof funnel.
        if re.match(r'Ffi[A-Z0-9]', f.function or ''):
            score += 15; factors.append("+15 (FFI export: dlopen-provable entry)")
        # Ranking v2: semantic-class evidence (author believed nullable but
        # the check doesn't protect) outranks generic no-check — mentor:
        # "排序依据与真实风险关系" (adjudication round 1)
        desc = f.description or ''
        if 'check-after-access' in desc or 'log-only-check' in desc:
            score += 10; factors.append("+10 (author null-check exists but doesn't protect)")
        elif 'reassigned-after-check' in desc or 'merged-branches' in desc:
            score += 10; factors.append("+10 (state invalidated by reassignment/merge)")
        elif 'out-param-source' in desc:
            score += 5; factors.append("+5 (out-param fill: callee contract)");
        # Lower: very short function (likely just a wrapper with caller-side check)
        if len(cleaned) < 200:
            score -= 10; factors.append("-10 (very short function)")

    elif f.pattern in ("P8_cross_uaf", "P8_double_free"):
        # Cross-function findings carry positional-alias evidence, but no
        # in-function context was scored (score_finding receives no body).
        # Keep them above the flat base so confidence sorting and
        # --min-confidence do not silently discard the whole layer.
        score += 5
        factors.append("+5 (cross-function alias evidence)")
        if f.severity == "high":
            score += 10
            factors.append("+10 (severity high)")

    elif f.pattern == "P8_use_after_free":
        freed = f.struct_type
        # Higher: more post-free uses
        post_uses = len(re.findall(rf'\b{re.escape(freed)}\s*(?:->|\[|\.|\+\+|=)', cleaned))
        if post_uses >= 3:
            score += 25; factors.append(f"+25 ({post_uses} post-free uses)")
        elif post_uses == 2:
            score += 15; factors.append(f"+15 ({post_uses} post-free uses)")
        # Lower: pointer is reassigned before use. Locate the free via the
        # same wrapper-aware pattern the scanner uses — plain `free(x)`
        # matching never fired for SoftBusFree/av_free codebases (audit B5)
        fm = re.search(rf'\b(?:free|SoftBusFree|av_free)\s*\(\s*{re.escape(freed)}\s*\)', cleaned)
        if fm and re.search(rf'{re.escape(freed)}\s*=\s*\w+', cleaned[fm.end():]):
            score -= 30; factors.append("-30 (reassigned after free)")
        # Lower: free is in error/cleanup path
        if re.search(rf'(?:error|fail|cleanup|goto\s+\w+_fail|goto\s+cleanup)', cleaned, re.I):
            if fm and re.search(rf'(?:free|SoftBusFree|av_free)\s*\(\s*{re.escape(freed)}',
                                cleaned[cleaned.lower().find('error') if 'error' in cleaned.lower() else 0:]):
                score -= 15; factors.append("-15 (error-path free)")
        # Higher: use is a write (more dangerous than read)
        if re.search(rf'{re.escape(freed)}\s*(?:->\w+\s*=|\[\w+\]\s*=)', cleaned):
            score += 10; factors.append("+10 (post-free write)")

    elif f.pattern == "P4_unbounded_copy":
        # f.struct_type carries the size variable (audit P1: it used to hold
        # the copy-function name, so these factors never tested the size).
        size_var = f.struct_type
        # Higher: size is directly a function parameter
        if size_var and size_var in params:
            score += 20; factors.append("+20 (size is direct parameter)")
        # Lower: any bounds check anywhere in function
        if size_var and _has_bound_check(cleaned, re.escape(size_var)):
            score -= 25; factors.append("-25 (bounds check exists)")
        # Lower: size is used with sizeof or min()
        if size_var and re.search(rf'(?:sizeof|min|MIN|clamp)\s*\([^)]*{re.escape(size_var)}', cleaned):
            score -= 15; factors.append("-15 (size clamped)")
        # Higher: network-facing (attacker controls the size)
        if any(k in f.file.lower() for k in ('network', 'socket', 'parse', 'decode', 'receive', 'input')):
            score += 15; factors.append("+15 (network-facing)")

    elif f.pattern == "P1_null_len":
        # Already well-filtered by CJ type matching
        score += 20; factors.append("+20 (CJ FFI pattern match)")
        # Lower: has partial check (one of null/len)
        if f.severity == "medium":  # medium = one check present
            score -= 15; factors.append("-15 (partial check exists)")

    elif f.pattern == "P5_stack_overflow":
        score += 15; factors.append("+15 (stack buffer + strcpy pattern)")
        # Lower: buffer size is very large (likely intentional)
        size_match = re.search(r'\[(\d+)\]', f.struct_type or '')
        if size_match and int(size_match.group(1)) >= 1024:
            score -= 15; factors.append("-15 (large buffer, likely intentional)")

    elif f.pattern == "P9_format_string":
        # Lower: variable is a known-safe constant format
        if re.search(rf'{re.escape(f.struct_type)}\s*=\s*"', cleaned):
            score -= 20; factors.append("-20 (assigned literal string)")
        # Higher: variable comes from parameter (external input)
        if f.struct_type in params:
            score += 20; factors.append("+20 (from function parameter)")

    elif f.pattern == "P7_alloc_overflow":
        # Lower: there's a max cap
        if re.search(r'(?:MAX|_MAX|max|UINT_MAX|SIZE_MAX|limit)', cleaned, re.I):
            score -= 20; factors.append("-20 (max cap exists)")

    # Common modifiers for all patterns
    # Higher: finding is in a header file (likely inline, more widely used)
    if f.file.endswith('.h'):
        score += 5; factors.append("+5 (header file, wider impact)")

    # Lower: function is marked as test/mock/example
    if any(k in f.function.lower() for k in ('test', 'mock', 'example', 'demo', 'sample')):
        score -= 30; factors.append("-30 (test/mock function)")

    # Clamp to [0, 100]
    f.confidence = max(0, min(100, score))
    f.confidence_factors = "; ".join(factors) if factors else "base score"
    return f


# ---------------------------------------------------------------------------
# Lightweight cross-function analysis (Joern-inspired)
# ---------------------------------------------------------------------------

class CallGraph:
    """Lightweight function-level call graph for cross-function analysis."""

    def __init__(self):
        self.functions: dict[str, dict] = {}  # name -> {file, params, calls, frees}
        self.callers: dict[str, set[str]] = {}  # callee -> set of callers

    def build(self, root: Path):
        """Scan all C/C++ files and build the call graph."""
        for src in list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
            try:
                text = src.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            rel = str(src.relative_to(root))
            for name, params, line, body, cleaned in _iter_functions(text):
                if name in ('if', 'for', 'while', 'switch', 'return', 'sizeof', 'main'):
                    continue
                # Find calls to other functions
                calls = set(re.findall(r'\b(\w+)\s*\(', cleaned))
                calls -= {'if', 'for', 'while', 'switch', 'return', 'sizeof',
                         'free', 'malloc', 'calloc', 'realloc', 'memcpy', 'strcpy',
                         'memset', 'strlen', 'printf', 'fprintf', 'snprintf', 'sprintf'}
                # Find frees
                frees = set(re.findall(r'\b(?:free|SoftBusFree|av_free)\s*\(\s*(\w+)\s*\)', cleaned))
                # Variables this function null-checks (for caller-side
                # P6 filtering; stored compactly instead of whole bodies)
                null_checked = set(re.findall(
                    r'if\s*\(\s*!?\s*(\w+)\s*(?:==\s*(?:NULL|nullptr|0)\s*)?\)', cleaned))
                self.functions[name] = {
                    'file': rel, 'line': line, 'params': params,
                    'calls': calls, 'frees': frees, 'null_checked': null_checked,
                }
                for callee in calls:
                    self.callers.setdefault(callee, set()).add(name)

    def caller_null_checks_arg(self, func_name: str, arg_name: str) -> bool:
        """True if some caller of func_name null-checks a variable it passes
        (or an identically-named one). Heuristic — no path analysis; callers
        are keyed by name only."""
        for caller in self.callers.get(func_name, ()):
            cinfo = self.functions.get(caller)
            if cinfo and arg_name in cinfo.get('null_checked', ()):
                return True
        return False

    def get_reachability(self, func_name: str, depth: int = 3) -> list[str]:
        """Get the chain of callers up to depth levels."""
        chain = []
        current = func_name
        for _ in range(depth):
            if current in self.callers:
                callers = self.callers[current]
                if callers:
                    next_caller = min(callers)  # deterministic
                    chain.append(next_caller)
                    current = next_caller
                else:
                    break
            else:
                break
        return chain


# ---------------------------------------------------------------------------
# CJ FFI patterns (P1–P3)
# ---------------------------------------------------------------------------
CJ_TYPES = {
    'CArrEntry': ('head','size'), 'CArrStr': ('head','size'),
    'CJByteArray': ('data','len'), 'CArrUI32': ('head','size'),
    'CArrDouble': ('head','size'), 'CArrParameters': ('head','size'),
    'CParameters': ('value','size'), 'CArrUI8': ('head','size'),
}

def scan_p1(root):
    out = []
    for src in root.rglob('*.cpp'):
        rel = str(src.relative_to(root))
        if '/cj/' not in rel.replace(os.sep, '/'): continue
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for name, params, line, body, cl in _iter_functions(text):
            for tn, pf, lf in [(t, *CJ_TYPES[t]) for t in CJ_TYPES if t in params]:
                if not (re.search(r'(?:->|\.)' + pf + r'\s*(?:\[|->|\.|\s*\+)', cl)
                        and re.search(r'(?:->|\.)' + lf + r'\b', cl)):
                    continue
                if _has_null_check(cl, r'\w+(?:->|\.)' + pf): continue
                if re.search(r'(?:->|\.)' + lf + r'\s*(?:==|<=|<)\s*0', cl): continue
                f = Finding(_fid("P1", rel, line, pf), "P1_null_len",
                           "high" if tn in ('CArrParameters','CArrEntry') else "medium",
                           rel, line, name, tn, "CWE-476",
                           f"{tn}.{pf} unchecked in loop",
                           trigger_hint=f"{{{pf}=NULL, {lf}=1}}")
                out.append(score_finding(f, body, cl, params))
    return out

def scan_p2(root):
    out = []
    for src in root.rglob('*.cpp'):
        rel = str(src.relative_to(root))
        if '/cj/' not in rel.replace(os.sep, '/'): continue
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        lines = text.splitlines()
        for m in re.finditer(r'static_cast<\s*(u?int(?:8|16|32)_t)\s*>\s*\(\s*\w+(?:\.\w+|->\w+)*(?:\.|->)\s*(?:size|len)\s*\)', text, re.I):
            line = text.count('\n', 0, m.start()) + 1
            f = Finding(_fid("P2", rel, line, ""), "P2_truncation", "medium", rel, line,
                       "", m.group(1), "CWE-190", f"int64→{m.group(1)} truncation",
                       trigger_hint="Pass negative size")
            # a window of LINES around the finding, not ~21 characters
            # (audit B6: the old slice was a character window)
            window = "\n".join(lines[max(0, line - 1):line + 20])
            out.append(score_finding(f, "", window, ""))
    return out

def scan_p3(root):
    out = []
    for src in root.rglob('*.cpp'):
        rel = str(src.relative_to(root))
        if '/cj/' not in rel.replace(os.sep, '/'): continue
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for m in re.finditer(r'\w+\s*\.\s*head\s*\[\s*\w+\s*\]\s*\.\s*\w+\s*\.\s*head', text, re.I):
            line = text.count('\n', 0, m.start()) + 1
            f = Finding(_fid("P3", rel, line, ""), "P3_nested_deref", "high", rel, line,
                       "", "nested", "CWE-476", "Multi-level pointer chain",
                       trigger_hint="Inner head=NULL")
            out.append(score_finding(f, "", text[max(0,m.start()-50):m.end()], ""))
    return out


# ---------------------------------------------------------------------------
# General C/C++ patterns (P4–P9)
# ---------------------------------------------------------------------------
_DANGEROUS_COPY = [
    (r'\bmemcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*\)', 'memcpy', 'CWE-120'),
    (r'\bmemmove\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*\)', 'memmove', 'CWE-120'),
    (r'\bstrcpy\s*\(\s*\w+\s*,\s*(\w+)\s*\)', 'strcpy', 'CWE-121'),
    (r'\bstrcat\s*\(\s*\w+\s*,\s*(\w+)\s*\)', 'strcat', 'CWE-121'),
    (r'\bsprintf\s*\(\s*\w+\s*,\s*(\w+)\s*[^"]', 'sprintf', 'CWE-134'),
]

def scan_p4(root):
    out = []
    for src in list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
        rel = str(src.relative_to(root))
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for name, params, line, body, cl in _iter_functions(text):
            for regex, fname, cwe in _DANGEROUS_COPY:
                for m in re.finditer(regex, cl):
                    size_var = m.group(1) if m.lastindex else None
                    if size_var and size_var in params and not _has_bound_check(cl, re.escape(size_var)):
                        f = Finding(_fid("P4", rel, line, size_var), "P4_unbounded_copy", "high",
                                   rel, line, name, size_var, cwe,
                                   f"{fname}() size from param '{size_var}'",
                                   trigger_hint=f"oversized {size_var}")
                        out.append(score_finding(f, body, cl, params))
    return out

def scan_p5(root):
    out = []
    for src in list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
        rel = str(src.relative_to(root))
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for name, params, line, body, cl in _iter_functions(text):
            for bm in re.finditer(r'\b(?:char|uint8_t)\s+(\w+)\s*\[\s*(\d+)\s*\]', cl):
                buf, sz = bm.group(1), int(bm.group(2))
                if sz > 4096: continue
                if re.search(rf'(?:strcpy|strcat|sprintf)\s*\(\s*{re.escape(buf)}\b', cl):
                    if not _has_bound_check(cl, re.escape(buf)):
                        f = Finding(_fid("P5", rel, line, buf), "P5_stack_overflow", "high",
                                   rel, line, name, f"char[{sz}]", "CWE-121",
                                   f"Stack buf {buf}[{sz}] + unchecked write",
                                   trigger_hint=f">{sz} bytes")
                        out.append(score_finding(f, body, cl, params))
    return out

# Smart-pointer parameter shapes: std::shared_ptr<T> name / const& —
# null-deref risk identical to bare pointers but invisible to the raw
# pointer param regex (retro eval 2026-09-30: GT4's observer fixes).
# sptr/wptr added 2026-10-15: GT4's real sites use OH's own refbase
# smart pointers (const sptr<...>& observer) — the std::-only shape was
# the second, previously unnamed reason GT4 stayed unreachable.
_SMART_PTR_PARAM = re.compile(
    r'(?:const\s+)?(?:(?:std::)?(?:shared|unique)_ptr|[sw]ptr)\s*<[^>;()]*>\s*(?:&\s*)?(\w+)')

# OH truthiness guard macros: bare *CHECK*(param, ...) returns when the
# first argument is falsy — a null guard the plain if-form matcher cannot
# see (retro eval 2026-09-30: SocketUpdateCocConnectionParams FP).
# Extended 2026-10-11 (dsoftbus FP audit, 229 explainable P6 leads):
#   - bare form now also matches prefixed families (AUTH_/TRANS_/_CHECK*)
#   - condition form (var ==/!= NULL) is only trusted for macros whose
#     name carries RETURN/RET polarity — CHECK_INVOKE(param != nullptr)
#     acts when NON-null and must NOT suppress (PR #95 semantics)
_TRUTHY_MACRO_GUARD = r'\b[A-Z0-9_]*CHECK[A-Z0-9_]*\s*\(\s*{var}\s*[,)]'
_CONDITION_RETURN_GUARD = r'\b[A-Z0-9_]*CHECK[A-Z0-9_]*(?:RETURN|RET)[A-Z0-9_]*\s*\(\s*!?\s*{var}\s*(?:==|!=)'
_RETURN_MACRO_GUARD = r'\bRETURN[A-Z0-9_]*\s*\(\s*!?\s*{var}\b'


def _fid(prefix, rel, line, var):
    """finding_id carries the triggering variable: one location can host
    several distinct observations (different params/fields) and triage
    state is keyed by id — the 2026-10-11 dsoftbus audit counted 501
    collided rows sharing a location id across different vars."""
    v = re.sub(r'[^A-Za-z0-9_]', '_', var or '')
    return f"{prefix}_{rel}_{line}" + (f"_{v}" if v else "")


# ---------------------------------------------------------------------------
# P6 protection analysis (Gap-A rework, mentor review 2026-10): a null
# check protects an access only when it (a) occurs BEFORE the access,
# (b) actually aborts the null path (return/goto — a log-only check does
# not), and (c) the pointer has not been reassigned in between. The old
# function-wide suppression treated "the function mentions a check" as
# "the access is protected"; the access/count/name-length gates deleted
# candidates before protection was even considered. Count is now a
# ranking factor only (score_finding), never a generation gate.
# ---------------------------------------------------------------------------

_ABORT_KW = re.compile(r'\b(?:return|goto|break|continue)\b')


def _p6_block_span(text: str, if_end: int):
    """Span of the statement/block guarded by an `if` whose ')' ends at
    if_end: braced block via brace matching, else the single statement
    through the next ';'. Returns (start, end) or None."""
    i = if_end
    while i < len(text) and text[i] in ' \t\r\n':
        i += 1
    if i >= len(text):
        return None
    if text[i] == '{':
        depth = 0
        for j in range(i, len(text)):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    return (i, j + 1)
        return None
    semi = text.find(';', i)
    return (i, semi + 1) if semi != -1 else None


def _p6_guards(cleaned: str, varesc: str):
    """Position/semantics-aware null checks of one pointer variable.

    Yields dicts {kind, start, end, block}:
      neg-abort : condition true-when-null AND guarded block aborts —
                  protects everything after `end`
      pos-block : condition true-when-non-null — protects only its block
    Log-only negative checks yield nothing (they protect no path).
    """
    guards = []
    # condition may itself contain calls: allow one level of balanced parens
    # (`p == nullptr || !dev.IsValid()`) — the old [^()]* could not match
    # such an if at all, silently dropping every compound guard.
    for m in re.finditer(
            r'if\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*[{;]?', cleaned):
        cond = m.group(1)
        # a null test disjoined with other conditions still guards (short
        # circuit: var null alone takes the branch) — dsoftbus/bluetooth
        # commonly write `p == nullptr || !other()`. Conjunctions do NOT
        # guard (p might be checked only when the other side is false).
        def _neg(c):
            return re.fullmatch(rf'\s*!\s*{varesc}\s*', c) or \
                re.fullmatch(rf'\s*{varesc}\s*==\s*(?:NULL|nullptr|0)\s*', c)
        is_neg = _neg(cond)
        if not is_neg:
            parts = re.split(r'\|\|', cond)
            if len(parts) > 1 and any(_neg(p) for p in parts):
                is_neg = True
        is_pos = re.fullmatch(rf'\s*{varesc}\s*', cond) or \
            re.fullmatch(rf'\s*{varesc}\s*!=\s*(?:NULL|nullptr)\s*', cond)
        if not (is_neg or is_pos):
            continue
        block = _p6_block_span(cleaned, m.end() - 1) or (m.end(), m.end())
        if is_neg:
            if _ABORT_KW.search(cleaned[block[0]:block[1]]):
                guards.append({"kind": "neg-abort", "start": m.start(),
                               "end": block[1], "block": block})
        else:
            guards.append({"kind": "pos-block", "start": m.start(),
                           "end": block[1], "block": block})
    # Truthy/return macro guards are neg-abort by definition (their name
    # carries RETURN polarity — PR #95 / 2026-10-11 dsoftbus audit).
    for rx in (_TRUTHY_MACRO_GUARD, _CONDITION_RETURN_GUARD, _RETURN_MACRO_GUARD):
        for m in re.finditer(rx.format(var=varesc), cleaned):
            guards.append({"kind": "neg-abort", "start": m.start(),
                           "end": m.end(), "block": (m.start(), m.end())})
    return guards


def _p6_block_spans(cleaned: str):
    """Innermost brace span for every position (positions between spans
    get None). Assignments inside a conditional block must not project
    their state past the block end: 'if (x) p = foo(); else p = NULL;'
    leaves p MaybeNull after the merge, not Null (straight-line
    latest-wins fabricated ~1.2k certain-deref FPs on dsoftbus)."""
    stack, spans = [], {}
    for i, c in enumerate(cleaned):
        if c == '{':
            stack.append(i)
        elif c == '}' and stack:
            s = stack.pop()
            spans[(s, i)] = None  # span markers kept by interval below
    # build position -> innermost span via sorted intervals
    intervals = sorted(spans.keys())
    import bisect
    starts = [s for s, _ in intervals]

    def enclosing(pos):
        # innermost interval containing pos
        idx = bisect.bisect_right(starts, pos) - 1
        while idx >= 0:
            s, e = intervals[idx]
            if s <= pos <= e:
                return (s, e)
            idx -= 1
        return None
    return enclosing


def _p6_access_states(cleaned: str, varesc: str, accesses: list):
    """Intra-function pointer-state timeline (mentor step 4, Gap A).

    Walks the cleaned body as ordered events (guards + assignments) and
    evaluates each access's state: Null / NonNull / MaybeNull(reason).
    Model scope is deliberately tiny: straight-line position semantics,
    the two guard forms from _p6_guards, direct assignments. Anything
    else (compound conditions, aliasing, loops) stays MaybeNull — an
    explicit unknown, never a guess of safety. Note NonNull means
    non-null only, not alive or valid (malloc results stay MaybeNull:
    allocation can return NULL).
    """
    guards = _p6_guards(cleaned, varesc)
    neg_aborts = [g for g in guards if g["kind"] == "neg-abort"]
    pos_blocks = [g for g in guards if g["kind"] == "pos-block"]
    enclosing = _p6_block_spans(cleaned)
    assigns = []
    for m in re.finditer(rf'\b{varesc}\s*=\s*([^;=][^;]*);', cleaned):
        rhs = m.group(1).strip()
        if re.fullmatch(r'(?:NULL|nullptr|0)\b.*', rhs):
            assigns.append({"pos": m.start(), "state": "Null",
                            "reason": "assigned-null"})
        elif re.match(r'&\s*\w', rhs):
            assigns.append({"pos": m.start(), "state": "NonNull",
                            "reason": "assigned-address"})
        else:
            assigns.append({"pos": m.start(), "state": "MaybeNull",
                            "reason": "reassigned-source-unknown"
                            if neg_aborts else "assigned-source-unknown"})
    for a in assigns:
        a["scope"] = enclosing(a["pos"])
    # out-param fills: Func(&var, ...) supersedes an earlier NULL init —
    # the callee's contract decides, so the honest state is MaybeNull
    # (40/43 of the top-funnel state=Null leads were this pattern)
    for m in re.finditer(rf'\w+\s*\(\s*[^();]*&\s*{varesc}\b', cleaned):
        assigns.append({"pos": m.start(), "state": "MaybeNull",
                        "reason": "out-param-source", "scope": enclosing(m.start())})
    assigns.sort(key=lambda a: a["pos"])
    for g in neg_aborts:
        g["scope"] = enclosing(g["start"])
    # loop bodies: list-cursor variables are assigned inside traversal
    # macros (LIST_FOR_EACH* et al.) the model cannot see; a Null carried
    # into a loop-body access is 'loop-scope-unknown', never certain —
    # ~1.2k macro-cursor FPs on dsoftbus were labeled state=Null before
    loop_spans = []
    for m in re.finditer(r'(?:for|while)\s*\(', cleaned):
        blk = _p6_block_span(cleaned, m.end() - 1)
        if blk:
            loop_spans.append(blk)
    # traversal-macro cursors: LIST_FOR_EACH(item, ...)- and camelCase
    # ForEach(capability, ...)-style invocations carry their for-loop inside
    # a macro defined elsewhere — no literal for/while appears at the call
    # site, so match the invocation shape (adjudication lead #15:
    # cJSON_ArrayForEach)
    traversal_macro = re.search(
        rf'\b\w*(?:LIST|FOR_EACH|FOREACH|ITER|TRAVERSE)\w*\s*\(\s*{varesc}\s*[,)]',
        cleaned, re.I)

    def in_loop(pos):
        if any(s <= pos <= e for s, e in loop_spans):
            return True
        return bool(traversal_macro) and traversal_macro.start() < pos
    out = []
    for acc in accesses:
        p = acc.start()
        in_pos_block = any(g["block"][0] <= p <= g["block"][1]
                           for g in pos_blocks)
        state, reason = None, None
        # latest fact before the access wins (chronological walk); facts
        # born inside a conditional block do NOT project past that block —
        # after the merge the variable is at best MaybeNull (branch-merge
        # rule; straight-line projection fabricated certain-deref FPs)
        def _applies(f):
            s = f.get("scope")
            return s is None or p <= s[1] or s[0] <= p <= s[1]
        facts = [{"pos": g["end"], "state": "NonNull",
                  "reason": "guard-fallthrough", "scope": g["scope"]}
                 for g in neg_aborts
                 if g["end"] <= p and _applies(g)] + \
                [a for a in assigns if a["pos"] < p and _applies(a)]
        merged = None
        if in_pos_block:
            state, reason = "NonNull", "positive-block"
        elif facts:
            last = max(facts, key=lambda f: f["pos"])
            s = last.get("scope")
            if s is not None and p > s[1]:
                state, reason = "MaybeNull", "merged-branches"
                merged = True
            else:
                state, reason = last["state"], last["reason"]
            # a scoped assignment whose block already closed joins the
            # merge: carried Null + conditional reassign = MaybeNull
            # (only the branch that skipped the block still carries Null)
            excluded = [a for a in assigns
                        if a["pos"] < p and a.get("scope")
                        and p > a["scope"][1] and a["pos"] > last["pos"]]
            if excluded and not merged and state != "MaybeNull":
                differing = [a for a in excluded if a["state"] != state]
                if differing:
                    state, reason = "MaybeNull", "merged-branches"
                    merged = True
            # a guard BEFORE a later assignment does not survive it
            if last["reason"] == "guard-fallthrough" and not merged:
                later_assign = [a for a in assigns
                                if a["pos"] < p and a["reason"] != "assigned-address"
                                and any(g["end"] <= a["pos"] for g in neg_aborts
                                        if g["end"] <= a["pos"] < p)]
                if later_assign:
                    a = max(later_assign, key=lambda x: x["pos"])
                    if a["state"] != "NonNull":
                        state, reason = a["state"], \
                            "reassigned-after-check" if neg_aborts else a["reason"]
        else:
            state, reason = "MaybeNull", "param-no-contract"
        if state == "Null" and in_loop(p):
            state, reason = "MaybeNull", "loop-scope-unknown"
        if state == "MaybeNull":
            late = [g for g in guards if g["start"] > p]
            non_abort_checks = len(guards) - len(neg_aborts)
            if late:
                reason = "check-after-access"
            elif non_abort_checks:
                reason = "log-only-check"
        out.append((acc, state, reason))
    return out


def _p6_pointer_vars(params: str, cl: str) -> set:
    """Candidate pointer variables of one function: parameters, GT1 local
    declarations, and GT2 member pointers.

    Members behave exactly like no-contract parameters from the single
    function's perspective — it cannot see the constructor. The state
    timeline, guards, and branch-merge rules apply unchanged (mentor step
    6 second item; retro GT2: bluetooth_socket pimpl)."""
    out = set(re.findall(r'(?:const\s+)?\w+\s*\*+\s*(\w+)', params))
    out |= set(_SMART_PTR_PARAM.findall(params))
    local_smart = re.compile(
        r'(?:const\s+)?(?:(?:std::)?(?:shared|unique)_ptr|[sw]ptr)'
        r'\s*<[^>;()]*>\s*(\w+)\s*=')
    local_raw = re.compile(r'(?:const\s+)?\w+\s*\*+\s*(\w+)\s*=')
    out |= set(local_smart.findall(cl)) | set(local_raw.findall(cl))
    # GT2: identifiers dereferenced with -> that aren't params/locals are
    # member or global pointers — treat as no-contract candidates. Only
    # those appearing at a dereference site (not in declarations/strings).
    keywords = ('if', 'for', 'while', 'return', 'sizeof', 'NULL', 'void',
                'new', 'delete', 'this', 'true', 'false', 'else', 'case',
                'break', 'continue', 'goto', 'switch', 'default')
    for m in re.finditer(r'\b(\w+)\s*->\w', cl):
        name = m.group(1)
        if name not in out and name not in keywords and len(name) > 1:
            out.add(name)
    return {v for v in out if v not in keywords}


def scan_p6(root, call_graph=None, _suppressed=None):
    out = []
    for src in list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
        rel = str(src.relative_to(root))
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for name, params, line, body, cl in _iter_functions(text):
            for pp in sorted(_p6_pointer_vars(params, cl)):
                varesc = re.escape(pp)
                # access = the variable itself dereferenced; a match
                # preceded by -> or . is a MEMBER NAME (fileList->fileInfo[i]),
                # not an access of the variable — adjudication lead #1
                def _real_access(m):
                    return not cl[max(0, m.start() - 2):m.start()].endswith(('->', '.'))
                accesses = [m for m in re.finditer(
                    rf'\b{varesc}\s*(?:->\w+|\[|\.\w)', cl) if _real_access(m)]
                if not accesses:
                    continue
                acc, state, reason = None, None, None
                for a, st, rs in _p6_access_states(cl, varesc, accesses):
                    if st != "NonNull":
                        acc, state, reason = a, st, rs
                        break
                if acc is None:
                    # mentor: "这次访问没有出现在最终结果里，原因是什么？"
                    # log the suppression reason for every protected access
                    if _suppressed is not None:
                        for a, st, rs in _p6_access_states(cl, varesc, accesses):
                            _suppressed.append({
                                "file": rel, "function": name, "var": pp,
                                "line": line, "state": st, "reason": rs,
                            })
                    continue
                severity = "high" if state == "Null" else "medium"
                f = Finding(_fid("P6", rel, line, pp), "P6_null_deref", severity,
                           rel, line, name, pp, "CWE-476",
                           f"Ptr '{pp}' ×{len(accesses)} deref(s), access state="
                           f"{state} ({reason})",
                           trigger_hint=f"{name}(NULL)")
                f = score_finding(f, body, cl, params)
                if state == "Null":
                    f.confidence = min(100, f.confidence + 25)
                    f.confidence_factors += "; +25 (access state=Null: certain deref)"
                # Cross-function: a caller that null-checks the argument
                # lowers confidence — it must NOT silently drop the finding
                # (audit P1: name coincidence with a caller param used to
                # discard the report entirely).
                if call_graph and call_graph.caller_null_checks_arg(name, pp):
                    f.confidence = max(0, f.confidence - 20)
                    f.confidence_factors += "; -20 (caller null-checks arg)"
                out.append(f)
    return out

def scan_p7(root):
    out = []
    for src in list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
        rel = str(src.relative_to(root))
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for name, params, line, body, cl in _iter_functions(text):
            for m in re.finditer(r'(?:malloc|calloc|av_malloc)\s*\(\s*(?:sizeof\s*\([^)]+\)\s*\*\s*(\w+)|(\w+)\s*\*\s*sizeof)', cl):
                sv = m.group(1) or m.group(2)
                if not sv or sv not in params: continue
                if re.search(r'OVERFLOW|overflow|MAX|_MAX|UINT_MAX|SIZE_MAX', cl, re.I): continue
                f = Finding(_fid("P7", rel, line, sv), "P7_alloc_overflow", "medium",
                           rel, line, name, sv, "CWE-680",
                           f"malloc(sizeof×{sv}), no overflow guard",
                           trigger_hint=f"{sv}=SIZE_MAX/8")
                out.append(score_finding(f, body, cl, params))
    return out

def scan_p8(root):
    out = []
    for src in list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
        rel = str(src.relative_to(root))
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for name, params, line, body, cl in _iter_functions(text):
            for fm in re.finditer(r'\b(?:free|SoftBusFree|av_free)\s*\(\s*(\w+)\s*\)', cl):
                fv = fm.group(1)
                if fv in ('NULL','nullptr'): continue
                after = cl[fm.end():]
                if re.search(rf'{re.escape(fv)}\s*=\s*(?:NULL|nullptr|0)\s*;', after): continue
                uses = re.findall(rf'\b{re.escape(fv)}\s*(?:->|\[|\.|\+\+|=)', after)
                if uses:
                    f = Finding(_fid("P8", rel, line, fv), "P8_use_after_free", "high",
                               rel, line, name, fv, "CWE-416",
                               f"'{fv}' freed then used ({len(uses)}×)",
                               trigger_hint=f"UAF path in {name}()")
                    out.append(score_finding(f, body, cl, params))
    return out

_P9_FMT_ARG = {
    # function name -> 0-based position of the format argument
    'printf': 0, 'vprintf': 0,
    'fprintf': 1, 'vfprintf': 1, 'syslog': 1,
    'sprintf': 1, 'vsprintf': 1,
    'snprintf': 2, 'vsnprintf': 2,
}


def _nth_argument(text: str, open_paren: int, n: int):
    """Return the n-th (0-based) top-level argument of a call whose opening
    '(' sits at `open_paren`; splits on commas at nesting depth 1."""
    depth = 0
    args = []
    cur = open_paren + 1
    i = open_paren
    while i < len(text):
        c = text[i]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
            if depth == 0:
                args.append(text[cur:i])
                return args[n].strip() if n < len(args) else None
        elif c == ',' and depth == 1:
            args.append(text[cur:i])
            cur = i + 1
        i += 1
    return None


def scan_p9(root):
    out = []
    for src in list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
        rel = str(src.relative_to(root))
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for name, params, line, body, cl in _iter_functions(text):
            for m in re.finditer(r'\b(vprintf|vfprintf|vsprintf|vsnprintf|'
                                 r'printf|fprintf|sprintf|snprintf|syslog)\s*\(', cl):
                fname = m.group(1)
                # Only plain printf has the format as argument 1: the old
                # code flagged fprintf's stream / snprintf's buffer as the
                # "format string" (audit P1, systematic false positives).
                fmt = _nth_argument(cl, m.end() - 1, _P9_FMT_ARG.get(fname, 0))
                if not fmt:
                    continue
                fmt = fmt.strip()
                if fmt.startswith('"'): continue
                vm = re.match(r'(\w+)', fmt)
                if vm and vm.group(1) not in ('NULL','nullptr','sizeof'):
                    f = Finding(_fid("P9", rel, line, vm.group(1)), "P9_format_string", "high",
                               rel, line, name, vm.group(1), "CWE-134",
                               f"Non-literal format '{vm.group(1)}' in {fname}()",
                               trigger_hint=f"'%n%n%n' as {vm.group(1)}")
                    out.append(score_finding(f, body, cl, params))
    return out


# ---------------------------------------------------------------------------
# PoC templates (unchanged from v2, using confidence-filtered generation)
# ---------------------------------------------------------------------------
_POC = {
"P1_null_len": '''/* Auto-PoC: {pattern} {cwe} conf={confidence}% {file}:{line} {function}
 * Trigger: {trigger_hint} */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
int main(int c, char **v) {{
    if (c != 2) return 2;
    void *lib = dlopen(v[1], RTLD_NOW); if (!lib) return 3;
    printf("P1: malformed -> {function}\\n"); return 0;
}}''',
"P4_unbounded_copy": '''/* Auto-PoC: {pattern} {cwe} conf={confidence}% {file}:{line} {function}
 * size variable: {struct_type} */
#include <stdio.h>
#include <string.h>
int main(void) {{
    char small[8]; char big[256]; memset(big,'A',255);
    printf("P4: unbounded copy size={struct_type}\\n"); return 0;
}}''',
"P5_stack_overflow": '''/* Auto-PoC: {pattern} {cwe} conf={confidence}% {file}:{line} {function} */
#include <stdio.h>
#include <string.h>
int main(void) {{
    char in[4096]; memset(in,'A',4095); in[4095]=0;
    printf("P5: {struct_type}\\n"); return 0;
}}''',
"P6_null_deref": '''/* Auto-PoC: {pattern} {cwe} conf={confidence}% {file}:{line} {function} */
#include <stdio.h>
#include <stddef.h>
int main(void) {{ printf("P6: {function}(NULL)\\n"); return 0; }}''',
"P7_alloc_overflow": '''#include <stdio.h>
#include <stdint.h>
int main(void) {{ printf("P7: {function}({struct_type}=SIZE_MAX/8)\\n"); return 0; }}''',
"P8_use_after_free": '''#include <stdio.h>
int main(void) {{ printf("P8: {function}() UAF '{struct_type}'\\n"); return 0; }}''',
"P9_format_string": '''#include <stdio.h>
int main(void) {{ char *f="%n%n%n"; printf("P9: {function}(f)\\n"); return 0; }}''',
}
_POC["P2_truncation"] = _POC["P1_null_len"]
_POC["P3_nested_deref"] = _POC["P1_null_len"]

def generate_poc(f, out_dir):
    tpl = _POC.get(f.pattern)
    if not tpl: return ""
    sid = re.sub(r'[^a-zA-Z0-9_]', '_', f.finding_id)[:40]
    # hash suffix: long finding_ids sharing the first 40 sanitized
    # characters used to overwrite each other's PoC files (audit B4)
    digest = hashlib.sha256(f.finding_id.encode('utf-8')).hexdigest()[:8]
    name = f"poc_{f.pattern}_{sid}_{digest}.c"
    (out_dir / name).write_text(tpl.format(
        pattern=f.pattern, cwe=f.cwe, confidence=f.confidence,
        file=f.file, line=f.line,
        function=f.function or "target", struct_type=f.struct_type or "buf",
        trigger_hint=f.trigger_hint or "see desc"), encoding='utf-8')
    return name


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
SCANNERS = [
    ("P1", scan_p1, "cj"), ("P2", scan_p2, "cj"), ("P3", scan_p3, "cj"),
    ("P4", scan_p4, "gen"), ("P5", scan_p5, "gen"), ("P6", scan_p6, "gen"),
    ("P7", scan_p7, "gen"), ("P8", scan_p8, "gen"), ("P9", scan_p9, "gen"),
]

# Joern CPG findings (J4/J6/J8) → pipeline Finding conversion table
JOERN_PATTERN_MAP = {
    "J4": ("J4_unbounded_copy", "high", "CWE-120"),
    "J6": ("J6_null_deref", "medium", "CWE-476"),
    "J8": ("J8_use_after_free", "high", "CWE-416"),
}


def _convert_joern_findings(joern_findings) -> list:
    """JoernFinding → Finding (confidence carried over from the CPG query)."""
    out = []
    for j in joern_findings:
        pname, sev, cwe = JOERN_PATTERN_MAP.get(
            j.pattern, (f"{j.pattern}_joern", "medium", "CWE-Other"))
        fid = re.sub(r'[^a-zA-Z0-9_]', '_', f"{pname}_{j.file}_{j.line}")[:80]
        out.append(Finding(
            finding_id=fid, pattern=pname, severity=sev,
            file=j.file, line=j.line, function=j.function or "",
            struct_type="", cwe=cwe,
            description=f"[Joern CPG] {j.detail}",
            trigger_hint="path-sensitive CPG query hit",
            confidence=max(0, min(100, int(j.confidence))),
            confidence_factors="Joern CPG query (path-sensitive)",
        ))
    return out


def run(source_root: Path, output_dir: Path, min_confidence: int = 0,
        joern: bool = False, progress=None) -> dict:
    """Run the full pipeline. ``progress(phase, detail)`` is an optional
    observer (webapp/CI friendly): called with coarse phases
    (surface/callgraph/layer/cross_uaf/joern/report) and never interrupts
    the scan when it raises."""
    def _emit(phase, detail=""):
        if progress is None:
            return
        try:
            progress(phase, detail)
        except Exception:
            pass
    if not source_root.is_dir():
        raise ValueError('Source directory does not exist')
    if not 0 <= min_confidence <= 100:
        raise ValueError('Confidence must be between 0 and 100')
    input_errors = []
    source_hashes = {}
    def walk_error(error):
        input_errors.append({'phase': 'enumeration', 'error': str(error)})
    for folder, dirs, names in os.walk(source_root, onerror=walk_error):
        dirs[:] = [d for d in dirs if not (Path(folder) / d).is_symlink()]
        for name in names:
            path = Path(folder) / name
            if path.suffix not in ('.c', '.cpp'):
                continue
            try:
                if path.is_symlink():
                    raise ValueError('Symbolic source link is not supported')
                raw = path.read_bytes()
                raw.decode('utf-8')
                source_hashes[str(path.relative_to(source_root))] = hashlib.sha256(raw).hexdigest()
            except (OSError, ValueError) as exc:
                input_errors.append({'file': str(path), 'error': str(exc)})
    t0 = time.time()
    _emit("surface")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "pocs").mkdir(exist_ok=True)
    all_cpp = list(source_root.rglob('*.cpp'))
    all_c = list(source_root.rglob('*.c'))
    cj = [p for p in all_cpp if '/cj/' in str(p).replace(os.sep, '/')]
    has_cj = len(cj) > 0
    # Deterministic sample, closed handles, OSError-proof (a directory
    # named *.c must not kill the run before the report is written).
    sample = sorted(all_cpp + all_c)[:200]
    sampled_lines = 0
    for p in sample:
        try:
            with p.open('rb') as fh:
                sampled_lines += sum(1 for _ in fh)
        except OSError:
            continue
    total_lines = sampled_lines
    if len(all_cpp + all_c) > 200:
        total_lines = sampled_lines * len(all_cpp + all_c) // 200

    # Build call graph for cross-function analysis
    t_cg = time.time()
    _emit("callgraph")
    cg = CallGraph()
    cg.build(source_root)
    cg_time = time.time() - t_cg

    # Run scanners (P6 uses call graph for cross-function filtering)
    findings = []
    executed = []
    for pid, scanner, scope in SCANNERS:
        if scope == "cj" and not has_cj: continue
        _emit("layer", pid)
        try:
            if pid == "P6":
                results = scanner(source_root, call_graph=cg)
            else:
                results = scanner(source_root)
            findings.extend(results)
            executed.append(pid)
        except Exception as e:
            print(f"WARN {pid}: {e}", file=sys.stderr)
            input_errors.append({'phase': pid, 'error': str(e)})

    # Enrich reachability from the call graph (the field used to stay
    # "n/a" for every regex finding — audit B8)
    for f in findings:
        if f.reachability in ("", "n/a") and f.function in cg.functions:
            chain = cg.get_reachability(f.function)
            if chain:
                f.reachability = " ← ".join(chain)

    # Cross-function UAF detection (P8-Cross)
    cross_ran = False
    _emit("cross_uaf")
    try:
        from .cross_uaf import build_facts, scan_cross_uaf
        t_x = time.time()
        xfacts = build_facts(source_root)
        cross_findings = scan_cross_uaf(source_root, xfacts)
        cross_time = time.time() - t_x
        findings.extend(cross_findings)
        cross_ran = True
        if cg_time == 0:
            cg_time = cross_time
        else:
            cg_time = round(cg_time + cross_time, 2)
    except Exception as e:
        print(f"WARN cross_uaf: {e}", file=sys.stderr)
        input_errors.append({'phase': 'cross_uaf', 'error': str(e)})

    # Joern CPG deep analysis (opt-in layer; requires WSL /opt/joern).
    # Degrades gracefully — never crashes the pipeline when unavailable.
    joern_info = {"enabled": bool(joern), "available": False,
                  "findings": 0, "seconds": 0.0, "error": ""}
    if joern:
        _emit("joern")
        try:
            from .joern_bridge import JoernAnalyzer
            analyzer = JoernAnalyzer(source_root, verbose=False)
            if not analyzer.is_available():
                joern_info["error"] = "joern-unavailable (WSL /opt/joern not found)"
                print("WARN joern: unavailable, continuing without CPG layer",
                      file=sys.stderr)
            else:
                t_j = time.time()
                jfindings = analyzer.run_all_queries()
                joern_info["available"] = True
                joern_info["seconds"] = round(time.time() - t_j, 2)
                joern_info["findings"] = len(jfindings)
                findings.extend(_convert_joern_findings(jfindings))
        except Exception as e:
            joern_info["error"] = f"{type(e).__name__}: {e}"
            print(f"WARN joern: {e}", file=sys.stderr)

    # Same-id duplicates (one var, several free events) keep the most
    # informative copy; distinct vars no longer collide since _fid.
    _best = {}
    for f in findings:
        k = f.finding_id
        if k not in _best or (f.confidence, len(f.description)) > \
                (_best[k].confidence, len(_best[k].description)):
            _best[k] = f
    findings = list(_best.values())

    # Fill source snippets for triage: a window around the finding line,
    # straight from the scanned tree (P6/P8 never carried snippets).
    _lines_cache = {}
    for f in findings:
        if f.source_snippet or not f.line:
            continue
        if f.file not in _lines_cache:
            try:
                _lines_cache[f.file] = (source_root / f.file).read_text(
                    encoding='utf-8', errors='replace').splitlines()
            except OSError:
                _lines_cache[f.file] = None
        lines = _lines_cache[f.file]
        if lines:
            lo, hi = max(0, f.line - 6), min(len(lines), f.line + 8)
            f.source_snippet = "\n".join(lines[lo:hi])[:1200]

    # Sort by confidence (descending)
    findings.sort(key=lambda f: f.confidence, reverse=True)

    # Filter by minimum confidence
    all_count = len(findings)
    findings = [f for f in findings if f.confidence >= min_confidence]

    # PoC generation only for confidence >= 50
    for f in findings:
        if f.confidence >= 50:
            f.poc_file = generate_poc(f, output_dir / "pocs")

    elapsed = time.time() - t0
    pc = {}
    for f in findings: pc[f.pattern] = pc.get(f.pattern, 0) + 1
    conf_bins = {"80+": 0, "60-79": 0, "40-59": 0, "0-39": 0}
    for f in findings:
        c = f.confidence
        if c >= 80: conf_bins["80+"] += 1
        elif c >= 60: conf_bins["60-79"] += 1
        elif c >= 40: conf_bins["40-59"] += 1
        else: conf_bins["0-39"] += 1

    # Layers that actually executed (the report must not omit a layer that
    # produced findings, nor list one that did not run).
    for rel, expected_hash in source_hashes.items():
        try:
            if hashlib.sha256((source_root / rel).read_bytes()).hexdigest() != expected_hash:
                input_errors.append({'file': rel, 'error': 'Source changed during scan'})
        except OSError as exc:
            input_errors.append({'file': rel, 'error': str(exc)})
    if cross_ran:
        executed.append("P8X_cross_uaf")
    if joern_info["available"]:
        executed.append("J_joern_cpg")

    report = {
        "status": "partial" if input_errors else "completed",
        "input_errors": input_errors,
        "source_hashes": source_hashes,
        "tool": "WildTrace Autopilot v3",
        "timestamp": datetime.now().isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "call_graph_seconds": round(cg_time, 2),
        "joern": joern_info,
        "surface": {"cpp": len(all_cpp), "c": len(all_c), "cj": len(cj),
                     "lines_est": total_lines, "has_cj": has_cj,
                     "call_graph_functions": len(cg.functions)},
        "summary": {
            "total": len(findings), "before_filter": all_count,
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "pocs": sum(1 for f in findings if f.poc_file),
            "patterns": pc,
            "confidence_distribution": conf_bins,
            "conf_70plus": sum(1 for f in findings if f.confidence >= 70),
            "min_confidence": min_confidence,
            "scanners": executed,
        },
        "findings": [asdict(f) for f in findings],
    }
    _emit("report")
    (output_dir / "findings.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    (output_dir / "findings.md").write_text(_md(report), encoding='utf-8')
    return report

def _md(r):
    s = r["summary"]; sf = r["surface"]
    jn = r.get("joern") or {}
    joern_line = ""
    if jn.get("enabled"):
        if jn.get("available"):
            joern_line = (f"\nJoern CPG 层：启用，{jn['findings']} 条发现，"
                          f"{jn['seconds']}s")
        else:
            joern_line = f"\nJoern CPG 层：已请求但不可用（{jn.get('error', '')}）"
    L = ["# 自动化漏洞分析报告", "",
         f"工具：{r['tool']} | {r['timestamp'][:19]} | 耗时 {r['elapsed_seconds']}s (含调用图 {r['call_graph_seconds']}s)",
         "", f"扫描面：C++ {sf['cpp']} | C {sf['c']} | CJ {sf['cj']} | ~{sf['lines_est']:,} 行 | 调用图 {sf['call_graph_functions']} 函数",
         joern_line,
         "", f"发现：**{s['total']}** 条（高危 {s['high']} / 中危 {s['medium']}）",
         f"PoC（置信度≥50）：{s['pocs']} 个 | 最低置信度：{s['min_confidence']}",
         "", "### 置信度分布", "",
         "| 置信度 | 数量 |", "|---|---|"]
    for k, v in s["confidence_distribution"].items():
        L.append(f"| {k} | {v} |")
    L += ["", "| 模式 | 数量 |", "|---|---|"]
    for p, c in sorted(s["patterns"].items()): L.append(f"| {p} | {c} |")
    L += ["", "### 高置信度发现（≥70）", "",
          "| 置信度 | 模式 | 严重度 | 位置 | 函数 | CWE | 因子 |", "|---|---|---|---|---|---|---|"]
    for f in r["findings"]:
        if f["confidence"] >= 70:
            L.append(f"| {f['confidence']} | {f['pattern']} | {f['severity']} "
                    f"| {f['file']}:{f['line']} | {f['function']} | {f['cwe']} "
                    f"| {f['confidence_factors'][:50]} |")
    L += ["", "> lead ≠ 漏洞。置信度是基于模式启发式的优先级排序，不是准确率保证。"]
    return "\n".join(L)

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("source_root", type=Path)
    p.add_argument("--output", type=Path, default=Path("autopilot_output"))
    p.add_argument("--min-confidence", type=int, default=0,
                   help="Filter findings below this confidence (0-100)")
    p.add_argument("--joern", action="store_true",
                   help="Enable the 11th layer: Joern CPG deep analysis "
                        "(requires WSL with /opt/joern; skipped with a "
                        "warning when unavailable)")
    a = p.parse_args()
    r = run(a.source_root, a.output, a.min_confidence, joern=a.joern)
    s = r["summary"]
    print(f"AUTOPILOT v3: {s['total']}/{s['before_filter']} findings "
          f"(H={s['high']} M={s['medium']}) pocs={s['pocs']} "
          f"conf>=70: {s['conf_70plus']} "
          f"in {r['elapsed_seconds']}s")
    return 0 if r['status'] == 'completed' else 1

if __name__ == "__main__":
    raise SystemExit(main())
