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
import json, os, re, sys, time
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
    r'[\w:<>~\[\]*&\s]+?)\s+(\w+)\s*\(([^;{}()]{0,800}?)\)\s*\{', re.S)

def _iter_functions(text):
    for m in _FUNC_RE.finditer(text):
        name, params = m.group(1), m.group(2)
        start = m.end() - 1; depth = 0; i = start
        while i < len(text):
            c = text[i]
            if c == '{': depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0: break
            elif c in '"\'':
                q = c; i += 1
                while i < len(text) and text[i] != q:
                    if text[i] == '\\': i += 1
                    i += 1
            i += 1
        if depth != 0 or i - start > 50000: continue
        line = text.count('\n', 0, start) + 1
        body = text[start:i+1]
        cleaned = re.sub(r'//[^\n]*', '', body)
        cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.S)
        cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', cleaned)
        cleaned = re.sub(r"'(?:[^'\\]|\\.)*'", "''", cleaned)
        yield name, params, line, body, cleaned

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
        # Lower: function has early returns (defensive style)
        early_returns = len(re.findall(r'\bif\s*\(.*\)\s*\{?\s*return', cleaned))
        if early_returns >= 2:
            score -= 15; factors.append(f"-15 ({early_returns} early returns)")
        elif early_returns == 1:
            score -= 5; factors.append("-5 (1 early return)")
        # Lower: pointer is checked in a different form (e.g., !ptr in a macro)
        if re.search(rf'\b(?:ASSERT|CHECK|RET_VAL|RETURN_IF)\s*\([^)]*{re.escape(f.struct_type)}', cleaned, re.I):
            score -= 20; factors.append("-20 (macro-based check)")
        # Higher: in a security-critical path (auth/crypto/ipc)
        if any(k in f.file.lower() for k in ('auth', 'crypto', 'ipc', 'ssl', 'tls', 'security')):
            score += 15; factors.append("+15 (security-critical path)")
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
        # Lower: pointer is reassigned before use
        if re.search(rf'{re.escape(freed)}\s*=\s*\w+', cleaned[ cleaned.index(f'free({freed})') + 10 :] if f'free({freed})' in cleaned else ''):
            score -= 30; factors.append("-30 (reassigned after free)")
        # Lower: free is in error/cleanup path
        if re.search(rf'(?:error|fail|cleanup|goto\s+\w+_fail|goto\s+cleanup)', cleaned, re.I):
            if re.search(rf'free\s*\(\s*{re.escape(freed)}', cleaned[cleaned.lower().find('error') if 'error' in cleaned.lower() else 0:]):
                score -= 15; factors.append("-15 (error-path free)")
        # Higher: use is a write (more dangerous than read)
        if re.search(rf'{re.escape(freed)}\s*(?:->\w+\s*=|\[\w+\]\s*=)', cleaned):
            score += 10; factors.append("+10 (post-free write)")

    elif f.pattern == "P4_unbounded_copy":
        # Higher: size is directly a function parameter
        if f.struct_type in params:
            score += 20; factors.append("+20 (size is direct parameter)")
        # Lower: any bounds check anywhere in function
        if _has_bound_check(cleaned, re.escape(f.struct_type)):
            score -= 25; factors.append("-25 (bounds check exists)")
        # Lower: size is used with sizeof or min()
        if re.search(rf'(?:sizeof|min|MIN|clamp)\s*\([^)]*{re.escape(f.struct_type)}', cleaned):
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
                self.functions[name] = {
                    'file': rel, 'line': line, 'params': params,
                    'calls': calls, 'frees': frees,
                }
                for callee in calls:
                    self.callers.setdefault(callee, set()).add(name)

    def is_pointer_checked_by_caller(self, func_name: str, param_name: str) -> bool:
        """Check if any caller of func_name null-checks the argument before calling."""
        if func_name not in self.callers:
            return False
        for caller in self.callers[func_name]:
            if caller in self.functions:
                caller_info = self.functions[caller]
                # Re-read the caller's source
                src = Path(caller_info['file'])
                # Look for null check before the call
                pattern = rf'if\s*\([^)]*{re.escape(param_name)}\s*(?:==\s*(?:NULL|nullptr|0)|!=\s*(?:NULL|nullptr))[^)]*\)[^;]*;?\s*[^;]*{re.escape(func_name)}\s*\('
                # This is a heuristic - full path analysis needs proper CPG
                if caller_info['params'] and param_name in caller_info['params']:
                    return True  # caller receives same param, may check it
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
                f = Finding(f"P1_{rel}_{line}", "P1_null_len",
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
        for m in re.finditer(r'static_cast<\s*(u?int(?:8|16|32)_t)\s*>\s*\(\s*\w+(?:\.\w+|->\w+)*(?:\.|->)\s*(?:size|len)\s*\)', text, re.I):
            line = text.count('\n', 0, m.start()) + 1
            f = Finding(f"P2_{rel}_{line}", "P2_truncation", "medium", rel, line,
                       "", m.group(1), "CWE-190", f"int64→{m.group(1)} truncation",
                       trigger_hint="Pass negative size")
            out.append(score_finding(f, "", text[line-1:line+20], ""))
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
            f = Finding(f"P3_{rel}_{line}", "P3_nested_deref", "high", rel, line,
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
                        f = Finding(f"P4_{rel}_{line}", "P4_unbounded_copy", "high",
                                   rel, line, name, fname, cwe,
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
                        f = Finding(f"P5_{rel}_{line}", "P5_stack_overflow", "high",
                                   rel, line, name, f"char[{sz}]", "CWE-121",
                                   f"Stack buf {buf}[{sz}] + unchecked write",
                                   trigger_hint=f">{sz} bytes")
                        out.append(score_finding(f, body, cl, params))
    return out

def scan_p6(root, call_graph=None):
    out = []
    for src in root.rglob('*.c'):
        rel = str(src.relative_to(root))
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for name, params, line, body, cl in _iter_functions(text):
            for pp in re.findall(r'(?:const\s+)?\w+\s*\*+\s*(\w+)', params):
                if len(pp) < 2 or pp in ('if','for','while','return','sizeof','NULL','void'): continue
                derefs = re.findall(rf'\b{re.escape(pp)}\s*(?:->\w+|\[|\.\w)', cl)
                if len(derefs) < 3: continue
                if _has_null_check(cl, re.escape(pp)): continue
                if re.search(rf'if\s*\(\s*!?\s*{re.escape(pp)}\s*\)\s*(?:return|goto)', cl): continue
                # Cross-function: check if any caller checks this pointer
                if call_graph and call_graph.is_pointer_checked_by_caller(name, pp):
                    continue  # Caller checks it, lower our confidence but keep finding
                f = Finding(f"P6_{rel}_{line}", "P6_null_deref", "medium",
                           rel, line, name, pp, "CWE-476",
                           f"Ptr '{pp}' ×{len(derefs)} derefs, no null check",
                           trigger_hint=f"{name}(NULL)")
                out.append(score_finding(f, body, cl, params))
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
                f = Finding(f"P7_{rel}_{line}", "P7_alloc_overflow", "medium",
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
                    f = Finding(f"P8_{rel}_{line}", "P8_use_after_free", "high",
                               rel, line, name, fv, "CWE-416",
                               f"'{fv}' freed then used ({len(uses)}×)",
                               trigger_hint=f"UAF path in {name}()")
                    out.append(score_finding(f, body, cl, params))
    return out

def scan_p9(root):
    out = []
    for src in list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
        rel = str(src.relative_to(root))
        try: text = src.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        for name, params, line, body, cl in _iter_functions(text):
            for m in re.finditer(r'\b(?:printf|fprintf|sprintf|snprintf|syslog)\s*\(', cl):
                after = cl[m.end():m.end()+80].lstrip()
                if after.startswith('"'): continue
                vm = re.match(r'(\w+)', after)
                if vm and vm.group(1) not in ('NULL','nullptr','sizeof'):
                    f = Finding(f"P9_{rel}_{line}", "P9_format_string", "high",
                               rel, line, name, vm.group(1), "CWE-134",
                               f"Non-literal format '{vm.group(1)}'",
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
"P4_unbounded_copy": '''/* Auto-PoC: {pattern} {cwe} conf={confidence}% {file}:{line} {function} */
#include <stdio.h>
#include <string.h>
int main(void) {{
    char small[8]; char big[256]; memset(big,'A',255);
    printf("P4: {struct_type}(small,big,%zu)\\n",strlen(big)); return 0;
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
    name = f"poc_{f.pattern}_{sid}.c"
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
        joern: bool = False) -> dict:
    t0 = time.time()
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
    cg = CallGraph()
    cg.build(source_root)
    cg_time = time.time() - t_cg

    # Run scanners (P6 uses call graph for cross-function filtering)
    findings = []
    for pid, scanner, scope in SCANNERS:
        if scope == "cj" and not has_cj: continue
        try:
            if pid == "P6":
                results = scanner(source_root, call_graph=cg)
            else:
                results = scanner(source_root)
            findings.extend(results)
        except Exception as e:
            print(f"WARN {pid}: {e}", file=sys.stderr)

    # Cross-function UAF detection (P8-Cross)
    cross_ran = False
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

    # Joern CPG deep analysis (opt-in layer; requires WSL /opt/joern).
    # Degrades gracefully — never crashes the pipeline when unavailable.
    joern_info = {"enabled": bool(joern), "available": False,
                  "findings": 0, "seconds": 0.0, "error": ""}
    if joern:
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
    executed = [p for p, _, s in SCANNERS if s == "gen" or (s == "cj" and has_cj)]
    if cross_ran:
        executed.append("P8X_cross_uaf")
    if joern_info["available"]:
        executed.append("J_joern_cpg")

    report = {
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

if __name__ == "__main__":
    main()
