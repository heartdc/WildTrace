"""Cross-function UAF / double-free / alias tracking (P8-Cross).

Detects three patterns that single-function P8 cannot see:

  Pattern A (Free→Pass):    caller frees ptr, then passes ptr to callee that derefs it
  Pattern B (Callee-Frees): callee frees ptr, caller uses ptr after the call
  Pattern C (Double-Free):  callee frees ptr, caller also frees ptr

Alias resolution: when caller passes `var` to callee at arg position N,
we look up callee's Nth parameter name to check if that param is freed/deref'd.
This handles the common case where param names differ between caller and callee.
"""
from __future__ import annotations
import re
from pathlib import Path
from dataclasses import dataclass, field

from .autopilot import Finding, _iter_functions, score_finding


@dataclass
class FuncFacts:
    """Per-function facts for cross-reference."""
    file: str = ""
    line: int = 0
    params_str: str = ""          # raw parameter string
    param_list: list = field(default_factory=list)  # ordered param names
    freed: set = field(default_factory=set)     # param names freed
    deref: set = field(default_factory=set)     # param names dereferenced
    passes: list = field(default_factory=list)  # [{callee, arg_pos, var, offset}]
    body_clean: str = ""


_SKIP = {
    'if', 'for', 'while', 'switch', 'return', 'sizeof', 'main', 'void',
    'static', 'inline', 'extern', 'const', 'struct', 'unsigned', 'signed',
    'free', 'malloc', 'calloc', 'realloc', 'memcpy', 'strcpy', 'memmove',
    'memset', 'strlen', 'printf', 'fprintf', 'snprintf', 'sprintf',
    'NULL', 'EOK', 'SOFTBUS_OK',
}


def _parse_params(params_str: str) -> list[str]:
    """Extract ordered parameter variable names."""
    names = []
    for chunk in params_str.split(','):
        chunk = chunk.strip()
        if not chunk or chunk == 'void':
            continue
        # Match "*name" or "**name" at end (pointer params)
        m = re.search(r'\*+\s*(\w+)\s*$', chunk)
        if m:
            names.append(m.group(1))
            continue
        # Match "type name" (non-pointer)
        m2 = re.search(r'\b(\w+)\s*$', chunk)
        if m2 and m2.group(1) not in ('const', 'struct', 'unsigned', 'signed', 'int',
                                        'char', 'long', 'short', 'float', 'double',
                                        'size_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
                                        'int8_t', 'int16_t', 'int32_t', 'int64_t', 'bool'):
            names.append(m2.group(1))
    return names


def build_facts(root: Path) -> dict[str, FuncFacts]:
    """Scan all C/C++ files and build per-function facts."""
    facts = {}
    for src in list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
        rel = str(src.relative_to(root))
        try:
            text = src.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for fname, params, line, body, cleaned in _iter_functions(text):
            if fname in _SKIP or fname.startswith('<'):
                continue
            ff = FuncFacts(file=rel, line=line, params_str=params, body_clean=cleaned)
            ff.param_list = _parse_params(params)

            # Classify parameters
            for pn in ff.param_list:
                if not pn or len(pn) < 1:
                    continue
                if re.search(rf'\b(?:free|SoftBusFree|av_free)\s*\(\s*{re.escape(pn)}\s*\)', cleaned):
                    ff.freed.add(pn)
                if re.findall(rf'\b{re.escape(pn)}\s*(?:->\w+|\[|\.\w)', cleaned):
                    ff.deref.add(pn)

            # Find call sites that pass local variables/params
            for cm in re.finditer(r'(\w+)\s*\(([^)]{1,300})\)', cleaned):
                callee = cm.group(1)
                if callee in _SKIP or callee == fname:
                    continue
                args = [a.strip() for a in cm.group(2).split(',')]
                for arg_pos, arg in enumerate(args):
                    # Strip casts: "(type*)var" → "var"
                    arg_base = re.sub(r'^\([^)]*\)\s*', '', arg).strip()
                    # Match exact param name or any identifier that's a local var
                    if arg_base and re.match(r'^\w+$', arg_base):
                        offset = cleaned[:cm.start()].count('\n')
                        ff.passes.append({
                            'callee': callee,
                            'arg_pos': arg_pos,
                            'var': arg_base,
                            'offset': offset,
                            'call': cm.group(0)[:60],
                        })

            if ff.freed or ff.deref or ff.passes:
                facts[fname] = ff
    return facts


def _param_at(facts: dict, callee: str, pos: int) -> str | None:
    """Get the parameter name at position `pos` in callee's signature."""
    cf = facts.get(callee)
    if cf and 0 <= pos < len(cf.param_list):
        return cf.param_list[pos]
    return None


def _pos_of(body: str, pattern: str) -> int:
    m = re.search(pattern, body)
    return m.start() if m else -1


def scan_cross_uaf(root: Path, facts: dict | None = None) -> list[Finding]:
    """Detect cross-function UAF / double-free using positional alias resolution."""
    if facts is None:
        facts = build_facts(root)

    findings = []

    for caller_name, cf in facts.items():
        for p in cf.passes:
            var = p['var']               # variable name in caller
            callee_name = p['callee']
            arg_pos = p['arg_pos']       # position in callee's args

            # Resolve what this variable maps to in the callee
            callee_param = _param_at(facts, callee_name, arg_pos)
            callee_f = facts.get(callee_name)
            if not callee_f:
                continue

            # --- Pattern A: caller frees var, then passes to callee that derefs ---
            if var in cf.freed:
                free_pos = _pos_of(cf.body_clean,
                    rf'\b(?:free|SoftBusFree|av_free)\s*\(\s*{re.escape(var)}\s*\)')
                pass_pos = _pos_of(cf.body_clean, rf'\b{re.escape(callee_name)}\s*\(')
                if free_pos >= 0 and pass_pos > free_pos and callee_param and callee_param in callee_f.deref:
                    f = Finding(
                        finding_id=f"P8A_{cf.file}_{cf.line + p['offset']}",
                        pattern="P8_cross_uaf", severity="high",
                        file=cf.file, line=cf.line + p['offset'],
                        function=caller_name, struct_type=var, cwe="CWE-416",
                        description=(f"'{var}' freed in {caller_name}() then passed to "
                                     f"{callee_name}() which derefs its param '{callee_param}'"),
                        trigger_hint=f"{caller_name}() frees '{var}' → {callee_name}() derefs",
                        reachability=f"{caller_name} → {callee_name}")
                    findings.append(f)

            # --- Pattern B: callee frees, caller uses after the call ---
            if callee_param and callee_param in callee_f.freed:
                call_pos = _pos_of(cf.body_clean, rf'\b{re.escape(callee_name)}\s*\(')
                if call_pos < 0:
                    continue
                after = cf.body_clean[call_pos:]
                post = re.findall(rf'\b{re.escape(var)}\s*(?:->\w+|\[)', after)
                before = cf.body_clean[:call_pos]
                pre = re.findall(rf'\b{re.escape(var)}\s*(?:->\w+|\[)', before)
                if len(post) > len(pre):
                    f = Finding(
                        finding_id=f"P8B_{cf.file}_{cf.line + p['offset']}",
                        pattern="P8_cross_uaf", severity="high",
                        file=cf.file, line=cf.line + p['offset'],
                        function=caller_name, struct_type=var, cwe="CWE-416",
                        description=(f"'{var}' freed by {callee_name}() (param '{callee_param}'), "
                                     f"then used {len(post)-len(pre)}× in {caller_name}()"),
                        trigger_hint=f"{caller_name}() calls {callee_name}() → frees → uses",
                        reachability=f"{caller_name} → {callee_name} → {caller_name}")
                    findings.append(f)

            # --- Pattern C: double-free (both caller and callee free) ---
            if var in cf.freed and callee_param and callee_param in callee_f.freed:
                f = Finding(
                    finding_id=f"P8C_{cf.file}_{cf.line + p['offset']}",
                    pattern="P8_double_free", severity="high",
                    file=cf.file, line=cf.line + p['offset'],
                    function=caller_name, struct_type=var, cwe="CWE-415",
                    description=(f"Double-free: '{var}' freed in both "
                                 f"{caller_name}() and {callee_name}() (as '{callee_param}')"),
                    trigger_hint=f"{caller_name}() and {callee_name}() both free '{var}'",
                    reachability=f"{caller_name} ↔ {callee_name}")
                findings.append(f)

    for f in findings:
        score_finding(f, "", "", "")
    return findings
