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


_TYPE_WORDS = {'const', 'struct', 'unsigned', 'signed', 'int',
               'char', 'long', 'short', 'float', 'double',
               'size_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
               'int8_t', 'int16_t', 'int32_t', 'int64_t', 'bool'}


def _parse_params(params_str: str) -> list[str]:
    """Extract ordered parameter variable names, positionally aligned.

    Chunks without a resolvable name (function pointers, arrays, unnamed
    params) keep an empty slot so later indices still line up with the
    callee's real signature (audit P1: dropping them shifted every
    following alias to the wrong parameter)."""
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
        if m2 and m2.group(1) not in _TYPE_WORDS:
            names.append(m2.group(1))
        else:
            names.append('')  # unnamed / fn-ptr / array: keep the slot
    return names


def build_facts(root: Path) -> dict[str, FuncFacts]:
    """Scan all C/C++ files and build per-function facts.

    A function name defined in more than one file (common for static
    helpers) cannot be resolved to a single implementation by name.
    Definitions with identical facts are kept (attribution is then
    irrelevant); any factual difference makes the name ambiguous and it
    is dropped instead of silently attributing everything to the last
    definition seen (audit P1)."""
    facts = {}
    ambiguous = set()
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

            if not (ff.freed or ff.deref or ff.passes):
                continue
            if fname in facts:
                existing = facts[fname]
                same = (existing.param_list == ff.param_list
                        and existing.freed == ff.freed
                        and existing.deref == ff.deref
                        and {(p['callee'], p['arg_pos'], p['var'])
                             for p in existing.passes}
                            == {(p['callee'], p['arg_pos'], p['var'])
                                for p in ff.passes})
                if same:
                    continue  # identical facts: attribution is irrelevant
                ambiguous.add(fname)
                continue
            facts[fname] = ff
    for name in ambiguous:
        facts.pop(name, None)
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


def _pos_all(body: str, pattern: str) -> list[int]:
    return [m.start() for m in re.finditer(pattern, body)]


def scan_cross_uaf(root: Path, facts: dict | None = None) -> list[Finding]:
    """Detect cross-function UAF / double-free using positional alias resolution."""
    if facts is None:
        facts = build_facts(root)

    findings = []

    for caller_name, cf in facts.items():
        # Each pattern is a property of the (callee, variable) pair: emit
        # it once instead of once per call site (audit P1: 3000 sink()
        # calls produced 3000 identical findings and dominated the 889
        # count).
        seen_a, seen_b, seen_c = set(), set(), set()
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
            if var in cf.freed and (callee_name, var) not in seen_a:
                seen_a.add((callee_name, var))
                free_pos = _pos_of(cf.body_clean,
                    rf'\b(?:free|SoftBusFree|av_free)\s*\(\s*{re.escape(var)}\s*\)')
                # any call site after the free counts — the first call may
                # legitimately precede it (audit P1: first-occurrence-only
                # missed the free-then-pass ordering)
                pass_poss = _pos_all(cf.body_clean, rf'\b{re.escape(callee_name)}\s*\(')
                if free_pos >= 0 and any(pp > free_pos for pp in pass_poss) \
                        and callee_param and callee_param in callee_f.deref:
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
                key = (callee_name, var)
                if key not in seen_b:
                    seen_b.add(key)
                    # calls that pass THIS variable (other arguments to the
                    # same callee are irrelevant for this pair)
                    call_poss = _pos_all(cf.body_clean,
                                         rf'\b{re.escape(callee_name)}\s*\(\s*{re.escape(var)}\b')
                    if not call_poss:
                        continue
                    after = cf.body_clean[call_poss[-1]:]
                    # a NULL reset after the freeing call retires the
                    # pointer — same rule single-function P8 applies
                    if re.search(rf'\b{re.escape(var)}\s*=\s*(?:NULL|nullptr|0)\s*;', after):
                        continue
                    post = re.findall(rf'\b{re.escape(var)}\s*(?:->\w+|\[)', after)
                    if post:
                        f = Finding(
                            finding_id=f"P8B_{cf.file}_{cf.line + p['offset']}",
                            pattern="P8_cross_uaf", severity="high",
                            file=cf.file, line=cf.line + p['offset'],
                            function=caller_name, struct_type=var, cwe="CWE-416",
                            description=(f"'{var}' freed by {callee_name}() (param '{callee_param}'), "
                                         f"then used {len(post)}× after the call in {caller_name}()"),
                            trigger_hint=f"{caller_name}() calls {callee_name}() → frees → uses",
                            reachability=f"{caller_name} → {callee_name} → {caller_name}")
                        findings.append(f)

            # --- Pattern C: double-free (both caller and callee free) ---
            if var in cf.freed and callee_param and callee_param in callee_f.freed \
                    and (callee_name, var) not in seen_c:
                seen_c.add((callee_name, var))
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
