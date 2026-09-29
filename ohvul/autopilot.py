"""End-to-end automated vulnerability analysis pipeline (v2 — 9 pattern families).

Given any C/C++ source tree, this tool automatically:
  1. Discovers files and classifies the code surface (CJ FFI / general native)
  2. Runs 9 pattern-family scanners:
     CJ FFI specific (only when /cj/ present):
       P1  Array struct null+unchecked loop
       P2  Integer truncation in size context
       P3  Nested multi-level pointer dereference
     General C/C++ (any codebase):
       P4  Unbounded memory copy (memcpy/strcpy/sprintf with param size)
       P5  Stack buffer overflow (fixed local buffer + unchecked write)
       P6  Null pointer dereference (pointer param, no null check, ≥3 uses)
       P7  Integer overflow in allocation (malloc(n*sizeof) with param n)
       P8  Use-after-free (free then use in same function, no NULL reset)
       P9  Format string (non-literal format from variable)
  3. Auto-generates PoC templates for high/medium findings
  4. Produces unified findings report (JSON + Markdown + pocs/ directory)

Usage: python -m ohvul.autopilot <source_root> --output <output_dir>
"""
from __future__ import annotations
import json, os, re, sys, time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    finding_id: str; pattern: str; severity: str; file: str; line: int
    function: str; struct_type: str; cwe: str; description: str
    ffi_export: str = ""; reachability: str = "n/a"; poc_file: str = ""
    source_snippet: str = ""; trigger_hint: str = ""


# ---------------------------------------------------------------------------
# Shared parser
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
    return bool(re.search(rf'if\s*\([^)]*{var}\s*(?:==\s*(?:NULL|nullptr|0)\b|!=\s*(?:NULL|nullptr))', cleaned, re.I))

def _has_bound_check(cleaned, var):
    return bool(re.search(rf'if\s*\([^)]*{var}\s*(?:[<>]=?|==)\s*\d', cleaned))


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
                if not (re.search(r'(?:->|\.)' + pf + r'\s*(?:\[|->|\.|\s*\+)', cl) and re.search(r'(?:->|\.)' + lf + r'\b', cl)):
                    continue
                if _has_null_check(cl, rf'\w+(?:->|\.){pf}'): continue
                if re.search(rf'(?:->|\.){lf}\s*(?:==|<=|<)\s*0', cl): continue
                out.append(Finding(
                    f"P1_{rel}_{line}", "P1_null_len", "high", rel, line, name, tn,
                    "CWE-476", f"{tn}.{pf} unchecked in loop",
                    trigger_hint=f"{{{pf}=NULL, {lf}=1}}"))
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
            out.append(Finding(f"P2_{rel}_{line}", "P2_truncation", "medium", rel, line,
                "", m.group(1), "CWE-190", f"int64→{m.group(1)} truncation",
                trigger_hint="Pass negative size"))
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
            out.append(Finding(f"P3_{rel}_{line}", "P3_nested_deref", "high", rel, line,
                "", "nested", "CWE-476", "Multi-level pointer chain",
                trigger_hint="Inner head=NULL, outer size>0"))
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
                        out.append(Finding(
                            f"P4_{rel}_{line}", "P4_unbounded_copy", "high", rel, line,
                            name, fname, cwe,
                            f"{fname}() size from param '{size_var}', no bounds check",
                            trigger_hint=f"Call {name}() with oversized {size_var}"))
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
                        out.append(Finding(
                            f"P5_{rel}_{line}", "P5_stack_overflow", "high", rel, line,
                            name, f"char[{sz}]", "CWE-121",
                            f"Stack buf {buf}[{sz}] + unchecked write",
                            trigger_hint=f"String >{sz} bytes to {name}()"))
    return out

def scan_p6(root):
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
                out.append(Finding(
                    f"P6_{rel}_{line}", "P6_null_deref", "medium", rel, line,
                    name, pp, "CWE-476",
                    f"Ptr '{pp}' dereferenced {len(derefs)}×, no null check",
                    trigger_hint=f"{name}(NULL)"))
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
                out.append(Finding(
                    f"P7_{rel}_{line}", "P7_alloc_overflow", "medium", rel, line,
                    name, sv, "CWE-680",
                    f"malloc(sizeof * {sv}), param-controlled, no overflow guard",
                    trigger_hint=f"{name}(SIZE_MAX/8)"))
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
                    out.append(Finding(
                        f"P8_{rel}_{line}", "P8_use_after_free", "high", rel, line,
                        name, fv, "CWE-416",
                        f"'{fv}' freed then used ({len(uses)} refs after free)",
                        trigger_hint=f"Path in {name}() reaching post-free use"))
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
                    out.append(Finding(
                        f"P9_{rel}_{line}", "P9_format_string", "high", rel, line,
                        name, vm.group(1), "CWE-134",
                        f"Non-literal format '{vm.group(1)}' in printf-family",
                        trigger_hint=f"Pass '%n%n%n' as {vm.group(1)}"))
    return out


# ---------------------------------------------------------------------------
# PoC templates
# ---------------------------------------------------------------------------
_POC = {
"P1_null_len": '''/* Auto-PoC: {pattern} {cwe} {file}:{line} {function}
 * Trigger: {trigger_hint} */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
int main(int c, char **v) {{
    if (c != 2) return 2;
    void *lib = dlopen(v[1], RTLD_NOW); if (!lib) return 3;
    printf("P1: malformed {{NULL,1}} -> {function}\\n");
    /* Call FFI export with {{NULL, 1}} */ return 0;
}}''',
"P2_truncation": None,  # reuse P1
"P3_nested_deref": None,
"P4_unbounded_copy": '''/* Auto-PoC: {pattern} {cwe} {file}:{line} {function}
 * Trigger: {trigger_hint} */
#include <stdio.h>
#include <string.h>
int main(void) {{
    char small[8] = {{0}};
    char big[256]; memset(big, 'A', sizeof(big)-1);
    printf("P4: {struct_type}(small, big, %zu)\\n", strlen(big));
    /* {struct_type}(small, big, strlen(big)); */ return 0;
}}''',
"P5_stack_overflow": '''/* Auto-PoC: {pattern} {cwe} {file}:{line} {function}
 * Trigger: {trigger_hint} */
#include <stdio.h>
#include <string.h>
int main(void) {{
    char input[4096]; memset(input, 'A', 4095); input[4095] = 0;
    printf("P5: %zu-byte string -> {function} ({struct_type})\\n", strlen(input));
    /* {function}(input); */ return 0;
}}''',
"P6_null_deref": '''/* Auto-PoC: {pattern} {cwe} {file}:{line} {function}
 * Trigger: {trigger_hint} */
#include <stdio.h>
#include <stddef.h>
int main(void) {{
    printf("P6: {function}(NULL)\\n");
    /* {function}(NULL); */ return 0;
}}''',
"P7_alloc_overflow": '''/* Auto-PoC: {pattern} {cwe} {file}:{line} {function}
 * Trigger: {trigger_hint} */
#include <stdio.h>
#include <stdint.h>
int main(void) {{
    printf("P7: {function}({struct_type}=SIZE_MAX/8)\\n");
    /* {function}(SIZE_MAX / 8); */ return 0;
}}''',
"P8_use_after_free": '''/* Auto-PoC: {pattern} {cwe} {file}:{line} {function}
 * Trigger: {trigger_hint} */
#include <stdio.h>
int main(void) {{
    printf("P8: {function}() post-free use of '{struct_type}'\\n");
    printf("Requires specific input reaching UAF path\\n"); return 0;
}}''',
"P9_format_string": '''/* Auto-PoC: {pattern} {cwe} {file}:{line} {function}
 * Trigger: {trigger_hint} */
#include <stdio.h>
int main(void) {{
    char *fmt = "%n%n%n";
    printf("P9: {function}(fmt=\\"%s\\")\\n", fmt);
    /* {function}(fmt); */ return 0;
}}''',
}
_POC["P2_truncation"] = _POC["P1_null_len"]
_POC["P3_nested_deref"] = _POC["P1_null_len"]

def generate_poc(f, out_dir):
    tpl = _POC.get(f.pattern)
    if not tpl: return ""
    sid = re.sub(r'[^a-zA-Z0-9_]', '_', f.finding_id)[:40]
    name = f"poc_{f.pattern}_{sid}.c"
    (out_dir / name).write_text(tpl.format(
        pattern=f.pattern, cwe=f.cwe, file=f.file, line=f.line,
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

def run(source_root: Path, output_dir: Path) -> dict:
    t0 = time.time()
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "pocs").mkdir(exist_ok=True)
    all_cpp = list(source_root.rglob('*.cpp')) if hasattr(source_root, 'rglob') else list(source_root.rglob('*.cpp'))
    all_c = list(source_root.rglob('*.c'))
    cj = [p for p in all_cpp if '/cj/' in str(p).replace(os.sep, '/')]
    has_cj = len(cj) > 0
    total_lines = 0
    for p in (all_cpp + all_c)[:200]:
        try: total_lines += sum(1 for _ in p.open('rb'))
        except OSError: pass
    if len(all_cpp + all_c) > 200:
        total_lines = total_lines * len(all_cpp + all_c) // 200

    findings = []
    for pid, scanner, scope in SCANNERS:
        if scope == "cj" and not has_cj: continue
        try: findings.extend(scanner(source_root))
        except Exception as e: print(f"WARN {pid}: {e}", file=sys.stderr)

    for f in findings:
        if f.severity in ("high", "medium"):
            f.poc_file = generate_poc(f, output_dir / "pocs")

    elapsed = time.time() - t0
    pc = {}
    for f in findings: pc[f.pattern] = pc.get(f.pattern, 0) + 1
    report = {
        "tool": "WildTrace Autopilot v2",
        "timestamp": datetime.now().isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "surface": {"cpp": len(all_cpp), "c": len(all_c), "cj": len(cj),
                     "lines_est": total_lines, "has_cj": has_cj},
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "pocs": sum(1 for f in findings if f.poc_file),
            "patterns": pc,
            "scanners": [p for p, _, s in SCANNERS if s == "gen" or (s == "cj" and has_cj)],
        },
        "findings": [asdict(f) for f in findings],
    }
    (output_dir / "findings.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    (output_dir / "findings.md").write_text(_md(report), encoding='utf-8')
    return report

def _md(r):
    s = r["summary"]; sf = r["surface"]
    L = ["# 自动化漏洞分析报告", "",
         f"工具：{r['tool']} | {r['timestamp'][:19]} | 耗时 {r['elapsed_seconds']}s",
         "", f"扫描面：C++ {sf['cpp']} | C {sf['c']} | CJ {sf['cj']} | ~{sf['lines_est']:,} 行",
         "", f"发现：**{s['total']}** 条（高危 {s['high']} / 中危 {s['medium']}）| PoC {s['pocs']} 个",
         f"扫描器：{', '.join(s['scanners'])}", "", "| 模式 | 数量 |", "|---|---|"]
    for p, c in sorted(s["patterns"].items()): L.append(f"| {p} | {c} |")
    L += ["", "| 模式 | 严重度 | 位置 | 函数 | CWE |", "|---|---|---|---|---|"]
    for f in r["findings"][:100]:
        L.append(f"| {f['pattern']} | {f['severity']} | {f['file']}:{f['line']} | {f['function']} | {f['cwe']} |")
    L += ["", "> lead ≠ 漏洞"]
    return "\n".join(L)

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("source_root", type=Path)
    p.add_argument("--output", type=Path, default=Path("autopilot_output"))
    a = p.parse_args()
    r = run(a.source_root, a.output)
    s = r["summary"]
    print(f"AUTOPILOT v2: {s['total']} (H={s['high']} M={s['medium']}) pocs={s['pocs']} "
          f"scanners={','.join(s['scanners'])} {r['elapsed_seconds']}s")

if __name__ == "__main__":
    main()
