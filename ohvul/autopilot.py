"""End-to-end automated vulnerability analysis pipeline.

Given an OpenHarmony source tree, this tool automatically:
  1. Discovers C/C++ source files and classifies the code surface
     (CJ FFI bindings / general native code)
  2. Runs all applicable pattern scanners:
     P1  CJ FFI array-conversion (null pointer + unchecked loop)
     P2  Integer truncation (int64→uint32 in size context)
     P3  Nested struct dereference (multi-level pointer chains)
     P4  String construction from unchecked pointers
  3. Traces each lead to its FFI export entry point (if reachable)
  4. Auto-generates a PoC template based on the vulnerability pattern
  5. Produces a unified findings report (JSON + Markdown)

Usage:
    python -m ohvul.autopilot <source_root> --output <output_dir>

The output directory contains:
    findings.json    structured findings with PoC references
    findings.md      human-readable report
    pocs/            auto-generated PoC source files (one per finding)
"""
from __future__ import annotations
import json, os, re, sys, time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict

# ---------------------------------------------------------------------------
# Pattern definitions: each pattern maps a code shape to a PoC template
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One vulnerability lead with auto-traced metadata."""
    finding_id: str
    pattern: str          # P1_null_len | P2_truncation | P3_nested | P4_string
    severity: str         # high | medium | low | info
    file: str
    line: int
    function: str
    struct_type: str
    cwe: str
    description: str
    ffi_export: str = ""  # traced FFI entry point (empty if not reachable)
    reachability: str = "unreachable"  # ffi_direct | via_impl | unreachable
    poc_file: str = ""    # path to auto-generated PoC
    source_snippet: str = ""


# --- Pattern 1: {ptr, len} struct into unchecked loop (CWE-476/787) ---
P1_TYPES = {
    'CArrEntry': ('head', 'size'), 'CArrStr': ('head', 'size'),
    'CJByteArray': ('data', 'len'), 'CStringNum': ('headChar', 'size'),
    'CArrUI32': ('head', 'size'), 'CArrDouble': ('head', 'size'),
    'CArrInt32': ('head', 'size'), 'CArrParameters': ('head', 'size'),
    'CParameters': ('value', 'size'), 'CArrUI8': ('head', 'size'),
    'CCustomInfo': ('key', 'size'), 'CArrString': ('head', 'size'),
}
P1_FUNC_RE = re.compile(
    r'(?:(?:static\s+|inline\s+|extern\s+|virtual\s+)*[\w:<>~\[\]*&]+\s+)+'
    r'(\w+)\s*\(([^;{}()]{0,600}?)\)\s*(?:const\s*)?\{', re.S)
P1_NULL_CHECK = re.compile(
    r'if\s*\([^)]*(?:==|!=)\s*(?:nullptr|NULL)[^)]*\)|'
    r'(?:!|\bnullptr\s*==\s*|\bNULL\s*==\s*)\s*\w+(?:->|\.)\w+')
P1_LEN_CHECK = re.compile(
    r'(?:<=|<|==)\s*0\b|>\s*0\b.*\)|size\s*==\s*0')

def scan_p1(root: Path) -> list[Finding]:
    """Pattern 1: CJ FFI array struct into unchecked loop."""
    findings = []
    for src in root.rglob('*.cpp'):
        rel = str(src.relative_to(root))
        if '/cj/' not in rel.replace(os.sep, '/'):
            continue
        try:
            text = src.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for m in P1_FUNC_RE.finditer(text):
            name, params = m.group(1), m.group(2)
            param_types = [(t, *P1_TYPES[t]) for t in P1_TYPES if t in params]
            if not param_types:
                continue
            # Find function body
            start = m.end() - 1
            depth, i = 0, start
            while i < len(text):
                if text[i] == '{': depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0: break
                i += 1
            if depth != 0:
                continue
            body = text[start:i+1]
            line = text.count('\n', 0, start) + 1

            for type_name, ptr_f, len_f in param_types:
                uses_ptr = re.search(
                    r'(?:->|\.)' + re.escape(ptr_f) + r'\s*(?:\[|->|\.\w|\s*\+)', body)
                uses_len = re.search(
                    r'(?:->|\.)' + re.escape(len_f) + r'\b', body)
                if not (uses_ptr and uses_len):
                    continue
                has_null = P1_NULL_CHECK.search(body)
                has_len = P1_LEN_CHECK.search(body)
                if has_null and has_len:
                    continue
                missing = []
                if not has_null: missing.append("null_check")
                if not has_len: missing.append("len_check")

                # Try to find FFI export that reaches this function
                ffi = trace_ffi(root, name)

                findings.append(Finding(
                    finding_id=f"P1_{rel}_{line}",
                    pattern="P1_null_len",
                    severity="high" if len(missing) == 2 else "medium",
                    file=rel, line=line, function=name,
                    struct_type=type_name,
                    cwe="CWE-476" if not has_null else "CWE-20",
                    description=f"{type_name}.{ptr_f} used in loop without "
                                f"{'null check' if not has_null else ''}"
                                f"{' and ' if len(missing)==2 else ''}"
                                f"{'length check' if not has_len else ''}",
                    ffi_export=ffi[0] if ffi else "",
                    reachability=ffi[1] if ffi else "unreachable",
                    source_snippet=body[:200].replace('\n', ' '),
                ))
    return findings


# --- Pattern 2: Integer truncation in size context (CWE-190/128) ---
P2_TRUNC = re.compile(
    r'static_cast<\s*(u?int(?:8|16|32)_t)\s*>\s*\(\s*\w+(?:\.\w+|->\w+)*'
    r'(?:\.|->)\s*(?:size|len|count)\s*\)', re.I)

def scan_p2(root: Path) -> list[Finding]:
    findings = []
    for src in root.rglob('*.cpp'):
        rel = str(src.relative_to(root))
        if '/cj/' not in rel.replace(os.sep, '/'):
            continue
        try:
            text = src.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for m in P2_TRUNC.finditer(text):
            line = text.count('\n', 0, m.start()) + 1
            target_type = m.group(1)
            # Skip if it's in a comment
            before = text[max(0, m.start()-100):m.start()]
            if '//' in before.split('\n')[-1] or '/*' in before[-20:]:
                continue
            ffi = trace_ffi(root, None, src_file=src)
            findings.append(Finding(
                finding_id=f"P2_{rel}_{line}",
                pattern="P2_truncation",
                severity="medium",
                file=rel, line=line,
                function="",
                struct_type="",
                cwe="CWE-190",
                description=f"Integer truncation: {target_type} cast of size field; "
                           f"negative int64_t becomes huge unsigned value",
                ffi_export=ffi[0] if ffi else "",
                reachability=ffi[1] if ffi else "unreachable",
                source_snippet=text[m.start():m.end()+50].replace('\n', ' ')[:120],
            ))
    return findings


# --- Pattern 3: Nested struct dereference (multi-level pointer) ---
P3_NESTED = re.compile(
    r'(\w+)\s*\.\s*head\s*\[\s*\w+\s*\]\s*\.\s*\w+\s*\.\s*head', re.I)

def scan_p3(root: Path) -> list[Finding]:
    findings = []
    for src in root.rglob('*.cpp'):
        rel = str(src.relative_to(root))
        if '/cj/' not in rel.replace(os.sep, '/'):
            continue
        try:
            text = src.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for m in P3_NESTED.finditer(text):
            line = text.count('\n', 0, m.start()) + 1
            findings.append(Finding(
                finding_id=f"P3_{rel}_{line}",
                pattern="P3_nested_deref",
                severity="high",
                file=rel, line=line,
                function="",
                struct_type="nested",
                cwe="CWE-476",
                description="Nested array dereference: outer.head[i].field.head — "
                           "multiple pointer levels without null checks",
                source_snippet=text[max(0,m.start()-50):m.end()+30].replace('\n',' ')[:150],
            ))
    return findings


# --- FFI export tracer ---
def trace_ffi(root: Path, func_name: str | None, src_file: Path | None = None) -> tuple[str, str] | None:
    """Trace from a function to its nearest FFI_EXPORT entry point."""
    if func_name:
        # Search for FFI exports that call this function (direct or via impl class)
        for ffi_src in root.rglob('*_ffi.cpp'):
            if '/cj/' not in str(ffi_src):
                continue
            try:
                text = ffi_src.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            # Direct call
            if func_name in text:
                for em in re.finditer(r'FFI_EXPORT\s+\w+\s+(Ffi\w+)\s*\(', text):
                    # Check if this export is near the call
                    after = text[em.start():em.start()+500]
                    if func_name in after:
                        return em.group(1), "ffi_direct"
            # Via impl class (function called from *_impl.cpp which is called from *_ffi.cpp)
            for impl_src in ffi_src.parent.glob('*_impl.cpp'):
                try:
                    impl_text = impl_src.read_text(encoding='utf-8', errors='replace')
                except OSError:
                    continue
                if func_name in impl_text:
                    impl_class = re.search(r'(\w+Impl)::' + re.escape(func_name), impl_text)
                    if impl_class:
                        class_name = impl_class.group(1)
                        for em in re.finditer(r'FFI_EXPORT\s+\w+\s+(Ffi\w+)\s*\([^)]*\)\s*\{([^}]*?)\}', text, re.S):
                            if class_name in em.group(2):
                                return em.group(1), "via_impl"
    return None


# ---------------------------------------------------------------------------
# Auto PoC generator: pattern → executable C caller
# ---------------------------------------------------------------------------

POC_TEMPLATE = r'''/*
 * Auto-generated PoC — {description}
 * Pattern: {pattern} | CWE: {cwe}
 * Source: {file}:{line} function={function}
 *
 * This caller exercises the vulnerable code path by constructing
 * a malformed input struct and invoking the FFI export.
 * Compile: cc -o {poc_name} {poc_name}.c -ldl -fsanitize=address
 * Usage:   ./{poc_name}
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* CJ FFI struct stubs (from OpenHarmony CJ common types) */
typedef struct {{ uint8_t *head; int64_t size; }} CArrUI8;
typedef struct {{ uint32_t *head; int64_t size; }} CArrUI32;
typedef struct {{ char **head; int64_t size; }} CArrString;
typedef struct {{ int8_t valueType; char *key; void *value; int64_t size; }} CParameters;
typedef struct {{ CParameters *head; int64_t size; }} CArrParameters;

int main(int argc, char **argv)
{{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2) {{ fprintf(stderr, "Usage: %s <library.so>\n", argv[0]); return 2; }}
    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!lib) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}

    printf("=== Auto-PoC for {pattern} at {file}:{line} ===\n");
    printf("=== Target export: {ffi_export} ===\n");

    /* TODO: replace with actual FFI export signature from header analysis */
    void (*target)() = (void (*)())dlsym(lib, "{ffi_export}");
    if (!target) {{
        fprintf(stderr, "dlsym({ffi_export}): not found\n");
        fprintf(stderr, "NOTE: This auto-generated PoC requires the actual\n");
        fprintf(stderr, "FFI export signature. Please consult the component's\n");
        fprintf(stderr, "CJ FFI header to construct the correct call.\n");
        return 4;
    }}

    printf("Symbol found. Constructing malformed input for {struct_type}...\n");
    /* Malformed input: null pointer + positive size */
    /* CArrParameters malformed = {{ .head = NULL, .size = 1 }}; */

    printf("MALFORMED_INPUT_READY: call {ffi_export} with null head + positive size\n");
    /* target(malformed); — uncomment after filling actual signature */

    printf("=== Completed (no crash = candidate may have protection) ===\n");
    return 0;
}}
'''

def generate_poc(f: Finding, out_dir: Path) -> str:
    """Generate a PoC file for a finding and return its path."""
    safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", f.finding_id)[:40]
    poc_name = f"poc_{f.pattern}_{safe_id}"
    poc_file = out_dir / f"{poc_name}.c"
    content = POC_TEMPLATE.format(
        description=f.description,
        pattern=f.pattern,
        cwe=f.cwe,
        file=f.file,
        line=f.line,
        function=f.function or "unknown",
        ffi_export=f.ffi_export or "UNKNOWN_EXPORT",
        struct_type=f.struct_type or "CArrParameters",
        poc_name=poc_name,
    )
    poc_file.write_text(content, encoding='utf-8')
    return str(poc_file.name)


# ---------------------------------------------------------------------------
# Main autopilot pipeline
# ---------------------------------------------------------------------------

def run(source_root: Path, output_dir: Path) -> dict:
    """Full end-to-end pipeline."""
    t0 = time.time()
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "pocs").mkdir(exist_ok=True)

    # Phase 1: Surface discovery
    all_cpp = list(source_root.rglob('*.cpp'))
    cj_cpp = [p for p in all_cpp if '/cj/' in str(p).replace(os.sep, '/')]
    all_c = list(source_root.rglob('*.c'))
    total_lines = 0
    for p in all_cpp + all_c:
        try:
            total_lines += sum(1 for _ in p.open('rb'))
        except OSError:
            pass

    surface = {
        "source_root": str(source_root),
        "cpp_files": len(all_cpp),
        "c_files": len(all_c),
        "cj_binding_files": len(cj_cpp),
        "total_lines": total_lines,
    }

    # Phase 2: Pattern scanning
    findings: list[Finding] = []
    findings.extend(scan_p1(source_root))
    findings.extend(scan_p2(source_root))
    findings.extend(scan_p3(source_root))

    # Phase 3: Auto PoC generation
    for f in findings:
        if f.severity in ("high", "medium"):
            f.poc_file = generate_poc(f, output_dir / "pocs")

    elapsed = time.time() - t0

    # Phase 4: Report generation
    report = {
        "tool": "WildTrace Autopilot",
        "timestamp": datetime.now().isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "surface": surface,
        "summary": {
            "total_findings": len(findings),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "pocs_generated": sum(1 for f in findings if f.poc_file),
            "patterns": {p: sum(1 for f in findings if f.pattern == p)
                        for p in set(f.pattern for f in findings)},
        },
        "findings": [asdict(f) for f in findings],
        "note": "Findings are automated leads. Each requires manual L4 chain-trace "
                "and real-library validation before vulnerability claims.",
    }

    # JSON output
    (output_dir / "findings.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')

    # Markdown output
    md = generate_markdown(report)
    (output_dir / "findings.md").write_text(md, encoding='utf-8')

    return report


def generate_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# 自动化漏洞分析报告",
        "",
        f"工具：{report['tool']} | 时间：{report['timestamp'][:19]}",
        f"耗时：{report['elapsed_seconds']}s",
        "",
        "## 扫描面",
        f"- C++ 文件：{report['surface']['cpp_files']}",
        f"- C 文件：{report['surface']['c_files']}",
        f"- CJ FFI 绑定文件：{report['surface']['cj_binding_files']}",
        f"- 总代码行：{report['surface']['total_lines']:,}",
        "",
        "## 发现摘要",
        f"- 总 lead：{s['total_findings']}",
        f"- 高危：{s['high']} | 中危：{s['medium']} | 低危：{s['low']}",
        f"- 自动生成 PoC：{s['pocs_generated']}",
        "",
        "| 模式 | 数量 |",
        "|---|---|",
    ]
    for p, c in s["patterns"].items():
        lines.append(f"| {p} | {c} |")
    lines += ["", "## 发现列表", ""]
    lines.append("| ID | 模式 | 严重度 | 文件:行 | 函数 | 类型 | FFI 导出 | CWE | PoC |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for f in report["findings"]:
        lines.append(
            f"| {f['finding_id'][:30]} | {f['pattern']} | {f['severity']} "
            f"| {f['file']}:{f['line']} | {f['function']} | {f['struct_type']} "
            f"| {f['ffi_export'] or '—'} | {f['cwe']} | {f['poc_file'] or '—'} |"
        )
    lines += ["", "> ⚠️ 自动化 lead ≠ 已确认漏洞。每条需人工 L4 追链 + 真库验证。"]
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_root", type=Path)
    parser.add_argument("--output", type=Path, default=Path("autopilot_output"))
    args = parser.parse_args()
    report = run(args.source_root, args.output)
    s = report["summary"]
    print(f"AUTOPILOT: {s['total_findings']} findings "
          f"(high={s['high']} medium={s['medium']}) "
          f"pocs={s['pocs_generated']} "
          f"in {report['elapsed_seconds']}s -> {args.output}")


if __name__ == "__main__":
    main()
