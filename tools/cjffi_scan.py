#!/usr/bin/env python3
"""CJ FFI 数组转换模式扫描器（第一线清扫，lead 级输出，不作判定）。

模式来源：IPC (CVE 候选) 与 KV (CVE 候选) 的共同形态——FFI 边界上的
{指针, 长度} 结构（CArrEntry/CJByteArray/CArrStr...）直接进入元素访问
循环，且循环前对指针无 NULL 检查、对长度无 <=0 检查。

输出为 review lead：命中≠漏洞，需人工 L4。
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

# ---------- CJ 数组类型自举：从所有头文件里挖 {指针,长度} 形态的 typedef ----------
ARR_STRUCT_RE = re.compile(
    r'typedef\s+struct\s*\{([^{}]{10,400}?)\}\s*([A-Z][A-Za-z0-9_]+)\s*;', re.S)
PTR_FIELD_RE = re.compile(r'\b[\w:<>]+\s*\*+\s*(\w+)\s*;')
NUM_FIELD_RE = re.compile(r'\b(?:int64_t|int32_t|uint32_t|uint64_t|size_t|unsigned)\s+(\w+)\s*;')
KNOWN_ARRAY_TYPES = {
    'CArrEntry': ('head', 'size'), 'CArrStr': ('head', 'size'),
    'CJByteArray': ('data', 'len'), 'CStringNum': ('headChar', 'size'),
    'CArrUI32': ('head', 'size'), 'CArrDouble': ('head', 'size'),
    'CArrInt32': ('head', 'size'),
}

def inventory_types(root: Path):
    types = dict(KNOWN_ARRAY_TYPES)
    for header in root.rglob('*.h'):
        try:
            text = header.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for body, name in ARR_STRUCT_RE.findall(text):
            ptrs = PTR_FIELD_RE.findall(body)
            nums = NUM_FIELD_RE.findall(body)
            len_like = [n for n in nums if n.lower() in ('size', 'len', 'count', 'num')]
            if ptrs and len_like:
                types.setdefault(name, (ptrs[0], len_like[0]))
    return types

# ---------- 函数粗切 ----------
FUNC_RE = re.compile(
    r'(?:(?:static\s+|inline\s+|extern\s+|virtual\s+)*[\w:<>~\[\]*&]+\s+)+'
    r'(\w+)\s*\(([^;{}()]{0,600}?)\)\s*(?:const\s*)?\{', re.S)

def split_functions(text: str):
    for m in FUNC_RE.finditer(text):
        name, params = m.group(1), m.group(2)
        start = m.end() - 1  # 指向 '{'
        depth, i = 0, start
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth == 0 and i - start < 30000:
            yield name, params, start, text[start:i + 1]

def line_of(text: str, offset: int):
    return text.count('\n', 0, offset) + 1

def scan_file(path: Path, types: dict):
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    hits = []
    for name, params, body_start, body in split_functions(text):
        # 参数里出现 CJ 数组类型？
        param_types = []
        for tname, (pfield, lfield) in types.items():
            if re.search(r'\b' + tname + r'\b', params):
                param_types.append((tname, pfield, lfield))
        if not param_types:
            continue
        # 循环里通过 .field/->field 访问元素？
        for tname, pfield, lfield in param_types:
            loop_uses = re.findall(
                r'(?:->|\.)' + re.escape(pfield) + r'\s*(?:\[|->|\.\w|\s*\+|\+\+|\))', body)
            len_uses = re.findall(
                r'(?:->|\.)' + re.escape(lfield) + r'\b', body)
            if not loop_uses or not len_uses:
                continue
            # 检查是否存在空指针/非正长度防护（循环体内或之前）
            null_check = re.search(
                r'if\s*\([^)]*(?:->|\.)' + re.escape(pfield) + r'\s*(?:==|!=)\s*(?:nullptr|NULL)|'
                r'(?:!|nullptr\s*==\s*|NULL\s*==\s*)(?:\w+->|\w+\.)' + re.escape(pfield), body)
            len_check = re.search(
                r'if\s*\([^)]*(?:->|\.)' + re.escape(lfield) + r'\s*(?:<=|<|==)\s*(?:0|0u)|'
                r'(?:->|\.)' + re.escape(lfield) + r'\s*>\s*0\s*\)|'
                r'(?:->|\.)' + re.escape(lfield) + r'\s*<=\s*0', body)
            if null_check and len_check:
                continue  # 双防护齐备，跳过
            snippet = body[:400].replace('\n', ' ')[:280]
            hits.append({
                'file': str(path), 'line': line_of(text, body_start),
                'func': name, 'type': tname,
                'missing': ('null' if not null_check else '') +
                           ('+' if not null_check and not len_check else '') +
                           ('len' if not len_check else ''),
                'snippet': snippet,
            })
    return hits

def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else '.')
    types = inventory_types(root)
    print(f'array types inventoried: {len(types)}', file=sys.stderr)
    all_hits = []
    files = 0
    for src in root.rglob('*.cpp'):
        files += 1
        all_hits.extend(scan_file(src, types))
    for src in root.rglob('*.c'):
        if '/cj/' in str(src).replace('\\', '/') or src.match('*.c'):
            files += 1
            all_hits.extend(scan_file(src, types))
    # 排序：缺双检 > 缺单检
    all_hits.sort(key=lambda h: (len(h['missing']), h['file'], h['line']))
    out = Path('cjffi_leads.json')
    json.dump({'types': {k: list(v) for k, v in types.items()},
               'files_scanned': files, 'hits': all_hits},
              open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'files={files} leads={len(all_hits)} -> {out}')
    both = [h for h in all_hits if h['missing'] in ('null+len', 'null+ len')]
    print(f'missing-both-checks: {len([h for h in all_hits if len(h["missing"]) > 4])}')

if __name__ == '__main__':
    main()
