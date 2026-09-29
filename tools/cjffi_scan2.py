#!/usr/bin/env python3
"""第二轮 CJ FFI 扫描：四个新模式族（lead 级输出，不作判定）。

F1  嵌套数组解引用     struct 内 CArr*/CJArray 字段在 for 循环中 head[i]，
                       且该 struct 本身来自外层数组（两层解引用）
F2  malloc 算术溢出    malloc/calloc(sizeof(X) * size) 或 malloc(sizeof(X)*n+m)，
                       size 来自 CJ 参数且无上限检查
F3  字符串无界构造     std::string(char*) 或 strcpy/strlen 直接作用于 CJ 传入的 char*，
                       未检查 nullptr
F4  整数截断链         int64_t size → uint32_t/int32_t/int16_t 截断后用于循环或分配
"""
from __future__ import annotations
import re, sys, json
from pathlib import Path

ARR_TYPES = {'CArrEntry','CArrStr','CJByteArray','CStringNum','CArrUI32','CArrDouble',
             'CArrInt32','CArrParameters','CParameters','CArrNativeScanFilter',
             'NativeScanFilter','CArrNativeManufactureData','CArrUI8','CCustomInfo',
             'CArrString','CArrDouble','CArrFloat','CArrLong','CArrShort'}

def split_functions(text):
    FUNC_RE = re.compile(
        r'(?:(?:static\s+|inline\s+|extern\s+|virtual\s+)*[\w:<>~\[\]*&]+\s+)+'
        r'(\w+)\s*\(([^;{}()]{0,600}?)\)\s*(?:const\s*)?\{', re.S)
    for m in FUNC_RE.finditer(text):
        name, params = m.group(1), m.group(2)
        start = m.end() - 1
        depth, i = 0, start
        while i < len(text):
            if text[i] == '{': depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0: break
            i += 1
        if depth == 0 and i - start < 30000:
            yield name, params, start, text[start:i + 1]

def line_of(text, offset):
    return text.count('\n', 0, offset) + 1

# F1: 嵌套数组解引用（外层.head[i] 内又有 .head[j] 或 .head[i].field.head）
NESTED_DEREF = re.compile(
    r'(\w+)\s*\.\s*head\s*\[\s*\w+\s*\]\s*\.\s*\w+\s*\.\s*head', re.I)

# F2: malloc 算术（乘法可能溢出）
MALLOC_ARITH = re.compile(
    r'(?:malloc|calloc|SoftBusMalloc|av_malloc)\s*\(\s*sizeof\s*\([^)]+\)\s*\*\s*(\w+(?:\.\w+|->\w+)*)', re.I)

# F3: std::string from char* without null check
STR_FROM_PTR = re.compile(
    r'std::string\s*\(\s*(\w+(?:->|\.)\w+)\s*\)', re.I)

# F4: int64 → uint32/int32 cast in size context
TRUNCATION = re.compile(
    r'(?:static_cast<\s*(u?int(?:8|16|32)_t)\s*>|\(\s*u?int(?:8|16|32)_t\s*\)\s*)'
    r'\(\s*(\w+(?:\.\w+|->\w+)*)\s*(?:\.|->)\s*(?:size|len|count)\s*\)', re.I)

def scan_file(path):
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    hits = []
    for name, params, body_start, body in split_functions(text):
        # F1: 嵌套数组
        for m in NESTED_DEREF.finditer(body):
            hits.append({'pattern': 'F1_nested_deref', 'file': str(path),
                        'line': line_of(text, body_start + m.start()),
                        'func': name, 'detail': m.group(0)[:80]})
        # F2: malloc 算术溢出
        for m in MALLOC_ARITH.finditer(body):
            var = m.group(1)
            # 检查 var 是否来自参数（可能是攻击者可控）
            if var in params or any(var.startswith(p.split('.')[0].split('->')[0]) for p in params.split(',') if p.strip()):
                hits.append({'pattern': 'F2_malloc_arith', 'file': str(path),
                            'line': line_of(text, body_start + m.start()),
                            'func': name, 'detail': f'malloc(sizeof * {var})'})
        # F3: 字符串无界构造（char* 字段直接进 std::string）
        for m in STR_FROM_PTR.finditer(body):
            var = m.group(1)
            if 'nullptr' not in body[max(0, m.start()-200):m.start()]:
                hits.append({'pattern': 'F3_str_from_ptr', 'file': str(path),
                            'line': line_of(text, body_start + m.start()),
                            'func': name, 'detail': f'std::string({var})'})
        # F4: 整数截断
        for m in TRUNCATION.finditer(body):
            hits.append({'pattern': 'F4_truncation', 'file': str(path),
                        'line': line_of(text, body_start + m.start()),
                        'func': name, 'detail': f'{m.group(1)}({m.group(2)})'})
    return hits

if __name__ == '__main__':
    root = Path(sys.argv[1])
    all_hits = []
    files = 0
    for ext in ('*.cpp', '*.c'):
        for src in root.rglob(ext):
            if '/cj/' in str(src).replace(chr(92), '/'):
                files += 1
                all_hits.extend(scan_file(src))
    all_hits.sort(key=lambda h: (h['pattern'], h['file'], h['line']))
    json.dump({'files': files, 'hits': all_hits},
              open('cjffi_leads2.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    from collections import Counter
    counts = Counter(h['pattern'] for h in all_hits)
    print(f'files={files} total={len(all_hits)}')
    for p, c in counts.most_common():
        print(f'  {p}: {c}')
