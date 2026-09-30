"""Enumerate OpenHarmony IPC attack surface from proxy/stub sources.

Scans a component repo for IPC server entry points (stub dispatch tables)
and extracts, per entry: the request code, handler name, definition
file:line, and the MessageParcel reads performed inside the handler body.
This yields the source-side target list for taint/fuzz work (P0-3 of the
discovery roadmap). Output is a review aid, never a vulnerability verdict.

Supported dispatch idioms:
  - memberFuncMap_[CODE] = &Class::OnXxx;      (registry)
  - switch (code) { case CODE: ... OnXxx(...); } (classic)
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

BS = chr(92)
REG_MAP = re.compile(r'memberFuncMap_\s*\[\s*(\w+)\s*\]\s*=\s*&(\w+)::(\w+)\s*;')
REG_CASE = re.compile(r'case\s+(\w+)\s*:.*?(\w+)::(\w+)\s*\(')
REG_DLSYM = re.compile(r'dlsym\s*\(\s*\w+\s*,\s*"(\w+)"\s*\)')
REG_DEF = re.compile(r'(?:int32_t|int|void)\s+(\w+)::(\w+)\s*\(\s*(?:MessageParcel|Parcel|DataBlob)\s*&\w+\s*,\s*(?:MessageParcel|Parcel)\s*&\w+')
REG_READ = re.compile(r'\b(?:data|parcel|req|request)\.(Read\w+)\s*\(')
REG_DECL = re.compile(r'^\s*int32_t\s+(\w+)\s*\(\s*(?:MessageParcel|Parcel)\s*&', re.M)
EXCLUDE = ('test', 'third_party')


def iter_sources(repo: Path):
    for p in repo.rglob('*.cpp'):
        s = str(p)
        if not any(x in s.lower() for x in EXCLUDE):
            yield p


def handler_bodies(text: str):
    """Yield (name, start_offset, body) for parcel-handler functions."""
    for m in REG_DEF.finditer(text):
        depth, i = 0, m.end()
        while i < len(text) and text[i] != '{':
            if text[i] == ';':      # declaration only
                break
            i += 1
        else:
            depth, j = 1, i
            i += 1
            while i < len(text):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        yield m.group(2), m.start(), text[m.start():i + 1]
                        break
                i += 1


def scan_repo(repo: Path) -> dict:
    files = {str(p.relative_to(repo)).replace(BS, '/'): p.read_text(
        encoding='utf-8', errors='replace') for p in iter_sources(repo)}
    stubs = []
    for rel, text in files.items():
        entries = []
        for m in REG_MAP.finditer(text):
            entries.append({'code': m.group(1), 'class': m.group(2), 'handler': m.group(3),
                            'registered_in': f'{rel}'})
        for m in REG_CASE.finditer(text):
            e = {'code': m.group(1), 'class': m.group(2), 'handler': m.group(3),
                 'registered_in': f'{rel}'}
            if not any(x['code'] == e['code'] and x['handler'] == e['handler'] for x in entries):
                entries.append(e)
        if entries:
            stubs.append({'file': rel, 'entries': entries})
        for m in REG_DLSYM.finditer(text):
            stubs.append({'file': rel, 'entries': [], 'dynamic_dispatch': m.group(1),
                          'note': 'handlers live in an extension .so loaded via dlsym; not statically enumerable in this repo'})
    # 定位 handler 定义与读取面
    defs = {}
    for rel, text in files.items():
        for name, off, body in handler_bodies(text):
            line = text[:off].count(chr(10)) + 1
            reads = {}
            for r in REG_READ.findall(body):
                reads[r] = reads.get(r, 0) + 1
            defs.setdefault(name, []).append({'file': rel, 'line': line, 'reads': reads})
    for stub in stubs:
        for e in stub['entries']:
            e['defined_at'] = defs.get(e['handler'], [])
    total = sum(len(s['entries']) for s in stubs)
    return {'schema': 'attack-surface-0.1', 'repo': str(repo),
            'stub_files': len(stubs), 'entries_total': total,
            'note': 'IPC server entry points for taint/fuzz targeting; review aid only',
            'stubs': stubs}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    result = scan_repo(args.repo)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding='utf-8')
    print(f"stub files: {result['stub_files']}, entries: {result['entries_total']} -> {args.out}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
