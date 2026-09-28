"""Variant-family scanner: mine the ffmpeg gap families' patterns elsewhere.

Families distilled from the 21 confirmed ffmpeg gaps
(docs/analysis/FFMPEG_GAP_BATCH_TRIAGE_20260921.md):

  F1 short-decompress-tail    decompress call in a function that returns
                              without zeroing the tail of the output buffer
  F2 config-size-vs-frame-size allocation by config/link size in one place,
                              indexed/copied by frame size in another
  F3 guard-arith-overflow     capacity checks with 3+-term additive int
                              arithmetic (wraparound-bypassable)

Text-level heuristics — hits are review leads only, never verdicts.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

BS = chr(92)
DECOMP = re.compile(r'\b(inflate|uncompress|BZ2_bzBuffToBuffDecompress|LZ4_decompress_safe|zlib_decompress|mszh_decomp|deflate.*decode)\s*\(')
MEMSET = re.compile(r'\bmemset\s*\(')
ALLOC_BY_LINK = re.compile(r'(?:av_malloc_array|av_calloc|av_malloc|malloc|calloc)\s*\(\s*(?:[a-z_]+->)?(?:w|width|inlink->w|inlink->width|s->width)\b')
FRAME_SIZE_USE = re.compile(r'\b(?:in|frame|src|p)->(?:width|w)\b')
GUARD_3TERM = re.compile(
    r'if\s*' + re.escape('(') + r'[^;{}]{10,120}?[-+]\s*[A-Za-z_][\w.>\[\]-]*\s*[-+]\s*[^;{}]{2,60}?>\s*[A-Z_][A-Z0-9_]{2,30}\s*' + re.escape(')'))
EXCLUDE = ('test', 'third_party', 'examples')


def functions(text: str):
    start = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w:<>,\s*&]*\([^;{}]*\)\s*(?:const\s*)?\{', re.M)
    for m in start.finditer(text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    yield m.start(), text[m.start():i + 1]
                    break
            i += 1


def scan_file(path: Path):
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    hits = []
    # F1: decompress + return, no memset in the same function
    for off, body in functions(text):
        if DECOMP.search(body) and 'memset' not in body and re.search(r'\breturn\b', body):
            hits.append(('F1_short_tail', text[:off].count(chr(10)) + 1,
                         DECOMP.search(body).group(0)[:40]))
    # F2: file-level alloc-by-link + frame-size use
    if ALLOC_BY_LINK.search(text) and FRAME_SIZE_USE.search(text):
        m = FRAME_SIZE_USE.search(text)
        hits.append(('F2_size_mismatch', text[:m.start()].count(chr(10)) + 1, m.group(0)[:60]))
    # F3: 3+-term additive capacity guards
    for m in GUARD_3TERM.finditer(text):
        hits.append(('F3_guard_overflow', text[:m.start()].count(chr(10)) + 1, m.group(0).strip()[:80]))
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, required=True)
    ap.add_argument('--ext', default='.c,.cpp,.h')
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    exts = tuple(args.ext.split(','))
    results = []
    files = [p for p in args.root.rglob('*')
             if p.suffix in exts and not any(x in str(p).lower() for x in EXCLUDE)]
    for p in files:
        for fam, line, ev in scan_file(p):
            results.append({'family': fam, 'file': str(p.relative_to(args.root)).replace(BS, '/'),
                            'line': line, 'evidence': ev})
    args.out.write_text(json.dumps({'schema': 'variant-scan-0.1', 'root': str(args.root),
                                    'files': len(files), 'hits': results},
                                   ensure_ascii=False, indent=1), encoding='utf-8')
    from collections import Counter
    print(f"files={len(files)} hits={len(results)} {dict(Counter(r['family'] for r in results))}")
    for r in results[:12]:
        print(f"  [{r['family']}] {r['file']}:{r['line']} {r['evidence'][:60]}")


if __name__ == '__main__':
    main()
