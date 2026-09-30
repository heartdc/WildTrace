"""Derive fuzzable inner functions from the IPC attack surface.

Reads an attack_surface.json, drills one level into each handler body to
find the internal functions it forwards to, locates their definitions in
the repo, and scores "fuzzability purity" (freedom from IPC/framework
runtime dependencies). Output targets feed the LLM harness pipeline
(P0-2). Purity is a heuristic lead filter — never a verdict.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

BS = chr(92)
CALL = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
KEYWORDS = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'case', 'else', 'do'}
IPC_NOISE = re.compile(r'^(Read|Write|Send|Check|GetDescriptor|SoftbusRecord|COMM_LOG|LNN_LOG|TRANS_LOG|AUTH_LOG|HILOG)')
FRAMEWORK_HINT = re.compile(r'GetSoftBusServer|GetInstance|GetServerManager|GetService|SoftBusMutex|ThreadLock|GetNodeManager|GetAuthManager|GetTransManager', re.I)
FN_DEF = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?(?:[A-Za-z_][\w:<>,\s\*&]+?)\s+\**([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*(?:const\s*)?\{', re.M)
SINGLE_LINE_COMMENT = re.compile(r'//[^\n]*')

def load_repo_sources(repo: Path, exts=('.c', '.cpp', '.h')):
    out = {}
    for p in repo.rglob('*'):
        if p.suffix in exts and 'test' not in str(p).lower() and 'third_party' not in str(p):
            out[str(p.relative_to(repo)).replace(BS, '/')] = p.read_text(encoding='utf-8', errors='replace')
    return out

def fn_body_at(text: str, offset: int):
    i = text.find('{', offset)
    if i < 0:
        return None
    depth, j = 1, i + 1
    while j < len(text):
        if text[j] == '{':
            depth += 1
        elif text[j] == '}':
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1
    return None

def function_defs(sources):
    """name -> [(file, offset)] candidates."""
    defs = {}
    for rel, text in sources.items():
        for m in FN_DEF.finditer(text):
            defs.setdefault(m.group(1), []).append((rel, m.start()))
    return defs

def score_purity(params: str, body: str, is_c: bool):
    score, reasons = 0, []
    p = params.strip()
    if p in ('void', ''):
        score += 5
        reasons.append('no params')
    if re.fullmatch(r'[^;]*\b(?:int|uint\d*_t|size_t|char|void|unsigned|bool|float|double)\b[^;]*', p) and '::' not in p and 'std::' not in p:
        score += 10
        reasons.append('scalar/pointer params')
    if 'std::' in p or '&' in p.replace('&&', ''):
        score -= 20
        reasons.append('C++ ref/std params')
    if IPC_NOISE.search(body) or '.Read' in body or '.Write' in body:
        score -= 100
        reasons.append('calls IPC parcel/log API')
    if FRAMEWORK_HINT.search(body):
        score -= 50
        reasons.append('framework runtime call')
    if is_c:
        score += 5
        reasons.append('C translation unit')
    return score, reasons

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--surface', type=Path, required=True, help='attack_surface.json')
    ap.add_argument('--repo', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--top', type=int, default=40, help='handlers to drill (by surface score)')
    args = ap.parse_args()

    surface = json.loads(args.surface.read_text(encoding='utf-8'))
    sources = load_repo_sources(args.repo)
    defs = function_defs(sources)

    # handler 排序靶（raw 读取优先）
    handlers = []
    for s in surface['stubs']:
        for e in s['entries']:
            for loc in e.get('defined_at', []):
                raw = loc['reads'].get('ReadRawData', 0) + loc['reads'].get('ReadBuffer', 0)
                handlers.append((raw * 10 + sum(loc['reads'].values()), e, loc))
    handlers.sort(key=lambda x: -x[0])

    targets = []
    seen_fn = set()
    for _, e, loc in handlers[: args.top]:
        text = sources.get(loc['file'])
        if text is None:
            continue
        body = fn_body_at(text, text.find(e['handler'] + '('))
        if not body:
            continue
        body = SINGLE_LINE_COMMENT.sub('', body)
        for name in {m.group(1) for m in CALL.finditer(body)}:
            if name in KEYWORDS or IPC_NOISE.match(name):
                continue
            for rel2, off2 in defs.get(name, [])[:1]:
                t2 = sources[rel2]
                m2 = FN_DEF.search(t2[off2:off2 + 400])
                params = m2.group(2) if m2 else ''
                body2 = fn_body_at(t2, off2)
                if not body2:
                    continue
                key = (rel2, name)
                if key in seen_fn:
                    continue
                seen_fn.add(key)
                sc, why = score_purity(params, body2, rel2.endswith('.c'))
                targets.append({'entry': e['code'], 'handler': e['handler'],
                                'fn': name, 'file': rel2,
                                'line': t2[:off2].count(chr(10)) + 1,
                                'params': params.strip()[:120],
                                'purity': sc, 'purity_why': why})
    targets.sort(key=lambda x: -x['purity'])
    out = {'schema': 'fuzz-targets-0.1', 'repo': str(args.repo),
           'drilled_handlers': min(args.top, len(handlers)),
           'inner_functions': len(targets), 'targets': targets}
    args.out.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf-8')
    print(f"handlers drilled: {out['drilled_handlers']}, inner fns: {len(targets)} -> {args.out}")
    for t in targets[:15]:
        print(f"[{t['purity']:4}] {t['fn'][:32]:34} {t['file'][-58:]}:{t['line']}  <- {t['entry'][:30]}")

if __name__ == '__main__':
    main()
