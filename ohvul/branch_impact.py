"""Compare saved local scan results; no Git or target execution."""
from pathlib import Path
import re
import hashlib

def verify_patch_hashes(root, expected):
    root = Path(root).resolve()
    if not isinstance(expected, dict): raise ValueError('expected hashes must be an object')
    result = {}
    for name, digest in expected.items():
        if not isinstance(name, str) or '://' in name: raise ValueError('patch path must be local')
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest): raise ValueError('invalid patch digest')
        path = (root / name).resolve()
        if root not in path.parents or not path.is_file(): raise ValueError('patch file unavailable')
        value = hashlib.sha256(path.read_bytes()).hexdigest()
        if value != digest: raise ValueError('patch hash mismatch')
        result[name] = value
    return result
import argparse, json

def validate_patch_scope(root, paths):
    root = Path(root).resolve()
    if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths): raise ValueError('patch paths must be strings')
    for value in paths:
        if '://' in value: raise ValueError('patch path must be local')
        candidate = (root / value).resolve()
        if candidate != root and root not in candidate.parents: raise ValueError('patch path escapes source root')
    return True
def compare_findings(base, revised):
    if not isinstance(base, dict) or not isinstance(revised, dict): raise ValueError('scan results must be objects')
    def ids(result):
        findings = result.get('findings', [])
        if not isinstance(findings, list) or any(not isinstance(f, dict) or not isinstance(f.get('evidence_id'), str) for f in findings):
            raise ValueError('invalid findings structure')
        return {f['evidence_id'] for f in findings}
    if base.get('schema_version') != '0.3' or revised.get('schema_version') != '0.3': raise ValueError('unsupported scan result schema')
    if base.get('scan', {}).get('root') != revised.get('scan', {}).get('root'): raise ValueError('scan roots differ')
    if base.get('safety', {}).get('local_only') is not True or revised.get('safety', {}).get('local_only') is not True:
        raise ValueError('only local-only results are supported')
    old, new = ids(base), ids(revised)
    return {'schema':'0.1','added_evidence_ids':sorted(new-old),'removed_evidence_ids':sorted(old-new),
            'unchanged_count':len(old & new),'review_required':True}

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('base',type=Path); p.add_argument('revised',type=Path); args=p.parse_args()
    try:
        result=compare_findings(json.loads(args.base.read_text(encoding='utf-8-sig')), json.loads(args.revised.read_text(encoding='utf-8-sig')))
        print(json.dumps(result,ensure_ascii=False,indent=2)); return 0
    except (OSError, ValueError, TypeError, KeyError) as exc: print(f'INVALID: {exc}'); return 1

if __name__=='__main__': raise SystemExit(main())
