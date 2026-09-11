"""Compare saved local scan results; no Git or target execution."""
from pathlib import Path

def validate_patch_scope(root, paths):
    root = Path(root).resolve()
    if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths): raise ValueError('patch paths must be strings')
    for value in paths:
        candidate = (root / value).resolve()
        if candidate != root and root not in candidate.parents: raise ValueError('patch path escapes source root')
    return True
def compare_findings(base, revised):
    def ids(result):
        return {f['evidence_id'] for f in result.get('findings', [])}
    if base.get('schema_version') != '0.3' or revised.get('schema_version') != '0.3': raise ValueError('unsupported scan result schema')
    if base.get('safety', {}).get('local_only') is not True or revised.get('safety', {}).get('local_only') is not True:
        raise ValueError('only local-only results are supported')
    old, new = ids(base), ids(revised)
    return {'schema':'0.1','added_evidence_ids':sorted(new-old),'removed_evidence_ids':sorted(old-new),
            'unchanged_count':len(old & new),'review_required':True}
