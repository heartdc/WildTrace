"""Compare saved local scan results; no Git or target execution."""
def compare_findings(base, revised):
    def ids(result):
        return {f['evidence_id'] for f in result.get('findings', [])}
    if base.get('safety', {}).get('local_only') is not True or revised.get('safety', {}).get('local_only') is not True:
        raise ValueError('only local-only results are supported')
    old, new = ids(base), ids(revised)
    return {'schema':'0.1','added_evidence_ids':sorted(new-old),'removed_evidence_ids':sorted(old-new),
            'unchanged_count':len(old & new),'review_required':True}
