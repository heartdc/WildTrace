"""Review-only Phase 5 branch impact report projection."""
import hashlib, json
from .branch_impact import make_impact_draft, validate_impact_draft

def build_impact_report(base, revised):
    draft = make_impact_draft(base, revised); validate_impact_draft(draft)
    return {'schema':'0.1','kind':'branch_impact_report', 'base_result_sha256':hashlib.sha256(json.dumps(base,sort_keys=True,separators=(',',':')).encode()).hexdigest(), 'revised_result_sha256':hashlib.sha256(json.dumps(revised,sort_keys=True,separators=(',',':')).encode()).hexdigest(), 'draft':draft,'review_required':True,'verdict':'undetermined'}

def validate_impact_report(report):
    if not isinstance(report,dict) or report.get('schema')!='0.1' or report.get('kind')!='branch_impact_report': raise ValueError('invalid impact report')
    if report.get('review_required') is not True or report.get('verdict')!='undetermined': raise ValueError('impact report must remain review-only')
    validate_impact_draft(report.get('draft',{})); return True
