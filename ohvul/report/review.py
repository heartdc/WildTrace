from datetime import datetime, timezone
from ohvul.domain.evidence import digest
DECISIONS={"needs_verification","rejected_candidate","approved_for_verification"}
def create_review(report:dict, reviewer:str, decision:str, note:str=""):
 if not isinstance(reviewer,str) or not reviewer.strip(): raise ValueError('reviewer required')
 if decision not in DECISIONS: raise ValueError('invalid review decision')
 task_id=(report.get('workflow') or {}).get('task_id')
 if not isinstance(task_id,str) or not task_id: raise ValueError('report task_id required')
 return {'review_schema':'0.1','task_id':task_id,'report_sha256':digest(report),'reviewer':reviewer,'decision':decision,'note':note,'created_at':datetime.now(timezone.utc).isoformat(),'final_vulnerability_verdict':False}
def validate_review(review:dict, report:dict):
 if set(review)!={'review_schema','task_id','report_sha256','reviewer','decision','note','created_at','final_vulnerability_verdict'} or review.get('review_schema')!='0.1': raise ValueError('invalid review schema')
 if not isinstance(review['task_id'],str) or review['task_id']!=(report.get('workflow') or {}).get('task_id'): raise ValueError('review task differs from report')
 if review['report_sha256']!=digest(report): raise ValueError('review does not match report')
 if review['decision'] not in DECISIONS or review['final_vulnerability_verdict'] is not False: raise ValueError('review cannot confirm vulnerability')
