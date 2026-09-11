from datetime import datetime, timezone
from ohvul.domain.evidence import digest
from .review import validate_review

def create_review_batch(batch_id, task_id, report, reviews):
 if not isinstance(batch_id,str) or not batch_id.strip() or not isinstance(task_id,str) or not task_id.strip(): raise ValueError('batch and task id required')
 if not isinstance(reviews,list) or not reviews: raise ValueError('reviews required')
 for review in reviews: validate_review(review,report)
 if any(review['task_id']!=task_id for review in reviews): raise ValueError('review task differs from batch')
 return {'batch_schema':'0.1','batch_id':batch_id,'task_id':task_id,'report_sha256':digest(report),'reviews':reviews,'created_at':datetime.now(timezone.utc).isoformat(),'final_vulnerability_verdict':False}

def validate_review_batch(batch,report):
 if set(batch)!={'batch_schema','batch_id','task_id','report_sha256','reviews','created_at','final_vulnerability_verdict'} or batch.get('batch_schema')!='0.1': raise ValueError('invalid review batch')
 if batch['report_sha256']!=digest(report): raise ValueError('batch report differs')
 if batch['final_vulnerability_verdict'] is not False or not batch['reviews']: raise ValueError('batch cannot confirm vulnerability')
 for review in batch['reviews']:
  validate_review(review,report)
  if review['task_id']!=batch['task_id']: raise ValueError('batch task differs')
