"""Deterministic linkage between a workflow checkpoint and harness record."""
import hashlib, json

def make_link(task_id, checkpoint_sha256, harness_record):
    if not task_id or len(checkpoint_sha256) != 64:
        raise ValueError('invalid checkpoint identity')
    if harness_record.get('verdict') != 'undetermined' or harness_record.get('review_required') is not True:
        raise ValueError('harness record is not review-only')
    return {'schema':'0.1','task_id':task_id,'checkpoint_sha256':checkpoint_sha256,
            'harness_record_sha256':hashlib.sha256(json.dumps(harness_record,sort_keys=True,separators=(',',':')).encode()).hexdigest()}

def validate_link(link, harness_record):
    if not isinstance(link, dict) or link.get('schema') != '0.1' or not link.get('task_id'):
        raise ValueError('invalid verification link')
    expected=hashlib.sha256(json.dumps(harness_record,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if link.get('harness_record_sha256') != expected: raise ValueError('harness record mismatch')
    return True
