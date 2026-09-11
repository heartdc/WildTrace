"""Deterministic linkage between a workflow checkpoint and harness record."""
import hashlib, json, re
from pathlib import Path
from .harness_record import validate_record
from .workflow.fsm import validate_checkpoint_data

def _checkpoint_from_bytes(raw):
    if not isinstance(raw, bytes):
        raise ValueError('checkpoint must be bytes')
    checkpoint = validate_checkpoint_data(json.loads(raw.decode('utf-8-sig')))
    if checkpoint.state != 'local_verification':
        raise ValueError('checkpoint must be in local_verification')
    return checkpoint

def make_checkpoint_link(checkpoint_bytes, harness_record):
    """Bind the exact supplied checkpoint bytes, not a caller's claimed hash."""
    checkpoint = _checkpoint_from_bytes(checkpoint_bytes)
    validate_record(harness_record)
    return make_link(checkpoint.task_id, hashlib.sha256(checkpoint_bytes).hexdigest(), harness_record)

def validate_checkpoint_link(link, harness_record, checkpoint_bytes):
    """Verify checkpoint schema, state, task, bytes and record together."""
    validate_record(harness_record)
    validate_link(link, harness_record)
    checkpoint = _checkpoint_from_bytes(checkpoint_bytes)
    if checkpoint.task_id != link['task_id']:
        raise ValueError('checkpoint task mismatch')
    if hashlib.sha256(checkpoint_bytes).hexdigest() != link['checkpoint_sha256']:
        raise ValueError('checkpoint bytes mismatch')
    return True

def make_link(task_id, checkpoint_sha256, harness_record):
    if not task_id or not re.fullmatch(r'[0-9a-f]{64}', str(checkpoint_sha256)):
        raise ValueError('invalid checkpoint identity')
    if harness_record.get('verdict') != 'undetermined' or harness_record.get('review_required') is not True:
        raise ValueError('harness record is not review-only')
    return {'schema':'0.1','task_id':task_id,'checkpoint_sha256':checkpoint_sha256,
            'harness_record_sha256':hashlib.sha256(json.dumps(harness_record,sort_keys=True,separators=(',',':')).encode()).hexdigest()}

def validate_link(link, harness_record):
    if (not isinstance(link, dict) or link.get('schema') != '0.1' or not link.get('task_id')
            or not re.fullmatch(r'[0-9a-f]{64}', str(link.get('checkpoint_sha256', '')))):
        raise ValueError('invalid verification link')
    expected=hashlib.sha256(json.dumps(harness_record,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if link.get('harness_record_sha256') != expected: raise ValueError('harness record mismatch')
    return True

def save_link(link, path, harness_record):
    validate_link(link, harness_record)
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise FileExistsError('verification link already exists')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(link, stream, ensure_ascii=False, indent=2); stream.write('\n')

def load_link(path, harness_record):
    link = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    validate_link(link, harness_record)
    return link

def validate_joint_files(checkpoint_path, result_path, harness_path):
    """Validate checkpoint, saved scan result, and review record as one chain."""
    load_verified_checkpoint(checkpoint_path, result_path, harness_path)
    return True

def load_verified_checkpoint(checkpoint_path, result_path, harness_path):
    """Return the checkpoint parsed from the same bytes that were verified."""
    for value in (checkpoint_path, result_path, harness_path):
        if Path(value).is_symlink(): raise ValueError('verification input must not be a symlink')
    checkpoint_bytes = Path(checkpoint_path).read_bytes()
    checkpoint = _checkpoint_from_bytes(checkpoint_bytes)
    result_bytes = Path(result_path).read_bytes()
    if checkpoint.result_sha256 != hashlib.sha256(result_bytes).hexdigest():
        raise ValueError('scan result bytes mismatch')
    result = json.loads(result_bytes.decode('utf-8-sig'))
    if not isinstance(result, dict) or not isinstance(result.get('workflow'), dict):
        raise ValueError('invalid scan result workflow')
    if result['workflow'].get('task_id') != checkpoint.task_id:
        raise ValueError('scan result task mismatch')
    from .verify import validate_result
    validate_result(result)
    payload = json.loads(Path(harness_path).read_text(encoding='utf-8-sig'))
    if not isinstance(payload, dict) or set(payload) != {'link', 'record'}:
        raise ValueError('invalid harness envelope')
    validate_checkpoint_link(payload['link'], payload['record'], checkpoint_bytes)
    return checkpoint
