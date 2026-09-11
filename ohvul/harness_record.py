"""Schema validation for synthetic local harness records."""
def validate_record(record):
    if not isinstance(record, dict) or set(record) != {'schema', 'case_id', 'verdict', 'review_required', 'reproducible'}:
        raise ValueError('invalid harness record fields')
    if record['schema'] != '0.1' or not isinstance(record['case_id'], str) or not record['case_id']:
        raise ValueError('invalid harness record identity')
    if record['verdict'] != 'undetermined' or record['review_required'] is not True:
        raise ValueError('harness record must remain undetermined and require review')
    if not isinstance(record['reproducible'], bool):
        raise ValueError('reproducible must be boolean')
    return True

def save_record(record, path):
    from pathlib import Path
    validate_record(record); path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError('harness record already exists')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        import json
        json.dump(record, stream, ensure_ascii=False, indent=2); stream.write('\n')
