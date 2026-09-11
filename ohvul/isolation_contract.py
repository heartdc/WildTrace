"""Validation for offline synthetic harness I/O."""
def validate_input(case):
    if not isinstance(case, dict) or set(case) != {'id', 'input', 'max_bytes', 'timeout_ms'} or not isinstance(case['id'], str) or not case['id']:
        raise ValueError('invalid synthetic input')
    if not isinstance(case['input'], (str, bytes, int, float, bool, type(None))):
        raise ValueError('synthetic input must be scalar')
    if not isinstance(case['max_bytes'], int) or not 0 < case['max_bytes'] <= 1048576:
        raise ValueError('invalid input budget')
    if isinstance(case['input'], (str, bytes)) and len(case['input'].encode() if isinstance(case['input'], str) else case['input']) > case['max_bytes']:
        raise ValueError('synthetic input exceeds max_bytes')
    if not isinstance(case['timeout_ms'], int) or not 0 < case['timeout_ms'] <= 60000:
        raise ValueError('invalid timeout budget')
    return True

def validate_output(output):
    if not isinstance(output, dict) or output.get('verdict') != 'undetermined' or output.get('review_required') is not True:
        raise ValueError('isolated output must remain review-only')
    if output.get('no_target_execution') is not True:
        raise ValueError('target execution flag required')
    return True
