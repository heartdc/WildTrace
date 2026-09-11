"""Offline source evidence recheck; never executes target code."""
from pathlib import Path
import hashlib

def recheck_finding(root, finding):
    location = finding['location']; path = Path(root).resolve() / location['file']
    line_no = location['line']
    if line_no < 1 or not path.is_file():
        return {'reproducible': False, 'reason': 'source location unavailable'}
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    if line_no > len(lines):
        return {'reproducible': False, 'reason': 'source line unavailable'}
    line = lines[line_no - 1]
    observed = hashlib.sha256(line.strip().encode()).hexdigest()[:16]
    return {'reproducible': observed == finding['evidence']['line_hash'],
            'line_hash': observed, 'no_execution': True, 'no_network': True}
