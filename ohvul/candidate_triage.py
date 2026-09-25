"""Offline worklist for a saved scan; priorities are workflow hints, not verdicts."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from pathlib import Path

from .review_queue import checked_path, read_bounded, decode_json, exclusive_json, canonical_bytes
from .source_scope import relative_path
from .verify import validate_result

MAX_SCAN_BYTES = 512 * 1024 * 1024
LANES = ('manual_review', 'needs_context', 'syntax_only', 'quality_only', 'test_support')
SUPPORT_PARTS = {'test', 'tests', 'testing', 'mock', 'mocks', 'kvstoremock',
                 'benchmark', 'benchmarks', 'example', 'examples', 'fuzztest', 'fuzztests'}


def classify(finding):
    """Never infer safety, reachability or impact from a path or a CWE alone."""
    parts = set(finding['location']['file'].lower().split('/'))
    if parts & SUPPORT_PARTS:
        return 'test_support', 'Test/example/mock path; production reachability still needs checking.'
    if finding['rule'] in ('deadcode.DeadStores', 'clang-analyzer-deadcode.DeadStores'):
        return 'quality_only', 'Dead store alone supplies no security impact evidence.'
    if (finding['source'] == 'builtin_rule' and finding['rule'] == 'null-dereference'
            and finding['evidence'].get('nullability') == 'unknown'):
        return 'syntax_only', 'Pointer syntax only; establish nullable origin and an unguarded path.'
    if finding['cwe_candidate'] == 'CWE-676':
        return 'needs_context', 'Generic API warning; inspect actual bounds and wrapper checks.'
    return 'manual_review', 'Review input control, bounds/lifetime checks and reachability; not confirmed.'


def build_triage(result, input_sha256):
    validate_result(result)
    groups = {}
    seen = set()
    for finding in result['findings']:
        alert = finding['alert_id']
        if not isinstance(alert, str) or not alert or alert in seen:
            raise ValueError('Missing or duplicate alert identifier')
        seen.add(alert)
        location = finding['location']
        if relative_path(location['file']) != location['file']:
            raise ValueError('Noncanonical source path')
        if type(location['line']) is not int or location['line'] < 1:
            raise ValueError('Invalid source line')
        lane, reason = classify(finding)
        key = (lane, location['file'], finding['source'], finding['rule'], finding['cwe_candidate'])
        group = groups.setdefault(key, {
            'lane': lane, 'file': location['file'], 'source': finding['source'],
            'rule': finding['rule'], 'cwe_candidate': finding['cwe_candidate'],
            'reason': reason, 'references': [], 'final_verdict': 'undetermined'})
        group['references'].append({'alert_id': alert, 'line': location['line'],
                                    'evidence_id': finding['evidence_id']})
    ordered = sorted(groups.values(), key=lambda g: (
        LANES.index(g['lane']), g['file'], g['source'], g['rule'], g['cwe_candidate'] or ''))
    counts = Counter()
    for group in ordered:
        group['references'].sort(key=lambda r: (r['line'], r['alert_id']))
        counts[group['lane']] += len(group['references'])
    return {'schema': 'candidate-triage-0.1', 'input_sha256': input_sha256,
            'input_status': result.get('status', 'unknown'),
            'finding_count': len(seen), 'group_count': len(ordered),
            'lane_counts': {lane: counts[lane] for lane in LANES}, 'groups': ordered,
            'candidate_only': True, 'confirmed_vulnerabilities': 0,
            'target_executed': False, 'model_invoked': False,
            'limitations': ['No findings are suppressed. Every alert is retained exactly once.',
                           'Grouping is not deduplication of vulnerabilities.',
                           'Lane order is not severity; lower lanes can contain real defects.',
                           'Hashes bind saved evidence, not current source or authenticity.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    dest = parser.add_mutually_exclusive_group(required=True)
    dest.add_argument('--output', type=Path)
    dest.add_argument('--verify', type=Path)
    args = parser.parse_args(argv)
    try:
        source = checked_path(args.result)
        raw = read_bounded(source, MAX_SCAN_BYTES)
        value = build_triage(decode_json(raw), hashlib.sha256(raw).hexdigest())
        if args.verify:
            saved = decode_json(read_bounded(args.verify, 64 * 1024 * 1024))
            if canonical_bytes(saved) != canonical_bytes(value):
                raise ValueError('Triage differs from saved input')
        else:
            exclusive_json(args.output, value, input_paths=[source])
        print('TRIAGE groups=' + str(value['group_count']) + ' retained=' + str(value['finding_count']))
        print(value['lane_counts'])
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('TRIAGE_REJECTED: ' + str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
