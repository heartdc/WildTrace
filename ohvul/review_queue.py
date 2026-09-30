"""Deterministic, offline review queues bound to explicit saved batch evidence.

No source/profile/manifest path embedded in input JSON is opened. Local hashes
detect inconsistent changes; they are not signatures or vulnerability verdicts.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import stat

from .source_scope import is_link, relative_path
from .report.schema import validate_report_against_result
from .verify import validate_result

MAX_SUMMARY_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_JOBS = 128
MAX_FINDINGS = 20000
BOUNDARY = {'candidate_only': True, 'confirmed_vulnerabilities': 0,
            'local_only': True, 'target_executed': False, 'no_network': True}
ARTIFACT_NAMES = {'result': 'result.json', 'report': 'report.candidate.json', 'receipt': 'receipt.json'}
CLANG_ALIASES = {'core.NullDereference', 'deadcode.DeadStores',
                 'security.insecureAPI.DeprecatedOrUnsafeBufferHandling', 'unix.Malloc'}


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _digest(value):
    _require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'invalid SHA-256')
    return value


def _text(value, name):
    _require(isinstance(value, str) and bool(value.strip()) and len(value) <= 8192
             and not any(ord(c) < 32 for c in value), 'invalid ' + name)
    return value


def _count(value, name):
    _require(type(value) is int and value >= 0, 'invalid count: ' + name)
    return value


def checked_path(path) -> Path:
    """Reject linked lexical ancestors and Git metadata before resolving."""
    path = Path(path).absolute()
    for ancestor in (path, *path.parents):
        _require(ancestor.name.casefold() != '.git' and not is_link(ancestor),
                 'linked or Git metadata path is not allowed')
    return path.resolve()


def read_bounded(path, limit) -> bytes:
    path = checked_path(path)
    _require(stat.S_ISREG(path.stat().st_mode), 'input must be a regular file')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    _require(len(raw) <= limit, 'input exceeds byte limit')
    return raw


def decode_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('nonfinite JSON value: ' + value)
    try:
        return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('invalid bounded JSON document') from exc


def _boundary(value):
    # bool is an int subclass: JSON comparison must not accept False as count 0.
    _require(isinstance(value, dict) and canonical_bytes(value) == canonical_bytes(BOUNDARY),
             'candidate-only boundary mismatch')


def _job_id(value):
    _require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value),
             'invalid job id')
    _require(relative_path(value) == value, 'invalid portable job id')
    return value


def _location(value):
    _require(isinstance(value, dict), 'invalid diagnostic location')
    name = relative_path(value.get('file'))
    _require(name == value['file'] and '.git' not in [x.casefold() for x in Path(name).parts],
             'noncanonical or Git metadata diagnostic path')
    _require(type(value.get('line')) is int and value['line'] > 0, 'invalid diagnostic line')
    return {'file': name, 'line': value['line']}


def _profile(receipt, inputs):
    _require(isinstance(receipt, dict) and receipt.get('schema') == 'profile-validation-0.1',
             'invalid profile validation receipt')
    for key in ('source_root', 'profile_sha256'):
        _require(receipt.get(key) == inputs[key], 'profile receipt binding mismatch')
    if 'source_snapshot_sha256' in receipt:
        _require(receipt['source_snapshot_sha256'] == inputs['source_snapshot_sha256'], 'profile snapshot mismatch')
    source_inputs = receipt.get('inputs', {})
    _require(source_inputs.get('complete') is True and all(source_inputs.get(k) == [] for k in (
        'missing_files', 'missing_include_dirs', 'missing_rule_files')), 'profile inputs not complete')
    provenance = receipt.get('provenance', {})
    checks = provenance.get('checks')
    _require(provenance.get('verified') is True and provenance.get('mismatches') == []
             and isinstance(checks, list) and 0 < len(checks) <= 10000, 'unverified profile provenance')
    _require(type(provenance.get('repositories')) is int and provenance['repositories'] == len(checks),
             'repository count mismatch')
    seen = set()
    for item in checks:
        _require(isinstance(item, dict), 'invalid repository check')
        name = relative_path(item.get('repository'), allow_root=True)
        _require(name.casefold() not in seen, 'duplicate repository check')
        seen.add(name.casefold())
        _require(item.get('clean') is True and item.get('status') == 'matched'
                 and isinstance(item.get('expected'), str)
                 and re.fullmatch(r'[0-9a-f]{40}', item['expected'])
                 and item['expected'] == item.get('actual'), 'repository check is not matched')


def _validate_job(job, result, report, receipt, manifest_digest, *, version='0.1'):
    _require(job.get('status') == 'completed' and job.get('analysis_attempted') is True,
             'job has not completed analysis')
    inputs = job.get('inputs')
    _require(isinstance(inputs, dict), 'missing job input bindings')
    for key in ('manifest_sha256', 'profile_sha256', 'source_snapshot_sha256'):
        _digest(inputs.get(key))
    for key in ('source_root', 'profile'):
        _text(inputs.get(key), key)
    _require(inputs['manifest_sha256'] == manifest_digest, 'job manifest mismatch')
    _require(isinstance(receipt, dict) and receipt.get('schema') == 'component-batch-receipt-' + version
             and receipt.get('outcome') == 'completed' and receipt.get('preflight_only') is False
             and receipt.get('error') is None and receipt.get('acceptance') == 'requires_final_summary',
             'receipt is not a completed observation')
    _boundary(receipt.get('boundary'))
    for key, value in inputs.items():
        _require(receipt.get(key) == value, 'receipt input binding mismatch: ' + key)
    _require(isinstance(result, dict) and isinstance(result.get('scan'), dict), 'invalid saved result')
    _require(result.get('status') == 'completed' and result.get('input_errors') == [], 'result did not complete')
    scan = result['scan']
    _require(scan.get('root') == inputs['source_root']
             and scan.get('source_snapshot_sha256') == inputs['source_snapshot_sha256'], 'result snapshot/root mismatch')
    pv = result.get('profile_validation')
    _profile(pv, inputs)
    _require(pv.get('source_snapshot_sha256') == inputs['source_snapshot_sha256'], 'unbound result profile')
    profiles = receipt.get('profile_receipts')
    _require(isinstance(profiles, list) and 1 <= len(profiles) <= 32 and pv in profiles,
             'result profile absent from receipt')
    for item in profiles:
        _profile(item, inputs)
        _require({k: v for k, v in item.items() if k != 'source_snapshot_sha256'} ==
                 {k: v for k, v in pv.items() if k != 'source_snapshot_sha256'}, 'profile observations disagree')
    selected = job.get('selected_engines')
    engine_names = {'clang-static-analyzer': 'clang', 'clang-tidy': 'clang-tidy', 'semgrep': 'semgrep'}
    if version == '0.2':
        from .component_batch import selection_engines
        selection = job.get('analysis_selection')
        _require(isinstance(selection, dict) and set(selection) == {'analyses', 'profile_engines'},
                 'missing explicit analysis selection')
        _require(canonical_bytes(selection) == canonical_bytes(receipt.get('analysis_selection'))
                 == canonical_bytes(result.get('analysis_selection')), 'analysis selection differs from receipt/result')
        expected_selection = selection_engines(selection['analyses'], selection['profile_engines'])
        _require(selected == expected_selection, 'declared and selected analysis engines differ')
        engine_names['compiler-ast'] = 'wildtrace-clang-ast'
        if 'compiler-ast' in selection['analyses']:
            from .compiler_analysis import compiler_evidence_summary
            compiler_evidence_summary(result)
        else:
            _require('compiler_facts' not in result, 'unrequested compiler facts')
    _require(isinstance(selected, list) and bool(selected)
             and all(isinstance(s, str) and s in engine_names for s in selected)
             and len(set(selected)) == len(selected), 'invalid selected engines')
    observations = result.get('engine_observations', [result])
    _require(isinstance(observations, list) and bool(observations), 'missing engine observations')
    observed_engines = set()
    for obs in observations:
        _require(isinstance(obs, dict) and obs.get('status') == 'completed'
                 and not obs.get('input_errors'), 'engine observation did not complete')
        run_scan = obs.get('scan', {})
        engine = obs.get('engine', run_scan.get('engine'))
        _require(isinstance(engine, str), 'engine identity missing')
        observed_engines.add(engine)
        _require(run_scan.get('root') == inputs['source_root']
                 and run_scan.get('source_snapshot_sha256') == inputs['source_snapshot_sha256'],
                 'engine observation source binding mismatch')
        outcomes = obs.get('file_results')
        _require(outcomes is None or (isinstance(outcomes, list) and all(
            isinstance(item, dict) and item.get('status') == 'completed' for item in outcomes)),
            'engine file outcome did not complete')
    _require(observed_engines == {engine_names[s] for s in selected}, 'selected engine coverage mismatch')
    _require(isinstance(result.get('findings'), list) and len(result['findings']) <= MAX_FINDINGS
             and isinstance(result.get('evidence_bundles'), list), 'invalid result containers')
    ids = set()
    for finding in result['findings']:
        _require(isinstance(finding, dict) and finding.get('status') == 'candidate', 'noncandidate diagnostic')
        alert = _text(finding.get('alert_id'), 'alert id')
        _require(alert not in ids, 'duplicate alert id')
        ids.add(alert)
        _location(finding.get('location'))
        _text(finding.get('source'), 'engine')
        _require(finding['source'] in observed_engines, 'diagnostic engine was not observed')
        _text(finding.get('rule'), 'rule')
        description = finding.get('description', '')
        _require(isinstance(description, str) and len(description) <= 32768, 'invalid description')
        cwe = finding.get('cwe_candidate')
        _require(cwe is None or (isinstance(cwe, str) and re.fullmatch(r'CWE-[1-9][0-9]*', cwe)), 'invalid CWE')
        evidence = finding.get('evidence')
        _require(isinstance(evidence, dict), 'missing diagnostic evidence')
        for display, bound in [('source', 'engine'), ('rule', 'rule'), ('description', 'description'),
                               ('engine_version', 'engine_version'), ('cwe_mapping_source', 'cwe_mapping_source'),
                               ('cwe_mapping_version', 'cwe_mapping_version')]:
            if bound in evidence:
                _require(finding.get(display) == evidence[bound], 'diagnostic presentation differs from evidence')
    _require(_count(job.get('candidate_findings'), 'job findings') == len(ids), 'job diagnostic count mismatch')
    validate_result(result)
    validate_report_against_result(report, result)
    _require(type(report['assessment']['confirmed_vulnerabilities']) is int
             and report['assessment']['confirmed_vulnerabilities'] == 0, 'invalid report verdict count')
    _require(len(report['findings']) == len(ids) and len({x['alert_id'] for x in report['findings']}) == len(ids),
             'duplicate or missing report diagnostic')
    for bundle in result['evidence_bundles']:
        if bundle.get('stage') == 'static_scan':
            _require(bundle.get('source', {}).get('root') == inputs['source_root'], 'evidence source root mismatch')


def _canonical_rule(finding):
    engine, rule = finding['source'], finding['rule']
    if engine == 'clang' and rule in CLANG_ALIASES:
        return 'clang-analyzer', rule
    if engine == 'clang-tidy' and rule.startswith('clang-analyzer-'):
        name = rule[len('clang-analyzer-'):]
        if name in CLANG_ALIASES:
            return 'clang-analyzer', name
    return engine, rule


def _questions(family, rule):
    category = 'unclassified_requires_review'
    if family == 'clang-analyzer' and rule == 'deadcode.DeadStores':
        category = 'code_quality_signal'
    elif family == 'clang-analyzer' and rule == 'security.insecureAPI.DeprecatedOrUnsafeBufferHandling':
        category = 'api_advisory'
    elif family == 'clang-analyzer' and rule == 'core.NullDereference':
        category = 'memory_safety_candidate'
    elif family == 'wildtrace-clang-ast' and re.fullmatch(
            r'compiler\.(?:(?:constant|range)-buffer-(?:read|write)|lifetime-(?:use-after-delete|aliased-handle-use))',
            rule):
        category = 'memory_safety_candidate'
    questions = [
        ('reachability', 'Is the reported path reachable in the selected product configuration?'),
        ('input_control', 'Which external inputs or principals can influence this path?'),
        ('bounds_and_lifetime', 'Which bounds, null, ownership or lifetime checks apply before the operation?'),
        ('security_impact', 'What security boundary is affected, beyond an API advisory or functional issue?'),
        ('independent_validation', 'Which independent evidence or authorized reproduction is still needed?')]
    return category, [{'id': key, 'question': text, 'status': 'unknown', 'evidence_refs': []}
                      for key, text in questions]


def _load_queue(summary_path):
    summary_path = checked_path(summary_path)
    raw = read_bounded(summary_path, MAX_SUMMARY_BYTES)
    summary = decode_json(raw)
    _require(isinstance(summary, dict) and summary.get('schema') in (
                 'component-batch-summary-0.1', 'component-batch-summary-0.2')
             and summary.get('status') == 'completed' and summary.get('preflight_only') is False,
             'explicit summary must be completed and non-preflight')
    _boundary(summary.get('boundary'))
    version = '0.2' if summary['schema'].endswith('0.2') else '0.1'
    manifest_digest = _digest(summary.get('manifest_sha256'))
    jobs = summary.get('jobs')
    _require(isinstance(jobs, list) and 0 < len(jobs) <= MAX_JOBS, 'invalid job count')
    _require(canonical_bytes(summary.get('counts')) == canonical_bytes({'completed': len(jobs)}), 'batch counts mismatch')
    expected_totals = dict(jobs=len(jobs), completed=len(jobs), analysis_attempted=len(jobs),
                           ready=0, blocked=0, failed=0, pending=0)
    _require(canonical_bytes(summary.get('totals')) == canonical_bytes(expected_totals), 'batch totals mismatch')
    seen = set()
    for job in jobs:
        _require(isinstance(job, dict), 'invalid job')
        identity = _job_id(job.get('id')).casefold()
        _require(identity not in seen, 'duplicate job id')
        seen.add(identity)
    captured = [(summary_path, raw, MAX_SUMMARY_BYTES)]
    used_bytes = len(raw)
    sources, groups, bindings = [], {}, []
    for job in sorted(jobs, key=lambda x: x['id']):
        artifacts = job.get('artifacts')
        _require(isinstance(artifacts, dict) and set(artifacts) == set(ARTIFACT_NAMES), 'completed job artifact set mismatch')
        loaded, artifact_refs = {}, {}
        for label, filename in ARTIFACT_NAMES.items():
            meta = artifacts[label]
            _require(isinstance(meta, dict) and set(meta) == {'path', 'bytes', 'sha256'}
                     and meta['path'] == filename, 'artifact basename mismatch')
            size = _count(meta['bytes'], 'artifact bytes')
            _require(size <= MAX_ARTIFACT_BYTES, 'artifact exceeds byte limit')
            digest = _digest(meta['sha256'])
            path = checked_path(summary_path.parent / job['id'] / filename)
            _require(path.is_relative_to(summary_path.parent), 'artifact escapes batch directory')
            data = read_bounded(path, MAX_ARTIFACT_BYTES)
            used_bytes += len(data)
            _require(used_bytes <= MAX_TOTAL_BYTES, 'batch evidence exceeds total byte limit')
            _require(len(data) == size and sha256(data) == digest, 'saved artifact bytes or digest mismatch')
            captured.append((path, data, MAX_ARTIFACT_BYTES))
            loaded[label] = decode_json(data)
            artifact_refs[label] = {'path': job['id'] + '/' + filename, 'sha256': digest, 'bytes': size}
        try:
            _validate_job(job, loaded['result'], loaded['report'], loaded['receipt'], manifest_digest, version=version)
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError('malformed batch evidence: ' + job['id']) from exc
        result = loaded['result']
        inputs = job['inputs']
        source = {'job': job['id'], 'source_root': inputs['source_root'],
                  'source_snapshot_sha256': inputs['source_snapshot_sha256'],
                  'profile_sha256': inputs['profile_sha256'], 'status': 'completed',
                  'raw_diagnostics': len(result['findings']), 'scan': copy.deepcopy(result['scan']),
                  'selected_engines': copy.deepcopy(job.get('selected_engines', [])), 'artifacts': artifact_refs}
        if version == '0.2':
            source['analysis_selection'] = copy.deepcopy(job['analysis_selection'])
            if 'compiler-ast' in job['analysis_selection']['analyses']:
                from .compiler_analysis import compiler_evidence_summary
                source['compiler_analysis'] = compiler_evidence_summary(result)
        sources.append(source)
        bindings.append({'job': job['id'], 'artifacts': artifact_refs})
        for finding in result['findings']:
            family, rule = _canonical_rule(finding)
            identity = {'job': job['id'], 'source_root': inputs['source_root'],
                        'source_snapshot_sha256': inputs['source_snapshot_sha256'],
                        'profile_sha256': inputs['profile_sha256'], 'location': _location(finding['location']),
                        'engine_family': family, 'canonical_rule': rule, 'cwe_candidate': finding.get('cwe_candidate'),
                        'description': finding.get('description', '')}
            key = sha256(canonical_bytes(identity))
            if key not in groups:
                category, questions = _questions(family, rule)
                groups[key] = {**identity, 'group_id': 'RG-' + key, 'category': category,
                               'final_verdict': 'undetermined', 'review_questions': questions, 'observations': []}
                if 'compiler_analysis' in source:
                    related = []
                    for unit in result['compiler_facts']:
                        if unit['source_file'] != identity['location']['file']:
                            continue
                        for call in unit['calls']:
                            if call.get('location', {}).get('line') == identity['location']['line']:
                                related.append({'facts_sha256': unit['facts_sha256'],
                                                'source_sha256': unit['source_sha256'],
                                                'call': copy.deepcopy(call)})
                    _require(len(related) <= 128, 'compiler call context budget exceeded')
                    groups[key]['compiler_context'] = {
                        'match': 'same_file_and_line_not_proven_diagnostic_equivalence',
                        'observations': related, 'reasoning_verified': False, 'target_executed': False}
            groups[key]['observations'].append({**copy.deepcopy(finding),
                  'result_sha256': artifact_refs['result']['sha256']})
    ordered = sorted(groups.values(), key=lambda g: (g['job'], g['location']['file'],
                     g['location']['line'], g['canonical_rule'], g['group_id']))
    for group in ordered:
        group['observations'].sort(key=lambda x: (x['source'], x['alert_id']))
    total = sum(x['raw_diagnostics'] for x in sources)
    _require(total <= MAX_FINDINGS and _count(summary.get('candidate_findings'), 'batch findings') == total,
             'batch diagnostic count mismatch')
    categories = {name: sum(g['category'] == name for g in ordered)
                  for name in sorted({g['category'] for g in ordered})}
    value = {'schema': 'candidate-review-queue-0.1', 'source_summary': str(summary_path),
             'source_summary_sha256': sha256(raw), 'source_summary_bytes': len(raw),
             'manifest_sha256': manifest_digest, 'input_bindings': bindings, 'sources': sources,
             'raw_diagnostics': total, 'group_count': len(ordered), 'categories': categories,
             'confirmed_vulnerabilities': 0, 'final_verdict': 'undetermined', 'groups': ordered,
             'limitations': ['Review groups are not unique vulnerabilities or independent reproductions.',
                             'Saved hashes establish local consistency, not authenticated provenance.',
                             'The supplied historical summary is explicit; latest-run status is not inferred.',
                             'No source, profile, original manifest, analyzer or network is accessed.']}
    recheck_inputs(captured)
    return value, captured


def recheck_inputs(captured):
    for path, raw, limit in captured:
        _require(read_bounded(path, limit) == raw, 'input changed during review generation')


def build_review_queue(summary_path: Path) -> dict:
    return _load_queue(summary_path)[0]


def validate_review_queue(value, summary_path: Path) -> None:
    expected = build_review_queue(summary_path)
    _require(canonical_bytes(value) == canonical_bytes(expected), 'review queue differs from bound batch evidence')


def exclusive_json(path, value, *, forbidden_trees=(), input_paths=(), before_publish=None):
    path = checked_path(path)
    _require(path.parent.is_dir(), 'output parent must exist')
    _require(not path.exists(), 'output exists; overwrite is not supported')
    for root in forbidden_trees:
        # Path comparison only. It does not grant access to embedded source roots.
        _require(not path.is_relative_to(Path(root).absolute()), 'output is inside an input tree')
    for source in input_paths:
        _require(path != Path(source).absolute(), 'output/input collision')
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
    _require(len(raw) <= MAX_TOTAL_BYTES, 'output exceeds byte limit')
    if before_publish:
        before_publish()
    checked_path(path)
    # Exclusive creation avoids platform-dependent rename-overwrite behavior.
    # Interrupted writes can leave incomplete files; independent verification is required.
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        __import__('os').fsync(stream.fileno())


def write_review_queue(summary_path: Path, output: Path) -> dict:
    value, captured = _load_queue(summary_path)
    exclusive_json(output, value,
                   forbidden_trees=[Path(summary_path).absolute().parent] + [s['source_root'] for s in value['sources']],
                   input_paths=[p for p, _, _ in captured], before_publish=lambda: recheck_inputs(captured))
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path)
    mode.add_argument('--verify', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.verify:
            validate_review_queue(decode_json(read_bounded(args.verify, MAX_TOTAL_BYTES)), args.summary)
            print('VERIFIED: local review bindings; no vulnerability verdict')
        else:
            value = write_review_queue(args.summary, args.output)
            print(json.dumps({k: value[k] for k in ('raw_diagnostics', 'group_count', 'categories', 'confirmed_vulnerabilities')}))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('REJECTED: ' + str(exc))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
