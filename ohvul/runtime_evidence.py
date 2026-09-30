"""Bridge existing candidate reports to externally collected runtime evidence.

This module NEVER executes a PoC, build, command or target. It checks supplied
records and artifacts, not the truth of an operator's execution claims. It does
not grant authorization, sign receipts or upgrade a vulnerability verdict.
"""
from __future__ import annotations

import argparse
import copy
import math
from pathlib import Path

from .report.schema import validate_report_against_result
from .review_queue import (canonical_bytes, checked_path, decode_json, exclusive_json,
                           read_bounded, recheck_inputs, sha256, _digest, _require)
from .source_scope import local_input_path, relative_path
from .source_snapshot import source_snapshot
from .verify import validate_result

MAX_JSON = 16 * 1024 * 1024
MAX_ARTIFACT = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_RUNS = 32
BASELINE_REPEATS = 3  # Project evidence policy, NOT a competition-specified count.
PHASES = ('baseline', 'independent', 'patched', 'regression')
FAILURES = {'build_failed', 'timeout', 'environment_failed', 'failed'}


def _fields(value, names, what):
    _require(isinstance(value, dict) and set(value) == set(names), 'invalid ' + what + ' fields')


def _text(value):
    _require(isinstance(value, str) and 0 < len(value.strip()) <= 2048
             and all(ord(c) >= 32 for c in value), 'invalid bounded text')


def _read(path, captured, limit=MAX_JSON):
    path = checked_path(path)
    raw = read_bounded(path, limit)
    captured.append((path, raw, limit))
    _require(sum(len(b) for _, b, _ in captured) <= MAX_TOTAL, 'aggregate input byte budget exceeded')
    return raw


def _case(result_path, report_path, root, alert_id):
    root = checked_path(root)
    _require(root.is_dir(), 'explicit source root required')
    captured = []
    result_raw, report_raw = (_read(p, captured) for p in (result_path, report_path))
    result, report = decode_json(result_raw), decode_json(report_raw)
    validate_result(result)
    validate_report_against_result(report, result)
    _require(result.get('status') == 'completed' and not result.get('input_errors'),
             'only complete static results may prepare a case')
    _require(checked_path(result['scan']['root']) == root, 'explicit root differs from result')
    # The legacy report binder uses dictionaries: reject duplicates here rather
    # than allowing a duplicate alert to disappear during identity comparison.
    for items in (result['findings'], report['findings']):
        ids = [x['alert_id'] for x in items]
        _require(len(ids) == len(set(ids)), 'duplicate alert identity')
    selected = [x for x in result['findings'] if x['alert_id'] == alert_id]
    _require(len(selected) == 1, 'one existing candidate must be explicitly selected')
    finding = selected[0]
    name = relative_path(finding['location']['file'])
    source = local_input_path(root, name)
    source_raw = _read(source, captured, 2 * 1024 * 1024)
    lines = source_raw.decode('utf-8-sig').splitlines()
    line = finding['location']['line']
    _require(type(line) is int and 1 <= line <= len(lines), 'candidate source line outside file')
    snapshot = _digest(result['scan'].get('source_snapshot_sha256'))
    _require(source_snapshot(root) == snapshot, 'candidate source snapshot changed')
    bindings = {'result_sha256': sha256(result_raw), 'report_sha256': sha256(report_raw),
                'source_snapshot_sha256': snapshot, 'source_file_sha256': sha256(source_raw)}
    value = {'schema': 'runtime-case-0.1',
             'case_id': 'RC-' + sha256(canonical_bytes({'alert_id': alert_id, 'bindings': bindings})),
             'input_bindings': bindings, 'candidate': copy.deepcopy(finding),
             'source_excerpt': [{'line': n, 'text': lines[n - 1]}
                                for n in range(max(1, line - 8), min(len(lines), line + 8) + 1)],
             'runtime_requirements': {'product_configuration': 'pending',
                 'authorized_isolated_environment': 'pending', 'security_trigger_definition': 'pending',
                 'poc_and_build_instructions': 'pending', 'review_and_submission_owner': 'pending'},
             'baseline_repeats_required': BASELINE_REPEATS,
             'execution_authorized_by_this_document': False, 'target_executed_by_this_tool': False,
             'final_verdict': 'undetermined', 'confirmed_vulnerabilities': 0}
    def recheck():
        recheck_inputs(captured)
        _require(source_snapshot(root) == snapshot, 'source changed before case publication')
    recheck()
    return value, captured, recheck


def prepare_case(result_path, report_path, root, alert_id, output):
    value, captured, recheck = _case(result_path, report_path, root, alert_id)
    exclusive_json(output, value, forbidden_trees=[root],
                   input_paths=[p for p, _, _ in captured], before_publish=recheck)
    return value


def inspect_runtime(case_path, result_path, report_path, root, record_path, artifacts_root):
    """Return a candidate-report appendix; even complete records require review."""
    captured = []
    case_raw = _read(case_path, captured)
    case = decode_json(case_raw)
    _require(isinstance(case, dict) and isinstance(case.get('candidate'), dict), 'invalid case')
    expected, static_inputs, recheck_source = _case(
        result_path, report_path, root, case['candidate']['alert_id'])
    _require(canonical_bytes(case) == canonical_bytes(expected), 'case differs from verified static inputs')
    captured.extend(static_inputs)
    record_raw = _read(record_path, captured)
    record = decode_json(record_raw)
    _fields(record, ('schema', 'case_id', 'case_sha256', 'origin', 'product', 'environment',
                     'authorization', 'trigger_definition', 'configuration', 'poc', 'patch', 'runs'), 'runtime record')
    _require(record['schema'] == 'external-runtime-evidence-0.1'
             and record['case_id'] == case['case_id'] and record['case_sha256'] == sha256(case_raw),
             'runtime record is not bound to this case')
    _require(record['origin'] in ('real_target', 'synthetic'), 'invalid execution origin')
    _fields(record['product'], ('name', 'version', 'configuration_sha256'), 'product')
    _text(record['product']['name']); _text(record['product']['version'])
    _digest(record['product']['configuration_sha256'])
    environment = record['environment']
    _fields(environment, ('id', 'isolation', 'image_sha256'), 'environment')
    _text(environment['id']); _digest(environment['image_sha256'])
    _require(environment['isolation'] in ('vm', 'container', 'emulator', 'dedicated_device'),
             'explicit isolated environment required')
    _text(record['trigger_definition'])
    auth = record['authorization']
    if auth is not None:
        _fields(auth, ('reference', 'approved_by', 'environment_id', 'case_id'), 'authorization')
        _text(auth['reference']); _text(auth['approved_by'])
        _require(auth['environment_id'] == environment['id'] and auth['case_id'] == case['case_id'],
                 'authorization scope differs from case/environment')
    artifacts_root = checked_path(artifacts_root)
    _require(artifacts_root.is_dir(), 'explicit artifacts root required')
    artifact_bindings, opened = [], {}
    def artifact(ref):
        _fields(ref, ('path', 'sha256', 'bytes'), 'artifact')
        name = relative_path(ref['path'])
        _require(name == ref['path'], 'artifact path must be canonical')
        _digest(ref['sha256'])
        _require(type(ref['bytes']) is int and 0 < ref['bytes'] <= MAX_ARTIFACT, 'artifact byte limit')
        path = checked_path(local_input_path(artifacts_root, name))
        if path in opened:
            _require(opened[path] == ref, 'conflicting artifact reference')
            return
        raw = _read(path, captured, MAX_ARTIFACT)
        _require(len(raw) == ref['bytes'] and sha256(raw) == ref['sha256'], 'artifact bytes/hash mismatch')
        opened[path] = copy.deepcopy(ref)
        artifact_bindings.append(copy.deepcopy(ref))
    artifact(record['poc'])
    artifact(record['configuration'])
    _require(record['configuration']['sha256'] == record['product']['configuration_sha256'],
             'product configuration is not bound to supplied bytes')
    patch = record['patch']
    if patch is not None:
        _fields(patch, ('artifact', 'source_snapshot_sha256'), 'patch')
        artifact(patch['artifact']); _digest(patch['source_snapshot_sha256'])
        _require(patch['source_snapshot_sha256'] != case['input_bindings']['source_snapshot_sha256'],
                 'patched source cannot reuse original snapshot')
    runs = record['runs']
    _require(isinstance(runs, list) and len(runs) <= MAX_RUNS, 'runtime run budget exceeded')
    by_phase = {p: [] for p in PHASES}
    ids, log_paths = set(), set()
    for run in runs:
        _fields(run, ('id', 'phase', 'session_id', 'operator', 'environment_id',
                      'source_snapshot_sha256', 'poc_sha256', 'build_status', 'target_executed',
                      'status', 'exit_code', 'elapsed_seconds', 'build_log', 'log', 'reset_log'), 'run')
        _text(run['id']); _text(run['session_id']); _text(run['operator'])
        _require(run['id'] not in ids and run['phase'] in PHASES, 'duplicate run or unknown phase')
        ids.add(run['id'])
        _require(run['environment_id'] == environment['id'], 'run environment mismatch')
        _require(type(run['target_executed']) is bool, 'target_executed must be boolean')
        _require(run['exit_code'] is None or type(run['exit_code']) is int, 'invalid exit code')
        elapsed = run['elapsed_seconds']
        _require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 86400,
                 'invalid bounded elapsed time')
        _require(run['build_status'] in ('succeeded', 'failed', 'not_run'), 'invalid build status')
        allowed = ({'passed', 'failed'} if run['phase'] == 'regression' else {'triggered', 'not_triggered'})
        _require(run['status'] in allowed | {'build_failed', 'timeout', 'environment_failed'}, 'invalid run status')
        if run['status'] in allowed:
            _require(run['build_status'] == 'succeeded' and run['target_executed'] is True
                     and type(run['exit_code']) is int, 'an unexecuted/failed build cannot claim an outcome')
        if run['status'] == 'build_failed':
            _require(run['build_status'] == 'failed' and run['target_executed'] is False,
                     'build failure cannot claim target execution')
        if run['status'] in ('not_triggered', 'passed'):
            _require(run['exit_code'] == 0, 'failed process cannot be a successful non-trigger or regression')
        if run['phase'] in ('baseline', 'independent'):
            snapshot = case['input_bindings']['source_snapshot_sha256']
        else:
            _require(patch is not None, 'patched/regression run needs an explicit patch')
            snapshot = patch['source_snapshot_sha256']
        _require(run['source_snapshot_sha256'] == snapshot, 'run source version mismatch')
        _require(run['poc_sha256'] == record['poc']['sha256'], 'run PoC differs from bound reproducer')
        artifact(run['build_log']); artifact(run['log'])
        if run['reset_log'] is not None:
            artifact(run['reset_log'])
        log_path = checked_path(local_input_path(artifacts_root, run['log']['path']))
        _require(log_path not in log_paths, 'one log file cannot count as several executions')
        # Hard links can disguise the same underlying log as multiple files.
        _require(not any(log_path.samefile(p) for p in log_paths), 'aliased execution log')
        log_paths.add(log_path)
        by_phase[run['phase']].append(run)
    base = by_phase['baseline']
    baseline_ok = len(base) >= BASELINE_REPEATS and all(r['status'] == 'triggered' for r in base)
    sessions = {r['session_id'] for r in base}
    independent = by_phase['independent']
    independent_ok = bool(independent) and all(r['status'] == 'triggered'
        and r['session_id'] not in sessions and r['reset_log'] is not None for r in independent)
    patched = by_phase['patched']; regression = by_phase['regression']
    patch_ok = bool(patched) and all(r['status'] == 'not_triggered' for r in patched)
    regression_ok = bool(regression) and all(r['status'] == 'passed' for r in regression)
    checks = {'real_target_origin_declared': record['origin'] == 'real_target',
              'scoped_authorization_record_present': auth is not None,
              'repeat_trigger_records_complete': baseline_ok,
              'separate_session_trigger_records_complete': independent_ok,
              'patch_nontrigger_records_complete': patch_ok,
              'functional_regression_records_complete': regression_ok}
    blockers = [k for k, v in checks.items() if not v]
    value = {'schema': 'runtime-evidence-review-0.1', 'case_id': case['case_id'],
             'input_bindings': {'case_sha256': sha256(case_raw), 'record_sha256': sha256(record_raw),
                               **case['input_bindings']},
             'candidate': copy.deepcopy(case['candidate']), 'checks': checks, 'blockers': blockers,
             'status': 'ready_for_human_evidence_review' if not blockers else 'evidence_incomplete',
             'run_counts': {k: len(v) for k, v in by_phase.items()},
             'failure_records': [{'id': r['id'], 'phase': r['phase'], 'status': r['status']}
                                 for r in runs if r['status'] in FAILURES],
             'artifact_bindings': artifact_bindings, 'runs': copy.deepcopy(runs),
             'claims': {'origin': record['origin'], 'product': record['product'],
                        'environment': environment, 'authorization': auth,
                        'trigger_definition': record['trigger_definition']},
             'authorization_authenticity_verified': False, 'execution_independently_observed': False,
             'patch_effectiveness_verified': False, 'target_executed_by_this_tool': False,
             'confirmed_vulnerabilities': 0, 'final_verdict': 'undetermined',
             'limitations': ['External records are operator claims, not signed or independently observed execution.',
                'Matching hashes establish consistency, not truth, exploitability or permission to run a target.',
                'Separate sessions are a necessary record condition, not proof of independent reproduction.',
                'Non-trigger plus regression records still require checking the same vulnerable path was exercised.',
                'Synthetic records never satisfy the real-target gate; no candidate is automatically promoted.']}
    def recheck():
        recheck_inputs(captured)
        recheck_source()
    recheck()
    return value, captured, recheck


def write_runtime_review(case_path, result_path, report_path, root, record_path, artifacts_root, output):
    value, captured, recheck = inspect_runtime(
        case_path, result_path, report_path, root, record_path, artifacts_root)
    exclusive_json(output, value, forbidden_trees=[root, artifacts_root],
                   input_paths=[p for p, _, _ in captured], before_publish=recheck)
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('prepare', 'inspect', 'verify'))
    for name in ('result', 'report', 'root', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--alert'); p.add_argument('--case', type=Path)
    p.add_argument('--record', type=Path); p.add_argument('--artifacts-root', type=Path)
    a = p.parse_args(argv)
    try:
        if a.mode == 'prepare':
            _require(a.alert and not any((a.case, a.record, a.artifacts_root)), 'prepare needs only an alert selection')
            value = prepare_case(a.result, a.report, a.root, a.alert, a.output)
            print('RUNTIME_CASE_PREPARED ' + value['case_id'] + '; authorization=pending; target_executed=False')
        else:
            _require(all((a.case, a.record, a.artifacts_root)) and not a.alert, 'explicit case/record/artifact root required')
            args = (a.case, a.result, a.report, a.root, a.record, a.artifacts_root)
            if a.mode == 'inspect':
                value = write_runtime_review(*args, a.output)
            else:
                value, _, recheck = inspect_runtime(*args)
                _require(canonical_bytes(decode_json(read_bounded(a.output, MAX_JSON))) == canonical_bytes(value),
                         'saved appendix differs from external evidence')
                recheck()
            print('RUNTIME_EVIDENCE ' + value['status'] + '; confirmed_vulnerabilities=0; records_only=True')
            return 0 if not value['blockers'] else 1
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('RUNTIME_EVIDENCE_REJECTED: invalid, changed or unbound input; no target executed')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
