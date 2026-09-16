"""Offline, evidence-bound follow-up tasks; never execute model suggestions.

Every review group and question remains visible. Failed/not-run records are not
answers. Reference-valid model drafts are still untrusted proposals, not facts,
human approvals, completed tasks or vulnerability confirmations.
"""
from __future__ import annotations

import argparse
import copy
from pathlib import Path

from .llm_review import QUESTIONS, _load, inspect_review, make_request
from .llm_evidence import extend_request
from .review_queue import (MAX_TOTAL_BYTES, canonical_bytes, checked_path, decode_json,
                           exclusive_json, read_bounded, recheck_inputs, sha256, _require)

MAX_REVIEW_RUNS = 8
MAX_HANDOFF_BYTES = 16 * 1024 * 1024


def evidence_task_id(group_id, question_id, queue_sha256, context_sha256):
    """Stable identity shared with local evidence expansion; no state change."""
    return 'ET-' + sha256(canonical_bytes({'group_id': group_id, 'question_id': question_id,
                                         'queue_sha256': queue_sha256, 'context_sha256': context_sha256}))


def _build(summary_path, queue_path, context_path, source_roots, review_runs, evidence_path=None):
    _require(isinstance(review_runs, (list, tuple)) and len(review_runs) <= MAX_REVIEW_RUNS,
             'at most eight explicit historical review runs are supported')
    _require(all(isinstance(p, (str, Path)) for p in review_runs), 'invalid explicit review run path')
    runs = [checked_path(path) for path in review_runs]
    _require(len(set(runs)) == len(runs), 'duplicate review run path')
    queue, context, captured, recheck_source = _load(
        summary_path, queue_path, context_path, source_roots, evidence_path)
    expansion = decode_json(captured[3][1]) if evidence_path is not None else None
    contexts = {item['group_id']: item for item in context['contexts']}
    by_group = {group['group_id']: [] for group in queue['groups']}
    run_records, seen = [], set()
    total_bytes = sum(len(raw) for _, raw, _ in captured)
    for path in runs:
        inspection = inspect_review(path, summary_path, queue_path, context_path, source_roots,
                                    evidence_path=evidence_path)
        plan, summary = inspection['plan'], inspection['summary']
        # Content identity deliberately excludes the enclosing directory. Copying
        # a run cannot make the same historical calls count a second time.
        run_id = 'LR-' + sha256(canonical_bytes({'plan': plan, 'summary': summary}))
        _require(run_id not in seen, 'duplicate review execution contents')
        seen.add(run_id)
        for binding in inspection['artifact_bindings']:
            source = checked_path(binding['path'])  # Constructed by inspector, never model output.
            raw = read_bounded(source, MAX_TOTAL_BYTES)
            _require(sha256(raw) == binding['sha256'] and len(raw) == binding['bytes'],
                     'review artifacts changed while collecting handoff')
            total_bytes += len(raw)
            _require(total_bytes <= MAX_TOTAL_BYTES, 'review handoff input byte budget exceeded')
            captured.append((source, raw, MAX_TOTAL_BYTES))
        run_records.append({'run_id': run_id, 'path': str(path),
                            'inspection_status': inspection['status'],
                            'execution_policy': inspection['execution_policy'],
                            'calls_attempted': summary['calls_attempted'],
                            'valid_drafts': summary['valid_drafts'],
                            'failed_calls': summary['failed_calls'],
                            'usage': copy.deepcopy(summary['usage']),
                            'artifact_bindings': copy.deepcopy(inspection['artifact_bindings']),
                            'reasoning_verified': False})
        for record in inspection['records']:
            by_group[record['group_id']].append((run_id, record))
    groups = []
    for group in queue['groups']:
        group_id = group['group_id']
        request = make_request(group, contexts[group_id])
        if expansion is not None and group_id in expansion['selection']:
            request = extend_request(request, expansion)
        outcomes, proposals, valid = {}, [], []
        for run_id, record in by_group[group_id]:
            outcome = record['outcome']
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
            reference = {'run_id': run_id, 'record_sha256': sha256(canonical_bytes(record))}
            if outcome == 'valid_draft':
                valid.append((reference, record['draft']))
                proposals.append({**reference, 'recommendation': record['draft']['recommendation'],
                                  'summary': record['draft']['summary'],
                                  'trust': 'untrusted_model_proposal', 'reasoning_verified': False})
        questions = {item['id']: item for item in group['review_questions']}
        _require(set(questions) == set(QUESTIONS), 'review question contract mismatch')
        tasks = []
        for question_id in QUESTIONS:
            assessments, checks = [], []
            for reference, draft in valid:
                row = next(item for item in draft['assessments'] if item['question_id'] == question_id)
                assessments.append({**reference, **copy.deepcopy(row),
                                    'trust': 'untrusted_model_proposal', 'reasoning_verified': False})
                checks.extend({**reference, 'needed_evidence': item['needed_evidence'],
                               'trust': 'untrusted_model_proposal', 'automatic_execution': False}
                              for item in draft['next_checks'] if item['question_id'] == question_id)
            identity = {'group_id': group_id, 'question_id': question_id,
                        'queue_sha256': sha256(captured[1][1]), 'context_sha256': sha256(captured[2][1])}
            tasks.append({'task_id': evidence_task_id(**identity),
                          'question_id': question_id, 'question': questions[question_id]['question'],
                          'state': 'needs_evidence_or_review', 'answer': 'unknown',
                          'human_review_status': 'unreviewed', 'automatic_execution': False,
                          'model_assessments': assessments, 'model_requested_evidence': checks})
        groups.append({'group_id': group_id, 'job': group['job'],
                       'location': copy.deepcopy(group['location']), 'category': group['category'],
                       'canonical_rule': group['canonical_rule'], 'cwe_candidate': group['cwe_candidate'],
                       'source_file_sha256': contexts[group_id]['source_file_sha256'],
                       'source_snapshot_sha256': group['source_snapshot_sha256'],
                       'profile_sha256': group['profile_sha256'],
                       'evidence_catalog': request['evidence_catalog'],
                       'model_outcomes': dict(sorted(outcomes.items())),
                       'model_review_state': ('proposals_require_review' if valid else
                                              'no_accepted_draft' if outcomes else 'not_requested'),
                       'priority_proposals': proposals, 'tasks': tasks, 'final_verdict': 'undetermined'})
        if 'compiler_context' in group:
            # Separate recorded compiler observations from model opinions. No task
            # is automatically answered, approved, closed or scheduled to execute.
            groups[-1]['compiler_context'] = copy.deepcopy(group['compiler_context'])
    value = {'schema': 'review-evidence-handoff-0.1',
             'input_bindings': dict(zip(('summary_sha256', 'queue_sha256', 'context_sha256'),
                                       (sha256(item[1]) for item in captured[:3]))),
             'source_roots': copy.deepcopy(context['source_roots']),
             'sources': copy.deepcopy(queue['sources']), 'raw_diagnostics': queue['raw_diagnostics'],
             'group_count': len(groups), 'open_tasks': sum(len(g['tasks']) for g in groups),
             'groups_without_valid_model_draft': sum(g['model_review_state'] != 'proposals_require_review'
                                                    for g in groups),
             'llm_runs': run_records, 'groups': groups,
             'execution': {'network_invoked': False, 'commands_executed': False,
                           'target_executed': False, 'model_invoked': False},
             'confirmed_vulnerabilities': 0, 'final_verdict': 'undetermined',
             'limitations': ['All tasks remain open until a separate evidence review records a decision.',
                             'Reference-valid model text is not factual validation or proof of safety.',
                             'A failed call, stopped call, and unselected group are distinct states.',
                             'Unknowns are retained; no runtime evidence or call paths are invented.',
                             'Evidence requests are text, never executable instructions.',
                             'Local hashes establish consistency, not signed provenance.']}
    _require(len(canonical_bytes(value)) <= MAX_HANDOFF_BYTES, 'handoff exceeds output byte budget')
    if expansion is not None:
        value['input_bindings']['evidence_sha256'] = sha256(captured[3][1])
    def recheck():
        recheck_inputs(captured)
        recheck_source()
    recheck()
    return value, recheck, runs, captured


def build_review_handoff(summary_path, queue_path, context_path, source_roots, review_runs=(), *, evidence_path=None):
    return _build(summary_path, queue_path, context_path, source_roots, review_runs, evidence_path)[0]


def validate_review_handoff(value, summary_path, queue_path, context_path, source_roots, review_runs=(), *, evidence_path=None):
    expected = build_review_handoff(summary_path, queue_path, context_path, source_roots, review_runs,
                                    evidence_path=evidence_path)
    _require(canonical_bytes(value) == canonical_bytes(expected), 'handoff differs from verified evidence inputs')


def write_review_handoff(summary_path, queue_path, context_path, source_roots, output, *, review_runs=(), evidence_path=None):
    value, recheck, runs, captured = _build(summary_path, queue_path, context_path, source_roots, review_runs, evidence_path)
    exclusive_json(output, value,
                   forbidden_trees=[Path(summary_path).absolute().parent, *source_roots.values(), *runs],
                   input_paths=[p for p, _, _ in captured], before_publish=recheck)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('summary', 'queue', 'context'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-root', action='append', default=[], metavar='JOB=PATH')
    parser.add_argument('--evidence', type=Path, help='explicit verified expansion used by selected LLM runs')
    parser.add_argument('--llm-run', action='append', default=[], type=Path,
                        help='explicit historical review directory, including bound failures; never invokes a model')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path)
    mode.add_argument('--verify', type=Path)
    args = parser.parse_args(argv)
    try:
        roots = {}
        for entry in args.source_root:
            job, separator, path = entry.partition('=')
            _require(bool(separator) and bool(job) and bool(path) and job not in roots,
                     'invalid or duplicate explicit source root')
            roots[job] = Path(path)
        if args.verify:
            value = decode_json(read_bounded(args.verify, MAX_TOTAL_BYTES))
            validate_review_handoff(value, args.summary, args.queue, args.context, roots, args.llm_run,
                                     evidence_path=args.evidence)
            print('HANDOFF_VERIFIED: evidence bindings only; no factual or vulnerability verdict')
        else:
            value = write_review_handoff(args.summary, args.queue, args.context, roots, args.output,
                                          review_runs=args.llm_run, evidence_path=args.evidence)
            print('HANDOFF_READY groups=' + str(value['group_count']) + ' open_tasks=' + str(value['open_tasks']) +
                  ' confirmed_vulnerabilities=0')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('HANDOFF_REJECTED ' + type(exc).__name__)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
