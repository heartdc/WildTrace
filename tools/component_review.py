"""Run existing static stages through verified review handoff; never a target or model."""
from pathlib import Path
import argparse
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ohvul.component_batch import _validate, _read_manifest, run_batch
from ohvul.engine_profile import _read_profile
from ohvul.review_queue import (write_review_queue, validate_review_queue, read_bounded,
                               decode_json, exclusive_json, sha256, canonical_bytes,
                               checked_path, recheck_inputs)
from ohvul.review_context import write_review_context, validate_review_context
from ohvul.review_handoff import write_review_handoff, validate_review_handoff


def _verified_status(manifest, original, output, jobs):
    """Rebuild readiness from fixed paths, never follow artifact paths from status."""
    roots = {job['id']: job['source_root'] for job in jobs}
    summary = output / 'batch' / f'summary-{len(jobs) + 2:04d}.json'
    review = output / 'review'
    queue_path, context_path, handoff_path = [review / n for n in ('queue.json', 'context.json', 'handoff.json')]
    paths = [summary, queue_path, context_path, handoff_path]
    captured = [(checked_path(p), read_bounded(p, 64 * 1024 * 1024), 64 * 1024 * 1024)
                for p in paths]
    batch, q, c, h = (decode_json(raw) for _, raw, _ in captured)
    if not isinstance(batch, dict) or not isinstance(batch.get('jobs'), list):
        raise ValueError('saved batch must contain a job list')
    if (batch.get('manifest_sha256') != sha256(original)
            or checked_path(batch['manifest']) != manifest
            or [j['id'] for j in batch['jobs']] != [j['id'] for j in jobs]):
        raise ValueError('saved batch differs from explicit manifest')
    for expected, saved in zip(jobs, batch['jobs']):
        inputs = saved['inputs']
        if (checked_path(inputs['source_root']) != expected['source_root']
                or checked_path(inputs['profile']) != expected['profile']
                or sha256(_read_profile(expected['profile'])) != inputs['profile_sha256']):
            raise ValueError('saved job differs from current explicit input')
        selection = saved.get('analysis_selection')
        if expected['modern'] and (not isinstance(selection, dict)
                                   or selection.get('analyses') != expected['analyses']):
            raise ValueError('saved stage selection differs from manifest')
    validate_review_queue(q, summary)
    validate_review_context(c, queue_path, summary, roots)
    validate_review_handoff(h, summary, queue_path, context_path, roots)
    status = {'schema': 'static-review-delivery-0.1', 'status': 'static_review_ready',
              'manifest_sha256': sha256(original), 'jobs': len(jobs),
              'raw_diagnostics': q['raw_diagnostics'], 'review_groups': q['group_count'],
              'open_evidence_tasks': h['open_tasks'], 'source_roots': {k: str(v) for k, v in roots.items()},
              'artifacts': [{'path': p.relative_to(output).as_posix(), 'sha256': sha256(raw), 'bytes': len(raw)}
                            for p, raw, _ in captured],
              'runtime_verification': 'not_run', 'target_executed': False, 'model_invoked': False,
              'confirmed_vulnerabilities': 0,
              'limitations': ['Static review readiness is not a completed vulnerability case.',
                              'Runtime scope, environment, security impact and independent reproduction remain separate gates.']}
    def recheck():
        if _read_manifest(manifest) != original:
            raise ValueError('manifest changed during review')
        recheck_inputs(captured)
        for expected, saved in zip(jobs, batch['jobs']):
            if sha256(_read_profile(expected['profile'])) != saved['inputs']['profile_sha256']:
                raise ValueError('profile changed during review')
        validate_review_handoff(h, summary, queue_path, context_path, roots)
    recheck()
    return status, recheck


def run_pipeline(manifest, output, *, timeout=120, max_jobs=32):
    manifest, original, output, jobs = _validate(manifest, output, max_jobs, timeout, False)
    roots = {job['id']: job['source_root'] for job in jobs}
    output.mkdir(exist_ok=False)
    if _read_manifest(manifest) != original:
        raise ValueError('manifest changed before execution')
    code = run_batch(manifest, output / 'batch', timeout=timeout, max_jobs=max_jobs)
    if code:
        raise ValueError('static batch incomplete; diagnostics retained, no review-ready receipt')
    summary = output / 'batch' / f'summary-{len(jobs) + 2:04d}.json'
    review = output / 'review'
    review.mkdir()
    queue_path, context_path, handoff_path = [review / n for n in ('queue.json', 'context.json', 'handoff.json')]
    write_review_queue(summary, queue_path)
    write_review_context(queue_path, summary, roots, context_path)
    write_review_handoff(summary, queue_path, context_path, roots, handoff_path)
    status, recheck = _verified_status(manifest, original, output, jobs)
    exclusive_json(output / 'status.json', status, forbidden_trees=roots.values(),
                   input_paths=[manifest], before_publish=recheck)
    return status


def verify_pipeline(manifest, output, *, timeout=120, max_jobs=32):
    """Read-only recheck of a saved delivery; invokes no analyzer or model."""
    manifest, original, output, jobs = _validate(
        manifest, output, max_jobs, timeout, False, existing_output=True)
    path = checked_path(output / 'status.json')
    raw = read_bounded(path, 1024 * 1024)
    saved = decode_json(raw)
    expected, recheck = _verified_status(manifest, original, output, jobs)
    if canonical_bytes(saved) != canonical_bytes(expected):
        raise ValueError('saved readiness receipt differs from verified inputs')
    recheck()
    if read_bounded(path, 1024 * 1024) != raw:
        raise ValueError('readiness receipt changed during verification')
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--verify', action='store_true',
                        help='offline check of existing delivery; never reruns analysis or writes files')
    args = parser.parse_args(argv)
    try:
        operation = verify_pipeline if args.verify else run_pipeline
        result = operation(args.manifest, args.output, timeout=args.timeout)
        print(('STATIC_REVIEW_VERIFIED' if args.verify else 'STATIC_REVIEW_READY') + ' groups=' + str(result['review_groups']) +
              ' open_tasks=' + str(result['open_evidence_tasks']) + ' runtime=not_run confirmed_vulnerabilities=0')
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('STATIC_REVIEW_INCOMPLETE ' + type(exc).__name__)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
