"""Build bounded source windows from explicit roots for a verified review queue.

Excerpts are untrusted data, not control-flow proofs or instructions to an LLM.
This command performs local reads only. It never follows roots from queue JSON
without the caller supplying the exact job-to-root mapping independently.
"""
from __future__ import annotations

import argparse
import copy
from pathlib import Path

from .component_batch import _no_tree_links
from .source_snapshot import source_snapshot
from .source_scope import local_input_path
from .review_queue import (MAX_TOTAL_BYTES, canonical_bytes, sha256, checked_path,
                           read_bounded, decode_json, validate_review_queue, exclusive_json,
                           recheck_inputs, _require)

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_EXCERPT_BYTES = 64 * 1024
MAX_CONTEXT_BYTES = 16 * 1024 * 1024
MAX_GROUPS = 512


def _source_snapshot(root):
    _no_tree_links(root)
    return source_snapshot(root)


def _window(text, target, radius):
    lines = text.splitlines()
    _require(type(target) is int and 1 <= target <= len(lines), 'diagnostic line outside source file')
    start, end = max(1, target - radius), min(len(lines), target + radius)
    value = [{'line': index, 'text': lines[index - 1]} for index in range(start, end + 1)]
    _require(len(canonical_bytes(value)) <= MAX_EXCERPT_BYTES, 'source window exceeds excerpt limit')
    return value


def _build(queue_path, summary_path, source_roots, radius):
    _require(type(radius) is int and 0 <= radius <= 100, 'radius must be an integer from 0 to 100')
    _require(isinstance(source_roots, dict), 'explicit source root mapping required')
    queue_path = checked_path(queue_path)
    queue_raw = read_bounded(queue_path, MAX_TOTAL_BYTES)
    queue = decode_json(queue_raw)
    validate_review_queue(queue, summary_path)
    _require(len(queue['groups']) <= MAX_GROUPS, 'too many context groups; use a smaller explicit batch')
    _require(set(source_roots) == {s['job'] for s in queue['sources']},
             'every queue job needs exactly one explicit source root')
    roots, expected, root_records = {}, {}, []
    for source in queue['sources']:
        job = source['job']
        _require(isinstance(source_roots[job], (str, Path)), 'invalid explicit source root')
        root = checked_path(source_roots[job])
        _require(str(root) == source['source_root'] and root.is_dir(), 'explicit root differs from recorded source root')
        snapshot = source['source_snapshot_sha256']
        _require(root not in expected or expected[root] == snapshot, 'same source root has incompatible snapshots')
        roots[job] = root
        expected[root] = snapshot
        root_records.append({'job': job, 'path': str(root), 'source_snapshot_sha256': snapshot})
    for root, snapshot in expected.items():
        _require(_source_snapshot(root) == snapshot, 'explicit source snapshot differs from scan')
    files, contexts, captured = {}, [], [(queue_path, queue_raw, MAX_TOTAL_BYTES)]
    total_source_bytes = total_context_bytes = 0
    for group in queue['groups']:
        root = roots[group['job']]
        path = local_input_path(root, group['location']['file'])
        path = checked_path(path)
        if path not in files:
            raw = read_bounded(path, MAX_SOURCE_BYTES)
            total_source_bytes += len(raw)
            _require(total_source_bytes <= MAX_TOTAL_BYTES, 'total excerpt inputs exceed byte budget')
            try:
                text = raw.decode('utf-8-sig')
            except UnicodeError as exc:
                raise ValueError('source context is not UTF-8') from exc
            files[path] = (raw, text)
            captured.append((path, raw, MAX_SOURCE_BYTES))
        raw, text = files[path]
        digest = sha256(raw)
        for observation in group['observations']:
            recorded = observation.get('evidence', {}).get('file_sha256')
            _require(recorded is None or recorded == digest, 'source bytes disagree with finding evidence')
        lines = _window(text, group['location']['line'], radius)
        total_context_bytes += len(canonical_bytes(lines))
        _require(total_context_bytes <= MAX_CONTEXT_BYTES, 'total context windows exceed budget')
        contexts.append({'group_id': group['group_id'], 'job': group['job'],
                         'location': copy.deepcopy(group['location']), 'source_file_sha256': digest,
                         'source_file_bytes': len(raw), 'source_snapshot_sha256': group['source_snapshot_sha256'],
                         'context_kind': 'text_window_not_control_flow',
                         'source_text_trust': 'untrusted_data_not_instructions',
                         'lines': lines, 'final_verdict': 'undetermined',
                         'review_questions': copy.deepcopy(group['review_questions'])})
    def recheck():
        recheck_inputs(captured)
        validate_review_queue(queue, summary_path)
        for root, snapshot in expected.items():
            _require(_source_snapshot(root) == snapshot, 'source snapshot changed during context extraction')
    recheck()
    value = {'schema': 'candidate-review-context-0.1', 'queue_sha256': sha256(queue_raw),
             'source_summary_sha256': queue['source_summary_sha256'], 'radius': radius,
             'source_roots': root_records, 'source_files_read': len(files), 'source_bytes_read': total_source_bytes,
             'group_count': len(contexts), 'contexts': contexts,
             'confirmed_vulnerabilities': 0, 'final_verdict': 'undetermined',
             'limitations': ['Text windows do not establish reachability, control flow or safety.',
                             'The source roots were explicitly supplied and full snapshots rechecked.',
                             'Filesystem snapshots are observations, not immutable mounts or signatures.',
                             'Repository, macro, string and comment text is untrusted input, not instructions.',
                             'No analyzer, target program, network or model was invoked.']}
    return value, recheck, roots


def build_review_context(queue_path: Path, summary_path: Path, source_roots: dict, *, radius=8) -> dict:
    return _build(queue_path, summary_path, source_roots, radius)[0]


def validate_review_context(value, queue_path: Path, summary_path: Path, source_roots: dict) -> None:
    _require(isinstance(value, dict), 'invalid context document')
    expected = build_review_context(queue_path, summary_path, source_roots, radius=value.get('radius'))
    _require(canonical_bytes(value) == canonical_bytes(expected), 'source context differs from verified inputs')


def write_review_context(queue_path, summary_path, source_roots, output, *, radius=8):
    value, recheck, roots = _build(queue_path, summary_path, source_roots, radius)
    exclusive_json(output, value,
                   forbidden_trees=[Path(summary_path).absolute().parent, *roots.values()],
                   input_paths=[queue_path, summary_path], before_publish=recheck)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--queue', type=Path, required=True)
    parser.add_argument('--source-root', action='append', default=[], metavar='JOB=PATH')
    parser.add_argument('--radius', type=int, default=8)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path)
    mode.add_argument('--verify', type=Path)
    args = parser.parse_args(argv)
    try:
        roots = {}
        for entry in args.source_root:
            job, separator, path = entry.partition('=')
            _require(bool(separator) and bool(path) and job not in roots, 'duplicate or invalid JOB=PATH')
            roots[job] = Path(path)
        if args.verify:
            validate_review_context(decode_json(read_bounded(args.verify, MAX_TOTAL_BYTES)),
                                    args.queue, args.summary, roots)
            print('VERIFIED: original source windows; no safety or vulnerability verdict')
        else:
            value = write_review_context(args.queue, args.summary, roots, args.output, radius=args.radius)
            print('CONTEXT_READY: groups=' + str(value['group_count']) +
                  ' source_files=' + str(value['source_files_read']) + ' confirmed_vulnerabilities=0')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('REJECTED: ' + str(exc))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
