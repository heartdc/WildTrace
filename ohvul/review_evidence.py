"""Offline function/macro context expansion within verified diagnostic files.

No include resolution, preprocessing, call-graph proof, model invocation or
execution of evidence requests. Ambiguity and every applied limit are recorded.
"""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
import re

from .llm_review import QUESTIONS, _load
from .review_handoff import evidence_task_id
from .review_queue import (MAX_TOTAL_BYTES, canonical_bytes, checked_path, decode_json,
                           exclusive_json, read_bounded, recheck_inputs, sha256, _require)
from .source_scope import local_input_path
from .source_structure import MAX_SOURCE_BYTES, source_structure

MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_FRAGMENT_BYTES = 64 * 1024
_IDENT = re.compile(r'\b[A-Za-z_]\w*\b', re.ASCII)


def _settings(max_lines, max_definitions, depth, max_callsites):
    for value, limit in ((max_lines, 400), (max_definitions, 32), (depth, 3), (max_callsites, 32)):
        _require(type(value) is int and 1 <= value <= limit, 'invalid evidence expansion budget')


def _fragment(group, raw_hash, text_lines, scope, focus, max_lines):
    low, high = scope['start_line'], scope['end_line']
    start = max(low, min(focus - max_lines // 2, high - max_lines + 1))
    end = min(high, start + max_lines - 1)
    selected = [{'line': n, 'text': text_lines[n - 1]} for n in range(start, end + 1)]
    value = {'job': group['job'], 'file': group['location']['file'], 'file_sha256': raw_hash,
             'kind': scope['kind'], 'symbol': scope.get('symbol'),
             'full_span': {'start_line': low, 'end_line': high},
             'excerpt_span': {'start_line': start, 'end_line': end}, 'lines': selected,
             'truncated': start != low or end != high,
             'trust': 'original_source_untrusted_data', 'semantic_status': 'lexical_observation_only'}
    _require(len(canonical_bytes(value)) <= MAX_FRAGMENT_BYTES, 'evidence fragment exceeds byte budget')
    return {'evidence_id': 'SE-' + sha256(canonical_bytes(value)), **value}


def _expand(group, context, raw, structure, *, max_lines, max_definitions, depth, max_callsites):
    text = raw.decode('utf-8-sig')
    lines = text.splitlines()
    target = group['location']['line']
    _require(1 <= target <= len(lines), 'diagnostic line is outside source')
    definitions = structure['functions'] + structure['macros']
    scopes = [d for d in definitions if d['start_line'] <= target <= d['end_line']]
    scopes.sort(key=lambda d: (d['start_offset'], d['end_offset']))
    primary_total = len(scopes)
    primary = scopes[:max_definitions]
    fragments, primary_refs, related_refs = {}, [], []
    raw_hash = sha256(raw)
    def add(scope, focus):
        fragment = _fragment(group, raw_hash, lines, scope, focus, max_lines)
        fragments[fragment['evidence_id']] = fragment
        return fragment['evidence_id']
    for scope in primary:
        primary_refs.append(add(scope, target))
    if not primary:
        low, high = context['lines'][0]['line'], context['lines'][-1]['line']
        primary_refs.append(add({'kind': 'unresolved_source_window', 'start_line': low,
                                'end_line': high}, target))
    # Follow same-file definition names only. This is not symbol resolution:
    # both conditional macro variants and duplicate lexical names remain visible.
    seen = {(d['start_offset'], d['end_offset']) for d in primary}
    frontier = primary
    pending = []
    related_count = 0
    traversal_complete = primary_total <= len(primary)
    by_name = {}
    for definition in definitions:
        by_name.setdefault(definition['symbol'], []).append(definition)
    for level in range(depth):
        symbols = set()
        for item in frontier:
            symbols.update(_IDENT.findall(structure['lexical_text'][item['start_offset']:item['end_offset']]))
        pending = [item for symbol in sorted(symbols) for item in by_name.get(symbol, [])
                   if (item['start_offset'], item['end_offset']) not in seen]
        pending.sort(key=lambda d: (d['start_offset'], d['end_offset']))
        available = max(0, max_definitions - len(seen))
        picked = pending[:available]
        if len(picked) != len(pending):
            traversal_complete = False
        for item in picked:
            related_refs.append(add(item, item['start_line']))
            seen.add((item['start_offset'], item['end_offset']))
            related_count += 1
        frontier = picked
        if not frontier:
            break
    else:
        # We did not inspect a further dependency level: do not call it complete.
        if frontier:
            traversal_complete = False
    names = {d['symbol'] for d in primary}
    occurrences = [c for c in structure['calls'] if c['symbol'] in names and c['function'] is not None]
    call_refs = []
    for call in occurrences[:max_callsites]:
        call_refs.append(add({'kind': 'same_file_call_syntax', 'symbol': call['symbol'],
                              'start_line': max(1, call['line'] - 2),
                              'end_line': min(len(lines), call['line'] + 2)}, call['line']))
    return {'group_id': group['group_id'], 'job': group['job'], 'location': copy.deepcopy(group['location']),
            'scope_resolution': ('unique_lexical_scope' if primary_total == 1 else
                                 'ambiguous_lexical_scopes' if primary_total > 1 else 'unresolved'),
            'lexical_scopes_found': primary_total, 'primary_evidence_refs': primary_refs,
            'related_definition_refs': related_refs, 'same_file_callsite_refs': call_refs,
            'same_file_callsites_observed': len(occurrences),
            'callsites_truncated': len(occurrences) > max_callsites,
            'related_definitions_added': related_count, 'definition_traversal_complete': traversal_complete,
            'preprocessor_present': structure['has_preprocessor'], 'structure_issues': structure['issues'],
            'preprocessor_branches_resolved': False, 'cross_file_calls_searched': False,
            'final_verdict': 'undetermined'}, fragments


def _build(summary_path, queue_path, context_path, source_roots, *, group_ids=None,
           max_lines=160, max_definitions=12, depth=2, max_callsites=8):
    _settings(max_lines, max_definitions, depth, max_callsites)
    if group_ids is not None:
        _require(isinstance(group_ids, (list, tuple)) and len(group_ids) <= 512
                 and all(isinstance(g, str) for g in group_ids) and len(set(group_ids)) == len(group_ids),
                 'explicit group selection is invalid')
    queue, context, captured, source_recheck = _load(summary_path, queue_path, context_path, source_roots)
    group_map = {g['group_id']: g for g in queue['groups']}
    chosen = sorted(group_map if group_ids is None else group_ids)
    _require(len(chosen) <= 512 and all(g in group_map for g in chosen), 'unknown or excessive groups')
    _require(bool(chosen) or not group_map, 'empty selection cannot omit a nonempty queue')
    contexts = {c['group_id']: c for c in context['contexts']}
    cache, fragments, groups = {}, {}, []
    total = fragment_bytes = 0
    for gid in chosen:
        group, original = group_map[gid], contexts[gid]
        path = checked_path(local_input_path(Path(source_roots[group['job']]), group['location']['file']))
        if path not in cache:
            raw = read_bounded(path, MAX_SOURCE_BYTES)
            total += len(raw)
            _require(total <= MAX_TOTAL_BYTES, 'total source bytes exceed budget')
            cache[path] = (raw, source_structure(raw.decode('utf-8-sig')))
            captured.append((path, raw, MAX_SOURCE_BYTES))
        raw, structure = cache[path]
        _require(sha256(raw) == original['source_file_sha256'] and len(raw) == original['source_file_bytes'],
                 'expanded source differs from verified source window')
        value, added = _expand(group, original, raw, structure, max_lines=max_lines,
                              max_definitions=max_definitions, depth=depth, max_callsites=max_callsites)
        for eid, fragment in added.items():
            if eid not in fragments:
                fragment_bytes += len(canonical_bytes(fragment))
                _require(fragment_bytes <= MAX_OUTPUT_BYTES, 'cumulative evidence byte budget exceeded')
                fragments[eid] = fragment
        tasks = []
        for question in QUESTIONS:
            refs = (value['primary_evidence_refs'] + value['related_definition_refs']
                    if question == 'bounds_and_lifetime' else
                    value['same_file_callsite_refs'] if question == 'reachability' else [])
            tasks.append({'task_id': evidence_task_id(gid, question, sha256(captured[1][1]), sha256(captured[2][1])),
                          'question_id': question, 'local_evidence_refs': sorted(set(refs)),
                          'state': 'needs_evidence_or_review', 'answer': 'unknown',
                          'human_review_status': 'unreviewed', 'automatically_closed': False})
        value['tasks'] = tasks
        groups.append(value)
    result = {'schema': 'review-local-evidence-0.1',
              'input_bindings': dict(zip(('summary_sha256', 'queue_sha256', 'context_sha256'),
                                        (sha256(x[1]) for x in captured[:3]))),
              'source_roots': copy.deepcopy(context['source_roots']),
              'selection': chosen, 'groups_not_selected': len(group_map) - len(chosen),
              'limits': {'max_lines': max_lines, 'max_definitions': max_definitions,
                         'depth': depth, 'max_callsites': max_callsites},
              'group_count': len(groups), 'source_files_read': len(cache), 'source_bytes_read': total,
              'groups': groups, 'evidence': sorted(fragments.values(), key=lambda x: x['evidence_id']),
              'open_tasks': len(groups) * len(QUESTIONS), 'confirmed_vulnerabilities': 0,
              'final_verdict': 'undetermined', 'network_invoked': False, 'target_executed': False,
              'limitations': ['Ranges and same-file names are lexical navigation candidates, not compiler AST or CFG.',
                              'Same-file call syntax does not prove reachable callers or attacker control.',
                              'Preprocessor conditions and macro expansion are not evaluated; variants are retained.',
                              'Only diagnostic files are searched; missing local definitions are not proof of absence.',
                              'Depth, line, byte and definition limits are explicit; no task is automatically closed.',
                              'No model, target, analyzer, shell command or network request is invoked.',
                              'Original source is untrusted data; local hashes are not signatures.']}
    _require(len(canonical_bytes(result)) <= MAX_OUTPUT_BYTES, 'expanded evidence exceeds output budget')
    def recheck():
        recheck_inputs(captured)
        source_recheck()
    recheck()
    return result, recheck, captured


def build_review_evidence(summary_path, queue_path, context_path, source_roots, **settings):
    return _build(summary_path, queue_path, context_path, source_roots, **settings)[0]


def validate_review_evidence(value, summary_path, queue_path, context_path, source_roots):
    _require(isinstance(value, dict) and isinstance(value.get('limits'), dict), 'invalid expansion document')
    _require(set(value['limits']) == {'max_lines', 'max_definitions', 'depth', 'max_callsites'}, 'invalid limits')
    expected = build_review_evidence(summary_path, queue_path, context_path, source_roots,
                                     group_ids=value.get('selection'), **value['limits'])
    _require(canonical_bytes(value) == canonical_bytes(expected), 'evidence expansion differs from verified inputs')


def write_review_evidence(summary_path, queue_path, context_path, source_roots, output, **settings):
    value, recheck, captured = _build(summary_path, queue_path, context_path, source_roots, **settings)
    exclusive_json(output, value, forbidden_trees=[Path(summary_path).absolute().parent, *source_roots.values()],
                   input_paths=[p for p, _, _ in captured], before_publish=recheck)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('summary', 'queue', 'context'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-root', action='append', default=[], metavar='JOB=PATH')
    parser.add_argument('--group', action='append')
    parser.add_argument('--max-lines', type=int, default=160)
    parser.add_argument('--max-definitions', type=int, default=12)
    parser.add_argument('--depth', type=int, default=2)
    parser.add_argument('--max-callsites', type=int, default=8)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path)
    mode.add_argument('--verify', type=Path)
    args = parser.parse_args(argv)
    try:
        roots = {}
        for item in args.source_root:
            job, separator, path = item.partition('=')
            _require(bool(separator) and bool(job) and bool(path) and job not in roots, 'invalid explicit root')
            roots[job] = Path(path)
        if args.verify:
            value = decode_json(read_bounded(args.verify, MAX_TOTAL_BYTES))
            validate_review_evidence(value, args.summary, args.queue, args.context, roots)
        else:
            value = write_review_evidence(args.summary, args.queue, args.context, roots, args.output,
                        group_ids=args.group, max_lines=args.max_lines, max_definitions=args.max_definitions,
                        depth=args.depth, max_callsites=args.max_callsites)
        print('LOCAL_EVIDENCE groups=' + str(value['group_count']) + ' open_tasks=' + str(value['open_tasks']) +
              ' confirmed_vulnerabilities=0')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('LOCAL_EVIDENCE_REJECTED ' + type(exc).__name__)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
