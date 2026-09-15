"""Conservative, source-bound length candidates. No CFG/data-flow proof.

Local observations and optional caller/parameter associations are kept separate.
Unsupported syntax never becomes a safe verdict. Use scan_semantic_files for
execution/coverage diagnostics; list-returning APIs are compatibility helpers.
"""
from __future__ import annotations

import re
from pathlib import Path

from .domain.evidence import make_bundle
from .source_scope import relative_path
from .semantic_syntax import load_units, line_at, parsed_calls, parameters, IDENT

VERSION = '0.2'
SINKS = {'memcpy': (2, 3), 'memmove': (2, 3), 'strncpy': (2, 3), 'snprintf': (1, None)}
LENGTH_SOURCES = {'strlen', 'strnlen', 'read', 'recv'}
GUARD = re.compile(r'\bif\s*\(|\b(?:sizeof|capacity|max_len|limit)\b')
MAX_CANDIDATES = 20000
MAX_ISSUES = 20000


def _issue(issues, unit, offset, reason, **extra):
    if len(issues) >= MAX_ISSUES:
        raise ValueError('semantic issue budget exceeded')
    issues.append({'file': unit['file'], 'line': line_at(unit, offset), 'reason': reason,
                   'status': 'unknown', **extra})


def _emit(output, value):
    if len(output) >= MAX_CANDIDATES:
        raise ValueError('semantic candidate budget exceeded')
    output.append(value)


def _local(unit, calls, issues):
    candidates, sinks = [], []
    code = unit['code']
    length_calls = [c for c in calls if c['symbol'] in LENGTH_SOURCES
                    and not c['member'] and not c['declaration']]
    for call in calls:
        name = call['symbol']
        if name not in SINKS:
            continue
        if call['declaration']:
            continue
        if call['member']:
            _issue(issues, unit, call['offset'], 'member_api_not_resolved', symbol=name)
            continue
        scope = call['scope']
        index, arity = SINKS[name]
        args = call['arguments']
        valid = args is not None and ((len(args) == arity) if arity else len(args) >= 3)
        if not valid:
            _issue(issues, unit, call['offset'], 'sink_arguments_unresolved', symbol=name)
        if scope is None:
            _issue(issues, unit, call['offset'], 'sink_function_unresolved', symbol=name)
        begin = scope['body_offset'] + 1 if scope else call['offset']
        earlier_sources = [c for c in length_calls if c['symbol'] in LENGTH_SOURCES
                           and c['scope'] is scope and scope is not None
                           and begin <= c['offset'] < call['offset'] and not c['member']]
        source_lines = sorted({c['line'] for c in earlier_sources})
        guard_lines = sorted({line_at(unit, m.start()) for m in GUARD.finditer(code, begin, call['offset'])})
        value = {'kind': 'length_propagation_candidate', 'status': 'candidate',
                 'semantic_status': 'lexical_observations_not_data_flow',
                 'source_file': unit['file'], 'source_file_sha256': {unit['file']: unit['sha256']},
                 'function': scope['symbol'] if scope else None,
                 'sink': {'kind': name, 'line': call['line'],
                          'column': call['offset'] - unit['starts'][call['line'] - 1] + 1,
                          'size_argument_index': index,
                          'size_expression': args[index]['text'] if valid else None},
                 'source_lines': source_lines, 'guard_lines': guard_lines,
                 'evidence': [{'kind': 'copy_sink', 'line': call['line'], 'symbol': name},
                              *[{'kind': 'length_source', 'line': n} for n in source_lines],
                              *[{'kind': 'guard_or_bound', 'line': n} for n in guard_lines]],
                 'limitations': ['Earlier source/guard observations do not prove dominance or dependence.',
                                 'No branch, alias, macro, capacity or lifetime proof is performed.'],
                 'review_questions': ['Is the size bounded by the actual destination capacity?',
                                      'Which inputs reach this operation in the selected product?',
                                      'Do conversions, aliases or lifetime changes invalidate checks?']}
        _emit(candidates, value)
        if valid and scope is not None:
            sinks.append((call, args[index]))
    return candidates, sinks


def _mutated(code, symbol, start, end):
    word = r'\b' + re.escape(symbol) + r'\b'
    pattern = word + r'\s*(?:=(?!=)|(?:[+*/%&|^\-]|<<|>>)=|\+\+|--)|(?:\+\+|--)\s*' + word
    return re.search(pattern, code[start:end]) is not None


def _origins(unit, calls, call, argument):
    """Direct producers or latest simple assignment, NOT reaching definitions."""
    direct = [c for c in calls if c['symbol'] in LENGTH_SOURCES and not c['member'] and not c['declaration']
              and argument['start'] <= c['offset'] < argument['end']
              and c['arguments'] is not None]
    if direct:
        return direct
    symbol = argument['code'].strip()
    if not IDENT.fullmatch(symbol) or call['scope'] is None:
        return []
    start = call['scope']['body_offset'] + 1
    end = call['offset']
    prefix = unit['code'][start:end]
    writes = list(re.finditer(r'\b' + re.escape(symbol) + r'\s*=(?!=)', prefix))
    if not writes:
        return []
    write = writes[-1]
    rhs_start = start + write.end()
    stack, rhs_end = [], -1
    for position in range(rhs_start, end):
        char = unit['code'][position]
        if char in '([{':
            stack.append(char)
        elif char in ')]}':
            if not stack or stack.pop() != {')': '(', ']': '[', '}': '{'}[char]:
                return []
        elif char in ',;' and not stack:
            rhs_end = position
            break
    if rhs_end < 0 or _mutated(unit['code'], symbol, rhs_end + 1, end):
        return []
    # Address escape after the assignment invalidates this narrow association.
    if re.search(r'&\s*\b' + re.escape(symbol) + r'\b', unit['code'][rhs_end + 1:end]):
        return []
    if re.search(r'\b(?:size_t|ssize_t|int|unsigned|long|short|char|auto|float|double)\s+'
                 + re.escape(symbol) + r'\b', unit['code'][rhs_end + 1:end]):
        return []
    return [c for c in calls if c['symbol'] in LENGTH_SOURCES and not c['member'] and not c['declaration']
            and c['scope'] is call['scope'] and rhs_start <= c['offset'] < rhs_end
            and c['arguments'] is not None]


def _cross(units, calls_by_file, sinks_by_file, issues):
    definitions = {}
    sink_scopes = {}
    for unit in units:
        for function in unit['structure']['functions']:
            definitions.setdefault(function['symbol'], []).append((unit, function))
        for sink, size in sinks_by_file[unit['file']]:
            sink_scopes.setdefault((unit['file'], sink['scope']['start_offset']), []).append((sink, size))
    candidates = []
    for unit in units:
        calls = calls_by_file[unit['file']]
        for call in calls:
            if call['declaration']:
                continue
            choices = definitions.get(call['symbol'], [])
            if not choices:
                continue
            possible = [(u, f) for u, f in choices if
                        u is unit or not re.search(r'\bstatic\b', u['code'][f['start_offset']:f['name_offset']])]
            if not possible:
                _issue(issues, unit, call['offset'], 'no_visible_definition', symbol=call['symbol'])
                continue
            if len(possible) != 1 or call['member'] or call['scope'] is None:
                _issue(issues, unit, call['offset'], 'ambiguous_or_indirect_call', symbol=call['symbol'])
                continue
            callee_unit, function = possible[0]
            targets = sink_scopes.get((callee_unit['file'], function['start_offset']), [])
            if not targets:
                continue
            try:
                params = parameters(callee_unit, function)
            except ValueError:
                _issue(issues, unit, call['offset'], 'callee_parameters_unresolved', symbol=call['symbol'])
                continue
            if call['arguments'] is None or len(call['arguments']) != len(params):
                _issue(issues, unit, call['offset'], 'call_arity_or_arguments_unresolved', symbol=call['symbol'])
                continue
            # Parameter names alone do not resolve overloaded types or lambdas.
            bodies = [callee_unit['code'][function['body_offset']:function['end_offset']],
                      unit['code'][call['scope']['body_offset']:call['scope']['end_offset']]]
            if any(re.search(r'\]\s*(?:\([^;{}]*\)\s*)?(?:mutable\s*)?\{', body) for body in bodies):
                _issue(issues, unit, call['offset'], 'nested_callable_requires_compiler')
                continue
            for sink, size in targets:
                if re.search(r'\b(?:sizeof|alignof|decltype)\b', size['code']):
                    _issue(issues, unit, call['offset'], 'type_dependent_size_requires_compiler')
                    continue
                symbols = set(IDENT.findall(size['code']))
                for index, param in enumerate(params):
                    if param not in symbols:
                        continue
                    if _mutated(callee_unit['code'], param, function['body_offset'] + 1, sink['offset']):
                        _issue(issues, unit, call['offset'], 'callee_parameter_mutation_unresolved', symbol=param)
                        continue
                    argument = call['arguments'][index]
                    origins = _origins(unit, calls, call, argument)
                    if not origins:
                        _issue(issues, unit, call['offset'], 'caller_length_origin_unresolved', symbol=param)
                        continue
                    source_evidence = [{'kind': 'caller_length_source', 'source_file': unit['file'],
                                        'line': c['line'], 'column': c['offset']-unit['starts'][c['line']-1]+1,
                                        'symbol': c['symbol']} for c in origins]
                    _emit(candidates, {
                        'kind': 'cross_function_length_propagation_candidate', 'status': 'candidate',
                        'semantic_status': 'lexical_association_not_data_flow',
                        'source_file_sha256': {unit['file']: unit['sha256'], callee_unit['file']: callee_unit['sha256']},
                        'caller': {'source_file': unit['file'], 'function': call['scope']['symbol'],
                                   'call_line': call['line'], 'callee': call['symbol'],
                                   'length_argument': argument['text'], 'argument_index': index},
                        'callee': {'source_file': callee_unit['file'], 'definition_line': function['name_line'],
                                   'function_end_line': function['end_line'], 'sink_line': sink['line'],
                                   'sink_kind': sink['symbol'], 'size_expression': size['text'],
                                   'size_parameter': param, 'size_parameter_index': index},
                        'evidence': [*source_evidence,
                                     {'kind': 'callee_copy_sink', 'source_file': callee_unit['file'], 'line': sink['line']}],
                        'limitations': ['Unique lexical name and argument positions are not a linked call graph.',
                                        'Branch dominance, aliasing, shadowing, macros and data flow remain unproven.'],
                        'review_questions': ['Does the observed source value actually reach this argument?',
                                             'Is the checked capacity valid on the reachable path?']})
    return candidates


def _analyze(units):
    local, issues, calls_by_file, sinks_by_file = [], [], {}, {}
    for unit in units:
        structure = unit['structure']
        for problem in structure['issues']:
            _issue(issues, unit, 0, problem)
        if structure['has_preprocessor']:
            _issue(issues, unit, 0, 'preprocessor_not_evaluated')
        calls = parsed_calls(unit)
        for call in calls:
            # Exact standard-library spellings only, not arbitrary namespaces.
            if call['symbol'].startswith('std::') and call['symbol'][5:] in (set(SINKS) | LENGTH_SOURCES):
                call['original_symbol'] = call['symbol']
                call['symbol'] = call['symbol'][5:]
        calls_by_file[unit['file']] = calls
        values, sinks = _local(unit, calls, issues)
        for value in values:
            _emit(local, value)
        sinks_by_file[unit['file']] = sinks
    return local, _cross(units, calls_by_file, sinks_by_file, issues), issues


def length_candidates(path: Path, *, root: Path | None = None) -> list[dict]:
    path = Path(path).absolute()
    root = Path(root).absolute() if root else path.parent
    if not path.is_relative_to(root):
        raise ValueError('source file escapes root')
    _, units, _, errors, recheck = load_units(root, [path.relative_to(root).as_posix()])
    if errors:
        raise ValueError('semantic source input failed: ' + errors[0]['error_type'])
    candidates, _, _ = _analyze(units)
    recheck()
    return candidates


def cross_function_length_candidates(root: Path, relative_files: list[str]) -> list[dict]:
    _, units, _, errors, recheck = load_units(root, relative_files)
    if errors:
        raise ValueError('semantic source input failed: ' + errors[0]['error_type'])
    _, candidates, _ = _analyze(units)
    recheck()
    return candidates


def candidates_to_audit_result(candidates: list[dict], *, root: Path,
                               source_snapshot_sha256: str | None = None) -> dict:
    """Projection does not know how many files were read; coverage stays unknown."""
    root = Path(root).resolve()
    if not isinstance(candidates, list) or len(candidates) > MAX_CANDIDATES:
        raise ValueError('invalid candidate collection')
    if source_snapshot_sha256 is not None and not re.fullmatch(r'[0-9a-f]{64}', source_snapshot_sha256):
        raise ValueError('invalid source snapshot digest')
    bundles, findings = [], []
    for index, candidate in enumerate(candidates, 1):
        if not isinstance(candidate, dict) or candidate.get('status') != 'candidate':
            raise ValueError('semantic candidate must remain candidate')
        if 'sink' in candidate:
            file_name, line = candidate['source_file'], candidate['sink']['line']
        else:
            file_name, line = candidate['callee']['source_file'], candidate['callee']['sink_line']
        if relative_path(file_name) != file_name or type(line) is not int or line < 1:
            raise ValueError('invalid semantic candidate location')
        # A generic copy/format advisory cannot establish a particular CWE.
        evidence = {'semantic_candidate': candidate, 'cwe_candidate': None}
        bundle = make_bundle('static_scan', {'root': str(root), 'file': file_name, 'line': line}, evidence=evidence)
        bundles.append(bundle.to_dict())
        findings.append({'alert_id': f'AL-SEM-{index:06d}', 'source': 'wildtrace-semantic-rules',
                         'cwe_candidate': None, 'rule': candidate['kind'],
                         'description': 'Lexical length/size observations require safety and data-flow review',
                         'location': {'file': file_name, 'line': line}, 'evidence': evidence,
                         'evidence_id': bundle.evidence_id, 'status': 'candidate'})
    scan = {'root': str(root), 'files_scanned': None, 'engine': 'wildtrace-semantic', 'engine_version': VERSION,
            'coverage_scope': 'unknown_without_execution_records'}
    if source_snapshot_sha256 is not None:
        scan['source_snapshot_sha256'] = source_snapshot_sha256
    return {'schema_version': '0.3', 'scan': scan, 'findings': findings,
            'evidence_bundles': bundles, 'safety': {'local_only': True, 'no_execution': True, 'no_network': True}}


def scan_semantic_files(root, relative_files, *, source_snapshot_sha256=None):
    """Read, analyze and recheck an explicit set, retaining execution and gaps."""
    root, units, records, errors, recheck = load_units(root, relative_files)
    local, cross, issues = _analyze(units)
    result = candidates_to_audit_result(local + cross, root=root, source_snapshot_sha256=source_snapshot_sha256)
    recheck()
    status = 'completed' if not errors else 'partial' if units else 'input_error'
    result.update(status=status, input_errors=errors, file_results=records, analysis_issues=issues,
                  analysis_coverage={'status': 'partial_lexical_analysis' if issues else 'lexical_only',
                                     'compiler_semantics_verified': False, 'control_flow_verified': False,
                                     'local_candidates': len(local), 'cross_function_candidates': len(cross),
                                     'unknowns': len(issues)})
    result['scan'].update(files_requested=len(records), files_attempted=len(records), files_scanned=len(units),
                          files_failed=len(errors), files_skipped=0, coverage_scope='explicit_successful_reads')
    return result
