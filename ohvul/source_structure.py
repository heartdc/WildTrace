"""Bounded C/C++ lexical ranges for navigation, NOT an AST or call graph.

Preprocessor branches are not evaluated. Unknown headers and unmatched braces
are not repaired. All returned associations are lexical navigation candidates.
"""
from bisect import bisect_right
import re

from .detect.lexical import mask_noncode

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TOKENS = 300000
_IDENT = re.compile(r'[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*', re.ASCII)
_TOKENS = re.compile(r'[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*|\S', re.ASCII)
_NON_FUNCTIONS = {'if', 'for', 'while', 'switch', 'catch', 'sizeof', 'alignof',
                  'decltype', 'noexcept', 'static_assert', '__attribute__', '__declspec'}


def source_structure(text):
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_SOURCE_BYTES:
        raise ValueError('source text exceeds lexical input budget')
    lexical, _ = mask_noncode(text)
    lines = lexical.splitlines(keepends=True)
    original_lines = text.splitlines(keepends=True)
    starts, offset = [], 0
    for line in lines:
        starts.append(offset)
        offset += len(line)
    def line_at(pos):
        return bisect_right(starts, pos)
    directives, macros = [], []
    index = 0
    while index < len(lines):
        if not re.match(r'^\s*#', lines[index]):
            index += 1
            continue
        first = index
        while original_lines[index].rstrip('\r\n').endswith('\\') and index + 1 < len(lines):
            index += 1
        start = starts[first]
        end = starts[index] + len(lines[index])
        directives.append((start, end))
        match = re.match(r'^\s*#\s*define\s+([A-Za-z_]\w*)', lexical[start:end], re.ASCII)
        if match:
            macros.append({'kind': 'lexical_macro_definition', 'symbol': match.group(1),
                           'start_line': first + 1, 'end_line': index + 1,
                           'start_offset': start, 'end_offset': end})
        index += 1
    chars = list(lexical)
    for start, end in directives:
        chars[start:end] = [c if c in '\r\n' else ' ' for c in lexical[start:end]]
    code = ''.join(chars)
    tokens = []
    for token in _TOKENS.finditer(code):
        if len(tokens) >= MAX_TOKENS:
            raise ValueError('source token budget exceeded')
        tokens.append(token)
    pairs, stack, issues = {}, [], []
    for i, token in enumerate(tokens):
        symbol = token.group()
        if symbol in ('(', '{'):
            stack.append((symbol, i))
        elif symbol in (')', '}'):
            expected = '(' if symbol == ')' else '{'
            if stack and stack[-1][0] == expected:
                _, begin = stack.pop()
                pairs[begin] = i
                pairs[i] = begin
            else:
                issues.append('unmatched_delimiter')
                stack.clear()
    if stack:
        issues.append('unmatched_delimiter')
    functions, signatures, boundary = [], set(), -1
    for i, token in enumerate(tokens):
        symbol = token.group()
        if symbol != '{':
            if symbol in (';', '}'):
                boundary = i
            continue
        previous_boundary = boundary
        boundary = i
        if i not in pairs or (functions and token.start() < functions[-1]['end_offset']):
            continue
        previous = i - 1
        while previous >= 0 and tokens[previous].group() in ('const', 'noexcept', 'override', 'final'):
            previous -= 1
        if previous < 0 or tokens[previous].group() != ')' or previous not in pairs:
            continue
        opening = pairs[previous]
        name_index = opening - 1
        if name_index < 0:
            continue
        name = tokens[name_index].group()
        if not _IDENT.fullmatch(name) or name in _NON_FUNCTIONS:
            continue
        # A simple return-type prefix or qualified constructor name is required.
        # Bare MACRO(args) { ... } stays unresolved rather than becoming a function.
        begin = previous_boundary + 1
        if begin >= name_index and '::' not in name:
            continue
        close = pairs[i]
        functions.append({'kind': 'lexical_function_definition', 'symbol': name,
                          'start_line': line_at(tokens[begin].start()),
                          'name_line': line_at(tokens[name_index].start()),
                          'end_line': line_at(tokens[close].start()),
                          'start_offset': tokens[begin].start(), 'name_offset': tokens[name_index].start(),
                          'body_offset': token.start(), 'end_offset': tokens[close].end()})
        signatures.update(range(begin, i + 1))
    if issues:
        # Conditional/malformed brace layouts cannot establish a unique owner.
        # Keep bounded macro ranges, but do not attach calls to guessed functions.
        functions = []
    body_starts = [f['body_offset'] for f in functions]
    def owner(pos):
        slot = bisect_right(body_starts, pos) - 1
        return functions[slot]['symbol'] if slot >= 0 and pos < functions[slot]['end_offset'] else None
    calls = []
    for i, token in enumerate(tokens[:-1]):
        name = token.group()
        if (i not in signatures and _IDENT.fullmatch(name) and name not in _NON_FUNCTIONS
                and tokens[i + 1].group() == '('):
            calls.append({'symbol': name, 'line': line_at(token.start()),
                          'offset': token.start(), 'function': owner(token.start())})
    return {'functions': functions, 'macros': macros, 'calls': calls,
            'code': code, 'lexical_text': lexical, 'line_starts': starts,
            'issues': sorted(set(issues)), 'has_preprocessor': bool(directives),
            'semantics': 'lexical_navigation_not_cfg_or_callgraph'}


def function_at(structure, offset):
    for function in structure['functions']:
        if function['body_offset'] <= offset < function['end_offset']:
            return function['symbol']
    return None
