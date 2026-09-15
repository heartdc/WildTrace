"""Narrow lexical review filters, not a C/C++ parser or a safety proof.

Keep original offsets while masking comments/literals. Unknown dereference
contexts remain candidates. Only direct guarded returns are de-prioritized,
with an observation; no path, alias, call, or lifetime analysis is claimed.
"""
from bisect import bisect_right
import re

RULE_VERSION = '2'
_IDENT = r'[A-Za-z_]\w*'
_RAW = r'R"(?P<delimiter>[^ ()\\\t\r\n"]{0,16})\([\s\S]*?\)(?P=delimiter)"'
_COMMENT = r'//(?:\\(?:\r\n|\r|\n)|[^\r\n])*|/\*[\s\S]*?(?:\*/|\Z)'
_STRING = r'"(?:\\[\s\S]|[^"\\])*"'
_CHAR = r"(?<![A-Za-z0-9_])'(?:\\[^\r\n]|[^'\\\r\n])+'"
_NONCODE = re.compile('|'.join((_RAW, _COMMENT, _STRING, _CHAR)))
_TOKEN = re.compile(_IDENT + r'|\d[\w.]*|->|&&|\|\||==|!=|<=|>=|\+\+|--|\+=|-=|\*=|/=|\S')
_UNARY_PREFIX = {'(', '[', '{', ';', ',', '=', '?', ':', '!', '~', '+', '-',
                 '/', '%', '&', '|', '^', '<', '>', '==', '!=', '<=', '>=',
                 '&&', '||', '+=', '-=', '*=', '/=', '++', '--',
                 'return', 'throw', 'co_return', 'else', 'do', ')'}
_BUILTIN_TYPES = {'void', 'char', 'short', 'int', 'long', 'float', 'double',
                  'bool', '_Bool', 'signed', 'unsigned', 'const', 'volatile'}
_TERNARY = re.compile(r'\breturn\s+(?P<p>' + _IDENT + r')\s*\?\s*'
                      r'(?P<use>\*\s*(?P=p))\s*:\s*(?:0|[1-9][0-9]*|NULL|nullptr)\s*;')
_IF_RETURN = re.compile(r'\bif\s*\(\s*(?P<p>' + _IDENT + r')\s*'
                        r'(?:!=\s*(?:0|NULL|nullptr)\s*)?\)\s*'
                        r'return\s+(?P<use>\*\s*(?P=p))\s*;')


def mask_noncode(text):
    """Return same-length text and actual line-comment spans."""
    comments = []

    def replace(match):
        value = match.group()
        if value.startswith('//'):
            comments.append((match.start(), value))
        return ''.join(c if c in '\r\n' else ' ' for c in value)

    return _NONCODE.sub(replace, text), comments


def review_syntax(text):
    masked, comments = mask_noncode(text)
    starts = [0]
    for line in text.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))

    def position(offset):
        line = bisect_right(starts, offset)
        return line, offset - starts[line - 1] + 1

    ignored = set()
    for offset, comment in comments:
        if re.search(r'\bohvul:ignore\b', comment):
            ignored.add(position(offset)[0])

    guards = {}
    # Volatile reads, atomics, and macro/conditional contexts are deliberately
    # left unknown. Even recognized guards are observations, not safe verdicts.
    unsupported = (re.search(r'\b(?:volatile|_Atomic|atomic)\b', masked)
                   or re.search(r'(?m)^\s*#\s*(?:define|if|ifdef|ifndef|elif)\b', masked))
    if not unsupported:
        for pattern in (_TERNARY, _IF_RETURN):
            for match in pattern.finditer(masked):
                guards[match.start('use')] = match.group('p')

    tokens = list(_TOKEN.finditer(masked))
    candidates, observations = {}, []
    for index, token in enumerate(tokens):
        symbol = token.group()
        if symbol not in ('*', '->'):
            continue
        line, column = position(token.start())
        if line in ignored:
            continue
        pointer_use = symbol == '->'
        if symbol == '*':
            previous = tokens[index - 1].group() if index else None
            if previous == '*':
                first = index - 1
                while first and tokens[first - 1].group() == '*':
                    first -= 1
                before = tokens[first - 1].group() if first else None
                # Known builtin multi-pointer declarations are not uses. For
                # ambiguous user-defined types / multiplication keep a candidate.
                pointer_use = before not in _BUILTIN_TYPES
            else:
                pointer_use = previous is None or previous in _UNARY_PREFIX
            following = tokens[index + 1].group() if index + 1 < len(tokens) else ''
            if not (re.fullmatch(_IDENT, following) or following in ('(', '*')):
                pointer_use = False
        decision = None
        if not pointer_use:
            decision = 'non_dereference_syntax'
        elif token.start() in guards:
            decision = 'same_expression_guard'
        if decision:
            observations.append({'line': line, 'column': column, 'decision': decision,
                                 'pointer': guards.get(token.start())})
        else:
            candidates.setdefault(line, []).append(column)
    for line in sorted(ignored):
        observations.append({'line': line, 'column': 1, 'decision': 'explicit_line_suppression',
                             'pointer': None})
    return {'masked_lines': masked.splitlines(), 'pointer_candidates': candidates,
            'observations': observations, 'ignored_lines': ignored}
