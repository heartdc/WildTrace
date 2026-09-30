"""Bounded lexical inputs and balanced arguments; never a compiler or CFG.

All offsets refer to the same decoded source bytes. Unsupported signatures and
argument syntax stay explicit instead of being guessed. No target execution.
"""
from bisect import bisect_right
import hashlib
from pathlib import Path
import re
import stat

from .source_scope import is_link, local_input_path, relative_paths
from .source_structure import MAX_SOURCE_BYTES, source_structure

MAX_FILES = 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_CALLS = 200000
EXTENSIONS = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.inl'}
IDENT = re.compile(r'[A-Za-z_]\w*', re.ASCII)


def read_source(path):
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('semantic input is not a regular file')
    with path.open('rb') as stream:
        raw = stream.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError('semantic source byte budget exceeded')
    return raw


def load_units(root, relative_files):
    root = Path(root).absolute()
    names = sorted(relative_paths(relative_files, nonempty=True))
    if len(names) > MAX_FILES:
        raise ValueError('semantic file budget exceeded')
    if any(Path(name).suffix.lower() not in EXTENSIONS or
           '.git' in [p.casefold() for p in Path(name).parts] for name in names):
        raise ValueError('unsupported semantic source path')
    if any(is_link(p) for p in (root, *root.parents)) or not root.is_dir():
        raise ValueError('semantic source root must be existing and unlinked')
    root = root.resolve()
    paths = [local_input_path(root, name) for name in names]
    units, records, errors = [], [], []
    total = 0
    for name, path in zip(names, paths):
        record = {'engine': 'wildtrace-semantic', 'file': name, 'source_file': str(path)}
        try:
            raw = read_source(path)
            total += len(raw)
            if total > MAX_TOTAL_BYTES:
                raise ValueError('total semantic byte budget exceeded')
            text = raw.decode('utf-8-sig')
            structure = source_structure(text)
        except (OSError, ValueError) as exc:
            if total > MAX_TOTAL_BYTES:
                raise ValueError('total semantic byte budget exceeded') from None
            error = {**record, 'status': 'input_error', 'error_type': type(exc).__name__,
                     'reason': str(exc)[:512]}
            errors.append(error)
            records.append(error)
            continue
        unit = {'file': name, 'path': path, 'root': root, 'raw': raw, 'text': text,
                'sha256': hashlib.sha256(raw).hexdigest(), 'structure': structure,
                'code': structure['code'], 'lines': text.splitlines(),
                'starts': structure['line_starts']}
        units.append(unit)
        records.append({**record, 'status': 'completed', 'file_sha256': unit['sha256'], 'bytes': len(raw)})

    def recheck():
        for unit in units:
            path = local_input_path(root, unit['file'])
            if path != unit['path'] or read_source(path) != unit['raw']:
                raise ValueError('semantic input changed during analysis')
    return root, units, records, errors, recheck


def line_at(unit, offset):
    return bisect_right(unit['starts'], offset)


def owner_at(unit, offset):
    functions = unit['structure']['functions']
    starts = unit.get('body_starts')
    if starts is None:
        starts = unit['body_starts'] = [f['body_offset'] for f in functions]
    index = bisect_right(starts, offset) - 1
    return functions[index] if index >= 0 and offset < functions[index]['end_offset'] else None


def arguments(unit, opening, end):
    """Split only top-level commas, preserving exact string and nested offsets."""
    code, text = unit['code'], unit['text']
    if opening >= end or code[opening] != '(':
        raise ValueError('missing opening parenthesis')
    stack, begin, result = ['('], opening + 1, []
    closing = {')': '(', ']': '[', '}': '{'}

    def append(stop):
        raw = text[begin:stop]
        if not raw.strip() and not result:
            return
        if not raw.strip() or len(result) >= 64:
            raise ValueError('empty or excessive argument list')
        result.append({'text': raw.strip(), 'code': code[begin:stop].strip(),
                       'start': begin, 'end': stop})

    for pos in range(opening + 1, end):
        char = code[pos]
        if char in '([{':
            stack.append(char)
        elif char in ')]}':
            if not stack or stack.pop() != closing[char]:
                raise ValueError('unbalanced argument delimiters')
            if not stack:
                append(pos)
                # Template argument commas cannot be resolved by this lexer.
                if re.search(r'\b[A-Za-z_]\w*(?:::\w+)*\s*<', code[opening + 1:pos], re.ASCII):
                    raise ValueError('template or comparison arguments need compiler parsing')
                return result, pos + 1
        elif char == ',' and len(stack) == 1:
            append(pos)
            begin = pos + 1
    raise ValueError('unterminated argument list')


def parsed_calls(unit):
    result = []
    for raw in unit['structure']['calls']:
        if len(result) >= MAX_CALLS:
            raise ValueError('semantic call budget exceeded')
        call = dict(raw)
        scope = owner_at(unit, call['offset'])
        call['scope'] = scope
        prefix_end = call['offset']
        while prefix_end and unit['code'][prefix_end - 1].isspace():
            prefix_end -= 1
        call['member'] = unit['code'][max(0, prefix_end - 2):prefix_end].endswith(('.', '->'))
        boundary = max(unit['code'].rfind(mark, 0, call['offset']) for mark in ';{}') + 1
        prefix = unit['code'][boundary:call['offset']].strip()
        call['declaration'] = bool(prefix and
            re.fullmatch(r'[A-Za-z_][A-Za-z_0-9:\s*&]*', prefix) and
            not re.search(r'\b(?:return|co_return|throw|new|delete|else|do|case|default)\b', prefix)
            and not re.search(r'(?<!:):(?!:)', prefix))
        opening = call['offset'] + len(call['symbol'])
        while opening < len(unit['code']) and unit['code'][opening].isspace():
            opening += 1
        try:
            call['arguments'], call['end'] = arguments(
                unit, opening, scope['end_offset'] if scope else len(unit['code']))
            call['parse_error'] = None
        except ValueError as exc:
            call.update(arguments=None, end=opening, parse_error=str(exc))
        result.append(call)
    return result


def parameters(unit, function):
    opening = function['name_offset'] + len(function['symbol'])
    while opening < function['body_offset'] and unit['code'][opening].isspace():
        opening += 1
    args, end = arguments(unit, opening, function['body_offset'])
    if len(args) == 1 and args[0]['code'] == 'void':
        return []
    names = []
    for arg in args:
        value = arg['code']
        if any(c in value for c in '=().{}'):
            raise ValueError('default, variadic or complex parameter needs compiler parsing')
        match = re.search(r'([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*$', value, re.ASCII)
        if not match or not value[:match.start()].strip():
            raise ValueError('unnamed parameter')
        names.append(match.group(1))
    if len(set(names)) != len(names):
        raise ValueError('duplicate parameter names')
    return names


def read_file_list(path):
    """Read explicit list bytes once; callers recheck them before publishing."""
    path = Path(path).absolute()
    if any(is_link(p) or p.name.casefold() == '.git' for p in (path, *path.parents)):
        raise ValueError('semantic file list must be an unlinked non-metadata file')
    raw = read_source(path)
    entries = [line.strip() for line in raw.decode('utf-8-sig').splitlines()
               if line.strip() and not line.lstrip().startswith('#')]
    names = relative_paths(entries, nonempty=True)
    if len(names) > MAX_FILES:
        raise ValueError('semantic file budget exceeded')
    return raw, names
