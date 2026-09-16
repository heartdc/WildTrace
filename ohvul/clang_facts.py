"""Compiler-derived main-file facts and narrow, object-size memory checks.

This is NOT a control-flow, reachability, alias, lifetime or exploitability proof.
Only compiler-recognized memory builtins with explicit array objects and known
constant or bounded local scalar lengths receive a numeric check.
Raw Clang process-local declaration IDs are never used as persistent identities.
"""
from __future__ import annotations

from bisect import bisect_right
import hashlib
import json
from pathlib import PurePosixPath
import re

# Main-file C++ analysis includes standard/dependency declarations needed to
# resolve calls. Camera translation units exceed 32 MiB after indentation
# removal; retain a finite 64 MiB serialized budget and the independent node cap.
MAX_AST_BYTES = 64 * 1024 * 1024
MAX_NODES = 400000
MAX_DEPTH = 300
MEMORY_APIS = {'memcpy', 'memmove', 'memset', '__builtin_memcpy',
              '__builtin_memmove', '__builtin_memset'}
FUNCTIONS = {'FunctionDecl', 'CXXMethodDecl', 'CXXConstructorDecl', 'CXXDestructorDecl'}
WRAPPERS = {'ParenExpr', 'ImplicitCastExpr', 'CStyleCastExpr', 'CXXStaticCastExpr',
            'CXXReinterpretCastExpr', 'ExprWithCleanups', 'ConstantExpr'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def children(node):
    return node.get('inner', [])


def typed(node):
    t = node.get('type', {})
    return t.get('desugaredQualType', t.get('qualType', 'unknown'))


def nodes(tree):
    stack, count = [(tree, 0)], 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if not isinstance(node, dict) or depth > MAX_DEPTH or count > MAX_NODES:
            raise ValueError('AST node/depth budget or schema violation')
        inner = children(node)
        if not isinstance(inner, list):
            raise ValueError('invalid AST children')
        yield node
        stack.extend((item, depth + 1) for item in reversed(inner))


def layout_from_macros(raw):
    """Read the selected compiler's observed default target layout, not host Python."""
    names = {'char': '__CHAR_BIT__', 'short': '__SIZEOF_SHORT__', 'int': '__SIZEOF_INT__',
             'long': '__SIZEOF_LONG__', 'long long': '__SIZEOF_LONG_LONG__',
             'pointer': '__SIZEOF_POINTER__', 'float': '__SIZEOF_FLOAT__',
             'double': '__SIZEOF_DOUBLE__'}
    found = dict(re.findall(r'^#define (\w+) ([0-9]+)$', raw, re.M))
    if found.get('__CHAR_BIT__') != '8' or any(n not in found for n in names.values()):
        raise ValueError('unsupported or missing target layout')
    value = {k: int(found[v]) for k, v in names.items()}
    value['char'] = 1
    value['bool'] = 1
    value['char_unsigned'] = '__CHAR_UNSIGNED__' in found
    if any(type(v) is int and not 1 <= v <= 32 for v in value.values()):
        raise ValueError('invalid target type sizes')
    return value


def _plain(t):
    return ' '.join(re.sub(r'\b(const|volatile|restrict|__restrict|__restrict__)\b', '', t).split())


def size_of(t, layout):
    t = _plain(t)
    dims = re.findall(r'\[([0-9]+)\]', t)
    if '[' in t:
        base = re.sub(r'\[[0-9]+\]', '', t).strip()
        if not dims or '[' in base:
            return None
        size = size_of(base, layout)
        for count in dims:
            if size is None or int(count) > 2**40:
                return None
            size *= int(count)
        return size if size is not None and size <= 2**63 else None
    if '*' in t or t.endswith('&'):
        return layout.get('pointer')
    t = re.sub(r'\b(unsigned|signed)\b', '', t).strip() or 'int'
    t = {'short int': 'short', 'long int': 'long', 'long long int': 'long long', '_Bool': 'bool'}.get(t, t)
    return layout.get(t)


def _integer_type(t, layout):
    t = _plain(t)
    if not re.fullmatch(r'(?:(?:unsigned|signed) )?(?:char|short(?: int)?|int|long(?: long)?(?: int)?|bool|_Bool)|unsigned|signed', t):
        return None
    size = size_of(t, layout)
    if size is None:
        return None
    unsigned = t.startswith('unsigned') or (t == 'char' and layout.get('char_unsigned', False))
    return size * 8, unsigned, t in ('bool', '_Bool')


def _coerce(value, t, layout):
    info = _integer_type(t, layout)
    if value is None or info is None:
        return None
    bits, unsigned, boolean = info
    if boolean:
        return int(value != 0)
    if unsigned:
        return value % (1 << bits)
    return value if -(1 << (bits-1)) <= value < (1 << (bits-1)) else None


def integer(node, layout, depth=0, *, values=None):
    """Pure integer evaluation; optional values come only from explicit local flow."""
    if depth > 64:
        return None
    kind, inner = node.get('kind'), children(node)
    value = None
    if kind == 'DeclRefExpr' and values is not None:
        value = values.get(node.get('referencedDecl', {}).get('id'))
    elif kind in ('IntegerLiteral', 'CharacterLiteral', 'ConstantExpr') and 'value' in node:
        try:
            value = int(node['value'])
        except (TypeError, ValueError):
            return None
    elif kind == 'CXXBoolLiteralExpr':
        value = int(node.get('value') is True)
    elif kind == 'UnaryExprOrTypeTraitExpr' and node.get('name') == 'sizeof':
        arg = node.get('argType')
        t = (arg.get('desugaredQualType', arg.get('qualType', '')) if arg
             else typed(inner[0]) if len(inner) == 1 else '')
        value = size_of(t, layout)
    elif kind in WRAPPERS and len(inner) == 1:
        value = integer(inner[0], layout, depth+1, values=values)
    elif kind == 'UnaryOperator' and len(inner) == 1:
        a = integer(inner[0], layout, depth+1, values=values)
        if a is not None:
            value = {'+': lambda: a, '-': lambda: -a, '~': lambda: ~a, '!': lambda: int(not a)}.get(node.get('opcode'), lambda: None)()
    elif kind == 'BinaryOperator' and len(inner) == 2:
        a, b = (integer(x, layout, depth+1, values=values) for x in inner)
        if a is not None and b is not None:
            op = node.get('opcode')
            if op in ('+', '-', '*', '&', '|', '^', '==', '!=', '<', '<=', '>', '>='):
                value = {'+': lambda: a+b, '-': lambda: a-b, '*': lambda: a*b,
                         '&': lambda: a&b, '|': lambda: a|b, '^': lambda: a^b,
                         '==': lambda: int(a==b), '!=': lambda: int(a!=b),
                         '<': lambda: int(a<b), '<=': lambda: int(a<=b),
                         '>': lambda: int(a>b), '>=': lambda: int(a>=b)}[op]()
    return _coerce(value, typed(node), layout)


def _unwrap(node):
    while node.get('kind') in WRAPPERS and len(children(node)) == 1:
        node = children(node)[0]
    return node


def _object(node, declarations, layout, depth=0, *, values=None):
    if depth > 64:
        return None
    kind, inner = node.get('kind'), children(node)
    if kind in WRAPPERS and len(inner) == 1:
        # Only representation-preserving pointer casts are eligible. Integer-to-
        # pointer conversions, pointer aliases and scalar variables are unknown.
        if 'Cast' in kind and node.get('castKind') not in ('NoOp', 'BitCast', 'ArrayToPointerDecay'):
            return None
        return _object(inner[0], declarations, layout, depth+1, values=values)
    if kind == 'DeclRefExpr':
        decl = declarations.get(node.get('referencedDecl', {}).get('id'))
        if not decl or decl.get('kind') != 'VarDecl' or '[' not in typed(decl):
            return None
        size = size_of(typed(decl), layout)
        if size is None:
            return None
        return {'name': decl.get('name'), 'type': typed(decl), 'capacity_bytes': size,
                'offset_bytes': 0, 'basis': 'compiler_fixed_array_type'}
    if kind == 'StringLiteral':
        size = size_of(typed(node), layout)
        return None if size is None else {'name': '<string-literal>', 'type': typed(node),
                    'capacity_bytes': size, 'offset_bytes': 0, 'basis': 'compiler_string_array_type'}
    if kind == 'UnaryOperator' and node.get('opcode') == '&' and len(inner) == 1:
        sub = _unwrap(inner[0])
        if sub.get('kind') == 'ArraySubscriptExpr' and len(children(sub)) == 2:
            base, index = children(sub)
            result = _object(base, declarations, layout, depth+1, values=values)
            amount, step = integer(index, layout, values=values), size_of(typed(sub), layout)
            if result is not None and amount is not None and step is not None:
                return {**result, 'offset_bytes': result['offset_bytes'] + amount*step}
            return None
        return _object(sub, declarations, layout, depth+1, values=values)
    if kind == 'BinaryOperator' and node.get('opcode') in ('+', '-') and len(inner) == 2:
        base, number = inner
        if '*' not in typed(base) and node.get('opcode') == '+':
            base, number = number, base
        t = _plain(typed(base))
        if not t.endswith('*'):
            return None
        step, amount = size_of(t[:-1].strip(), layout), integer(number, layout, values=values)
        result = _object(base, declarations, layout, depth+1, values=values)
        if result is not None and amount is not None and step is not None:
            sign = -1 if node.get('opcode') == '-' else 1
            return {**result, 'offset_bytes': result['offset_bytes'] + sign*amount*step}
    return None


def extract_compiler_facts(ast, source_bytes, *, source_file, compiler_file, layout):
    if not isinstance(ast, dict) or ast.get('kind') != 'TranslationUnitDecl':
        raise ValueError('a complete Clang translation unit is required')
    if not isinstance(source_bytes, bytes) or len(source_bytes) > 2*1024*1024:
        raise ValueError('source byte budget exceeded')
    source_bytes.decode('utf-8-sig')
    if not isinstance(source_file, str) or PurePosixPath(source_file).is_absolute() or '..' in PurePosixPath(source_file).parts:
        raise ValueError('canonical relative source file required')
    all_nodes = list(nodes(ast))
    declarations = {n['id']: n for n in all_nodes if 'id' in n and n.get('kind', '').endswith('Decl')}
    # A namesake in another namespace must not suppress the standard function.
    # Conversely, a user definition in the SAME redeclaration chain must disable
    # builtin assumptions even if a prior declaration carried BuiltinAttr.
    parent = {key: key for key in declarations}
    def canonical(key):
        trail = []
        while key in parent and parent[key] != key:
            trail.append(key)
            key = parent[key]
            if len(trail) > len(parent):
                raise ValueError('cyclic declaration identity')
        for old in trail: parent[old] = key
        return key
    for n in all_nodes:
        if n.get('kind') in FUNCTIONS and n.get('previousDecl') and n.get('id'):
            parent[canonical(n['id'])] = canonical(n['previousDecl'])
    defined = {canonical(n.get('id')) for n in all_nodes if n.get('kind') in FUNCTIONS
               and any(c.get('kind') == 'CompoundStmt' for c in children(n))}
    starts = [0] + [m.end() for m in re.finditer(b'\n', source_bytes)]
    def location(node):
        raw = node.get('range', {}).get('begin', node.get('loc', {}))
        macro = 'expansionLoc' in raw
        pos = raw.get('expansionLoc', raw)
        off = pos.get('offset')
        if ('includedFrom' in pos or pos.get('file', compiler_file) != compiler_file
                or type(off) is not int or not 0 <= off < len(source_bytes)):
            return None
        line = bisect_right(starts, off)
        return {'file': source_file, 'line': line, 'column': off-starts[line-1]+1,
                'byte_offset': off, 'macro_expansion': macro}
    functions, calls, findings, issues = [], [], [], []
    seen = set()
    for function in all_nodes:
        if function.get('kind') not in FUNCTIONS:
            continue
        bodies = [c for c in children(function) if c.get('kind') == 'CompoundStmt']
        loc = function.get('loc', {})
        offset, name = loc.get('offset'), function.get('name', '')
        if (not bodies or 'includedFrom' in loc or 'spellingLoc' in loc
                or loc.get('file', compiler_file) != compiler_file):
            continue
        if (type(offset) is not int or not name or not 0 <= offset < len(source_bytes)
                or source_bytes[offset:offset+len(name.encode())] != name.encode()):
            issues.append({'kind': 'main_file_definition_location_unresolved'})
            continue
        where = location(function)
        if where is None:
            issues.append({'kind': 'main_file_definition_range_unresolved'})
            continue
        identity = (offset, typed(function))
        if identity in seen:
            continue
        seen.add(identity)
        info = {'name': name, 'type': typed(function), 'location': where,
                'parameters': [{'name': p.get('name'), 'type': typed(p)}
                               for p in children(function) if p.get('kind') == 'ParmVarDecl']}
        functions.append(info)
        local_decls = {n['id']: n for n in nodes(bodies[0]) if n.get('kind') == 'VarDecl' and 'id' in n}
        from .clang_flow import scalar_events
        events, flow_issues = scalar_events(bodies[0], layout, location)
        issues.extend({'kind': code, 'function': name} for code in flow_issues)
        for n, values, flow_evidence in events:
            kind, inner = n.get('kind'), children(n)
            where = location(n)
            if where is None or not inner:
                issues.append({'kind': 'call_location_unresolved', 'function': name})
                continue
            ref = _unwrap(inner[0]).get('referencedDecl', {})
            decl = declarations.get(ref.get('id'), {})
            direct = kind == 'CallExpr' and ref.get('kind') == 'FunctionDecl'
            target = ref.get('name') if direct else None
            args = [{'type': typed(a), 'constant_integer': integer(a, layout, values=values),
                     'object': _object(a, local_decls, layout, values=values)} for a in inner[1:]]
            flow = {'mode': ('constant_only_fallback' if 'local_scalar_flow_disabled_unstructured_control' in flow_issues
                             else 'bounded_exact_local_values'), 'evidence': flow_evidence,
                    'general_ranges_proven': False, 'callee_effects_summarized': False}
            call = {'function': name, 'function_type': typed(function), 'location': where,
                    'callee': {'name': target, 'type': ref.get('type', {}).get('qualType'),
                               'mangled_name': decl.get('mangledName'),
                               'resolution': 'compiler_direct_declaration' if direct else 'unresolved_or_indirect'},
                    'arguments': args, 'memory_checks': [], 'scalar_flow': flow, 'reachability': 'not_proven'}
            builtin = target in MEMORY_APIS and canonical(ref.get('id')) not in defined and any(
                a.get('kind') == 'BuiltinAttr' for a in children(decl))
            if builtin and len(args) == 3:
                count = args[2]['constant_integer']
                for side, index, cwe in [('write', 0, 'CWE-787')] + ([] if target.endswith('memset') else [('read', 1, 'CWE-125')]):
                    obj = args[index]['object']
                    check = {'side': side, 'requested_bytes': count, 'object': obj, 'status': 'unknown'}
                    if count is not None and obj is not None:
                        remaining = max(0, obj['capacity_bytes'] - obj['offset_bytes'])
                        exceeds = count > 0 and (obj['offset_bytes'] < 0 or count > remaining)
                        check.update(available_bytes=remaining, status='exceeds_known_object' if exceeds else 'within_known_object')
                        if exceeds:
                            findings.append({'source': 'wildtrace-clang-ast', 'rule': 'compiler.constant-buffer-' + side,
                                'cwe_candidate': cwe, 'cwe_mapping_source': 'typed_object_size_rule',
                                'cwe_mapping_version': '1', 'location': {'file': source_file, 'line': where['line']},
                                'description': f'{target}: {count} bytes {side} exceeds the known array region if this call executes',
                                'evidence': {'file_sha256': hashlib.sha256(source_bytes).hexdigest(),
                                             'function': info, 'call_location': where, 'callee_type': call['callee'],
                                             'memory_check': dict(check), 'rule_version': '2', 'scalar_flow': flow,
                                             'reachability': 'not_proven', 'platform_impact': 'not_verified'},
                                'status': 'candidate'})
                    call['memory_checks'].append(check)
            elif target in MEMORY_APIS:
                call['memory_semantics'] = 'unrecognized_or_overridden_builtin'
            calls.append(call)
    value = {'schema': 'clang-main-file-facts-0.1', 'analysis_version': '2', 'source_file': source_file,
             'source_sha256': hashlib.sha256(source_bytes).hexdigest(), 'target_layout': layout,
             'functions': functions, 'calls': calls, 'findings': findings, 'issues': issues,
             'coverage': {'scope': 'main_file_function_bodies', 'compiler_ast': True,
                          'control_flow_proven': False, 'interprocedural_analysis': False,
                          'dynamic_lengths_proven': False, 'exact_local_scalar_flow': True,
                          'macro_configuration': 'selected_compiler_configuration'},
             'limitations': ['An in-bounds observation is not a general safety verdict.',
                             'Only direct builtins with fixed objects and constant or exact local scalar lengths are checked.',
                             'Unknown branch values, side effects and loop-carried values are not guessed.',
                             'Pointer variables, heap objects, members and general dynamic ranges remain unknown.',
                             'Call reachability, effective guards, lifetime and security impact are not established.',
                             'Header function bodies and unresolved source locations are outside main-file coverage.']}
    value['statistics'] = {'functions': len(functions), 'calls': len(calls),
        'resolved_direct_calls': sum(c['callee']['resolution']=='compiler_direct_declaration' for c in calls),
        'indirect_or_unresolved_calls': sum(c['callee']['resolution']!='compiler_direct_declaration' for c in calls),
        'numeric_memory_checks': sum(z['status']!='unknown' for c in calls for z in c['memory_checks']),
        'unknown_memory_checks': sum(z['status']=='unknown' for c in calls for z in c['memory_checks']),
        'calls_with_local_scalar_evidence': sum(bool(c['scalar_flow']['evidence']) for c in calls)}
    value['facts_sha256'] = digest(value)
    return value
