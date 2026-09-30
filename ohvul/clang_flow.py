"""Bounded integer transfer and branch constraints in a Clang AST.

No relational solver, alias analysis, interprocedural summaries or CFG proof.
Unknown effects kill facts instead of reusing an initializer indefinitely.
Declaration IDs are used only in memory; persisted evidence uses source ranges.
"""
import re

MAX_FLOW_NODES = 100000
MAX_FLOW_DEPTH = 128
MAX_BINDINGS = 4096
MAX_ORIGINS = 64
CALLS = {'CallExpr', 'CXXMemberCallExpr', 'CXXOperatorCallExpr'}
UNEVALUATED = {'UnaryExprOrTypeTraitExpr', 'CXXNoexceptExpr', 'LambdaExpr'}
UNSTRUCTURED = {'GotoStmt', 'IndirectGotoStmt', 'LabelStmt', 'SwitchStmt',
                'CXXTryStmt', 'GCCAsmStmt', 'MSAsmStmt', 'CoroutineBodyStmt', 'CleanupAttr'}


def scalar_events(body, layout, location, *, parameters=(), include_ranges=False):
    # Runtime import avoids a module cycle: integer() itself never invokes flow.
    from .clang_facts import children, nodes, typed, integer, size_of, _integer_type, _coerce, FUNCTIONS
    from .clang_ranges import interval, type_interval, coerce_interval, exact_values, comparison_reference

    all_nodes = list(nodes(body))
    variable_array = any((n.get('kind') == 'VarDecl' and '[' in typed(n) and size_of(typed(n), layout) is None)
                         or (n.get('kind') == 'UnaryExprOrTypeTraitExpr' and
                             '[' in n.get('argType', {}).get('qualType', '') and
                             size_of(n['argType']['qualType'], layout) is None) for n in all_nodes)
    disabled = variable_array or any(n.get('kind') in UNSTRUCTURED for n in all_nodes)
    declarations = {n['id']: n for n in all_nodes if n.get('kind') == 'VarDecl' and 'id' in n}
    declarations.update({n['id']: n for n in parameters if n.get('kind') == 'ParmVarDecl' and 'id' in n})
    eligible = {key for key, n in declarations.items()
                if n.get('storageClass') not in ('static', 'extern') and not n.get('tls')
                and not re.search(r'\b(?:volatile|_Atomic|atomic)\b', typed(n))
                and _integer_type(typed(n), layout) is not None}
    if len(eligible) > MAX_BINDINGS:
        raise ValueError('local scalar binding budget')
    events, visited = [], 0
    issue_codes = set()
    if disabled:
        issue_codes.add('local_scalar_flow_disabled_unstructured_control')
    if variable_array:
        issue_codes.add('variable_array_evaluation_not_summarized')

    def vals(env):
        return exact_values(env)

    def binding(bounds, evidence):
        return {'lower': bounds[0], 'upper': bounds[1],
                'value': bounds[0] if bounds[0] == bounds[1] else None, 'evidence': evidence}

    def value(node, env):
        return integer(node, layout, values=vals(env))

    def origins(node, env):
        result = []
        for n in nodes(node):
            if n.get('kind') == 'DeclRefExpr':
                binding = env.get(n.get('referencedDecl', {}).get('id'))
                for ref in binding['evidence'] if binding else []:
                    if ref not in result:
                        result.append(ref)
        return result

    def merge(left, right):
        if left is None:
            return right
        if right is None:
            return left
        out = {}
        for key in left.keys() & right.keys():
            refs = left[key]['evidence'] + [x for x in right[key]['evidence'] if x not in left[key]['evidence']]
            if len(refs) <= MAX_ORIGINS:
                out[key] = binding((min(left[key]['lower'], right[key]['lower']),
                                    max(left[key]['upper'], right[key]['upper'])), refs)
        return out

    def set_value(env, key, expr, point):
        found = coerce_interval(interval(expr, layout, env), typed(declarations.get(key, {})), layout)
        refs = origins(expr, env)
        env.pop(key, None)
        where = location(point)
        if disabled or key not in eligible or found is None or where is None:
            return
        ref = {'symbol': declarations[key].get('name'), 'type': typed(declarations[key]),
               'location': where, 'basis': 'compiler_local_scalar_assignment'}
        ref.update({'value': found[0]} if found[0] == found[1] else
                   {'range': {'lower': found[0], 'upper': found[1]}})
        if ref not in refs:
            refs.append(ref)
        if len(refs) <= MAX_ORIGINS:
            env[key] = binding(found, refs)

    def assume(node, truth, env, budget=None):
        if env is None or disabled:
            return env
        budget = [128] if budget is None else budget
        budget[0] -= 1
        if budget[0] < 0:
            issue_codes.add('integer_condition_refinement_budget')
            return env
        known = interval(node, layout, env)
        if known == (0, 0):
            return env if not truth else None
        if known is not None and (known[0] > 0 or known[1] < 0):
            return env if truth else None
        kind, inner = node.get('kind'), children(node)
        if kind == 'ParenExpr' and len(inner) == 1:
            return assume(inner[0], truth, env, budget)
        if kind == 'UnaryOperator' and node.get('opcode') == '!' and len(inner) == 1:
            return assume(inner[0], not truth, env, budget)
        op = node.get('opcode')
        if kind == 'BinaryOperator' and op in ('&&', '||') and len(inner) == 2:
            sequential = (op == '&&' and truth) or (op == '||' and not truth)
            if sequential:
                return assume(inner[1], truth, assume(inner[0], truth, env, budget), budget)
            first = assume(inner[0], truth, env, budget)
            second = assume(inner[1], truth, assume(inner[0], not truth, env, budget), budget)
            return merge(first, second)
        if kind != 'BinaryOperator' or op not in ('<', '<=', '>', '>=', '==', '!=') or len(inner) != 2:
            return env
        bound_expr = inner[1]
        key, bound = comparison_reference(inner[0], layout), value(bound_expr, env)
        if key is None or bound is None:
            bound_expr = inner[0]
            key, bound = comparison_reference(inner[1], layout), value(bound_expr, env)
            op = {'<': '>', '<=': '>=', '>': '<', '>=': '<=', '==': '==', '!=': '!='}[op]
        if key not in eligible or bound is None:
            issue_codes.add('integer_guard_relation_unresolved')
            return env
        old = env.get(key)
        domain = type_interval(typed(declarations[key]), layout)
        low, high = (old['lower'], old['upper']) if old else domain
        effective = op if truth else {'<': '>=', '<=': '>', '>': '<=', '>=': '<', '==': '!=', '!=': '=='}[op]
        if effective == '<': high = min(high, bound - 1)
        elif effective == '<=': high = min(high, bound)
        elif effective == '>': low = max(low, bound + 1)
        elif effective == '>=': low = max(low, bound)
        elif effective == '==': low, high = max(low, bound), min(high, bound)
        elif low == bound: low += 1
        elif high == bound: high -= 1
        if low > high:
            return None
        where = location(node)
        if where is None:
            issue_codes.add('integer_guard_location_unresolved')
            return env
        refs = list(old['evidence']) if old else []
        refs.extend(ref for ref in origins(bound_expr, env) if ref not in refs)
        ref = {'basis': 'compiler_integer_branch_constraint', 'symbol': declarations[key].get('name'),
               'type': typed(declarations[key]), 'location': where, 'assumed_branch': truth,
               'comparison': op, 'boundary': bound, 'range': {'lower': low, 'upper': high}}
        if ref not in refs:
            refs.append(ref)
        if len(refs) > MAX_ORIGINS:
            issue_codes.add('integer_guard_evidence_budget')
            return env
        result = dict(env)
        result[key] = binding((low, high), refs)
        return result

    def has_effect(node):
        kind = node.get('kind', '')
        if kind in UNEVALUATED or kind in FUNCTIONS:
            return False
        if (kind in CALLS or kind in ('CXXNewExpr', 'CXXDeleteExpr', 'CXXConstructExpr',
                                      'CXXTemporaryObjectExpr', 'CompoundAssignOperator', 'AtomicExpr')
                or kind == 'BinaryOperator' and node.get('opcode') == '='
                or kind == 'UnaryOperator' and node.get('opcode') in ('++', '--', '&')):
            return True
        return any(has_effect(x) for x in children(node))

    def visit(node, env, depth=0):
        nonlocal visited
        visited += 1
        if visited > MAX_FLOW_NODES or depth > MAX_FLOW_DEPTH:
            raise ValueError('local scalar flow node/depth budget')
        kind, inner = node.get('kind', ''), children(node)
        if kind in UNEVALUATED or kind in FUNCTIONS:
            # Captures and escaping closures are not summarized here.
            if kind == 'LambdaExpr':
                env = {}
            return env
        if kind in ('CompoundStmt', 'DeclStmt'):
            for child in inner:
                env = visit(child, env, depth+1)
                if env is None:
                    break
            if env is not None and kind == 'CompoundStmt' and any(
                    n.get('kind') in ('CXXConstructExpr', 'CXXTemporaryObjectExpr') or
                    (n.get('kind') == 'VarDecl' and '*' not in typed(n) and '&' not in typed(n)
                     and size_of(typed(n), layout) is None) for n in nodes(node)):
                issue_codes.add('scope_cleanup_not_summarized')
                return {}
            return env
        if kind == 'VarDecl':
            key = node.get('id')
            initial = [x for x in inner if not x.get('kind', '').endswith('Attr')]
            if len(initial) == 1 and not has_effect(initial[0]):
                set_value(env, key, initial[0], node)
                return env
            for child in initial:
                env = visit(child, env, depth+1)
                if env is None:
                    return None
            env.pop(key, None)
            return env
        if kind == 'BinaryOperator' and node.get('opcode') == '=' and len(inner) == 2:
            key = inner[0].get('referencedDecl', {}).get('id') if inner[0].get('kind') == 'DeclRefExpr' else None
            if key in eligible and not has_effect(inner[1]):
                set_value(env, key, inner[1], node)
                return env
            # Unknown stores may write through an alias. Do not assume order.
            for child in inner:
                visit(child, {}, depth+1)
            return {}
        if kind in ('IfStmt', 'ConditionalOperator') and not node.get('hasInit') and not node.get('hasVar') and len(inner) in (2, 3):
            env = visit(inner[0], env, depth+1)
            if env is None:
                return None
            cond = value(inner[0], env) if not has_effect(inner[0]) else None
            if cond is not None:
                branch = inner[1] if cond else inner[2] if len(inner) == 3 else None
                return visit(branch, env, depth+1) if branch else env
            refinable = not has_effect(inner[0])
            yes = assume(inner[0], True, dict(env)) if refinable else dict(env)
            no = assume(inner[0], False, dict(env)) if refinable else dict(env)
            left = visit(inner[1], yes, depth+1) if yes is not None else None
            right = visit(inner[2], no, depth+1) if no is not None and len(inner) == 3 else no
            return merge(left, right)
        if kind in ('IfStmt', 'ConditionalOperator', 'BinaryConditionalOperator'):
            issue_codes.add('unsupported_condition_shape')
            for child in inner:
                visit(child, {}, depth+1)
            return {}
        if kind == 'BinaryOperator' and node.get('opcode') in ('&&', '||') and len(inner) == 2:
            env = visit(inner[0], env, depth+1)
            if env is None:
                return None
            cond = value(inner[0], env) if not has_effect(inner[0]) else None
            short = cond is not None and ((node['opcode'] == '&&' and cond == 0) or (node['opcode'] == '||' and cond != 0))
            if short:
                return env
            needed = node['opcode'] == '&&'
            right_env = assume(inner[0], needed, dict(env)) if not has_effect(inner[0]) else dict(env)
            right = visit(inner[1], right_env, depth+1) if right_env is not None else None
            return right if cond is not None else merge(env, right)
        if kind in ('WhileStmt', 'ForStmt', 'DoStmt', 'CXXForRangeStmt'):
            # Every iteration starts unknown; fresh body assignments remain useful.
            if kind == 'WhileStmt' and len(inner) == 2 and integer(inner[0], layout) == 0:
                return env
            issue_codes.add('loop_state_not_summarized')
            for child in inner:
                visit(child, {}, depth+1)
            return {}
        if kind in ('ReturnStmt', 'CXXThrowExpr'):
            for child in inner:
                visit(child, env, depth+1)
            return {} if disabled else None
        if kind in ('BreakStmt', 'ContinueStmt'):
            return None
        if kind in CALLS:
            # A nested call or write in any argument invalidates ordering assumptions.
            current = {} if disabled or any(has_effect(x) for x in inner) else env
            for child in inner:
                visit(child, dict(current), depth+1)
            refs = origins(node, current)
            accepted_env = current if len(refs) <= MAX_ORIGINS else {}
            event = (node, vals(accepted_env), refs if len(refs) <= MAX_ORIGINS else [])
            events.append((*event, dict(accepted_env)) if include_ranges else event)
            # Callee side effects/ref parameters/escapes are not modeled.
            return {}
        if kind in ('BinaryOperator', 'UnaryOperator', 'CompoundAssignOperator') and has_effect(node):
            for child in inner:
                visit(child, {}, depth+1)
            return {}
        if kind in UNSTRUCTURED or kind in ('CXXConstructExpr', 'CXXTemporaryObjectExpr', 'CXXNewExpr', 'CXXDeleteExpr', 'AtomicExpr'):
            issue_codes.add('unsupported_local_effect')
            for child in inner:
                visit(child, {}, depth+1)
            return {}
        if kind in ('InitListExpr', 'ParenListExpr', 'CXXParenListInitExpr') and has_effect(node):
            issue_codes.add('initializer_effect_order_unknown')
            for child in inner:
                visit(child, {}, depth+1)
            return {}
        if kind == 'ExprWithCleanups':
            for child in inner:
                visit(child, env, depth+1)
            issue_codes.add('full_expression_cleanup_not_summarized')
            return {}
        for child in inner:
            env = visit(child, env, depth+1)
            if env is None:
                return None
        return env

    initial = {key: binding(type_interval(typed(n), layout), []) for key, n in declarations.items()
               if not disabled and key in eligible and n.get('kind') == 'ParmVarDecl'}
    visit(body, initial)
    return events, sorted(issue_codes)
