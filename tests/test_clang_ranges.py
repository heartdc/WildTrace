"""Typed branch/range contracts. No network, target execution or model calls."""
import copy
import unittest

from tests.test_clang_facts import fixture, analyze, literal, cast, reference, SOURCE, LAYOUT


def at(node):
    return {**node, 'range': {'begin': {'offset': SOURCE.index(b'char')}}}


def compound(*items):
    return {'kind': 'CompoundStmt', 'inner': list(items)}


def compare(op, left, right):
    return at({'kind': 'BinaryOperator', 'opcode': op,
               'type': {'qualType': 'int'}, 'inner': [left, right]})


def branch(condition, yes, no=None):
    return at({'kind': 'IfStmt', 'inner': [condition, yes] + ([] if no is None else [no])})


def local(value, key='n'):
    return at({'kind': 'VarDecl', 'id': key, 'name': key,
               'type': {'qualType': 'unsigned long'}, 'inner': [literal(value, 'unsigned long')]})


def setup(t='unsigned long'):
    tree, function, call = fixture(count=reference('n', t))
    body = function['inner'][0]
    function['inner'].insert(0, at({'kind': 'ParmVarDecl', 'id': 'n', 'name': 'n',
                                   'type': {'qualType': t}}))
    r = reference('n', t)
    r['referencedDecl']['kind'] = 'ParmVarDecl'
    return tree, body, call, r


def memory(result):
    return next(c for c in result['calls'] if c['callee']['name'] == 'memcpy')


class BranchRangeTests(unittest.TestCase):
    def test_early_return_bounds_parameter_at_call(self):
        tree, body, call, r = setup()
        body['inner'][-1:] = [branch(compare('>', r, literal(4, 'unsigned long')),
                                    {'kind': 'ReturnStmt'}), call]
        result = analyze(tree)
        arg = memory(result)['arguments'][2]
        self.assertEqual(arg['integer_range'], {'lower': 0, 'upper': 4})
        self.assertTrue(arg['range_evidence'])
        self.assertEqual(memory(result)['memory_checks'][0]['status'], 'within_known_object')
        self.assertEqual(result['findings'], [])
        self.assertFalse(result['coverage']['control_flow_proven'])

    def test_true_branch_lower_bound_yields_extent_candidate(self):
        tree, body, call, r = setup()
        body['inner'][-1] = branch(compare('>', r, literal(4, 'unsigned long')), call)
        result = analyze(tree)
        write = next(f for f in result['findings'] if f['cwe_candidate'] == 'CWE-787')
        self.assertEqual(write['evidence']['memory_check']['requested_bytes_range']['lower'], 5)
        self.assertEqual(write['status'], 'candidate')
        self.assertEqual(write['evidence']['reachability'], 'not_proven')

    def test_overlapping_range_is_not_a_definite_violation(self):
        tree, body, call, r = setup()
        body['inner'][-1] = branch(compare('<=', r, literal(8, 'unsigned long')), call)
        result = analyze(tree)
        self.assertEqual(memory(result)['memory_checks'][0]['status'], 'may_exceed_known_object')
        self.assertEqual(result['findings'], [])

    def test_later_guard_does_not_retroactively_bound_call(self):
        tree, body, call, r = setup()
        body['inner'].append(branch(compare('>', r, literal(4, 'unsigned long')), {'kind': 'ReturnStmt'}))
        check = memory(analyze(tree))['memory_checks'][0]
        self.assertEqual(check['status'], 'unknown')

    def test_bound_invalidated_by_intervening_call(self):
        tree, body, call, r = setup()
        opaque = at({'kind': 'CallExpr', 'inner': [{'kind': 'DeclRefExpr',
                    'referencedDecl': {'kind': 'FunctionDecl', 'id': 'opaque', 'name': 'opaque'}}]})
        body['inner'][-1] = branch(compare('<=', r, literal(4, 'unsigned long')), compound(opaque, call))
        self.assertEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'unknown')

    def test_bound_invalidated_by_increment(self):
        tree, body, call, r = setup()
        inc = at({'kind': 'UnaryOperator', 'opcode': '++', 'type': {'qualType': 'unsigned long'}, 'inner': [r]})
        body['inner'][-1] = branch(compare('<=', r, literal(4, 'unsigned long')), compound(inc, call))
        self.assertEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'unknown')

    def test_overwrite_replaces_guard_not_combines_with_it(self):
        tree, body, call, r = setup()
        assignment = at({'kind': 'BinaryOperator', 'opcode': '=', 'type': {'qualType': 'unsigned long'},
                         'inner': [r, literal(8, 'unsigned long')]})
        body['inner'][-1] = branch(compare('<=', r, literal(4, 'unsigned long')), compound(assignment, call))
        self.assertEqual(len(analyze(tree)['findings']), 1)

    def test_signed_nonnegative_and_upper_bound_combine(self):
        tree, body, call, r = setup('int')
        body['inner'][-1:] = [branch(compare('<', r, literal(0)), {'kind': 'ReturnStmt'}),
                              branch(compare('>', r, literal(4)), {'kind': 'ReturnStmt'}), call]
        self.assertEqual(memory(analyze(tree))['arguments'][2]['integer_range'], {'lower': 0, 'upper': 4})

    def test_signed_negative_to_unsigned_is_not_small_length(self):
        tree, body, call, r = setup('int')
        body['inner'][-1] = branch(compare('<', r, literal(0)), call)
        result = analyze(tree)
        self.assertEqual({f['cwe_candidate'] for f in result['findings']}, {'CWE-787', 'CWE-125'})
        self.assertGreater(memory(result)['arguments'][2]['integer_range']['lower'], 8)

    def test_narrowing_guard_cannot_constrain_original_variable(self):
        tree, body, call, r = setup()
        narrowed = cast(r, 'unsigned char')
        body['inner'][-1] = branch(compare('<=', narrowed, literal(4)), call)
        self.assertEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'unknown')

    def test_signed_to_unsigned_comparison_is_not_inverted_unsafely(self):
        tree, body, call, r = setup('int')
        condition = compare('>', cast(r, 'unsigned int'), literal(4, 'unsigned int'))
        body['inner'][-1] = branch(condition, call)
        self.assertEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'unknown')

    def test_boolean_and_contradictory_conditions_prune_only_infeasible_branch(self):
        tree, body, call, r = setup()
        condition = compare('&&', compare('<=', r, literal(4, 'unsigned long')),
                             compare('>=', r, literal(8, 'unsigned long')))
        body['inner'][-1] = branch(condition, call)
        self.assertEqual(analyze(tree)['calls'], [])

    def test_disjunction_uses_union_not_intersection(self):
        tree, body, call, r = setup()
        condition = compare('||', compare('<=', r, literal(4, 'unsigned long')),
                             compare('>=', r, literal(8, 'unsigned long')))
        body['inner'][-1] = branch(condition, call)
        self.assertNotEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'within_known_object')

    def test_disjunction_of_small_ranges_is_bounded(self):
        tree, body, call, r = setup()
        condition = compare('||', compare('<=', r, literal(2, 'unsigned long')),
                             compare('==', r, literal(4, 'unsigned long')))
        body['inner'][-1] = branch(condition, call)
        self.assertEqual(memory(analyze(tree))['arguments'][2]['integer_range'], {'lower': 0, 'upper': 4})

    def test_reversed_comparison_and_negation(self):
        tree, body, call, r = setup()
        condition = at({'kind': 'UnaryOperator', 'opcode': '!', 'type': {'qualType': 'int'},
                         'inner': [compare('<', literal(4, 'unsigned long'), r)]})
        body['inner'][-1] = branch(condition, call)
        self.assertEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'within_known_object')

    def test_branch_merge_uses_hull_and_does_not_choose_one_value(self):
        tree, body, call, r = setup()
        flag = reference('flag', 'int')
        def assign(value):
            return at({'kind': 'BinaryOperator', 'opcode': '=', 'type': {'qualType': 'unsigned long'},
                       'inner': [r, literal(value, 'unsigned long')]})
        body['inner'][-1:] = [branch(flag, assign(4), assign(8)), call]
        result = analyze(tree)
        self.assertEqual(memory(result)['arguments'][2]['integer_range'], {'lower': 4, 'upper': 8})
        self.assertIsNone(memory(result)['arguments'][2]['constant_integer'])
        self.assertEqual(result['findings'], [])

    def test_pure_arithmetic_transfers_guarded_range(self):
        tree, body, call, r = setup()
        expression = at({'kind': 'BinaryOperator', 'opcode': '+', 'type': {'qualType': 'unsigned long'},
                         'inner': [r, literal(1, 'unsigned long')]})
        call['inner'][-1] = expression
        body['inner'][-1] = branch(compare('<=', r, literal(3, 'unsigned long')), call)
        self.assertEqual(memory(analyze(tree))['arguments'][2]['integer_range'], {'lower': 1, 'upper': 4})

    def test_unsigned_wrap_is_not_treated_as_monotone_addition(self):
        from ohvul.clang_ranges import coerce_interval
        self.assertEqual(coerce_interval((250, 260), 'unsigned char', LAYOUT), (0, 255))
        self.assertEqual(coerce_interval((256, 260), 'unsigned char', LAYOUT), (0, 4))

    def test_signed_overflow_range_is_unknown(self):
        from ohvul.clang_ranges import coerce_interval
        self.assertIsNone(coerce_interval((2**31-2, 2**31+2), 'int', LAYOUT))

    def test_type_range_alone_does_not_claim_checked_safety(self):
        tree, _, _, _ = setup()
        self.assertEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'unknown')

    def test_guard_evidence_has_no_process_local_ids(self):
        tree, body, call, r = setup()
        body['inner'][-1] = branch(compare('<=', r, literal(4, 'unsigned long')), call)
        other = copy.deepcopy(tree)
        def replace(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == 'id': value[key] = item + '-other-process'
                    else: replace(item)
            elif isinstance(value, list):
                for item in value: replace(item)
        replace(other)
        self.assertEqual(analyze(tree), analyze(other))

    def test_unrelated_guard_is_not_evidence_for_length(self):
        tree, body, call, r = setup()
        body['inner'][-1] = branch(compare('<=', reference('other', 'unsigned long'),
                                         literal(4, 'unsigned long')), call)
        self.assertEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'unknown')

    def test_assignment_clamp_joins_with_false_branch_bound(self):
        tree, body, call, r = setup()
        assignment = at({'kind': 'BinaryOperator', 'opcode': '=', 'type': {'qualType': 'unsigned long'},
                         'inner': [r, literal(4, 'unsigned long')]})
        body['inner'][-1:] = [branch(compare('>', r, literal(4, 'unsigned long')), assignment), call]
        self.assertEqual(memory(analyze(tree))['arguments'][2]['integer_range'], {'lower': 0, 'upper': 4})

    def test_equality_guard_can_produce_exact_parameter(self):
        tree, body, call, r = setup()
        body['inner'][-1:] = [branch(compare('!=', r, literal(4, 'unsigned long')), {'kind': 'ReturnStmt'}), call]
        self.assertEqual(memory(analyze(tree))['arguments'][2]['constant_integer'], 4)

    def test_guard_with_nested_side_effect_does_not_certify_size(self):
        tree, body, call, r = setup()
        side_effect = at({'kind': 'CallExpr', 'inner': [{'kind': 'DeclRefExpr',
                          'referencedDecl': {'kind': 'FunctionDecl', 'id': 'opaque', 'name': 'opaque'}}]})
        body['inner'][-1] = branch(compare('&&', compare('<=', r, literal(4, 'unsigned long')), side_effect), call)
        self.assertEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'unknown')

    def test_unsigned_conversion_encloses_every_small_domain_value(self):
        from ohvul.clang_ranges import coerce_interval
        for low in range(-270, 271, 31):
            for width in (0, 1, 4, 100, 255, 256, 300):
                bounds = coerce_interval((low, low + width), 'unsigned char', LAYOUT)
                self.assertTrue(all(bounds[0] <= n % 256 <= bounds[1]
                                    for n in range(low, low + width + 1)))

    def test_constant_guard_operand_retains_assignment_origin(self):
        tree, body, call, r = setup()
        body['inner'][-1:] = [local(4, 'limit'),
            branch(compare('>', r, reference('limit', 'unsigned long')), {'kind': 'ReturnStmt'}), call]
        arg = memory(analyze(tree))['arguments'][2]
        self.assertEqual(arg['integer_range'], {'lower': 0, 'upper': 4})
        self.assertTrue(any(x.get('symbol') == 'limit' and x.get('value') == 4 for x in arg['range_evidence']))

    def test_potential_signed_arithmetic_overflow_does_not_get_a_range(self):
        from ohvul.clang_ranges import interval
        expr = {'kind': 'BinaryOperator', 'opcode': '+', 'type': {'qualType': 'int'},
                'inner': [reference('n', 'int'), literal(1)]}
        bindings = {'n': {'lower': 0, 'upper': 2**31-1, 'evidence': []}}
        self.assertIsNone(interval(expr, LAYOUT, bindings))

    def test_parameter_guard_does_not_leak_across_unsupported_loop(self):
        tree, body, call, r = setup()
        body['inner'][-1:] = [branch(compare('>', r, literal(4, 'unsigned long')), {'kind': 'ReturnStmt'}),
            {'kind': 'WhileStmt', 'inner': [r, compound(call)]}]
        self.assertEqual(memory(analyze(tree))['memory_checks'][0]['status'], 'unknown')

    def test_arithmetic_intervals_enclose_exhaustive_small_inputs(self):
        from ohvul.clang_ranges import interval
        for op in ('+', '-', '*'):
            for lo, hi in ((0, 4), (-3, 2), (3, 8)):
                expr = {'kind': 'BinaryOperator', 'opcode': op, 'type': {'qualType': 'int'},
                        'inner': [reference('n', 'int'), literal(3)]}
                result = interval(expr, LAYOUT, {'n': {'lower': lo, 'upper': hi, 'evidence': []}})
                expected = [n+3 if op == '+' else n-3 if op == '-' else n*3 for n in range(lo, hi+1)]
                self.assertTrue(all(result[0] <= n <= result[1] for n in expected))


if __name__ == '__main__':
    unittest.main()
