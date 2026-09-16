"""Small typed AST fixtures; real-compiler validation is run separately."""
import copy
import unittest

from ohvul.clang_facts import extract_compiler_facts, integer, size_of, layout_from_macros, nodes

LAYOUT = {'char': 1, 'short': 2, 'int': 4, 'long': 8, 'long long': 8,
          'pointer': 8, 'float': 4, 'double': 8, 'bool': 1, 'char_unsigned': False}
SOURCE = b'void sample(void) {\n char a[4], b[8];\n memcpy(a,b,8);\n}\n'


def literal(value, t='int'):
    return {'kind': 'IntegerLiteral', 'type': {'qualType': t}, 'value': str(value)}


def cast(node, t, kind='IntegralCast'):
    return {'kind': 'ImplicitCastExpr', 'type': {'qualType': t}, 'castKind': kind, 'inner': [node]}


def reference(name, t):
    return {'kind': 'DeclRefExpr', 'type': {'qualType': t},
            'referencedDecl': {'id': name, 'kind': 'VarDecl', 'name': name, 'type': {'qualType': t}}}


def array(name, t):
    element = t.split('[')[0]
    return cast(cast(reference(name, t), element + ' *', 'ArrayToPointerDecay'), 'void *', 'BitCast')


def fixture(a='char[4]', b='char[8]', count=None, target='memcpy'):
    call = {'kind': 'CallExpr', 'range': {'begin': {'offset': SOURCE.index(b'memcpy')}},
            'type': {'qualType': 'void *'}, 'inner': [
                {'kind': 'DeclRefExpr', 'referencedDecl': {'id': 'lib', 'kind': 'FunctionDecl',
                     'name': target, 'type': {'qualType': 'void *(void *, const void *, unsigned long)'}}},
                array('a', a), array('b', b), cast(literal(8) if count is None else count, 'unsigned long')]}
    function = {'kind': 'FunctionDecl', 'id': 'fn', 'name': 'sample',
                'loc': {'file': '/source/a.c', 'offset': 5},
                'range': {'begin': {'offset': 0}}, 'type': {'qualType': 'void (void)'},
                'inner': [{'kind': 'CompoundStmt', 'inner': [
                    {'kind': 'VarDecl', 'id': 'a', 'name': 'a', 'type': {'qualType': a}},
                    {'kind': 'VarDecl', 'id': 'b', 'name': 'b', 'type': {'qualType': b}}, call]}]}
    tree = {'kind': 'TranslationUnitDecl', 'inner': [
        {'kind': 'FunctionDecl', 'id': 'lib', 'name': target, 'inner': [{'kind': 'BuiltinAttr'}]}, function]}
    return tree, function, call


def analyze(tree, source=SOURCE):
    return extract_compiler_facts(tree, source, source_file='a.c', compiler_file='/source/a.c', layout=LAYOUT)


class CompilerFactsTests(unittest.TestCase):
    def test_write_extent_is_numeric_and_candidate_only(self):
        value = analyze(fixture()[0])
        self.assertEqual([f['cwe_candidate'] for f in value['findings']], ['CWE-787'])
        check = value['findings'][0]['evidence']['memory_check']
        self.assertEqual((check['requested_bytes'], check['available_bytes']), (8, 4))
        self.assertEqual(value['findings'][0]['status'], 'candidate')
        self.assertFalse(value['coverage']['control_flow_proven'])

    def test_safe_counterpart_has_observations_not_safe_verdict(self):
        value = analyze(fixture(count=literal(4))[0])
        self.assertEqual(value['findings'], [])
        self.assertEqual([c['status'] for c in value['calls'][0]['memory_checks']], ['within_known_object']*2)
        self.assertEqual(value['calls'][0]['reachability'], 'not_proven')

    def test_read_and_write_are_separate(self):
        value = analyze(fixture(a='char[8]', b='char[4]')[0])
        self.assertEqual([f['cwe_candidate'] for f in value['findings']], ['CWE-125'])
        both = analyze(fixture(a='char[2]', b='char[2]')[0])
        self.assertEqual({f['cwe_candidate'] for f in both['findings']}, {'CWE-787', 'CWE-125'})

    def test_memset_does_not_treat_fill_integer_as_source_buffer(self):
        tree, _, call = fixture(target='memset')
        call['inner'][2] = literal(0)
        result = analyze(tree)
        self.assertEqual(len(result['calls'][0]['memory_checks']), 1)

    def test_integer_array_capacity_uses_target_layout(self):
        result = analyze(fixture(a='int[4]', count=literal(8))[0])
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['calls'][0]['arguments'][0]['object']['capacity_bytes'], 16)

    def test_pointer_offset_uses_pointed_to_element_size(self):
        tree, _, call = fixture(a='int[4]', count=literal(8))
        pointer = cast(reference('a', 'int[4]'), 'int *', 'ArrayToPointerDecay')
        call['inner'][1] = cast({'kind': 'BinaryOperator', 'opcode': '+', 'type': {'qualType': 'int *'},
                                'inner': [pointer, literal(3)]}, 'void *', 'BitCast')
        check = analyze(tree)['findings'][0]['evidence']['memory_check']
        self.assertEqual(check['available_bytes'], 4)
        self.assertEqual(check['object']['offset_bytes'], 12)

    def test_byte_cast_changes_pointer_step_not_whole_object_size(self):
        tree, _, call = fixture(a='int[4]', count=literal(8))
        pointer = cast(array('a', 'int[4]'), 'char *', 'BitCast')
        call['inner'][1] = {'kind': 'BinaryOperator', 'opcode': '+', 'type': {'qualType': 'char *'},
                            'inner': [pointer, literal(3)]}
        self.assertEqual(analyze(tree)['findings'], [])

    def test_address_of_subscript_uses_remaining_object(self):
        tree, _, call = fixture(a='char[8]', count=literal(4))
        call['inner'][1] = {'kind': 'UnaryOperator', 'opcode': '&', 'type': {'qualType': 'char *'},
            'inner': [{'kind': 'ArraySubscriptExpr', 'type': {'qualType': 'char'},
                       'inner': [array('a','char[8]'), literal(6)]}]}
        self.assertEqual(analyze(tree)['findings'][0]['evidence']['memory_check']['available_bytes'], 2)

    def test_negative_offset_positive_length_is_not_in_bounds(self):
        tree, _, call = fixture(count=literal(1))
        call['inner'][1] = {'kind': 'BinaryOperator', 'opcode': '-', 'type': {'qualType': 'char *'},
                            'inner': [cast(reference('a','char[4]'),'char *','ArrayToPointerDecay'),literal(1)]}
        self.assertEqual(len(analyze(tree)['findings']), 1)

    def test_sizeof_array_and_sizeof_pointer_differ(self):
        sized = {'kind': 'UnaryExprOrTypeTraitExpr', 'name': 'sizeof', 'type': {'qualType': 'unsigned long'},
                 'inner': [reference('a','char[4]')]}
        self.assertEqual(analyze(fixture(count=sized)[0])['findings'], [])
        sized['inner'] = [reference('p','char *')]
        self.assertEqual(len(analyze(fixture(count=sized)[0])['findings']), 1)

    def test_pointer_to_array_size_is_pointer_size(self):
        # Reproduced against real Clang 22.1.8: 'char (*p)[4]' has sizeof ==
        # sizeof(void*) == 8. Treating the [4] as an outer array dimension
        # yielded 32 and two false overflow candidates against char[16] buffers.
        thirty_two_bit = {**LAYOUT, 'pointer': 4}
        self.assertEqual(size_of('char (*)[4]', LAYOUT), 8)
        self.assertEqual(size_of('char (*)[4]', thirty_two_bit), 4)
        self.assertEqual(size_of('char const (* restrict)[4]', LAYOUT), 8)
        self.assertEqual(size_of('void (*)(int)', LAYOUT), 8)
        self.assertEqual(size_of('char (*)[4][8]', LAYOUT), 8)
        self.assertEqual(size_of('char *[4]', LAYOUT), 32)
        self.assertEqual(size_of('char *[4]', thirty_two_bit), 16)
        self.assertIsNone(size_of('char (*[4])[8]', LAYOUT))
        self.assertIsNone(size_of('int (&)[4]', LAYOUT))

    def test_sizeof_pointer_to_array_does_not_flag_fixed_buffers(self):
        sized = {'kind': 'UnaryExprOrTypeTraitExpr', 'name': 'sizeof',
                 'type': {'qualType': 'unsigned long'},
                 'inner': [reference('p', 'char (*)[4]')]}
        value = analyze(fixture(a='char[16]', b='char[16]', count=sized)[0])
        self.assertEqual(value['findings'], [])
        self.assertEqual([c['status'] for c in value['calls'][0]['memory_checks']],
                         ['within_known_object'] * 2)

    def test_pointer_to_array_variable_is_not_a_fixed_object(self):
        tree, _, call = fixture(a='char[16]', b='char[16]', count=literal(8))
        call['inner'][2] = cast(reference('p', 'char (*)[4]'), 'void *', 'BitCast')
        value = analyze(tree)
        self.assertIsNone(value['calls'][0]['arguments'][1]['object'])
        self.assertEqual([c['status'] for c in value['calls'][0]['memory_checks']],
                         ['within_known_object', 'unknown'])
        self.assertEqual(value['findings'], [])

    def test_sizeof_pointer_array_still_flags_both_sides(self):
        sized = {'kind': 'UnaryExprOrTypeTraitExpr', 'name': 'sizeof',
                 'type': {'qualType': 'unsigned long'},
                 'inner': [reference('q', 'char *[4]')]}
        value = analyze(fixture(a='char[16]', b='char[16]', count=sized)[0])
        self.assertEqual({f['cwe_candidate'] for f in value['findings']}, {'CWE-787', 'CWE-125'})

    # --- lifecycle (deleter-sequence) rule ---------------------------------

    def life_call(self, source, marker, fn_id, fn_name, fn_type, args):
        return {'kind': 'CallExpr', 'range': {'begin': {'offset': source.index(marker)}},
                'type': {'qualType': 'void'}, 'inner': [
                    {'kind': 'DeclRefExpr', 'referencedDecl': {'id': fn_id, 'kind': 'FunctionDecl',
                        'name': fn_name, 'type': {'qualType': fn_type}}}, *args]}

    def life_tree(self, source, name, params, body, ftype):
        params = params if isinstance(params, list) else [params]
        return {'kind': 'TranslationUnitDecl', 'inner': [
            {'kind': 'FunctionDecl', 'id': 'fn', 'name': name,
             'loc': {'file': '/source/a.c', 'offset': source.index(name.encode())},
             'range': {'begin': {'offset': 0}}, 'type': {'qualType': ftype},
             'inner': [*params, {'kind': 'CompoundStmt', 'inner': body}]}]}

    def test_delete_then_same_type_handle_flags_aliased_use(self):
        source = (b'typedef struct cJSON cJSON;\n'
                  b'void merge(cJSON *target, cJSON *patch) {\n'
                  b'    cJSON_Delete(target);\n'
                  b'    cJSON_Duplicate(patch, 1);\n'
                  b'}\n')
        params = [{'kind': 'ParmVarDecl', 'id': 'target', 'name': 'target', 'type': {'qualType': 'cJSON *'}},
                  {'kind': 'ParmVarDecl', 'id': 'patch', 'name': 'patch', 'type': {'qualType': 'cJSON *'}}]
        delete = self.life_call(source, b'cJSON_Delete', 'del', 'cJSON_Delete', 'void (cJSON *)',
                                [cast(reference('target', 'cJSON *'), 'void *', 'BitCast')])
        use = self.life_call(source, b'cJSON_Duplicate', 'dup', 'cJSON_Duplicate',
                             'cJSON *(const cJSON *, int)',
                             [cast(reference('patch', 'cJSON *'), 'const cJSON *'), literal(1)])
        value = analyze(self.life_tree(source, 'merge', params, [delete, use],
                                       'void (cJSON *, cJSON *)'), source=source)
        self.assertEqual([f['rule'] for f in value['findings']],
                         ['compiler.lifetime-aliased-handle-use'])
        self.assertEqual(value['findings'][0]['cwe_candidate'], 'CWE-416')
        check = value['findings'][0]['evidence']['lifetime_check']
        self.assertFalse(check['alias_proven'])
        self.assertEqual((check['deleted_handle'], check['used_handle']), ('target', 'patch'))
        self.assertEqual(value['statistics']['lifetime_sequence_candidates'], 1)
        self.assertEqual(value['calls'][1]['lifetime_checks'][0]['rule'],
                         'compiler.lifetime-aliased-handle-use')

    def test_same_handle_after_delete_and_fixed_ordering(self):
        source = (b'typedef struct obj obj;\n'
                  b'void use(obj *handle) {\n'
                  b'    free(handle);\n'
                  b'    sink(handle);\n'
                  b'}\n')
        params = {'kind': 'ParmVarDecl', 'id': 'handle', 'name': 'handle', 'type': {'qualType': 'obj *'}}
        free = self.life_call(source, b'free', 'fr', 'free', 'void (void *)',
                              [cast(reference('handle', 'obj *'), 'void *', 'BitCast')])
        sink = self.life_call(source, b'sink', 'sk', 'sink', 'void (obj *)',
                              [reference('handle', 'obj *')])
        value = analyze(self.life_tree(source, 'use', params, [free, sink],
                                       'void (obj *)'), source=source)
        self.assertEqual([f['rule'] for f in value['findings']],
                         ['compiler.lifetime-use-after-delete'])
        self.assertTrue(value['findings'][0]['evidence']['lifetime_check']['alias_proven'])
        # Using the handle BEFORE the delete is the reviewed safe ordering.
        safe = analyze(self.life_tree(source, 'use', params, [sink, free],
                                      'void (obj *)'), source=source)
        self.assertEqual(safe['findings'], [])

    def test_reassignment_and_fresh_allocation_between_suppress(self):
        source = (b'typedef struct cJSON cJSON;\n'
                  b'void merge(cJSON *target, cJSON *patch) {\n'
                  b'    cJSON_Delete(target);\n'
                  b'    patch = other;\n'
                  b'    cJSON_Duplicate(patch, 1);\n'
                  b'}\n')
        params = [{'kind': 'ParmVarDecl', 'id': 'target', 'name': 'target', 'type': {'qualType': 'cJSON *'}},
                  {'kind': 'ParmVarDecl', 'id': 'patch', 'name': 'patch', 'type': {'qualType': 'cJSON *'}}]
        delete = self.life_call(source, b'cJSON_Delete', 'del', 'cJSON_Delete', 'void (cJSON *)',
                                [cast(reference('target', 'cJSON *'), 'void *', 'BitCast')])
        assign = {'kind': 'BinaryOperator', 'opcode': '=', 'type': {'qualType': 'cJSON *'},
                  'range': {'begin': {'offset': source.index(b'patch = other')}},
                  'inner': [reference('patch', 'cJSON *'), reference('other', 'cJSON *')]}
        use = self.life_call(source, b'cJSON_Duplicate', 'dup', 'cJSON_Duplicate',
                             'cJSON *(const cJSON *, int)',
                             [cast(reference('patch', 'cJSON *'), 'const cJSON *'), literal(1)])
        value = analyze(self.life_tree(source, 'merge', params, [delete, assign, use],
                                       'void (cJSON *, cJSON *)'), source=source)
        self.assertEqual(value['findings'], [])
        # A fresh local allocation cannot alias any pre-existing handle.
        fresh = {'kind': 'VarDecl', 'id': 'kept', 'name': 'kept', 'type': {'qualType': 'cJSON *'},
                 'inner': [{'kind': 'CallExpr', 'inner': [
                     {'kind': 'DeclRefExpr', 'referencedDecl': {'id': 'mal', 'kind': 'FunctionDecl',
                         'name': 'malloc', 'type': {'qualType': 'void *(unsigned long)'}}}, literal(16)]}]}
        use_kept = self.life_call(source, b'cJSON_Duplicate', 'dup', 'cJSON_Duplicate',
                                  'cJSON *(const cJSON *, int)',
                                  [cast(reference('kept', 'cJSON *'), 'const cJSON *'), literal(1)])
        value = analyze(self.life_tree(source, 'merge', params, [delete, fresh, use_kept],
                                       'void (cJSON *, cJSON *)'), source=source)
        self.assertEqual(value['findings'], [])

    def test_different_pointee_and_user_defined_deleter_ignored(self):
        source = (b'typedef struct obj obj;\n'
                  b'typedef struct other other;\n'
                  b'void mixed(obj *dropped, other *kept) {\n'
                  b'    free(dropped);\n'
                  b'    use_other(kept);\n'
                  b'}\n')
        params = [{'kind': 'ParmVarDecl', 'id': 'dropped', 'name': 'dropped', 'type': {'qualType': 'obj *'}},
                  {'kind': 'ParmVarDecl', 'id': 'kept', 'name': 'kept', 'type': {'qualType': 'other *'}}]
        delete = self.life_call(source, b'free', 'fr', 'free', 'void (void *)',
                                [cast(reference('dropped', 'obj *'), 'void *', 'BitCast')])
        use = self.life_call(source, b'use_other', 'uo', 'use_other', 'void (other *)',
                             [reference('kept', 'other *')])
        value = analyze(self.life_tree(source, 'mixed', params, [delete, use],
                                       'void (obj *, other *)'), source=source)
        self.assertEqual(value['findings'], [])
        # A same-chain user definition of the deleter disables the assumption.
        tree = self.life_tree(source, 'mixed', params, [delete, use], 'void (obj *, other *)')
        tree['inner'].append({'kind': 'FunctionDecl', 'id': 'other_free', 'previousDecl': 'fr',
                              'name': 'free', 'inner': [{'kind': 'CompoundStmt'}]})
        value = analyze(tree, source=source)
        self.assertEqual(value['findings'], [])

    def test_unsigned_narrowing_and_negative_size_conversion(self):
        self.assertEqual(integer(cast(literal(300), 'unsigned char'), LAYOUT), 44)
        negative = {'kind': 'UnaryOperator', 'opcode': '-', 'type': {'qualType': 'int'}, 'inner': [literal(1)]}
        self.assertEqual(integer(cast(negative,'unsigned long'),LAYOUT), 2**64-1)
        self.assertEqual(len(analyze(fixture(count=negative)[0])['findings']), 2)

    def test_signed_overflow_remains_unknown(self):
        expression = {'kind': 'BinaryOperator', 'opcode': '+', 'type': {'qualType': 'int'},
                      'inner': [literal(2**31-1), literal(1)]}
        self.assertIsNone(integer(expression, LAYOUT))
        self.assertEqual(analyze(fixture(count=expression)[0])['findings'], [])

    def test_dynamic_length_is_not_evaluated_from_variable_initializer(self):
        value = analyze(fixture(count=reference('n', 'unsigned long'))[0])
        self.assertEqual(value['findings'], [])
        self.assertTrue(all(c['status']=='unknown' for c in value['calls'][0]['memory_checks']))

    def test_pointer_variable_and_heap_size_not_guessed(self):
        value = analyze(fixture(a='char *', count=literal(4))[0])
        self.assertIsNone(value['calls'][0]['arguments'][0]['object'])
        self.assertEqual(value['findings'], [])

    def test_parameter_array_is_not_treated_as_inline_array(self):
        tree, fn, _ = fixture()
        fn['inner'][0]['inner'][0]['kind'] = 'ParmVarDecl'
        self.assertEqual(analyze(tree)['findings'], [])

    def test_unrecognized_or_overridden_builtin_not_name_matched(self):
        tree, _, _ = fixture()
        tree['inner'][0]['inner'] = []
        self.assertEqual(analyze(tree)['findings'], [])
        tree['inner'][0]['inner'] = [{'kind': 'BuiltinAttr'}, {'kind': 'CompoundStmt'}]
        self.assertEqual(analyze(tree)['findings'], [])

    def test_indirect_and_member_calls_not_bound_to_free_builtin(self):
        for kind in ('CXXMemberCallExpr', 'CXXOperatorCallExpr'):
            tree, _, call = fixture()
            call['kind'] = kind
            self.assertEqual(analyze(tree)['findings'], [])
        tree, _, call = fixture()
        call['inner'][0]['referencedDecl']['kind'] = 'VarDecl'
        self.assertEqual(analyze(tree)['calls'][0]['callee']['resolution'], 'unresolved_or_indirect')

    def test_unrelated_namespace_namesake_does_not_hide_builtin(self):
        tree, _, _ = fixture()
        tree['inner'].append({'kind':'FunctionDecl','id':'other','name':'memcpy',
                              'inner':[{'kind':'CompoundStmt'}]})
        self.assertEqual(len(analyze(tree)['findings']),1)

    def test_same_redeclaration_chain_definition_disables_builtin(self):
        tree, _, _ = fixture()
        tree['inner'].append({'kind':'FunctionDecl','id':'other','previousDecl':'lib','name':'memcpy',
                              'inner':[{'kind':'CompoundStmt'}]})
        self.assertEqual(analyze(tree)['findings'],[])

    def test_unevaluated_expressions_are_not_executed_calls(self):
        tree, fn, call = fixture()
        fn['inner'][0]['inner'][-1] = {'kind': 'UnaryExprOrTypeTraitExpr', 'name': 'sizeof', 'inner': [call]}
        self.assertEqual(analyze(tree)['calls'], [])

    def test_constant_false_branch_does_not_create_candidate(self):
        tree, fn, call = fixture()
        fn['inner'][0]['inner'][-1] = {'kind': 'IfStmt', 'inner': [literal(0), call]}
        self.assertEqual(analyze(tree)['findings'], [])
        fn['inner'][0]['inner'][-1]['inner'][0] = literal(1)
        self.assertEqual(len(analyze(tree)['findings']), 1)

    def test_constant_short_circuit_does_not_visit_right_operand(self):
        for opcode,left in (('&&',0),('||',1)):
            tree,fn,call=fixture()
            fn['inner'][0]['inner'][-1]={'kind':'BinaryOperator','opcode':opcode,
                                        'type':{'qualType':'int'},'inner':[literal(left),call]}
            self.assertEqual(analyze(tree)['findings'],[])

    def test_constant_ternary_and_while_skip_unexecuted_branch(self):
        for node in ('ConditionalOperator','WhileStmt'):
            tree,fn,call=fixture()
            children=[literal(0),call]+([literal(0)] if node=='ConditionalOperator' else [])
            fn['inner'][0]['inner'][-1]={'kind':node,'inner':children}
            self.assertEqual(analyze(tree)['findings'],[])

    def test_header_definition_not_attributed_to_main_file(self):
        tree, fn, _ = fixture()
        fn['loc']['includedFrom'] = {'file': '/source/a.c'}
        self.assertEqual(analyze(tree)['functions'], [])

    def test_macro_expansion_location_is_explicit(self):
        tree, _, call = fixture()
        call['range']['begin'] = {'spellingLoc': {'file': '/source/macro.h', 'offset': 0},
                                 'expansionLoc': {'file': '/source/a.c', 'offset': SOURCE.index(b'memcpy')}}
        self.assertTrue(analyze(tree)['calls'][0]['location']['macro_expansion'])

    def test_malformed_ast_and_resource_contract(self):
        for ast in ({}, {'kind': 'FunctionDecl'}, {'kind': 'TranslationUnitDecl', 'inner': 'bad'}):
            with self.assertRaises(ValueError):
                analyze(ast)
        with self.assertRaises(ValueError):
            list(nodes({'inner': [None]}))

    def test_unknown_types_do_not_inherit_host_sizes(self):
        self.assertIsNone(size_of('Record[4]', LAYOUT))
        self.assertIsNone(size_of('char[n]', LAYOUT))
        self.assertEqual(size_of('unsigned short[4]', LAYOUT), 8)
        with self.assertRaises(ValueError):
            layout_from_macros('#define __CHAR_BIT__ 16\n')

    def test_normalized_output_omits_process_local_ast_ids(self):
        tree, _, _ = fixture()
        changed = copy.deepcopy(tree)
        def replace(n):
            if isinstance(n, dict):
                for key, value in n.items():
                    if key == 'id': n[key] = value+'-new-process'
                    else: replace(value)
            elif isinstance(n, list):
                for item in n: replace(item)
        replace(changed)
        self.assertEqual(analyze(tree), analyze(changed))


if __name__ == '__main__':
    unittest.main()
