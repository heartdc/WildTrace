"""Exact local scalar flow is evidence, not general symbolic execution."""
import copy
import unittest
from tests.test_clang_facts import fixture, analyze, literal, reference, cast, SOURCE


def var(value=8, name='n', kind='unsigned long', **extra):
    return {'kind': 'VarDecl', 'id': name, 'name': name,
            'type': {'qualType': kind}, 'loc': {'offset': SOURCE.index(b'char')},
            'init': 'c', 'inner': [cast(literal(value), kind)], **extra}


def assign(value, name='n'):
    return {'kind': 'BinaryOperator', 'opcode': '=', 'type': {'qualType': 'unsigned long'},
            'range': {'begin': {'offset': SOURCE.index(b'char')}},
            'inner': [reference(name, 'unsigned long'), literal(value)]}


def block(*items):
    return {'kind': 'CompoundStmt', 'inner': list(items)}


def unknown_call(arg=None):
    return {'kind': 'CallExpr', 'range': {'begin': {'offset': SOURCE.index(b'memcpy')}},
            'inner': [{'kind': 'DeclRefExpr', 'referencedDecl': {
                'kind': 'FunctionDecl', 'id': 'external', 'name': 'modify'}}] + ([arg] if arg else [])}


class ScalarFlowTests(unittest.TestCase):
    def setup_tree(self, *before, count=None):
        tree, fn, call = fixture(count=reference('n', 'unsigned long') if count is None else count)
        fn['inner'][0]['inner'][-1:-1] = list(before)
        return tree, fn, call

    def memory_call(self, value):
        return next(c for c in value['calls'] if c['callee']['name'] == 'memcpy')

    def test_initialized_local_has_numeric_size_and_origin(self):
        value = analyze(self.setup_tree(var())[0])
        self.assertEqual(len(value['findings']), 1)
        call = self.memory_call(value)
        self.assertEqual(call['arguments'][2]['constant_integer'], 8)
        self.assertEqual(call['scalar_flow']['mode'], 'bounded_exact_local_values')
        self.assertTrue(call['scalar_flow']['evidence'])
        self.assertFalse(value['coverage']['control_flow_proven'])

    def test_latest_assignment_wins_not_initializer(self):
        value = analyze(self.setup_tree(var(), assign(4))[0])
        self.assertEqual(value['findings'], [])
        self.assertEqual(self.memory_call(value)['arguments'][2]['constant_integer'], 4)

    def test_alias_expression_and_unsigned_conversion_use_compiler_types(self):
        n = var(260, kind='unsigned char')
        count = cast(reference('n', 'unsigned char'), 'unsigned long')
        self.assertEqual(self.memory_call(analyze(self.setup_tree(n, count=count)[0]))['arguments'][2]['constant_integer'], 4)
        m = var(name='m')
        m['inner'] = [{'kind': 'BinaryOperator', 'opcode': '+', 'type': {'qualType': 'unsigned long'},
                       'inner': [reference('n', 'unsigned long'), literal(4)]}]
        self.assertEqual(len(analyze(self.setup_tree(var(4), m, count=reference('m','unsigned long'))[0])['findings']), 1)

    def test_unknown_branch_join_keeps_only_equal_values(self):
        cond = reference('parameter','int')
        for right, expected in ((4,4), (8,None)):
            branch = {'kind':'IfStmt','inner':[cond, block(assign(4)), block(assign(right))]}
            value = analyze(self.setup_tree(var(), branch)[0])
            self.assertEqual(self.memory_call(value)['arguments'][2]['constant_integer'], expected)

    def test_scalar_constant_condition_skips_impossible_branch(self):
        tree, fn, call = self.setup_tree(var(0))
        fn['inner'][0]['inner'][-1] = {'kind':'IfStmt','inner':[reference('n','unsigned long'),call]}
        self.assertEqual(analyze(tree)['calls'], [])

    def test_address_escape_invalidates_value_before_call(self):
        address = {'kind':'UnaryOperator','opcode':'&','type':{'qualType':'unsigned long *'},
                   'inner':[reference('n','unsigned long')]}
        value = analyze(self.setup_tree(var(), unknown_call(address))[0])
        self.assertIsNone(self.memory_call(value)['arguments'][2]['constant_integer'])

    def test_side_effect_in_another_argument_prevents_order_assumption(self):
        tree, _, call = self.setup_tree(var())
        call['inner'][2] = {'kind':'BinaryOperator','opcode':',','type':{'qualType':'void *'},
                           'inner':[assign(4),call['inner'][2]]}
        self.assertIsNone(self.memory_call(analyze(tree))['arguments'][2]['constant_integer'])

    def test_loop_does_not_reuse_entry_value_for_every_iteration(self):
        tree, fn, call = self.setup_tree(var())
        fn['inner'][0]['inner'][-1] = {'kind':'WhileStmt','inner':[
            reference('parameter','int'), block(call, assign(4))]}
        self.assertIsNone(self.memory_call(analyze(tree))['arguments'][2]['constant_integer'])

    def test_loop_body_fresh_assignment_can_be_used(self):
        tree, fn, call = self.setup_tree(var(1))
        fn['inner'][0]['inner'][-1] = {'kind':'WhileStmt','inner':[
            reference('parameter','int'), block(assign(8),call)]}
        self.assertEqual(len(analyze(tree)['findings']),1)

    def test_same_spelling_different_declaration_does_not_overwrite(self):
        shadow=var(4,name='inner'); shadow['name']='n'
        value=analyze(self.setup_tree(var(),block(shadow))[0])
        self.assertEqual(self.memory_call(value)['arguments'][2]['constant_integer'],8)

    def test_static_volatile_and_atomic_scalars_remain_unknown(self):
        for decl in (var(storageClass='static'), var(kind='volatile unsigned long'),
                     var(kind='_Atomic(unsigned long)')):
            value=analyze(self.setup_tree(decl)[0])
            self.assertIsNone(self.memory_call(value)['arguments'][2]['constant_integer'])

    def test_unstructured_jump_disables_local_flow(self):
        value=analyze(self.setup_tree(var(), {'kind':'GotoStmt','targetLabelDeclId':'label'})[0])
        self.assertIsNone(self.memory_call(value)['arguments'][2]['constant_integer'])

    def test_early_return_stops_linear_successor(self):
        tree,_,_=self.setup_tree(var(),{'kind':'ReturnStmt'})
        self.assertEqual(analyze(tree)['calls'],[])

    def test_signed_overflow_is_not_a_known_length(self):
        decl=var(kind='int')
        decl['inner']=[{'kind':'BinaryOperator','opcode':'+','type':{'qualType':'int'},
                        'inner':[literal(2**31-1),literal(1)]}]
        self.assertIsNone(self.memory_call(analyze(self.setup_tree(decl)[0]))['arguments'][2]['constant_integer'])

    def test_increment_invalidates_stale_value(self):
        inc={'kind':'UnaryOperator','opcode':'++','type':{'qualType':'unsigned long'},
             'inner':[reference('n','unsigned long')]}
        self.assertIsNone(self.memory_call(analyze(self.setup_tree(var(),inc)[0]))['arguments'][2]['constant_integer'])

    def test_flow_evidence_has_no_process_local_ids(self):
        tree,_,_=self.setup_tree(var())
        other=copy.deepcopy(tree)
        def edit(node):
            if isinstance(node,dict):
                for k,v in list(node.items()):
                    if k=='id': node[k]=v+'-rerun'
                    else: edit(v)
            elif isinstance(node,list):
                for x in node: edit(x)
        edit(other)
        self.assertEqual(analyze(tree),analyze(other))

    def test_if_with_initializer_is_not_processed_as_linear_branches(self):
        branch={'kind':'IfStmt','hasInit':True,'inner':[
            var(0,name='flag'),reference('parameter','int'),block(assign(4)),block(assign(8))]}
        self.assertIsNone(self.memory_call(analyze(self.setup_tree(var(),branch)[0]))['arguments'][2]['constant_integer'])

    def test_destructor_scope_invalidates_reintroduced_value(self):
        scope=block({'kind':'CXXConstructExpr'},assign(8))
        self.assertIsNone(self.memory_call(analyze(self.setup_tree(var(),scope)[0]))['arguments'][2]['constant_integer'])

    def test_flow_budgets_fail_explicitly(self):
        from unittest.mock import patch
        with patch('ohvul.clang_flow.MAX_FLOW_NODES',1), self.assertRaises(ValueError):
            analyze(self.setup_tree(var())[0])

    def test_shortcircuit_right_write_does_not_leak_to_successor(self):
        logical={'kind':'BinaryOperator','opcode':'&&','type':{'qualType':'int'},
                 'inner':[reference('parameter','int'),assign(4)]}
        self.assertIsNone(self.memory_call(analyze(self.setup_tree(var(),logical)[0]))['arguments'][2]['constant_integer'])

    def test_variable_array_bound_effects_never_reuse_stale_scalars(self):
        vla={'kind':'VarDecl','id':'vla','name':'a','type':{'qualType':'char[n--]'}}
        value=analyze(self.setup_tree(var(),vla)[0])
        self.assertIsNone(self.memory_call(value)['arguments'][2]['constant_integer'])
        self.assertIn('variable_array_evaluation_not_summarized',{i['kind'] for i in value['issues']})

    def test_cleanup_attributes_disable_scalar_propagation(self):
        n=var(); n['inner'].append({'kind':'CleanupAttr'})
        self.assertIsNone(self.memory_call(analyze(self.setup_tree(n)[0]))['arguments'][2]['constant_integer'])

    def test_aggregate_destructor_is_not_assumed_trivial(self):
        obj={'kind':'VarDecl','id':'obj','name':'obj','type':{'qualType':'Reset'},
             'inner':[{'kind':'InitListExpr'}]}
        value=analyze(self.setup_tree(var(),block(obj,assign(8)))[0])
        self.assertIsNone(self.memory_call(value)['arguments'][2]['constant_integer'])


if __name__=='__main__': unittest.main()
