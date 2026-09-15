import copy
import io
import json
import unittest
from unittest.mock import patch
from ohvul import clang_stream
from tests.test_clang_facts import fixture,analyze,SOURCE


class AstStreamTests(unittest.TestCase):
    def capture(self,tree,limit=65536):
        raw=json.dumps(tree,ensure_ascii=False,indent=2).encode()
        projected,meta=clang_stream.capture_main_ast(io.BytesIO(raw),SOURCE,'/source/a.c',output_limit=limit)
        self.assertEqual(meta['raw_bytes'],len(raw))
        return json.loads(projected),meta

    def test_projection_preserves_main_body_and_builtin_identity(self):
        tree,_,_=fixture()
        projected,meta=self.capture(tree)
        self.assertEqual(analyze(projected),analyze(tree))
        self.assertEqual(meta['statistics']['main_bodies'],1)

    def test_header_body_is_omitted_but_definition_still_disables_builtin(self):
        tree,_,_=fixture()
        tree['inner'][0].update(loc={'includedFrom':{'file':'/source/a.c'}})
        tree['inner'][0]['inner'].append({'kind':'CompoundStmt','inner':[{'kind':'ReturnStmt'}]})
        projected,meta=self.capture(tree)
        self.assertEqual(analyze(projected),analyze(tree))
        self.assertEqual(meta['statistics']['header_bodies_omitted'],1)

    def test_namespace_wrapper_does_not_hide_main_function(self):
        tree,fn,_=fixture()
        tree['inner'][1]={'kind':'NamespaceDecl','name':'example','inner':[fn]}
        projected,_=self.capture(tree)
        self.assertEqual(analyze(projected),analyze(tree))

    def test_large_discarded_header_body_is_not_captured(self):
        tree,_,_=fixture()
        tree['inner'].insert(1,{'kind':'FunctionDecl','id':'header','name':'header',
            'loc':{'includedFrom':{'file':'/source/a.c'}},'inner':[{'kind':'CompoundStmt',
             'inner':[{'kind':'StringLiteral','value':'x'*500000}]}]})
        projected,meta=self.capture(tree,limit=10000)
        self.assertGreater(meta['raw_bytes'],500000)
        self.assertEqual(len(analyze(projected)['findings']),1)

    def test_invalid_json_even_in_discarded_body_is_rejected(self):
        for raw in (b'{"kind":"TranslationUnitDecl","inner":[{"kind":"CompoundStmt","inner":[NaN]}]}',
                    b'{"kind":"TranslationUnitDecl","kind":"Other"}',
                    b'{"kind":"TranslationUnitDecl"} {}',b'{"inner":[],"kind":"TranslationUnitDecl"}'):
            with self.assertRaises(ValueError):
                clang_stream.capture_main_ast(io.BytesIO(raw),SOURCE,'/source/a.c',output_limit=65536)

    def test_chunk_boundaries_and_utf8_preserve_strings(self):
        class Tiny(io.BytesIO):
            def read(self,size=-1): return super().read(min(size,7))
        tree,_,_=fixture(); tree['inner'][0]['note']='  中文 \\" quotes  '
        raw=json.dumps(tree,ensure_ascii=False).encode()
        projected,_=clang_stream.capture_main_ast(Tiny(raw),SOURCE,'/source/a.c',output_limit=65536)
        self.assertEqual(json.loads(projected)['inner'][0]['note'],tree['inner'][0]['note'])

    def test_raw_and_projected_output_limits_are_enforced(self):
        with patch.object(clang_stream,'MAX_RAW_BYTES',100):
            with self.assertRaises(ValueError): self.capture(fixture()[0])
        with self.assertRaises(ValueError): self.capture(fixture()[0],limit=10)

    def test_discarded_duplicate_type_is_recorded_without_interpretation(self):
        tree,_,_=fixture()
        header={'kind':'FunctionDecl','id':'header','name':'header',
                'loc':{'includedFrom':{'file':'/source/a.c'}},
                'inner':[{'kind':'CompoundStmt','inner':[{'type':{'qualType':'first'},'other_type':{'qualType':'second'}}]}]}
        tree['inner'].insert(1,header)
        raw=json.dumps(tree).replace('"other_type"','"type"').encode()
        projected,meta=clang_stream.capture_main_ast(io.BytesIO(raw),SOURCE,'/source/a.c',output_limit=65536)
        self.assertEqual(meta['statistics']['discarded_duplicate_type_fields'],1)
        self.assertEqual(len(analyze(json.loads(projected))['findings']),1)
        self.assertNotIn(b'first',projected)
        self.assertNotIn(b'second',projected)

    def test_retained_duplicate_type_cannot_use_last_wins(self):
        raw=b'{"kind":"TranslationUnitDecl","inner":[{"kind":"FunctionDecl","name":"sample","id":"fn","loc":{"file":"/source/a.c","offset":5},"inner":[{"kind":"CompoundStmt","inner":[{"type":{},"type":{}}]}]}]}'
        with self.assertRaises(ValueError):
            clang_stream.capture_main_ast(io.BytesIO(raw),SOURCE,'/source/a.c',output_limit=65536)

    def test_projected_away_template_argument_types_are_not_interpreted(self):
        raw=b'{"kind":"TranslationUnitDecl","inner":[{"kind":"TemplateArgument","type":{"qualType":"one"},"type":{"qualType":"two"}}]}'
        projected,meta=clang_stream.capture_main_ast(io.BytesIO(raw),SOURCE,'/source/a.c',output_limit=65536)
        self.assertEqual(json.loads(projected)['inner'],[])
        self.assertEqual(meta['statistics']['discarded_duplicate_type_fields'],1)
        retained=b'{"kind":"TranslationUnitDecl","inner":[{"kind":"ParmVarDecl","type":{},"type":{}}]}'
        with self.assertRaises(ValueError):
            clang_stream.capture_main_ast(io.BytesIO(retained),SOURCE,'/source/a.c',output_limit=65536)


if __name__=='__main__': unittest.main()
