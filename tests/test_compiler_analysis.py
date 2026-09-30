"""Runner failure/coverage contracts; remote requests and targets never run."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ohvul import compiler_analysis as module
from tests.test_clang_facts import fixture, SOURCE

MACROS = b'''#define __CHAR_BIT__ 8
#define __SIZEOF_SHORT__ 2
#define __SIZEOF_INT__ 4
#define __SIZEOF_LONG__ 8
#define __SIZEOF_LONG_LONG__ 8
#define __SIZEOF_POINTER__ 8
#define __SIZEOF_FLOAT__ 4
#define __SIZEOF_DOUBLE__ 8
'''


class CompilerRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base/'source'
        self.root.mkdir()
        (self.root/'a.c').write_bytes(SOURCE)
        self.profile_path = self.base/'profile.json'
        self.profile_path.write_text('{}')
        self.profile = {'schema': 'engine-profile-0.1', 'component': 'fixture',
            'source_repositories': {'.':'a'*40}, 'source_files':['a.c'], 'include_dirs':[],
            'defines':[], 'extra_compile_args':[], 'engines':['clang-static-analyzer']}
        self.receipt = {'profile_sha256':module.hashlib.sha256(self.profile_path.read_bytes()).hexdigest()}
        self.enterContext(patch.object(module,'prepare_profile',return_value=(self.profile,self.receipt)))
        self.recheck = self.enterContext(patch.object(module,'recheck_profile'))
        self.invoked = self.enterContext(patch.object(module,'_invoke',side_effect=self.reply))
        self.status, self.reason, self.body = 'completed', None, None

    def reply(self, command, timeout, **kwargs):
        if '--version' in command:
            raw = b'clang version 22.1.8\nTarget: x86_64-unknown-linux-gnu\n'
        elif '-dM' in command:
            raw = MACROS
        else:
            tree, function, _ = fixture()
            function['loc']['file'] = command[-1]
            raw = json.dumps(tree).encode() if self.body is None else self.body
            return {'status':self.status,'reason':self.reason,'stdout':raw,'stderr':b'',
                     'seconds':0.01,'returncode':0 if self.status=='completed' else 1}
        return {'status':'completed','reason':None,'stdout':raw,'stderr':b'','seconds':0.01,'returncode':0}

    def run_stage(self, **kwargs):
        return module.run_compiler_profile(self.root,self.profile_path,**kwargs)

    def test_actual_completed_files_and_compiler_facts_are_retained(self):
        result = self.run_stage()
        self.assertEqual(result['status'],'completed')
        self.assertEqual(result['scan']['files_scanned'],1)
        self.assertEqual(len(result['findings']),1)
        self.assertEqual(result['compiler_version']['version'],'22.1.8')
        self.assertEqual(len(result['compiler_facts'][0]['functions']),1)
        self.assertEqual(result['findings'][0]['evidence']['compiler_execution']['returncode'],0)
        self.assertEqual(self.invoked.call_count,3)

    def test_zero_findings_is_completed_not_zero_coverage(self):
        self.body = b'{"kind":"TranslationUnitDecl","inner":[]}'
        result = self.run_stage()
        self.assertEqual((len(result['findings']),result['scan']['files_scanned']), (0,1))
        self.assertFalse(result['analysis_scope']['control_flow_verified'])

    def test_compiler_failure_with_parseable_ast_is_not_success(self):
        self.status,self.reason = 'input_error','compiler_diagnostics_error'
        result = self.run_stage()
        self.assertEqual(result['status'],'input_error')
        self.assertEqual(result['scan']['files_scanned'],0)
        self.assertEqual(result['findings'],[])
        self.assertEqual(result['compiler_facts'],[])

    def test_timeout_keeps_file_status_and_never_becomes_clean(self):
        self.status,self.reason = 'timeout','compiler_timeout'
        result = self.run_stage()
        self.assertEqual(result['file_results'][0]['status'],'timeout')
        self.assertNotEqual(result['status'],'completed')

    def test_invalid_json_and_non_translation_unit_fail_closed(self):
        for body in (b'bad',b'{}',b'{"kind":"TranslationUnitDecl","kind":"Other"}'):
            self.body=body
            result=self.run_stage()
            self.assertEqual(result['scan']['files_scanned'],0)
            self.assertTrue(result['input_errors'])

    def test_layout_failure_stops_analysis_without_invented_counts(self):
        def response(command,timeout,**kwargs):
            result=self.reply(command,timeout,**kwargs)
            if '-dM' in command: result['stdout']=b'unknown layout'
            return result
        self.invoked.side_effect=response
        result=self.run_stage()
        self.assertEqual(result['scan']['files_attempted'],0)
        self.assertEqual(self.invoked.call_count,2)
        self.assertEqual(result['file_results'][0]['status'],'not_run')

    def test_source_changes_during_compiler_call_are_rejected(self):
        def response(command,timeout,**kwargs):
            value=self.reply(command,timeout,**kwargs)
            if '-ast-dump=json' in command: (self.root/'a.c').write_bytes(SOURCE+b'/*changed*/')
            return value
        self.invoked.side_effect=response
        result=self.run_stage()
        self.assertFalse(result['input_bindings_valid'])
        self.assertEqual(result['findings'],[])

    def test_provenance_change_prevents_success(self):
        self.recheck.side_effect=ValueError('changed input')
        result=self.run_stage()
        self.assertFalse(result['input_bindings_valid'])
        self.assertEqual(result['status'],'input_error')

    def test_arguments_are_fixed_ast_mode_not_template_engine_execution(self):
        self.run_stage()
        cmd=self.invoked.call_args.args[0]
        self.assertIn('--no-default-config',cmd)
        self.assertIn('-fsyntax-only',cmd)
        self.assertIn('-ast-dump=json',cmd)
        self.assertNotIn('--analyze',cmd)
        self.assertNotIn('-o',cmd)

    def test_bad_timeout_rejected_before_any_compiler_invocation(self):
        for value in (True,0,121,1.5):
            with self.assertRaises(ValueError): self.run_stage(timeout=value)
        self.invoked.assert_not_called()

    def test_cli_failed_analysis_does_not_create_success_report(self):
        self.status,self.reason='input_error','synthetic_failure'
        out=self.base/'output'
        code=module.main(['--root',str(self.root),'--profile',str(self.profile_path),'--output',str(out)])
        self.assertEqual(code,1)
        self.assertTrue((out/'result.json').exists())
        self.assertFalse((out/'report.candidate.json').exists())

    def test_cli_no_overwrite_or_source_output(self):
        for out in (self.root/'output',self.root,self.base):
            self.assertEqual(module.main(['--root',str(self.root),'--profile',str(self.profile_path),'--output',str(out)]),2)
        self.invoked.assert_not_called()

    def test_report_preparation_change_blocks_publication(self):
        original=module.build_audit_report
        def changed(result):
            report=original(result)
            self.profile_path.write_text('{"changed":true}')
            return report
        with patch.object(module,'build_audit_report',side_effect=changed):
            out=self.base/'changed-output'
            self.assertEqual(module.main(['--root',str(self.root),'--profile',str(self.profile_path),'--output',str(out)]),2)
        self.assertFalse(out.exists())

    def test_main_cli_integrates_typed_facts_and_candidate_evidence(self):
        from ohvul import cli
        result=self.run_stage()
        output=self.base/'audit.json'
        argv=['ohvul',str(self.root),'--compiler-profile',str(self.profile_path),'--output',str(output)]
        with patch.object(cli,'run_compiler_profile',return_value=result),patch.object(sys,'argv',argv):
            cli.main()
        saved=json.loads(output.read_bytes())
        self.assertEqual(saved['compiler_scan']['status'],'completed')
        self.assertEqual(len(saved['compiler_facts']),1)
        self.assertTrue(any(f['source']=='wildtrace-clang-ast' for f in saved['findings']))

    def test_main_cli_failed_compilation_cannot_commit_success(self):
        from ohvul import cli
        self.status,self.reason='input_error','synthetic_compile_error'
        result=self.run_stage()
        output,checkpoint,journal=[self.base/n for n in ('audit.json','checkpoint.json','journal.jsonl')]
        argv=['ohvul',str(self.root),'--compiler-profile',str(self.profile_path),'--output',str(output),
              '--checkpoint',str(checkpoint),'--journal',str(journal)]
        with patch.object(cli,'run_compiler_profile',return_value=result),patch.object(sys,'argv',argv):
            with self.assertRaises(SystemExit): cli.main()
        self.assertFalse(output.exists())
        saved=json.loads(checkpoint.read_bytes())
        self.assertEqual(saved['state'],'blocked')
        self.assertIsNone(saved['result_sha256'])
        self.assertIn('abort',journal.read_text())
        self.assertNotIn('commit',journal.read_text())


class CompilerPipeTests(unittest.TestCase):
    def test_indentation_compaction_preserves_json_and_raw_accounting(self):
        value={'text':'  string spaces stay  \\n', 'nested':{'value':list(range(20))}}
        command=[sys.executable,'-c','import json; print(json.dumps('+repr(value)+',indent=80))']
        result=module._invoke(command,2,output_limit=2048,compact_json=True)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(json.loads(result['stdout']),value)
        self.assertGreater(result['stdout_raw_bytes'],len(result['stdout']))
        self.assertEqual(result['stdout_capture_mode'],'json_indentation_removed')

    def test_compaction_does_not_join_invalid_numeric_tokens(self):
        command=[sys.executable,'-c','print("[1\\n  2]")']
        result=module._invoke(command,2,compact_json=True)
        with self.assertRaises(json.JSONDecodeError): json.loads(result['stdout'])

    def test_compacted_stream_still_has_raw_and_capture_budgets(self):
        command=[sys.executable,'-c','print(" "*5000+"{}")']
        with patch.object(module,'RAW_AST_LIMIT',1000):
            result=module._invoke(command,2,compact_json=True)
        self.assertEqual(result['reason'],'compiler_output_limit')
        result=module._invoke([sys.executable,'-c','print("x"*5000)'],2,compact_json=True,output_limit=100)
        self.assertEqual(result['reason'],'compiler_output_limit')

    def test_bounded_stdout_stderr_drain_without_shell(self):
        result=module._invoke([sys.executable,'-c','import sys; print("ok"); print("note",file=sys.stderr)'],2)
        self.assertEqual(result['status'],'completed')
        self.assertIn(b'ok',result['stdout'])
        self.assertIn(b'note',result['stderr'])

    def test_output_limit_is_failure_not_valid_partial_ast(self):
        result=module._invoke([sys.executable,'-c','print("x"*10000)'],2,output_limit=100)
        self.assertEqual(result['reason'],'compiler_output_limit')
        self.assertLessEqual(len(result['stdout']),101)

    def test_missing_compiler_is_explicit(self):
        with patch.object(module.subprocess,'Popen',side_effect=FileNotFoundError):
            result=module._invoke(['missing-compiler'],1)
        self.assertEqual(result['reason'],'compiler_start_failed')


if __name__=='__main__':
    unittest.main()
