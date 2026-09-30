"""Offline compilation import contracts; no compiler or model is executed."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ohvul import compile_database as importer


class CompileDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'inc').mkdir()
        (self.root / 'inc' / 'a.h').write_text('int a;\n', encoding='utf8')
        (self.root / 'a.c').write_text('int main(void) {return 0;}\n', encoding='utf8')
        self.database = self.base / 'compile_commands.json'
        self.template = self.base / 'template.json'
        self.output = self.base / 'imported'
        self.profile = {
            'schema': 'engine-profile-0.1', 'component': 'synthetic',
            'source_repositories': {'.': 'a' * 40}, 'source_files': ['unused.c'],
            'include_dirs': [], 'defines': ['OLD_TEMPLATE_MACRO=1'],
            'extra_compile_args': [], 'engines': ['clang-static-analyzer', 'clang-tidy']}
        self.template.write_text(json.dumps(self.profile), encoding='utf8')
        self.entry = {'directory': str(self.root), 'file': 'a.c',
                      'arguments': ['clang', '-D', 'ACTIVE=1', '-Iinc', '-std=c11',
                                    '-c', 'a.c', '-o', 'a.o']}
        self.save([self.entry])

    def save(self, entries):
        self.database.write_text(json.dumps(entries), encoding='utf8')

    def build(self):
        return importer.build_import(self.database, self.root, self.template)

    def write(self):
        return importer.write_import(self.database, self.root, self.template, self.output)

    def test_typed_flags_and_no_template_argument_fallback(self):
        result = self.build()
        self.assertEqual(result['status'], 'drafts_ready')
        unit = result['units'][0]
        p = unit['profile_draft']
        self.assertEqual(p['defines'], ['ACTIVE=1'])
        self.assertEqual(p['source_files'], ['a.c'])
        self.assertEqual(p['include_dirs'], ['inc'])
        self.assertEqual(p['extra_compile_args'], ['-std=c11'])
        self.assertFalse(result['provenance_verified'])
        self.assertFalse(result['commands_executed'])

    def test_different_configurations_of_same_file_are_preserved(self):
        other = copy.deepcopy(self.entry)
        other['arguments'][2] = 'ACTIVE=2'
        self.save([self.entry, other])
        result = self.write()
        self.assertEqual(result['counts'], {'entries': 2, 'imported': 2, 'blocked': 0})
        self.assertEqual(len({x['unit_id'] for x in result['units']}), 2)
        manifest = json.loads((self.output / 'batch.json').read_bytes())
        self.assertEqual(len(manifest['jobs']), 2)

    def test_duplicate_configuration_is_visible_not_double_counted(self):
        self.save([self.entry, self.entry])
        result = self.write()
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['counts']['imported'], 1)
        self.assertEqual(result['units'][1]['error_code'], 'duplicate_configuration')
        self.assertFalse((self.output / 'batch.json').exists())

    def test_shell_only_record_is_not_executed(self):
        self.save([{'directory': str(self.root), 'file': 'a.c',
                    'command': 'clang a.c && echo unsafe'}])
        with patch('subprocess.run') as process, patch('urllib.request.urlopen') as network:
            result = self.build()
        self.assertEqual(result['units'][0]['error_code'], 'argument_vector_required')
        process.assert_not_called()
        network.assert_not_called()

    def test_arguments_are_authoritative_when_command_also_exists(self):
        self.entry['command'] = 'not used or executed'
        self.save([self.entry])
        unit = self.build()['units'][0]
        self.assertTrue(unit['command_string_ignored'])

    def test_unsafe_or_unrepresentable_arguments_block_record(self):
        for flag in ('@args.rsp', '-Xclang', '-fplugin=unknown', '-isystem',
                     '--sysroot=/unknown', '-include', '-UACTIVE', '-x',
                     '-O0', '-E', '--', '-Wl,anything'):
            with self.subTest(flag=flag):
                item = copy.deepcopy(self.entry)
                item['arguments'].insert(1, flag)
                self.save([item])
                self.assertEqual(self.build()['counts']['blocked'], 1)

    def test_wrappers_are_not_guessed_or_invoked(self):
        self.entry['arguments'].insert(0, 'ccache')
        self.save([self.entry])
        self.assertEqual(self.build()['units'][0]['error_code'], 'unsupported_compiler_driver')

    def test_output_and_dependency_flags_are_recorded_not_executed(self):
        self.entry['arguments'].extend(['-MMD', '-MP', '-MF', 'a.d', '-MT', 'target'])
        self.save([self.entry])
        self.assertEqual(self.build()['status'], 'drafts_ready')
        self.assertFalse((self.root / 'a.o').exists())
        self.assertFalse((self.root / 'a.d').exists())
        self.assertTrue(self.build()['units'][0]['excluded_driver_arguments'])

    def test_source_argument_must_match_record_file(self):
        (self.root / 'b.c').write_text('int b;', encoding='utf8')
        self.entry['file'] = 'b.c'
        self.save([self.entry])
        self.assertEqual(self.build()['units'][0]['error_code'], 'source_argument_mismatch')

    def test_multiple_compile_inputs_and_missing_compile_switch_rejected(self):
        for args in (['clang', '-c', 'a.c', 'a.c'], ['clang', 'a.c']):
            self.entry['arguments'] = args
            self.save([self.entry])
            self.assertEqual(self.build()['counts']['blocked'], 1)

    def test_missing_source_or_include_not_counted_as_imported(self):
        (self.root / 'a.c').unlink()
        self.assertEqual(self.build()['units'][0]['error_code'], 'source_file_missing')
        (self.root / 'a.c').write_text('int a;', encoding='utf8')
        self.entry['arguments'][3] = '-Iabsent'
        self.save([self.entry])
        self.assertEqual(self.build()['units'][0]['error_code'], 'include_directory_missing')

    def test_paths_outside_root_are_blocked(self):
        for key, value in (('directory', str(self.base)), ('file', '../outside.c')):
            item = copy.deepcopy(self.entry)
            item[key] = value
            self.save([item])
            self.assertEqual(self.build()['counts']['blocked'], 1)

    def test_duplicate_macros_or_conflicting_standards_are_not_reordered(self):
        for args in (['-DACTIVE=2'], ['-std=c99'], ['-Iinc']):
            item = copy.deepcopy(self.entry)
            item['arguments'].extend(args)
            self.save([item])
            self.assertEqual(self.build()['counts']['blocked'], 1)

    def test_partial_import_keeps_all_records_without_success_batch(self):
        self.save([self.entry, {'directory': str(self.root), 'file': 'a.c', 'command': 'clang -c a.c'}])
        result = self.write()
        self.assertEqual(result['counts'], {'entries': 2, 'imported': 1, 'blocked': 1})
        self.assertFalse((self.output / 'batch.json').exists())
        importer.verify_import(self.database, self.root, self.template, self.output)

    def test_strict_json_schema_and_resource_limits(self):
        for raw in (b'{}', b'[]', b'null', b'[NaN]',
                    b'[{"file":"a.c","file":"a.c"}]'):
            self.database.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.build()
        self.save([self.entry])
        with patch.object(importer, 'MAX_DATABASE_BYTES', 4), self.assertRaises(ValueError):
            self.build()

    def test_unknown_record_fields_and_non_string_arguments_are_blocked(self):
        for item in ({**self.entry, 'environment': {'X': 'Y'}},
                     {**self.entry, 'arguments': ['clang', True]}):
            self.save([item])
            self.assertEqual(self.build()['counts']['blocked'], 1)

    def test_deterministic_generation_and_independent_verification(self):
        first = self.write()
        self.assertEqual(first, self.build())
        self.assertEqual(importer.verify_import(self.database, self.root, self.template, self.output), first)

    def test_profile_and_summary_tampering_rejected(self):
        self.write()
        path = next(self.output.glob('unit-*.profile.json'))
        path.write_text('{}', encoding='utf8')
        with self.assertRaises(ValueError):
            importer.verify_import(self.database, self.root, self.template, self.output)

    def test_changed_database_or_source_cannot_verify_old_import(self):
        self.write()
        (self.root / 'a.c').write_text('int changed;', encoding='utf8')
        with self.assertRaises(ValueError):
            importer.verify_import(self.database, self.root, self.template, self.output)

    def test_source_mutation_during_publication_cannot_publish_summary(self):
        original = importer.exclusive_json
        def changed(path, value, **kwargs):
            result = original(path, value, **kwargs)
            if Path(path).name.endswith('.profile.json'):
                (self.root / 'a.c').write_text('changed', encoding='utf8')
            return result
        with patch.object(importer, 'exclusive_json', side_effect=changed), self.assertRaises(ValueError):
            self.write()
        self.assertFalse((self.output / 'summary.json').exists())

    def test_output_does_not_overwrite_or_enter_source_tree(self):
        self.output = self.root / 'output'
        with self.assertRaises(ValueError):
            self.write()
        self.output = self.base / 'exists'
        self.output.mkdir()
        with self.assertRaises(ValueError):
            self.write()

    def test_semgrep_template_is_not_silently_changed(self):
        self.profile.update(engines=['semgrep'], semgrep_rule_files=['rules.yml'])
        self.template.write_text(json.dumps(self.profile), encoding='utf8')
        with self.assertRaises(ValueError):
            self.build()

    def test_output_like_unknown_flags_are_not_silently_dropped(self):
        for flag in ('-openmp', '-objc-arc', '-oa.o', '-MFa.d'):
            item = copy.deepcopy(self.entry)
            item['arguments'].insert(1, flag)
            self.save([item])
            self.assertEqual(self.build()['units'][0]['error_code'], 'unsupported_compile_argument')

    def test_mutated_generated_profile_prevents_success_summary(self):
        original = importer.exclusive_json
        def corrupt(path, value, **kwargs):
            result = original(path, value, **kwargs)
            if Path(path).name.endswith('.profile.json'):
                Path(path).write_text('{}', encoding='utf8')
            return result
        with patch.object(importer, 'exclusive_json', side_effect=corrupt), self.assertRaises(ValueError):
            self.write()
        self.assertFalse((self.output / 'summary.json').exists())

    def test_symlink_ancestor_rejected_before_import(self):
        original = __import__('ohvul.component_batch', fromlist=['is_link']).is_link
        with patch('ohvul.component_batch.is_link',
                   side_effect=lambda p: p == self.root or original(p)):
            with self.assertRaises(ValueError):
                self.build()

    def test_exported_profile_reaches_real_local_git_validation(self):
        import os
        import subprocess
        from ohvul.engine_profile import prepare_profile
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0')
        command = ['git', '-c', 'core.hooksPath=' + str(self.base / 'disabled-hooks'),
                   '-c', 'core.autocrlf=false', '-c', 'user.name=Local Fixture',
                   '-c', 'user.email=fixture@example.invalid', '-C', str(self.root)]
        for args in (['init', '-q'], ['add', '.'], ['commit', '-qm', 'synthetic inputs']):
            subprocess.run(command + args, env=env, check=True, capture_output=True, timeout=30)
        pin = subprocess.check_output(command + ['rev-parse', 'HEAD'], env=env, text=True, timeout=30).strip()
        self.profile['source_repositories'] = {'.': pin}
        self.template.write_text(json.dumps(self.profile), encoding='utf8')
        self.write()
        profile, receipt = prepare_profile(next(self.output.glob('unit-*.profile.json')), self.root)
        self.assertTrue(receipt['provenance']['verified'])
        self.assertEqual(profile['source_files'], ['a.c'])
        self.assertEqual(profile['defines'], ['ACTIVE=1'])


if __name__ == '__main__':
    unittest.main()
