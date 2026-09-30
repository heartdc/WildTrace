import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ohvul.ffi_boundary_audit import audit_source, main


class FfiBoundaryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_raw_array_index_is_retained_as_candidate(self):
        (self.root / 'ffi.cpp').write_text(
            'struct CArr { int *head; int64_t size; };\n'
            'void f(CArr a) { for (int64_t i = 0; i < a.size; ++i) use(a.head[i]); }\n',
            encoding='utf-8')
        result = audit_source(self.root)
        self.assertEqual(len(result['findings']), 1)
        finding = result['findings'][0]
        self.assertEqual(finding['cwe_candidate'], 'unknown')
        self.assertEqual(finding['status'], 'candidate')
        self.assertFalse(finding['evidence']['guard_hint'])
        self.assertEqual(result['confirmed_vulnerabilities'], 0)

    def test_guard_hint_does_not_suppress_finding(self):
        (self.root / 'ffi.cpp').write_text(
            'struct CArr { char **head; int64_t size; };\n'
            'void f(CArr a) { if (a.head == nullptr) return; use(a.head[0]); }\n',
            encoding='utf-8')
        result = audit_source(self.root)
        self.assertEqual(len(result['findings']), 1)
        self.assertTrue(result['findings'][0]['evidence']['guard_hint'])

    def test_unrelated_index_and_scalar_struct_are_ignored(self):
        (self.root / 'ffi.cpp').write_text(
            'struct Scalar { int value; int size; };\n'
            'void f(int *head) { use(head[0]); }\n', encoding='utf-8')
        self.assertEqual(audit_source(self.root)['findings'], [])

    def test_missing_file_and_decode_failure_are_not_coverage(self):
        (self.root / 'bad.cpp').write_bytes(b'\xff')
        result = audit_source(self.root, ['missing.cpp', 'bad.cpp'])
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(result['files_requested'], 2)
        self.assertEqual(result['files_scanned'], 0)
        self.assertEqual(result['files_failed'], 2)
        self.assertEqual(len(result['file_results']), 2)
        output = self.root / 'failure.json'
        self.assertEqual(main([str(self.root), '--output', str(output)]), 1)
        self.assertEqual(json.loads(output.read_text())['status'], 'input_error')

    def test_partial_read_retains_success_and_fails_cli(self):
        (self.root / 'ok.cpp').write_text('int x;', encoding='utf-8')
        (self.root / 'bad.cpp').write_bytes(b'\xff')
        result = audit_source(self.root)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['files_scanned'], 1)
        self.assertEqual(result['files_failed'], 1)
        self.assertTrue(result['scope_complete'])
        self.assertEqual(main([str(self.root), '--output', str(self.root / 'partial.json')]), 1)

    def test_enumeration_failure_is_not_a_complete_empty_scan(self):
        def inaccessible(root, **kwargs):
            kwargs['onerror'](PermissionError(13, 'denied', str(root / 'private')))
            return iter(())
        with patch('ohvul.ffi_boundary_audit.os.walk', side_effect=inaccessible):
            result = audit_source(self.root)
        self.assertEqual(result['status'], 'input_error')
        self.assertFalse(result['scope_complete'])
        self.assertIsNone(result['files_requested'])
        self.assertEqual(result['files_scanned'], 0)
        self.assertEqual(result['input_errors'][0]['stage'], 'enumeration')

    def test_invalid_explicit_scope_is_rejected_before_reads(self):
        (self.root / 'ok.cpp').write_text('int x;', encoding='utf-8')
        invalid_lists = [
            ['ok.cpp', '../outside.cpp'], [str(self.root / 'ok.cpp')],
            ['ok.cpp', './ok.cpp'], ['ok.cpp', 'x/../ok.cpp'],
            ['C:\\outside.cpp'], ['ok.cpp', 'note.txt'],
        ]
        for names in invalid_lists:
            with self.subTest(names=names), patch.object(Path, 'open', side_effect=AssertionError('read before scope validation')):
                with self.assertRaises(ValueError):
                    audit_source(self.root, names)

    def test_explicit_link_rejected_without_reading_target(self):
        target = self.root / 'ok.cpp'
        target.write_text('int x;', encoding='utf-8')
        link = self.root / 'link.cpp'
        try:
            link.symlink_to(target)
        except OSError as exc:
            self.skipTest('symlink creation unavailable: ' + str(exc))
        with patch.object(Path, 'open', side_effect=AssertionError('followed link')):
            with self.assertRaises(ValueError):
                audit_source(self.root, ['link.cpp'])
        result = audit_source(self.root)
        self.assertEqual(result['files_scanned'], 1)
        self.assertEqual(result['files_skipped'], 1)

    def test_comments_and_literals_do_not_create_shapes_or_uses(self):
        (self.root / 'ffi.cpp').write_text(
            '// struct Fake { int *fake; int size; };\n'
            '/* use(a.fake[0]); */\n'
            'const char *s = "struct Fake { int *head; int size; }; use(a.head[0]);";\n'
            'const char *raw = R"tag(struct Fake { int *head; int size; };\nuse(a.head[0]);)tag";\n',
            encoding='utf-8')
        self.assertEqual(audit_source(self.root)['findings'], [])

    def test_masking_preserves_real_location_and_ignores_fake_guard(self):
        source = ('struct CArr { int *head; int size; };\n'
                  '// nullptr a.head[0]\n'
                  'const char *s = "NULL a.head[1]";\n'
                  'void f(CArr a) { a.head[0] = 1; }\n')
        (self.root / 'ffi.cpp').write_text(source, encoding='utf-8')
        findings = audit_source(self.root)['findings']
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['location']['line'], 4)
        self.assertEqual(findings[0]['evidence']['code'], source.splitlines()[3])
        self.assertFalse(findings[0]['evidence']['guard_hint'])
        self.assertEqual(findings[0]['cwe_candidate'], 'unknown')

    def test_same_named_member_and_legal_access_remain_untyped_navigation(self):
        (self.root / 'shape.h').write_text('struct CArr { int *head; int size; };', encoding='utf-8')
        (self.root / 'use.cpp').write_text(
            'struct Unrelated { int head[2]; };\n'
            'void f() { Unrelated a{}; a.head[0] = 1; use(a.head[1]); }\n', encoding='utf-8')
        findings = audit_source(self.root)['findings']
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(finding['cwe_candidate'], 'unknown')
            self.assertEqual(finding['evidence']['association'], 'field_name_only')
            self.assertEqual(finding['evidence']['type_binding'], 'unknown')
            self.assertEqual(finding['evidence']['bounds'], 'unknown')
            self.assertEqual(finding['status'], 'candidate')

    def test_cli_output_is_exclusive(self):
        (self.root / 'ffi.cpp').write_text(
            'struct CArr { int *head; int size; };\nvoid f(CArr a) { use(a.head[0]); }\n',
            encoding='utf-8')
        output = self.root / 'out.json'
        self.assertEqual(main([str(self.root), '--output', str(output)]), 0)
        self.assertEqual(main([str(self.root), '--output', str(output)]), 1)
        self.assertEqual(len(json.loads(output.read_text(encoding='utf-8'))['findings']), 1)


if __name__ == '__main__':
    unittest.main()
