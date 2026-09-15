"""Real local evidence fixtures; no analyzers or remote model calls."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_review_queue import BatchFixture, raw_finding
from ohvul import review_context, review_queue, review_evidence as evidence
from ohvul.review_handoff import build_review_handoff
from ohvul.source_snapshot import source_snapshot

SOURCE = ('#define LIMIT 16\n'
          '#define CHECK(n) ((n) <= LIMIT)\n'
          'void copy(char *d, const char *s, int n) {\n'
          ' if (CHECK(n)) {\n'
          '  memcpy(d,s,n);\n'
          ' }\n'
          '}\n'
          'void caller(){ copy(d,s,4); }\n')


class ReviewEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.f = BatchFixture(self.base, findings=[raw_finding(rule='unix.Malloc', line=5)])
        old = self.f.result['scan']['source_snapshot_sha256']
        (self.f.source / 'a.c').write_text(SOURCE, encoding='utf-8', newline='\n')
        new = source_snapshot(self.f.source)
        def replace(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if item == old:
                        value[key] = new
                    else:
                        replace(item)
            elif isinstance(value, list):
                for item in value:
                    replace(item)
        for value in (self.f.result, self.f.receipt, self.f.summary):
            replace(value)
        self.f.persist()
        review_queue.write_review_queue(self.f.summary_path, self.f.output)
        self.roots = {'one': self.f.source}
        self.context = self.base / 'context.json'
        review_context.write_review_context(self.f.output, self.f.summary_path, self.roots, self.context, radius=0)
        self.args = (self.f.summary_path, self.f.output, self.context, self.roots)
        self.output = self.base / 'expanded.json'

    def build(self, **settings):
        return evidence.build_review_evidence(*self.args, **settings)

    def test_adds_function_macro_dependencies_and_local_call_syntax(self):
        result = self.build()
        symbols = {f['symbol'] for f in result['evidence']}
        self.assertTrue({'copy', 'CHECK', 'LIMIT'}.issubset(symbols))
        group = result['groups'][0]
        self.assertEqual(group['scope_resolution'], 'unique_lexical_scope')
        self.assertEqual(group['same_file_callsites_observed'], 1)
        self.assertFalse(group['preprocessor_branches_resolved'])
        self.assertEqual(result['open_tasks'], 5)

    def test_original_bytes_and_line_numbers_are_retained(self):
        result = self.build()
        for fragment in result['evidence']:
            self.assertEqual(fragment['file_sha256'], review_queue.sha256(SOURCE.encode()))
            for line in fragment['lines']:
                self.assertEqual(line['text'], SOURCE.splitlines()[line['line'] - 1])

    def test_task_ids_match_existing_handoff_without_closing_tasks(self):
        result = self.build()
        handoff = build_review_handoff(*self.args)
        self.assertEqual([t['task_id'] for t in result['groups'][0]['tasks']],
                         [t['task_id'] for t in handoff['groups'][0]['tasks']])
        self.assertTrue(all(t['answer'] == 'unknown' and not t['automatically_closed']
                            for t in result['groups'][0]['tasks']))

    def test_deterministic_and_independent_verification(self):
        value = self.build()
        self.assertEqual(value, self.build())
        evidence.validate_review_evidence(value, *self.args)

    def test_tampered_lines_refs_state_and_verdict_rejected(self):
        original = self.build()
        for kind in ('line', 'state', 'remove', 'verdict'):
            value = copy.deepcopy(original)
            if kind == 'line': value['evidence'][0]['lines'][0]['text'] = 'invented'
            if kind == 'state': value['groups'][0]['tasks'][0]['state'] = 'closed'
            if kind == 'remove': value['evidence'].pop()
            if kind == 'verdict': value['confirmed_vulnerabilities'] = 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                evidence.validate_review_evidence(value, *self.args)

    def test_limits_are_visible_not_silent(self):
        value = self.build(max_lines=2, max_definitions=1)
        self.assertTrue(any(f['truncated'] for f in value['evidence']))
        self.assertFalse(value['groups'][0]['definition_traversal_complete'])
        self.assertEqual(value['group_count'], 1)

    def test_invalid_resource_settings_before_source_reads(self):
        for setting in ({'depth': 0}, {'depth': True}, {'max_lines': 401}, {'max_definitions': -1},
                        {'max_callsites': 1.5}, {'group_ids': ['x', 'x']}):
            with self.subTest(setting=setting), patch.object(evidence, '_load') as load:
                with self.assertRaises(ValueError): self.build(**setting)
                load.assert_not_called()

    def test_unknown_group_is_not_silently_ignored(self):
        with self.assertRaises(ValueError): self.build(group_ids=['unknown'])

    def test_source_and_context_changes_rejected(self):
        (self.f.source / 'a.c').write_text(SOURCE + '\n', encoding='utf-8')
        with self.assertRaises(ValueError): self.build()

    def test_mutation_during_expansion_blocks_publication(self):
        original = evidence._expand
        def changed(*args, **kw):
            result = original(*args, **kw)
            (self.f.source / 'a.c').write_text(SOURCE + '\n', encoding='utf-8')
            return result
        with patch.object(evidence, '_expand', side_effect=changed):
            with self.assertRaises(ValueError):
                evidence.write_review_evidence(*self.args, self.output)
        self.assertFalse(self.output.exists())

    def test_output_is_new_and_never_inside_source(self):
        evidence.write_review_evidence(*self.args, self.output)
        before = self.output.read_bytes()
        with self.assertRaises(ValueError): evidence.write_review_evidence(*self.args, self.output)
        self.assertEqual(before, self.output.read_bytes())
        with self.assertRaises(ValueError): evidence.write_review_evidence(*self.args, self.f.source / 'no.json')
        self.assertFalse((self.f.source / 'no.json').exists())

    def test_cli_and_schema_validation_without_network(self):
        args = ['--summary', str(self.args[0]), '--queue', str(self.args[1]), '--context', str(self.context),
                '--source-root', 'one=' + str(self.f.source), '--output', str(self.output)]
        self.assertEqual(evidence.main(args), 0)
        self.assertEqual(evidence.main(args[:-2] + ['--verify', str(self.output)]), 0)

    def test_byte_limits_reject_instead_of_dropping_context(self):
        with patch.object(evidence, 'MAX_OUTPUT_BYTES', 64):
            with self.assertRaises(ValueError): self.build()

    def test_empty_selection_cannot_hide_nonempty_queue(self):
        with self.assertRaises(ValueError): self.build(group_ids=[])

    def test_zero_findings_document_is_independently_verifiable(self):
        self.f.result['findings'] = []
        self.f.result['evidence_bundles'] = []
        self.f.summary['candidate_findings'] = self.f.job['candidate_findings'] = 0
        self.f.persist()
        self.f.output.unlink()
        self.context.unlink()
        review_queue.write_review_queue(self.f.summary_path, self.f.output)
        review_context.write_review_context(self.f.output, self.f.summary_path, self.roots, self.context)
        value = self.build()
        self.assertEqual(value['groups'], [])
        self.assertEqual(len(value['source_roots']), 1)
        evidence.validate_review_evidence(value, *self.args)


if __name__ == '__main__':
    unittest.main()
