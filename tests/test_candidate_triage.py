"""Evidence retention and misleading-priority regression tests."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from ohvul.candidate_triage import build_triage, main
from ohvul.detect.scanner import scan_path
from ohvul.engine_adapter import normalize_findings, engine_result_to_audit_result


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'src').mkdir()
        (self.root / 'tests').mkdir()
        (self.root / 'src/a.c').write_text('return *p;\nmalloc(n + 1);\nmemcpy(d,s,n);\n')
        (self.root / 'tests/a.c').write_text('return *p;\n')
        self.result = scan_path(self.root)

    def test_lossless_partition_and_no_mutation(self):
        original = copy.deepcopy(self.result)
        work = build_triage(self.result, 'a' * 64)
        refs = [r['alert_id'] for g in work['groups'] for r in g['references']]
        self.assertCountEqual(refs, [f['alert_id'] for f in self.result['findings']])
        self.assertEqual(self.result, original)
        self.assertEqual(work['lane_counts']['syntax_only'], 1)
        self.assertEqual(work['lane_counts']['test_support'], 1)
        self.assertEqual(work['lane_counts']['manual_review'], 2)
        self.assertEqual(work['confirmed_vulnerabilities'], 0)

    def test_engine_null_diagnostic_is_not_lexical_noise(self):
        engine = normalize_findings({'findings': [{'rule': 'core.NullDereference',
            'location': {'file': 'src/a.c', 'line': 1}}]}, engine='clang', source_root=self.root)
        result = engine_result_to_audit_result(engine, source_root=self.root)
        self.assertEqual(build_triage(result, 'b' * 64)['lane_counts']['manual_review'], 1)

    def test_changed_evidence_is_rejected(self):
        self.result['findings'][0]['evidence']['code'] = 'changed'
        with self.assertRaises(ValueError):
            build_triage(self.result, 'a' * 64)

    def test_duplicate_ids_are_rejected(self):
        self.result['findings'].append(copy.deepcopy(self.result['findings'][0]))
        with self.assertRaises(ValueError):
            build_triage(self.result, 'a' * 64)

    def test_cli_verifies_counts_and_refuses_overwrite(self):
        source, output = self.root / 'result.json', self.root / 'triage.json'
        source.write_text(json.dumps(self.result), encoding='utf-8')
        args = ['--result', str(source)]
        self.assertEqual(main(args + ['--output', str(output)]), 0)
        self.assertEqual(main(args + ['--verify', str(output)]), 0)
        self.assertEqual(main(args + ['--output', str(output)]), 1)
        value = json.loads(output.read_text(encoding='utf-8'))
        value['groups'].pop()
        output.write_text(json.dumps(value), encoding='utf-8')
        self.assertEqual(main(args + ['--verify', str(output)]), 1)
