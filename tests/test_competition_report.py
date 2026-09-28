import json
import tempfile
import unittest
from pathlib import Path

from ohvul.competition_report import assemble, project_case, render_markdown


def _write(root: Path, name: str, record: dict):
    (root / name).mkdir()
    (root / name / 'case.json').write_text(json.dumps(record, ensure_ascii=False), encoding='utf-8')


class CompetitionReportTests(unittest.TestCase):
    def _root(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def test_legacy_schema_case_projects_with_unknowns(self):
        root = self._root()
        _write(root, 'legacy-case', {
            'id': 'legacy', 'component': 'third_party/curl',
            'cve_reference': 'CVE-2026-82209', 'cwe_candidate': 'CWE-201',
            'new_discovery': False, 'discovery_method': 'version probe',
            'runtime_status': 'not_run',
            'submission': {'ticket': 'OHSA26-092226014', 'status': '已提交'},
        })
        report = assemble(root)
        case = report['cases'][0]
        self.assertEqual(case['cve'], 'CVE-2026-82209')
        self.assertEqual(case['submission']['ticket'], 'OHSA26-092226014')
        self.assertEqual(case['submission']['official_status'], 'unknown')
        self.assertIn('product_impact', case['missing_dimensions'])
        self.assertFalse(case['confirmed_vulnerability'])
        self.assertEqual(report['confirmed_vulnerabilities'], 0)
        self.assertEqual(report['completeness']['submission_record'], 1)
        self.assertEqual(report['completeness']['product_impact'], 0)

    def test_candidate_schema_case_projects_validation_evidence(self):
        root = self._root()
        _write(root, 'ipc-case', {
            'schema': 'wildtrace-candidate-case-0.2', 'case_id': 'ipc-x',
            'component': 'foundation/ipc', 'confirmed_vulnerability': False,
            'candidate': {'source': 'a.cpp', 'lines': [1]},
            'validation_evidence': {'asan': 'zero-page SEGV', 'platform_binary_linked': False},
            'runtime_scope': {'open_harmony_binary_linked': False},
        })
        report = assemble(root)
        case = report['cases'][0]
        self.assertEqual(case['runtime_status'], 'equivalent_reproduction')
        self.assertTrue(case['evidence_dimensions']['equivalent_or_runtime_reproduction'])
        self.assertFalse(case['evidence_dimensions']['product_impact'])
        self.assertEqual(case['submission']['ticket'], 'none')

    def test_confirmed_flag_is_projected_never_inferred(self):
        root = self._root()
        _write(root, 'confirmed-case', {
            'case_id': 'c', 'component': 'x', 'confirmed_vulnerability': True,
            'cwe_candidate': ['CWE-416'],
        })
        report = assemble(root)
        self.assertEqual(report['confirmed_vulnerabilities'], 1)
        self.assertTrue(report['cases'][0]['confirmed_vulnerability'])

    def test_minimal_record_stays_explicitly_unknown(self):
        case = project_case({'case_id': 'bare'}, 'bare-dir')
        self.assertEqual(case['cve'], 'none')
        self.assertEqual(case['cwe'], ['unknown'])
        self.assertEqual(case['discovery_method'], 'unknown')
        self.assertEqual(case['runtime_status'], 'unknown')
        self.assertEqual(case['missing_dimensions'], [
            'source_verification', 'equivalent_or_runtime_reproduction', 'product_impact',
            'fix_reference', 'submission_record', 'official_acceptance'])

    def test_deterministic_ordering_and_statement(self):
        root = self._root()
        _write(root, 'b-case', {'case_id': 'b'})
        _write(root, 'a-case', {'case_id': 'a'})
        report = assemble(root)
        self.assertEqual([c['case'] for c in report['cases']], ['a-case', 'b-case'])
        self.assertIn('not inferred', report['statement'])

    def test_markdown_renders_matrix_and_unknowns(self):
        root = self._root()
        _write(root, 'legacy-case', {
            'id': 'legacy', 'cve_reference': 'CVE-1', 'cwe_candidate': 'CWE-201',
            'submission': {'ticket': 'T1', 'status': 's'},
        })
        text = render_markdown(assemble(root))
        self.assertIn('## 证据完整度矩阵', text)
        self.assertIn('legacy-case', text)
        self.assertIn('缺失维度', text)
        self.assertIn('确认产品漏洞数：0', text)


if __name__ == '__main__':
    unittest.main()
