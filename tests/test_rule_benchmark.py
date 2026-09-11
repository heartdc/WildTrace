import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from ohvul.benchmark import evaluate
from ohvul.detect.scanner import scan_path

class RuleBenchmarkTests(unittest.TestCase):
 def test_benchmark_expected_candidate_categories(self):
  cases=json.loads(pathlib.Path('docs/design/rule_benchmark.json').read_text(encoding='utf-8'))
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)
   for case in cases:
    path=root/(case['id']+'.c')
    path.write_text(case['code'])
    result=scan_path(root)
    findings=[x for x in result['findings'] if x['location']['file']==path.name]
    observed={x['cwe_candidate'] for x in findings}
    self.assertTrue(set(case['expected_cwe']).issubset(observed),case['id'])
    if case['label']=='reviewed_suppressed': self.assertFalse(findings,case['id'])

if __name__=='__main__': unittest.main()

class BenchmarkStatsTests(unittest.TestCase):
 def test_benchmark_reports_candidate_metrics_only(self):
  import subprocess,sys
  proc=subprocess.run([sys.executable,'-m','ohvul.benchmark','docs/design/rule_benchmark.json'],capture_output=True,text=True); self.assertEqual(proc.returncode,0); data=json.loads(proc.stdout); self.assertEqual(data['benchmark_schema'],'0.1'); self.assertIn('precision',data['candidate_metrics']); self.assertIn('Candidate-rule statistics only',data['disclaimer'])

class ExtendedBenchmarkTests(unittest.TestCase):
 def test_extended_cases_are_observed_as_candidates(self):
  import json,pathlib,tempfile
  from ohvul.detect.scanner import scan_path
  cases=json.loads(pathlib.Path('docs/design/rule_benchmark.json').read_text(encoding='utf-8'))
  expected={'integer_length_candidate':'CWE-190','pointer_deref_candidate':'CWE-476'}
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)
   for case in cases:
    if case['id'] not in expected: continue
    path=root/(case['id']+'.c'); path.write_text(case['code']); observed={x['cwe_candidate'] for x in scan_path(root)['findings'] if x['location']['file']==path.name}; self.assertIn(expected[case['id']],observed)

class SafeCounterexampleTests(unittest.TestCase):
 def test_checked_pointer_case_is_kept_as_explicit_false_positive_candidate(self):
  import json,pathlib,tempfile
  from ohvul.detect.scanner import scan_path
  cases=json.loads(pathlib.Path('docs/design/rule_benchmark.json').read_text(encoding='utf-8'))
  case=next(x for x in cases if x['id']=='checked_pointer_safe_control')
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); path=root/(case['id']+'.c'); path.write_text(case['code']); findings=scan_path(root)['findings']; self.assertTrue(any(x['cwe_candidate']=='CWE-476' for x in findings)); self.assertEqual(case['expected_cwe'],[])

class BenchmarkReasonTests(unittest.TestCase):
 def test_every_case_has_explanation_reason(self):
  import json,pathlib
  cases=json.loads(pathlib.Path('docs/design/rule_benchmark.json').read_text(encoding='utf-8'))
  self.assertTrue(cases); self.assertTrue(all(isinstance(x.get('reason'),str) and x['reason'] for x in cases))

class BenchmarkOverlapTests(unittest.TestCase):
 def test_statistics_include_overlap_and_reason(self):
  import subprocess,sys
  proc=subprocess.run([sys.executable,'-m','ohvul.benchmark','docs/design/rule_benchmark.json'],capture_output=True,text=True); data=json.loads(proc.stdout); self.assertIn('rule_overlap_cases',data); self.assertTrue(all('reason' in x and 'rule_overlap' in x for x in data['results']))

class BenchmarkTaxonomyTests(unittest.TestCase):
 def test_cases_have_language_and_component_taxonomy(self):
  import json,pathlib
  cases=json.loads(pathlib.Path('docs/design/rule_benchmark.json').read_text(encoding='utf-8'))
  self.assertTrue(all(x.get('language') and x.get('component') for x in cases))

class BenchmarkInputTests(unittest.TestCase):
 def setUp(self):
  self.case = dict(id='control', code='int f(void){ return 0; }',
                   expected_cwe=[], label='safe_control', reason='Constant return.',
                   language='C', component='control')

 def test_invalid_annotations_rejected_before_io(self):
  variants = [None, {}, [None], [{}], [dict(self.case, extra=True)]]
  for field, value in [('id', ''), ('code', 3), ('reason', ' '),
                       ('component', None), ('language', 'Python'),
                       ('label', 'confirmed'), ('expected_cwe', 'CWE-122'),
                       ('expected_cwe', [None]), ('expected_cwe', ['CWE-0']),
                       ('expected_cwe', ['CWE-122']), ('label', 'candidate')]:
   variants.append([dict(self.case, **{field: value})])
  variants.append([dict(self.case, label='candidate',
                        expected_cwe=['CWE-122', 'CWE-122'])])
  variants.append([self.case, self.case])
  variants.append([self.case, {}])
  with patch('ohvul.benchmark.tempfile.TemporaryDirectory') as temporary:
   for cases in variants:
    with self.subTest(cases=cases), self.assertRaises(ValueError):
     evaluate(cases)
   temporary.assert_not_called()

 def test_case_id_is_metadata_and_language_selects_extension(self):
  for language, filename in [('C', 'sample.c'), ('C++', 'sample.cpp')]:
   def inspect(root):
    self.assertEqual([p.name for p in root.iterdir()], [filename])
    return {'findings': []}
   with patch('ohvul.benchmark.scan_path', side_effect=inspect):
    result = evaluate([dict(self.case, id='display / label', language=language)])
   self.assertEqual(result['results'][0]['id'], 'display / label')

 def test_existing_snapshot_is_unchanged(self):
  root = pathlib.Path(__file__).resolve().parents[1] / 'docs' / 'design'
  cases = json.loads((root / 'rule_benchmark.json').read_text(encoding='utf-8'))
  snapshot = json.loads((root / 'rule_benchmark_report.json').read_text(encoding='utf-8-sig'))
  self.assertEqual(evaluate(cases), snapshot)

 def test_empty_benchmark_has_no_rates(self):
  result = evaluate([])
  self.assertEqual(result['cases'], 0)
  self.assertEqual(result['candidate_metrics'],
                   dict(tp=0, fp=0, fn=0, precision=None, recall=None))

 def test_cli_rejects_invalid_schema_without_traceback(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as directory:
   path = pathlib.Path(directory) / 'invalid.json'
   path.write_text('[{}]', encoding='utf-8')
   proc = subprocess.run([sys.executable, '-m', 'ohvul.benchmark', str(path)],
                         capture_output=True, text=True)
  self.assertEqual(proc.returncode, 1)
  self.assertIn('INVALID: case[0]', proc.stdout)
  self.assertNotIn('Traceback', proc.stderr)
