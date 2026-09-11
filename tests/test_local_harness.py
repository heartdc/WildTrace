import unittest
from ohvul.local_harness import evaluate_synthetic

class LocalHarnessTests(unittest.TestCase):
 def test_synthetic_case_stays_undetermined(self):
  result=evaluate_synthetic(workflow_state='static_scan', recheck_results=[{'reproducible':True}], synthetic_case={'id':'case-1','input':'x','max_bytes':10,'timeout_ms':1000})
  self.assertTrue(result['ready']); self.assertTrue(result['review_required']); self.assertEqual(result['verdict'],'undetermined'); self.assertTrue(result['no_target_execution'])
 def test_gate_failure_is_preserved(self):
  result=evaluate_synthetic(workflow_state='intake', recheck_results=[], synthetic_case={'id':'case-2','input':'x','max_bytes':10,'timeout_ms':1000})
  self.assertFalse(result['ready']); self.assertEqual(result['verdict'],'undetermined')
