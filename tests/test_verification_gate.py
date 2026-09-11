import unittest
from ohvul.verification_gate import can_request_local_verification, request_local_verification_transition

class VerificationGateTests(unittest.TestCase):
 def test_requires_static_scan_and_reproducible_evidence(self):
  self.assertEqual(can_request_local_verification(workflow_state='intake', recheck_results=[{'reproducible':True}])[0],False)
  self.assertEqual(can_request_local_verification(workflow_state='static_scan', recheck_results=[])[0],False)
  self.assertEqual(can_request_local_verification(workflow_state='static_scan', recheck_results=[{'reproducible':False}])[0],False)
  self.assertEqual(can_request_local_verification(workflow_state='static_scan', recheck_results=[{'reproducible':True}])[0],True)
  self.assertEqual(request_local_verification_transition(workflow_state='static_scan', recheck_results=[{'reproducible':True}]), 'local_verification')
