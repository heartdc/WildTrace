import unittest
from ohvul.isolation_contract import validate_input, validate_output

class IsolationContractTests(unittest.TestCase):
 def test_scalar_synthetic_input_only(self):
  self.assertTrue(validate_input({'id':'x','input':'synthetic','max_bytes':1024,'timeout_ms':1000}))
  with self.assertRaises(ValueError): validate_input({'id':'x','input':{'path':'source.c'},'max_bytes':1024,'timeout_ms':1000})
  with self.assertRaises(ValueError): validate_input({'id':'x','input':'x','max_bytes':0,'timeout_ms':1000})
  with self.assertRaises(ValueError): validate_input({'id':'x','input':'long','max_bytes':2,'timeout_ms':1000})
 def test_review_only_output(self):
  self.assertTrue(validate_output({'verdict':'undetermined','review_required':True,'no_target_execution':True}))
  with self.assertRaises(ValueError): validate_output({'verdict':'confirmed','review_required':True,'no_target_execution':True})
