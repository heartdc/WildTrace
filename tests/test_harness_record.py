import unittest
from ohvul.harness_record import validate_record

class HarnessRecordTests(unittest.TestCase):
 def test_schema_accepts_only_undetermined_review(self):
  self.assertTrue(validate_record({'schema':'0.1','case_id':'x','verdict':'undetermined','review_required':True,'reproducible':True}))
 def test_confirmed_verdict_rejected(self):
  with self.assertRaises(ValueError): validate_record({'schema':'0.1','case_id':'x','verdict':'confirmed','review_required':True,'reproducible':True})
 def test_save_refuses_overwrite(self):
  import tempfile
  from pathlib import Path
  from ohvul.harness_record import save_record
  record={'schema':'0.1','case_id':'x','verdict':'undetermined','review_required':True,'reproducible':True}
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'record.json'; save_record(record,p)
   with self.assertRaises(FileExistsError): save_record(record,p)
