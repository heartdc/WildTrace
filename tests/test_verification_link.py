import unittest
from ohvul.verification_link import make_link, validate_link

class VerificationLinkTests(unittest.TestCase):
 def test_link_binds_record(self):
  record={'schema':'0.1','case_id':'x','verdict':'undetermined','review_required':True,'reproducible':True}
  link=make_link('task','a'*64,record); self.assertTrue(validate_link(link,record))
  with self.assertRaises(ValueError): validate_link(dict(link, checkpoint_sha256='z'*64),record)
  record['case_id']='y'
  with self.assertRaises(ValueError): validate_link(link,record)
 def test_save_link_refuses_overwrite(self):
  import tempfile
  from pathlib import Path
  from ohvul.verification_link import save_link
  record={'schema':'0.1','case_id':'x','verdict':'undetermined','review_required':True,'reproducible':True}
  link=make_link('task','a'*64,record)
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'link.json'; save_link(link,p,record)
   with self.assertRaises(FileExistsError): save_link(link,p,record)
