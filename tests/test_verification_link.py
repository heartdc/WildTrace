import unittest
from ohvul.verification_link import make_link, validate_link

class VerificationLinkTests(unittest.TestCase):
 def test_link_binds_record(self):
  record={'schema':'0.1','case_id':'x','verdict':'undetermined','review_required':True,'reproducible':True}
  link=make_link('task','a'*64,record); self.assertTrue(validate_link(link,record))
  record['case_id']='y'
  with self.assertRaises(ValueError): validate_link(link,record)
