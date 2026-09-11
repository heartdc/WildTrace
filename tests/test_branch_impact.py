import unittest
from ohvul.branch_impact import compare_findings, validate_patch_scope

class BranchImpactTests(unittest.TestCase):
 def test_compares_local_results_deterministically(self):
  safety={'local_only':True}; a={'schema_version':'0.3','scan':{'root':'/src'},'safety':safety,'findings':[{'evidence_id':'a'}]}; b={'schema_version':'0.3','scan':{'root':'/src'},'safety':safety,'findings':[{'evidence_id':'b'}]}
  self.assertEqual(compare_findings(a,b),{'schema':'0.1','added_evidence_ids':['b'],'removed_evidence_ids':['a'],'unchanged_count':0,'review_required':True})
 def test_patch_scope_rejects_escape(self):
  import tempfile
  with tempfile.TemporaryDirectory() as d:
   self.assertTrue(validate_patch_scope(d,['src/file.c']))
   with self.assertRaises(ValueError): validate_patch_scope(d,['../../outside.c'])
 def test_non_local_result_rejected(self):
  with self.assertRaises(ValueError): compare_findings({'schema_version':'0.3','scan':{'root':'/x'},'safety':{},'findings':[]},{'schema_version':'0.3','scan':{'root':'/x'},'safety':{'local_only':True},'findings':[]})


   with self.assertRaises(ValueError): validate_patch_scope(d,['https://example.invalid/x.c'])

