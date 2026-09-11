import unittest
from ohvul.branch_impact import compare_findings

class BranchImpactTests(unittest.TestCase):
 def test_compares_local_results_deterministically(self):
  safety={'local_only':True}; a={'safety':safety,'findings':[{'evidence_id':'a'}]}; b={'safety':safety,'findings':[{'evidence_id':'b'}]}
  self.assertEqual(compare_findings(a,b),{'schema':'0.1','added_evidence_ids':['b'],'removed_evidence_ids':['a'],'unchanged_count':0,'review_required':True})
