import unittest
from ohvul.impact_report import build_impact_report, validate_impact_report

class ImpactReportTests(unittest.TestCase):
 def test_report_is_review_only_and_bound(self):
  r={'schema_version':'0.3','scan':{'root':'/src'},'safety':{'local_only':True},'findings':[]}
  report=build_impact_report(r,r); self.assertTrue(validate_impact_report(report)); self.assertEqual(report['verdict'],'undetermined')

  from ohvul.impact_report import project_for_review
  projected=project_for_review(report,'task'); self.assertEqual(projected['workflow']['task_id'],'task'); self.assertEqual(projected['assessment']['confirmed_vulnerabilities'],0)
  from ohvul.report.review import create_review, validate_review
  review=create_review(projected,'reviewer','approved_for_verification'); self.assertTrue(validate_review(review,projected)); self.assertFalse(review['final_vulnerability_verdict'])
  with self.assertRaises(ValueError): project_for_review(report,'')
