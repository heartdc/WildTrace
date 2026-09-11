import unittest
from ohvul.impact_report import build_impact_report, validate_impact_report

class ImpactReportTests(unittest.TestCase):
 def test_report_is_review_only_and_bound(self):
  r={'schema_version':'0.3','scan':{'root':'/src'},'safety':{'local_only':True},'findings':[]}
  report=build_impact_report(r,r); self.assertTrue(validate_impact_report(report)); self.assertEqual(report['verdict'],'undetermined')
