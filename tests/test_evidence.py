import tempfile, pathlib, unittest
from ohvul.detect.scanner import scan_path
class EvidenceTests(unittest.TestCase):
 def test_finding_references_bundle(self):
  with tempfile.TemporaryDirectory() as d:
   (pathlib.Path(d)/"x.c").write_text('void f(char *p){ strcpy(p,"x"); }')
   r=scan_path(pathlib.Path(d)); self.assertEqual(len(r["findings"]),1); self.assertEqual(r["findings"][0]["evidence_id"],r["evidence_bundles"][0]["evidence_id"])
if __name__=="__main__": unittest.main()
