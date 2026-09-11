import tempfile, pathlib, unittest
from ohvul.detect.scanner import scan_path
class ScannerTests(unittest.TestCase):
 def test_local_scan_emits_candidate(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"x.c"; p.write_text("void f(char *p){ strcpy(p, \"x\"); }\n")
   r=scan_path(pathlib.Path(d)); self.assertEqual(r["scan"]["files_scanned"],1); self.assertTrue(r["findings"]); self.assertTrue(r["safety"]["local_only"])
if __name__=="__main__": unittest.main()

class RuleQualityTests(unittest.TestCase):
 def test_explicit_ignore_is_local_and_traceable(self):
  from ohvul.detect.scanner import scan_path
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'a.c').write_text('strcpy(d,s); // ohvul:ignore\nmemcpy(d,s,n);')
   result=scan_path(root); self.assertEqual(len(result['findings']),1); self.assertEqual(result['findings'][0]['location']['line'],2)
 def test_ignore_does_not_hide_other_lines(self):
  from ohvul.detect.scanner import scan_path
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'a.c').write_text('strcpy(d,s); // ohvul:ignore\nstrcpy(d,s);')
   self.assertEqual(len(scan_path(root)['findings']),1)
