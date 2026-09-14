import tempfile, pathlib, unittest
from ohvul.detect.scanner import scan_path
class ScannerTests(unittest.TestCase):
 def test_scan_does_not_call_network_or_llm(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   pathlib.Path(d,'x.c').write_text('int x;')
   with patch('urllib.request.urlopen', side_effect=AssertionError('network call')):
    scan_path(d)
 def test_symlink_sources_are_skipped(self):
  import tempfile, os
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'real.c').write_text('int x;')
   try: os.symlink(root/'real.c', root/'linked.c')
   except (OSError, NotImplementedError): self.skipTest('symlink unavailable')
   self.assertEqual(scan_path(root)['scan']['files_scanned'],1)
 def test_local_scan_emits_candidate(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"x.c"; p.write_text("void f(char *p){ strcpy(p, \"x\"); }\n")
   r=scan_path(pathlib.Path(d)); self.assertEqual(r["scan"]["files_scanned"],1); self.assertTrue(r["findings"]); self.assertTrue(r["safety"]["local_only"])
 def test_explicit_file_list_reads_only_listed_paths(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'a.c').write_text('strcpy(d,s);'); (root/'b.c').write_text('strcpy(d,s);')
   result=scan_path(root, relative_files=['a.c'])
   self.assertEqual(result['scan']['files_scanned'],1)
   self.assertEqual({x['location']['file'] for x in result['findings']},{'a.c'})
 def test_explicit_file_list_rejects_escape(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError): scan_path(pathlib.Path(d), relative_files=['../outside.c'])
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
