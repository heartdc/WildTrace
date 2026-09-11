import tempfile, pathlib, unittest, json
from ohvul.detect.vuln_metadata import load_vulnerability_metadata, match_components, strip_internal_bundles
class MetadataTests(unittest.TestCase):
 def test_local_metadata_matches_component_and_version(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"db.json"; p.write_text(json.dumps([{"id":"CVE-TEST","component":"demo","version":"1.2.3","cwe":"CWE-122"}]))
   db=load_vulnerability_metadata(p); r=match_components([{"name":"demo","version":"1.2.3"}],db); clean,b=strip_internal_bundles(r)
   self.assertEqual(clean[0]["matches"][0]["id"],"CVE-TEST"); self.assertEqual(clean[0]["matches"][0]["evidence_id"],b[0]["evidence_id"])
if __name__=="__main__": unittest.main()

class MetadataNegativeTests(unittest.TestCase):
 def test_unknown_versions_never_become_exact_matches(self):
  for version in (None, '', 'unknown', '*'):
   with self.subTest(version=version):
    result=match_components([{'name':'demo','version':version}], [{'id':'TEST','component':'demo','version':'1.2.3'}])[0]
    self.assertEqual(result['matches'], [])
    self.assertEqual(result['unresolved'][0]['match_status'], 'unknown')

 def test_unspecified_record_version_is_not_a_wildcard(self):
  result=match_components([{'name':'demo','version':'1.2.3'}], [{'id':'TEST','component':'demo'}])[0]
  self.assertFalse(result['matches'])
  self.assertEqual(len(result['unresolved']),1)

 def test_different_versions_do_not_match(self):
  result=match_components([{'name':'demo','version':'2.0'}], [{'id':'TEST','component':'demo','version':'1.0'}])[0]
  self.assertFalse(result['matches'])
  self.assertFalse(result['unresolved'])

 def test_invalid_records_are_not_silently_discarded(self):
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'db.json'
   for records in ([None], [{'component':'demo'}], [{'id':'TEST','component':'demo','version':123}]):
    path.write_text(json.dumps(records),encoding='utf-8')
    with self.assertRaises(ValueError):
     load_vulnerability_metadata(path)
