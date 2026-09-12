import json, tempfile, unittest
from pathlib import Path
from ohvul.knowledge_base import load_records, match_records

class KnowledgeBaseTests(unittest.TestCase):
 def test_local_records_are_versioned_and_hashed(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'kb.json'; p.write_text(json.dumps({'schema':'0.1','records':[{'id':'CVE-2024-1234','cwe':['CWE-120'],'summary':'x','component':'c','affected_versions':['1'],'fixed_versions':['2'],'source':'local'}]}))
   result=load_records(p); self.assertEqual(len(result['records']),1); self.assertEqual(len(result['records_sha256']),64); self.assertEqual(match_records(result,'c','1')[0]['match_level'],'exact'); self.assertEqual(match_records(result,'c','1')[0]['knowledge_base_sha256'],result['records_sha256'])
   self.assertEqual(match_records(result,'c','unknown')[0]['match_level'],'unresolved')
 def test_invalid_id_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'kb.json'; p.write_text(json.dumps({'schema':'0.1','records':[{'id':'bad'}]}))
   with self.assertRaises(ValueError): load_records(p)




 def test_empty_source_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'kb.json'; record={'id':'CVE-2024-1234','cwe':['CWE-120'],'summary':'x','component':'c','affected_versions':['1'],'fixed_versions':['2'],'source':''}; p.write_text(json.dumps({'schema':'0.1','records':[record]}))
   with self.assertRaises(ValueError): load_records(p)

 def test_oversized_file_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'kb.json'; p.write_bytes(b'x' * (16*1024*1024+1))
   with self.assertRaises(ValueError): load_records(p)
