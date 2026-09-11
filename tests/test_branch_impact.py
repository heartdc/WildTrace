import unittest
from ohvul.branch_impact import compare_findings, validate_patch_scope, make_impact_draft, validate_impact_draft

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




 def test_malformed_findings_rejected(self):
  base={'schema_version':'0.3','scan':{'root':'/x'},'safety':{'local_only':True}}
  with self.assertRaises(ValueError): compare_findings(dict(base, findings=[{'evidence_id':1}]), dict(base, findings=[]))

 def test_cli_success_path(self):
  import json, tempfile, subprocess, sys
  from pathlib import Path
  base={'schema_version':'0.3','scan':{'root':'/src'},'safety':{'local_only':True},'findings':[]}
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a.json'; b=Path(d)/'b.json'; a.write_text(json.dumps(base)); b.write_text(json.dumps(base))
   proc=subprocess.run([sys.executable,'-m','ohvul.branch_impact',str(a),str(b)],capture_output=True,text=True)
  self.assertEqual(proc.returncode,0); self.assertEqual(json.loads(proc.stdout)['unchanged_count'],0)

 def test_patch_hashes_verify_local_file(self):
  import tempfile, hashlib
  from pathlib import Path
  from ohvul.branch_impact import verify_patch_hashes
  with tempfile.TemporaryDirectory() as d:
   Path(d,'a.c').write_text('x'); digest=hashlib.sha256(b'x').hexdigest()
   self.assertEqual(verify_patch_hashes(d,{'a.c':digest})['a.c'],digest)

 def test_patch_digest_format_rejected(self):
  import tempfile
  from ohvul.branch_impact import verify_patch_hashes
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError): verify_patch_hashes(d,{'a.c':'bad'})

 def test_impact_draft_remains_candidate_only(self):
  from ohvul.branch_impact import make_impact_draft
  base={'schema_version':'0.3','scan':{'root':'/src'},'safety':{'local_only':True},'findings':[]}
  draft=make_impact_draft(base,base)
  self.assertEqual(draft['assessment']['status'],'candidate_only')
  self.assertEqual(draft['assessment']['confirmed_vulnerabilities'],0)
  self.assertTrue(draft['assessment']['review_required'])

