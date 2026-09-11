import tempfile, unittest
from pathlib import Path
from ohvul.local_recheck import recheck_finding

class LocalRecheckTests(unittest.TestCase):
 def test_rechecks_line_hash_without_execution(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'a.c').write_text('int x;\n')
   finding={'location':{'file':'a.c','line':1},'evidence':{'line_hash':'d3e1'}}
   finding['evidence']['line_hash']='d3e1'
   import hashlib
   finding['evidence']['line_hash']=hashlib.sha256(b'int x;').hexdigest()[:16]
   result=recheck_finding(d,finding)
   self.assertTrue(result['reproducible']); self.assertTrue(result['no_execution'])
 def test_missing_location_is_not_confirmed(self):
  result=recheck_finding('.', {'location':{'file':'missing.c','line':1},'evidence':{'line_hash':'x'}})
  self.assertFalse(result['reproducible'])
