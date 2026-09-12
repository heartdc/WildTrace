import tempfile, unittest
from pathlib import Path
from ohvul.git_scope import validate_scope
class GitScopeTests(unittest.TestCase):
 def test_local_scope_is_normalized(self):
  with tempfile.TemporaryDirectory() as d:
   result=validate_scope({'source_root':d,'revision':'v1.0.0','branch':'master','since':'2024-01-01','until':'2024-12-31','components':['foundation','foundation']})
   self.assertEqual(result['components'],['foundation']); self.assertTrue(Path(result['source_root']).is_absolute())
 def test_remote_and_invalid_ranges_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   base={'source_root':d,'revision':'v1','branch':'master','since':'2024-02-01','until':'2024-01-01','components':['x']}
   with self.assertRaises(ValueError): validate_scope(base)
   with self.assertRaises(ValueError): validate_scope(dict(base,since='2024-01-01',until='2024-02-01',revision='https://example.invalid/ref'))

 def test_inspect_local_revision(self):
  import subprocess
  root=Path(__file__).resolve().parents[1]
  scope={'source_root':str(root),'revision':'HEAD','branch':'master','since':'2024-01-01','until':'2030-01-01','components':['ohvul']}
  result=__import__('ohvul.git_scope',fromlist=['inspect_revision']).inspect_revision(scope)
  self.assertEqual(result['schema'],'0.1'); self.assertTrue(result['local_only']); self.assertEqual(len(result['commit']),40)
