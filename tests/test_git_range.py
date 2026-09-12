import unittest
from pathlib import Path
from ohvul.git_scope import inspect_range
class GitRangeTests(unittest.TestCase):
 def test_local_range_is_deterministic(self):
  root=Path(__file__).resolve().parents[1]
  scope={'source_root':str(root),'revision':'HEAD','branch':'master','since':'2020-01-01','until':'2030-01-01','components':['ohvul']}
  result=inspect_range(scope)
  self.assertTrue(result['local_only']); self.assertTrue(result['commits']); self.assertTrue(all(isinstance(x,str) for x in result['changed_files']))
