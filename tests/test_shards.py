import tempfile, unittest
from pathlib import Path
from ohvul.shards import build_manifest

class ShardTests(unittest.TestCase):
 def test_deterministic_and_filters_extensions(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); (root/'b.cpp').write_text('x'); (root/'a.c').write_text('x'); (root/'note.txt').write_text('x')
   one=build_manifest(root,1); two=build_manifest(root,1)
   self.assertEqual(one,two); self.assertEqual(one['files'],2); self.assertEqual([s['files'] for s in one['shards']], [['a.c'],['b.cpp']])
 def test_invalid_size_rejected(self):
  with self.assertRaises(ValueError): build_manifest('.',0)
 def test_resource_limit_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'a.c').write_text('x')
   with self.assertRaises(ValueError): build_manifest(d,max_files=0)
   with self.assertRaises(ValueError): build_manifest(d,max_files=0)
