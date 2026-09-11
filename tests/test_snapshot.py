import pathlib, tempfile, unittest
from ohvul.source_snapshot import source_snapshot
class SourceSnapshotTests(unittest.TestCase):
 def test_snapshot_is_deterministic_and_changes_with_content(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'b.c').write_text('b'); (root/'a.c').write_text('a')
   first=source_snapshot(root); self.assertEqual(first,source_snapshot(root)); (root/'a.c').write_text('changed'); self.assertNotEqual(first,source_snapshot(root))
 def test_symlinks_are_not_included(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); real=root/'real.c'; real.write_text('x'); link=root/'link.c'
   try: link.symlink_to(real)
   except (OSError,NotImplementedError): self.skipTest('symlink unavailable')
   only=source_snapshot(root); link.unlink(); self.assertEqual(only,source_snapshot(root))
if __name__=='__main__': unittest.main()
