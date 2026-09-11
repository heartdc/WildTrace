import tempfile, unittest
from pathlib import Path
from ohvul.shards import build_manifest, scan_shard, merge_shard_results
from ohvul.verify import validate_result

class ShardScanTests(unittest.TestCase):
 def test_only_manifest_files_are_scanned(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); (root/'a.c').write_text('void f(char*d,const char*s){strcpy(d,s);}')
   (root/'b.c').write_text('void g(char*d,const char*s){strcpy(d,s);}')
   manifest=build_manifest(root,1)
   result=scan_shard(root, manifest['shards'][0])
   self.assertEqual(result['scan']['files_scanned'],1)
   self.assertEqual(result['findings'][0]['location']['file'],'a.c')
 def test_invalid_shard_rejected(self):
   with self.assertRaises(ValueError): scan_shard('.', {'files':[1]})
 def test_merge_is_deterministic_and_root_bound(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); (root/'a.c').write_text('void f(char*d,const char*s){strcpy(d,s);}')
   result=scan_shard(root, build_manifest(root,1)['shards'][0]); merged=merge_shard_results([result],root)
   self.assertEqual(merged['findings'][0]['alert_id'],'AL-000001')
   self.assertEqual(validate_result(merged), 1)
   with self.assertRaises(ValueError): merge_shard_results([result], Path(d)/'other')
   altered=dict(result); altered['evidence_bundles']=[dict(result['evidence_bundles'][0], artifacts=[])]
   with self.assertRaises(ValueError): merge_shard_results([result, altered], root)
