from pathlib import Path
import copy
import pathlib
import tempfile
import unittest
from ohvul.detect.scanner import scan_path
from ohvul.domain.evidence import make_bundle, validate_bundle
from ohvul.verify import validate_result
from ohvul.workflow.fsm import save_checkpoint, WorkflowCheckpoint

class IntegrityTests(unittest.TestCase):
    def test_source_and_environment_changes_detected(self):
        original = make_bundle('static_scan', {'file': 'test.c'}).to_dict()
        validate_bundle(original)
        for field in ('source', 'environment'):
            changed = copy.deepcopy(original)
            changed[field]['changed'] = True
            with self.assertRaises(ValueError):
                validate_bundle(changed)

    def test_saved_result_references_and_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'test.c').write_text('memcpy(dst, src, length);')
            result = scan_path(root)
            self.assertGreater(validate_result(result), 0)
            changed = copy.deepcopy(result)
            changed['findings'][0]['evidence']['code'] = 'modified'
            with self.assertRaises(ValueError):
                validate_result(changed)
            result['evidence_bundles'] = []
            with self.assertRaises(ValueError):
                validate_result(result)

    def test_legacy_and_empty_objects_rejected(self):
        for value in ({}, {'schema_version': '0.2'}, []):
            with self.assertRaises(ValueError):
                validate_result(value)


    def test_output_overwrite_requires_force(self):
        # CLI policy is exercised by the integration command in the test body.
        import subprocess, sys
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root / "source"; source.mkdir()
            (source / "a.c").write_text("memcpy(d,s,n);")
            output=root / "result.json"
            command=[sys.executable, "-m", "ohvul.cli", str(source), "--output", str(output)]
            self.assertEqual(subprocess.run(command).returncode, 0)
            self.assertNotEqual(subprocess.run(command).returncode, 0)
            forced=command+["--force"]
            self.assertEqual(subprocess.run(forced).returncode, 0)



class PathSafetyTests(unittest.TestCase):
 def test_output_inside_source_is_rejected(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory); source=root/'source'; source.mkdir(); output=source/'result.json'
   proc=subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--output',str(output)])
   self.assertNotEqual(proc.returncode,0); self.assertFalse(output.exists())

 def test_database_cannot_be_overwritten(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory); source=root/'source'; source.mkdir(); db=root/'db.json'; db.write_text('[]')
   proc=subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--vuln-db',str(db),'--output',str(db),'--force'])
   self.assertNotEqual(proc.returncode,0); self.assertEqual(db.read_text(),'[]')


class LinkSafetyTests(unittest.TestCase):
 def test_checkpoint_symlink_is_rejected(self):
  import os
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); target=root/'target.json'; target.write_text('unchanged'); link=root/'checkpoint.json'
   try: link.symlink_to(target)
   except (OSError, NotImplementedError): self.skipTest('symlink unavailable')
   with self.assertRaises(ValueError): save_checkpoint(WorkflowCheckpoint('x'),link,force=True)
   self.assertEqual(target.read_text(),'unchanged')

class ScanInputGateTests(unittest.TestCase):
 def test_source_snapshot_gate_function_rejects_different_snapshot(self):
  from ohvul.source_snapshot import source_snapshot
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'a.c').write_text('one'); first=source_snapshot(root); (root/'a.c').write_text('two'); self.assertNotEqual(first,source_snapshot(root))


