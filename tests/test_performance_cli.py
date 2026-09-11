import subprocess, sys, json, unittest
class PerformanceCliTests(unittest.TestCase):
 def test_cli_outputs_json(self):
  p=subprocess.run([sys.executable,'-m','ohvul.performance','--files','1','--lines','1'],capture_output=True,text=True)
  self.assertEqual(p.returncode,0); self.assertTrue(json.loads(p.stdout)['local_only'])
