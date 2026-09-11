import tempfile, pathlib, unittest
from ohvul.detect.components import identify_components
class ComponentTests(unittest.TestCase):
 def test_marker_and_version_are_read_only(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"demo"; p.mkdir(); (p/"README.md").write_text("Version: 1.2.3\n")
   r=identify_components(pathlib.Path(d)); self.assertEqual(r[0]["version"],"1.2.3"); self.assertEqual(r[0]["marker"],"README.md")
if __name__=="__main__": unittest.main()
