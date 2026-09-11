import unittest
from ohvul.performance import benchmark_scan

class PerformanceTests(unittest.TestCase):
 def test_bounded_synthetic_benchmark(self):
  result=benchmark_scan(files=2, lines=3)
  self.assertEqual(result['files'],2); self.assertTrue(result['local_only']); self.assertTrue(result['no_execution'])
 def test_bounds_rejected(self):
  with self.assertRaises(ValueError): benchmark_scan(files=0)
