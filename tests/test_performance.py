import unittest
from ohvul.performance import benchmark_scan, benchmark_matrix, compare_throughput, validate_performance_result, save_performance_result

class PerformanceTests(unittest.TestCase):
 def test_bounded_synthetic_benchmark(self):
  result=benchmark_scan(files=2, lines=3)
  self.assertEqual(result['files'],2); self.assertTrue(result['local_only']); self.assertTrue(result['no_execution'])
 def test_bounds_rejected(self):
  with self.assertRaises(ValueError): benchmark_scan(files=0)




  with self.assertRaises(ValueError): validate_performance_result(dict(benchmark_scan(files=1,lines=1), files_per_second=-1))

