import unittest

from tools.kb_gap_audit import baseline_in_affected


class VersionBoundaryTests(unittest.TestCase):
    def test_less_than_or_equal_includes_upper_endpoint(self):
        affected = [{"versions": [{
            "status": "affected", "version": "1.0", "lessThanOrEqual": "1.2"
        }]}]
        self.assertEqual(baseline_in_affected("1.2", affected), "covered")

    def test_less_than_excludes_upper_endpoint(self):
        affected = [{"versions": [{
            "status": "affected", "version": "1.0", "lessThan": "1.2"
        }]}]
        self.assertEqual(baseline_in_affected("1.2", affected), "outside")

    def test_less_than_takes_precedence_when_both_bounds_exist(self):
        affected = [{"versions": [{
            "status": "affected", "version": "1.0",
            "lessThan": "1.2", "lessThanOrEqual": "1.3"
        }]}]
        self.assertEqual(baseline_in_affected("1.2", affected), "outside")


if __name__ == "__main__":
    unittest.main()
