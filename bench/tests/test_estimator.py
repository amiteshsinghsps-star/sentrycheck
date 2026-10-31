"""Tests for bench/estimator.py: suite cost/time estimates."""
import unittest


# Suites that have explicit drivers in estimator.py
KNOWN_SUITES = ("BM-01", "BM-02", "BM-03", "BM-04", "BM-07", "BM-08", "BM-13", "BM-14")


class EstimatorTests(unittest.TestCase):
    def test_estimate_suite_returns_dict_with_required_keys(self):
        from bench.estimator import estimate_suite
        result = estimate_suite("BM-01")
        for key in ("suite", "description", "case_count", "runs_count",
                    "estimated_seconds", "estimated_minutes", "estimated_disk_mb", "peak_rss_mb"):
            self.assertIn(key, result, "estimate_suite result missing key: %s" % key)

    def test_all_known_suites_are_estimable(self):
        from bench.estimator import estimate_suite
        for suite_id in KNOWN_SUITES:
            result = estimate_suite(suite_id)
            self.assertEqual(result["suite"], suite_id)
            self.assertGreaterEqual(result["estimated_minutes"], 0,
                                    "estimated_minutes must be non-negative for %s" % suite_id)
            self.assertGreaterEqual(result["estimated_disk_mb"], 0,
                                    "estimated_disk_mb must be non-negative for %s" % suite_id)

    def test_unknown_suite_returns_zero_estimate(self):
        """Unknown suites return a zeroed estimate (graceful fallback, not an error)."""
        from bench.estimator import estimate_suite
        result = estimate_suite("BM-99")
        # Either returns a result with 0 estimates, or raises KeyError — both are acceptable
        self.assertEqual(result["suite"], "BM-99")
        self.assertEqual(result["estimated_seconds"], 0)

    def test_numeric_fields_are_non_negative(self):
        from bench.estimator import estimate_suite
        for suite_id in KNOWN_SUITES:
            result = estimate_suite(suite_id)
            self.assertGreaterEqual(result["estimated_seconds"], 0)
            self.assertGreaterEqual(result["estimated_disk_mb"], 0)
            self.assertGreaterEqual(result["peak_rss_mb"], 0)
            self.assertGreaterEqual(result["case_count"], 0)
            self.assertGreaterEqual(result["runs_count"], 0)

    def test_description_field_is_non_empty_string_for_known_suites(self):
        from bench.estimator import estimate_suite, SUITE_DESCRIPTIONS
        for suite_id in SUITE_DESCRIPTIONS:
            result = estimate_suite(suite_id)
            self.assertIsInstance(result["description"], str)
            self.assertTrue(result["description"].strip(),
                            "description must not be empty for %s" % suite_id)

    def test_minutes_equals_seconds_divided_by_60(self):
        from bench.estimator import estimate_suite
        for suite_id in KNOWN_SUITES:
            result = estimate_suite(suite_id)
            expected = round(result["estimated_seconds"] / 60.0, 2)
            self.assertAlmostEqual(result["estimated_minutes"], expected, places=1,
                                   msg="minutes must equal seconds/60 for %s" % suite_id)


if __name__ == "__main__":
    unittest.main()
