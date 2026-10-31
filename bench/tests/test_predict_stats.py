"""BT-01 mapping and PRD 4.3 estimator tests, checked against hand-computed references."""
import unittest

from bench import predict, stats


def report(status="complete", tier="dynamic-runsc-diff", severities=(), fallback=(), reasons=(), dynamic=True):
    findings = [{"severity": value, "rule_id": "r-%s" % value} for value in severities]
    payload = {"schema_version": "1.0", "status": status, "incomplete_reasons": list(reasons),
               "findings": findings}
    if dynamic:
        payload["dynamic"] = {"evidence_tier": tier, "fallback_observations": list(fallback)}
    return payload


class PredictTests(unittest.TestCase):
    def test_severity_ladder_ordering(self):
        self.assertEqual(predict.predict(report(severities=["hard-failure"]))["class"], "hard-failure")
        self.assertEqual(predict.predict(report(severities=["hard-failure", "silent-degradation"]))["class"],
                         "hard-failure")
        self.assertEqual(predict.predict(report(severities=["silent-degradation", "performance-regression"]))["class"],
                         "silent-degradation")
        self.assertEqual(predict.predict(report(severities=["performance-regression"]))["class"],
                         "performance-regression")

    def test_fallback_observation_is_tolerated(self):
        payload = report(fallback=[{"syscall": "io_uring_setup", "resolution": "fallback"}])
        self.assertEqual(predict.predict(payload)["class"], "tolerated")

    def test_clean_dynamic_run_is_compatible(self):
        self.assertEqual(predict.predict(report())["class"], "compatible")
        self.assertEqual(predict.predict(report(severities=["compatibility-risk"]))["class"], "compatible")

    def test_static_only_never_becomes_compatible(self):
        payload = report(status="incomplete", tier="static-only", reasons=["Static-only scan: capability candidates are unconfirmed."])
        result = predict.predict(payload)
        self.assertEqual(result["class"], "indeterminate")
        self.assertEqual(result["incomplete_reason_codes"], ["static-only"])
        self.assertFalse(result["complete"])

    def test_hard_failure_without_dynamic_tier_is_not_claimed(self):
        payload = report(status="incomplete", tier="static-only", severities=["hard-failure"])
        result = predict.predict(payload)
        self.assertNotEqual(result["class"], "hard-failure", "a static candidate cannot establish a hard failure")

    def test_incomplete_with_observation_keeps_class_and_flags_reason(self):
        payload = report(status="incomplete", severities=["silent-degradation"], reasons=[])
        result = predict.predict(payload)
        self.assertEqual(result["class"], "silent-degradation")
        self.assertEqual(result["incomplete_reason_codes"], ["incomplete-with-observation"])

    def test_reason_codes_are_grouped_and_stable(self):
        codes = predict.reason_codes(["KB snapshot is 34 days old (maximum 30).",
                                      "Static-only scan: capability candidates are unconfirmed.",
                                      "KB snapshot is stale", "unrecognised text here"])
        self.assertEqual(codes, ["kb-stale", "other:unrecognised text here", "static-only"])

    def test_mapping_document_is_the_published_artifact(self):
        document = predict.mapping_document()
        self.assertEqual(document["label_classes"], list(predict.LABEL_CLASSES))
        self.assertEqual([rule["id"] for rule in document["rules"]], ["R1", "R2", "R3", "R4", "R5", "R6"])
        self.assertIn("dynamic.evidence_tier", document["inputs_read"])


class StatsTests(unittest.TestCase):
    def test_wilson_matches_textbook_value(self):
        interval = stats.wilson(68, 100)
        self.assertAlmostEqual(interval["low"], 0.5834, places=4)
        self.assertAlmostEqual(interval["high"], 0.7633, places=4)
        self.assertEqual(stats.wilson(0, 0)["point"], None)

    def test_clopper_pearson_is_conservative_and_exact_at_edges(self):
        self.assertAlmostEqual(stats.clopper_pearson(5, 10)["low"], 0.1871, places=4)
        self.assertAlmostEqual(stats.clopper_pearson(0, 10)["high"], 0.3085, places=4)
        self.assertEqual(stats.clopper_pearson(10, 10)["high"], 1.0)
        self.assertEqual(stats.clopper_pearson(0, 10)["low"], 0.0)
        exact, score = stats.clopper_pearson(5, 10), stats.wilson(5, 10)
        self.assertLess(exact["low"], score["low"], "Clopper-Pearson must be the conservative bound")
        self.assertGreater(exact["high"], score["high"])

    def test_geometric_mean_is_undefined_for_non_positive_input(self):
        self.assertEqual(stats.geometric_mean([1, 2, 4, 8]), 2.828427)
        self.assertIsNone(stats.geometric_mean([1, 0, 3]))
        self.assertIsNone(stats.geometric_mean([]))

    def test_mcnemar_exact_counts_discordants(self):
        pairs = [(1, 0), (1, 0), (1, 0), (1, 1), (0, 0)]
        result = stats.mcnemar_exact(pairs)
        self.assertEqual((result["discordant_b"], result["discordant_c"]), (3, 0))
        self.assertAlmostEqual(result["p_value"], 0.25, places=6)
        self.assertEqual(stats.mcnemar_exact([(1, 1), (0, 0)])["p_value"], 1.0)

    def test_mann_whitney_and_cliff_agree_on_a_stochastic_dominance_case(self):
        first, second = [1, 2, 3], [4, 5, 6]
        u = stats.mann_whitney_u(first, second)
        self.assertEqual(u["u"], 0.0)
        self.assertLess(u["p_value"], 0.2)
        self.assertEqual(stats.cliffs_delta(first, second)["delta"], -1.0)
        self.assertEqual(stats.cliffs_delta([1], [1])["magnitude"], "negligible")

    def test_holm_is_monotone_and_matches_the_step_down_formula(self):
        result = stats.holm([0.01, 0.04, 0.03, 0.001])
        self.assertEqual(result["adjusted"], [0.03, 0.06, 0.06, 0.004])
        self.assertEqual(result["reject"], [True, False, False, True])

    def test_change_point_requires_two_consecutive_confirmations(self):
        series = [10, 10, 10, 10, 30, 10, 30, 31]
        result = stats.change_point(series)
        self.assertEqual(result["flagged"], [6, 7])
        self.assertEqual(result["dropped_single_spikes"], [4])
        self.assertEqual(result["baseline"], 10)
        self.assertEqual(result["required_confirmations"], 2)
        self.assertEqual(stats.change_point([1, 2])["insufficient_data"], True)

    def test_kappa_matches_reference_tables(self):
        perfect = [("a", "a"), ("b", "b"), ("c", "c")]
        self.assertEqual(stats.cohens_kappa(perfect)["kappa"], 1.0)
        self.assertEqual(stats.cohens_kappa([("a", "a"), ("b", "b"), ("a", "b"), ("b", "a")])["kappa"], 0.0)
        self.assertEqual(stats.cohens_kappa([("a", "b"), ("b", "a")])["kappa"], -1.0,
                         "systematic disagreement is the floor, not chance")
        fleiss = stats.fleiss_kappa([[0, 0, 0, 0, 0, 0, 0, 0, 0, 10],
                                     [0, 0, 0, 0, 0, 0, 0, 0, 0, 10],
                                     [9, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                                     [0, 0, 0, 8, 0, 0, 0, 0, 0, 2],
                                     [0, 0, 0, 0, 5, 0, 0, 0, 0, 5]])
        self.assertAlmostEqual(fleiss["kappa"], 0.653, places=3)
        self.assertEqual(fleiss["interpretation"], "substantial")

    def test_cluster_bootstrap_reports_clusters_not_runs(self):
        groups = [[1, 1, 1], [0, 0, 0], [1, 1, 0]]
        result = stats.cluster_bootstrap_by_case(groups, samples=200)
        self.assertEqual(result["clusters"], 3)
        self.assertAlmostEqual(result["point"], 5 / 9.0, places=6)
        self.assertLessEqual(result["low"], result["point"])
        self.assertGreaterEqual(result["high"], result["point"])

    def test_bootstrap_is_deterministic_for_a_seed(self):
        values = list(range(1, 120))
        first = stats.bootstrap_percentile(values, 95, samples=100, seed=7)
        second = stats.bootstrap_percentile(values, 95, samples=100, seed=7)
        self.assertEqual(first, second)
        bca = stats.bootstrap_percentile(values, 95, samples=100, seed=7, bca=True)
        self.assertEqual(bca["method"], "bca")
        self.assertIn("acceleration", bca)

    def test_small_positive_set_triggers_the_prd_warning(self):
        note = stats.sample_size_note(20, 17)
        self.assertEqual(note["warning"], "recall interval is wider than the PRD 4.4 target")
        self.assertEqual(stats.sample_size_note(0)["warning"], "no positives recorded; recall is unmeasurable")

    def test_distribution_uses_nearest_rank(self):
        result = stats.distribution([1, 2, 3, 4])
        self.assertEqual(result["p50"], 2)
        self.assertEqual(result["p95"], 4)
        self.assertEqual(stats.distribution([]), {"count": 0})


if __name__ == "__main__":
    unittest.main()
