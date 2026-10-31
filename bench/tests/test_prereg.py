"""Phase 3: the BT-01 mapping is registered, sealed and re-derivable from disk."""
import hashlib
import unittest

from bench import predict
from bench.common import BENCH, ROOT, BenchError, canonical_json, read_json, sha256_file, write_json
from bench.store import verify_preregistration


class PreregistrationTests(unittest.TestCase):
    def setUp(self):
        self.path = BENCH / "analysis" / "preregistration.json"
        self.payload = read_json(self.path)

    def body(self, **overrides):
        payload = dict(self.payload, **overrides)
        return {key: value for key, value in payload.items()
                if key not in ("registration_sha256", "registered_at")}

    def test_seal_matches_the_registered_content(self):
        recorded = self.payload["registration_sha256"]
        self.assertEqual(recorded,
                         "sha256:" + hashlib.sha256(canonical_json(self.body()).encode("utf-8")).hexdigest())

    def test_editing_a_registered_value_breaks_the_seal(self):
        claims = dict(self.payload["claims_ceiling"], level="L5")
        tampered = "sha256:" + hashlib.sha256(
            canonical_json(self.body(claims_ceiling=claims)).encode("utf-8")).hexdigest()
        self.assertNotEqual(tampered, self.payload["registration_sha256"])

    def test_verify_passes_and_reports_the_registration(self):
        report = verify_preregistration()
        self.assertEqual(report["failures"], [], report)
        self.assertEqual(report["checked"], 1)

    def test_every_ready_case_is_registered_or_deviated(self):
        from bench.cases import REGISTRY, case_record
        ready = sorted(case_id for case_id, seed in REGISTRY.items()
                       if case_record(case_id, seed)[1] is None)
        listed = sorted(sum((value for key, value in self.payload["splits"].items()
                             if isinstance(value, list)), []))
        self.assertTrue(set(listed) <= set(ready), "a registered case is no longer resolvable on this host")
        log = (BENCH / "analysis" / "DEVIATIONS.md").read_text(encoding="utf-8")
        for case_id in ready:
            if case_id in listed:
                continue
            self.assertIn(case_id, log,
                          "%s became available after the seal; scoring it without a deviation entry is "
                          "an undisclosed corpus change" % case_id)

    def test_prediction_map_digest_in_the_registration_is_current(self):
        self.assertEqual(self.payload["prediction_map"]["sha256"],
                         sha256_file(BENCH / "analysis" / "prediction-map.json"))

    def test_fixed_inputs_match_the_cli_defaults(self):
        from bench.cli import build_parser
        parser = build_parser()
        suite = parser.parse_args(["suite", "BM-08"])
        self.assertEqual(suite.seed, self.payload["fixed_inputs"]["seed"])

    def test_deviation_log_is_appended_to_rather_than_inside_the_seal(self):
        self.assertNotIn("deviations", self.payload)
        self.assertEqual(self.payload["deviation_log"]["path"], "bench/analysis/DEVIATIONS.md")
        self.assertTrue((ROOT / "bench" / "analysis" / "DEVIATIONS.md").is_file())

    def test_scored_analysis_is_refused_when_the_seal_is_broken(self):
        from bench.store import require_preregistration
        self.assertEqual(require_preregistration()["checked"], 1)
        original = self.path.read_bytes()
        try:
            claims = dict(self.payload["claims_ceiling"], level="L5")
            write_json(self.path, dict(self.payload, claims_ceiling=claims))
            with self.assertRaises(BenchError) as caught:
                require_preregistration()
            self.assertIn("changed after registration", str(caught.exception))
        finally:
            self.path.write_bytes(original)
        self.assertEqual(require_preregistration()["checked"], 1)


class MappingSnapshotTests(unittest.TestCase):
    def test_retained_distribution_is_rederivable(self):
        snapshot = read_json(BENCH / "analysis" / "preregistration.json")["mapping_validation_snapshot"]
        paths = sorted(set(ROOT.joinpath("artifacts").rglob("report.json"))
                       | set(ROOT.joinpath("artifacts").rglob("*.report.json")))
        counts = {}
        for path in paths:
            label = predict.predict(read_json(path))["class"]
            counts[label] = counts.get(label, 0) + 1
        self.assertEqual(snapshot["reports"], len(paths))
        self.assertEqual(snapshot["distribution"], counts)

    def test_prediction_table_paths_are_repo_relative(self):
        table = read_json(BENCH / "analysis" / "predictions-retained.json")
        self.assertEqual(len(table["rows"]), 34)
        for row in table["rows"]:
            self.assertNotIn("\\", row["report"], row["report"])
            self.assertTrue((ROOT / row["report"]).is_file(), row["report"])


if __name__ == "__main__":
    unittest.main()
