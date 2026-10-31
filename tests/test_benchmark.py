"""Benchmark statistics, evidence boundaries, and small real CLI measurements."""
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


benchmark = module("benchmark", ROOT / "scripts" / "benchmark.py")
fixtures = module("benchmark_fixtures", ROOT / "scripts" / "make_fixtures.py")


class StatisticsTests(unittest.TestCase):
    def test_known_empirical_percentiles(self):
        result = benchmark.distribution(list(range(1, 101)))
        self.assertEqual([result[key] for key in ["p50", "p95", "p99"]], [50, 95, 99])
        self.assertEqual(result["n"], 100)
        self.assertAlmostEqual(result["mean"], 50.5)

    def test_small_sample_tails_are_not_given_finite_confidence(self):
        result = benchmark.distribution([3.0, 1.0, 2.0])
        self.assertEqual(result["p99"], 3.0)
        self.assertIsNone(result["dkw_95_quantile_bounds"]["p99"]["upper"])
        self.assertTrue(any("p99" in warning and "exploratory" in warning for warning in result["warnings"]))
        self.assertIsNone(benchmark.distribution([])["p95"])

    def test_negative_ci_deltas_and_nonfinite_inputs(self):
        self.assertEqual(benchmark.nearest_rank([-2, -1, 0, 1], 0.5), -1)
        for values in [[math.nan], [math.inf]]:
            with self.assertRaises(ValueError):
                benchmark.distribution(values)

    def test_wilson_does_not_claim_zero_uncertainty_after_zero_hits(self):
        result = benchmark.wilson(0, 3)
        self.assertAlmostEqual(result["lower"], 0)
        self.assertGreater(result["upper"], 0.5)
        self.assertIsNone(benchmark.wilson(0, 0)["upper"])

    def test_warmups_invalid_attempts_and_changed_inputs_are_separate(self):
        base = {"kind": "scan", "name": "case", "mode": "static", "cache": "disabled", "scan_status": "incomplete",
                "evidence_tier": "static-only", "warmup": False, "measurement_valid": True, "wall_seconds": 1,
                "cache_hits": 0, "exit_code": 2, "sequence": 0, "image_digest": "a", "kb_snapshot_version": "snapshot"}
        rows = [base, dict(base, warmup=True, wall_seconds=100), dict(base, measurement_valid=False, wall_seconds=200),
                dict(base, image_digest="b"), dict(base, scan_status="complete", evidence_tier="dynamic-runsc-diff")]
        summary = benchmark.summarize(rows)
        self.assertEqual(summary["warmup_attempts"], 1)
        self.assertEqual(len(summary["excluded_invalid_measurements"]), 1)
        self.assertEqual(len(summary["groups"]), 3)
        self.assertTrue(all(group["wall_seconds"]["n"] == 1 and group["wall_seconds"]["p99"] == 1 for group in summary["groups"]))


class ManifestTests(unittest.TestCase):
    def case(self, **changes):
        return {"name": "fixture", "image": "image", "mode": "static", **changes}

    def test_managed_arguments_and_imported_evidence_cannot_change_measurement(self):
        for key in ["--output", "--cache", "--evidence", "--format", "--static-only"]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                benchmark.check_manifest({"schema_version": "1.0", "cases": [self.case(scan_args=[key, "value"])]})

    def test_warm_cache_requires_warmup_and_path_names_are_contained(self):
        for case in [self.case(cache="warm-analyzer", warmups=0), self.case(name="../outside"), self.case(repetitions=True),
                     self.case(expected_exit_codes=[True]), self.case(scan_args=["--version", "a", "--version", "b"])]:
            with self.subTest(case=case), self.assertRaises(ValueError):
                benchmark.check_manifest({"schema_version": "1.0", "cases": [case]})

    def test_label_requires_explicit_source(self):
        with self.assertRaises(ValueError):
            benchmark.check_manifest({"schema_version": "1.0", "historical_reports": [{"name": "r", "report": "r.json", "clean_label": True}]})

    def test_static_exit_two_is_a_valid_measurement_not_a_failure(self):
        report = {"status": "incomplete", "findings": [], "dynamic": None}
        benchmark.check_scan_outcome(self.case(), report, 2)
        with self.assertRaises(ValueError):
            benchmark.check_scan_outcome(self.case(), report, 0)

    def test_failure_exit_precedes_incomplete_and_imports_are_not_live(self):
        report = {"status": "incomplete", "findings": [{"severity": "hard-failure"}], "dynamic": {"provenance": "locally-executed"}}
        benchmark.check_scan_outcome(self.case(mode="live"), report, 1)
        with self.assertRaises(ValueError):
            benchmark.check_scan_outcome(self.case(mode="live"), report, 2)
        report["dynamic"]["provenance"] = "imported-user-supplied"
        with self.assertRaisesRegex(ValueError, "imported"):
            benchmark.check_scan_outcome(self.case(mode="live"), report, 1)

    def test_github_measurement_cannot_be_claimed_locally(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=False), self.assertRaisesRegex(ValueError, "GitHub Actions"):
            benchmark.run_ci_pair({"environment": "github-actions"}, ROOT, ROOT, None)


class ArtifactTests(unittest.TestCase):
    def test_historical_risk_incidence_excludes_imported_incomplete_and_unlabeled_reports(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-bench-incidence-") as directory:
            root = Path(directory)
            items = []
            for index, (status, provenance, label) in enumerate([
                ("complete", "locally-executed", True), ("incomplete", "locally-executed", True),
                ("complete", "imported-user-supplied", True), ("complete", "locally-executed", None)
            ]):
                report = {"status": status, "scanned_at": str(index), "dynamic": {"provenance": provenance},
                          "findings": [{"severity": "compatibility-risk"}]}
                path = root / f"report-{index}.json"
                benchmark.write_json(path, report)
                items.append({"name": f"r{index}", "report": str(path), "clean_label": label, "label_source": "independent fixture label"})
            # Validation is independently integration-tested against the CLI;
            # this isolates denominator selection with deliberately mixed scope.
            with patch.object(benchmark, "validate_report", side_effect=lambda path, *_: {"valid": True, "report_sha256": benchmark.digest_file(path)}):
                result = benchmark.historical_incidence(items, None, root)
                self.assertEqual(result["eligible_reports"], 1)
                self.assertEqual(result["risk_positive_reports"], 1)
                self.assertEqual(result["risk_incidence"], 1)
                self.assertFalse(result["label_independence_verified"])
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    benchmark.historical_incidence([items[0], dict(items[0], name="duplicate")], None, root)

    def test_kb_age_is_policy_coverage_not_reconstructed_accuracy(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-bench-kb-") as directory:
            root = Path(directory)
            snapshot = {"snapshot_version": "fixture", "created_at": "2026-09-26T12:00:00Z", "entries": [
                {"first_observed": "2026-09-01", "last_verified": "2026-09-26"},
                {"first_observed": "2026-08-01", "last_verified": "2026-09-01"}]}
            benchmark.write_json(root / "kb.json", snapshot)
            config = {"snapshot": "kb.json", "as_of": "2026-09-26", "ages_days": [0, 7, 31], "max_age_days": 30}
            result = benchmark.kb_age_policy(config, root)
            self.assertEqual([r["entries_with_recent_verification"] for r in result["rows"]], [2, 1, 0])
            self.assertEqual([r["snapshot_accepted_by_age_policy"] for r in result["rows"]], [True, True, False])
            self.assertIn("No accuracy", result["scope"])
            with self.assertRaisesRegex(ValueError, "before"):
                benchmark.kb_age_policy(dict(config, as_of="2026-09-25"), root)

    def test_standalone_svg_escapes_untrusted_labels(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-bench-svg-") as directory:
            path = Path(directory) / "plot.svg"
            benchmark.svg_chart(path, "<script>&", ["<script>alert(1)</script>"], [("p50", [2], "#000000")], "seconds")
            output = path.read_text()
            self.assertNotIn("<script>", output)
            self.assertIn("&lt;script&gt;", output)
            self.assertNotIn("href=", output)

    def test_timeout_is_not_a_successful_sample(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-bench-timeout-") as directory:
            root = Path(directory)
            result = benchmark.run_process([sys.executable, "-c", "import time; time.sleep(5)"], root, root / "out", root / "err", 0.05)
            self.assertTrue(result["timed_out"])
            self.assertIsNone(result["exit_code"])
            self.assertIsNotNone(result["process_error"])


class BenchmarkCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ.get("SENTRYCHECK_BIN", ROOT / "target" / "debug" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck"))).resolve()
        if not cls.binary.exists():
            raise RuntimeError("Build sentrycheck before benchmark integration tests")

    def execute(self, root, manifest, out="results"):
        manifest_path = root / "manifest.json"
        benchmark.write_json(manifest_path, manifest)
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "benchmark.py"), "run", "--binary", str(self.binary),
                               "--manifest", str(manifest_path), "--out", str(root / out)], capture_output=True, text=True, timeout=90)

    def test_real_static_cli_samples_are_validated_and_warm_cache_is_observed(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-bench-cli-") as directory:
            root = Path(directory)
            fixtures.oci(root / "image", {"workload": fixtures.elf(bytes.fromhex("b83c00000031ff0f05"))})
            manifest = {"schema_version": "1.0", "cases": [{"name": "small", "image": "image", "mode": "static", "cache": "warm-analyzer",
                         "repetitions": 2, "warmups": 1, "scan_args": ["--version", "20260921.0"], "expected_exit_codes": [2]}]}
            result = self.execute(root, manifest)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            summary = benchmark.load_json(root / "results" / "summary.json")
            raw = [json.loads(line) for line in (root / "results" / "samples.jsonl").read_text().splitlines()]
            self.assertEqual(len(raw), 3)
            self.assertTrue(all(row["validation"]["valid"] and row["measurement_valid"] and row["exit_code"] == 2 for row in raw))
            self.assertEqual(summary["measurements"]["groups"][0]["wall_seconds"]["n"], 2)
            self.assertEqual(summary["measurements"]["groups"][0]["cache_hits"], [1, 1])
            self.assertEqual(summary["scanner"]["sha256"], benchmark.digest_file(self.binary))
            self.assertEqual(summary["raw_samples_sha256"], benchmark.digest_file(root / "results" / "samples.jsonl"))
            self.assertEqual(raw[-1]["report_sha256"], benchmark.digest_file(root / "results" / "small" / "latest-report.json"))
            self.assertTrue((root / "results" / "latency.svg").is_file())
            repeat = self.execute(root, manifest)
            self.assertEqual(repeat.returncode, 2)
            self.assertIn("never overwritten", repeat.stderr)

    def test_scanner_input_error_remains_failed_raw_attempt(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-bench-bad-") as directory:
            root = Path(directory)
            digest = fixtures.oci(root / "invalid-image", {"workload": fixtures.elf(bytes.fromhex("b83c00000031ff0f05"))})
            blob = root / "invalid-image" / "blobs" / "sha256" / digest[7:]
            blob.write_bytes(blob.read_bytes() + b"\n")  # Valid JSON, corrupted content-addressed identity.
            manifest = {"schema_version": "1.0", "cases": [{"name": "invalid", "image": "invalid-image", "mode": "static", "repetitions": 1, "warmups": 0}]}
            result = self.execute(root, manifest)
            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            summary = benchmark.load_json(root / "results" / "summary.json")
            self.assertEqual(summary["status"], "completed-with-invalid-measurements")
            self.assertEqual(summary["measurements"]["groups"], [])
            self.assertEqual(summary["measurements"]["invalid_attempts_including_warmups"], 1)

    def test_real_ci_pairs_preserve_order_sign_and_label_local_scope(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-bench-pair-") as directory:
            root = Path(directory)
            manifest = {"schema_version": "1.0", "ci_pairs": [{"name": "local-pair", "baseline": [sys.executable, "-c", "pass"],
                         "gate": [sys.executable, "-c", "pass"], "environment": "local", "repetitions": 2, "warmups": 0}]}
            result = self.execute(root, manifest)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            raw = [json.loads(line) for line in (root / "results" / "samples.jsonl").read_text().splitlines()]
            self.assertEqual([row["order"] for row in raw], [["baseline", "gate"], ["gate", "baseline"]])
            self.assertTrue(all(row["environment"] == "local" and row["prorated_cost_delta_usd"] is None for row in raw))
            self.assertAlmostEqual(raw[0]["delta_seconds"], raw[0]["gate"]["wall_seconds"] - raw[0]["baseline"]["wall_seconds"])


if __name__ == "__main__":
    unittest.main()
