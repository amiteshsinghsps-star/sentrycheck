"""Black-box scanner tests. Trace fixtures are synthetic, not live compatibility results."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fixtures", ROOT / "scripts" / "make_fixtures.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)

class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ.get("SENTRYCHECK_BIN", ROOT / "target" / "debug" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck")))
        if not cls.binary.exists():
            raise RuntimeError("Build sentrycheck before running black-box tests")
        cls.temp = tempfile.TemporaryDirectory(prefix="sentrycheck-tests-")
        cls.root = Path(cls.temp.name)
        cls.digest = fixtures.oci(cls.root / "image", {"workload": fixtures.elf(bytes.fromhex("b8a90100000f05b83c00000031ff0f05"))})
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()
    def scan(self, *args):
        result = subprocess.run([str(self.binary), "scan", str(self.root / "image"), "--cache", str(self.root / "cache"), "--format", "json", *args], capture_output=True, text=True, timeout=30)
        return result, json.loads(result.stdout) if result.stdout else None
    def test_static_is_incomplete_and_never_hard_failure(self):
        result, report = self.scan("--static-only")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["findings"], [])
        self.assertTrue(any(c["syscall"] == "io_uring_setup" for c in report["capability_set"]["capabilities"]))
        self.assertFalse(report["silent_fallback_check"]["performed"])
    def test_incremental_cache_reuses_unchanged_elf(self):
        self.scan("--static-only")
        _, report = self.scan("--static-only")
        self.assertEqual(report["capability_set"]["cache_hits"], 1)
    def test_hard_failure_and_tolerated_fallback_are_distinct(self):
        for scenario, expected in [("hard-failure", 1), ("fallback", 2), ("native-fails", 2)]:
            path = fixtures.evidence(self.root / scenario, self.digest, scenario)
            result, report = self.scan("--evidence", str(path))
            self.assertEqual(result.returncode, expected, result.stderr)
            hard = [f for f in report["findings"] if f["severity"] == "hard-failure"]
            self.assertEqual(bool(hard), scenario == "hard-failure")
            if scenario == "hard-failure":
                self.assertEqual(len(hard), 1)
                self.assertEqual(hard[0]["gap_id"], "gap-observed-workload-failure")
                self.assertTrue(any(f["static_evidence"] and f["severity"] == "compatibility-risk" for f in report["findings"]))
                self.assertEqual(hard[0]["evidence_tier"], "dynamic-runsc-diff")
                self.assertEqual(len(report["capability_set_only"]), len(report["capability_set"]["capabilities"]))
            self.assertIn("user-supplied", " ".join(report["incomplete_reasons"]))
    def test_silent_and_performance_differences(self):
        for scenario, severity in [("output-diff", "silent-degradation"), ("performance", "performance-regression")]:
            path = fixtures.evidence(self.root / scenario, self.digest, scenario)
            result, report = self.scan("--evidence", str(path), "--fail-on", severity)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue(any(f["severity"] == severity for f in report["findings"]))
            if scenario == "performance":
                self.assertEqual(report["assessment"], "performance-regression-observed")
    def test_native_only_is_not_a_confirmed_failure(self):
        path = fixtures.evidence(self.root / "native-only", self.digest, "native-only")
        result, report = self.scan("--evidence", str(path))
        self.assertEqual(result.returncode, 2)
        self.assertTrue(all(f["severity"] == "compatibility-risk" for f in report["findings"]))

    def test_failed_run_diagnostics_need_not_be_deterministic(self):
        path = fixtures.evidence(self.root / "variable-diagnostics", self.digest, "hard-failure")
        data = json.loads(path.read_text())
        for index, run in enumerate(data["sandbox"]):
            diagnostic = f"PID {index}: unavailable capability\n".encode()
            (path.parent / run["stdout"]).write_bytes(diagnostic)
            run["stdout_sha256"] = fixtures.digest(diagnostic)
        path.write_text(json.dumps(data))
        result, report = self.scan("--evidence", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertFalse(any("varied within" in reason for reason in report["incomplete_reasons"]))
    def test_rejects_tampered_trace_and_wrong_image(self):
        path = fixtures.evidence(self.root / "tampered", self.digest, "fallback")
        (path.parent / "native-0.trace").write_text("forged")
        result, _ = self.scan("--evidence", str(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("digest mismatch", result.stderr)
        path = fixtures.evidence(self.root / "wrong-image", "sha256:" + "b" * 64, "fallback")
        result, _ = self.scan("--evidence", str(path))
        self.assertIn("scanned OCI manifest", result.stderr)
    def test_uncovered_release_does_not_inherit_rules(self):
        _, report = self.scan("--static-only", "--version", "20990101.0")
        self.assertTrue(all(not c["version_match"] for c in report["candidate_gaps"]))
        self.assertEqual(report["status"], "incomplete")
    def test_oci_digest_corruption_fails_closed(self):
        image = self.root / "corrupt"
        fixtures.oci(image, {"workload": fixtures.elf(b"\x0f\x05")})
        index = json.loads((image / "index.json").read_text())
        blob = image / "blobs" / "sha256" / index["manifests"][0]["digest"][7:]
        blob.write_bytes(blob.read_bytes() + b"x")
        result = subprocess.run([str(self.binary), "scan", str(image), "--static-only"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("mismatch", result.stderr)

    def test_kb_age_policy_is_explicit_not_wall_clock(self):
        # The checked-in snapshot ages every day; without an explicit budget the default
        # 30-day policy silently marks every scan incomplete. Benchmark records must therefore
        # state the budget they ran with, and this pair locks both directions.
        stale = [r for r in self.scan("--static-only", "--max-kb-age-days", "0")[1]["incomplete_reasons"] if "days old" in r]
        self.assertEqual(len(stale), 1, stale)
        self.assertIn("maximum 0", stale[0])
        allowed = [r for r in self.scan("--static-only", "--max-kb-age-days", "100000")[1]["incomplete_reasons"] if "days old" in r]
        self.assertEqual(allowed, [])

if __name__ == "__main__": unittest.main()
