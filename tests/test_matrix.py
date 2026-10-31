"""Synthetic comparison mechanics. No test in this file claims a real Kata run."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_cli import ROOT, fixtures


class RuntimeComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ.get("SENTRYCHECK_BIN", ROOT / "target/debug" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck")))
        cls.temp = tempfile.TemporaryDirectory(prefix="sentrycheck-matrix-")
        cls.directory = Path(cls.temp.name)
        cls.image = cls.directory / "image"
        cls.digest = fixtures.oci(cls.image, {"workload": fixtures.elf(bytes.fromhex("b8a90100000f05b83c00000031ff0f05"))})
        cls.reports = {}
        cls.evidence = {}
        for scenario in ["hard-failure", "fallback", "native-only", "native-fails"]:
            bundle = fixtures.evidence(cls.directory / scenario, cls.digest, scenario)
            cls.evidence[scenario] = bundle
            run = cls.command("scan", str(cls.image), "--evidence", str(bundle), "--format", "json", "--cache", str(cls.directory / "cache"))
            cls.reports[scenario] = json.loads(run.stdout)
        cls.kata_bundle = fixtures.evidence(cls.directory / "kata", cls.digest, "fallback")
        bundle = json.loads(cls.kata_bundle.read_text())
        bundle["target_runtime"].update(name="kata", version="3.3.0")
        for run in bundle["sandbox"]:
            run.update(runtime="kata", runtime_version="3.3.0", trace_kind="strace-guest")
            trace = b'1 io_uring_setup(8, {flags=0}) = 3\n1 write(1, "ok\\n", 3) = 3\n1 exit_group(0) = ?\n'
            (cls.kata_bundle.parent / run["trace"]).write_bytes(trace)
            run["trace_sha256"] = fixtures.digest(trace)
        cls.kata_bundle.write_text(json.dumps(bundle))
        run = cls.command("scan", str(cls.image), "--runtime", "kata", "--version", "3.3.0", "--evidence", str(cls.kata_bundle), "--format", "json", "--cache", str(cls.directory / "cache"))
        cls.kata = json.loads(run.stdout)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def command(cls, *args):
        return subprocess.run([str(cls.binary), *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=60)

    def save(self, name, value):
        path = self.directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def compare(self, gvisor=None, kata=None):
        return self.command("report", "compare", self.save("gvisor.json", gvisor or self.reports["fallback"]), self.save("kata.json", kata or self.kata), "--format", "json")

    def test_imported_pair_retains_grades_and_original_report_objects(self):
        result = self.compare()
        self.assertEqual(result.returncode, 2, result.stderr)
        matrix = json.loads(result.stdout)
        self.assertEqual(matrix["schema_version"], "1.1")
        self.assertEqual(matrix["report_kind"], "runtime-comparison")
        self.assertEqual(matrix["reports"], [self.reports["fallback"], self.kata])
        self.assertEqual([r["version"] for r in matrix["target_runtimes"]], ["20260921.0", "3.3.0"])
        self.assertTrue(matrix["cross_runtime"]["comparable"])
        self.assertFalse(matrix["cross_runtime"]["locally_collected_pair"])
        self.assertFalse(matrix["authenticated"])
        self.assertFalse(matrix["cross_runtime"]["outcome_difference"])
        self.assertFalse(matrix["cross_runtime"]["stdout_difference"])
        self.assertIsNone(matrix["cross_runtime"]["stderr_difference"])
        self.assertEqual(matrix["cross_runtime"]["baseline_relationship"], "separate-native-executions")
        self.assertEqual([r["dynamic"]["evidence_tier"] for r in matrix["reports"]], ["dynamic-runsc-diff", "dynamic-kata-diff"])

    def test_observed_failure_takes_precedence_over_incomplete(self):
        result = self.compare(gvisor=self.reports["hard-failure"])
        self.assertEqual(result.returncode, 1, result.stderr)
        matrix = json.loads(result.stdout)
        self.assertEqual(matrix["status"], "incomplete")
        self.assertTrue(matrix["cross_runtime"]["outcome_difference"])
        self.assertEqual(matrix["cross_runtime"]["outcomes"], {"gvisor": "failure", "kata": "success"})
        self.assertTrue(any(f["severity"] == "hard-failure" for f in matrix["reports"][0]["findings"]))

    def test_missing_sandbox_or_failed_native_is_not_comparable(self):
        for scenario in ["native-only", "native-fails"]:
            with self.subTest(scenario=scenario):
                result = self.compare(gvisor=self.reports[scenario])
                self.assertEqual(result.returncode, 2, result.stderr)
                matrix = json.loads(result.stdout)
                self.assertFalse(matrix["cross_runtime"]["comparable"])
                self.assertIsNone(matrix["cross_runtime"]["outcome_difference"])
                self.assertIsNone(matrix["cross_runtime"]["stdout_difference"])

    def test_different_native_outputs_do_not_establish_runtime_divergence(self):
        changed = copy.deepcopy(self.kata)
        for run in changed["dynamic"]["native"] + changed["dynamic"]["sandbox"]:
            run["stdout_sha256"] = "sha256:" + "1" * 64
        result = self.compare(kata=changed)
        self.assertEqual(result.returncode, 2, result.stderr)
        matrix = json.loads(result.stdout)
        self.assertFalse(matrix["cross_runtime"]["comparable"])
        self.assertIn("Native baseline stdout", " ".join(matrix["cross_runtime"]["comparison_limits"]))

    def test_mismatched_identity_profile_runtime_and_version_rejected(self):
        for mutation in ["image", "profile", "architecture", "runtime", "version"]:
            changed = copy.deepcopy(self.kata)
            if mutation == "image":
                changed["image_digest"] = "sha256:" + "a" * 64
            elif mutation == "profile":
                changed["dynamic"]["profile"]["timeout_seconds"] += 1
                changed["dynamic"]["profile_sha256"] = fixtures.digest(fixtures.compact(changed["dynamic"]["profile"]))
            elif mutation == "architecture":
                changed["target_runtime"]["architecture"] = "arm64"
                changed["platform"] = "linux/arm64"
            elif mutation == "runtime":
                changed = copy.deepcopy(self.reports["fallback"])
            else:
                changed["target_runtime"]["version"] = "unversioned"
                for run in changed["dynamic"]["sandbox"]:
                    run["runtime_version"] = "unversioned"
            result = self.compare(kata=changed)
            self.assertEqual(result.returncode, 2, mutation + ": " + result.stderr)
            self.assertEqual(result.stdout, "")

    def test_extract_roundtrip_and_consistency_check(self):
        matrix = json.loads(self.compare().stdout)
        path = self.save("matrix.json", matrix)
        output = self.directory / "extracted.json"
        result = self.command("report", "extract", path, "--runtime", "kata", "--output", str(output), "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text()), self.kata)
        valid = self.command("report", "validate", str(output))
        self.assertEqual(valid.returncode, 0, valid.stderr)
        for mutation in ["summary", "digest", "status", "target", "nested", "extra", "order"]:
            changed = copy.deepcopy(matrix)
            if mutation == "summary": changed["cross_runtime"]["comparable"] = False
            elif mutation == "digest": changed["report_digests"]["gvisor"] = "sha256:" + "1" * 64
            elif mutation == "status": changed["status"] = "complete"
            elif mutation == "target": changed["target_runtimes"][1]["version"] = "4.0.0"
            elif mutation == "nested": changed["reports"][0]["dynamic"]["profile"]["timeout_seconds"] += 1
            elif mutation == "order": changed["reports"].reverse()
            else: changed["unverified_summary"] = True
            result = self.command("report", "extract", self.save("tampered.json", changed), "--runtime", "kata", "--output", str(output))
            self.assertEqual(result.returncode, 2, mutation + ": " + result.stderr)
            self.assertEqual(json.loads(output.read_text()), self.kata)

    def test_cannot_overwrite_source_reports(self):
        source = self.save("gvisor-source.json", self.reports["fallback"])
        original = Path(source).read_bytes()
        result = self.command("report", "compare", source, self.save("kata-source.json", self.kata), "--output", source)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(Path(source).read_bytes(), original)
        matrix = self.save("matrix-source.json", json.loads(self.compare().stdout))
        original = Path(matrix).read_bytes()
        result = self.command("report", "extract", matrix, "--runtime", "gvisor", "--output", matrix)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(Path(matrix).read_bytes(), original)

    def test_scan_orchestration_accepts_separate_versions_and_imports(self):
        result = self.command("scan", str(self.image), "--runtime", "gvisor,kata", "--gvisor-version", "20260921.0", "--kata-version", "3.3.0", "--gvisor-evidence", str(self.evidence["hard-failure"]), "--kata-evidence", str(self.kata_bundle), "--format", "json", "--cache", str(self.directory / "cache"))
        self.assertEqual(result.returncode, 1, result.stderr)
        matrix = json.loads(result.stdout)
        self.assertEqual(matrix["report_kind"], "runtime-comparison")
        self.assertFalse(matrix["cross_runtime"]["locally_collected_pair"])

    def test_static_scan_stays_incomplete_and_shared_version_rejected(self):
        base = ["scan", str(self.image), "--runtime", "gvisor,kata", "--static-only", "--format", "json", "--cache", str(self.directory / "cache")]
        for extras in [[], ["--version", "20260921.0"], ["--gvisor-version", "20260921.0"], ["--gvisor-version", "20260921.0", "--kata-version", "latest"]]:
            result = self.command(*base, *extras)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, "")
        result = self.command(*base, "--gvisor-version", "20260921.0", "--kata-version", "3.3.0")
        self.assertEqual(result.returncode, 2, result.stderr)
        matrix = json.loads(result.stdout)
        self.assertFalse(matrix["cross_runtime"]["comparable"])
        self.assertTrue(all(r["dynamic"] is None and not r["findings"] for r in matrix["reports"]))

    def test_schema_accepts_matrix_and_rejects_invalid_envelope(self):
        import jsonschema
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
        schema = json.loads((ROOT / "schema/runtime-comparison.schema.json").read_text())
        report_schema = json.loads((ROOT / "schema/report.schema.json").read_text())
        registry = Registry().with_resource("urn:sentrycheck:report:1.0", Resource.from_contents(report_schema, default_specification=DRAFT202012))
        validator = jsonschema.Draft202012Validator(schema, registry=registry)
        matrix = json.loads(self.compare().stdout)
        validator.validate(matrix)
        matrix["reports"].pop()
        self.assertTrue(list(validator.iter_errors(matrix)))


if __name__ == "__main__":
    unittest.main()
