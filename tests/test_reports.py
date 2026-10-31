"""Offline report mechanics use explicitly synthetic fixtures, not live measurement claims."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_cli import ROOT, fixtures


class ReportToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ.get("SENTRYCHECK_BIN", ROOT / "target/debug" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck")))
        cls.temp = tempfile.TemporaryDirectory(prefix="sentrycheck-report-tests-")
        cls.root = Path(cls.temp.name)
        cls.digest = fixtures.oci(cls.root / "image", {"workload": fixtures.elf(bytes.fromhex("b8a90100000f05b83c00000031ff0f05"))})
        cls.reports = {}
        for scenario in ["hard-failure", "fallback", "output-diff", "native-only"]:
            bundle = fixtures.evidence(cls.root / scenario, cls.digest, scenario)
            process = cls.command("scan", str(cls.root / "image"), "--evidence", str(bundle), "--format", "json", "--cache", str(cls.root / "cache"))
            cls.reports[scenario] = json.loads(process.stdout)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def command(cls, *args):
        return subprocess.run([str(cls.binary), *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=30)

    def save(self, name, report):
        path = self.root / (name + ".json")
        path.write_text(json.dumps(report), encoding="utf-8")
        return str(path)

    def comparable_fixture(self, scenario):
        # This intentionally models a fabricated caller-owned report. Validation is NOT authentication.
        report = copy.deepcopy(self.reports[scenario])
        report["dynamic"]["provenance"] = "locally-executed"
        report["status"] = "complete"
        report["incomplete_reasons"] = []
        for finding in report["findings"]:
            finding["dynamic_evidence"]["provenance"] = "locally-executed"
        if not report["findings"]:
            report["assessment"] = "no-incompatibility-observed-in-profile"
        return report

    def test_validate_preserves_incomplete_status(self):
        process = self.command("report", "validate", self.save("valid", self.reports["fallback"]), "--format", "json")
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["scan_status"], "incomplete")
        self.assertFalse(result["authenticated"])

    def test_aggregate_report_can_exceed_individual_trace_budget(self):
        report = copy.deepcopy(self.reports["fallback"])
        report["limitations"].append("x" * (33 * 1024 * 1024))
        process = self.command("report", "validate", self.save("aggregate-large", report))
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_validate_rejects_profile_tampering_and_complete_import(self):
        for mutation in ["profile", "complete", "version", "assessment"]:
            report = copy.deepcopy(self.reports["fallback"])
            if mutation == "profile": report["dynamic"]["profile"]["timeout_seconds"] += 1
            if mutation == "complete": report.update(status="complete", incomplete_reasons=[])
            if mutation == "version": report["schema_version"] = "99.0"
            if mutation == "assessment": report["assessment"] = "incompatibility-observed"
            process = self.command("report", "validate", self.save("invalid-" + mutation, report))
            self.assertEqual(process.returncode, 2, mutation)

    def test_artifact_integrity_and_containment(self):
        report = self.reports["fallback"]
        path = self.save("artifacts", report)
        process = self.command("report", "validate", path, "--artifacts-root", str(self.root), "--format", "json")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["artifacts_checked"], 18)
        conservative = copy.deepcopy(report)
        conservative["dynamic"]["native"][0]["trace_summary"]["truncated"] = True
        process = self.command("report", "validate", self.save("retained-prefix", conservative), "--artifacts-root", str(self.root))
        self.assertEqual(process.returncode, 0, process.stderr)
        outside = self.command("report", "validate", path, "--artifacts-root", str(self.root / "image"))
        self.assertEqual(outside.returncode, 2)
        run = report["dynamic"]["native"][0]
        trace = Path(run["trace_ref"])
        original = trace.read_bytes()
        try:
            trace.write_bytes(original + b"tampered\n")
            bad = self.command("report", "validate", path, "--artifacts-root", str(self.root))
            self.assertEqual(bad.returncode, 2)
            self.assertIn("digest mismatch", bad.stderr)
        finally:
            trace.write_bytes(original)

    def test_validate_rejects_missing_or_fabricated_findings(self):
        bad = self.comparable_fixture("hard-failure")
        bad["findings"] = []
        bad["assessment"] = "no-incompatibility-observed-in-profile"
        process = self.command("report", "validate", self.save("hidden-failure", bad))
        self.assertEqual(process.returncode, 2)
        self.assertIn("outcomes", process.stderr)
        bad = self.comparable_fixture("fallback")
        bad["dynamic"]["native"][0]["stdout_sha256"] = "sha256:" + "1" * 64
        process = self.command("report", "validate", self.save("unstable-output", bad))
        self.assertEqual(process.returncode, 2)
        self.assertIn("non-deterministic", process.stderr)
        bad = self.comparable_fixture("hard-failure")
        bad["findings"][0]["dynamic_evidence"]["profile_sha256"] = "sha256:" + "2" * 64
        process = self.command("report", "validate", self.save("wrong-reference", bad))
        self.assertEqual(process.returncode, 2)
        self.assertIn("references", process.stderr)

    def test_trace_loss_and_contradictory_totals_cannot_validate_complete(self):
        for mutation in ["lost-record", "false-totals"]:
            report = self.comparable_fixture("fallback")
            summary = report["dynamic"]["native"][0]["trace_summary"]
            if mutation == "lost-record": summary["discarded_guest_records"] = 1
            else: summary["syscalls"]["invented_syscall"] = 1
            result = self.command("report", "validate", self.save(mutation, report))
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_malformed_guest_record_makes_collection_incomplete(self):
        bundle = fixtures.evidence(self.root / "lost-guest-record", self.digest, "fallback")
        data = json.loads(bundle.read_text(encoding="utf-8"))
        record = data["sandbox"][0]
        trace = bundle.parent / record["trace"]
        trace.write_bytes(trace.read_bytes() + b'I0926 00:00:00 strace.go:601] app X bpf(5) = bad\n')
        record["trace_sha256"] = fixtures.digest(trace.read_bytes())
        bundle.write_text(json.dumps(data), encoding="utf-8")
        result = self.command("scan", str(self.root / "image"), "--evidence", str(bundle), "--format", "json", "--cache", str(self.root / "cache"))
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["dynamic"]["sandbox"][0]["trace_summary"]["discarded_guest_records"], 1)
        self.assertTrue(any("Guest trace collection" in reason for reason in report["incomplete_reasons"]))
        self.assertFalse(any(f["severity"] == "hard-failure" for f in report["findings"]))

    def test_sarif_has_no_invented_source_locations(self):
        process = self.command("report", "sarif", self.save("sarif", self.reports["hard-failure"]))
        self.assertEqual(process.returncode, 1, process.stderr)
        sarif = json.loads(process.stdout)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertFalse(run["invocations"][0]["executionSuccessful"])
        self.assertTrue(run["invocations"][0]["toolExecutionNotifications"])
        self.assertTrue(any(r["level"] == "error" for r in run["results"]))
        self.assertTrue(all("locations" not in r for r in run["results"]))
        for result in run["results"]:
            self.assertEqual(run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"], result["ruleId"])
        mapped = self.command("report", "sarif", self.save("mapped", self.reports["hard-failure"]), "--source-file", "README.md", "--source-line", "1")
        self.assertEqual(mapped.returncode, 1, mapped.stderr)
        location = json.loads(mapped.stdout)["runs"][0]["results"][0]["locations"][0]
        self.assertEqual(location["physicalLocation"]["artifactLocation"]["uri"], "README.md")
        self.assertIn("User-supplied", location["message"]["text"])

    def test_sarif_preserves_static_incompleteness_and_rejects_bad_context(self):
        process = self.command("scan", str(self.root / "image"), "--static-only", "--format", "sarif", "--cache", str(self.root / "cache"))
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(json.loads(process.stdout)["runs"][0]["results"], [])
        bad = self.command("report", "sarif", self.save("bad-context", self.reports["fallback"]), "--source-file", "../outside")
        self.assertEqual(bad.returncode, 2)

    def test_diff_detects_new_failures_but_not_changed_ids(self):
        baseline = self.comparable_fixture("fallback")
        current = self.comparable_fixture("hard-failure")
        before, after = self.save("before", baseline), self.save("after", current)
        process = self.command("report", "diff", before, after, "--format", "json")
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertTrue(json.loads(process.stdout)["selected_regression"])
        for index, finding in enumerate(current["findings"]):
            finding["id"] = "changed-" + str(index)
        identical = self.command("report", "diff", after, self.save("renumbered", current), "--format", "json")
        self.assertEqual(identical.returncode, 0, identical.stderr)
        self.assertEqual(json.loads(identical.stdout)["added"], [])
        removed = self.command("report", "diff", after, before, "--format", "json")
        self.assertEqual(removed.returncode, 0)
        self.assertTrue(json.loads(removed.stdout)["not_observed_in_current"])

    def test_diff_refuses_evidence_or_target_downgrade(self):
        complete = self.comparable_fixture("fallback")
        before = self.save("complete", complete)
        for key in ["incomplete", "kb", "profile", "target"]:
            current = copy.deepcopy(complete)
            if key == "incomplete": current = self.reports["fallback"]
            if key == "kb": current["kb_snapshot_version"] = "another-snapshot"
            if key == "profile":
                current["dynamic"]["profile"]["timeout_seconds"] += 1
                current["dynamic"]["profile_sha256"] = fixtures.digest(fixtures.compact(current["dynamic"]["profile"]))
            if key == "target":
                current["target_runtime"]["version"] = "20260920.0"
                for run in current["dynamic"]["sandbox"]: run["runtime_version"] = "20260920.0"
            process = self.command("report", "diff", before, self.save("changed-" + key, current), "--format", "json")
            self.assertEqual(process.returncode, 2, process.stderr)
            self.assertFalse(json.loads(process.stdout)["comparable"])

    def test_doctor_static_and_missing_tools(self):
        # --max-kb-age-days is pinned so this does not silently turn red as the checked-in
        # snapshot ages past the product's 30-day policy default; see test_doctor_flags_a_stale_kb.
        process = self.command("doctor", "--static-only", "--format", "json", "--max-kb-age-days", "100000", "--cache", str(self.root / "cache"))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["mode"], "static")
        missing = str(self.root / "missing-executable")
        process = self.command("doctor", "--format", "json", "--runc-bin", missing, "--strace-bin", missing, "--runsc-bin", missing, "--cache", str(self.root / "cache"))
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(json.loads(process.stdout)["status"], "not-ready")

    def test_doctor_flags_a_stale_kb(self):
        # Age only ever grows, so a zero-day budget fails the same way on any future date.
        process = self.command("doctor", "--static-only", "--format", "json", "--max-kb-age-days", "0", "--cache", str(self.root / "cache"))
        self.assertEqual(process.returncode, 2, process.stderr)
        payload = json.loads(process.stdout)
        self.assertEqual(payload["status"], "not-ready")
        stale = [c for c in payload["checks"] if c["id"] == "knowledge-base"]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["status"], "fail")
        self.assertIn("age", stale[0]["detail"])


if __name__ == "__main__":
    unittest.main()
